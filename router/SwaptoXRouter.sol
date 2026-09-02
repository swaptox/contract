// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

library ERC20Helper {

    /// @dev sentinel address used to represent native ETH
    address constant ETH_ADDRESS = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    /// @dev Accepts standard ERC20 transfers that either return no data or a 32-byte true value.
    function isERC20Success(bool success, bytes memory data) internal pure returns (bool) {
        if (!success) return false;
        if (data.length == 0) return true;
        if (data.length < 32) return false;
        return abi.decode(data, (bool));
    }

    function safeTransferFrom(address token, address from, address to, uint256 value) internal {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(isERC20Success(success, data), "SwaptoX: STF");
    }

    function safeTransfer(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(isERC20Success(success, data), "SwaptoX: ST");
    }

    /// @notice Safe ETH transfer helper that reverts on failure.
    function safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = payable(to).call{value: value}("");
        require(success, "SwaptoX: ETH transfer failed");
    }

    /// @dev Restricts raw permit calldata to known permit selectors
    ///      (0xd505accf or 0x8fcbaf0c) to prevent arbitrary token calls.
    function permit(address token, bytes calldata permitData) internal {
        require(permitData.length >= 4, "SwaptoX: invalid permit");
        bytes4 selector;
        assembly {
            selector := and(
                calldataload(permitData.offset),
                0xffffffff00000000000000000000000000000000000000000000000000000000
            )
        }
        require(selector == 0xd505accf || selector == 0x8fcbaf0c, "SwaptoX: SELECTOR_FAILED");
        bytes memory callData = permitData;
        (bool ok,) = token.call(callData);
        (ok); //Regardless of whether `ok` is true or false, execution proceeds; ultimately, `safeTransferFrom` serves as the final safeguard.
    }

    /// @dev Returns 0 if staticcall fails or the returned data is shorter than expected. 
    /// No revert to ensure compatibility.
    function balanceOf(address token, address account) internal view returns (uint256) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSelector(0x70a08231, account));
        if (!success || data.length < 32) return 0;
        return abi.decode(data, (uint256));
    }

}

interface ITimelockContext {
    function currentOpId() external view returns (bytes32);
}

contract OwnerContract {

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event WalletAddressSet(bytes32 indexed opId, address indexed previousWallet, address indexed newWallet);
    event SwapAddressSet(bytes32 indexed opId, uint256 indexed version, address indexed newAddress);
    event FeeTokenChanged(bytes32 indexed opId, address indexed token, uint8 fee);
    event FreeTokenChanged(bytes32 indexed opId, address indexed token, bool free);
    event DefaultFeeChanged(bytes32 indexed opId, uint8 fee);
    event SwaptoXTokenSet(bytes32 indexed opId, address token);
    event LadderSwitchChanged(bytes32 indexed opId, bool enabled);
    event FeeLadderUpdated(bytes32 indexed opId, FeeTier[] fees);
    event Withdraw(address indexed sender, address indexed token, address indexed to, uint256 amount);

    /**
     * @notice Fee ladder tier definition.
     * @param amount Minimum token balance required to reach this tier
     * @param discount Discount in basis points applied to the base fee (0-10000)
     */
    struct FeeTier {
        uint256 amount;
        uint16 discount; // Range 0-10000
    }

    address public admin;
    address public SwaptoXToken;  // Platform token used for fee discount calculation
    address public walletAddress; // Address used to collect protocol fees
    mapping(uint256 => address) public swapAddress; // Swap execution contract (router / executor layer)

    /// @notice Fee ladder tiers sorted by ascending token amount
    FeeTier[] public feeTiers;

    /// @notice Global switch to enable or disable ladder discount logic
    bool public isLadderEnabled = true;

    /// @notice Default swap fee (basis points)
    /// default fee in basis points (1 BP = 0.01%)
    /// capped to 20 BP (0.2%) by design
    uint8 public defaultFeeBP = 0; 

    /// @notice Tokens that are completely exempt from swap fees
    mapping(address => bool) public isFeeExemptToken;

    /// @notice Custom fee configuration per token (basis points)
    mapping(address => uint8) public customFeeBP;

    /// @notice Maximum free period of the agreement, storage timestamp
    uint256 public maxFreeTime = 0;

    modifier onlySelf() {
        require(msg.sender == admin, "ONLY_SELF");
        _;
    }

    constructor(address _admin, uint256 _freeMonth) {
        require(_admin != address(0), "SwaptoX: admin cannot be zero");
        admin = _admin;
        if(_freeMonth>0){
            maxFreeTime = block.timestamp + ((60*60*24*30)*_freeMonth);
        }
    }


    function _getOpId() internal view returns (bytes32 opId) {
        if (msg.sender.code.length == 0) return bytes32(0);
        (bool success, bytes memory data) = msg.sender.staticcall(
            abi.encodeWithSelector(ITimelockContext.currentOpId.selector)
        );
        if (success && data.length >= 32) {
            opId = abi.decode(data, (bytes32));
        }
    }


    /// @notice Enable or disable the fee ladder discount mechanism
    function setLadderEnabled(bool _enabled) external onlySelf {
        isLadderEnabled = _enabled;
        emit LadderSwitchChanged(_getOpId(), _enabled);
    }

    /// @notice Configure whether a token is fully exempt from swap fees
    function setFreeSwapToken(address token, bool isFree) external onlySelf {
        isFeeExemptToken[token] = isFree;
        emit FreeTokenChanged(_getOpId(), token, isFree);
    }

    /**
     * @notice Set custom fee for a specific token.
     *
     * @dev Fixes ambiguity between:
     * - token without custom fee
     * - token with custom fee set to zero
     * - fee is capped at 20 BP (0.2%) by design
     *
     * If fee == 0:
     *   custom fee configuration is considered disabled.
     */
    function setCustomFeeToken(address token, uint8 fee) external onlySelf {
        require(block.timestamp >= maxFreeTime, "SwaptoX: Free period of the agreement");
        require(20 >= fee, "SwaptoX: invalid fee value"); // Maximum 0.2%, avoid triggering high agreement fees.
        customFeeBP[token] = fee;
        emit FeeTokenChanged(_getOpId(), token, fee);
    }

    /// @notice Update global default swap fee
    function setDefaultSwapFee(uint8 fee) external onlySelf {
        require(block.timestamp >= maxFreeTime, "SwaptoX: Free period of the agreement");
        require(20 >= fee, "SwaptoX: invalid default fee"); // Maximum 0.2%, avoid triggering high agreement fees.
        defaultFeeBP = fee;
        emit DefaultFeeChanged(_getOpId(), fee);
    }

    /// @notice Set the fee collection wallet
    function setWalletAddress(address _address) external onlySelf {
        require(_address != address(0), "SwaptoX: zero address");
        address oldWallet = walletAddress;
        walletAddress = _address;
        emit WalletAddressSet(_getOpId(), oldWallet, _address);
    }

    /// @notice Set execution swap contract
    /// @dev Overwriting existing versions is prohibited, ensuring that configured versions remain permanently available.
    function setSwapAddress(uint256 version, address _address) external onlySelf {
        require(_address != address(0), "SwaptoX: zero address");
        require(_address.code.length > 0, "SwaptoX: not contract");
        require(swapAddress[version] == address(0), "SwaptoX: Version already exists");
        swapAddress[version] = _address;
        emit SwapAddressSet(_getOpId(), version, _address);
    }

    /// @notice Configure token used for ladder discount calculation
    function setSwaptoXToken(address _address) external onlySelf {
        require(_address != address(0), "SwaptoX: zero address");
        require(_address.code.length > 0, "SwaptoX: not contract");
        SwaptoXToken = _address;
        emit SwaptoXTokenSet(_getOpId(), _address);
    }

    /**
     * @notice Update fee ladder tiers
     *
     * Design constraints:
     * - Maximum tiers limited to 6 to prevent excessive gas usage
     * - Amounts must be strictly ascending
     * - discount == 10000 is allowed and waives the fee for matched users
     */
    function setFeeLadder(FeeTier[] calldata fees) external onlySelf {
        uint len = fees.length;
        require(len <= 6, "SwaptoX: Too many tiers");
        delete feeTiers;
        for (uint i = 0; i < len; ++i) {
            require(10000 >= fees[i].discount, "SwaptoX: Cannot exceed 10000");
            if (i > 0) {
                require(fees[i].amount > fees[i-1].amount, "SwaptoX: Must be ascending");
            }
            feeTiers.push(fees[i]);
        }
        emit FeeLadderUpdated(_getOpId(), fees);
    }

    /// @notice Withdraw accumulated protocol fees to the configured treasury wallet.
    function ownerWithdraw(address token, uint256 amount) external onlySelf {
        require(walletAddress != address(0), "SwaptoX: wallet not configured");
        if (address(token) == ERC20Helper.ETH_ADDRESS) {
            ERC20Helper.safeTransferETH(walletAddress, amount);
        } else {
            ERC20Helper.safeTransfer(token, walletAddress, amount);
        }
        emit Withdraw(msg.sender, token, walletAddress, amount);
    }

    /* ---------------------------- View Functions --------------------------- */

    /**
     * @notice Calculate fee discount based on SwaptoXToken holdings
     *
     * @dev Iterates from highest tier to lowest tier so that
     * the first matched tier gives the maximum discount.
     * @return If 0 is returned, there is no discount.
     */
    function getFeeLadderDiscount(address account) public view returns (uint256) {
        uint256 len = feeTiers.length;
        if (!isLadderEnabled || SwaptoXToken == address(0) || len == 0) return 0;
        uint256 balance = ERC20Helper.balanceOf(SwaptoXToken, account);
        if (balance == 0) return 0;
        // Reverse iteration avoids extra comparisons
        for (uint256 i = len; i > 0; i--) {
            uint256 idx = i - 1;
            if (balance >= feeTiers[idx].amount) {
                return uint256(feeTiers[idx].discount);
            }
        }
        return 0;
    }

    /**
     * @notice Get effective swap fee in basis points
     *
     * Fee priority:
     * 1. Fee-exempt token
     * 2. Custom token fee
     * 3. Default fee
     */
    function getTokenFeeBP(address token) public view returns (uint256) {
        uint256 feeBP;
        if (isFeeExemptToken[token]) {
            return 0;
        }

        if (customFeeBP[token] != 0) {
            feeBP = customFeeBP[token];
        } else {
            feeBP = defaultFeeBP;
        }

        return feeBP;
    }

    /**
     * @notice Get effective swap fee in basis points
     *
     * Ladder discount is applied last. A 10000 BP discount returns a zero fee by design.
     */
    function getSwapFeeBP(address account, address token) public view returns (uint256) {
        uint256 baseFee = getTokenFeeBP(token);
        if (baseFee > 0) {
            uint256 discount = getFeeLadderDiscount(account);
            if (discount > 0) {
                baseFee = (baseFee * (10000 - discount)) / 10000;
            }
        }
        return baseFee;
    }

    /// @notice Returns effective fee and ladder configuration
    function getSwapFeeLadder(address account, address token) public view returns (uint256 effectiveFeeBP, FeeTier[] memory ladder) {
        return (getSwapFeeBP(account, token), feeTiers);
    }

    /// @notice Calculate actual swap amount after deducting fee
    function getActualSwapAmount(address sender, address token, uint256 amount) public view returns (uint256 actualSwapAmount, uint256 feeAmount) {
        uint256 feeBP = getSwapFeeBP(sender, token);
        feeAmount = (amount * feeBP / 10000);
        actualSwapAmount = amount - feeAmount;
    }

    /* ---------------------------- Ownership helpers --------------------------- */

    /// @notice EOA wallets are permitted to be set as administrators, but this setting becomes locked once switched to a contract address.
    function transferOwnership(address newOwner) public onlySelf {
        require(admin.code.length == 0, "SwaptoX: The admin account has been locked");
        require(newOwner != address(0), "SwaptoX: new owner cannot be zero");
        address oldOwner = admin;
        admin = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

contract InviterContract {

    event InviterBound(address indexed user, address indexed inviter);
    event InviterFeePaid(address indexed user, address indexed inviter, address indexed token, uint256 rewardAmount, uint256 swapVolume);
    event InviterFeeFailed(address indexed user, address indexed inviter, address indexed token, uint256 rewardAmount, uint256 swapVolume);

    /// @notice user => inviter mapping (can only be bound once)
    mapping(address => address) public inviterOf;
    /// @notice inviter => number of successful invite bindings
    mapping(address => uint256) public inviteCount;

    /// @notice return inviter reward percentage based on invite count
    /// @dev value represents percentage of the swap fee (30% ~ 50%)
    function getRewardBP(address inviter) public view returns (uint256){
        uint256 count = inviteCount[inviter];
        if (count < 50) return 3000;
        if (count < 100) return 3500;
        if (count < 200) return 4000;
        if (count < 300) return 4500;
        return 5000;
    }

    /// @notice bind inviter for msg.sender
    /// @dev
    /// - can only bind once
    /// - invalid inviters are ignored
    /// - usually called before a successful swap execution
    function bindInviter(address inviter) internal {
        if (inviter == address(0) || inviter == msg.sender) return;// reject invalid inviters
        if (inviterOf[msg.sender] != address(0)) return;// inviter already bound
        inviterOf[msg.sender] = inviter;
        inviteCount[inviter]++;// increase inviter statistics
        emit InviterBound(msg.sender, inviter);
    }

    /// @notice distribute inviter reward from swap fee
    /// @dev
    /// - does NOT revert on transfer failure
    /// - swap execution should never be blocked by inviter payout
    /// - supports both native ETH and ERC20 tokens
    function awardInviter(address token, uint256 swapVolume, uint feeAmount) internal {
        if (feeAmount < 100) return; // Skip tiny payouts (<100 units) to avoid wasting gas
        address inviter = inviterOf[msg.sender];
        if (inviter == address(this) || inviter == address(0)) return;
        uint inviterFeeAmount = feeAmount * getRewardBP(inviter) / 10000;
        bool success;
        if (token == ERC20Helper.ETH_ADDRESS) {
            // limited gas prevents complex reentrancy patterns
            (success, ) = payable(inviter).call{value: inviterFeeAmount, gas: 30000}("");
        } else {
            // low-level ERC20 transfer for maximum compatibility
            (bool ok, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, inviter, inviterFeeAmount));
            success = ERC20Helper.isERC20Success(ok, data);
        }
        if (success) {
            emit InviterFeePaid(msg.sender, inviter, token, inviterFeeAmount, swapVolume);
        } else {
            emit InviterFeeFailed(msg.sender, inviter, token, inviterFeeAmount, swapVolume);
        }
    }
}

/* -------------------------------------------------------------------------- */
/* ------------------------------- Main Contract ---------------------------- */
/* -------------------------------------------------------------------------- */

struct SwapParameter {
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 amountMinOut;
    address recipient;
    bytes swapData;
    bytes permitData;
}

interface IWETH {
    function deposit() external payable;
    function withdraw(uint wad) external;
}

interface SwapExecutor {
    function entered(address sender, address tokenIn, uint256 amountMinOut, bytes calldata data, address recipient) external;
}

contract SwaptoXRouter is OwnerContract, InviterContract {

    event Swapped(address indexed sender, address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut, address recipient);
    event Deposited(address indexed sender, uint256 amount);

    address public immutable WETH;

    constructor(address _WETH, address _admin, uint256 _freeMonth) OwnerContract(_admin, _freeMonth) {
        require(_WETH != address(0), "SwaptoX: WETH cannot be zero");
        require(_WETH.code.length > 0, "SwaptoX: WETH not contract");
        WETH = _WETH;
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    uint256 private unlocked = 1;
    modifier nonReentrant() {
        require(unlocked == 1, "SwaptoX: LOCKED");
        unlocked = 2;
        _;
        unlocked = 1;
    }

    /// @notice Deadline validator modifier used by external entrypoints.
    modifier ensure(uint deadline) {
        require(deadline >= block.timestamp, "SwaptoX: deadline expired");
        _;
    }


    /// @notice Pull tokens from the caller into this contract and return the real received amount.
    /// @dev Supports tokens that impose transfer taxes as we compute the delta on balance.
    function safetyTransferIn(address token, uint256 value) internal returns (uint256) {
        uint256 balanceBefore = ERC20Helper.balanceOf(token, address(this));
        ERC20Helper.safeTransferFrom(token, msg.sender, address(this), value);
        uint256 balanceAfter = ERC20Helper.balanceOf(token, address(this));
        require((balanceAfter - balanceBefore) > 0, "SwaptoX: invalid transfer amount");
        return balanceAfter - balanceBefore;
    }

    /**
     * @notice Internal helper that transfers `amountIn` of tokenIn to the external swap executor (swapAddress),
     *         triggers the executor callback, and validates that the recipient has received at least amountMinOut.
     *
     * @dev This mirrors UniswapV2-like flow: transfer tokens to executor, call executor.entered(...), then check balance delta.
     */
    function _executeSwap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountMinOut,
        bytes calldata swapData,
        address recipient
    ) internal returns (uint256 amountOut) {
        (uint256 version, bytes memory data) = abi.decode(swapData, (uint256, bytes));
        address _toAddress = swapAddress[version];
        require(_toAddress != address(0), "SwaptoX: Swap Version Error");
        ERC20Helper.safeTransfer(tokenIn, _toAddress, amountIn);
        uint256 balanceBefore = ERC20Helper.balanceOf(tokenOut, recipient);
        SwapExecutor(_toAddress).entered(
            msg.sender,
            tokenIn,
            amountMinOut,
            data,
            recipient
        );
        uint256 balanceAfter = ERC20Helper.balanceOf(tokenOut, recipient);
        require(balanceAfter >= (balanceBefore + amountMinOut), "SwaptoX: insufficient output received");
        amountOut = balanceAfter - balanceBefore;
    }

    /// @notice token -> token swap variant (ERC20 in, ERC20 out).
    function token2token(
        SwapParameter calldata desc,
        uint256 realInput
    ) internal returns (uint256 amountOut) {
        (uint actualSwapAmount, uint feeAmount) = getActualSwapAmount(msg.sender, desc.tokenIn, realInput);
        amountOut = _executeSwap(
            desc.tokenIn,
            desc.tokenOut,
            actualSwapAmount,
            desc.amountMinOut,
            desc.swapData,
            desc.recipient
        );
        awardInviter(desc.tokenIn, realInput, feeAmount);
    }

    /// @notice native ETH -> token swap variant: wrap ETH into WETH then execute swap.
    function ETH2token(
        SwapParameter calldata desc,
        uint256 realInput
    ) internal returns (uint256 amountOut) {
        (uint actualSwapAmount, uint feeAmount) = getActualSwapAmount(msg.sender, desc.tokenIn, realInput);
        IWETH(WETH).deposit{value: actualSwapAmount}();
        amountOut = _executeSwap(
            WETH,
            desc.tokenOut,
            actualSwapAmount,
            desc.amountMinOut,
            desc.swapData,
            desc.recipient
        );
        awardInviter(desc.tokenIn, realInput, feeAmount);
    }

    /// @notice token -> native ETH swap variant: swap to WETH then unwrap and forward native ETH to recipient.
    function token2ETH(
        SwapParameter calldata desc,
        uint256 realInput
    ) internal returns (uint256 amountOut) {
        (uint actualSwapAmount, uint feeAmount) = getActualSwapAmount(msg.sender, desc.tokenIn, realInput);
        amountOut = _executeSwap(
            desc.tokenIn,
            WETH,
            actualSwapAmount,
            desc.amountMinOut,
            desc.swapData,
            address(this)
        );
        IWETH(WETH).withdraw(amountOut);
        ERC20Helper.safeTransferETH(desc.recipient, amountOut);
        awardInviter(desc.tokenIn, realInput, feeAmount);
    }

    /**
     * @notice Internal orchestrator that handles input validation, optional permit flows,
     *         dispatches to the appropriate swap variant, and emits Swapped event.
     * 
     * @dev Reentrancy-guarded. The original validation rules were preserved.
     */
    function _swap(
        SwapParameter calldata desc
    ) internal returns (uint256 amountOut) {
        require(
            desc.tokenIn != address(this) &&
            desc.tokenOut != address(this) &&
            desc.tokenIn != desc.tokenOut,
            "SwaptoX: invalid token"
        );        
        require(desc.recipient != address(this) && desc.recipient != address(0), "SwaptoX: invalid recipient");
        require(desc.amountIn > 0 && desc.amountMinOut > 0, "SwaptoX: amount must be > 0");

        uint256 realInput;

        if (address(desc.tokenIn) == ERC20Helper.ETH_ADDRESS) {
            require(msg.value > 0 && msg.value == desc.amountIn, "SwaptoX: invalid input");
            realInput = msg.value;
            if(desc.tokenOut == WETH){
                amountOut = _native2Wrapped(desc, realInput);
            }else{
                amountOut = ETH2token(desc, realInput);
            }
        } else {
            require(msg.value == 0, "SwaptoX: no ETH allowed for ERC20 input");
            if (desc.permitData.length > 0) {
                ERC20Helper.permit(desc.tokenIn, desc.permitData);
            }
            realInput = safetyTransferIn(desc.tokenIn, desc.amountIn);

            if (address(desc.tokenOut) == ERC20Helper.ETH_ADDRESS) {
                if (desc.tokenIn == WETH) {
                    amountOut = _wrapped2native(desc, realInput);
                }else{
                    amountOut = token2ETH(desc, realInput);
                }
            } else {
                amountOut = token2token(desc, realInput);
            }
        }

        emit Swapped(msg.sender, desc.tokenIn, desc.tokenOut, realInput, amountOut, desc.recipient);
    }

    /* --------------------------- External entrypoints ------------------------ */

    /**
     * @notice Public swap entrypoint. Caller provides deadline for optional anti-replay/anti-front-run.
     * @param desc SwapParameter describing the swap.
     * @param deadline Unix timestamp after which the call is invalid.
     * @param referral Address to bind as referral. address(0) binds the platform address permanently.
     * @return amountOut Output amount delivered.
     * @return gasUsed Gas consumed by the operation (approximate).
     */
    function swap(
        SwapParameter calldata desc,
        uint256 deadline,
        address referral
    ) external payable nonReentrant ensure(deadline) returns (uint256 amountOut, uint256 gasUsed) {
        uint256 gasBefore = gasleft();
        if (referral == address(0)) {
            bindInviter(address(this));
        }else{
            bindInviter(referral);
        }
        amountOut = _swap(desc);
        unchecked {
            gasUsed = gasBefore - gasleft();
        }
    }

    // @notice Wraps native ETH into WETH (Wrapped Token)
    function _native2Wrapped(
        SwapParameter calldata desc,
        uint256 realInput
    ) internal returns (uint256 amountOut) {
        IWETH(WETH).deposit{value: realInput}();
        uint256 balanceBefore = ERC20Helper.balanceOf(WETH, desc.recipient);
        ERC20Helper.safeTransfer(WETH, desc.recipient, realInput);
        uint256 balanceAfter = ERC20Helper.balanceOf(WETH, desc.recipient);
        require(balanceAfter >= (balanceBefore + desc.amountMinOut), "SwaptoX: insufficient output received");
        amountOut = balanceAfter - balanceBefore;
    }

    // @notice Unwraps WETH into native ETH
    function _wrapped2native(
        SwapParameter calldata desc,
        uint256 realInput
    ) internal returns (uint256 amountOut) {
        require(realInput >= desc.amountMinOut, "SwaptoX: amountMinOut insufficient");
        IWETH(WETH).withdraw(realInput);
        ERC20Helper.safeTransferETH(desc.recipient, realInput);
        amountOut = realInput;
    }

}
