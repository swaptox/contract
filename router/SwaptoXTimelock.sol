// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;


/**
 * @title SwaptoXTimelock
 * @notice Timelocked governance with 2-of-3 owner approval and emergency guardian mechanism.
 *
 * @dev === TRUST MODEL & SECURITY ASSUMPTIONS ===
 *
 * This contract assumes that at least TWO owners remain honest and responsive under normal conditions.
 *
 * The guardian mechanism is NOT part of the normal governance flow. It is designed strictly as a
 * last-resort recovery mechanism in case a majority of owners (>=2) become permanently unavailable
 * (e.g., lost keys, inactivity, or catastrophic failure).
 *
 * === GUARDIAN ACTIVATION MODEL ===
 *
 * - Any owner can propose guardian activation.
 * - Activation is subject to a long delay (GUARDIAN_DELAY).
 * - During this delay, ANY active owner can cancel the activation at any time.
 *
 * Therefore:
 * - If at least TWO owners are active, guardian activation can always be prevented.
 * - Guardian can only become effective if governance is effectively stalled.
 *
 * === GUARDIAN POWERS ===
 *
 * Once activated, the guardian can propose ownership replacement operations.
 * These operations are still subject to:
 * - Timelock delay
 * - Owner execution
 *
 * The guardian CANNOT directly execute actions or bypass the timelock.
 *
 * === IMPORTANT SECURITY NOTE ===
 *
 * This system DOES NOT protect against malicious owners.
 * If at least two owners collude, they retain full control of the system.
 *
 * Guardian is designed to restore system liveness, NOT to override an operational governance process.
 */



/**
 * @title Ownable3
 * @dev Implementation of a 3-owner multisig with a specialized Guardian rescue mechanism.
 * The rescue mechanism is designed for cases where 2 out of 3 owners are unresponsive.
 */
contract Ownable3 {

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    event GuardianActivationProposed(address indexed proposer, uint256 timestamp);
    event GuardianActivationExecuted(address indexed executor, uint256 timestamp);
    event GuardianActivationCancelled(address indexed canceller, uint256 timestamp);

    event GuardianOwnershipTransferProposed(address indexed proposer, address indexed oldOwner, address indexed newOwner);
    event GuardianOwnershipTransferExecuted(address indexed executor, address indexed oldOwner, address indexed newOwner);
    event GuardianOwnershipTransferCancelled(address indexed canceller, address indexed oldOwner, address indexed newOwner);


    struct PendingOwnershipTransfer {
        address oldOwner;
        address newOwner;
        address proposer;
        uint256 executeAfter;
        bool exists;
    }

    /// @notice Minimum delay for standard Timelock operations
    uint256 public constant MIN_DELAY = 3 days;

    /// @notice Fixed set of 3 owners
    address[3] public owners;

    /// @notice Guardian address (deployer)
    address public guardian;
    /// @notice Status flag for the Guardian rescue mode
    bool public isGuardianActive;
    /// @notice Timestamp when the Guardian mode can be activated (10-day safety window)
    uint256 public guardianActivationTime;
    /// @notice Pending ownership transfer initiated by guardian
    PendingOwnershipTransfer public pendingTransfer;

    modifier onlyOwner() {
        require(_isOwner(msg.sender), "NOT_OWNER");
        _;
    }

    function _isOwner(address account) internal view returns (bool) {
        return (account == owners[0] || account == owners[1] || account == owners[2]);
    }


    uint256 private _reentrancyStatus = 1;
    modifier nonReentrant() {
        require(_reentrancyStatus != 2, "REENTRANCY");
        _reentrancyStatus = 2;
        _;
        _reentrancyStatus = 1;
    }

    constructor(address owner1, address owner2, address owner3) {
        require(owner1 != address(0) && owner2 != address(0) && owner3 != address(0), "ZERO_ADDRESS");
        require(owner1 != owner2 && owner1 != owner3 && owner2 != owner3, "DUPLICATE_OWNERS");
        require(owner1 != msg.sender && owner2 != msg.sender && owner3 != msg.sender, "GUARDIAN_CONFLICT");
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        guardian = msg.sender;
    }

    /* ---------------------------- Standard Ownership --------------------------- */

    /**
     * @notice Replaces an owner address via standard Timelock execution.
     * @dev Must be called by the contract itself (address(this)) after 2-of-3 consensus.
     */
    function transferOwnership(address oldOwner, address newOwner) external {
        require(msg.sender == address(this), "ONLY_SELF");
        require(oldOwner != newOwner, "SAME_OWNER");
        require(newOwner != address(0), "ZERO_ADDRESS");
        require(_isOwner(oldOwner), "INVALID_OLD_OWNER");
        require(!_isOwner(newOwner), "ALREADY_OWNER");
        _transferOwnership(oldOwner, newOwner);
    }

    function _transferOwnership(address oldOwner, address newOwner) internal {
        for (uint256 i = 0; i < 3; ) {
            if (owners[i] == oldOwner) {
                owners[i] = newOwner;
                emit OwnershipTransferred(oldOwner, newOwner);
                return;
            }
            unchecked { ++i; }
        }
        revert("OWNER_NOT_FOUND");
    }


    /* ---------------------------- Rescue Mechanism --------------------------- */

    /// @dev Long delay ensures sufficient time for any active owner to cancel activation.
    /// If governance is functional, guardian activation is always preventable.
    uint256 public constant GUARDIAN_DELAY = 10 days;

    /// @dev Public notice period for ownership transfer proposals (30 days).
    /// This extended delay ensures sufficient time for monitoring, review,
    /// and intervention by any remaining active owners or off-chain governance.
    uint256 public constant OWNERSHIP_TRANSFER_NOTICE_PERIOD = 30 days;

    /**
     * @notice Propose activation of the guardian mechanism
     *
     * @dev This is a FAILSAFE mechanism and should only be used if governance is stalled.
     *
     * Security properties:
     * - Activation is delayed by GUARDIAN_DELAY
     * - ANY owner can cancel during the delay period
     *
     * Implication:
     * - If at least TWO owners are responsive, activation CANNOT succeed
     * - Activation only succeeds when governance is effectively non-functional
     *
     * This prevents a single malicious owner from unilaterally activating guardian powers.
     */
    function proposeGuardianActivation() external onlyOwner {
        require(!isGuardianActive && guardianActivationTime == 0, "GUARDIAN_ALREADY_PROPOSED");
        guardianActivationTime = block.timestamp + GUARDIAN_DELAY;
        emit GuardianActivationProposed(msg.sender, block.timestamp);
    }

    /**
     * @notice Finalizes Guardian activation after the 10-day window.
     */
    function executeGuardianActivation() external onlyOwner {
        require(guardianActivationTime != 0, "NOT_PROPOSED");
        require(!isGuardianActive, "ALREADY_OPEN");
        require(block.timestamp >= guardianActivationTime, "TIMELOCK");
        isGuardianActive = true;
        emit GuardianActivationExecuted(msg.sender, block.timestamp);
    }

    /**
     * @notice Cancel pending guardian activation
     *
     * @dev This function is the primary safeguard against malicious or accidental
     * guardian activation proposals.
     *
     * Any active owner can cancel at any time before activation.
     *
     * This guarantees that as long as governance is functional (>=2 active owners),
     * the guardian mechanism cannot be enabled.
     */
    function cancelGuardianActivation() public onlyOwner {
        guardianActivationTime = 0;
        isGuardianActive = false;
        if (pendingTransfer.exists) {
            delete pendingTransfer;
        }
        emit GuardianActivationCancelled(msg.sender, block.timestamp);
    }

    /**
     * @notice Propose ownership transfer (guardian recovery flow)
     *
     * @dev This operation uses an EXTENDED timelock delay (30 days),
     * significantly longer than standard operations.
     *
     * Rationale:
     * - Ownership changes are highly sensitive
     * - Provides a long public notice window
     * - Allows any remaining active owner to intervene
     * - Enables off-chain monitoring systems to react
     *
     * This delay acts as a social and technical safeguard against
     * unexpected or malicious ownership changes.
     */
    function proposeGuardianOwnershipTransfer(address oldOwner, address newOwner) external {
        require(isGuardianActive, "GUARDIAN_NOT_ACTIVE");
        require(msg.sender == guardian, "ONLY_GUARDIAN");
        require(msg.sender != newOwner, "INVALID_NEW_OWNER");
        require(oldOwner != newOwner, "SAME_OWNER");
        require(!pendingTransfer.exists, "PENDING_EXISTS");
        require(newOwner != address(0), "ZERO_ADDRESS");
        require(_isOwner(oldOwner), "INVALID_OLD_OWNER");
        require(!_isOwner(newOwner), "ALREADY_OWNER");
        pendingTransfer = PendingOwnershipTransfer({
            oldOwner: oldOwner,
            newOwner: newOwner,
            proposer: msg.sender,
            executeAfter: block.timestamp + OWNERSHIP_TRANSFER_NOTICE_PERIOD,
            exists: true
        });
        emit GuardianOwnershipTransferProposed(msg.sender, oldOwner, newOwner);
    }

    /**
     * @notice Executed by the remaining active owner to confirm the Guardian's rescue proposal.
     */
    function executeGuardianOwnershipTransfer() external onlyOwner {
        require(isGuardianActive, "GUARDIAN_NOT_ACTIVE");
        require(pendingTransfer.exists, "NO_PENDING");
        require(pendingTransfer.oldOwner != pendingTransfer.newOwner, "SAME_OWNER");
        require(guardian != pendingTransfer.newOwner, "INVALID_NEW_OWNER");
        require(block.timestamp >= pendingTransfer.executeAfter, "TIMELOCK");
        require(!_isOwner(pendingTransfer.newOwner), "ALREADY_OWNER");
        bool replaced = false;
        for (uint i = 0; i < 3; i++) {
            if (owners[i] == pendingTransfer.oldOwner) {
                emit GuardianOwnershipTransferExecuted(msg.sender, pendingTransfer.oldOwner, pendingTransfer.newOwner);
                owners[i] = pendingTransfer.newOwner;
                replaced = true;
                break;
            }
        }
        require(replaced, "OWNER_NOT_FOUND");
        cancelGuardianActivation();// Cleanup: Guardian is deactivated once the system is restored to 2/3 health
    }

    /**
     * @notice Cancel pending guardian transfer
     */
    function cancelGuardianOwnershipTransfer() public onlyOwner {
        if (pendingTransfer.exists) {
            emit GuardianOwnershipTransferCancelled(msg.sender, pendingTransfer.oldOwner, pendingTransfer.newOwner);
            delete pendingTransfer;
        }
    }

}



/* ---------------------------- Whitelist Operator --------------------------- */
interface ITimelockActions {
    function transferOwnership(address oldOwner, address newOwner) external;
    function setAllowedTargets(address contractAddr, bool isopen) external;
    function setAllowedSelectors(address contractAddr, bytes4 selector, bool isopen) external;
}

/**
 * @dev Selector + target whitelist controlled via timelock (self-call)
 */
contract ConstantOperator {

    event AllowedTargetUpdated(address indexed target, bool isAllowed);
    event AllowedSelectorUpdated(address indexed target, bytes4 selector, bool isAllowed);

    mapping(address => mapping(bytes4 => bool)) public allowedSelectors;
    mapping(address => bool) public allowedTargets;

    constructor() {
        // Initialize core timelock functions in whitelist
        allowedTargets[address(this)] = true;
        allowedSelectors[address(this)][ITimelockActions.transferOwnership.selector] = true;
        allowedSelectors[address(this)][ITimelockActions.setAllowedTargets.selector] = true;
        allowedSelectors[address(this)][ITimelockActions.setAllowedSelectors.selector] = true;
    }

    function setAllowedTargets(address target, bool isAllowed) external {
        require(msg.sender == address(this), "ONLY_TIMELOCK");
        require(target != address(this), "SELF_PROTECTED");
        require(target.code.length > 0, "NOT_CONTRACT");
        allowedTargets[target] = isAllowed;
        emit AllowedTargetUpdated(target, isAllowed);
    }

    function setAllowedSelectors(address target, bytes4 selector, bool isAllowed) external {
        require(msg.sender == address(this), "ONLY_TIMELOCK");
        require(target != address(this), "SELF_PROTECTED");
        require(allowedTargets[target], "TARGET_NOT_ALLOWED");
        allowedSelectors[target][selector] = isAllowed;
        emit AllowedSelectorUpdated(target, selector, isAllowed);
    }

}


/* ---------------------------- Main Timelock --------------------------- */

/**
 * @title SwaptoXTimelock
 *
 * @dev
 * - 2-of-3 multisig (proposer != executor)
 * - Timelock enforced execution
 * - Selector + target whitelist enforcement
 *
 * ⚠ External call model:
 * Target contracts MUST enforce access control (e.g., onlySelf)
 *
 * === EXECUTION CONTEXT ===
 *
 * During operation execution, `currentOpId` exposes the active operation ID.
 * This allows integrated contracts to perform on-chain introspection
 * and associate state changes with a specific governance action.
 *
 * This value is ephemeral and MUST NOT be used for access control.
 */
contract SwaptoXTimelock is Ownable3, ConstantOperator {

    event OperationProposed(address indexed proposer, bytes32 indexed opId, address indexed target, bytes4 selector, bytes data);
    event OperationExecuted(address proposer, address indexed executor, bytes32 indexed opId, address indexed target, bytes4 selector, bytes data);
    event OperationCancelled(address proposer, address indexed canceller, bytes32 indexed opId, address indexed target, bytes4 selector, bytes data);

    struct Operation {
        bytes32 id;            // operation id (keccak256(target, selector, data, salt)) Must be unique; enforced by ALREADY_EXISTS check
        bytes4 selector;       // target function selector
        bytes data;            // ABI-encoded arguments (without selector)
        uint256 unlockTime;    // timestamp when execution is allowed
        bool executed;         // execution flag
        address proposer;      // proposer address
        address target;        // The contract address to be operated on
    }

    /// @notice Operation storage
    mapping(bytes32 => Operation) public operations;

    /// @notice Pending operation list (for off-chain/UI enumeration)
    bytes32[] public pendingOps;


    constructor(address owner1, address owner2, address owner3) Ownable3(owner1, owner2, owner3) {}


    /** @notice Currently executing operation ID (ephemeral execution context)
    *
    * @dev This value is set immediately before an operation is executed
    * and cleared immediately after execution completes.
    *
    * Purpose:
    * - Enables target contracts to introspect the originating timelock operation
    * - Improves on-chain traceability and auditability
    * - Allows downstream contracts to associate state changes with a specific opId
    *
    * Security properties:
    * - This value MUST NOT be used for authorization or access control
    * - It is purely informational and may be manipulated within the same transaction context
    * - Only valid during the execution of a timelock operation
    *
    * Lifecycle:
    * - Set in `execute()` before external call
    * - Cleared after execution (even if call succeeds)
    *
    * Note:
    * - Consumers should treat this as a best-effort context signal, not a trusted input
    */
    bytes32 public currentOpId;


    /**
    * @notice Propose a new admin operation
    * @param selector Function selector of the target admin function
    * @param data ABI-encoded parameters (without selector)
    * @param salt Arbitrary user-provided value to ensure unique opIds
    *
    * @dev
    * - The correctness of `data` is enforced implicitly by ABI decoding
    *   during execution (invalid encoding will revert)
    */
    function propose(address target, bytes4 selector, bytes calldata data, bytes32 salt) external onlyOwner returns (bytes32 opId){
        require(allowedTargets[target], "TARGET_NOT_ALLOWED");
        require(allowedSelectors[target][selector], "SELECTOR_NOT_ALLOWED");
        // A maximum of 256 tasks can exist at a time. Tasks must be `cancel` or `execute` before another task can be added.
        require(pendingOps.length < 256, "PENDING_TASK_UPPER_LIMIT");
        opId = keccak256(abi.encode(target, selector, data, salt));
        // Prevent overwriting an active operation
        require(operations[opId].id == 0, "ALREADY_EXISTS");
        operations[opId] = Operation({
            id: opId,
            selector: selector,
            data: data,
            unlockTime: block.timestamp + MIN_DELAY,
            executed: false,
            proposer: msg.sender,
            target: target
        });
        pendingOps.push(opId);
        emit OperationProposed(msg.sender, opId, target, selector, data);
    }

    /**
    * @notice Execute a queued operation after timelock
    * @param opId Operation identifier
    *
    * @dev
    * - This performs a low-level call to `address(this)`
    * - Target functions MUST enforce `onlySelf`
    */
    function execute(bytes32 opId) external onlyOwner nonReentrant {
        Operation storage op = operations[opId];
        require(op.id != 0, "NOT_FOUND");
        require(msg.sender != op.proposer, "PROPOSER_CANNOT_EXECUTE");
        require(allowedTargets[op.target], "TARGET_NOT_ALLOWED");
        require(allowedSelectors[op.target][op.selector], "SELECTOR_NOT_ALLOWED");
        // If proposer is removed, the operation becomes permanently non-executable.
        // It can only be cancelled after the protection window expires.
        require(_isOwner(op.proposer), "INVALID_PROPOSER");
        require(!op.executed, "ALREADY_EXECUTED");
        require(block.timestamp >= op.unlockTime, "TIMELOCK");
        require(op.target.code.length > 0, "TARGET_NOT_CONTRACT");
        // Effects
        op.executed = true;
        // Expose execution context for downstream contracts (audit / trace only)
        currentOpId = opId;
        // Interaction
        (bool success, bytes memory returnData) = op.target.call(bytes.concat(op.selector, op.data));
        // Always clear execution context after external call
        currentOpId = 0;
        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    revert(add(returnData, 32), mload(returnData))
                }
            } else {
                revert("CALL_FAILED");
            }
        }
        _removePending(opId);
        emit OperationExecuted(op.proposer, msg.sender, opId, op.target, op.selector, op.data);
    }

    /**
    * @notice Cancel a pending operation
    * @param opId Operation identifier
    *
    * @dev
    * - Within 2 * MIN_DELAY (6 days): only proposer can cancel
    * - After that: Any active owner can cancel during the delay period
    *
    * Rationale:
    * - Prevent immediate cancellation after timelock unlock
    */
    function cancel(bytes32 opId) external onlyOwner {
        Operation storage op = operations[opId];
        require(op.id != 0, "NOT_FOUND");
        require(!op.executed, "ALREADY_EXECUTED");
        // Protection window (first 6 days)
        if (block.timestamp < (op.unlockTime + MIN_DELAY)) {
            require(msg.sender == op.proposer || !_isOwner(op.proposer), "ONLY_PROPOSER");
        }
        emit OperationCancelled(op.proposer, msg.sender, opId, op.target, op.selector, op.data);
        delete operations[opId];
        _removePending(opId);
    }

    function _removePending(bytes32 opId) internal {
        bytes32[] storage list = pendingOps;
        uint256 length = list.length;
        for (uint256 i = 0; i < length; ) {
            if (list[i] == opId) {
                list[i] = list[length - 1];
                list.pop();
                return;
            }
            unchecked { ++i; }
        }
    }


    /* ---------------------------- View Functions --------------------------- */


    function getOwners() public view returns (address[3] memory) {
        return owners;
    }

    function isExecutable(bytes32 opId) external view returns (bool) {
        Operation storage op = operations[opId];
        return (
            op.id != 0 &&
            !op.executed &&
            block.timestamp >= op.unlockTime &&
            _isOwner(op.proposer)
        );
    }

    function getTransferOwnership() external view returns (PendingOwnershipTransfer memory) {
        return pendingTransfer;
    }

    function getOperation(bytes32 opId) external view returns (Operation memory) {
        return operations[opId];
    }

    function getPendingOps() public view returns (Operation[] memory) {
        uint256 length = pendingOps.length;
        Operation[] memory _pendingOps = new Operation[](length);
        for (uint256 i = 0; i < length; ) {
            _pendingOps[i] = operations[pendingOps[i]];
            unchecked { ++i; }
        }
        return _pendingOps;
    }

    struct GuardianInfo {
        address guardian;
        bool isGuardianActive;
        uint256 guardianActivationTime;
    }
    function getGuardianInfo() public view returns (GuardianInfo memory) {
        GuardianInfo memory _guardianInfo = GuardianInfo({
            guardian: guardian,
            isGuardianActive: isGuardianActive,
            guardianActivationTime: guardianActivationTime
        });
        return _guardianInfo;
    }

    function getUiViewData() external view returns (address[3] memory, Operation[] memory, PendingOwnershipTransfer memory, GuardianInfo memory, uint256) {
        return (getOwners(), getPendingOps(), pendingTransfer, getGuardianInfo(), block.timestamp);
    }

}
