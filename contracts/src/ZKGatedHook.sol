// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";
import {ModifyLiquidityParams, SwapParams} from "v4-core/types/PoolOperation.sol";
import {IAuthorizationVerifier} from "./IAuthorizationVerifier.sol";

/// @title ZKGatedHook — Uniswap V4 Hook that gates swaps behind ZK proofs
/// @notice Only agents with valid Groth16 ZK authorization proofs can swap through pools using this hook.
///         Combines Uniswap V4 Hooks with privacy-preserving access control.
///         The hook calls an on-chain AuthorizationVerifier to validate proofs.
///         Once verified, an address is cached (with TTL) to avoid re-proving on every swap.
/// @dev Deployed via CREATE2 with address flags encoding BEFORE_SWAP_FLAG (bit 7).
contract ZKGatedHook is IHooks {
    // ──────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────
    error HookNotImplemented();
    error OnlyPoolManager();
    error NotAuthorized();
    error InvalidProof();
    error ZeroAddress();
    error ProofAlreadyUsed();
    error AgentBindingMismatch();
    error PreAuthDisabled();

    // ──────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────
    event AgentAuthorized(address indexed agent, uint256 indexed agentId, uint256 indexed policyCommitment);
    event AgentRevoked(address indexed agent);
    event AgentBound(uint256 indexed agentId, address indexed agent);
    event PreAuthPermanentlyDisabled();

    // ──────────────────────────────────────────────────────────────
    // Constants
    // ──────────────────────────────────────────────────────────────

    /// @notice Authorization cache TTL (24 hours)
    uint256 public constant AUTH_TTL = 24 hours;

    // ──────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────

    /// @notice The Uniswap V4 PoolManager
    IPoolManager public immutable poolManager;

    /// @notice The Groth16 ZK verifier for agent authorization proofs
    IAuthorizationVerifier public immutable verifier;

    /// @notice Hook owner (can revoke authorizations)
    address public immutable owner;

    /// @notice Authorization expiry timestamp per address (SEC-H02 fix)
    mapping(address => uint256) public authorizedUntil;

    /// @notice Proof nullifier — each proof hash can only be used once (SEC-H01 fix)
    mapping(bytes32 => bool) public usedProofHashes;

    /// @notice Agent ID to Ethereum address binding (SEC-H01 fix)
    /// @dev If set, only the bound address can use proofs for that agentId
    mapping(uint256 => address) public agentBinding;

    /// @notice Total number of currently authorized agents
    uint256 public authorizedCount;

    /// @notice Whether preAuthorize is permanently disabled (SEC-M01 fix)
    bool public preAuthDisabled;

    // ──────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(IPoolManager _poolManager, IAuthorizationVerifier _verifier, address _owner) {
        if (address(_poolManager) == address(0)) revert ZeroAddress();
        if (address(_verifier) == address(0)) revert ZeroAddress();
        if (_owner == address(0)) revert ZeroAddress();

        poolManager = _poolManager;
        verifier = _verifier;
        owner = _owner;

        // Validate hook address flags
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    // ──────────────────────────────────────────────────────────────
    // Hook Permissions
    // ──────────────────────────────────────────────────────────────

    function getHookPermissions() public pure returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // ──────────────────────────────────────────────────────────────
    // Core: beforeSwap — ZK Gate
    // ──────────────────────────────────────────────────────────────

    /// @notice Called by PoolManager before every swap. Verifies ZK authorization.
    /// @dev If sender has a non-expired cached authorization, allows immediately.
    ///      Otherwise, decodes a Groth16 proof from hookData and verifies on-chain.
    ///      Each proof can only be used once (nullifier). Agent ID must be bound to sender if binding exists.
    function beforeSwap(
        address sender,
        PoolKey calldata, /* key */
        SwapParams calldata, /* params */
        bytes calldata hookData
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        if (msg.sender != address(poolManager)) revert OnlyPoolManager();

        // Check cached authorization (with TTL)
        if (block.timestamp < authorizedUntil[sender]) {
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        // No valid cache — verify proof
        _verifyAndAuthorize(sender, hookData);

        return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    /// @dev Internal: decode, nullify, bind-check, verify, and cache authorization.
    function _verifyAndAuthorize(address sender, bytes calldata hookData) internal {
        if (hookData.length == 0) revert NotAuthorized();

        // Proof nullifier — prevent replay (SEC-H01)
        bytes32 proofHash = keccak256(hookData);
        if (usedProofHashes[proofHash]) revert ProofAlreadyUsed();
        usedProofHashes[proofHash] = true;

        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC,
            uint256[2] memory pubSignals
        ) = abi.decode(hookData, (uint256[2], uint256[2][2], uint256[2], uint256[2]));

        // Agent binding check — if agentId is bound, sender must match (SEC-H01)
        address boundAddr = agentBinding[pubSignals[0]];
        if (boundAddr != address(0) && boundAddr != sender) revert AgentBindingMismatch();

        // Verify Groth16 proof on-chain
        if (!verifier.verifyProof(pA, pB, pC, pubSignals)) revert InvalidProof();

        // Cache authorization with TTL (SEC-H02)
        authorizedUntil[sender] = block.timestamp + AUTH_TTL;
        authorizedCount++;

        emit AgentAuthorized(sender, pubSignals[0], pubSignals[1]);
    }

    // ──────────────────────────────────────────────────────────────
    // Admin: Agent binding
    // ──────────────────────────────────────────────────────────────

    /// @notice Bind an agent ID to a specific Ethereum address (owner only)
    /// @dev Once bound, only that address can use proofs for this agentId
    /// @param agentId The agent ID from the ZK proof
    /// @param agent The Ethereum address to bind
    function bindAgent(uint256 agentId, address agent) external {
        require(msg.sender == owner, "Not owner");
        agentBinding[agentId] = agent;
        emit AgentBound(agentId, agent);
    }

    // ──────────────────────────────────────────────────────────────
    // Admin: Revoke authorization
    // ──────────────────────────────────────────────────────────────

    /// @notice Revoke an agent's cached authorization (owner only)
    /// @param agent The address to revoke
    function revokeAuthorization(address agent) external {
        require(msg.sender == owner, "Not owner");
        require(authorizedUntil[agent] > block.timestamp, "Not authorized");
        authorizedUntil[agent] = 0;
        authorizedCount--;
        emit AgentRevoked(agent);
    }

    // ──────────────────────────────────────────────────────────────
    // Pre-authorize (can be permanently disabled) (SEC-M01)
    // ──────────────────────────────────────────────────────────────

    /// @notice Pre-authorize an address without requiring a ZK proof (owner only)
    /// @param agent The address to authorize
    function preAuthorize(address agent) external {
        require(msg.sender == owner, "Not owner");
        if (preAuthDisabled) revert PreAuthDisabled();
        if (block.timestamp >= authorizedUntil[agent]) {
            authorizedUntil[agent] = block.timestamp + AUTH_TTL;
            authorizedCount++;
            emit AgentAuthorized(agent, 0, 0);
        }
    }

    /// @notice Permanently disable preAuthorize — cannot be re-enabled (owner only)
    function disablePreAuth() external {
        require(msg.sender == owner, "Not owner");
        preAuthDisabled = true;
        emit PreAuthPermanentlyDisabled();
    }

    // ──────────────────────────────────────────────────────────────
    // View: check if authorized (convenience)
    // ──────────────────────────────────────────────────────────────

    /// @notice Check if an address is currently authorized
    function authorized(address agent) external view returns (bool) {
        return block.timestamp < authorizedUntil[agent];
    }

    // ──────────────────────────────────────────────────────────────
    // Unimplemented hooks — revert if called
    // ──────────────────────────────────────────────────────────────

    function beforeInitialize(address, PoolKey calldata, uint160) external pure override returns (bytes4) {
        revert HookNotImplemented();
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24) external pure override returns (bytes4) {
        revert HookNotImplemented();
    }

    function beforeAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function afterAddLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure override returns (bytes4, BalanceDelta) {
        revert HookNotImplemented();
    }

    function beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function afterRemoveLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure override returns (bytes4, BalanceDelta) {
        revert HookNotImplemented();
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata)
        external
        pure
        override
        returns (bytes4, int128)
    {
        revert HookNotImplemented();
    }

    function beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert HookNotImplemented();
    }
}
