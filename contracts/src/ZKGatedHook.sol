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
///         Once verified, an address is cached as authorized to avoid re-proving on every swap.
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

    // ──────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────
    event AgentAuthorized(address indexed agent, uint256 indexed agentId, uint256 indexed policyCommitment);
    event AgentRevoked(address indexed agent);
    event SwapGated(address indexed sender, bool authorized);

    // ──────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────

    /// @notice The Uniswap V4 PoolManager
    IPoolManager public immutable poolManager;

    /// @notice The Groth16 ZK verifier for agent authorization proofs
    IAuthorizationVerifier public immutable verifier;

    /// @notice Hook owner (can revoke authorizations)
    address public immutable owner;

    /// @notice Mapping of authorized addresses (cached after first ZK proof)
    mapping(address => bool) public authorized;

    /// @notice Total number of unique authorized agents
    uint256 public authorizedCount;

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

        // Validate hook address flags — the address must have BEFORE_SWAP_FLAG set
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
    /// @dev If sender is already authorized (cached), allows immediately.
    ///      Otherwise, decodes a Groth16 proof from hookData and verifies on-chain.
    ///      Proof format in hookData: abi.encode(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[2] pubSignals)
    function beforeSwap(
        address sender,
        PoolKey calldata, /* key */
        SwapParams calldata, /* params */
        bytes calldata hookData
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        if (msg.sender != address(poolManager)) revert OnlyPoolManager();

        if (authorized[sender]) {
            emit SwapGated(sender, true);
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }

        // Decode ZK proof from hookData
        if (hookData.length == 0) revert NotAuthorized();

        (
            uint256[2] memory pA,
            uint256[2][2] memory pB,
            uint256[2] memory pC,
            uint256[2] memory pubSignals
        ) = abi.decode(hookData, (uint256[2], uint256[2][2], uint256[2], uint256[2]));

        // Verify Groth16 proof on-chain
        bool valid = verifier.verifyProof(pA, pB, pC, pubSignals);
        if (!valid) revert InvalidProof();

        // Cache authorization
        authorized[sender] = true;
        authorizedCount++;

        emit AgentAuthorized(sender, pubSignals[0], pubSignals[1]);
        emit SwapGated(sender, true);

        return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    // ──────────────────────────────────────────────────────────────
    // Admin: Revoke authorization
    // ──────────────────────────────────────────────────────────────

    /// @notice Revoke an agent's cached authorization (owner only)
    /// @param agent The address to revoke
    function revokeAuthorization(address agent) external {
        require(msg.sender == owner, "Not owner");
        require(authorized[agent], "Not authorized");
        authorized[agent] = false;
        authorizedCount--;
        emit AgentRevoked(agent);
    }

    // ──────────────────────────────────────────────────────────────
    // Pre-authorize (owner can whitelist without proof for testing)
    // ──────────────────────────────────────────────────────────────

    /// @notice Pre-authorize an address without requiring a ZK proof (owner only)
    /// @param agent The address to authorize
    function preAuthorize(address agent) external {
        require(msg.sender == owner, "Not owner");
        if (!authorized[agent]) {
            authorized[agent] = true;
            authorizedCount++;
            emit AgentAuthorized(agent, 0, 0);
        }
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
