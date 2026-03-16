// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";
import {SwapParams} from "v4-core/types/PoolOperation.sol";
import {ZKGatedHook} from "../src/ZKGatedHook.sol";
import {IAuthorizationVerifier} from "../src/IAuthorizationVerifier.sol";

/// @notice Mock verifier that returns configurable results
contract MockVerifier is IAuthorizationVerifier {
    bool public shouldVerify = true;

    function setResult(bool _result) external {
        shouldVerify = _result;
    }

    function verifyProof(uint256[2] calldata, uint256[2][2] calldata, uint256[2] calldata, uint256[2] calldata)
        external
        view
        override
        returns (bool)
    {
        return shouldVerify;
    }
}

contract ZKGatedHookTest is Test {
    ZKGatedHook hook;
    MockVerifier verifier;
    address poolManager = address(0xBEEF);
    address deployer = address(this);
    address agent = address(0xA1);
    address unauthorized = address(0xBAD);

    // Dummy proof data for testing
    uint256[2] dummyA = [uint256(1), uint256(2)];
    uint256[2][2] dummyB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
    uint256[2] dummyC = [uint256(7), uint256(8)];
    uint256[2] dummyPubSignals = [uint256(42), uint256(0xdeadbeef)]; // [agentId, policyCommitment]

    function setUp() public {
        verifier = new MockVerifier();

        // Deploy hook to an address with BEFORE_SWAP_FLAG set (bit 7 = 0x80)
        // Use deployCodeTo to place the hook at a valid flag address
        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG);
        address hookAddr = address(flags);

        // Deploy the hook bytecode to the flag-compliant address
        deployCodeTo(
            "ZKGatedHook.sol:ZKGatedHook",
            abi.encode(IPoolManager(poolManager), IAuthorizationVerifier(address(verifier)), deployer),
            hookAddr
        );
        hook = ZKGatedHook(hookAddr);
    }

    // ──────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────

    function test_constructor_setsImmutables() public view {
        assertEq(address(hook.poolManager()), poolManager);
        assertEq(address(hook.verifier()), address(verifier));
        assertEq(hook.authorizedCount(), 0);
    }

    function test_constructor_rejectsZeroPoolManager() public {
        vm.expectRevert(ZKGatedHook.ZeroAddress.selector);
        new ZKGatedHook(IPoolManager(address(0)), IAuthorizationVerifier(address(verifier)), deployer);
    }

    function test_constructor_rejectsZeroVerifier() public {
        vm.expectRevert(ZKGatedHook.ZeroAddress.selector);
        new ZKGatedHook(IPoolManager(poolManager), IAuthorizationVerifier(address(0)), deployer);
    }

    // ──────────────────────────────────────────────────────────────
    // beforeSwap — ZK gating
    // ──────────────────────────────────────────────────────────────

    function test_beforeSwap_rejectsNonPoolManager() public {
        bytes memory hookData = _encodeProof();
        vm.prank(agent);
        vm.expectRevert(ZKGatedHook.OnlyPoolManager.selector);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
    }

    function test_beforeSwap_rejectsUnauthorizedWithoutProof() public {
        vm.prank(poolManager);
        vm.expectRevert(ZKGatedHook.NotAuthorized.selector);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), "");
    }

    function test_beforeSwap_authorizesWithValidProof() public {
        bytes memory hookData = _encodeProof();

        vm.prank(poolManager);
        (bytes4 selector, BeforeSwapDelta delta, uint24 fee) =
            hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);

        assertEq(selector, IHooks.beforeSwap.selector);
        assertEq(BeforeSwapDelta.unwrap(delta), 0);
        assertEq(fee, 0);
        assertTrue(hook.authorized(agent));
        assertEq(hook.authorizedCount(), 1);
    }

    function test_beforeSwap_rejectsInvalidProof() public {
        verifier.setResult(false);
        bytes memory hookData = _encodeProof();

        vm.prank(poolManager);
        vm.expectRevert(ZKGatedHook.InvalidProof.selector);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
    }

    function test_beforeSwap_cachedAuthSkipsProof() public {
        // First call with proof
        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);

        // Second call without proof (cached)
        vm.prank(poolManager);
        (bytes4 selector,,) = hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), "");
        assertEq(selector, IHooks.beforeSwap.selector);
    }

    function test_beforeSwap_differentAgentsNeedOwnProofs() public {
        // Authorize agent
        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);

        // Different address still needs proof
        vm.prank(poolManager);
        vm.expectRevert(ZKGatedHook.NotAuthorized.selector);
        hook.beforeSwap(unauthorized, _dummyPoolKey(), _dummySwapParams(), "");
    }

    function test_beforeSwap_emitsAgentAuthorized() public {
        bytes memory hookData = _encodeProof();

        vm.prank(poolManager);
        vm.expectEmit(true, true, true, true);
        emit ZKGatedHook.AgentAuthorized(agent, 42, 0xdeadbeef);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
    }

    function test_beforeSwap_emitsSwapGated() public {
        bytes memory hookData = _encodeProof();

        vm.prank(poolManager);
        vm.expectEmit(true, false, false, true);
        emit ZKGatedHook.SwapGated(agent, true);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
    }

    // ──────────────────────────────────────────────────────────────
    // Admin: preAuthorize
    // ──────────────────────────────────────────────────────────────

    function test_preAuthorize_ownerCanWhitelist() public {
        vm.prank(hook.owner());
        hook.preAuthorize(agent);
        assertTrue(hook.authorized(agent));
        assertEq(hook.authorizedCount(), 1);
    }

    function test_preAuthorize_nonOwnerReverts() public {
        vm.prank(unauthorized);
        vm.expectRevert("Not owner");
        hook.preAuthorize(agent);
    }

    function test_preAuthorize_idempotent() public {
        vm.startPrank(hook.owner());
        hook.preAuthorize(agent);
        hook.preAuthorize(agent); // second call is no-op
        vm.stopPrank();
        assertEq(hook.authorizedCount(), 1);
    }

    // ──────────────────────────────────────────────────────────────
    // Admin: revokeAuthorization
    // ──────────────────────────────────────────────────────────────

    function test_revokeAuthorization_ownerCanRevoke() public {
        // First authorize
        vm.prank(hook.owner());
        hook.preAuthorize(agent);
        assertTrue(hook.authorized(agent));

        // Then revoke
        vm.prank(hook.owner());
        hook.revokeAuthorization(agent);
        assertFalse(hook.authorized(agent));
        assertEq(hook.authorizedCount(), 0);
    }

    function test_revokeAuthorization_nonOwnerReverts() public {
        vm.prank(hook.owner());
        hook.preAuthorize(agent);

        vm.prank(unauthorized);
        vm.expectRevert("Not owner");
        hook.revokeAuthorization(agent);
    }

    function test_revokeAuthorization_notAuthorizedReverts() public {
        vm.prank(hook.owner());
        vm.expectRevert("Not authorized");
        hook.revokeAuthorization(agent);
    }

    function test_revokeAuthorization_emitsEvent() public {
        vm.prank(hook.owner());
        hook.preAuthorize(agent);

        vm.prank(hook.owner());
        vm.expectEmit(true, false, false, false);
        emit ZKGatedHook.AgentRevoked(agent);
        hook.revokeAuthorization(agent);
    }

    function test_revoked_agentNeedsNewProof() public {
        // Authorize via proof
        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
        assertTrue(hook.authorized(agent));

        // Revoke
        vm.prank(hook.owner());
        hook.revokeAuthorization(agent);

        // Now agent needs proof again
        vm.prank(poolManager);
        vm.expectRevert(ZKGatedHook.NotAuthorized.selector);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), "");
    }

    // ──────────────────────────────────────────────────────────────
    // Hook permissions
    // ──────────────────────────────────────────────────────────────

    function test_hookPermissions_onlyBeforeSwap() public view {
        Hooks.Permissions memory perms = hook.getHookPermissions();
        assertTrue(perms.beforeSwap);
        assertFalse(perms.afterSwap);
        assertFalse(perms.beforeInitialize);
        assertFalse(perms.afterInitialize);
        assertFalse(perms.beforeAddLiquidity);
        assertFalse(perms.afterAddLiquidity);
        assertFalse(perms.beforeRemoveLiquidity);
        assertFalse(perms.afterRemoveLiquidity);
        assertFalse(perms.beforeDonate);
        assertFalse(perms.afterDonate);
        assertFalse(perms.beforeSwapReturnDelta);
        assertFalse(perms.afterSwapReturnDelta);
        assertFalse(perms.afterAddLiquidityReturnDelta);
        assertFalse(perms.afterRemoveLiquidityReturnDelta);
    }

    // ──────────────────────────────────────────────────────────────
    // Unimplemented hooks revert
    // ──────────────────────────────────────────────────────────────

    function test_unimplementedHooks_revert() public {
        vm.expectRevert(ZKGatedHook.HookNotImplemented.selector);
        hook.beforeInitialize(address(0), _dummyPoolKey(), 0);

        vm.expectRevert(ZKGatedHook.HookNotImplemented.selector);
        hook.afterInitialize(address(0), _dummyPoolKey(), 0, 0);
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    function _encodeProof() internal view returns (bytes memory) {
        return abi.encode(dummyA, dummyB, dummyC, dummyPubSignals);
    }

    function _dummyPoolKey() internal view returns (PoolKey memory) {
        return PoolKey({
            currency0: Currency.wrap(address(0)),
            currency1: Currency.wrap(address(1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
    }

    function _dummySwapParams() internal pure returns (SwapParams memory) {
        return SwapParams({zeroForOne: true, amountSpecified: -1e18, sqrtPriceLimitX96: 0});
    }
}
