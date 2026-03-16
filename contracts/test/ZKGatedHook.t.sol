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
    address agent2 = address(0xA2);
    address unauthorized = address(0xBAD);

    // Dummy proof data for testing
    uint256[2] dummyA = [uint256(1), uint256(2)];
    uint256[2][2] dummyB = [[uint256(3), uint256(4)], [uint256(5), uint256(6)]];
    uint256[2] dummyC = [uint256(7), uint256(8)];
    uint256[2] dummyPubSignals = [uint256(42), uint256(0xdeadbeef)]; // [agentId, policyCommitment]

    function setUp() public {
        verifier = new MockVerifier();

        // Deploy hook to an address with BEFORE_SWAP_FLAG set (bit 7 = 0x80)
        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG);
        address hookAddr = address(flags);

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

    function test_constructor_rejectsZeroOwner() public {
        vm.expectRevert(ZKGatedHook.ZeroAddress.selector);
        new ZKGatedHook(IPoolManager(poolManager), IAuthorizationVerifier(address(verifier)), address(0));
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

        // Second call without proof — uses cache
        vm.prank(poolManager);
        (bytes4 selector,,) = hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), "");
        assertEq(selector, IHooks.beforeSwap.selector);
    }

    function test_beforeSwap_differentAgentsNeedOwnProofs() public {
        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);

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

    // ──────────────────────────────────────────────────────────────
    // SEC-H01: Proof replay prevention (nullifier)
    // ──────────────────────────────────────────────────────────────

    function test_proofReplay_sameProofRejectedSecondTime() public {
        bytes memory hookData = _encodeProof();

        // First use succeeds
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);

        // Warp past TTL so cache expires
        vm.warp(block.timestamp + hook.AUTH_TTL() + 1);

        // Same proof rejected (nullifier)
        vm.prank(poolManager);
        vm.expectRevert(ZKGatedHook.ProofAlreadyUsed.selector);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
    }

    function test_proofReplay_differentProofsWork() public {
        bytes memory hookData1 = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData1);

        // Warp past TTL
        vm.warp(block.timestamp + hook.AUTH_TTL() + 1);

        // Different proof data works
        bytes memory hookData2 = _encodeProofWithDifferentSignals(43, 0xbeef);
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData2);
    }

    function test_proofReplay_frontRunnerBlockedByBinding() public {
        // Owner binds agentId 42 to agent address
        hook.bindAgent(42, agent);

        bytes memory hookData = _encodeProof();

        // Front-runner (unauthorized) tries to use the proof — binding blocks them
        vm.prank(poolManager);
        vm.expectRevert(ZKGatedHook.AgentBindingMismatch.selector);
        hook.beforeSwap(unauthorized, _dummyPoolKey(), _dummySwapParams(), hookData);
    }

    function test_proofReplay_boundAgentCanUseProof() public {
        hook.bindAgent(42, agent);

        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
        assertTrue(hook.authorized(agent));
    }

    function test_proofReplay_unboundAgentIdAllowsAnyone() public {
        // No binding set — any sender can use the proof
        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(unauthorized, _dummyPoolKey(), _dummySwapParams(), hookData);
        assertTrue(hook.authorized(unauthorized));
    }

    // ──────────────────────────────────────────────────────────────
    // SEC-H02: Authorization expiry (TTL)
    // ──────────────────────────────────────────────────────────────

    function test_authExpiry_expiresAfterTTL() public {
        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
        assertTrue(hook.authorized(agent));

        // Warp past TTL
        vm.warp(block.timestamp + hook.AUTH_TTL() + 1);
        assertFalse(hook.authorized(agent));
    }

    function test_authExpiry_requiresNewProofAfterExpiry() public {
        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);

        // Warp past TTL
        vm.warp(block.timestamp + hook.AUTH_TTL() + 1);

        // Empty hookData fails — cache expired
        vm.prank(poolManager);
        vm.expectRevert(ZKGatedHook.NotAuthorized.selector);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), "");
    }

    function test_authExpiry_newProofRefreshesTTL() public {
        bytes memory hookData1 = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData1);

        // Warp past TTL
        vm.warp(block.timestamp + hook.AUTH_TTL() + 1);

        // New proof refreshes
        bytes memory hookData2 = _encodeProofWithDifferentSignals(43, 0xbeef);
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData2);
        assertTrue(hook.authorized(agent));
    }

    function test_authExpiry_ttlIs24Hours() public view {
        assertEq(hook.AUTH_TTL(), 24 hours);
    }

    // ──────────────────────────────────────────────────────────────
    // SEC-M01: preAuthorize can be permanently disabled
    // ──────────────────────────────────────────────────────────────

    function test_preAuthorize_ownerCanWhitelist() public {
        hook.preAuthorize(agent);
        assertTrue(hook.authorized(agent));
        assertEq(hook.authorizedCount(), 1);
    }

    function test_preAuthorize_nonOwnerReverts() public {
        vm.prank(unauthorized);
        vm.expectRevert("Not owner");
        hook.preAuthorize(agent);
    }

    function test_preAuthorize_disablePermanently() public {
        hook.disablePreAuth();
        assertTrue(hook.preAuthDisabled());

        vm.expectRevert(ZKGatedHook.PreAuthDisabled.selector);
        hook.preAuthorize(agent);
    }

    function test_preAuthorize_disableOnlyOwner() public {
        vm.prank(unauthorized);
        vm.expectRevert("Not owner");
        hook.disablePreAuth();
    }

    function test_preAuthorize_disableEmitsEvent() public {
        vm.expectEmit(false, false, false, false);
        emit ZKGatedHook.PreAuthPermanentlyDisabled();
        hook.disablePreAuth();
    }

    function test_preAuthorize_idempotentWhileActive() public {
        hook.preAuthorize(agent);
        hook.preAuthorize(agent); // no-op while still active
        assertEq(hook.authorizedCount(), 1);
    }

    // ──────────────────────────────────────────────────────────────
    // Admin: bindAgent
    // ──────────────────────────────────────────────────────────────

    function test_bindAgent_ownerCanBind() public {
        hook.bindAgent(42, agent);
        assertEq(hook.agentBinding(42), agent);
    }

    function test_bindAgent_nonOwnerReverts() public {
        vm.prank(unauthorized);
        vm.expectRevert("Not owner");
        hook.bindAgent(42, agent);
    }

    function test_bindAgent_canRebind() public {
        hook.bindAgent(42, agent);
        hook.bindAgent(42, agent2);
        assertEq(hook.agentBinding(42), agent2);
    }

    function test_bindAgent_canUnbind() public {
        hook.bindAgent(42, agent);
        hook.bindAgent(42, address(0));
        assertEq(hook.agentBinding(42), address(0));
    }

    function test_bindAgent_emitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit ZKGatedHook.AgentBound(42, agent);
        hook.bindAgent(42, agent);
    }

    // ──────────────────────────────────────────────────────────────
    // Admin: revokeAuthorization
    // ──────────────────────────────────────────────────────────────

    function test_revokeAuthorization_ownerCanRevoke() public {
        hook.preAuthorize(agent);
        assertTrue(hook.authorized(agent));

        hook.revokeAuthorization(agent);
        assertFalse(hook.authorized(agent));
        assertEq(hook.authorizedCount(), 0);
    }

    function test_revokeAuthorization_nonOwnerReverts() public {
        hook.preAuthorize(agent);

        vm.prank(unauthorized);
        vm.expectRevert("Not owner");
        hook.revokeAuthorization(agent);
    }

    function test_revokeAuthorization_notAuthorizedReverts() public {
        vm.expectRevert("Not authorized");
        hook.revokeAuthorization(agent);
    }

    function test_revokeAuthorization_emitsEvent() public {
        hook.preAuthorize(agent);

        vm.expectEmit(true, false, false, false);
        emit ZKGatedHook.AgentRevoked(agent);
        hook.revokeAuthorization(agent);
    }

    function test_revoked_agentNeedsNewProof() public {
        bytes memory hookData = _encodeProof();
        vm.prank(poolManager);
        hook.beforeSwap(agent, _dummyPoolKey(), _dummySwapParams(), hookData);
        assertTrue(hook.authorized(agent));

        hook.revokeAuthorization(agent);

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

    function _encodeProofWithDifferentSignals(uint256 agentId, uint256 commitment) internal view returns (bytes memory) {
        uint256[2] memory signals = [agentId, commitment];
        return abi.encode(dummyA, dummyB, dummyC, signals);
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
