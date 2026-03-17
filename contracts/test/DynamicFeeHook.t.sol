// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {DynamicFeeHook} from "../src/DynamicFeeHook.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {Currency} from "v4-core/types/Currency.sol";
import {BeforeSwapDelta} from "v4-core/types/BeforeSwapDelta.sol";
import {SwapParams} from "v4-core/types/PoolOperation.sol";

contract DynamicFeeHookTest is Test {
    DynamicFeeHook hook;
    address poolManager;
    address oracle;
    address owner;

    function setUp() public {
        poolManager = makeAddr("poolManager");
        oracle = makeAddr("oracle");
        owner = address(this);

        // Deploy hook — in production, would need CREATE2 with address flags
        // For testing, we deploy normally and use deployCodeTo for correct address
        hook = new DynamicFeeHook(IPoolManager(poolManager), oracle);
    }

    // ── Fee Computation ──────────────────────────────────────

    function test_minFee_atLowVolatility() public view {
        // Volatility at or below low threshold → min fee
        uint24 fee = hook.computeFee(50);  // 0.5%, below 1% threshold
        assertEq(fee, 100); // 0.01%
    }

    function test_maxFee_atHighVolatility() public view {
        // Volatility at or above high threshold → max fee
        uint24 fee = hook.computeFee(1500); // 15%, above 10% threshold
        assertEq(fee, 10000); // 1%
    }

    function test_linearInterpolation_midpoint() public view {
        // Midpoint: (100 + 1000) / 2 = 550 bps → midpoint fee
        uint24 fee = hook.computeFee(550);
        uint24 expectedMid = (100 + 10000) / 2; // 5050
        assertEq(fee, expectedMid);
    }

    function test_linearInterpolation_quarterPoint() public view {
        // 25% of the way: 100 + (1000-100)*0.25 = 325 bps
        uint24 fee = hook.computeFee(325);
        // 25% of fee range: 100 + (10000-100)*0.25 = 2575
        assertEq(fee, 2575);
    }

    function test_feeAtLowThreshold() public view {
        uint24 fee = hook.computeFee(100);
        assertEq(fee, 100);
    }

    function test_feeAtHighThreshold() public view {
        uint24 fee = hook.computeFee(1000);
        assertEq(fee, 10000);
    }

    function test_feeIncreasesWithVolatility() public view {
        uint24 low = hook.computeFee(200);
        uint24 mid = hook.computeFee(500);
        uint24 high = hook.computeFee(800);
        assertTrue(low < mid);
        assertTrue(mid < high);
    }

    // ── Volatility Oracle ────────────────────────────────────

    function test_updateVolatility() public {
        vm.prank(oracle);
        hook.updateVolatility(500);

        assertEq(hook.currentVolatilityBps(), 500);
        assertEq(hook.lastObservationTime(), block.timestamp);
    }

    function test_updateVolatility_onlyOracle() public {
        vm.expectRevert(DynamicFeeHook.OnlyOracle.selector);
        hook.updateVolatility(500);
    }

    function test_updateVolatility_updatesState() public {
        vm.prank(oracle);
        hook.updateVolatility(500);
        assertEq(hook.currentVolatilityBps(), 500);

        vm.prank(oracle);
        hook.updateVolatility(800);
        assertEq(hook.currentVolatilityBps(), 800);
    }

    // ── beforeSwap ───────────────────────────────────────────

    function test_beforeSwap_returnsDynamicFee() public {
        // Set volatility
        vm.prank(oracle);
        hook.updateVolatility(550); // Midpoint → ~5050 fee

        // Call beforeSwap as pool manager
        PoolKey memory key = _makePoolKey();
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 1e18,
            sqrtPriceLimitX96: 0
        });

        vm.prank(poolManager);
        (bytes4 selector, , uint24 fee) = hook.beforeSwap(address(0), key, params, "");

        assertEq(selector, IHooks.beforeSwap.selector);
        // Fee should have OVERRIDE_FEE_FLAG set
        assertTrue(fee & LPFeeLibrary.OVERRIDE_FEE_FLAG != 0);
        // Actual fee (without flag) should be ~5050
        uint24 actualFee = fee & ~uint24(LPFeeLibrary.OVERRIDE_FEE_FLAG);
        assertEq(actualFee, 5050);
    }

    function test_beforeSwap_staleFallsToMidpoint() public {
        // Set volatility, then warp past max observation age
        vm.prank(oracle);
        hook.updateVolatility(100); // Low vol → should be 100 fee

        vm.warp(block.timestamp + 5 hours); // Past 4h max age

        PoolKey memory key = _makePoolKey();
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 1e18,
            sqrtPriceLimitX96: 0
        });

        vm.prank(poolManager);
        (, , uint24 fee) = hook.beforeSwap(address(0), key, params, "");

        uint24 actualFee = fee & ~uint24(LPFeeLibrary.OVERRIDE_FEE_FLAG);
        uint24 midFee = (100 + 10000) / 2;
        assertEq(actualFee, midFee); // Falls back to midpoint
    }

    function test_beforeSwap_onlyPoolManager() public {
        PoolKey memory key = _makePoolKey();
        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 1e18,
            sqrtPriceLimitX96: 0
        });

        vm.expectRevert(DynamicFeeHook.OnlyPoolManager.selector);
        hook.beforeSwap(address(0), key, params, "");
    }

    // ── Admin ────────────────────────────────────────────────

    function test_setFeeRange() public {
        hook.setFeeRange(200, 5000);
        assertEq(hook.minFee(), 200);
        assertEq(hook.maxFee(), 5000);
    }

    function test_setFeeRange_invalidReverts() public {
        vm.expectRevert(DynamicFeeHook.InvalidFeeRange.selector);
        hook.setFeeRange(5000, 200); // min > max
    }

    function test_setFeeRange_exceedsMaxReverts() public {
        vm.expectRevert(DynamicFeeHook.InvalidFeeRange.selector);
        hook.setFeeRange(100, 1000001); // > MAX_LP_FEE
    }

    function test_setFeeRange_onlyOwner() public {
        vm.prank(makeAddr("attacker"));
        vm.expectRevert(DynamicFeeHook.OnlyOwner.selector);
        hook.setFeeRange(200, 5000);
    }

    function test_setOracle() public {
        address newOracle = makeAddr("newOracle");
        hook.setOracle(newOracle);
        assertEq(hook.oracle(), newOracle);
    }

    function test_setOracle_onlyOwner() public {
        vm.prank(makeAddr("attacker"));
        vm.expectRevert(DynamicFeeHook.OnlyOwner.selector);
        hook.setOracle(makeAddr("newOracle"));
    }

    function test_setThresholds() public {
        hook.setThresholds(50, 2000);
        assertEq(hook.lowThreshold(), 50);
        assertEq(hook.highThreshold(), 2000);
    }

    function test_setThresholds_invalidReverts() public {
        vm.expectRevert(DynamicFeeHook.InvalidFeeRange.selector);
        hook.setThresholds(1000, 100); // low > high
    }

    function test_setMaxObservationAge() public {
        hook.setMaxObservationAge(8 hours);
        assertEq(hook.maxObservationAge(), 8 hours);
    }

    // ── Hook Permissions ─────────────────────────────────────

    function test_permissions() public view {
        Hooks.Permissions memory perms = hook.getHookPermissions();
        assertTrue(perms.beforeSwap);
        assertFalse(perms.afterSwap);
        assertFalse(perms.beforeInitialize);
        assertFalse(perms.beforeAddLiquidity);
    }

    // ── Unimplemented Hooks Revert ───────────────────────────

    function test_unimplementedHooksRevert() public {
        PoolKey memory key = _makePoolKey();

        vm.expectRevert(DynamicFeeHook.HookNotImplemented.selector);
        hook.beforeInitialize(address(0), key, 0);

        vm.expectRevert(DynamicFeeHook.HookNotImplemented.selector);
        hook.afterInitialize(address(0), key, 0, 0);
    }

    // ── Helper ───────────────────────────────────────────────

    function _makePoolKey() internal pure returns (PoolKey memory) {
        return PoolKey({
            currency0: Currency.wrap(address(0x1)),
            currency1: Currency.wrap(address(0x2)),
            fee: LPFeeLibrary.DYNAMIC_FEE_FLAG, // Dynamic fee pool
            tickSpacing: 10,
            hooks: IHooks(address(0))
        });
    }
}
