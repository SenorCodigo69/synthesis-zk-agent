// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {LPFeeLibrary} from "v4-core/libraries/LPFeeLibrary.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";
import {ModifyLiquidityParams, SwapParams} from "v4-core/types/PoolOperation.sol";

/// @title DynamicFeeHook — Volatility-Adjusted Pool Fees for Uniswap V4
/// @notice Adjusts swap fees based on on-chain volatility signals from the LP agent.
///         Low volatility → low fee (attract volume, LPs earn more from tight ranges).
///         High volatility → high fee (protect LPs from adverse selection + IL).
///
///         The agent pushes volatility observations on-chain. The hook reads the latest
///         observation and maps it to a fee in the configured range.
///
/// @dev Fee override mechanism:
///      1. Pool is initialized with DYNAMIC_FEE_FLAG (0x800000) as its fee
///      2. beforeSwap returns the computed fee OR'd with OVERRIDE_FEE_FLAG (0x400000)
///      3. PoolManager uses the returned fee for that swap
///
///      Deployed via CREATE2 with BEFORE_SWAP_FLAG (bit 7) in the address.
contract DynamicFeeHook is IHooks {
    // ──────────────────────────────────────────────────────────────
    // Errors
    // ──────────────────────────────────────────────────────────────
    error HookNotImplemented();
    error OnlyPoolManager();
    error OnlyOracle();
    error OnlyOwner();
    error InvalidFeeRange();
    error StaleObservation();

    // ──────────────────────────────────────────────────────────────
    // Events
    // ──────────────────────────────────────────────────────────────
    event VolatilityUpdated(uint256 indexed volatilityBps, uint24 computedFee, uint256 timestamp);
    event FeeRangeUpdated(uint24 minFee, uint24 maxFee);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);

    // ──────────────────────────────────────────────────────────────
    // State
    // ──────────────────────────────────────────────────────────────

    IPoolManager public immutable poolManager;
    address public owner;
    address public oracle; // Address authorized to push volatility observations

    /// @notice Fee range in hundredths of a bip (1 = 0.0001%)
    /// Default: 100 (0.01%) to 10000 (1%)
    uint24 public minFee = 100;   // 0.01% — low vol floor
    uint24 public maxFee = 10000; // 1% — high vol ceiling

    /// @notice Latest volatility observation (in basis points of price, e.g., 300 = 3%)
    uint256 public currentVolatilityBps;

    /// @notice Timestamp of latest observation
    uint256 public lastObservationTime;

    /// @notice Maximum age of observation before it's considered stale (default 4 hours)
    uint256 public maxObservationAge = 4 hours;

    /// @notice Volatility threshold for fee scaling
    /// volatilityBps <= lowThreshold → minFee
    /// volatilityBps >= highThreshold → maxFee
    /// Between → linear interpolation
    uint256 public lowThreshold = 100;   // 1% daily vol → min fee
    uint256 public highThreshold = 1000; // 10% daily vol → max fee

    // ──────────────────────────────────────────────────────────────
    // Modifiers
    // ──────────────────────────────────────────────────────────────

    modifier onlyPoolManager() {
        if (msg.sender != address(poolManager)) revert OnlyPoolManager();
        _;
    }

    modifier onlyOracle() {
        if (msg.sender != oracle) revert OnlyOracle();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // ──────────────────────────────────────────────────────────────
    // Constructor
    // ──────────────────────────────────────────────────────────────

    constructor(IPoolManager _poolManager, address _oracle) {
        poolManager = _poolManager;
        oracle = _oracle;
        owner = msg.sender;
        lastObservationTime = block.timestamp;
    }

    // ──────────────────────────────────────────────────────────────
    // Oracle — Agent pushes volatility signals on-chain
    // ──────────────────────────────────────────────────────────────

    /// @notice Update the volatility observation. Called by the LP agent's oracle address.
    /// @param volatilityBps Volatility in basis points of price (e.g., 300 = 3% ATR)
    function updateVolatility(uint256 volatilityBps) external onlyOracle {
        currentVolatilityBps = volatilityBps;
        lastObservationTime = block.timestamp;

        uint24 fee = computeFee(volatilityBps);
        emit VolatilityUpdated(volatilityBps, fee, block.timestamp);
    }

    /// @notice Compute the dynamic fee for a given volatility level.
    /// @param volatilityBps Volatility in basis points
    /// @return fee The computed fee in hundredths of a bip
    function computeFee(uint256 volatilityBps) public view returns (uint24) {
        if (volatilityBps <= lowThreshold) {
            return minFee;
        }
        if (volatilityBps >= highThreshold) {
            return maxFee;
        }
        // Linear interpolation between minFee and maxFee
        uint256 range = highThreshold - lowThreshold;
        uint256 feeRange = uint256(maxFee) - uint256(minFee);
        uint256 position = volatilityBps - lowThreshold;
        uint24 fee = minFee + uint24((position * feeRange) / range);
        return fee;
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
            beforeSwap: true,        // ← We override the fee here
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
    // beforeSwap — Dynamic Fee Override
    // ──────────────────────────────────────────────────────────────

    function beforeSwap(
        address,
        PoolKey calldata,
        SwapParams calldata,
        bytes calldata
    ) external view onlyPoolManager returns (bytes4, BeforeSwapDelta, uint24) {
        uint24 fee;

        // If observation is stale, use a safe default (midpoint fee)
        if (block.timestamp > lastObservationTime + maxObservationAge) {
            fee = (minFee + maxFee) / 2;
        } else {
            fee = computeFee(currentVolatilityBps);
        }

        // Return fee with OVERRIDE_FEE_FLAG to activate dynamic fee
        return (
            IHooks.beforeSwap.selector,
            BeforeSwapDeltaLibrary.ZERO_DELTA,
            fee | LPFeeLibrary.OVERRIDE_FEE_FLAG
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Admin
    // ──────────────────────────────────────────────────────────────

    /// @notice Update the fee range
    function setFeeRange(uint24 _minFee, uint24 _maxFee) external onlyOwner {
        if (_minFee >= _maxFee) revert InvalidFeeRange();
        if (_maxFee > LPFeeLibrary.MAX_LP_FEE) revert InvalidFeeRange();
        minFee = _minFee;
        maxFee = _maxFee;
        emit FeeRangeUpdated(_minFee, _maxFee);
    }

    /// @notice Update the volatility thresholds
    function setThresholds(uint256 _low, uint256 _high) external onlyOwner {
        if (_low >= _high) revert InvalidFeeRange();
        lowThreshold = _low;
        highThreshold = _high;
    }

    /// @notice Update the oracle address
    function setOracle(address _oracle) external onlyOwner {
        emit OracleUpdated(oracle, _oracle);
        oracle = _oracle;
    }

    /// @notice Update the max observation age
    function setMaxObservationAge(uint256 _age) external onlyOwner {
        maxObservationAge = _age;
    }

    // ──────────────────────────────────────────────────────────────
    // Unimplemented Hooks (required by IHooks interface)
    // ──────────────────────────────────────────────────────────────

    function beforeInitialize(address, PoolKey calldata, uint160) external pure returns (bytes4) {
        revert HookNotImplemented();
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24) external pure returns (bytes4) {
        revert HookNotImplemented();
    }

    function beforeAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external pure returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function afterAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, BalanceDelta, BalanceDelta, bytes calldata)
        external pure returns (bytes4, BalanceDelta)
    {
        revert HookNotImplemented();
    }

    function beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external pure returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function afterRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, BalanceDelta, BalanceDelta, bytes calldata)
        external pure returns (bytes4, BalanceDelta)
    {
        revert HookNotImplemented();
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata)
        external pure returns (bytes4, int128)
    {
        revert HookNotImplemented();
    }

    function beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external pure returns (bytes4)
    {
        revert HookNotImplemented();
    }
}
