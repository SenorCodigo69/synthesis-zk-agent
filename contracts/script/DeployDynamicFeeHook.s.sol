// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {DynamicFeeHook} from "../src/DynamicFeeHook.sol";
import {HookMiner} from "./HookMiner.sol";

/// @title DeployDynamicFeeHook — Deploy the volatility-adjusted fee hook to Base
/// @notice Uses CREATE2 with mined salt for hook address flag compliance
contract DeployDynamicFeeHook is Script {
    // Base mainnet addresses
    address constant POOL_MANAGER = 0x498581fF718922c3f8e6A244956aF099B2652b2b;
    address constant ORACLE = 0x8d691720bF8C81044DB1a77b82D0eF5f5bffdE6C; // Agent wallet = oracle
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() external {
        require(block.chainid == 8453, "Deploy restricted to Base mainnet (8453)");

        // DynamicFeeHook needs BEFORE_SWAP_FLAG (bit 7 = 0x80)
        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG);

        bytes memory constructorArgs = abi.encode(
            IPoolManager(POOL_MANAGER),
            ORACLE
        );

        (address hookAddress, bytes32 salt) = HookMiner.find(
            CREATE2_DEPLOYER,
            flags,
            type(DynamicFeeHook).creationCode,
            constructorArgs
        );

        console.log("=== DynamicFeeHook Deploy ===");
        console.log("Mined hook address:", hookAddress);
        console.log("Salt:", vm.toString(salt));
        console.log("Flags (BEFORE_SWAP):", uint256(flags));

        vm.startBroadcast();

        DynamicFeeHook hook = new DynamicFeeHook{salt: salt}(
            IPoolManager(POOL_MANAGER),
            ORACLE
        );

        require(address(hook) == hookAddress, "Address mismatch");

        console.log("=== Deployed ===");
        console.log("Hook:", address(hook));
        console.log("PoolManager:", POOL_MANAGER);
        console.log("Oracle:", ORACLE);
        console.log("Owner:", hook.owner());
        console.log("Min fee:", uint256(hook.minFee()));
        console.log("Max fee:", uint256(hook.maxFee()));

        vm.stopBroadcast();
    }
}
