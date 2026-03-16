// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {ZKGatedHook} from "../src/ZKGatedHook.sol";
import {IAuthorizationVerifier} from "../src/IAuthorizationVerifier.sol";
import {HookMiner} from "./HookMiner.sol";

/// @title DeployZKHook — Deploy the ZK-gated Uniswap V4 Hook to Base mainnet
/// @notice Uses CREATE2 with mined salt for hook address flag compliance
contract DeployZKHook is Script {
    // Base mainnet addresses
    address constant POOL_MANAGER = 0x498581fF718922c3f8e6A244956aF099B2652b2b;
    address constant AUTH_VERIFIER = 0x2a8FBE80BDc9cb907b20acBE84F13a858CBEdAe4;
    address constant OWNER = 0x8d691720bF8C81044DB1a77b82D0eF5f5bffdE6C;

    // Deterministic CREATE2 deployer (available on all EVM chains)
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() external {
        // Safety: Base only
        require(block.chainid == 8453, "Deploy restricted to Base mainnet (8453)");

        // The hook needs BEFORE_SWAP_FLAG (bit 7 = 0x80)
        uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG);

        // Mine a salt for CREATE2 address with correct flag bits
        bytes memory constructorArgs = abi.encode(
            IPoolManager(POOL_MANAGER),
            IAuthorizationVerifier(AUTH_VERIFIER),
            OWNER
        );

        (address hookAddress, bytes32 salt) = HookMiner.find(
            CREATE2_DEPLOYER,
            flags,
            type(ZKGatedHook).creationCode,
            constructorArgs
        );

        console.log("Mined hook address:", hookAddress);
        console.log("Salt:", vm.toString(salt));
        console.log("Required flags (BEFORE_SWAP):", uint256(flags));
        console.log("Address flags:", uint160(hookAddress) & uint160((1 << 14) - 1));

        vm.startBroadcast();

        // Deploy via CREATE2 with the mined salt
        ZKGatedHook hook = new ZKGatedHook{salt: salt}(
            IPoolManager(POOL_MANAGER),
            IAuthorizationVerifier(AUTH_VERIFIER),
            OWNER
        );

        require(address(hook) == hookAddress, "Address mismatch");

        console.log("=== ZKGatedHook Deployed ===");
        console.log("Hook address:", address(hook));
        console.log("PoolManager:", POOL_MANAGER);
        console.log("AuthVerifier:", AUTH_VERIFIER);
        console.log("Owner:", hook.owner());

        vm.stopBroadcast();
    }
}
