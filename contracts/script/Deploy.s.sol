// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/PolicyCommitment.sol";
import "../src/AuthorizationVerifier.sol";
import "../src/BudgetRangeVerifier.sol";
import "../src/CumulativeSpendVerifier.sol";

contract Deploy is Script {
    function run() external {
        // Safety: require explicit DEPLOY_ANY_CHAIN=1 env for non-Base chains
        require(
            block.chainid == 8453 || block.chainid == 84532,
            "Deploy restricted to Base mainnet (8453) or Base Sepolia (84532)"
        );
        vm.startBroadcast();

        PolicyCommitment policyCommitment = new PolicyCommitment();
        AuthorizationVerifier authVerifier = new AuthorizationVerifier();
        BudgetRangeVerifier budgetVerifier = new BudgetRangeVerifier();
        CumulativeSpendVerifier spendVerifier = new CumulativeSpendVerifier();

        vm.stopBroadcast();

        console.log("PolicyCommitment:", address(policyCommitment));
        console.log("AuthorizationVerifier:", address(authVerifier));
        console.log("BudgetRangeVerifier:", address(budgetVerifier));
        console.log("CumulativeSpendVerifier:", address(spendVerifier));
    }
}
