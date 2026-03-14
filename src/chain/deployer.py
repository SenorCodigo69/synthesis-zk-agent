"""Contract deployment — deploys PolicyCommitment + ZK verifier contracts."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


class ContractDeployer:
    """Deploys Solidity contracts via Foundry."""

    def __init__(self, build_dir: str, rpc_url: str, private_key: str | None = None):
        self.build_dir = Path(build_dir)
        self.rpc_url = rpc_url
        self.private_key = private_key

    def compile_contracts(self, contracts_dir: str) -> bool:
        """Compile Solidity contracts with Foundry.

        Args:
            contracts_dir: Path to contracts/ directory with foundry.toml.

        Returns:
            True if compilation succeeded.
        """
        result = subprocess.run(
            ["forge", "build"],
            cwd=contracts_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.returncode == 0

    def deploy_contract(
        self,
        contracts_dir: str,
        contract_path: str,
        constructor_args: list[str] | None = None,
    ) -> dict[str, Any]:
        """Deploy a contract to the configured chain.

        Args:
            contracts_dir: Path to contracts/ directory.
            contract_path: Contract path (e.g., "src/PolicyCommitment.sol:PolicyCommitment").
            constructor_args: Constructor arguments.

        Returns:
            Dict with deployed address and tx hash.
        """
        if not self.private_key:
            return {
                "deployed": False,
                "reason": "No private key configured — paper mode",
                "address": "0x_paper_contract",
            }

        cmd = [
            "forge", "create",
            "--rpc-url", self.rpc_url,
            "--private-key", self.private_key,
            contract_path,
        ]

        if constructor_args:
            cmd.append("--constructor-args")
            cmd.extend(constructor_args)

        result = subprocess.run(
            cmd,
            cwd=contracts_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            return {"deployed": False, "error": result.stderr}

        # Parse deployed address from output
        address = None
        tx_hash = None
        for line in result.stdout.split("\n"):
            if "Deployed to:" in line:
                address = line.split("Deployed to:")[-1].strip()
            if "Transaction hash:" in line:
                tx_hash = line.split("Transaction hash:")[-1].strip()

        return {
            "deployed": True,
            "address": address,
            "tx_hash": tx_hash,
        }

    def get_verifier_abi(self, circuit_name: str) -> list[dict] | None:
        """Load the ABI for a snarkjs-exported Solidity verifier.

        The Groth16 verifier always has the same interface:
            function verifyProof(
                uint[2] a, uint[2][2] b, uint[2] c, uint[N] input
            ) public view returns (bool)
        """
        verifier_sol = self.build_dir / f"{circuit_name}_verifier.sol"
        if not verifier_sol.exists():
            return None

        # Standard Groth16 verifier ABI
        return [{
            "inputs": [
                {"name": "_pA", "type": "uint256[2]"},
                {"name": "_pB", "type": "uint256[2][2]"},
                {"name": "_pC", "type": "uint256[2]"},
                {"name": "_pubSignals", "type": "uint256[]"},
            ],
            "name": "verifyProof",
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "view",
            "type": "function",
        }]
