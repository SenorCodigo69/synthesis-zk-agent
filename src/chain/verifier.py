"""On-chain ZK proof verification via deployed verifier contracts."""
from __future__ import annotations

from typing import Any

from src.models import ZKProof
from src.zk.prover import ZKProver


class OnChainVerifier:
    """Verifies ZK proofs on-chain via deployed Groth16 verifier contracts."""

    def __init__(
        self,
        prover: ZKProver,
        contract_addresses: dict[str, str] | None = None,
        web3_provider: Any = None,
    ):
        self.prover = prover
        self.contract_addresses = contract_addresses or {}
        self.w3 = web3_provider

    def verify_on_chain(self, proof: ZKProof) -> dict:
        """Verify a proof on-chain (or simulate if no web3 provider).

        Returns:
            Dict with verification result.
        """
        # Get calldata
        calldata = self.prover.export_calldata(proof)

        if self.w3 is None:
            # Paper mode — verify off-chain only
            off_chain_valid = self.prover.verify_proof(proof)
            return {
                "verified": off_chain_valid,
                "mode": "off_chain",
                "calldata": calldata,
                "proof_type": proof.proof_type.value,
            }

        # Live mode — call the verifier contract
        contract_addr = self.contract_addresses.get(proof.proof_type.value)
        if not contract_addr:
            return {
                "verified": False,
                "error": f"No contract address for {proof.proof_type.value}",
            }

        # Parse calldata and call contract
        # snarkjs exports calldata as: ["0x..","0x.."],[[...],[...]],["0x..","0x.."],[inputs]
        try:
            abi = [{
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

            contract = self.w3.eth.contract(
                address=self.w3.to_checksum_address(contract_addr),
                abi=abi,
            )

            # Parse the calldata components
            parts = self._parse_calldata(calldata)
            result = contract.functions.verifyProof(
                parts["a"], parts["b"], parts["c"], parts["inputs"]
            ).call()

            return {
                "verified": result,
                "mode": "on_chain",
                "contract": contract_addr,
                "proof_type": proof.proof_type.value,
            }
        except Exception as e:
            return {
                "verified": False,
                "mode": "on_chain",
                "error": str(e),
            }

    def _parse_calldata(self, calldata: str) -> dict:
        """Parse snarkjs calldata output into contract call parameters.

        snarkjs exports: ["0x..","0x.."],[["0x..","0x.."],["0x..","0x.."]],["0x..","0x.."],["0x.."]
        We wrap the whole thing in an array and parse as JSON.
        """
        import json

        # Wrap in array brackets to make valid JSON: [[a],[b],[c],[inputs]]
        wrapped = "[" + calldata.strip() + "]"
        try:
            parsed = json.loads(wrapped)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse snarkjs calldata: {e}")

        if len(parsed) != 4:
            raise ValueError(f"Expected 4 calldata components, got {len(parsed)}")

        def to_int(x: str) -> int:
            if isinstance(x, str) and x.startswith("0x"):
                return int(x, 16)
            return int(x)

        return {
            "a": [to_int(x) for x in parsed[0]],
            "b": [[to_int(x) for x in row] for row in parsed[1]],
            "c": [to_int(x) for x in parsed[2]],
            "inputs": [to_int(x) for x in parsed[3]],
        }
