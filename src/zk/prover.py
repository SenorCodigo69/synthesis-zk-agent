"""ZK proof generation and verification via snarkjs.

Wraps snarkjs CLI for:
  - Witness generation (WASM)
  - Groth16 proof generation
  - Proof verification (off-chain)
  - Solidity calldata export
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from src.models import ProofType, ZKProof


class ZKProver:
    """Generates and verifies ZK proofs using snarkjs."""

    def __init__(self, build_dir: str):
        self.build_dir = Path(build_dir)
        if not self.build_dir.exists():
            raise FileNotFoundError(
                f"Build directory not found: {build_dir}. Run scripts/compile.sh and scripts/setup.sh first."
            )

    def _circuit_paths(self, proof_type: ProofType) -> dict[str, Path]:
        """Get file paths for a circuit."""
        name = proof_type.value
        return {
            "wasm": self.build_dir / f"{name}_js" / f"{name}.wasm",
            "zkey": self.build_dir / f"{name}_final.zkey",
            "vkey": self.build_dir / f"{name}_verification_key.json",
        }

    def _check_circuit_ready(self, proof_type: ProofType) -> None:
        """Verify all circuit artifacts exist."""
        paths = self._circuit_paths(proof_type)
        for key, path in paths.items():
            if not path.exists():
                raise FileNotFoundError(
                    f"Missing {key} for {proof_type.value}: {path}. "
                    "Run scripts/compile.sh and scripts/setup.sh."
                )

    def generate_proof(
        self, proof_type: ProofType, inputs: dict[str, str | int]
    ) -> ZKProof:
        """Generate a Groth16 proof.

        Args:
            proof_type: Which circuit to use.
            inputs: Circuit input signals (all values as strings or ints).

        Returns:
            ZKProof with proof data and public signals.
        """
        self._check_circuit_ready(proof_type)
        paths = self._circuit_paths(proof_type)

        # Validate inputs are numeric (prevent malformed data reaching snarkjs)
        for k, v in inputs.items():
            sv = str(v)
            if not sv.lstrip("-").isdigit():
                raise ValueError(f"Invalid circuit input '{k}': must be numeric, got '{sv}'")

        # Convert all inputs to strings (snarkjs expects string values)
        str_inputs = {k: str(v) for k, v in inputs.items()}

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            input_file = tmpdir / "input.json"
            witness_file = tmpdir / "witness.wtns"
            proof_file = tmpdir / "proof.json"
            public_file = tmpdir / "public.json"

            # Write input
            input_file.write_text(json.dumps(str_inputs))

            # Generate witness
            self._run_snarkjs([
                "wtns", "calculate",
                str(paths["wasm"]),
                str(input_file),
                str(witness_file),
            ])

            # Generate proof
            self._run_snarkjs([
                "groth16", "prove",
                str(paths["zkey"]),
                str(witness_file),
                str(proof_file),
                str(public_file),
            ])

            proof_data = json.loads(proof_file.read_text())
            public_signals = json.loads(public_file.read_text())

            # Load verification key
            vkey = json.loads(paths["vkey"].read_text())

        return ZKProof(
            proof_type=proof_type,
            proof=proof_data,
            public_signals=public_signals,
            verification_key=vkey,
        )

    def verify_proof(self, zk_proof: ZKProof) -> bool:
        """Verify a proof off-chain using snarkjs.

        Returns:
            True if proof is valid, False otherwise.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            vkey_file = tmpdir / "vkey.json"
            proof_file = tmpdir / "proof.json"
            public_file = tmpdir / "public.json"

            vkey_file.write_text(json.dumps(zk_proof.verification_key))
            proof_file.write_text(json.dumps(zk_proof.proof))
            public_file.write_text(json.dumps(zk_proof.public_signals))

            result = subprocess.run(
                ["snarkjs", "groth16", "verify",
                 str(vkey_file), str(public_file), str(proof_file)],
                capture_output=True, text=True, timeout=30,
            )
            is_valid = result.returncode == 0 and "OK" in result.stdout
            zk_proof.verified = is_valid
            return is_valid

    def export_calldata(self, zk_proof: ZKProof) -> str:
        """Export proof as Solidity calldata for on-chain verification.

        Returns:
            Solidity-formatted calldata string.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            proof_file = tmpdir / "proof.json"
            public_file = tmpdir / "public.json"

            proof_file.write_text(json.dumps(zk_proof.proof))
            public_file.write_text(json.dumps(zk_proof.public_signals))

            result = subprocess.run(
                ["snarkjs", "zkey", "export", "soliditycalldata",
                 str(public_file), str(proof_file)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Calldata export failed: {result.stderr}")
            return result.stdout.strip()

    def _run_snarkjs(self, args: list[str]) -> str:
        """Run snarkjs CLI command."""
        result = subprocess.run(
            ["snarkjs"] + args,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"snarkjs {' '.join(args[:2])} failed: {result.stderr}")
        return result.stdout
