"""Baby JubJub EdDSA key management.

Uses @zk-kit/eddsa-poseidon via Node.js subprocess for key generation
and signing. Keys are compatible with circomlib's EdDSAPoseidonVerifier.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from src.models import OwnerKeys

SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"


def _run_node(script: str, args: list[str]) -> dict:
    """Run a Node.js helper script and return parsed JSON output."""
    cmd = ["node", str(SCRIPTS_DIR / script)] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"Node script {script} failed: {result.stderr}")
    return json.loads(result.stdout.strip())


def generate_keys(private_key: str | None = None) -> OwnerKeys:
    """Generate or derive Baby JubJub EdDSA keypair.

    Args:
        private_key: Hex string. If None, generates a random key.

    Returns:
        OwnerKeys with private key and public key coordinates.
    """
    args = [private_key] if private_key else []
    data = _run_node("keygen.js", args)
    return OwnerKeys(
        private_key=data["privateKey"],
        public_key_ax=data["publicKey"][0],
        public_key_ay=data["publicKey"][1],
    )


def sign_message(private_key: str, message: str) -> dict:
    """Sign a field element with EdDSA-Poseidon.

    Args:
        private_key: Baby JubJub private key (hex).
        message: Field element as string (the Poseidon hash of the delegation).

    Returns:
        Dict with signature (S, R8x, R8y) and publicKey (Ax, Ay).
    """
    data = _run_node("sign.js", [private_key, message])
    return {
        "S": data["signature"]["S"],
        "R8x": data["signature"]["R8"][0],
        "R8y": data["signature"]["R8"][1],
        "Ax": data["publicKey"][0],
        "Ay": data["publicKey"][1],
    }


def poseidon_hash(inputs: list[str | int]) -> str:
    """Compute Poseidon hash matching circomlib's implementation.

    Args:
        inputs: 2-6 field elements (as strings or ints).

    Returns:
        Hash value as string.
    """
    str_inputs = [str(x) for x in inputs]
    cmd = ["node", str(SCRIPTS_DIR / "poseidon_hash.js")] + str_inputs
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"Poseidon hash failed: {result.stderr}")
    return result.stdout.strip()
