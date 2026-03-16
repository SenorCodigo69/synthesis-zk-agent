"""ZK-Gated Uniswap V4 Hook client.

Interacts with the deployed ZKGatedHook contract on Base mainnet.
Handles:
  - Pre-authorizing agents (owner only)
  - Revoking authorizations
  - Encoding ZK proofs as hookData for Uniswap V4 swaps
  - Checking authorization status
"""
from __future__ import annotations

import logging
from typing import Any

from web3 import Web3

logger = logging.getLogger(__name__)

# Deployed contract addresses on Base mainnet
ZK_HOOK_ADDRESS = "0x859Ae689bE007183aC78D364e5550EBc15324080"
POOL_MANAGER_ADDRESS = "0x498581fF718922c3f8e6A244956aF099B2652b2b"
AUTH_VERIFIER_ADDRESS = "0x2a8FBE80BDc9cb907b20acBE84F13a858CBEdAe4"

# Minimal ABI for ZKGatedHook
ZK_HOOK_ABI = [
    {
        "inputs": [{"name": "agent", "type": "address"}],
        "name": "authorized",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "authorizedCount",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "agent", "type": "address"}],
        "name": "preAuthorize",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "agent", "type": "address"}],
        "name": "revokeAuthorization",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agent", "type": "address"},
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": True, "name": "policyCommitment", "type": "uint256"},
        ],
        "name": "AgentAuthorized",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agent", "type": "address"},
        ],
        "name": "AgentRevoked",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "sender", "type": "address"},
            {"indexed": False, "name": "authorized", "type": "bool"},
        ],
        "name": "SwapGated",
        "type": "event",
    },
]


class ZKHookClient:
    """Client for interacting with the ZK-Gated Uniswap V4 Hook."""

    def __init__(
        self,
        w3: Web3,
        hook_address: str = ZK_HOOK_ADDRESS,
        private_key: str | None = None,
    ):
        self.w3 = w3
        self.hook_address = w3.to_checksum_address(hook_address)
        self.contract = w3.eth.contract(address=self.hook_address, abi=ZK_HOOK_ABI)
        self.private_key = private_key
        self.account = (
            w3.eth.account.from_key(private_key).address if private_key else None
        )

    def is_authorized(self, agent_address: str) -> bool:
        """Check if an address is authorized to swap through the hook."""
        addr = self.w3.to_checksum_address(agent_address)
        return self.contract.functions.authorized(addr).call()

    def authorized_count(self) -> int:
        """Get the total number of authorized agents."""
        return self.contract.functions.authorizedCount().call()

    def owner(self) -> str:
        """Get the hook owner address."""
        return self.contract.functions.owner().call()

    def pre_authorize(self, agent_address: str) -> dict:
        """Pre-authorize an agent without requiring a ZK proof (owner only).

        Args:
            agent_address: The address to authorize.

        Returns:
            Transaction receipt dict.
        """
        if not self.private_key:
            raise ValueError("Private key required for transactions")

        addr = self.w3.to_checksum_address(agent_address)
        tx = self.contract.functions.preAuthorize(addr).build_transaction({
            "from": self.account,
            "nonce": self.w3.eth.get_transaction_count(self.account),
            "maxFeePerGas": self.w3.to_wei(0.5, "gwei"),
            "maxPriorityFeePerGas": self.w3.to_wei(0.001, "gwei"),
            "chainId": 8453,
        })

        signed = self.w3.eth.account.sign_transaction(tx, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        logger.info(
            "Pre-authorized %s on ZKGatedHook | tx: %s | status: %s",
            addr,
            receipt["transactionHash"].hex(),
            "success" if receipt["status"] == 1 else "FAILED",
        )
        return dict(receipt)

    def revoke_authorization(self, agent_address: str) -> dict:
        """Revoke an agent's authorization (owner only).

        Args:
            agent_address: The address to revoke.

        Returns:
            Transaction receipt dict.
        """
        if not self.private_key:
            raise ValueError("Private key required for transactions")

        addr = self.w3.to_checksum_address(agent_address)
        tx = self.contract.functions.revokeAuthorization(addr).build_transaction({
            "from": self.account,
            "nonce": self.w3.eth.get_transaction_count(self.account),
            "maxFeePerGas": self.w3.to_wei(0.5, "gwei"),
            "maxPriorityFeePerGas": self.w3.to_wei(0.001, "gwei"),
            "chainId": 8453,
        })

        signed = self.w3.eth.account.sign_transaction(tx, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        logger.info(
            "Revoked authorization for %s | tx: %s",
            addr,
            receipt["transactionHash"].hex(),
        )
        return dict(receipt)

    @staticmethod
    def encode_proof_as_hook_data(
        p_a: list[int],
        p_b: list[list[int]],
        p_c: list[int],
        pub_signals: list[int],
    ) -> bytes:
        """Encode a Groth16 ZK proof as hookData for Uniswap V4 swaps.

        The hookData is ABI-encoded as:
            abi.encode(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[2] pubSignals)

        Args:
            p_a: Proof point A [2 elements]
            p_b: Proof point B [2x2 elements]
            p_c: Proof point C [2 elements]
            pub_signals: Public signals [agentId, policyCommitment]

        Returns:
            ABI-encoded bytes for hookData parameter.
        """
        return Web3().codec.encode(
            ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[2]"],
            [p_a, p_b, p_c, pub_signals],
        )

    @staticmethod
    def parse_calldata_to_hook_data(calldata: str) -> bytes:
        """Convert snarkjs calldata output to ABI-encoded hookData.

        Args:
            calldata: Raw snarkjs calldata string.

        Returns:
            ABI-encoded bytes for hookData.
        """
        import json

        wrapped = "[" + calldata.strip() + "]"
        parsed = json.loads(wrapped)

        if len(parsed) != 4:
            raise ValueError(f"Expected 4 calldata components, got {len(parsed)}")

        def to_int(x: Any) -> int:
            if isinstance(x, str) and x.startswith("0x"):
                return int(x, 16)
            return int(x)

        p_a = [to_int(x) for x in parsed[0]]
        p_b = [[to_int(x) for x in row] for row in parsed[1]]
        p_c = [to_int(x) for x in parsed[2]]
        pub_signals = [to_int(x) for x in parsed[3]]

        return ZKHookClient.encode_proof_as_hook_data(p_a, p_b, p_c, pub_signals)
