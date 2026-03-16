"""ZK-Gated Uniswap V4 Hook client.

Interacts with the deployed ZKGatedHook contract on Base mainnet.
Handles:
  - Pre-authorizing agents (owner only)
  - Revoking authorizations
  - Binding agent IDs to addresses
  - Encoding ZK proofs as hookData for Uniswap V4 swaps
  - Checking authorization status
"""
from __future__ import annotations

import logging
from typing import Any

from web3 import Web3

logger = logging.getLogger(__name__)

# Deployed contract addresses on Base mainnet
ZK_HOOK_ADDRESS = "0x45eC09fB08B83f104F15f3709F4677736112c080"
POOL_MANAGER_ADDRESS = "0x498581fF718922c3f8e6A244956aF099B2652b2b"
AUTH_VERIFIER_ADDRESS = "0x2a8FBE80BDc9cb907b20acBE84F13a858CBEdAe4"

# Base chain ID
BASE_CHAIN_ID = 8453

# Gas ceiling (SEC-M03)
MAX_FEE_PER_GAS_WEI = Web3.to_wei(5, "gwei")

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
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "agent", "type": "address"},
        ],
        "name": "bindAgent",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "disablePreAuth",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "preAuthDisabled",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "agent", "type": "address"}],
        "name": "authorizedUntil",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "agentId", "type": "uint256"}],
        "name": "agentBinding",
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "proofHash", "type": "bytes32"}],
        "name": "usedProofHashes",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
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
        "inputs": [{"indexed": True, "name": "agent", "type": "address"}],
        "name": "AgentRevoked",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "agentId", "type": "uint256"},
            {"indexed": True, "name": "agent", "type": "address"},
        ],
        "name": "AgentBound",
        "type": "event",
    },
]


class _TransactionSigner:
    """Isolated private key holder — key never exposed as attribute (SEC-M02)."""

    __slots__ = ("_key", "_address")

    def __init__(self, private_key: str, w3: Web3):
        acct = w3.eth.account.from_key(private_key)
        self._key = private_key
        self._address = acct.address

    @property
    def address(self) -> str:
        return self._address

    def sign(self, tx: dict, w3: Web3) -> bytes:
        signed = w3.eth.account.sign_transaction(tx, self._key)
        return signed.raw_transaction


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
        self._signer: _TransactionSigner | None = None

        if private_key:
            # Validate chain ID on startup (SEC-L02)
            chain_id = w3.eth.chain_id
            if chain_id != BASE_CHAIN_ID:
                raise ValueError(
                    f"Wrong chain: connected to {chain_id}, expected Base ({BASE_CHAIN_ID})"
                )
            self._signer = _TransactionSigner(private_key, w3)

    def _build_and_send_tx(self, fn) -> dict:
        """Build, sign, and send a transaction with dynamic gas (SEC-M03)."""
        if not self._signer:
            raise ValueError("Private key required for transactions")

        # Dynamic gas pricing with ceiling
        base_fee = self.w3.eth.gas_price
        max_fee = min(base_fee * 2, MAX_FEE_PER_GAS_WEI)
        priority_fee = min(self.w3.to_wei(0.001, "gwei"), max_fee)

        tx = fn.build_transaction({
            "from": self._signer.address,
            "nonce": self.w3.eth.get_transaction_count(self._signer.address),
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": priority_fee,
            "chainId": BASE_CHAIN_ID,
        })

        raw = self._signer.sign(tx, self.w3)
        tx_hash = self.w3.eth.send_raw_transaction(raw)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        return dict(receipt)

    def is_authorized(self, agent_address: str) -> bool:
        """Check if an address is currently authorized (TTL-aware)."""
        addr = self.w3.to_checksum_address(agent_address)
        return self.contract.functions.authorized(addr).call()

    def authorized_until(self, agent_address: str) -> int:
        """Get the authorization expiry timestamp for an address."""
        addr = self.w3.to_checksum_address(agent_address)
        return self.contract.functions.authorizedUntil(addr).call()

    def authorized_count(self) -> int:
        """Get the total number of authorized agents."""
        return self.contract.functions.authorizedCount().call()

    def owner(self) -> str:
        """Get the hook owner address."""
        return self.contract.functions.owner().call()

    def is_pre_auth_disabled(self) -> bool:
        """Check if preAuthorize is permanently disabled."""
        return self.contract.functions.preAuthDisabled().call()

    def get_agent_binding(self, agent_id: int) -> str:
        """Get the address bound to an agent ID."""
        return self.contract.functions.agentBinding(agent_id).call()

    def is_proof_used(self, proof_hash: bytes) -> bool:
        """Check if a proof hash has been used (nullifier)."""
        return self.contract.functions.usedProofHashes(proof_hash).call()

    def pre_authorize(self, agent_address: str) -> dict:
        """Pre-authorize an agent without requiring a ZK proof (owner only)."""
        addr = self.w3.to_checksum_address(agent_address)
        receipt = self._build_and_send_tx(
            self.contract.functions.preAuthorize(addr)
        )
        logger.info(
            "Pre-authorized %s | tx: %s | status: %s",
            addr,
            receipt["transactionHash"].hex(),
            "success" if receipt["status"] == 1 else "FAILED",
        )
        return receipt

    def revoke_authorization(self, agent_address: str) -> dict:
        """Revoke an agent's authorization (owner only)."""
        addr = self.w3.to_checksum_address(agent_address)
        receipt = self._build_and_send_tx(
            self.contract.functions.revokeAuthorization(addr)
        )
        logger.info(
            "Revoked authorization for %s | tx: %s",
            addr,
            receipt["transactionHash"].hex(),
        )
        return receipt

    def bind_agent(self, agent_id: int, agent_address: str) -> dict:
        """Bind an agent ID to an Ethereum address (owner only).

        Once bound, only this address can use proofs for this agentId.
        """
        addr = self.w3.to_checksum_address(agent_address)
        receipt = self._build_and_send_tx(
            self.contract.functions.bindAgent(agent_id, addr)
        )
        logger.info(
            "Bound agentId %d to %s | tx: %s",
            agent_id,
            addr,
            receipt["transactionHash"].hex(),
        )
        return receipt

    def disable_pre_auth(self) -> dict:
        """Permanently disable preAuthorize (owner only, irreversible)."""
        receipt = self._build_and_send_tx(
            self.contract.functions.disablePreAuth()
        )
        logger.info(
            "Pre-auth permanently disabled | tx: %s",
            receipt["transactionHash"].hex(),
        )
        return receipt

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
        """
        return Web3().codec.encode(
            ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[2]"],
            [p_a, p_b, p_c, pub_signals],
        )

    @staticmethod
    def parse_calldata_to_hook_data(calldata: str) -> bytes:
        """Convert snarkjs calldata output to ABI-encoded hookData."""
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
