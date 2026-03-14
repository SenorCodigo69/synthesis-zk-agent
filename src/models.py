"""Data models for the ZK privacy agent."""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Optional


class ProofType(str, enum.Enum):
    BUDGET_RANGE = "budget_range"
    AUTHORIZATION = "authorization"
    CUMULATIVE_SPEND = "cumulative_spend"


class DisclosureLevel(str, enum.Enum):
    AUDITOR = "auditor"
    TAX_AUTHORITY = "tax_authority"
    PUBLIC = "public"


class ExecutionMode(str, enum.Enum):
    PAPER = "paper"
    DRY_RUN = "dry_run"
    LIVE = "live"


@dataclass
class OwnerKeys:
    """Baby JubJub EdDSA keypair for the owner."""
    private_key: str          # Hex string
    public_key_ax: str        # Field element as string
    public_key_ay: str        # Field element as string


@dataclass
class AgentDelegation:
    """Signed delegation from owner to agent."""
    agent_id: int
    spend_limit: int          # USDC amount (no decimals, raw integer)
    valid_until: int          # Unix timestamp
    nonce: int
    salt: int
    # Signature components
    signature_s: str
    signature_r8x: str
    signature_r8y: str
    # Owner public key
    owner_pub_ax: str
    owner_pub_ay: str
    # Computed
    policy_commitment: str    # Poseidon hash stored on-chain
    message_hash: str         # The signed message hash


@dataclass
class ZKProof:
    """A generated ZK proof with public signals."""
    proof_type: ProofType
    proof: dict               # Groth16 proof (pi_a, pi_b, pi_c, protocol)
    public_signals: list[str]
    verification_key: dict
    generated_at: float = field(default_factory=time.time)
    verified: bool = False


@dataclass
class SpendRecord:
    """Record of a private spend action."""
    amount: int
    timestamp: float
    proof_type: ProofType
    proof_hash: str           # Hash of the proof for audit trail
    commitment: str           # Current cumulative commitment
    protocol: Optional[str] = None
    tx_hash: Optional[str] = None


@dataclass
class DisclosureProof:
    """A selective disclosure proof for a specific audience."""
    level: DisclosureLevel
    claim: str                # What is being disclosed
    value: str                # The disclosed value
    proof: ZKProof            # The ZK proof backing the claim
    generated_at: float = field(default_factory=time.time)


@dataclass
class PolicyState:
    """Current state of the spending policy."""
    delegation: AgentDelegation
    period_limit: int = 0
    cumulative_total: int = 0
    period_start: float = 0.0
    current_commitment: str = ""
    current_salt: int = 0
    spend_history: list[SpendRecord] = field(default_factory=list)
