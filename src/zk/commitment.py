"""On-chain commitment scheme for spending policies.

The commitment scheme (Option B from design doc):
  1. Owner defines policy + signs delegation
  2. Policy commitment = Poseidon(ownerPubAx, spendLimit, validUntil, nonce, salt)
  3. Commitment published on-chain
  4. Agent proves compliance via ZK proofs referencing the commitment
"""
from __future__ import annotations

import copy
import secrets
import time

from src.models import AgentDelegation, PolicyState, ProofType, SpendRecord
from src.zk.keys import generate_keys, poseidon_hash, sign_message

# Sequential nonce counter — initialized from DB on first call to avoid
# reuse across process restarts.
_nonce_counter = 0
_nonce_initialized = False


def _next_nonce() -> int:
    """Return a sequential nonce for anti-replay protection.

    On first call, loads the max nonce from the database to avoid
    reusing nonces from previous sessions.
    """
    global _nonce_counter, _nonce_initialized
    if not _nonce_initialized:
        _nonce_initialized = True
        try:
            from src.database import Database
            db = Database()
            row = db.conn.execute(
                "SELECT MAX(CAST(nonce AS INTEGER)) as max_nonce FROM delegations"
            ).fetchone()
            if row and row["max_nonce"] is not None:
                _nonce_counter = row["max_nonce"]
            db.close()
        except Exception:
            pass  # Fresh DB or no delegations yet
    _nonce_counter += 1
    return _nonce_counter


def create_delegation(
    owner_private_key: str,
    agent_id: int,
    spend_limit: int,
    valid_for_seconds: int = 604800,
    nonce: int | None = None,
    salt: int | None = None,
) -> AgentDelegation:
    """Create a signed delegation from owner to agent.

    Args:
        owner_private_key: Owner's Baby JubJub private key (hex).
        agent_id: Agent identifier.
        spend_limit: Maximum spend amount (USDC, no decimals).
        valid_for_seconds: How long the delegation is valid.
        nonce: Anti-replay nonce (auto-generated if None).
        salt: Commitment salt (auto-generated if None).

    Returns:
        AgentDelegation with all fields populated.
    """
    if nonce is None:
        nonce = _next_nonce()
    if salt is None:
        salt = secrets.randbits(128)

    valid_until = int(time.time()) + valid_for_seconds

    # Derive owner public key
    keys = generate_keys(owner_private_key)

    # Compute delegation message = Poseidon(agentId, spendLimit, validUntil, nonce)
    message_hash = poseidon_hash([agent_id, spend_limit, valid_until, nonce])

    # Sign the message
    sig = sign_message(owner_private_key, message_hash)

    # Compute policy commitment = Poseidon(ownerPubAx, spendLimit, validUntil, nonce, salt)
    policy_commitment = poseidon_hash([
        keys.public_key_ax, spend_limit, valid_until, nonce, salt
    ])

    return AgentDelegation(
        agent_id=agent_id,
        spend_limit=spend_limit,
        valid_until=valid_until,
        nonce=nonce,
        salt=salt,
        signature_s=sig["S"],
        signature_r8x=sig["R8x"],
        signature_r8y=sig["R8y"],
        owner_pub_ax=sig["Ax"],
        owner_pub_ay=sig["Ay"],
        policy_commitment=policy_commitment,
        message_hash=message_hash,
    )


def initialize_policy_state(
    delegation: AgentDelegation,
    period_limit: int,
) -> PolicyState:
    """Initialize a fresh policy state for cumulative spend tracking.

    Args:
        delegation: The signed delegation from the owner.
        period_limit: Maximum cumulative spend per period.

    Returns:
        PolicyState with initial commitment.
    """
    initial_salt = secrets.randbits(128)
    # Initial commitment: Poseidon(0, periodLimit, salt) — total=0
    initial_commitment = poseidon_hash([0, period_limit, initial_salt])

    return PolicyState(
        delegation=delegation,
        period_limit=period_limit,
        cumulative_total=0,
        period_start=time.time(),
        current_commitment=initial_commitment,
        current_salt=initial_salt,
    )


def record_spend(
    state: PolicyState,
    amount: int,
    proof_hash: str,
    protocol: str | None = None,
    tx_hash: str | None = None,
    new_salt: int | None = None,
) -> PolicyState:
    """Record a spend and return a new PolicyState with updated commitment.

    The original state is not modified.

    Args:
        state: Current policy state.
        amount: Amount spent.
        proof_hash: Hash of the ZK proof for audit trail.
        protocol: Protocol name (optional).
        tx_hash: On-chain tx hash (optional).
        new_salt: Salt for new commitment (use proof's salt for consistency).

    Returns:
        New PolicyState with updated commitment.
    """
    new_total = state.cumulative_total + amount
    if new_salt is None:
        new_salt = secrets.randbits(128)

    # Compute new commitment with the period limit
    new_commitment = poseidon_hash([
        new_total, state.period_limit, new_salt
    ])

    record = SpendRecord(
        amount=amount,
        timestamp=time.time(),
        proof_type=ProofType.CUMULATIVE_SPEND,
        proof_hash=proof_hash,
        commitment=new_commitment,
        protocol=protocol,
        tx_hash=tx_hash,
    )

    new_state = copy.deepcopy(state)
    new_state.cumulative_total = new_total
    new_state.current_commitment = new_commitment
    new_state.current_salt = new_salt
    new_state.spend_history.append(record)

    return new_state
