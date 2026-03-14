"""Tests for the commitment scheme and delegation."""
import time

import pytest

from src.zk.commitment import (
    create_delegation,
    initialize_policy_state,
    record_spend,
)
from src.zk.keys import poseidon_hash


class TestCreateDelegation:
    def test_creates_valid_delegation(self):
        priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        delegation = create_delegation(
            owner_private_key=priv_key,
            agent_id=1,
            spend_limit=5000,
        )
        assert delegation.agent_id == 1
        assert delegation.spend_limit == 5000
        assert delegation.valid_until > time.time()
        assert delegation.policy_commitment
        assert delegation.signature_s
        assert delegation.owner_pub_ax

    def test_deterministic_with_same_params(self):
        priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        # Use same valid_for_seconds=0 so valid_until is based on same second
        d1 = create_delegation(priv_key, 1, 5000, nonce=42, salt=99)
        # Same key, same nonce+salt → same owner pubkey in commitment
        # But valid_until changes with time.time(), so compare pubkeys + message structure
        d2 = create_delegation(priv_key, 1, 5000, nonce=42, salt=99)
        assert d1.owner_pub_ax == d2.owner_pub_ax
        assert d1.owner_pub_ay == d2.owner_pub_ay

    def test_different_agents_different_commitments(self):
        priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        d1 = create_delegation(priv_key, 1, 5000)
        d2 = create_delegation(priv_key, 2, 5000)
        # Different agent IDs → different message hashes → different signatures
        assert d1.message_hash != d2.message_hash


class TestPolicyState:
    def test_initialize_state(self):
        priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        delegation = create_delegation(priv_key, 1, 5000)
        state = initialize_policy_state(delegation, 10000)

        assert state.cumulative_total == 0
        assert state.current_commitment
        assert state.current_salt > 0
        assert state.period_start > 0
        assert len(state.spend_history) == 0

    def test_record_spend_updates_state(self):
        priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        delegation = create_delegation(priv_key, 1, 5000)
        state = initialize_policy_state(delegation, 10000)

        old_commitment = state.current_commitment
        state = record_spend(state, 1000, "proof_hash_1", "aave-v3")

        assert state.cumulative_total == 1000
        assert state.current_commitment != old_commitment
        assert len(state.spend_history) == 1
        assert state.spend_history[0].amount == 1000
        assert state.spend_history[0].protocol == "aave-v3"

    def test_multiple_spends_accumulate(self):
        priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        delegation = create_delegation(priv_key, 1, 5000)
        state = initialize_policy_state(delegation, 10000)

        state = record_spend(state, 1000, "ph1")
        state = record_spend(state, 2000, "ph2")
        state = record_spend(state, 500, "ph3")

        assert state.cumulative_total == 3500
        assert len(state.spend_history) == 3
