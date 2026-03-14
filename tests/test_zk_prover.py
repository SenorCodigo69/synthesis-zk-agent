"""Tests for ZK proof generation and verification."""
import secrets

import pytest

from src.models import ProofType
from src.zk.prover import ZKProver
from src.zk.keys import generate_keys, poseidon_hash, sign_message
from src.zk.commitment import create_delegation


@pytest.fixture
def prover():
    return ZKProver("build")


class TestBudgetRangeProof:
    def test_valid_amount_within_budget(self, prover):
        """Amount < budget should produce valid=1."""
        proof = prover.generate_proof(ProofType.BUDGET_RANGE, {
            "amount": 500,
            "maxBudget": 1000,
            "salt": secrets.randbits(64),
        })
        assert proof.public_signals[1] == "1"  # valid
        assert prover.verify_proof(proof)

    def test_exact_amount_equals_budget(self, prover):
        """Amount == budget should produce valid=1 (less-than-or-equal)."""
        proof = prover.generate_proof(ProofType.BUDGET_RANGE, {
            "amount": 1000,
            "maxBudget": 1000,
            "salt": secrets.randbits(64),
        })
        assert proof.public_signals[1] == "1"
        assert prover.verify_proof(proof)

    def test_amount_exceeds_budget(self, prover):
        """Amount > budget should produce valid=0."""
        proof = prover.generate_proof(ProofType.BUDGET_RANGE, {
            "amount": 1500,
            "maxBudget": 1000,
            "salt": secrets.randbits(64),
        })
        assert proof.public_signals[1] == "0"  # invalid
        assert prover.verify_proof(proof)  # Proof itself is still valid

    def test_same_commitment_regardless_of_validity(self, prover):
        """Same budget+salt should produce same commitment hash."""
        salt = secrets.randbits(64)
        proof_valid = prover.generate_proof(ProofType.BUDGET_RANGE, {
            "amount": 500, "maxBudget": 1000, "salt": salt,
        })
        proof_invalid = prover.generate_proof(ProofType.BUDGET_RANGE, {
            "amount": 1500, "maxBudget": 1000, "salt": salt,
        })
        # Same budget policy → same commitment
        assert proof_valid.public_signals[0] == proof_invalid.public_signals[0]

    def test_zero_amount(self, prover):
        """Zero amount should be valid."""
        proof = prover.generate_proof(ProofType.BUDGET_RANGE, {
            "amount": 0, "maxBudget": 1000, "salt": secrets.randbits(64),
        })
        assert proof.public_signals[1] == "1"

    def test_calldata_export(self, prover):
        """Should export valid Solidity calldata."""
        proof = prover.generate_proof(ProofType.BUDGET_RANGE, {
            "amount": 500, "maxBudget": 1000, "salt": secrets.randbits(64),
        })
        calldata = prover.export_calldata(proof)
        assert calldata
        assert "0x" in calldata


class TestAuthorizationProof:
    def test_valid_authorization(self, prover):
        """Valid delegation should produce a verifiable proof."""
        delegation = create_delegation(
            owner_private_key="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            agent_id=1,
            spend_limit=5000,
        )

        proof = prover.generate_proof(ProofType.AUTHORIZATION, {
            "ownerPubKeyAx": delegation.owner_pub_ax,
            "ownerPubKeyAy": delegation.owner_pub_ay,
            "signatureS": delegation.signature_s,
            "signatureR8x": delegation.signature_r8x,
            "signatureR8y": delegation.signature_r8y,
            "spendLimit": delegation.spend_limit,
            "validUntil": delegation.valid_until,
            "nonce": delegation.nonce,
            "salt": delegation.salt,
            "agentId": delegation.agent_id,
            "policyCommitment": delegation.policy_commitment,
        })

        assert prover.verify_proof(proof)

    def test_wrong_commitment_fails(self, prover):
        """Mismatched commitment should fail proof generation."""
        delegation = create_delegation(
            owner_private_key="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            agent_id=1,
            spend_limit=5000,
        )

        with pytest.raises(RuntimeError):
            prover.generate_proof(ProofType.AUTHORIZATION, {
                "ownerPubKeyAx": delegation.owner_pub_ax,
                "ownerPubKeyAy": delegation.owner_pub_ay,
                "signatureS": delegation.signature_s,
                "signatureR8x": delegation.signature_r8x,
                "signatureR8y": delegation.signature_r8y,
                "spendLimit": delegation.spend_limit,
                "validUntil": delegation.valid_until,
                "nonce": delegation.nonce,
                "salt": delegation.salt,
                "agentId": delegation.agent_id,
                "policyCommitment": "999999",  # Wrong commitment
            })


class TestCumulativeSpendProof:
    def test_within_limit(self, prover):
        """Cumulative spend within limit should produce valid proof."""
        prev_salt = secrets.randbits(64)
        new_salt = secrets.randbits(64)
        period_limit = 10000
        current_total = 3000
        new_amount = 2000

        # Compute previous commitment
        prev_commitment = poseidon_hash([current_total, period_limit, prev_salt])

        proof = prover.generate_proof(ProofType.CUMULATIVE_SPEND, {
            "currentTotal": current_total,
            "newAmount": new_amount,
            "periodLimit": period_limit,
            "previousSalt": prev_salt,
            "newSalt": new_salt,
            "previousCommitment": prev_commitment,
        })

        assert prover.verify_proof(proof)
        # Public signals: [newCommitment, withinLimit, previousCommitment]
        assert proof.public_signals[1] == "1"

    def test_exceeds_limit(self, prover):
        """Cumulative spend exceeding limit should produce withinLimit=0."""
        prev_salt = secrets.randbits(64)
        new_salt = secrets.randbits(64)
        period_limit = 5000
        current_total = 4000
        new_amount = 2000  # 4000 + 2000 = 6000 > 5000

        prev_commitment = poseidon_hash([current_total, period_limit, prev_salt])

        proof = prover.generate_proof(ProofType.CUMULATIVE_SPEND, {
            "currentTotal": current_total,
            "newAmount": new_amount,
            "periodLimit": period_limit,
            "previousSalt": prev_salt,
            "newSalt": new_salt,
            "previousCommitment": prev_commitment,
        })

        assert prover.verify_proof(proof)
        assert proof.public_signals[1] == "0"  # Over limit

    def test_wrong_previous_commitment_fails(self, prover):
        """Wrong previous commitment should fail proof generation."""
        with pytest.raises(RuntimeError):
            prover.generate_proof(ProofType.CUMULATIVE_SPEND, {
                "currentTotal": 1000,
                "newAmount": 500,
                "periodLimit": 10000,
                "previousSalt": 42,
                "newSalt": 99,
                "previousCommitment": "999999",  # Wrong
            })
