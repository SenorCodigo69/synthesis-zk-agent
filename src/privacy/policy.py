"""Spending policy management — human-defined constraints with ZK enforcement."""
from __future__ import annotations

import secrets
import time
from typing import Any

from src.models import PolicyState, ProofType
from src.zk.prover import ZKProver


class PolicyManager:
    """Manages spending policies and generates compliance proofs."""

    def __init__(self, prover: ZKProver, config: dict[str, Any]):
        self.prover = prover
        self.policy_config = config.get("spending_policy", {})
        self.max_single = self.policy_config.get("max_single_spend", 5000)
        self.period_limit = self.policy_config.get("period_limit", 10000)
        self.period_seconds = self.policy_config.get("period_seconds", 86400)

    def check_authorization(self, state: PolicyState) -> dict:
        """Generate authorization proof that agent is delegated by owner.

        Returns:
            Dict with proof and authorization status.
        """
        delegation = state.delegation

        # Check expiry
        if delegation.valid_until < time.time():
            return {"authorized": False, "reason": "Delegation expired"}

        inputs = {
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
        }

        proof = self.prover.generate_proof(ProofType.AUTHORIZATION, inputs)
        verified = self.prover.verify_proof(proof)

        return {
            "authorized": verified,
            "proof": proof,
            "agent_id": delegation.agent_id,
            "policy_commitment": delegation.policy_commitment,
        }

    def check_budget(self, amount: int, state: PolicyState) -> dict:
        """Generate budget range proof that amount is within spend limit.

        Args:
            amount: The proposed spend amount.
            state: Current policy state.

        Returns:
            Dict with proof and budget status.
        """
        if amount > self.max_single:
            return {
                "within_budget": False,
                "reason": f"Amount {amount} exceeds max single spend {self.max_single}",
            }

        inputs = {
            "amount": amount,
            "maxBudget": state.delegation.spend_limit,
            "salt": secrets.randbits(128),
        }

        proof = self.prover.generate_proof(ProofType.BUDGET_RANGE, inputs)
        verified = self.prover.verify_proof(proof)

        # Public signals: [commitmentHash, valid]
        valid_signal = proof.public_signals[1] if len(proof.public_signals) > 1 else "0"

        return {
            "within_budget": verified and valid_signal == "1",
            "proof": proof,
            "commitment": proof.public_signals[0] if proof.public_signals else None,
        }

    def check_cumulative(self, amount: int, state: PolicyState) -> dict:
        """Generate cumulative spend proof that total is within period limit.

        Args:
            amount: The proposed spend amount.
            state: Current policy state.

        Returns:
            Dict with proof, new commitment, and limit status.
        """
        import secrets
        from src.zk.keys import poseidon_hash

        # Auto-reset if period expired
        if time.time() - state.period_start > self.period_seconds:
            state.cumulative_total = 0
            state.period_start = time.time()
            state.current_salt = secrets.randbits(128)
            state.current_commitment = poseidon_hash([
                0, state.period_limit, state.current_salt
            ])

        new_salt = secrets.randbits(128)

        inputs = {
            "currentTotal": state.cumulative_total,
            "newAmount": amount,
            "periodLimit": state.period_limit,
            "previousSalt": state.current_salt,
            "newSalt": new_salt,
            "previousCommitment": state.current_commitment,
        }

        proof = self.prover.generate_proof(ProofType.CUMULATIVE_SPEND, inputs)
        verified = self.prover.verify_proof(proof)

        # Public signals: [newCommitment, withinLimit, previousCommitment]
        within_limit = (
            proof.public_signals[1] == "1"
            if len(proof.public_signals) > 1
            else False
        )

        return {
            "within_limit": verified and within_limit,
            "proof": proof,
            "new_commitment": proof.public_signals[0] if proof.public_signals else None,
            "new_salt": new_salt,
        }

    def full_compliance_check(self, amount: int, state: PolicyState) -> dict:
        """Run all 3 proofs: authorization + budget + cumulative.

        Returns:
            Dict with all proof results and overall compliance status.
        """
        auth = self.check_authorization(state)
        if not auth["authorized"]:
            return {"compliant": False, "reason": "Authorization failed", "auth": auth}

        budget = self.check_budget(amount, state)
        if not budget["within_budget"]:
            return {"compliant": False, "reason": "Budget exceeded", "budget": budget}

        cumulative = self.check_cumulative(amount, state)
        if not cumulative["within_limit"]:
            return {
                "compliant": False,
                "reason": "Cumulative limit exceeded",
                "cumulative": cumulative,
            }

        return {
            "compliant": True,
            "auth": auth,
            "budget": budget,
            "cumulative": cumulative,
        }
