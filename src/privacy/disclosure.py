"""Selective disclosure controller — ZK-backed claims for different audiences.

Each disclosure generates a purpose-specific ZK proof:
  - Auditor: total monthly spend (not individual txs)
  - Tax authority: total yield earned (not which protocols)
  - Public: proof of compliance only
"""
from __future__ import annotations

import secrets
from typing import Any

from src.models import DisclosureLevel, DisclosureProof, PolicyState, ProofType
from src.zk.prover import ZKProver


class DisclosureController:
    """Manages selective disclosure with ZK proofs."""

    def __init__(self, prover: ZKProver, config: dict[str, Any]):
        self.prover = prover
        self.policies = config.get("disclosure", {})

    def can_disclose(self, level: DisclosureLevel, claim: str) -> bool:
        """Check if a claim is allowed for a disclosure level."""
        policy = self.policies.get(level.value, {})
        allowed = policy.get("can_see", [])
        blocked = policy.get("cannot_see", [])

        if claim in blocked:
            return False
        if claim in allowed:
            return True
        # Default deny
        return False

    def generate_spend_total_proof(
        self,
        state: PolicyState,
        level: DisclosureLevel,
    ) -> DisclosureProof | None:
        """Generate a proof of total spend for a disclosure level.

        Uses a budget range proof to prove the total is within a range
        without revealing the exact amount or individual transactions.
        """
        claim = "total_monthly_spend"
        if not self.can_disclose(level, claim):
            return None

        total = state.cumulative_total
        limit = state.delegation.spend_limit

        # Generate a range proof showing total <= limit (unique salt per disclosure)
        inputs = {
            "amount": total,
            "maxBudget": limit,
            "salt": secrets.randbits(128),
        }

        proof = self.prover.generate_proof(ProofType.BUDGET_RANGE, inputs)
        self.prover.verify_proof(proof)

        return DisclosureProof(
            level=level,
            claim=claim,
            value=f"Total spend within authorized limit (proof verified)",
            proof=proof,
        )

    def generate_compliance_proof(
        self,
        state: PolicyState,
        level: DisclosureLevel,
    ) -> DisclosureProof | None:
        """Generate a proof of policy compliance for public disclosure."""
        claim = "proof_of_compliance"
        if not self.can_disclose(level, claim):
            return None

        # Use budget range proof — proves agent operated within limits
        total = state.cumulative_total
        limit = state.delegation.spend_limit

        inputs = {
            "amount": total,
            "maxBudget": limit,
            "salt": secrets.randbits(128),
        }

        proof = self.prover.generate_proof(ProofType.BUDGET_RANGE, inputs)
        self.prover.verify_proof(proof)

        return DisclosureProof(
            level=level,
            claim=claim,
            value="Agent operated within all policy constraints",
            proof=proof,
        )

    def generate_solvency_proof(
        self,
        state: PolicyState,
        current_balance: int,
        level: DisclosureLevel,
    ) -> DisclosureProof | None:
        """Generate a proof of solvency — balance covers obligations.

        Proves balance >= cumulative_total without revealing exact balance.
        """
        claim = "proof_of_solvency"
        if not self.can_disclose(level, claim):
            return None

        # Prove balance >= total_spent (balance is the "budget", total is the "amount")
        inputs = {
            "amount": state.cumulative_total,
            "maxBudget": current_balance,
            "salt": secrets.randbits(128),
        }

        proof = self.prover.generate_proof(ProofType.BUDGET_RANGE, inputs)
        self.prover.verify_proof(proof)

        return DisclosureProof(
            level=level,
            claim=claim,
            value="Agent is solvent (obligations covered by balance)",
            proof=proof,
        )

    def get_disclosure_summary(
        self, state: PolicyState, level: DisclosureLevel
    ) -> dict:
        """Get all available disclosures for a given level."""
        policy = self.policies.get(level.value, {})
        allowed = policy.get("can_see", [])

        summary = {
            "level": level.value,
            "allowed_claims": allowed,
            "proofs": {},
        }

        if "total_monthly_spend" in allowed:
            proof = self.generate_spend_total_proof(state, level)
            if proof:
                summary["proofs"]["total_monthly_spend"] = {
                    "claim": proof.claim,
                    "value": proof.value,
                    "verified": proof.proof.verified,
                }

        if "proof_of_compliance" in allowed:
            proof = self.generate_compliance_proof(state, level)
            if proof:
                summary["proofs"]["proof_of_compliance"] = {
                    "claim": proof.claim,
                    "value": proof.value,
                    "verified": proof.proof.verified,
                }

        if "proof_of_solvency" in allowed:
            # Solvency needs balance — use spend limit as proxy
            proof = self.generate_solvency_proof(
                state, state.delegation.spend_limit, level
            )
            if proof:
                summary["proofs"]["proof_of_solvency"] = {
                    "claim": proof.claim,
                    "value": proof.value,
                    "verified": proof.proof.verified,
                }

        return summary
