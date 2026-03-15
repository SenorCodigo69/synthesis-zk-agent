"""ZK-gated private execution — all DeFi actions require valid ZK proofs.

Flow:
  1. Agent proposes an action (deposit/withdraw)
  2. Full compliance check: authorization + budget + cumulative
  3. If compliant, execute the action
  4. Record spend with proof hash for audit trail
  5. Update cumulative commitment
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from src.models import ExecutionMode, PolicyState, ProofType
from src.privacy.policy import PolicyManager
from src.zk.commitment import record_spend
from src.zk.prover import ZKProver


class PrivateExecutor:
    """Executes DeFi actions with ZK proof gates."""

    def __init__(
        self,
        prover: ZKProver,
        policy_manager: PolicyManager,
        mode: ExecutionMode = ExecutionMode.PAPER,
    ):
        self.prover = prover
        self.policy_manager = policy_manager
        self.mode = mode
        self.execution_log: list[dict] = []

    def execute_private_action(
        self,
        action: str,
        amount: int,
        protocol: str,
        state: PolicyState,
    ) -> dict:
        """Execute a DeFi action with ZK proof gate.

        Args:
            action: "deposit" or "withdraw"
            amount: USDC amount (no decimals)
            protocol: Target protocol name
            state: Current policy state

        Returns:
            Dict with execution result, proofs, and updated state.
        """
        result = {
            "action": action,
            "amount": amount,
            "protocol": protocol,
            "mode": self.mode.value,
            "timestamp": time.time(),
        }

        # Step 1: Full compliance check
        compliance = self.policy_manager.full_compliance_check(amount, state)
        result["compliance"] = {
            "compliant": compliance["compliant"],
            "reason": compliance.get("reason"),
        }

        if not compliance["compliant"]:
            result["status"] = "REJECTED"
            result["reason"] = compliance.get("reason", "Compliance check failed")
            self.execution_log.append(result)
            return result

        # Step 2: Execute (or simulate)
        if self.mode == ExecutionMode.PAPER:
            result["status"] = "SIMULATED"
            result["tx_hash"] = f"0x_paper_{int(time.time())}_{amount}"
        elif self.mode == ExecutionMode.DRY_RUN:
            result["status"] = "DRY_RUN"
            result["tx_hash"] = None
        else:
            # Live mode — would call web3 here
            result["status"] = "LIVE_NOT_IMPLEMENTED"
            result["tx_hash"] = None

        # Step 3: Record spend and update state
        proof_hash = self._hash_proof(compliance)
        # Use the salt from the cumulative proof for commitment consistency
        cumulative_salt = compliance.get("cumulative", {}).get("new_salt")
        updated_state = record_spend(
            state=state,
            amount=amount,
            proof_hash=proof_hash,
            protocol=protocol,
            tx_hash=result.get("tx_hash"),
            new_salt=cumulative_salt,
        )
        result["updated_state"] = {
            "cumulative_total": updated_state.cumulative_total,
            "commitment": updated_state.current_commitment,
            "current_salt": updated_state.current_salt,
            "spend_count": len(updated_state.spend_history),
        }
        # Expose full state for callers that need to chain actions
        result["_policy_state"] = updated_state

        # Step 4: Collect proof data
        result["proofs"] = {
            "authorization": self._proof_summary(compliance.get("auth", {}).get("proof")),
            "budget_range": self._proof_summary(compliance.get("budget", {}).get("proof")),
            "cumulative_spend": self._proof_summary(
                compliance.get("cumulative", {}).get("proof")
            ),
        }

        self.execution_log.append(result)
        return result

    def get_execution_log(self) -> list[dict]:
        """Get the full execution audit trail."""
        return self.execution_log

    def _hash_proof(self, compliance: dict) -> str:
        """Create a hash of the compliance proofs for the audit trail."""
        proof_data = {}
        for key in ("auth", "budget", "cumulative"):
            p = compliance.get(key, {}).get("proof")
            if p:
                proof_data[key] = p.public_signals
        return hashlib.sha256(json.dumps(proof_data).encode()).hexdigest()[:16]

    def _proof_summary(self, proof: Any) -> dict | None:
        """Extract a summary from a ZKProof for logging."""
        if proof is None:
            return None
        return {
            "type": proof.proof_type.value,
            "public_signals": proof.public_signals,
            "verified": proof.verified,
        }
