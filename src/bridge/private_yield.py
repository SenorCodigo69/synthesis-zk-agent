"""Bridge between yield agent and ZK privacy layer.

Wraps the yield agent's execution with ZK proof gates:
  1. Yield agent computes allocation plan (what to deposit/withdraw)
  2. For each action, ZK agent runs 3 compliance proofs
  3. If compliant -> execute; if not -> skip
  4. Record both yield execution and ZK proofs in audit trail
"""
from __future__ import annotations

import asyncio
import logging
import time
from decimal import Decimal
from typing import Any

from src.models import ExecutionMode, PolicyState
from src.privacy.executor import PrivateExecutor
from src.privacy.policy import PolicyManager
from src.zk.prover import ZKProver

logger = logging.getLogger(__name__)


class PrivateYieldExecutor:
    """Wraps yield agent execution with ZK proof gates."""

    def __init__(
        self,
        prover: ZKProver,
        policy_manager: PolicyManager,
        policy_state: PolicyState,
        mode: ExecutionMode = ExecutionMode.PAPER,
    ):
        self.private_executor = PrivateExecutor(prover, policy_manager, mode)
        self.policy_state = policy_state
        self.mode = mode
        self.results: list[dict] = []

    def execute_yield_actions(
        self,
        actions: list[dict],
    ) -> list[dict]:
        """Execute a list of yield actions with ZK proof gates.

        Args:
            actions: List of dicts with keys:
                - action: "deposit" or "withdraw"
                - protocol: Protocol name string
                - amount_usd: Decimal amount in USD
                - reasoning: Why this action is being taken

        Returns:
            List of result dicts with ZK compliance + execution status.
        """
        results = []

        for action_spec in actions:
            action = action_spec["action"]
            protocol = action_spec["protocol"]
            amount_usd = action_spec["amount_usd"]
            reasoning = action_spec.get("reasoning", "")

            # Convert Decimal USD to integer USDC (ZK circuits use integers)
            amount_usdc = int(amount_usd)

            if amount_usdc <= 0:
                results.append({
                    "action": action,
                    "protocol": protocol,
                    "amount_usd": float(amount_usd),
                    "status": "SKIPPED",
                    "reason": "Zero or negative amount",
                    "zk_compliant": False,
                })
                continue

            # Withdrawals don't need ZK compliance (only spending does)
            if action == "withdraw":
                results.append({
                    "action": action,
                    "protocol": protocol,
                    "amount_usd": float(amount_usd),
                    "status": "SIMULATED" if self.mode == ExecutionMode.PAPER else "DRY_RUN",
                    "zk_compliant": True,
                    "reason": "Withdrawals bypass ZK gates (not a spend)",
                    "proofs": {},
                })
                continue

            # Run ZK compliance check + execute
            result = self.private_executor.execute_private_action(
                action=action,
                amount=amount_usdc,
                protocol=protocol,
                state=self.policy_state,
            )

            # Update policy state if execution succeeded
            if result["status"] not in ("REJECTED",):
                # PrivateExecutor returns the full updated PolicyState
                new_state = result.get("_policy_state")
                if new_state is not None:
                    self.policy_state = new_state

            bridge_result = {
                "action": action,
                "protocol": protocol,
                "amount_usd": float(amount_usd),
                "amount_usdc": amount_usdc,
                "status": result["status"],
                "zk_compliant": result["compliance"]["compliant"],
                "reason": result.get("reason", reasoning),
                "tx_hash": result.get("tx_hash"),
                "proofs": result.get("proofs", {}),
                "cumulative_total": result.get("updated_state", {}).get("cumulative_total", 0),
                "timestamp": result.get("timestamp", time.time()),
            }
            results.append(bridge_result)

        self.results.extend(results)
        return results

    def get_summary(self) -> dict:
        """Get execution summary."""
        total = len(self.results)
        executed = sum(1 for r in self.results if r["status"] in ("SIMULATED", "DRY_RUN", "SUCCESS"))
        rejected = sum(1 for r in self.results if r["status"] == "REJECTED")
        skipped = sum(1 for r in self.results if r["status"] == "SKIPPED")
        total_usd = sum(r["amount_usd"] for r in self.results if r["status"] not in ("REJECTED", "SKIPPED"))
        proof_count = sum(
            len(r.get("proofs", {}))
            for r in self.results
            if r.get("proofs")
        )

        return {
            "total_actions": total,
            "executed": executed,
            "rejected": rejected,
            "skipped": skipped,
            "total_usd": total_usd,
            "proof_count": proof_count,
            "cumulative_total": self.policy_state.cumulative_total,
            "period_limit": self.policy_state.period_limit,
        }


def actions_from_yield_plan(plan_data: dict) -> list[dict]:
    """Convert yield agent allocation plan JSON to bridge action format.

    The yield agent's `allocate --json` command outputs a plan with allocations.
    This converts that into the action format the bridge expects.

    Args:
        plan_data: JSON output from yield agent's allocate command.

    Returns:
        List of action dicts for execute_yield_actions().
    """
    actions = []
    for alloc in plan_data.get("allocations", []):
        actions.append({
            "action": "deposit",
            "protocol": alloc["protocol"],
            "amount_usd": Decimal(str(alloc["amount_usd"])),
            "reasoning": f"Yield allocation: {alloc['target_pct']:.1%} of capital",
        })
    return actions
