"""Tests for the private yield bridge."""
import time
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

from src.bridge.private_yield import PrivateYieldExecutor, actions_from_yield_plan
from src.models import ExecutionMode, PolicyState, AgentDelegation


def _make_delegation(**overrides) -> AgentDelegation:
    defaults = {
        "agent_id": 1,
        "spend_limit": 5000,
        "valid_until": int(time.time()) + 86400,
        "nonce": 1,
        "salt": 12345,
        "signature_s": "111",
        "signature_r8x": "222",
        "signature_r8y": "333",
        "owner_pub_ax": "444",
        "owner_pub_ay": "555",
        "policy_commitment": "666",
        "message_hash": "777",
    }
    defaults.update(overrides)
    return AgentDelegation(**defaults)


def _make_state(**overrides) -> PolicyState:
    delegation = overrides.pop("delegation", _make_delegation())
    defaults = {
        "delegation": delegation,
        "period_limit": 10000,
        "cumulative_total": 0,
        "period_start": time.time(),
        "current_commitment": "abc",
        "current_salt": 999,
    }
    defaults.update(overrides)
    return PolicyState(**defaults)


class TestActionsFromYieldPlan:
    def test_converts_allocations(self):
        plan = {
            "allocations": [
                {"protocol": "aave-v3", "amount_usd": 4000, "target_pct": 0.4},
                {"protocol": "morpho-v1", "amount_usd": 4000, "target_pct": 0.4},
            ]
        }
        actions = actions_from_yield_plan(plan)
        assert len(actions) == 2
        assert actions[0]["action"] == "deposit"
        assert actions[0]["protocol"] == "aave-v3"
        assert actions[0]["amount_usd"] == Decimal("4000")

    def test_empty_plan(self):
        actions = actions_from_yield_plan({})
        assert actions == []

    def test_single_allocation(self):
        plan = {
            "allocations": [
                {"protocol": "aave-v3", "amount_usd": 5000, "target_pct": 0.5},
            ]
        }
        actions = actions_from_yield_plan(plan)
        assert len(actions) == 1


class TestPrivateYieldExecutor:
    @pytest.fixture
    def mock_prover(self):
        prover = MagicMock()
        proof = MagicMock()
        proof.proof_type.value = "budget_range"
        proof.public_signals = ["123", "1", "456"]
        proof.verified = True
        proof.proof = {}
        prover.generate_proof.return_value = proof
        prover.verify_proof.return_value = True
        prover.export_calldata.return_value = '["0x1","0x2"]'
        return prover

    @pytest.fixture
    def mock_policy_mgr(self, mock_prover):
        mgr = MagicMock()
        proof = MagicMock()
        proof.proof_type.value = "authorization"
        proof.public_signals = ["1", "666"]
        proof.verified = True
        proof.proof = {}

        mgr.full_compliance_check.return_value = {
            "compliant": True,
            "auth": {"authorized": True, "proof": proof},
            "budget": {"within_budget": True, "proof": proof},
            "cumulative": {"within_limit": True, "proof": proof, "new_salt": 999},
        }
        return mgr

    def test_execute_deposit_with_zk(self, mock_prover, mock_policy_mgr):
        state = _make_state()
        bridge = PrivateYieldExecutor(mock_prover, mock_policy_mgr, state)

        actions = [{"action": "deposit", "protocol": "aave-v3", "amount_usd": Decimal("2000")}]
        results = bridge.execute_yield_actions(actions)

        assert len(results) == 1
        assert results[0]["status"] == "SIMULATED"
        assert results[0]["zk_compliant"] is True
        assert results[0]["amount_usdc"] == 2000

    def test_rejected_action(self, mock_prover):
        mgr = MagicMock()
        mgr.full_compliance_check.return_value = {
            "compliant": False,
            "reason": "Budget exceeded",
        }
        state = _make_state()
        bridge = PrivateYieldExecutor(mock_prover, mgr, state)

        actions = [{"action": "deposit", "protocol": "aave-v3", "amount_usd": Decimal("9999")}]
        results = bridge.execute_yield_actions(actions)

        assert len(results) == 1
        assert results[0]["status"] == "REJECTED"
        assert results[0]["zk_compliant"] is False

    def test_withdraw_bypasses_zk(self, mock_prover, mock_policy_mgr):
        state = _make_state()
        bridge = PrivateYieldExecutor(mock_prover, mock_policy_mgr, state)

        actions = [{"action": "withdraw", "protocol": "aave-v3", "amount_usd": Decimal("1000")}]
        results = bridge.execute_yield_actions(actions)

        assert len(results) == 1
        assert results[0]["zk_compliant"] is True
        assert "bypass" in results[0]["reason"].lower()
        # ZK compliance check should NOT be called for withdrawals
        mock_policy_mgr.full_compliance_check.assert_not_called()

    def test_zero_amount_skipped(self, mock_prover, mock_policy_mgr):
        state = _make_state()
        bridge = PrivateYieldExecutor(mock_prover, mock_policy_mgr, state)

        actions = [{"action": "deposit", "protocol": "aave-v3", "amount_usd": Decimal("0")}]
        results = bridge.execute_yield_actions(actions)

        assert results[0]["status"] == "SKIPPED"

    def test_multiple_actions(self, mock_prover, mock_policy_mgr):
        state = _make_state()
        bridge = PrivateYieldExecutor(mock_prover, mock_policy_mgr, state)

        actions = [
            {"action": "deposit", "protocol": "aave-v3", "amount_usd": Decimal("2000")},
            {"action": "deposit", "protocol": "morpho-v1", "amount_usd": Decimal("2000")},
        ]
        results = bridge.execute_yield_actions(actions)

        assert len(results) == 2
        assert all(r["status"] == "SIMULATED" for r in results)

    def test_summary(self, mock_prover, mock_policy_mgr):
        state = _make_state()
        bridge = PrivateYieldExecutor(mock_prover, mock_policy_mgr, state)

        actions = [
            {"action": "deposit", "protocol": "aave-v3", "amount_usd": Decimal("2000")},
            {"action": "deposit", "protocol": "morpho-v1", "amount_usd": Decimal("3000")},
        ]
        bridge.execute_yield_actions(actions)
        summary = bridge.get_summary()

        assert summary["total_actions"] == 2
        assert summary["executed"] == 2
        assert summary["rejected"] == 0
        assert summary["total_usd"] == 5000.0

    def test_dry_run_mode(self, mock_prover, mock_policy_mgr):
        state = _make_state()
        bridge = PrivateYieldExecutor(mock_prover, mock_policy_mgr, state, ExecutionMode.DRY_RUN)

        actions = [{"action": "deposit", "protocol": "aave-v3", "amount_usd": Decimal("2000")}]
        results = bridge.execute_yield_actions(actions)

        assert results[0]["status"] == "DRY_RUN"
