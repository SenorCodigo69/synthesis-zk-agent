"""Tests for the policy manager."""
import pytest

from src.models import ProofType
from src.privacy.policy import PolicyManager
from src.zk.commitment import create_delegation, initialize_policy_state
from src.zk.prover import ZKProver


@pytest.fixture
def prover():
    return ZKProver("build")


@pytest.fixture
def config():
    return {
        "spending_policy": {
            "max_single_spend": 5000,
            "period_limit": 10000,
            "period_seconds": 86400,
        }
    }


@pytest.fixture
def state():
    priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    delegation = create_delegation(priv_key, 1, 5000)
    return initialize_policy_state(delegation, 10000)


class TestPolicyManager:
    def test_check_authorization(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        result = mgr.check_authorization(state)
        assert result["authorized"]
        assert result["proof"]

    def test_check_budget_within_limit(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        result = mgr.check_budget(2000, state)
        assert result["within_budget"]
        assert result["proof"]

    def test_check_budget_exceeds_single_max(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        result = mgr.check_budget(6000, state)
        assert not result["within_budget"]
        assert "exceeds" in result["reason"]

    def test_full_compliance_check(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        result = mgr.full_compliance_check(2000, state)
        assert result["compliant"]
        assert "auth" in result
        assert "budget" in result
        assert "cumulative" in result
