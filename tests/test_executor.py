"""Tests for the private executor."""
import pytest

from src.models import ExecutionMode
from src.privacy.executor import PrivateExecutor
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


class TestPrivateExecutor:
    def test_paper_execution_succeeds(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        executor = PrivateExecutor(prover, mgr, ExecutionMode.PAPER)

        result = executor.execute_private_action("deposit", 2000, "aave-v3", state)
        assert result["status"] == "SIMULATED"
        assert result["compliance"]["compliant"]
        assert result["updated_state"]["cumulative_total"] == 2000

    def test_over_budget_rejected(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        executor = PrivateExecutor(prover, mgr, ExecutionMode.PAPER)

        result = executor.execute_private_action("deposit", 6000, "aave-v3", state)
        assert result["status"] == "REJECTED"
        assert not result["compliance"]["compliant"]

    def test_dry_run_mode(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        executor = PrivateExecutor(prover, mgr, ExecutionMode.DRY_RUN)

        result = executor.execute_private_action("deposit", 1000, "morpho", state)
        assert result["status"] == "DRY_RUN"
        assert result["compliance"]["compliant"]

    def test_execution_log_tracks_actions(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        executor = PrivateExecutor(prover, mgr, ExecutionMode.PAPER)

        executor.execute_private_action("deposit", 1000, "aave-v3", state)
        executor.execute_private_action("deposit", 2000, "morpho", state)

        log = executor.get_execution_log()
        assert len(log) == 2
        assert log[0]["amount"] == 1000
        assert log[1]["amount"] == 2000

    def test_proofs_included_in_result(self, prover, config, state):
        mgr = PolicyManager(prover, config)
        executor = PrivateExecutor(prover, mgr, ExecutionMode.PAPER)

        result = executor.execute_private_action("deposit", 1000, "aave-v3", state)
        proofs = result["proofs"]
        assert proofs["authorization"] is not None
        assert proofs["budget_range"] is not None
        assert proofs["cumulative_spend"] is not None
