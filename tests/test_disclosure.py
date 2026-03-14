"""Tests for the selective disclosure controller."""
import pytest

from src.models import DisclosureLevel
from src.privacy.disclosure import DisclosureController
from src.zk.commitment import create_delegation, initialize_policy_state
from src.zk.prover import ZKProver


@pytest.fixture
def prover():
    return ZKProver("build")


@pytest.fixture
def config():
    return {
        "disclosure": {
            "auditor": {
                "can_see": ["total_monthly_spend", "proof_of_solvency", "period_count"],
                "cannot_see": ["individual_transactions", "protocol_names", "exact_balances"],
            },
            "public": {
                "can_see": ["proof_of_compliance"],
                "cannot_see": ["everything_else"],
            },
        }
    }


@pytest.fixture
def state():
    priv_key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    delegation = create_delegation(priv_key, 1, 5000)
    return initialize_policy_state(delegation, 10000)


class TestDisclosureController:
    def test_auditor_can_see_total(self, config):
        controller = DisclosureController(None, config)
        assert controller.can_disclose(DisclosureLevel.AUDITOR, "total_monthly_spend")

    def test_auditor_cannot_see_individual_txs(self, config):
        controller = DisclosureController(None, config)
        assert not controller.can_disclose(DisclosureLevel.AUDITOR, "individual_transactions")

    def test_public_can_see_compliance(self, config):
        controller = DisclosureController(None, config)
        assert controller.can_disclose(DisclosureLevel.PUBLIC, "proof_of_compliance")

    def test_public_cannot_see_balances(self, config):
        controller = DisclosureController(None, config)
        assert not controller.can_disclose(DisclosureLevel.PUBLIC, "exact_balances")

    def test_generate_spend_total_proof(self, prover, config, state):
        controller = DisclosureController(prover, config)
        proof = controller.generate_spend_total_proof(state, DisclosureLevel.AUDITOR)
        assert proof is not None
        assert proof.claim == "total_monthly_spend"

    def test_generate_compliance_proof(self, prover, config, state):
        controller = DisclosureController(prover, config)
        proof = controller.generate_compliance_proof(state, DisclosureLevel.PUBLIC)
        assert proof is not None
        assert proof.claim == "proof_of_compliance"

    def test_blocked_disclosure_returns_none(self, prover, config, state):
        controller = DisclosureController(prover, config)
        proof = controller.generate_spend_total_proof(state, DisclosureLevel.PUBLIC)
        assert proof is None  # Public can't see total_monthly_spend

    def test_disclosure_summary(self, prover, config, state):
        controller = DisclosureController(prover, config)
        summary = controller.get_disclosure_summary(state, DisclosureLevel.AUDITOR)
        assert summary["level"] == "auditor"
        assert "total_monthly_spend" in summary["allowed_claims"]
        assert "total_monthly_spend" in summary["proofs"]
