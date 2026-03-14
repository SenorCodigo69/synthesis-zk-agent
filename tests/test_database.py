"""Tests for SQLite database."""
import os
import tempfile

import pytest

from src.database import Database


@pytest.fixture
def db():
    tmpfile = tempfile.mktemp(suffix=".db")
    database = Database(tmpfile)
    yield database
    database.close()
    os.unlink(tmpfile)


class TestDatabase:
    def test_save_and_get_spend(self, db):
        db.save_spend({
            "amount": 1000,
            "protocol": "aave-v3",
            "tx_hash": "0x123",
            "proof_hash": "abc123",
            "commitment": "comm123",
            "cumulative_total": 1000,
        })
        total = db.get_spend_total()
        assert total == 1000

    def test_multiple_spends(self, db):
        for i in range(3):
            db.save_spend({
                "amount": 1000,
                "proof_hash": f"ph{i}",
                "commitment": f"c{i}",
                "cumulative_total": (i + 1) * 1000,
            })
        assert db.get_spend_total() == 3000

    def test_spend_history(self, db):
        db.save_spend({
            "amount": 500,
            "protocol": "morpho",
            "proof_hash": "ph1",
            "commitment": "c1",
            "cumulative_total": 500,
        })
        history = db.get_spend_history()
        assert len(history) == 1
        assert history[0]["amount"] == 500
        assert history[0]["protocol"] == "morpho"

    def test_save_delegation(self, db):
        row_id = db.save_delegation({
            "agent_id": 1,
            "spend_limit": 5000,
            "valid_until": 9999999999,
            "nonce": 42,
            "salt": 99,
            "policy_commitment": "pc123",
            "owner_pub_ax": "ax123",
            "owner_pub_ay": "ay123",
        })
        assert row_id > 0

    def test_save_proof(self, db):
        row_id = db.save_proof("budget_range", ["signal1", "signal2"], {"pi_a": []}, True)
        assert row_id > 0
        counts = db.get_proof_count()
        assert counts["budget_range"] == 1

    def test_disclosure_log(self, db):
        row_id = db.log_disclosure("auditor", "total_monthly_spend")
        assert row_id > 0
