"""Tests for the structured execution logger."""

import json
import os
import tempfile

import pytest

from src.execution_logger import ExecutionLogger, _safe_serialize


@pytest.fixture
def tmp_log(tmp_path):
    """Return path to a temporary log file."""
    return str(tmp_path / "agent_log.json")


@pytest.fixture
def logger(tmp_log):
    """Return a fresh ExecutionLogger."""
    return ExecutionLogger(log_path=tmp_log)


class TestCycleLifecycle:
    def test_begin_and_end_cycle(self, logger, tmp_log):
        logger.begin_cycle(1, "paper")
        logger.end_cycle({"proofs_generated": 3, "proofs_verified": 3, "actions_executed": 1})

        data = json.loads(open(tmp_log).read())
        assert len(data) == 1
        assert data[0]["cycle_id"] == 1
        assert data[0]["mode"] == "paper"
        assert data[0]["final_output"]["proofs_generated"] == 3
        assert data[0]["final_output"]["actions_executed"] == 1
        assert data[0]["duration_sec"] >= 0

    def test_end_cycle_without_begin_is_noop(self, logger, tmp_log):
        logger.end_cycle({"proofs_generated": 0})
        assert not os.path.exists(tmp_log)

    def test_multiple_cycles(self, logger, tmp_log):
        for i in range(3):
            logger.begin_cycle(i)
            logger.end_cycle({"proofs_generated": i})

        data = json.loads(open(tmp_log).read())
        assert len(data) == 3
        assert [c["cycle_id"] for c in data] == [0, 1, 2]


class TestStepLogging:
    def test_log_step(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_step("generate_auth_proof", "ok", "delegation verified")
        logger.log_step("verify_budget", "ok")
        logger.end_cycle({"proofs_generated": 2})

        data = json.loads(open(tmp_log).read())
        steps = data[0]["steps"]
        assert len(steps) == 2
        assert steps[0]["step"] == "generate_auth_proof"
        assert steps[0]["detail"] == "delegation verified"
        assert steps[1]["step"] == "verify_budget"

    def test_step_detail_truncated(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_step("big_step", "ok", "x" * 1000)
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        assert len(data[0]["steps"][0]["detail"]) == 500


class TestToolCallLogging:
    def test_log_tool_call(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_tool_call("snarkjs", "generate_proof", "success", "auth proof")
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        tc = data[0]["tool_calls"]
        assert len(tc) == 1
        assert tc[0]["tool"] == "snarkjs"
        assert tc[0]["action"] == "generate_proof"

    def test_tool_call_with_tokens(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_tool_call("snarkjs", "prove", tokens=100)
        logger.log_tool_call("snarkjs", "verify", tokens=50)
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        assert data[0]["compute_budget"]["cycle_tokens"] == 150
        assert data[0]["compute_budget"]["cycle_api_calls"] == 2

    def test_tool_call_retry_flag(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_tool_call("snarkjs", "prove", "fail", retry=True)
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        assert data[0]["tool_calls"][0]["retry"] is True


class TestDecisionLogging:
    def test_log_decision(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_decision("compliance_check", "approved", "all 3 proofs verified")
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        d = data[0]["decisions"][0]
        assert d["type"] == "compliance_check"
        assert d["outcome"] == "approved"
        assert d["reasoning"] == "all 3 proofs verified"

    def test_log_decision_with_data(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_decision("budget_check", "pass", data={"amount": 2000, "limit": 5000})
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        assert data[0]["decisions"][0]["data"]["amount"] == 2000

    def test_decision_without_cycle_is_noop(self, logger):
        logger.log_decision("test", "ok")  # Should not raise


class TestProofLogging:
    def test_log_proof(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_proof("authorization", True, ["123", "456"], "agent 1 authorized")
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        p = data[0]["proof_results"][0]
        assert p["proof_type"] == "authorization"
        assert p["verified"] is True
        assert p["public_signals_count"] == 2
        assert p["detail"] == "agent 1 authorized"

    def test_log_proof_failed(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_proof("budget_range", False)
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        assert data[0]["proof_results"][0]["verified"] is False

    def test_proof_without_cycle_is_noop(self, logger):
        logger.log_proof("test", True)  # Should not raise


class TestExecutionLogging:
    def test_log_execution(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_execution("aave-v3", "deposit", 2000.0, "SIMULATED", "0xabc123")
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        e = data[0]["executions"][0]
        assert e["protocol"] == "aave-v3"
        assert e["action"] == "deposit"
        assert e["amount_usd"] == 2000.0
        assert e["status"] == "SIMULATED"
        assert e["tx_hash"] == "0xabc123"

    def test_execution_without_tx_hash(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_execution("morpho", "deposit", 1000.0, "REJECTED")
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        assert "tx_hash" not in data[0]["executions"][0]

    def test_execution_without_cycle_is_noop(self, logger):
        logger.log_execution("aave", "deposit", 100, "ok")  # Should not raise


class TestFailureLogging:
    def test_log_failure(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_failure("snarkjs", "witness generation failed", recoverable=True)
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        f = data[0]["failures"][0]
        assert f["component"] == "snarkjs"
        assert f["recoverable"] is True

    def test_failure_error_truncated(self, logger, tmp_log):
        logger.begin_cycle(1)
        logger.log_failure("prover", "x" * 1000)
        logger.end_cycle({})

        data = json.loads(open(tmp_log).read())
        assert len(data[0]["failures"][0]["error"]) == 300


class TestBoundedStorage:
    def test_max_cycles_enforced(self, tmp_log):
        lg = ExecutionLogger(log_path=tmp_log)
        lg.MAX_CYCLES = 5
        for i in range(10):
            lg.begin_cycle(i)
            lg.end_cycle({})

        data = json.loads(open(tmp_log).read())
        assert len(data) == 5
        assert data[0]["cycle_id"] == 5  # Oldest kept


class TestCorruptFileRecovery:
    def test_recovers_from_corrupt_json(self, tmp_log):
        with open(tmp_log, "w") as f:
            f.write("{corrupt json!!!")

        lg = ExecutionLogger(log_path=tmp_log)
        lg.begin_cycle(1)
        lg.end_cycle({"proofs_generated": 1})

        data = json.loads(open(tmp_log).read())
        assert len(data) == 1
        assert data[0]["cycle_id"] == 1


class TestStats:
    def test_get_stats_empty(self, logger):
        stats = logger.get_stats()
        assert stats["total_cycles"] == 0

    def test_get_stats(self, logger):
        logger.begin_cycle(1)
        logger.log_tool_call("snarkjs", "prove")
        logger.log_failure("chain", "timeout")
        logger.end_cycle({"proofs_generated": 3, "proofs_verified": 3, "actions_executed": 1, "actions_rejected": 0})

        logger.begin_cycle(2)
        logger.end_cycle({"proofs_generated": 3, "proofs_verified": 2, "actions_executed": 0, "actions_rejected": 1})

        stats = logger.get_stats()
        assert stats["total_cycles"] == 2
        assert stats["total_proofs"] == 6
        assert stats["total_verified"] == 5
        assert stats["total_executed"] == 1
        assert stats["total_rejected"] == 1
        assert stats["total_failures"] == 1
        assert stats["total_tool_calls"] == 1
        assert stats["verification_rate"] == round(5 / 6, 4)


class TestGetRecentCycles:
    def test_returns_last_n(self, logger):
        for i in range(5):
            logger.begin_cycle(i)
            logger.end_cycle({})

        recent = logger.get_recent_cycles(3)
        assert len(recent) == 3
        assert recent[0]["cycle_id"] == 2

    def test_returns_empty_when_no_file(self, tmp_path):
        lg = ExecutionLogger(log_path=str(tmp_path / "nonexistent.json"))
        assert lg.get_recent_cycles() == []


class TestSafeSerialize:
    def test_truncates_long_strings(self):
        result = _safe_serialize({"key": "x" * 500})
        assert len(result["key"]) == 303  # 300 + "..."

    def test_caps_lists(self):
        result = _safe_serialize({"items": list(range(50))})
        assert len(result["items"]) == 20

    def test_nested_dicts(self):
        result = _safe_serialize({"outer": {"inner": "val"}})
        assert result["outer"]["inner"] == "val"

    def test_non_json_types_stringified(self):
        result = _safe_serialize({"obj": object()})
        assert isinstance(result["obj"], str)

    def test_preserves_primitives(self):
        result = _safe_serialize({"a": 1, "b": 2.5, "c": True, "d": None})
        assert result == {"a": 1, "b": 2.5, "c": True, "d": None}
