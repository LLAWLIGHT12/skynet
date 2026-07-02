"""Tests for skynet.audit.token_tracker — 结构化 Token 统计。"""

import pytest
from skynet.audit.token_tracker import (
    LLMCallRecord,
    StageStats,
    TokenTracker,
)


# ── LLMCallRecord ──────────────────────────────────────────────

class TestLLMCallRecord:
    def test_total_tokens(self):
        rec = LLMCallRecord(stage="hunt", task_id="t1", input_tokens=100, output_tokens=50)
        assert rec.total_tokens == 150

    def test_to_dict(self):
        rec = LLMCallRecord(
            stage="validate", task_id="t2",
            input_tokens=200, output_tokens=80,
            model="claude-3", latency_ms=500,
        )
        d = rec.to_dict()
        assert d["stage"] == "validate"
        assert d["task_id"] == "t2"
        assert d["total_tokens"] == 280
        assert d["model"] == "claude-3"
        assert d["latency_ms"] == 500
        assert "timestamp" in d

    def test_defaults(self):
        rec = LLMCallRecord(stage="x", task_id="y", input_tokens=10, output_tokens=5)
        assert rec.model == ""
        assert rec.latency_ms == 0


# ── StageStats ─────────────────────────────────────────────────

class TestStageStats:
    def test_averages(self):
        ss = StageStats(stage="hunt", call_count=3, total_input=300, total_output=150, total_latency_ms=900)
        assert ss.total_tokens == 450
        assert ss.avg_input_tokens == 100.0
        assert ss.avg_output_tokens == 50.0
        assert ss.avg_latency_ms == 300.0

    def test_zero_calls(self):
        ss = StageStats(stage="empty")
        assert ss.avg_input_tokens == 0.0
        assert ss.avg_output_tokens == 0.0
        assert ss.avg_latency_ms == 0.0

    def test_to_dict(self):
        ss = StageStats(stage="report", call_count=1, total_input=500, total_output=200, total_latency_ms=100)
        d = ss.to_dict()
        assert d["stage"] == "report"
        assert d["call_count"] == 1
        assert d["total_tokens"] == 700
        assert d["avg_input_tokens"] == 500.0


# ── TokenTracker ───────────────────────────────────────────────

class TestTokenTracker:
    def test_empty_tracker(self):
        t = TokenTracker()
        assert t.total_calls == 0
        assert t.total_tokens == 0
        assert t.total_input == 0
        assert t.total_output == 0
        assert t.total_latency_ms == 0
        assert t.stages == []

    def test_single_record(self):
        t = TokenTracker()
        rec = t.record("hunt", "t1", 100, 50)
        assert isinstance(rec, LLMCallRecord)
        assert t.total_calls == 1
        assert t.total_input == 100
        assert t.total_output == 50
        assert t.total_tokens == 150

    def test_multiple_stages(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50)
        t.record("hunt", "t2", 200, 80)
        t.record("validate", "t3", 150, 60)

        assert t.total_calls == 3
        assert t.total_input == 450
        assert t.total_output == 190
        assert set(t.stages) == {"hunt", "validate"}

    def test_stage_stats(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50, latency_ms=100)
        t.record("hunt", "t2", 200, 80, latency_ms=200)

        ss = t.get_stage_stats("hunt")
        assert ss is not None
        assert ss.call_count == 2
        assert ss.total_input == 300
        assert ss.total_output == 130
        assert ss.total_latency_ms == 300

    def test_get_stage_stats_missing(self):
        t = TokenTracker()
        assert t.get_stage_stats("nonexistent") is None

    def test_negative_tokens_clamped(self):
        t = TokenTracker()
        t.record("hunt", "t1", -10, -5)
        assert t.total_input == 0
        assert t.total_output == 0

    def test_model_tracking(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50, model="claude-3")
        t.record("hunt", "t2", 200, 80, model="gpt-4")
        t.record("validate", "t3", 150, 60, model="claude-3")

        summary = t.summary()
        assert "claude-3" in summary["by_model"]
        assert "gpt-4" in summary["by_model"]
        assert summary["by_model"]["claude-3"]["call_count"] == 2
        assert summary["by_model"]["gpt-4"]["call_count"] == 1

    def test_unknown_model(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50)  # no model specified
        summary = t.summary()
        assert "unknown" in summary["by_model"]

    def test_summary_structure(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50, model="claude-3", latency_ms=100)
        t.record("validate", "t2", 200, 80, model="claude-3", latency_ms=200)

        s = t.summary()
        assert s["total_calls"] == 2
        assert s["total_input"] == 300
        assert s["total_output"] == 130
        assert s["total_tokens"] == 430
        assert s["total_latency_ms"] == 300
        assert "hunt" in s["by_stage"]
        assert "validate" in s["by_stage"]

    def test_stage_summary(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50, model="claude-3")
        t.record("hunt", "t2", 200, 80, model="gpt-4")
        t.record("validate", "t3", 150, 60)

        hs = t.stage_summary("hunt")
        assert hs is not None
        assert hs["call_count"] == 2
        assert len(hs["records"]) == 2
        assert hs["records"][0]["task_id"] == "t1"

    def test_stage_summary_missing(self):
        t = TokenTracker()
        assert t.stage_summary("nonexistent") is None

    def test_reset(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50)
        t.record("validate", "t2", 200, 80)
        assert t.total_calls == 2

        t.reset()
        assert t.total_calls == 0
        assert t.total_tokens == 0
        assert t.stages == []
        assert t.records == []

    def test_records_property_is_copy(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50)
        recs = t.records
        recs.clear()  # 修改副本不应影响 tracker
        assert t.total_calls == 1

    def test_to_dict(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50, model="claude-3", latency_ms=100)
        d = t.to_dict()
        assert "summary" in d
        assert "records" in d
        assert len(d["records"]) == 1
        assert d["records"][0]["stage"] == "hunt"

    def test_from_records(self):
        data = [
            {"stage": "hunt", "task_id": "t1", "input_tokens": 100, "output_tokens": 50, "model": "claude-3", "latency_ms": 100},
            {"stage": "validate", "task_id": "t2", "input_tokens": 200, "output_tokens": 80},
        ]
        t = TokenTracker.from_records(data)
        assert t.total_calls == 2
        assert t.total_input == 300
        assert t.get_stage_stats("hunt").call_count == 1

    def test_roundtrip_serialization(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50, model="claude-3", latency_ms=100)
        t.record("report", "t2", 500, 300, model="gpt-4", latency_ms=500)

        d = t.to_dict()
        t2 = TokenTracker.from_records(d["records"])
        assert t2.total_calls == t.total_calls
        assert t2.total_tokens == t.total_tokens
        assert t2.stages == t.stages

    def test_latency_tracking(self):
        t = TokenTracker()
        t.record("hunt", "t1", 100, 50, latency_ms=1000)
        t.record("hunt", "t2", 200, 80, latency_ms=2000)
        assert t.total_latency_ms == 3000

        ss = t.get_stage_stats("hunt")
        assert ss.avg_latency_ms == 1500.0
