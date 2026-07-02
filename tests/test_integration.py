"""端到端集成测试 — 验证 audit 辅助模块与 orchestrator 的集成。

所有测试使用 mock 替代真实 LLM 调用和数据库操作。
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from skynet.audit.token_tracker import TokenTracker
from skynet.audit.token_budget import TokenBudget
from skynet.audit.location_resolver import resolve_finding_location
from skynet.audit.compression import (
    compress_messages,
    should_compress,
    count_tokens,
)
from skynet.audit.preview import preview_analysis, preview_audit


# ── TokenTracker 集成 ───────────────────────────────────────────

class TestTokenTrackerIntegration:
    def test_tracker_records_across_stages(self):
        """模拟多阶段 token 跟踪。"""
        tracker = TokenTracker()

        # 模拟各阶段
        tracker.record("recon", "task_001", 500, 200, model="claude-3", latency_ms=1000)
        tracker.record("hunt", "task_002", 1500, 800, model="claude-3", latency_ms=3000)
        tracker.record("hunt", "task_003", 1200, 600, model="claude-3", latency_ms=2500)
        tracker.record("validate", "task_004", 800, 300, model="claude-3", latency_ms=1500)
        tracker.record("global_filter", "_global", 2000, 500, model="claude-3", latency_ms=2000)

        summary = tracker.summary()
        assert summary["total_calls"] == 5
        assert summary["total_input"] == 6000
        assert summary["total_output"] == 2400
        assert set(summary["by_stage"].keys()) == {"recon", "hunt", "validate", "global_filter"}
        assert summary["by_stage"]["hunt"]["call_count"] == 2

    def test_tracker_serialization_roundtrip(self):
        """验证 tracker 可以序列化和恢复。"""
        tracker = TokenTracker()
        tracker.record("hunt", "t1", 100, 50, model="claude-3")
        tracker.record("validate", "t2", 200, 80, model="gpt-4")

        data = tracker.to_dict()
        restored = TokenTracker.from_records(data["records"])

        assert restored.total_calls == tracker.total_calls
        assert restored.total_tokens == tracker.total_tokens
        assert set(restored.stages) == set(tracker.stages)


# ── TokenBudget 集成 ───────────────────────────────────────────

class TestTokenBudgetIntegration:
    def test_budget_tracks_usage(self):
        """验证预算跟踪与实际使用。"""
        budget = TokenBudget(max_per_task=5000, max_total=50000)

        # 模拟多任务
        assert budget.check_task_budget(3000) is True
        budget.record(3000, 1000)

        assert budget.check_task_budget(4000) is True
        budget.record(4000, 1500)

        # 单任务超限
        assert budget.check_task_budget(6000) is False
        assert budget.rejected_count == 1

        # 全局检查
        assert budget.check_global_budget() is True
        assert budget.total_tokens == 9500

    def test_budget_exhaustion(self):
        """验证预算耗尽检测。"""
        budget = TokenBudget(max_total=1000)
        budget.record(600, 500)  # 1100 > 1000
        assert budget.check_global_budget() is False

    def test_budget_summary(self):
        """验证预算摘要格式。"""
        budget = TokenBudget(max_per_task=1000, max_total=10000)
        budget.record(500, 200)
        budget.record(300, 100)

        summary = budget.summary()
        assert summary["max_per_task"] == 1000
        assert summary["max_total"] == 10000
        assert summary["total_tokens"] == 1100
        assert summary["task_count"] == 2
        assert summary["remaining"] == 8900


# ── LocationResolver 集成 ──────────────────────────────────────

class TestLocationResolverIntegration:
    def test_resolve_with_valid_evidence(self, tmp_path):
        """验证行号解析器可以修正 finding 位置。"""
        # 创建测试文件
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "def foo():\n"
            "    x = 1\n"
            "    vulnerable_call(x)\n"
            "    return x\n"
        )

        finding = {
            "finding_id": "test_001",
            "file": "test.py",
            "line_start": 1,  # 错误位置
            "line_end": 1,
            "evidence": "vulnerable_call(x)",
        }

        start, end, was_resolved = resolve_finding_location(finding, str(tmp_path))
        assert was_resolved is True
        assert start == 3  # 正确位置
        assert end == 3


# ── Compression 集成 ──────────────────────────────────────────

class TestCompressionIntegration:
    def test_should_compress_logic(self):
        """验证压缩触发逻辑。"""
        # 低于阈值不压缩
        assert should_compress([{"role": "user", "content": "short"}], 1000) == "none"

        # 超过软阈值触发异步压缩
        long_content = "x" * 2000
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": long_content},
            {"role": "assistant", "content": "response"},
        ]
        result = should_compress(messages, 1000)
        assert result in ("async", "sync")

    def test_count_tokens_fallback(self):
        """验证 token 估算 fallback。"""
        text = "hello world"
        tokens = count_tokens(text)
        assert tokens > 0
        # fallback: len(text) // 3
        assert tokens == max(1, len(text) // 3)


# ── Preview 集成 ──────────────────────────────────────────────

class TestPreviewIntegration:
    def test_preview_analysis_on_real_structure(self, tmp_path):
        """验证 preview_analysis 可以扫描真实目录结构。"""
        # 创建模拟仓库
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('hello')")
        (tmp_path / "src" / "utils.py").write_text("def helper(): pass")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_main.py").write_text("def test(): pass")

        result = preview_analysis(tmp_path)
        assert result.total_files >= 2  # 至少 main.py 和 utils.py
        assert result.total_estimated_tokens > 0
        assert len(result.items) >= 2

    def test_preview_audit_returns_estimate(self, tmp_path):
        """验证 preview_audit 返回任务估算。"""
        (tmp_path / "app.py").write_text("def main(): pass")
        result = preview_audit(tmp_path)
        # preview_audit 返回 dict，包含 attack_classes 和 estimated_hunt_tasks
        assert isinstance(result, dict)
        assert "attack_classes" in result
        assert "estimated_hunt_tasks" in result
        assert result["estimated_hunt_tasks"] >= 1


# ── Orchestrator 集成 ─────────────────────────────────────────

class TestOrchestratorIntegration:
    def test_orchestrator_accepts_new_params(self):
        """验证 orchestrator 接受新参数。"""
        from skynet.audit.orchestrator import run_pipeline
        import inspect

        sig = inspect.signature(run_pipeline)
        params = sig.parameters

        assert "token_tracker" in params
        assert "token_budget" in params
        assert "enable_global_filter" in params
        assert "enable_location_resolver" in params

    def test_orchestrator_default_values(self):
        """验证新参数有合理默认值。"""
        from skynet.audit.orchestrator import run_pipeline
        import inspect

        sig = inspect.signature(run_pipeline)
        params = sig.parameters

        assert params["token_tracker"].default is None
        assert params["token_budget"].default is None
        assert params["enable_global_filter"].default is False
        assert params["enable_location_resolver"].default is True

    def test_helper_functions_exist(self):
        """验证辅助函数已定义。"""
        from skynet.audit.orchestrator import (
            _apply_location_resolver,
            _run_global_filter_with_tracking,
        )
        assert callable(_apply_location_resolver)
        assert callable(_run_global_filter_with_tracking)


# ── StateDB 扩展 ──────────────────────────────────────────────

class TestStateDBExtension:
    def test_update_finding_location_method_exists(self):
        """验证 StateDB 有 update_finding_location 方法。"""
        from skynet.audit.state import StateDB
        assert hasattr(StateDB, "update_finding_location")

    def test_update_finding_location_signature(self):
        """验证方法签名正确。"""
        from skynet.audit.state import StateDB
        import inspect

        sig = inspect.signature(StateDB.update_finding_location)
        params = list(sig.parameters.keys())
        assert "self" in params
        assert "finding_id" in params
        assert "line_start" in params
        assert "line_end" in params


# ── Stages 导出 ───────────────────────────────────────────────

class TestStagesExport:
    def test_global_filter_exported(self):
        """验证 global_filter 已导出到 stages 模块。"""
        from skynet.audit import stages
        assert hasattr(stages, "run_global_filter")
        assert "run_global_filter" in stages.__all__


# ── 端到端流程模拟 ────────────────────────────────────────────

class TestEndToEndFlow:
    def test_full_pipeline_flow_with_mocks(self, tmp_path):
        """模拟完整 pipeline 流程（mock LLM 调用）。"""
        from skynet.audit.orchestrator import (
            _apply_location_resolver,
            _run_global_filter_with_tracking,
        )

        # 创建 mock context 和 db
        ctx = MagicMock()
        ctx.run_id = "test_run"
        ctx.repo_path = tmp_path

        db = MagicMock()
        db.get_findings.return_value = []

        tracker = TokenTracker()
        budget = TokenBudget(max_total=100000)

        # 测试 location resolver 集成
        result = _apply_location_resolver(ctx, db, tracker)
        assert result == 0  # 无 findings

        # 测试 global filter 集成
        import asyncio
        result = asyncio.run(
            _run_global_filter_with_tracking(ctx, db, tracker, budget)
        )
        assert result == 0  # 无 findings

    def test_tracker_and_budget_work_together(self):
        """验证 tracker 和 budget 协同工作。"""
        tracker = TokenTracker()
        budget = TokenBudget(max_per_task=5000, max_total=20000)

        # 模拟多阶段调用
        stages_data = [
            ("recon", 500, 200),
            ("hunt", 3000, 1500),
            ("validate", 2000, 800),
            ("global_filter", 1000, 300),
        ]

        for stage, input_t, output_t in stages_data:
            # 预算检查
            assert budget.check_task_budget(input_t) is True
            assert budget.check_global_budget() is True

            # 记录
            tracker.record(stage, f"task_{stage}", input_t, output_t)
            budget.record(input_t, output_t)

        # 验证统计
        assert tracker.total_tokens == 9300
        assert budget.total_tokens == 9300
        assert budget.remaining() == 10700

        summary = tracker.summary()
        assert len(summary["by_stage"]) == 4
