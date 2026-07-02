"""Task 4: Token 预算精细管理测试。"""

from __future__ import annotations

import pytest

from skynet.audit.token_budget import TokenBudget, estimate_tokens


# ── estimate_tokens ─────────────────────────────────────────────

class TestEstimateTokens:
    def test_empty_string(self):
        assert estimate_tokens("") == 0

    def test_short_string(self):
        assert estimate_tokens("hi") >= 1

    def test_longer_string(self):
        assert estimate_tokens("a" * 300) == 100

    def test_zero_for_empty(self):
        assert estimate_tokens("") == 0


# ── TokenBudget.check_task_budget ───────────────────────────────

class TestCheckTaskBudget:
    def test_no_limit(self):
        """max_per_task=0 时不限制。"""
        budget = TokenBudget(max_per_task=0)
        assert budget.check_task_budget(999999) is True

    def test_within_limit(self):
        """单任务未超限 — 通过。"""
        budget = TokenBudget(max_per_task=10000)
        assert budget.check_task_budget(5000) is True

    def test_exceeds_limit(self):
        """单任务超限 — 返回 False + warning。"""
        budget = TokenBudget(max_per_task=1000)
        assert budget.check_task_budget(2000) is False
        assert budget.rejected_count == 1

    def test_exact_limit(self):
        """恰好等于限制 — 通过。"""
        budget = TokenBudget(max_per_task=1000)
        assert budget.check_task_budget(1000) is True

    def test_multiple_rejections(self):
        """多次超限累计计数。"""
        budget = TokenBudget(max_per_task=100)
        budget.check_task_budget(200)
        budget.check_task_budget(300)
        assert budget.rejected_count == 2


# ── TokenBudget.check_global_budget ─────────────────────────────

class TestCheckGlobalBudget:
    def test_no_limit(self):
        """max_total=0 时不限制。"""
        budget = TokenBudget(max_total=0)
        budget.record(999999, 999999)
        assert budget.check_global_budget() is True

    def test_within_budget(self):
        """预算充足。"""
        budget = TokenBudget(max_total=100000)
        budget.record(1000, 500)
        assert budget.check_global_budget() is True

    def test_budget_exhausted(self):
        """预算耗尽。"""
        budget = TokenBudget(max_total=1000)
        budget.record(600, 500)
        assert budget.check_global_budget() is False

    def test_budget_exactly_used(self):
        """恰好用完。"""
        budget = TokenBudget(max_total=1000)
        budget.record(500, 500)
        assert budget.check_global_budget() is False  # >= 即耗尽


# ── TokenBudget.record & properties ─────────────────────────────

class TestRecordAndProperties:
    def test_record_updates_totals(self):
        budget = TokenBudget()
        budget.record(100, 50)
        budget.record(200, 80)
        assert budget.total_input == 300
        assert budget.total_output == 130
        assert budget.total_tokens == 430
        assert budget.task_count == 2

    def test_remaining_with_limit(self):
        budget = TokenBudget(max_total=10000)
        budget.record(1000, 500)
        assert budget.remaining() == 8500

    def test_remaining_no_limit(self):
        budget = TokenBudget(max_total=0)
        assert budget.remaining() == -1

    def test_summary(self):
        budget = TokenBudget(max_per_task=5000, max_total=100000)
        budget.record(1000, 500)
        budget.record(2000, 800)
        s = budget.summary()
        assert s["max_per_task"] == 5000
        assert s["max_total"] == 100000
        assert s["total_input"] == 3000
        assert s["total_output"] == 1300
        assert s["total_tokens"] == 4300
        assert s["task_count"] == 2
        assert s["rejected_count"] == 0
        assert s["remaining"] == 95700


# ── TokenBudget integration ─────────────────────────────────────

class TestBudgetIntegration:
    def test_task_then_global_check(self):
        """先检查单任务预算，再检查全局预算。"""
        budget = TokenBudget(max_per_task=5000, max_total=10000)

        # 任务 1: 通过
        assert budget.check_task_budget(3000) is True
        budget.record(3000, 1000)

        # 任务 2: 单任务通过
        assert budget.check_task_budget(4000) is True
        budget.record(4000, 1500)

        # 任务 3: 单任务超限
        assert budget.check_task_budget(6000) is False

        # 全局: 已用 9500，还有 500
        assert budget.check_global_budget() is True
        budget.record(300, 200)

        # 全局: 已用 10000，耗尽
        assert budget.check_global_budget() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
