"""Token 预算精细管理 —— 单任务预检 + 全局预算控制。

- TokenBudget 类跟踪和管控 token 使用
- check_task_budget() — 单任务预检
- check_global_budget() — 全局预算检查
- estimate_tokens() — 粗略估算 token 数
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


def estimate_tokens(text: str) -> int:
    """粗略估算 token 数（1 token ≈ 3 字符）。

    比 compression.count_tokens 更轻量，用于预检场景。
    """
    if not text:
        return 0
    return max(1, len(text) // 3)


@dataclass
class TokenBudget:
    """Token 预算管理器。

    Parameters
    ----------
    max_per_task : int
        单任务最大 token 数（prompt tokens）。0 表示不限制。
    max_total : int
        全局 token 预算（input + output 总和）。0 表示不限制。
    """
    max_per_task: int = 0
    max_total: int = 0

    # 运行时统计
    _total_input: int = field(default=0, init=False, repr=False)
    _total_output: int = field(default=0, init=False, repr=False)
    _task_count: int = field(default=0, init=False, repr=False)
    _rejected_count: int = field(default=0, init=False, repr=False)

    @property
    def total_tokens(self) -> int:
        """已使用的总 token 数。"""
        return self._total_input + self._total_output

    @property
    def total_input(self) -> int:
        return self._total_input

    @property
    def total_output(self) -> int:
        return self._total_output

    @property
    def task_count(self) -> int:
        return self._task_count

    @property
    def rejected_count(self) -> int:
        return self._rejected_count

    def check_task_budget(self, prompt_tokens: int) -> bool:
        """单任务 token 预检。

        Parameters
        ----------
        prompt_tokens : int
            预估的 prompt token 数。

        Returns
        -------
        bool
            True = 在预算内，可以执行；False = 超限，应跳过。
        """
        if self.max_per_task <= 0:
            return True
        if prompt_tokens > self.max_per_task:
            self._rejected_count += 1
            log.warning(
                "token_budget: task rejected — %d tokens > max_per_task(%d)",
                prompt_tokens, self.max_per_task,
            )
            return False
        return True

    def check_global_budget(self) -> bool:
        """全局预算检查。

        Returns
        -------
        bool
            True = 预算充足；False = 已耗尽。
        """
        if self.max_total <= 0:
            return True
        if self.total_tokens >= self.max_total:
            log.warning(
                "token_budget: global budget exhausted — %d >= %d",
                self.total_tokens, self.max_total,
            )
            return False
        return True

    def record(self, input_tokens: int, output_tokens: int) -> None:
        """记录一次 LLM 调用的 token 使用。"""
        self._total_input += input_tokens
        self._total_output += output_tokens
        self._task_count += 1

    def remaining(self) -> int:
        """剩余全局预算。max_total=0 时返回 float('inf')。"""
        if self.max_total <= 0:
            return -1  # 无限制
        return max(0, self.max_total - self.total_tokens)

    def summary(self) -> dict[str, Any]:
        """返回预算使用摘要。"""
        return {
            "max_per_task": self.max_per_task,
            "max_total": self.max_total,
            "total_input": self._total_input,
            "total_output": self._total_output,
            "total_tokens": self.total_tokens,
            "task_count": self._task_count,
            "rejected_count": self._rejected_count,
            "remaining": self.remaining(),
        }
