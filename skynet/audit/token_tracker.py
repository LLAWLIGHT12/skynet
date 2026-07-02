"""结构化 Token 统计 —— 按阶段 / 按调用细粒度跟踪 token 使用。

- TokenTracker 类记录每次 LLM 调用的 input/output tokens
- 按 stage 分组统计
- 支持生成结构化报告 (dict / JSON)
- 与 TokenBudget 互补：Budget 管控，Tracker 统计
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class LLMCallRecord:
    """单次 LLM 调用的 token 记录。"""
    stage: str
    task_id: str
    input_tokens: int
    output_tokens: int
    model: str = ""
    latency_ms: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "task_id": self.task_id,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "model": self.model,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp,
        }


@dataclass
class StageStats:
    """单个 stage 的汇总统计。"""
    stage: str
    call_count: int = 0
    total_input: int = 0
    total_output: int = 0
    total_latency_ms: int = 0

    @property
    def total_tokens(self) -> int:
        return self.total_input + self.total_output

    @property
    def avg_input_tokens(self) -> float:
        return self.total_input / self.call_count if self.call_count else 0.0

    @property
    def avg_output_tokens(self) -> float:
        return self.total_output / self.call_count if self.call_count else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.call_count if self.call_count else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "call_count": self.call_count,
            "total_input": self.total_input,
            "total_output": self.total_output,
            "total_tokens": self.total_tokens,
            "avg_input_tokens": round(self.avg_input_tokens, 1),
            "avg_output_tokens": round(self.avg_output_tokens, 1),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "total_latency_ms": self.total_latency_ms,
        }


class TokenTracker:
    """结构化 Token 统计跟踪器。

    用法::

        tracker = TokenTracker()

        # 记录一次 LLM 调用
        tracker.record("hunt", "task_001", input_tokens=1500, output_tokens=300)

        # 带 model 和 latency
        tracker.record("validate", "task_002", 2000, 500,
                       model="claude-3.5-sonnet", latency_ms=1200)

        # 查看统计
        stats = tracker.summary()
        print(stats["total_tokens"])
        print(stats["by_stage"]["hunt"]["call_count"])
    """

    def __init__(self) -> None:
        self._records: list[LLMCallRecord] = []
        self._stages: dict[str, StageStats] = {}

    @property
    def records(self) -> list[LLMCallRecord]:
        """所有调用记录（只读）。"""
        return list(self._records)

    @property
    def total_calls(self) -> int:
        return len(self._records)

    def record(
        self,
        stage: str,
        task_id: str,
        input_tokens: int,
        output_tokens: int,
        model: str = "",
        latency_ms: int = 0,
    ) -> LLMCallRecord:
        """记录一次 LLM 调用。

        Parameters
        ----------
        stage : str
            阶段名称（如 "hunt", "validate", "report"）。
        task_id : str
            任务标识。
        input_tokens : int
            输入 token 数。
        output_tokens : int
            输出 token 数。
        model : str
            使用的模型名称（可选）。
        latency_ms : int
            调用延迟（毫秒，可选）。

        Returns
        -------
        LLMCallRecord
            本次记录。
        """
        rec = LLMCallRecord(
            stage=stage,
            task_id=task_id,
            input_tokens=max(0, input_tokens),
            output_tokens=max(0, output_tokens),
            model=model,
            latency_ms=max(0, latency_ms),
        )
        self._records.append(rec)

        # 更新 stage 统计
        if stage not in self._stages:
            self._stages[stage] = StageStats(stage=stage)
        ss = self._stages[stage]
        ss.call_count += 1
        ss.total_input += rec.input_tokens
        ss.total_output += rec.output_tokens
        ss.total_latency_ms += rec.latency_ms

        return rec

    def get_stage_stats(self, stage: str) -> StageStats | None:
        """获取指定 stage 的汇总统计。"""
        return self._stages.get(stage)

    @property
    def stages(self) -> list[str]:
        """已记录的 stage 名称列表。"""
        return list(self._stages.keys())

    @property
    def total_input(self) -> int:
        return sum(r.input_tokens for r in self._records)

    @property
    def total_output(self) -> int:
        return sum(r.output_tokens for r in self._records)

    @property
    def total_tokens(self) -> int:
        return self.total_input + self.total_output

    @property
    def total_latency_ms(self) -> int:
        return sum(r.latency_ms for r in self._records)

    def summary(self) -> dict[str, Any]:
        """生成完整的结构化统计摘要。

        Returns
        -------
        dict
            包含 total、by_stage、by_model 等维度的统计。
        """
        by_stage = {name: ss.to_dict() for name, ss in self._stages.items()}

        # 按 model 聚合
        by_model: dict[str, dict[str, Any]] = {}
        for rec in self._records:
            m = rec.model or "unknown"
            if m not in by_model:
                by_model[m] = {"call_count": 0, "input_tokens": 0, "output_tokens": 0}
            by_model[m]["call_count"] += 1
            by_model[m]["input_tokens"] += rec.input_tokens
            by_model[m]["output_tokens"] += rec.output_tokens
        for m_data in by_model.values():
            m_data["total_tokens"] = m_data["input_tokens"] + m_data["output_tokens"]

        return {
            "total_calls": self.total_calls,
            "total_input": self.total_input,
            "total_output": self.total_output,
            "total_tokens": self.total_tokens,
            "total_latency_ms": self.total_latency_ms,
            "by_stage": by_stage,
            "by_model": by_model,
        }

    def stage_summary(self, stage: str) -> dict[str, Any] | None:
        """获取指定 stage 的详细统计（含该 stage 的所有调用记录）。

        Returns
        -------
        dict or None
        """
        ss = self._stages.get(stage)
        if ss is None:
            return None
        records = [r.to_dict() for r in self._records if r.stage == stage]
        return {
            **ss.to_dict(),
            "records": records,
        }

    def reset(self) -> None:
        """清空所有记录。"""
        self._records.clear()
        self._stages.clear()

    def to_dict(self) -> dict[str, Any]:
        """序列化整个 tracker 状态。"""
        return {
            "summary": self.summary(),
            "records": [r.to_dict() for r in self._records],
        }

    @classmethod
    def from_records(cls, records_data: list[dict[str, Any]]) -> TokenTracker:
        """从序列化数据恢复 tracker。"""
        tracker = cls()
        for rd in records_data:
            tracker.record(
                stage=rd["stage"],
                task_id=rd["task_id"],
                input_tokens=rd["input_tokens"],
                output_tokens=rd["output_tokens"],
                model=rd.get("model", ""),
                latency_ms=rd.get("latency_ms", 0),
            )
        return tracker
