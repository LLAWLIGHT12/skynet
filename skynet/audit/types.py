"""共享类型定义 —— 避免 runner.py 和 agent_runner.py 之间的循环导入。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AgentResult:
    payload: dict
    cost_usd: float | None
    input_tokens: int | None
    output_tokens: int | None
    cache_read_tokens: int | None
    cache_creation_tokens: int | None
    num_turns: int | None
    duration_ms: int | None
    session_id: str | None
    artifact_path: Path
    repair_used: bool
    raw_result_message: dict = field(default_factory=dict)


class AgentRunError(RuntimeError):
    """Schema validation failed after repair attempts."""


class TransientAgentError(RuntimeError):
    """API returned a transient error. The agent call should be retried."""


class QuotaExhaustedError(RuntimeError):
    """Subscription quota exhausted. Don't retry — abort resumable."""
