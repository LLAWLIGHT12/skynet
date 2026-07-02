"""Audit agent runner compatibility facade.

Skynet audit stages import :func:`run_agent` from this module. The
implementation lives in :mod:`skynet.audit.agent_runner` and runs a
multi-turn Skynet Tool Agent (read_file / grep / glob / read_node)
via :class:`skynet.llm.client.LLMClient`.
"""

from __future__ import annotations

from skynet.audit.agent_runner import run_agent, run_agent_text
from skynet.audit.types import (
    AgentResult,
    AgentRunError,
    QuotaExhaustedError,
    TransientAgentError,
)

__all__ = [
    "AgentResult",
    "AgentRunError",
    "QuotaExhaustedError",
    "TransientAgentError",
    "run_agent",
    "run_agent_text",
]
