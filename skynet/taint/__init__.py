"""污点流追踪。"""

from skynet.taint.catalog import TaintCatalog
from skynet.taint.models import FlowCandidate, FlowRecord, FlowTraceSummary
from skynet.taint.gap_detector import GraphGapDetector

__all__ = [
    "TaintCatalog",
    "GraphGapDetector",
    "FlowCandidate",
    "FlowRecord",
    "FlowTraceSummary",
]


def __getattr__(name: str):
    if name == "TraceRunner":
        from skynet.taint.runner import TraceRunner
        return TraceRunner
    if name == "FlowVerifier":
        from skynet.taint.verifier import FlowVerifier
        return FlowVerifier
    if name == "AgentFlowResolver":
        from skynet.taint.agent_resolver import AgentFlowResolver
        return AgentFlowResolver
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
