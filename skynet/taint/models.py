"""污点分析数据模型。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class TaintHit:
    """节点上的 source/sink/sanitizer 标注。"""

    role: str  # source | sink | sanitizer
    rule_id: str
    description: str
    tags: list[str] = field(default_factory=list)
    depth: str = ""  # sanitizer only: strong | medium | shallow


@dataclass
class NodeAnnotation:
    qualified_name: str
    node_id: int
    hits: list[TaintHit] = field(default_factory=list)

    @property
    def is_source(self) -> bool:
        return any(h.role == "source" for h in self.hits)

    @property
    def is_sink(self) -> bool:
        return any(h.role == "sink" for h in self.hits)

    @property
    def sink_types(self) -> list[str]:
        return [h.rule_id for h in self.hits if h.role == "sink"]


@dataclass
class FlowCandidate:
    """图上枚举的 source→sink 候选路径。"""

    source_qn: str
    sink_qn: str
    path_qns: list[str]
    sink_type: str
    hop_count: int
    communities: list[int] = field(default_factory=list)
    criticality: float = 0.0
    gap_score: int = 0
    gap_reasons: list[str] = field(default_factory=list)
    needs_agent: bool = False
    sink_had_no_path: bool = False

    @property
    def flow_id(self) -> str:
        raw = "|".join(self.path_qns)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "source_qn": self.source_qn,
            "sink_qn": self.sink_qn,
            "path_qns": self.path_qns,
            "sink_type": self.sink_type,
            "hop_count": self.hop_count,
            "communities": self.communities,
            "criticality": self.criticality,
            "gap_score": self.gap_score,
            "gap_reasons": self.gap_reasons,
            "needs_agent": self.needs_agent,
            "sink_had_no_path": self.sink_had_no_path,
        }


@dataclass
class FlowRecord:
    """流分析档案（可检索记忆）。"""

    flow_id: str
    source_qn: str
    sink_qn: str
    path_qns: list[str]
    sink_type: str
    verdict: str  # vulnerable | sanitized | unknown | inconclusive
    severity: str = "medium"
    confidence: float = 0.5
    reachability: str = "unknown"
    sanitizers: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    related_flow_ids: list[str] = field(default_factory=list)
    communities: list[int] = field(default_factory=list)
    summary: str = ""
    false_positive: bool = False
    analyzed_at: str = ""
    model: str = ""
    analysis_count: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "fingerprint": {
                "source_qn": self.source_qn,
                "sink_qn": self.sink_qn,
                "path_qns": self.path_qns,
                "sink_type": self.sink_type,
                "communities": self.communities,
            },
            "verdict": self.verdict,
            "severity": self.severity,
            "confidence": self.confidence,
            "reachability": self.reachability,
            "sanitizers": self.sanitizers,
            "evidence": self.evidence,
            "tags": self.tags,
            "open_questions": self.open_questions,
            "related_flow_ids": self.related_flow_ids,
            "analysis": {
                "summary": self.summary,
                "analyzed_at": self.analyzed_at,
                "model": self.model,
                "analysis_count": self.analysis_count,
            },
            "false_positive": self.false_positive,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FlowRecord":
        fp = data.get("fingerprint", {})
        analysis = data.get("analysis", {})
        return cls(
            flow_id=data.get("flow_id", ""),
            source_qn=fp.get("source_qn", data.get("source_qn", "")),
            sink_qn=fp.get("sink_qn", data.get("sink_qn", "")),
            path_qns=fp.get("path_qns", data.get("path_qns", [])),
            sink_type=fp.get("sink_type", data.get("sink_type", "")),
            verdict=data.get("verdict", "unknown"),
            severity=data.get("severity", "medium"),
            confidence=float(data.get("confidence", 0.5)),
            reachability=data.get("reachability", "unknown"),
            sanitizers=list(data.get("sanitizers", [])),
            evidence=dict(data.get("evidence", {})),
            tags=list(data.get("tags", [])),
            open_questions=list(data.get("open_questions", [])),
            related_flow_ids=list(data.get("related_flow_ids", [])),
            communities=list(fp.get("communities", data.get("communities", []))),
            summary=analysis.get("summary", data.get("summary", "")),
            false_positive=bool(data.get("false_positive", False)),
            analyzed_at=analysis.get("analyzed_at", ""),
            model=analysis.get("model", ""),
            analysis_count=int(analysis.get("analysis_count", 1)),
        )


@dataclass
class FlowTraceSummary:
    repo_root: str
    candidates: int = 0
    traced: int = 0
    skipped_cached: int = 0
    vulnerable: int = 0
    agent_invoked: int = 0
    high_gap_candidates: int = 0
    records: list[FlowRecord] = field(default_factory=list)
    composite_findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    output_path: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_root": self.repo_root,
            "candidates": self.candidates,
            "traced": self.traced,
            "skipped_cached": self.skipped_cached,
            "vulnerable": self.vulnerable,
            "agent_invoked": self.agent_invoked,
            "high_gap_candidates": self.high_gap_candidates,
            "records": [r.to_dict() for r in self.records],
            "composite_findings": self.composite_findings,
            "errors": self.errors,
            "output_path": self.output_path,
        }
