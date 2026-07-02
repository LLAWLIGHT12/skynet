"""分析结果数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class SecurityFinding:
    title: str
    severity: str
    vulnerability_type: str
    description: str
    confidence: float = 0.5
    cwe_id: Optional[str] = None
    recommendation: str = ""
    line_hint: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "vulnerability_type": self.vulnerability_type,
            "description": self.description,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "recommendation": self.recommendation,
            "line_hint": self.line_hint,
        }


@dataclass
class ChunkAnalysisResult:
    qualified_name: str
    kind: str
    file_path: str
    line_start: int
    line_end: int
    findings: list[SecurityFinding] = field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None
    raw_response: Optional[str] = None
    knowledge_used: dict[str, Any] = field(default_factory=dict)
    web_search_used: bool = False
    needs_flow_trace: bool = False
    sink_types: list[str] = field(default_factory=list)
    usage: Optional[dict[str, Any]] = None  # LLM token usage

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "qualified_name": self.qualified_name,
            "kind": self.kind,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "error": self.error,
            "finding_count": len(self.findings),
            "knowledge_used": self.knowledge_used,
            "web_search_used": self.web_search_used,
            "needs_flow_trace": self.needs_flow_trace,
            "sink_types": self.sink_types,
            "usage": self.usage,
        }
