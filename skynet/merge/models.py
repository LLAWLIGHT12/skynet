"""统一扫描发现数据模型。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


@dataclass
class UnifiedFinding:
    """合并后的单条安全发现。"""

    title: str
    severity: str
    vulnerability_type: str
    description: str
    sources: list[str] = field(default_factory=list)
    confidence: float = 0.5
    cwe_id: Optional[str] = None
    recommendation: str = ""
    qualified_name: str = ""
    sink_qn: str = ""
    flow_id: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    dedup_key: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: str = ""

    def __post_init__(self) -> None:
        if not self.dedup_key:
            self.dedup_key = self.compute_dedup_key()

    def compute_dedup_key(self) -> str:
        cwe = (self.cwe_id or "").upper()
        if cwe and not cwe.startswith("CWE"):
            cwe = f"CWE-{cwe}"
        sink = self.sink_qn or self.qualified_name
        vtype = self.vulnerability_type.lower().strip()
        if sink and (cwe or vtype not in ("", "unknown", "security issue")):
            raw = f"{cwe}|{sink}|{vtype}"
        else:
            title_norm = self.title.lower().strip()[:80]
            raw = f"{cwe}|{sink}|{vtype}|{title_norm}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity.lower(), 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dedup_key": self.dedup_key,
            "title": self.title,
            "severity": self.severity,
            "vulnerability_type": self.vulnerability_type,
            "description": self.description,
            "sources": self.sources,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "recommendation": self.recommendation,
            "qualified_name": self.qualified_name,
            "sink_qn": self.sink_qn,
            "flow_id": self.flow_id,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
        }


@dataclass
class ScanReport:
    """一次完整扫描的合并报告。"""

    repo_root: str
    generated_at: str = ""
    model: str = ""
    chunk_findings: list[UnifiedFinding] = field(default_factory=list)
    flow_findings: list[UnifiedFinding] = field(default_factory=list)
    composite_findings: list[UnifiedFinding] = field(default_factory=list)
    merged: list[UnifiedFinding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    analysis_path: Optional[str] = None
    flow_trace_path: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.now().isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "repo_root": self.repo_root,
            "model": self.model,
            "analysis_path": self.analysis_path,
            "flow_trace_path": self.flow_trace_path,
            "stats": self.stats,
            "chunk_findings": [f.to_dict() for f in self.chunk_findings],
            "flow_findings": [f.to_dict() for f in self.flow_findings],
            "composite_findings": [f.to_dict() for f in self.composite_findings],
            "merged": [f.to_dict() for f in self.merged],
        }
