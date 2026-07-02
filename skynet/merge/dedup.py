"""发现去重与合并。"""

from __future__ import annotations

from skynet.merge.models import SEVERITY_RANK, UnifiedFinding


def merge_findings(groups: list[list[UnifiedFinding]]) -> list[UnifiedFinding]:
    """多组 findings 合并去重，保留最高 severity 与合并 sources。"""
    by_key: dict[str, UnifiedFinding] = {}

    for group in groups:
        for f in group:
            key = f.dedup_key or f.compute_dedup_key()
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = UnifiedFinding(
                    title=f.title,
                    severity=f.severity,
                    vulnerability_type=f.vulnerability_type,
                    description=f.description,
                    sources=list(f.sources),
                    confidence=f.confidence,
                    cwe_id=f.cwe_id,
                    recommendation=f.recommendation,
                    qualified_name=f.qualified_name,
                    sink_qn=f.sink_qn,
                    flow_id=f.flow_id,
                    evidence=dict(f.evidence),
                    dedup_key=key,
                )
                continue

            for src in f.sources:
                if src not in existing.sources:
                    existing.sources.append(src)

            if f.severity_rank() > existing.severity_rank():
                existing.severity = f.severity

            if f.confidence > existing.confidence:
                existing.confidence = f.confidence

            if len(f.description) > len(existing.description):
                existing.description = f.description

            if not existing.cwe_id and f.cwe_id:
                existing.cwe_id = f.cwe_id

            if not existing.flow_id and f.flow_id:
                existing.flow_id = f.flow_id
            if not existing.sink_qn and f.sink_qn:
                existing.sink_qn = f.sink_qn
            if not existing.qualified_name and f.qualified_name:
                existing.qualified_name = f.qualified_name

            existing.evidence.update(f.evidence)

    merged = list(by_key.values())
    merged.sort(key=lambda x: (-x.severity_rank(), -x.confidence))
    return merged


def is_actionable(f: UnifiedFinding) -> bool:
    """过滤无实质内容的条目。"""
    if f.severity in ("info",) and f.confidence < 0.3:
        return False
    if not f.title and not f.description:
        return False
    return True
