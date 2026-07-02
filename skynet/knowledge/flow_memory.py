"""Flow Memory — 流级可检索记忆。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from skynet.knowledge.internal.store import InternalKnowledgeStore
from skynet.taint.models import FlowCandidate, FlowRecord


class FlowMemoryStore:
    """管理 project.json 中的 flow_records / flow_index / system_memory。"""

    def __init__(self, repo_root: str, graph_dir_name: str = ".skynet") -> None:
        self._store = InternalKnowledgeStore(repo_root, graph_dir_name)

    @property
    def path(self):
        return self._store.path

    def get(self, flow_id: str) -> Optional[FlowRecord]:
        raw = self._store._data.get("flow_records", {}).get(flow_id)
        if not raw:
            return None
        return FlowRecord.from_dict(raw)

    def upsert(self, record: FlowRecord) -> None:
        prev = self._store._data.get("flow_records", {}).get(record.flow_id)
        if prev:
            record.analysis_count = int(
                prev.get("analysis", {}).get("analysis_count", 1)
            ) + 1
            if prev.get("false_positive"):
                record.false_positive = True

        self._store._data.setdefault("flow_records", {})[record.flow_id] = record.to_dict()
        self._rebuild_index_for_record(record)
        self._link_related_flows(record)
        self._store.save()

    def _rebuild_index_for_record(self, record: FlowRecord) -> None:
        idx = self._store._data.setdefault("flow_index", {
            "by_sink": {},
            "by_node": {},
            "by_community": {},
            "open_questions": [],
        })
        fid = record.flow_id
        idx.setdefault("by_sink", {}).setdefault(record.sink_qn, [])
        if fid not in idx["by_sink"][record.sink_qn]:
            idx["by_sink"][record.sink_qn].append(fid)

        for qn in record.path_qns:
            idx.setdefault("by_node", {}).setdefault(qn, [])
            if fid not in idx["by_node"][qn]:
                idx["by_node"][qn].append(fid)

        for cid in record.communities:
            key = str(cid)
            idx.setdefault("by_community", {}).setdefault(key, [])
            if fid not in idx["by_community"][key]:
                idx["by_community"][key].append(fid)

        idx["open_questions"] = [
            q for q in idx.get("open_questions", [])
            if q.get("flow_id") != fid
        ]
        for text in record.open_questions:
            idx["open_questions"].append({"flow_id": fid, "text": text})

    def _link_related_flows(self, record: FlowRecord) -> None:
        related: set[str] = set()
        idx = self._store._data.get("flow_index", {})
        for qn in record.path_qns:
            for fid in idx.get("by_node", {}).get(qn, []):
                if fid != record.flow_id:
                    related.add(fid)
        for fid in idx.get("by_sink", {}).get(record.sink_qn, []):
            if fid != record.flow_id:
                related.add(fid)
        record.related_flow_ids = sorted(related)[:10]
        self._store._data["flow_records"][record.flow_id] = record.to_dict()

    def should_skip(self, candidate: FlowCandidate, code_hash: str = "") -> Optional[FlowRecord]:
        """若已有未标记误报的缓存结论，可跳过 LLM。"""
        existing = self.get(candidate.flow_id)
        if existing is None:
            return None
        if existing.false_positive:
            return existing
        if existing.verdict in ("vulnerable", "sanitized") and existing.confidence >= 0.7:
            return existing
        return None

    def get_context_for_flow(self, candidate: FlowCandidate, limit: int = 5) -> list[dict[str, Any]]:
        """检索相关历史流档案，供 LLM prompt 使用。"""
        idx = self._store._data.get("flow_index", {})
        seen: set[str] = {candidate.flow_id}
        items: list[dict[str, Any]] = []

        def _add(fid: str) -> None:
            if fid in seen:
                return
            rec = self.get(fid)
            if rec:
                seen.add(fid)
                items.append({
                    "flow_id": rec.flow_id,
                    "path": " → ".join(
                        q.rsplit("::", 1)[-1] for q in rec.path_qns
                    ),
                    "verdict": rec.verdict,
                    "severity": rec.severity,
                    "summary": rec.summary,
                    "sanitizers": rec.sanitizers,
                    "open_questions": rec.open_questions,
                })

        for qn in candidate.path_qns:
            for fid in idx.get("by_node", {}).get(qn, []):
                _add(fid)
            if len(items) >= limit:
                break

        for fid in idx.get("by_sink", {}).get(candidate.sink_qn, []):
            _add(fid)
            if len(items) >= limit:
                break

        for cid in candidate.communities:
            for fid in idx.get("by_community", {}).get(str(cid), []):
                _add(fid)
                if len(items) >= limit:
                    break

        return items[:limit]

    def get_open_questions(self, community_ids: list[int], limit: int = 5) -> list[str]:
        idx = self._store._data.get("flow_index", {})
        flow_ids: set[str] = set()
        for cid in community_ids:
            flow_ids.update(idx.get("by_community", {}).get(str(cid), []))
        texts: list[str] = []
        for item in idx.get("open_questions", []):
            if item.get("flow_id") in flow_ids:
                texts.append(str(item.get("text", "")))
            if len(texts) >= limit:
                break
        return texts

    def add_hypothesis(self, text: str, flow_ids: list[str], tags: list[str] | None = None) -> None:
        mem = self._store._data.setdefault("system_memory", {
            "invariants": [],
            "hypotheses": [],
            "composite_findings": [],
        })
        mem.setdefault("hypotheses", []).append({
            "text": text,
            "flow_ids": flow_ids,
            "tags": tags or [],
            "recorded_at": datetime.now().isoformat(),
        })
        if len(mem["hypotheses"]) > 100:
            mem["hypotheses"] = mem["hypotheses"][-100:]
        self._store.save()

    def add_composite_finding(self, finding: dict[str, Any]) -> None:
        mem = self._store._data.setdefault("system_memory", {
            "invariants": [],
            "hypotheses": [],
            "composite_findings": [],
        })
        finding["recorded_at"] = datetime.now().isoformat()
        mem.setdefault("composite_findings", []).append(finding)
        if len(mem["composite_findings"]) > 100:
            mem["composite_findings"] = mem["composite_findings"][-100:]
        self._store.save()

    def get_vulnerable_flows(self) -> list[FlowRecord]:
        records: list[FlowRecord] = []
        for raw in self._store._data.get("flow_records", {}).values():
            rec = FlowRecord.from_dict(raw)
            if rec.false_positive:
                continue
            if rec.verdict in ("vulnerable", "inconclusive"):
                records.append(rec)
        return records

    def mark_flow_false_positive(self, flow_id: str, reason: str = "") -> bool:
        return self._store.mark_flow_false_positive(flow_id, reason)

    def mark_chunk_false_positive(self, qualified_name: str, reason: str = "") -> bool:
        return self._store.mark_chunk_false_positive(qualified_name, reason)

    def save(self) -> None:
        self._store.save()
