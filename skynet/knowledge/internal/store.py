"""项目内部知识库（.skynet/knowledge/）。"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


def internal_knowledge_path(repo_root: str | Path, graph_dir_name: str = ".skynet") -> Path:
    return Path(repo_root).resolve() / graph_dir_name / "knowledge" / "project.json"


class InternalKnowledgeStore:
    """读写项目级内部知识：模块画像、chunk 历史、关联发现。"""

    def __init__(self, repo_root: str | Path, graph_dir_name: str = ".skynet") -> None:
        self.repo_root = Path(repo_root).resolve()
        self.path = internal_knowledge_path(repo_root, graph_dir_name)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "version": 2,
            "updated_at": None,
            "modules": {},
            "chunk_history": {},
            "cross_chunk_findings": [],
            "flow_records": {},
            "flow_index": {
                "by_sink": {},
                "by_node": {},
                "by_community": {},
                "open_questions": [],
            },
            "system_memory": {
                "invariants": [],
                "hypotheses": [],
                "composite_findings": [],
            },
        }

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return self._empty()
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return self._empty()
            return self._migrate(data)
        except (json.JSONDecodeError, OSError):
            pass
        return self._empty()

    @staticmethod
    def _migrate(data: dict[str, Any]) -> dict[str, Any]:
        if data.get("version", 1) >= 2:
            return data
        data["version"] = 2
        data.setdefault("flow_records", {})
        data.setdefault("flow_index", {
            "by_sink": {},
            "by_node": {},
            "by_community": {},
            "open_questions": [],
        })
        data.setdefault("system_memory", {
            "invariants": [],
            "hypotheses": [],
            "composite_findings": [],
        })
        return data

    def save(self) -> None:
        self._data["updated_at"] = datetime.now().isoformat()
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)

    def get_module(self, community_id: Optional[int]) -> Optional[dict[str, Any]]:
        if community_id is None:
            return None
        return self._data.get("modules", {}).get(str(community_id))

    def get_module_by_path(self, file_path: str) -> Optional[dict[str, Any]]:
        scenario = ""
        for part in Path(file_path).parts:
            if part.startswith("scenario_"):
                scenario = part
                break
        for mod in self._data.get("modules", {}).values():
            prefix = str(mod.get("file_prefix", ""))
            if scenario and scenario in prefix:
                return mod
            if prefix and prefix in file_path:
                return mod
        return None

    def set_module_summary(
        self,
        community_id: int,
        name: str,
        summary: str,
        file_prefix: str = "",
    ) -> None:
        self._data.setdefault("modules", {})[str(community_id)] = {
            "name": name,
            "summary": summary,
            "file_prefix": file_prefix,
            "updated_at": datetime.now().isoformat(),
        }

    def get_chunk_history(self, qualified_name: str) -> Optional[dict[str, Any]]:
        return self._data.get("chunk_history", {}).get(qualified_name)

    def record_chunk_analysis(
        self,
        qualified_name: str,
        findings_count: int,
        summary: str,
        false_positive: bool = False,
    ) -> None:
        hist = self._data.setdefault("chunk_history", {})
        prev = hist.get(qualified_name, {})
        hist[qualified_name] = {
            "last_analysis": datetime.now().isoformat(),
            "findings_count": findings_count,
            "summary": summary,
            "analysis_count": int(prev.get("analysis_count", 0)) + 1,
            "false_positive": false_positive or prev.get("false_positive", False),
        }

    def get_related_findings(self, qualified_names: list[str], limit: int = 5) -> list[dict[str, Any]]:
        names = set(qualified_names)
        related: list[dict[str, Any]] = []
        for item in reversed(self._data.get("cross_chunk_findings", [])):
            if item.get("qualified_name") in names:
                related.append(item)
            elif any(n in item.get("related_chunks", []) for n in names):
                related.append(item)
            if len(related) >= limit:
                break
        return related

    def add_cross_finding(
        self,
        qualified_name: str,
        finding: dict[str, Any],
        related_chunks: Optional[list[str]] = None,
    ) -> None:
        self._data.setdefault("cross_chunk_findings", []).append({
            "qualified_name": qualified_name,
            "finding": finding,
            "related_chunks": related_chunks or [],
            "recorded_at": datetime.now().isoformat(),
        })
        # 保留最近 200 条
        items = self._data["cross_chunk_findings"]
        if len(items) > 200:
            self._data["cross_chunk_findings"] = items[-200:]

    def mark_chunk_false_positive(self, qualified_name: str, reason: str = "") -> bool:
        hist = self._data.setdefault("chunk_history", {})
        if qualified_name not in hist:
            hist[qualified_name] = {
                "last_analysis": datetime.now().isoformat(),
                "findings_count": 0,
                "summary": "",
                "analysis_count": 0,
            }
        hist[qualified_name]["false_positive"] = True
        hist[qualified_name]["false_positive_reason"] = reason
        hist[qualified_name]["false_positive_at"] = datetime.now().isoformat()
        self.save()
        return True

    def mark_flow_false_positive(self, flow_id: str, reason: str = "") -> bool:
        records = self._data.setdefault("flow_records", {})
        rec = records.get(flow_id)
        if not rec:
            return False
        rec["false_positive"] = True
        rec["false_positive_reason"] = reason
        rec["false_positive_at"] = datetime.now().isoformat()
        self.save()
        return True
