"""Agent / LSP 补边持久化与 BFS 合并。"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from code_review_graph.graph import GraphStore


def overrides_path(repo_root: str | Path, graph_dir_name: str = ".skynet") -> Path:
    return Path(repo_root).resolve() / graph_dir_name / "graph_overrides.json"


class GraphOverridesStore:
    """读写 `.skynet/graph_overrides.json` 中的 CALLS 补边。"""

    def __init__(self, repo_root: str | Path, graph_dir_name: str = ".skynet") -> None:
        self.repo_root = Path(repo_root).resolve()
        self.path = overrides_path(repo_root, graph_dir_name)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._load()

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {"version": 1, "updated_at": None, "calls": []}

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return self._empty()
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("calls", [])
                return data
        except (json.JSONDecodeError, OSError):
            pass
        return self._empty()

    def save(self) -> None:
        self._data["updated_at"] = datetime.now().isoformat()
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)

    @property
    def calls(self) -> list[dict[str, Any]]:
        return list(self._data.get("calls", []))

    def add_calls(
        self,
        edges: list[tuple[str, str]],
        *,
        flow_id: str = "",
        source: str = "agent",
        confidence: float = 0.85,
    ) -> int:
        if not edges:
            return 0
        existing = {
            (c.get("source"), c.get("target"))
            for c in self._data.get("calls", [])
        }
        added = 0
        for src, tgt in edges:
            if not src or not tgt or (src, tgt) in existing:
                continue
            self._data.setdefault("calls", []).append({
                "source": src,
                "target": tgt,
                "kind": "CALLS",
                "flow_id": flow_id,
                "source_agent": source,
                "confidence": confidence,
                "recorded_at": datetime.now().isoformat(),
            })
            existing.add((src, tgt))
            added += 1
        if added:
            self.save()
        return added

    def merge_into_calls_in(
        self,
        calls_in: dict[str, list[str]],
    ) -> dict[str, list[str]]:
        """将补边合并进反向 CALLS 索引（target -> [sources]）。"""
        merged = {k: list(v) for k, v in calls_in.items()}
        for edge in self._data.get("calls", []):
            if edge.get("kind", "CALLS") != "CALLS":
                continue
            src = str(edge.get("source", ""))
            tgt = str(edge.get("target", ""))
            if not src or not tgt:
                continue
            callers = merged.setdefault(tgt, [])
            if src not in callers:
                callers.append(src)
        return merged

    def has_calls_edge(self, src: str, tgt: str) -> bool:
        tgt_name = tgt.rsplit("::", 1)[-1]
        for edge in self._data.get("calls", []):
            if edge.get("source") != src:
                continue
            et = str(edge.get("target", ""))
            if et == tgt or et == tgt_name:
                return True
        return False


def resolve_path_item(
    item: Any,
    store: GraphStore,
    repo_root: Path,
) -> Optional[str]:
    """将 resolved_path 条目解析为 qualified_name。"""
    if not isinstance(item, str) or not item.strip():
        return None
    text = item.strip()
    if "::" in text:
        node = store.get_node(text)
        return text if node else None
    if ":" in text and (text.endswith(".py") or "/" in text or "\\" in text):
        file_part, _, line_part = text.rpartition(":")
        try:
            line = int(line_part)
        except ValueError:
            return None
        file_path = str((repo_root / file_part).resolve()) if not Path(file_part).is_absolute() else file_part
        for node in store.get_all_nodes():
            if node.file_path.replace("\\", "/") != Path(file_path).as_posix().replace("\\", "/"):
                continue
            if node.line_start and abs(node.line_start - line) <= 3:
                return node.qualified_name
        return None
    node = store.get_node(text)
    if node:
        return node.qualified_name
    for node in store.get_all_nodes():
        if node.name == text.rsplit("::", 1)[-1]:
            return node.qualified_name
    return None


def edges_from_resolved_path(
    resolved_path: list[Any],
    store: GraphStore,
    repo_root: str | Path,
) -> list[tuple[str, str]]:
    """从 Agent conclude 的 resolved_path 提取连续 CALLS 边。"""
    root = Path(repo_root).resolve()
    qns: list[str] = []
    for item in resolved_path:
        qn = resolve_path_item(item, store, root)
        if qn and (not qns or qns[-1] != qn):
            qns.append(qn)
    return [(qns[i], qns[i + 1]) for i in range(len(qns) - 1)]


def persist_agent_resolved_path(
    store: GraphStore,
    repo_root: str | Path,
    resolved_path: list[Any],
    flow_id: str = "",
    graph_dir_name: str = ".skynet",
) -> int:
    edges = edges_from_resolved_path(resolved_path, store, repo_root)
    if not edges:
        return 0
    ostore = GraphOverridesStore(repo_root, graph_dir_name)
    return ostore.add_calls(edges, flow_id=flow_id, source="agent")
