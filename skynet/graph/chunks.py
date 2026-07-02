"""从图谱节点生成可分析的代码 chunk。"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from code_review_graph.graph import GraphNode, GraphStore

from skynet.config import SkynetConfig, get_config


@dataclass
class CodeChunk:
    """以 Function / Class 为粒度的分析单元。"""

    node_id: int
    qualified_name: str
    kind: str
    name: str
    file_path: str
    line_start: int
    line_end: int
    language: str
    source: str
    signature: Optional[str] = None
    parent_name: Optional[str] = None
    is_test: bool = False

    @property
    def loc(self) -> int:
        if self.line_end >= self.line_start > 0:
            return self.line_end - self.line_start + 1
        return len(self.source.splitlines())


def _safe_resolve(repo_root: Path, file_path: str) -> Optional[Path]:
    """安全解析文件路径，确保在 repo_root 范围内，防止路径遍历。"""
    p = Path(file_path)
    if p.is_absolute():
        try:
            resolved = p.resolve()
            root_resolved = repo_root.resolve()
            resolved.relative_to(root_resolved)  # 路径逃逸时会抛出 ValueError
            return resolved
        except (ValueError, OSError):
            return None
    else:
        candidate = repo_root / p
        try:
            resolved = candidate.resolve()
            root_resolved = repo_root.resolve()
            resolved.relative_to(root_resolved)
            return resolved
        except (ValueError, OSError):
            return None


def read_node_source(
    node: GraphNode,
    repo_root: Optional[Path] = None,
) -> str:
    """按节点行号从源文件截取代码片段。"""
    if repo_root is not None:
        safe_path = _safe_resolve(repo_root, node.file_path)
        if safe_path is not None and safe_path.is_file():
            path = safe_path
        else:
            return ""
    else:
        path = Path(node.file_path)
        if not path.is_file():
            return ""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""

    start = max((node.line_start or 1) - 1, 0)
    end = node.line_end or len(lines)
    if end < start:
        end = start
    return "\n".join(lines[start:end])


def iter_chunks(
    store: GraphStore,
    repo_root: str | Path,
    kinds: Optional[list[str]] = None,
    config: Optional[SkynetConfig] = None,
    skip_tests: bool = True,
) -> Iterator[CodeChunk]:
    """遍历图谱中可分析的代码 chunk。"""
    cfg = config or get_config()
    kinds = kinds or cfg.graph.analyzable_kinds
    root = Path(repo_root).resolve()

    for node in store.get_nodes_by_kind(kinds):
        if skip_tests and node.is_test:
            continue
        if node.kind == "Test":
            continue

        source = read_node_source(node, root)
        if not source.strip():
            continue

        yield CodeChunk(
            node_id=node.id,
            qualified_name=node.qualified_name,
            kind=node.kind,
            name=node.name,
            file_path=node.file_path,
            line_start=node.line_start or 0,
            line_end=node.line_end or 0,
            language=node.language,
            source=source,
            signature=node.extra.get("signature") if node.extra else None,
            parent_name=node.parent_name,
            is_test=node.is_test,
        )


def count_chunks(
    store: GraphStore,
    kinds: Optional[list[str]] = None,
    config: Optional[SkynetConfig] = None,
) -> int:
    cfg = config or get_config()
    kinds = kinds or cfg.graph.analyzable_kinds
    return len(store.get_nodes_by_kind(kinds))
