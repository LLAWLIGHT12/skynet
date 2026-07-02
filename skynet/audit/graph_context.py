"""图谱增强上下文 —— 为 audit 管线阶段提供 skynet 图谱能力。

当图谱可用时，StageContext 获得额外的 graph_info 字段，包含：
- community 信息（子系统划分）
- node 类型统计（入口点类型分布）
- 影响半径分析
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class GraphInfo:
    """从 skynet 代码图谱提取的结构化信息，注入到管线阶段。"""

    available: bool = False
    repo_root: str = ""
    db_path: str = ""

    # 社区/子系统
    communities: list[dict[str, Any]] = field(default_factory=list)
    community_count: int = 0

    # 节点统计
    total_nodes: int = 0
    total_edges: int = 0
    nodes_by_kind: dict[str, int] = field(default_factory=dict)
    files_count: int = 0

    # 入口点
    entry_points: list[dict[str, Any]] = field(default_factory=list)

    # 安全相关节点统计
    sink_candidates: int = 0
    source_candidates: int = 0

    def to_prompt_block(self) -> str:
        """生成注入到 prompt 的结构化信息块。"""
        if not self.available:
            return ""

        lines = [
            "\n## Code Graph Analysis (pre-computed)",
            f"- Repository: `{self.repo_root}`",
            f"- Total files parsed: {self.files_count}",
            f"- Total code nodes: {self.total_nodes}, edges: {self.total_edges}",
            f"- Communities detected: {self.community_count}",
        ]

        if self.nodes_by_kind:
            kinds = ", ".join(f"{k}: {v}" for k, v in sorted(self.nodes_by_kind.items()))
            lines.append(f"- Node types: {kinds}")

        if self.entry_points:
            lines.append("- Detected entry points:")
            for ep in self.entry_points[:20]:
                lines.append(f"  - `{ep.get('qualified_name', ep.get('name', '?'))}` "
                             f"({ep.get('kind', '?')}) @ {ep.get('file', '?')}")

        if self.communities:
            lines.append("- Subsystems (communities):")
            for c in self.communities[:15]:
                name = c.get("name", c.get("community_id", "?"))
                size = c.get("size", c.get("node_count", "?"))
                lines.append(f"  - {name} ({size} nodes)")

        return "\n".join(lines) + "\n"


def build_graph_info(repo_root: str | Path) -> GraphInfo:
    """从 skynet 图谱构建 GraphInfo。失败时返回 available=False。"""
    try:
        from code_review_graph.graph import GraphStore

        root = Path(repo_root).resolve()
        db_path = root / ".skynet" / "graph.db"

        if not db_path.is_file():
            log.debug("图谱不存在: %s，跳过图谱增强", db_path)
            return GraphInfo(available=False)

        with GraphStore(db_path) as store:
            stats = store.get_stats()

            info = GraphInfo(
                available=True,
                repo_root=str(root),
                db_path=str(db_path),
                total_nodes=stats.total_nodes,
                total_edges=stats.total_edges,
                nodes_by_kind=dict(stats.nodes_by_kind) if stats.nodes_by_kind else {},
                files_count=stats.files_count,
                community_count=0,
            )

            # 提取社区信息
            try:
                communities = store.get_communities()
                if communities:
                    info.communities = [
                        {"community_id": cid, "node_count": len(nodes)}
                        for cid, nodes in communities.items()
                    ]
                    info.community_count = len(info.communities)
            except Exception as e:
                log.warning("图谱社区信息提取失败: %s", e)

            # 提取入口点
            try:
                from skynet.graph.chunks import iter_chunks

                # 快速扫描有外部调用者的节点作为入口点
                entry_candidates: list[dict[str, Any]] = []
                # 查找 HTTP handler、CLI entry、public API 等
                entry_kinds = {"http_handler", "cli_command", "public_api", "rpc_handler"}
                for chunk in iter_chunks(store, root, skip_tests=True):
                    if chunk.kind in entry_kinds:
                        entry_candidates.append({
                            "qualified_name": chunk.qualified_name,
                            "kind": chunk.kind,
                            "file": chunk.file_path,
                            "line_start": chunk.line_start,
                        })
                        if len(entry_candidates) >= 30:
                            break
                info.entry_points = entry_candidates
            except Exception as e:
                log.warning("图谱入口点提取失败: %s", e)

            # 估算 source/sink 候选
            try:
                from skynet.taint.catalog import TaintCatalog

                catalog = TaintCatalog(None).build_from_store(store, root)
                info.source_candidates = len(catalog.sources)
                info.sink_candidates = len(catalog.sinks)
            except Exception as e:
                log.warning("图谱 source/sink 候选估算失败: %s", e)

            log.info(
                "图谱增强: %d communities, %d entry points, %d sources, %d sinks",
                info.community_count, len(info.entry_points),
                info.source_candidates, info.sink_candidates,
            )
            return info

    except Exception as e:
        log.debug("图谱增强失败: %s", e)
        return GraphInfo(available=False)
