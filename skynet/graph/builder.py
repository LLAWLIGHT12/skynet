"""封装 code-review-graph 的全量/增量构图流程。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from code_review_graph.graph import GraphStore
from code_review_graph.incremental import full_build, incremental_update
from code_review_graph.postprocessing import run_post_processing

from skynet.config import SkynetConfig, get_config, graph_db_path


@dataclass
class BuildResult:
    """构图结果摘要。"""

    repo_root: Path
    db_path: Path
    build_type: str
    files_parsed: int = 0
    total_nodes: int = 0
    total_edges: int = 0
    post_processing: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, str]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_root": str(self.repo_root),
            "db_path": str(self.db_path),
            "build_type": self.build_type,
            "files_parsed": self.files_parsed,
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "post_processing": self.post_processing,
            "errors": self.errors,
            "stats": self.stats,
        }


class GraphBuilder:
    """将目标仓库构建为持久化 SQLite 代码图谱。"""

    def __init__(
        self,
        repo_root: str | Path,
        config: Optional[SkynetConfig] = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.config = config or get_config()
        self.db_path = graph_db_path(self.repo_root, self.config)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def build(self, full_rebuild: Optional[bool] = None) -> BuildResult:
        """构建或增量更新代码图谱，并运行后处理（FTS / flows / communities）。"""
        force_full = (
            self.config.graph.full_rebuild
            if full_rebuild is None
            else full_rebuild
        )
        use_full = force_full or not self.db_path.exists()

        logger.info(
            "开始{}构图: {} -> {}",
            "全量" if use_full else "增量",
            self.repo_root,
            self.db_path,
        )

        with GraphStore(self.db_path) as store:
            if use_full:
                raw = full_build(self.repo_root, store)
                build_type = "full"
            else:
                raw = incremental_update(self.repo_root, store)
                build_type = "incremental"

            post = run_post_processing(store)
            stats = store.get_stats()

        result = BuildResult(
            repo_root=self.repo_root,
            db_path=self.db_path,
            build_type=build_type,
            files_parsed=raw.get("files_parsed", 0),
            total_nodes=raw.get("total_nodes", stats.total_nodes),
            total_edges=raw.get("total_edges", stats.total_edges),
            post_processing=post,
            errors=raw.get("errors", []),
            stats={
                "nodes_by_kind": stats.nodes_by_kind,
                "edges_by_kind": stats.edges_by_kind,
                "languages": stats.languages,
                "files_count": stats.files_count,
                "last_updated": stats.last_updated,
            },
        )

        logger.info(
            "构图完成: {} 文件, {} 节点, {} 边 ({} 个解析错误)",
            result.files_parsed,
            result.total_nodes,
            result.total_edges,
            len(result.errors),
        )
        return result

    def open_store(self) -> GraphStore:
        if not self.db_path.exists():
            raise FileNotFoundError(
                f"图谱不存在: {self.db_path}，请先运行 build 命令"
            )
        return GraphStore(self.db_path)
