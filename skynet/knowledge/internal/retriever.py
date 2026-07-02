"""内部知识检索。"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from skynet.graph.chunks import CodeChunk
from skynet.graph.context import StructuralContext
from skynet.knowledge.internal.store import InternalKnowledgeStore


class InternalKnowledgeRetriever:
    """检索项目模块画像、历史审计与跨 chunk 关联。"""

    def __init__(
        self,
        repo_root: str | Path,
        graph_dir_name: str = ".skynet",
    ) -> None:
        self.store = InternalKnowledgeStore(repo_root, graph_dir_name)

    def retrieve(
        self,
        chunk: CodeChunk,
        structural_ctx: StructuralContext,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        module = None
        if structural_ctx.community_id is not None:
            module = self.store.get_module(structural_ctx.community_id)
        if module is None:
            module = self.store.get_module_by_path(chunk.file_path)
        if module:
            results.append({
                "type": "module",
                "id": f"community_{structural_ctx.community_id or module.get('name', 'module')}",
                "name": module.get("name", f"Community {structural_ctx.community_id}"),
                "description": module.get("summary", ""),
                "file_prefix": module.get("file_prefix", ""),
            })
        elif structural_ctx.community_id is not None:
            prefix = self._infer_module_prefix(chunk.file_path)
            results.append({
                "type": "module_inferred",
                "id": f"community_{structural_ctx.community_id}",
                "name": prefix,
                "description": f"图谱社区 {structural_ctx.community_id}，主要文件前缀: {prefix}",
            })

        hist = self.store.get_chunk_history(chunk.qualified_name)
        if hist:
            results.append({
                "type": "history",
                "id": chunk.qualified_name,
                "name": "历史分析记录",
                "description": (
                    f"上次分析: {hist.get('last_analysis')}, "
                    f"发现 {hist.get('findings_count', 0)} 个问题, "
                    f"摘要: {hist.get('summary', '')}"
                ),
                "false_positive": hist.get("false_positive", False),
            })

        neighbor_names = [
            n.qualified_name
            for n in (structural_ctx.callers + structural_ctx.callees)
        ]
        for rel in self.store.get_related_findings(
            [chunk.qualified_name] + neighbor_names,
            limit=3,
        ):
            f = rel.get("finding", {})
            results.append({
                "type": "cross_chunk",
                "id": rel.get("qualified_name"),
                "name": f.get("title", "关联发现"),
                "description": f.get("description", ""),
                "severity": f.get("severity"),
            })

        if structural_ctx.flow_criticality:
            max_crit = max(structural_ctx.flow_criticality)
            if max_crit >= 0.5:
                results.append({
                    "type": "flow",
                    "id": "execution_flow",
                    "name": "高关键性执行流",
                    "description": (
                        f"该 chunk 位于关键性 {max_crit:.2f} 的执行流上，"
                        "需重点关注逻辑漏洞与组合攻击面。"
                    ),
                })

        return results

    @staticmethod
    def _infer_module_prefix(file_path: str) -> str:
        p = Path(file_path)
        parts = p.parts
        if len(parts) >= 2:
            return "/".join(parts[-3:-1]) if len(parts) >= 3 else parts[-2]
        return p.stem

    def persist_analysis(
        self,
        chunk: CodeChunk,
        structural_ctx: StructuralContext,
        findings: list[dict[str, Any]],
        summary: str,
    ) -> None:
        self.store.record_chunk_analysis(
            chunk.qualified_name,
            len(findings),
            summary,
        )
        for f in findings:
            if f.get("severity") in ("critical", "high", "medium"):
                neighbors = [n.qualified_name for n in structural_ctx.callees[:5]]
                self.store.add_cross_finding(
                    chunk.qualified_name,
                    f,
                    related_chunks=neighbors,
                )
        self.store.save()
