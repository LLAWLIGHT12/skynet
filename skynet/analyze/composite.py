"""组合/逻辑漏洞二次分析 v2（社区聚类 + impact radius）。"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from code_review_graph.graph import GraphStore

from skynet.config import SkynetConfig, get_config
from skynet.knowledge.flow_memory import FlowMemoryStore
from skynet.knowledge.internal.store import InternalKnowledgeStore
from skynet.llm.client import LLMClient
from skynet.taint.models import FlowRecord


COMPOSITE_SYSTEM_PROMPT = """你是代码安全审计助手，专注组合漏洞与逻辑漏洞。

你将收到同一影响域内多条数据流、chunk 高危发现、impact radius 波及文件。
任务：判断是否存在单独看每条流/chunk 无法发现的跨模块组合或逻辑漏洞（如越权链、状态不一致、信任边界缺失）。

返回 JSON：
{
  "composite_findings": [
    {
      "title": "标题",
      "severity": "critical|high|medium|low",
      "vulnerability_type": "如 Broken Access Control / Business Logic",
      "description": "组合逻辑说明，说明模块间如何串联",
      "confidence": 0.0-1.0,
      "involved_flows": ["flow_id1"],
      "involved_chunks": ["qualified_name"],
      "recommendation": "修复建议"
    }
  ],
  "summary": "一句话；无则 no composite issues"
}

若无组合问题，composite_findings 为空。"""


@dataclass
class CompositeCluster:
    community_ids: list[int] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    chunks: list[dict[str, Any]] = field(default_factory=list)
    seed_files: list[str] = field(default_factory=list)
    impact: dict[str, Any] = field(default_factory=dict)

    @property
    def is_multi_signal(self) -> bool:
        modules = {c.get("file_path", "") for c in self.chunks}
        modules |= {f.get("source_file", "") for f in self.flows}
        modules |= {f.get("sink_file", "") for f in self.flows}
        modules = {m for m in modules if m}
        if len(self.flows) >= 2:
            return True
        if self.flows and self.chunks:
            return True
        if len(modules) >= 2 and (self.flows or self.chunks):
            return True
        impacted = self.impact.get("impacted_files") or []
        return len(impacted) >= 2 and (bool(self.flows) or bool(self.chunks))


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return json.loads(match.group())
    raise ValueError("无法解析组合分析 JSON")


def _qn_file(qn: str) -> str:
    if "::" in qn:
        return qn.rsplit("::", 1)[0]
    return qn


def _scenario_key(path: str) -> str:
    p = Path(path)
    for part in p.parts:
        if part.startswith("scenario_"):
            return part
    if len(p.parts) >= 2:
        return p.parts[-2]
    return p.parent.name or "default"


class CompositeAnalyzer:
    """按社区 + impact radius 聚类，单次 LLM 判组合漏洞。"""

    def __init__(
        self,
        repo_root: str | Path,
        config: Optional[SkynetConfig] = None,
        llm: Optional[LLMClient] = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.config = config or get_config()
        self.llm = llm or LLMClient()
        self.memory = FlowMemoryStore(
            self.repo_root,
            graph_dir_name=self.config.graph.dir_name,
        )
        self.internal = InternalKnowledgeStore(
            self.repo_root,
            graph_dir_name=self.config.graph.dir_name,
        )

    def _collect_flows(self) -> list[FlowRecord]:
        flows = self.memory.get_vulnerable_flows()
        extra: list[FlowRecord] = []
        for raw in self.memory._store._data.get("flow_records", {}).values():
            rec = FlowRecord.from_dict(raw)
            if rec.false_positive:
                continue
            if rec.verdict in ("inconclusive", "unknown") and rec.open_questions:
                extra.append(rec)
        seen = {f.flow_id for f in flows}
        for rec in extra:
            if rec.flow_id not in seen:
                flows.append(rec)
        return flows

    def _collect_chunk_findings(self, chunk_findings: Optional[list[dict]] = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        if chunk_findings:
            for item in chunk_findings:
                if str(item.get("severity", "")).lower() in ("critical", "high", "medium"):
                    items.append(item)
            return items

        for rel in self.internal._data.get("cross_chunk_findings", []):
            f = rel.get("finding", {})
            if str(f.get("severity", "")).lower() in ("critical", "high", "medium"):
                items.append({
                    "qualified_name": rel.get("qualified_name", ""),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "vulnerability_type": f.get("vulnerability_type", ""),
                    "description": f.get("description", ""),
                    "file_path": _qn_file(str(rel.get("qualified_name", ""))),
                })
        return items

    def _build_clusters(
        self,
        store: GraphStore,
        flows: list[FlowRecord],
        chunk_items: list[dict[str, Any]],
    ) -> list[CompositeCluster]:
        buckets: dict[str, CompositeCluster] = {}

        def _bucket_key(community_ids: list[int], seed_file: str) -> str:
            scenario = _scenario_key(seed_file)
            if scenario.startswith("scenario_"):
                return f"scenario:{scenario}"
            if community_ids:
                return f"comm:{community_ids[0]}"
            return f"file:{scenario}"

        for rec in flows:
            communities = rec.communities or []
            seed = _qn_file(rec.sink_qn or rec.source_qn)
            key = _bucket_key(communities, seed)
            cluster = buckets.setdefault(key, CompositeCluster(community_ids=communities))
            if communities and not cluster.community_ids:
                cluster.community_ids = communities
            cluster.flows.append({
                "flow_id": rec.flow_id,
                "source": rec.source_qn.rsplit("::", 1)[-1],
                "sink": rec.sink_qn.rsplit("::", 1)[-1],
                "source_file": _qn_file(rec.source_qn),
                "sink_file": _qn_file(rec.sink_qn),
                "verdict": rec.verdict,
                "severity": rec.severity,
                "summary": rec.summary,
                "open_questions": rec.open_questions,
                "tags": rec.tags,
            })
            if seed and seed not in cluster.seed_files:
                cluster.seed_files.append(seed)

        for item in chunk_items:
            qn = str(item.get("qualified_name", ""))
            seed = str(item.get("file_path") or _qn_file(qn))
            node = store.get_node(qn) if qn else None
            communities: list[int] = []
            if node is not None:
                cid = store.get_node_community_id(node.id)
                if cid is not None:
                    communities = [cid]
            key = _bucket_key(communities, seed)
            cluster = buckets.setdefault(key, CompositeCluster(community_ids=communities))
            cluster.chunks.append(item)
            if seed and seed not in cluster.seed_files:
                cluster.seed_files.append(seed)

        clusters: list[CompositeCluster] = []
        for cluster in buckets.values():
            if store and cluster.seed_files:
                try:
                    rel_files: list[str] = []
                    for f in cluster.seed_files:
                        p = Path(f)
                        if p.is_absolute():
                            try:
                                rel_files.append(str(p.relative_to(self.repo_root)))
                            except ValueError:
                                rel_files.append(str(p))
                        else:
                            rel_files.append(f)
                    cluster.impact = store.get_impact_radius(rel_files, max_depth=2, max_nodes=200)
                except Exception as e:
                    logger.debug("impact_radius 失败: {}", e)
                    cluster.impact = {}
            if not cluster.is_multi_signal:
                continue
            clusters.append(cluster)

        clusters.sort(key=lambda c: -(len(c.flows) + len(c.chunks)))
        return clusters[: self.config.taint.max_composite_clusters]

    def _cluster_prompt(self, cluster: CompositeCluster, index: int) -> str:
        lines = [f"## Cluster {index + 1}"]
        if cluster.community_ids:
            lines.append(f"Communities: {cluster.community_ids}")
        impact = cluster.impact or {}
        impacted = impact.get("impacted_files") or []
        if impacted:
            lines.append(f"Impact radius files ({len(impacted)}): {', '.join(impacted[:12])}")
        if cluster.flows:
            lines.append("\n### Flows")
            for item in cluster.flows:
                lines.append(
                    f"- [{item['verdict']}] {item['source']} → {item['sink']}: {item['summary']}"
                )
        if cluster.chunks:
            lines.append("\n### Chunk findings")
            for item in cluster.chunks:
                lines.append(
                    f"- [{item.get('severity')}] {item.get('title')} @ {item.get('qualified_name', '')}"
                )
                if item.get("description"):
                    lines.append(f"  {str(item['description'])[:200]}")
        open_qs = self.memory.get_open_questions(cluster.community_ids)
        if open_qs:
            lines.append("\n### Open questions")
            for q in open_qs:
                lines.append(f"- {q}")
        return "\n".join(lines) + "\n\n请返回 JSON。"

    async def run(
        self,
        store: Optional[GraphStore] = None,
        chunk_findings: Optional[list[dict[str, Any]]] = None,
    ) -> list[dict[str, Any]]:
        flows = self._collect_flows()
        chunk_items = self._collect_chunk_findings(chunk_findings)

        if not flows and not chunk_items:
            logger.info("无流记忆或 chunk 发现可组合分析")
            return []

        clusters: list[CompositeCluster] = []
        if store is not None:
            clusters = self._build_clusters(store, flows, chunk_items)
        else:
            db = self.repo_root / self.config.graph.dir_name / self.config.graph.db_name
            if db.is_file():
                with GraphStore(db) as gstore:
                    clusters = self._build_clusters(gstore, flows, chunk_items)

        if not clusters:
            logger.info("无多信号组合簇（需跨模块 flow/chunk 或 impact radius）")
            return []

        all_findings: list[dict[str, Any]] = []
        for i, cluster in enumerate(clusters):
            user_prompt = self._cluster_prompt(cluster, i)
            try:
                raw, _ = await self.llm.chat_json(COMPOSITE_SYSTEM_PROMPT, user_prompt)
                parsed = _extract_json(raw)
                findings = parsed.get("composite_findings") or []
                if isinstance(findings, list):
                    for f in findings:
                        if isinstance(f, dict) and f.get("title"):
                            f.setdefault("community_ids", cluster.community_ids)
                            f.setdefault("impacted_files", (cluster.impact or {}).get("impacted_files", []))
                            all_findings.append(f)
                            self.memory.add_composite_finding(f)
            except Exception as e:
                logger.warning("组合分析失败 cluster {}: {}", i, e)

        logger.info("组合分析: {} 条发现", len(all_findings))
        return all_findings
