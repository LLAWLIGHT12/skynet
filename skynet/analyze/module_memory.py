"""分析结束后写回社区/模块摘要。"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from code_review_graph.graph import GraphStore

from skynet.analyze.models import ChunkAnalysisResult
from skynet.config import SkynetConfig, get_config
from skynet.knowledge.internal.store import InternalKnowledgeStore
from skynet.llm.client import LLMClient

MODULE_SUMMARY_PROMPT = """你是代码库架构助手。根据同一模块内多个函数的分析摘要，用 1-2 句中文概括该模块职责与安全关注点。

返回 JSON：{"name": "模块短名", "summary": "1-2句描述"}"""


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return json.loads(match.group())
    raise ValueError("无法解析模块摘要 JSON")


def _scenario_key(path: str) -> str:
    p = Path(path)
    for part in p.parts:
        if part.startswith("scenario_"):
            return part
    if len(p.parts) >= 2:
        return p.parts[-2]
    return p.parent.name or "default"


class ModuleMemoryWriter:
    """为图谱社区生成并持久化模块 summary。"""

    def __init__(
        self,
        repo_root: str | Path,
        config: Optional[SkynetConfig] = None,
        llm: Optional[LLMClient] = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.config = config or get_config()
        self.llm = llm or LLMClient()
        self.store = InternalKnowledgeStore(
            self.repo_root,
            graph_dir_name=self.config.graph.dir_name,
        )

    async def write_from_results(
        self,
        store: GraphStore,
        results: list[ChunkAnalysisResult],
    ) -> int:
        by_community: dict[int, list[ChunkAnalysisResult]] = defaultdict(list)
        by_scenario: dict[str, list[ChunkAnalysisResult]] = defaultdict(list)
        for result in results:
            if result.error:
                continue
            node = store.get_node(result.qualified_name)
            cid: Optional[int] = None
            if node is not None:
                cid = store.get_node_community_id(node.id)
            if cid is not None:
                by_community[cid].append(result)
            else:
                by_scenario[_scenario_key(result.file_path)].append(result)

        written = 0
        for cid, items in by_community.items():
            written += await self._write_one_group(store, cid, items)
        for scenario, items in by_scenario.items():
            if not items:
                continue
            pseudo_id = -abs(hash(scenario)) % 1_000_000
            written += await self._write_one_group(store, pseudo_id, items, scenario_name=scenario)
        if written:
            self.store.save()
        return written

    async def _write_one_group(
        self,
        store: GraphStore,
        cid: int,
        items: list[ChunkAnalysisResult],
        scenario_name: str = "",
    ) -> int:
        existing = self.store.get_module(cid)
        if existing and existing.get("summary"):
            return 0

        prefix = self._common_prefix(items)
        lines = [
            f"- {r.qualified_name.rsplit('::', 1)[-1]}: {r.summary or 'no summary'}"
            for r in items[:8]
        ]
        label = scenario_name or f"Community {cid}"
        user = f"{label}\n文件前缀: {prefix}\n\n" + "\n".join(lines)
        try:
            raw, _ = await self.llm.chat_json(MODULE_SUMMARY_PROMPT, user)
            parsed = _extract_json(raw)
            name = str(parsed.get("name", prefix or label))
            summary = str(parsed.get("summary", "")).strip()
            if summary:
                self.store.set_module_summary(cid, name, summary, file_prefix=prefix)
                logger.info("模块记忆 community={}: {}", cid, summary[:80])
                return 1
        except Exception as e:
            logger.warning("模块摘要生成失败 community {}: {}", cid, e)
        return 0

    @staticmethod
    def _common_prefix(items: list[ChunkAnalysisResult]) -> str:
        paths = [Path(r.file_path) for r in items if r.file_path]
        if not paths:
            return ""
        parts = [list(p.parts) for p in paths]
        common: list[str] = []
        for segment in zip(*parts):
            if len(set(segment)) == 1:
                common.append(segment[0])
            else:
                break
        return "/".join(common[-3:]) if common else paths[0].parent.name
