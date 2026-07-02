"""单路径流污点验证（含历史记忆检索）。"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from code_review_graph.graph import GraphStore

from skynet.config import SkynetConfig, get_config
from skynet.graph.chunks import read_node_source
from skynet.knowledge.external.retriever import ExternalKnowledgeRetriever
from skynet.knowledge.flow_memory import FlowMemoryStore
from skynet.llm.client import LLMClient
from skynet.taint.models import FlowCandidate, FlowRecord
from skynet.taint.prompts import (
    FLOW_SYSTEM_PROMPT,
    build_flow_prompt,
    format_history_block,
)


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return json.loads(match.group())
    raise ValueError("无法解析流分析 JSON")


class FlowVerifier:
    """对单条 FlowCandidate 做 LLM 污点验证并写入 Flow Memory。"""

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
        kdir = self.config.knowledge.external_dir or None
        self.external = ExternalKnowledgeRetriever(kdir)
        self.max_lines = min(120, self.config.analyze.max_source_lines // 3)

    def _path_source_blocks(
        self,
        store: GraphStore,
        path_qns: list[str],
    ) -> str:
        blocks: list[str] = []
        for i, qn in enumerate(path_qns):
            node = store.get_node(qn)
            if node is None:
                blocks.append(f"### [{i}] {qn}\n(not in graph)")
                continue
            src = read_node_source(node, self.repo_root)
            lines = src.splitlines()
            if len(lines) > self.max_lines:
                src = "\n".join(lines[: self.max_lines]) + f"\n# ... ({len(lines) - self.max_lines} more)"
            short = qn.rsplit("::", 1)[-1]
            blocks.append(f"### [{i}] {short}\n```\n{src}\n```")
        return "\n\n".join(blocks)

    async def verify(
        self,
        store: GraphStore,
        candidate: FlowCandidate,
        use_cache: bool = True,
    ) -> FlowRecord:
        if use_cache and self.config.taint.cache_flow_results:
            cached = self.memory.should_skip(candidate)
            if cached:
                logger.debug("流缓存命中: {}", candidate.flow_id)
                return cached

        history = self.memory.get_context_for_flow(candidate)
        combined_text = "\n".join(candidate.path_qns)
        knowledge = self.external.retrieve_by_text(
            combined_text,
            max_items=self.config.knowledge.max_external_items,
        )
        knowledge_block = ""
        if knowledge:
            lines = ["## External security knowledge"]
            for k in knowledge:
                lines.append(
                    f"- [{k.get('type')}] {k.get('id', '')} {k.get('name', '')}: {k.get('description', '')}"
                )
            knowledge_block = "\n".join(lines)

        cand_summary = (
            f"- flow_id: {candidate.flow_id}\n"
            f"- source: {candidate.source_qn}\n"
            f"- sink: {candidate.sink_qn}\n"
            f"- sink_type: {candidate.sink_type}\n"
            f"- hops: {candidate.hop_count}\n"
            f"- path: {' → '.join(q.rsplit('::', 1)[-1] for q in candidate.path_qns)}"
        )

        user_prompt = build_flow_prompt(
            candidate_summary=cand_summary,
            path_blocks=self._path_source_blocks(store, candidate.path_qns),
            history_block=format_history_block(history),
            knowledge_block=knowledge_block,
            gap_block=self._gap_block(candidate),
        )

        raw, _ = await self.llm.chat_json(FLOW_SYSTEM_PROMPT, user_prompt)
        parsed = _extract_json(raw)
        record = self._to_record(candidate, parsed)

        hypothesis = str(parsed.get("hypothesis", "")).strip()
        if hypothesis:
            self.memory.add_hypothesis(
                hypothesis,
                flow_ids=[candidate.flow_id],
                tags=record.tags,
            )

        self.memory.upsert(record)
        return record

    @staticmethod
    def _gap_block(candidate: FlowCandidate) -> str:
        if not candidate.gap_reasons:
            return ""
        lines = [f"## Graph gap signals (score={candidate.gap_score})"]
        for r in candidate.gap_reasons:
            lines.append(f"- {r}")
        return "\n".join(lines)

    def _to_record(self, candidate: FlowCandidate, parsed: dict[str, Any]) -> FlowRecord:
        verdict = str(parsed.get("verdict", "unknown")).lower()
        if verdict not in ("vulnerable", "sanitized", "inconclusive", "unknown"):
            verdict = "unknown"

        severity = str(parsed.get("severity", "medium")).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        try:
            confidence = float(parsed.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        reach = str(parsed.get("reachability", "unknown")).lower()
        if reach not in ("confirmed", "likely", "rejected", "unknown"):
            reach = "unknown"

        cwe = parsed.get("cwe_id")
        evidence = dict(parsed.get("evidence") or {})
        if cwe:
            evidence["cwe_id"] = cwe

        return FlowRecord(
            flow_id=candidate.flow_id,
            source_qn=candidate.source_qn,
            sink_qn=candidate.sink_qn,
            path_qns=candidate.path_qns,
            sink_type=candidate.sink_type,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            reachability=reach,
            sanitizers=list(parsed.get("sanitizers") or []),
            evidence=evidence,
            tags=list(parsed.get("tags") or []),
            open_questions=list(parsed.get("open_questions") or []),
            communities=candidate.communities,
            summary=str(parsed.get("summary", "")),
            analyzed_at=datetime.now().isoformat(),
            model=self.llm.config.model_name,
        )
