"""Bounded mini-Agent：图断点补边（Tool Use + multilspy LSP）。"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from code_review_graph.graph import GraphStore

from skynet.config import SkynetConfig, get_config
from skynet.knowledge.external.retriever import ExternalKnowledgeRetriever
from skynet.knowledge.flow_memory import FlowMemoryStore
from skynet.llm.client import LLMClient
from skynet.taint.models import FlowCandidate, FlowRecord
from skynet.taint.prompts import format_history_block
from skynet.taint.verifier import FlowVerifier
from skynet.tools.agent_tools import AgentToolExecutor, format_tool_specs_for_prompt
from skynet.tools.lsp_tools import LSPToolkit
from skynet.graph.overrides import persist_agent_resolved_path


def build_agent_system_prompt(lsp_available: bool) -> str:
    tools = format_tool_specs_for_prompt()
    lsp_note = (
        "LSP 已就绪，遇到 bare_call / dynamic / path_break 请优先 lsp_definition 或 lsp_references。"
        if lsp_available
        else "LSP 不可用，请使用 read_node。"
    )
    return f"""你是代码安全流分析 Agent。图分析发现调用链可能存在断边，需补全 source→sink 数据流。

{tools}

{lsp_note}

规则：
- 最多使用给定步数；用 tool observation 驱动下一步
- resolved_path 给出推断的完整调用链（qualified_name 或 file:line）
- 不要臆测库内部实现；外部库标记 external
- conclude 时必须给出 verdict 和 summary"""


class AgentFlowResolver:
    """GapScore 超阈值时，用 Tool Use + LSP 补边并写 FlowRecord。"""

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
        self.max_steps = self.config.taint.agent_max_steps

    async def resolve(
        self,
        store: GraphStore,
        candidate: FlowCandidate,
        lsp: Optional[LSPToolkit] = None,
    ) -> FlowRecord:
        logger.info(
            "Agent 补边 [{}] gap={} lsp={} reasons={}",
            candidate.flow_id,
            candidate.gap_score,
            lsp.available if lsp else False,
            candidate.gap_reasons[:3],
        )

        tools = AgentToolExecutor(self.repo_root, store, lsp, self.config)
        system_prompt = build_agent_system_prompt(bool(lsp and lsp.available))

        history = self.memory.get_context_for_flow(candidate)
        knowledge = self.external.retrieve_by_text(
            "\n".join(candidate.path_qns),
            max_items=5,
        )

        gap_block = "## Graph gap signals\n" + "\n".join(
            f"- {r}" for r in candidate.gap_reasons
        )
        history_block = format_history_block(history)

        # 预读路径 + 对 bare_call 给出 LSP 提示
        for qn in candidate.path_qns:
            await tools.execute({"action": "read_node", "qualified_name": qn})

        lsp_hints = self._gap_lsp_hints(tools, candidate)
        if lsp_hints:
            tools._observations.append(f"### Gap LSP hints\n{lsp_hints}")

        conclusion: Optional[dict[str, Any]] = None

        for step in range(self.max_steps):
            user_prompt = self._build_step_prompt(
                candidate,
                gap_block,
                history_block,
                tools.observations,
                step,
                knowledge,
            )
            raw, _ = await self.llm.chat_json(system_prompt, user_prompt)
            parsed = self._extract_json(raw)

            obs, is_conclusion = await tools.execute(parsed)
            if is_conclusion:
                if parsed.get("summary") and parsed.get("verdict") not in (None, "", "unknown"):
                    conclusion = parsed
                    break
                conclusion = await self._force_conclude(
                    candidate, gap_block, history_block, tools.observations, knowledge,
                )
                break

            if step == self.max_steps - 1:
                conclusion = await self._force_conclude(
                    candidate, gap_block, history_block, tools.observations, knowledge,
                )
                break

        if conclusion is None:
            conclusion = await self._force_conclude(
                candidate, gap_block, history_block, tools.observations, knowledge,
            )

        conclusion = self._normalize_conclusion(conclusion, candidate)

        record = self._to_record(candidate, conclusion)
        record.evidence["agent_used"] = True
        record.evidence["lsp_used"] = bool(lsp and lsp.available)
        record.evidence["gap_score"] = candidate.gap_score
        record.evidence["gap_reasons"] = candidate.gap_reasons
        record.evidence["tool_steps"] = len(tools.observations)
        record.tags = list(set(record.tags + ["agent_resolved"]))
        if conclusion.get("resolved_path"):
            record.evidence["resolved_path"] = conclusion["resolved_path"]
            added = persist_agent_resolved_path(
                store,
                self.repo_root,
                conclusion["resolved_path"],
                flow_id=candidate.flow_id,
                graph_dir_name=self.config.graph.dir_name,
            )
            if added:
                record.evidence["graph_overrides_added"] = added
                logger.info("graph_overrides: 写入 {} 条 CALLS 边", added)

        self.memory.upsert(record)
        return record

    async def _force_conclude(
        self,
        candidate: FlowCandidate,
        gap_block: str,
        history_block: str,
        observations: list[str],
        knowledge: list[dict],
    ) -> dict[str, Any]:
        """最后一步：仅允许 conclude。"""
        prompt = "\n\n".join([
            "## Final step — you MUST conclude now",
            f"Source: {candidate.source_qn}",
            f"Sink: {candidate.sink_qn} ({candidate.sink_type})",
            gap_block,
            history_block,
            "## Tool observations",
            "\n\n".join(observations[-8:]) if observations else "(none)",
            '返回 JSON: {"action":"conclude","verdict":"...","summary":"...","confidence":0.0-1.0,...}',
        ])
        try:
            raw, _ = await self.llm.chat_json(
                "你是安全流分析 Agent。根据已有证据给出最终 conclude JSON。",
                prompt,
            )
            parsed = self._extract_json(raw)
            if parsed.get("verdict") or parsed.get("action") == "conclude":
                if not parsed.get("summary"):
                    parsed["summary"] = f"流 {candidate.source_qn} → {candidate.sink_qn} 分析完成"
                return parsed
        except Exception as e:
            logger.warning("force_conclude 失败: {}", e)
        return {
            "verdict": "inconclusive",
            "summary": "Agent 未能基于证据给出明确结论",
            "confidence": 0.4,
            "reachability": "unknown",
        }

    @staticmethod
    def _normalize_conclusion(conclusion: dict[str, Any], candidate: FlowCandidate) -> dict[str, Any]:
        valid_verdicts = {"vulnerable", "sanitized", "inconclusive", "unknown"}
        verdict = str(conclusion.get("verdict", "inconclusive")).lower()
        if verdict not in valid_verdicts:
            verdict = "inconclusive"
        conclusion["verdict"] = verdict
        if not str(conclusion.get("summary", "")).strip():
            src = candidate.source_qn.rsplit("::", 1)[-1]
            sink = candidate.sink_qn.rsplit("::", 1)[-1]
            conclusion["summary"] = f"{src} → {sink}: {verdict} ({candidate.sink_type})"
        return conclusion

    def _gap_lsp_hints(
        self,
        tools: AgentToolExecutor,
        candidate: FlowCandidate,
    ) -> str:
        hints: list[str] = []
        for reason in candidate.gap_reasons:
            if reason.startswith("bare_call:"):
                part = reason.split(":", 1)[-1]
                if "->" in part:
                    src_name = part.split("->")[0]
                    for qn in candidate.path_qns:
                        if qn.rsplit("::", 1)[-1] == src_name or src_name in qn:
                            pos = tools.resolve_position_from_node(qn)
                            if pos:
                                hints.append(
                                    f"建议 lsp_definition file={pos['file_path']} "
                                    f"line={pos['line']} symbol={pos['symbol']}"
                                )
            if reason.startswith("dynamic:"):
                tag, _, at = reason.partition("@")
                for qn in candidate.path_qns:
                    if qn.rsplit("::", 1)[-1] == at:
                        pos = tools.resolve_position_from_node(qn)
                        if pos:
                            hints.append(
                                f"建议 lsp_definition 于 dynamic site {tag}: "
                                f"{pos['file_path']}:{pos['line']}"
                            )
        return "\n".join(hints)

    def _build_step_prompt(
        self,
        candidate: FlowCandidate,
        gap_block: str,
        history_block: str,
        observations: list[str],
        step: int,
        knowledge: list[dict],
    ) -> str:
        klines = ""
        if knowledge:
            klines = "## Knowledge\n" + "\n".join(
                f"- {k.get('id', '')} {k.get('name', '')}" for k in knowledge
            )
        return "\n\n".join([
            f"## Step {step + 1}/{self.max_steps}",
            f"Source: {candidate.source_qn}",
            f"Sink: {candidate.sink_qn} ({candidate.sink_type})",
            f"Graph path: {' → '.join(candidate.path_qns)}",
            gap_block,
            history_block,
            klines,
            "## Tool observations",
            "\n\n".join(observations) if observations else "(none yet)",
            "返回 JSON（含 action 字段）。若已足够，请 action=conclude。",
        ])

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            return json.loads(match.group())
        return {}

    def _to_record(self, candidate: FlowCandidate, parsed: dict[str, Any]) -> FlowRecord:
        verifier = FlowVerifier(self.repo_root, self.config, self.llm)
        record = verifier._to_record(candidate, parsed)
        record.analyzed_at = datetime.now().isoformat()
        record.model = self.llm.config.model_name
        return record
