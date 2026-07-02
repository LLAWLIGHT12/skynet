"""单个 chunk 的 LLM 安全分析（含三层知识）。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from skynet.analyze.models import ChunkAnalysisResult, SecurityFinding, VALID_SEVERITIES
from skynet.analyze.prompts import (
    SYSTEM_PROMPT,
    REFINE_SYSTEM_PROMPT,
    build_user_prompt,
)
from skynet.config import SkynetConfig, get_config
from skynet.graph.chunks import CodeChunk
from skynet.graph.context import StructuralContext
from skynet.knowledge.context import KnowledgeContext
from skynet.knowledge.orchestrator import KnowledgeOrchestrator
from skynet.llm.client import LLMClient
from skynet.taint.catalog import TaintCatalog
from skynet.tools.web_search import WebSearchTool

try:
    from skynet.knowledge.frameworks import FrameworkKnowledgeBase
    _FRAMEWORK_KB: FrameworkKnowledgeBase | None = None
    def _get_framework_kb() -> FrameworkKnowledgeBase:
        global _FRAMEWORK_KB
        if _FRAMEWORK_KB is None:
            _FRAMEWORK_KB = FrameworkKnowledgeBase()
        return _FRAMEWORK_KB
    _FRAMEWORK_AVAILABLE = True
except ImportError:
    _FRAMEWORK_AVAILABLE = False

try:
    from skynet.knowledge.external.vuln_knowledge import VulnPatternRetriever
    _VULN_RETRIEVER: VulnPatternRetriever | None = None
    def _get_vuln_retriever() -> VulnPatternRetriever:
        global _VULN_RETRIEVER
        if _VULN_RETRIEVER is None:
            _VULN_RETRIEVER = VulnPatternRetriever()
        return _VULN_RETRIEVER
    _VULN_AVAILABLE = True
except ImportError:
    _VULN_AVAILABLE = False


def _truncate_source(source: str, max_lines: int) -> str:
    lines = source.splitlines()
    if len(lines) <= max_lines:
        return source
    head = lines[:max_lines]
    return "\n".join(head) + f"\n\n# ... truncated ({len(lines) - max_lines} more lines)"


def _parse_response(raw: dict[str, Any]) -> tuple[list[SecurityFinding], str, bool, list[str], str]:
    findings_raw = raw.get("findings") or []
    if not isinstance(findings_raw, list):
        findings_raw = []

    findings: list[SecurityFinding] = []
    for item in findings_raw:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "medium")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"

        try:
            confidence = float(item.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))

        line_hint = item.get("line_hint")
        if line_hint is not None:
            try:
                line_hint = int(line_hint)
            except (TypeError, ValueError):
                line_hint = None

        cwe = item.get("cwe_id")
        if cwe and not str(cwe).upper().startswith("CWE"):
            cwe = f"CWE-{cwe}"

        findings.append(
            SecurityFinding(
                title=str(item.get("title", "Security issue")),
                severity=severity,
                vulnerability_type=str(item.get("vulnerability_type", "Unknown")),
                description=str(item.get("description", "")),
                confidence=confidence,
                cwe_id=str(cwe) if cwe else None,
                recommendation=str(item.get("recommendation", "")),
                line_hint=line_hint,
            )
        )

    summary = str(raw.get("summary", ""))
    needs_search = bool(raw.get("needs_web_search", False))
    queries = raw.get("search_queries") or []
    if not isinstance(queries, list):
        queries = []
    queries = [str(q) for q in queries if q]
    uncertainty = str(raw.get("uncertainty_reason", ""))
    return findings, summary, needs_search, queries, uncertainty


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return json.loads(match.group())
    raise ValueError("无法从 LLM 响应中解析 JSON")


def _should_web_search(
    findings: list[SecurityFinding],
    needs_search: bool,
    queries: list[str],
    threshold: float,
) -> bool:
    if needs_search and queries:
        return True
    if findings and min(f.confidence for f in findings) < threshold:
        return True
    return False


def _build_search_queries(
    chunk: CodeChunk,
    findings: list[SecurityFinding],
    queries: list[str],
    uncertainty: str,
) -> list[str]:
    if queries:
        return queries[:3]
    if findings:
        f = findings[0]
        return [f"{f.vulnerability_type} {chunk.language} security CWE"]
    if uncertainty:
        return [f"{chunk.name} security vulnerability {uncertainty[:80]}"]
    return [f"{chunk.qualified_name} security audit"]


class ChunkAnalyzer:
    """对单个代码 chunk 执行安全分析（外部 + 内部知识 + 可选 Web 搜索）。"""

    def __init__(
        self,
        llm: Optional[LLMClient] = None,
        config: Optional[SkynetConfig] = None,
        repo_root: Optional[str | Path] = None,
    ) -> None:
        self.config = config or get_config()
        self.llm = llm or LLMClient(skynet_config=self.config)
        self.max_lines = self.config.analyze.max_source_lines
        self.repo_root = Path(repo_root) if repo_root else None
        self._knowledge: Optional[KnowledgeOrchestrator] = None
        self._web: Optional[WebSearchTool] = None
        self._taint_catalog: Optional[TaintCatalog] = None
        self._framework_kb = None
        self._vuln_retriever = None
        if _FRAMEWORK_AVAILABLE and self.config.framework_knowledge.enabled:
            self._framework_kb = _get_framework_kb()
        if _VULN_AVAILABLE and self.config.vuln_pattern.enabled:
            self._vuln_retriever = _get_vuln_retriever()

    def _get_taint_catalog(self) -> Optional[TaintCatalog]:
        if not self.config.taint.enabled:
            return None
        if self._taint_catalog is None:
            kdir = self.config.taint.knowledge_dir or None
            self._taint_catalog = TaintCatalog(kdir)
        return self._taint_catalog

    def _get_knowledge(self) -> Optional[KnowledgeOrchestrator]:
        if not self.repo_root:
            return None
        if self._knowledge is None:
            self._knowledge = KnowledgeOrchestrator(self.repo_root, self.config)
        return self._knowledge

    def _get_web(self) -> WebSearchTool:
        if self._web is None:
            wcfg = self.config.web_search
            import os
            self._web = WebSearchTool(
                provider=wcfg.provider,
                api_key=os.environ.get(wcfg.api_key_env, ""),
                max_results=wcfg.max_results,
            )
        return self._web

    async def analyze(
        self,
        chunk: CodeChunk,
        structural_ctx: StructuralContext,
    ) -> ChunkAnalysisResult:
        base = ChunkAnalysisResult(
            qualified_name=chunk.qualified_name,
            kind=chunk.kind,
            file_path=chunk.file_path,
            line_start=chunk.line_start,
            line_end=chunk.line_end,
        )

        source = _truncate_source(chunk.source, self.max_lines)
        knowledge_ctx = KnowledgeContext()

        orchestrator = self._get_knowledge()
        if orchestrator and (
            self.config.knowledge.enable_external or self.config.knowledge.enable_internal
        ):
            knowledge_ctx = orchestrator.gather(chunk, structural_ctx)

        # ── 注入框架知识 + 漏洞模式知识 ──
        extra_knowledge = self._gather_deepaudit_knowledge(chunk, source)
        if extra_knowledge:
            knowledge_block = knowledge_ctx.to_prompt_block() + "\n\n" + extra_knowledge
        else:
            knowledge_block = knowledge_ctx.to_prompt_block()

        user_prompt = build_user_prompt(
            qualified_name=chunk.qualified_name,
            kind=chunk.kind,
            language=chunk.language,
            structural_context=structural_ctx.to_prompt_block(),
            source_code=source,
            knowledge_block=knowledge_block,
        )

        try:
            raw_text, usage1 = await self.llm.chat_json(SYSTEM_PROMPT, user_prompt)
            parsed = _extract_json(raw_text)
            findings, summary, needs_search, queries, uncertainty = _parse_response(parsed)

            wcfg = self.config.web_search
            threshold = self.config.analyze.confidence_search_threshold
            if (
                wcfg.enabled
                and _should_web_search(findings, needs_search, queries, threshold)
            ):
                search_queries = _build_search_queries(chunk, findings, queries, uncertainty)
                logger.info("Web 搜索: {}", search_queries)
                web_results = await self._get_web().search_many(
                    search_queries[: wcfg.max_queries]
                )
                if web_results:
                    knowledge_ctx.web = web_results
                    web_block = KnowledgeContext(web=web_results).to_prompt_block()
                    refine_prompt = build_user_prompt(
                        qualified_name=chunk.qualified_name,
                        kind=chunk.kind,
                        language=chunk.language,
                        structural_context=structural_ctx.to_prompt_block(),
                        source_code=source,
                        knowledge_block=knowledge_ctx.to_prompt_block(),
                        web_block=web_block,
                    )
                    raw_text2, usage2 = await self.llm.chat_json(REFINE_SYSTEM_PROMPT, refine_prompt)
                    parsed = _extract_json(raw_text2)
                    findings, summary, _, _, _ = _parse_response(parsed)
                    base.web_search_used = True
                    base.raw_response = raw_text2
                    base.usage = usage2
                else:
                    base.usage = usage1
                    base.raw_response = raw_text
            else:
                base.usage = usage1
                base.raw_response = raw_text

            base.findings = findings
            base.summary = summary

            catalog = self._get_taint_catalog()
            if catalog:
                base.sink_types = catalog.chunk_sink_types(chunk)
                base.needs_flow_trace = bool(base.sink_types) or any(
                    f.severity in ("critical", "high") and f.confidence < 0.85
                    for f in findings
                )

            base.knowledge_used = {
                "external_count": len(knowledge_ctx.external),
                "internal_count": len(knowledge_ctx.internal),
                "signals": [s.get("signal_id") for s in knowledge_ctx.code_signals],
                "web_count": len(knowledge_ctx.web),
            }

            if orchestrator:
                orchestrator.persist(
                    chunk,
                    structural_ctx,
                    [f.to_dict() for f in findings],
                    summary,
                )

            logger.debug(
                "{} -> {} findings (ext={} int={} web={})",
                chunk.qualified_name,
                len(findings),
                len(knowledge_ctx.external),
                len(knowledge_ctx.internal),
                len(knowledge_ctx.web),
            )
        except Exception as e:
            logger.warning("分析失败 {}: {}", chunk.qualified_name, e)
            base.error = str(e)

        return base

    def _gather_deepaudit_knowledge(
        self, chunk: CodeChunk, source: str,
    ) -> str:
        """收集框架安全知识 + 漏洞模式知识，返回 prompt 文本块。"""
        parts: list[str] = []

        # 框架知识
        if self._framework_kb is not None:
            try:
                detected = self._framework_kb.detect(source, chunk.language)
                for fw_name in detected:
                    fw_knowledge = self._framework_kb.get_knowledge(fw_name)
                    if fw_knowledge:
                        prompt_ctx = self._framework_kb.get_prompt_context(fw_name)
                        if prompt_ctx:
                            parts.append(prompt_ctx)
            except Exception as e:
                logger.debug("框架知识获取失败: {}", e)

        # 漏洞模式知识（根据 chunk 的 sink 类型）
        if self._vuln_retriever is not None:
            try:
                catalog = self._get_taint_catalog()
                if catalog:
                    sink_types = catalog.chunk_sink_types(chunk)
                    if sink_types:
                        vuln_ctx = self._vuln_retriever.get_context_for_prompt(
                            sink_types=list(sink_types)[:5],
                        )
                        if vuln_ctx:
                            parts.append(vuln_ctx)
            except Exception as e:
                logger.debug("漏洞模式知识获取失败: {}", e)

        return "\n\n".join(parts)
