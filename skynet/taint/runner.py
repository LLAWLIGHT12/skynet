"""流污点追踪调度。"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from loguru import logger

from skynet.analyze.composite import CompositeAnalyzer
from skynet.config import SkynetConfig, get_config
from skynet.graph import GraphBuilder
from skynet.taint.agent_resolver import AgentFlowResolver
from skynet.taint.catalog import TaintCatalog
from skynet.taint.gap_detector import GraphGapDetector
from skynet.taint.models import FlowCandidate, FlowRecord, FlowTraceSummary
from skynet.taint.paths import enumerate_flow_candidates
from skynet.taint.verifier import FlowVerifier
from skynet.tools.lsp_tools import LSPToolkit

if TYPE_CHECKING:
    from skynet.state import StateDB


class TraceRunner:
    """枚举候选流 → Gap 检测 → 验证 / Agent+LSP 补边 → 组合分析。

    可选 state_db 参数：传入 StateDB 实例后会自动记录流追踪结果。
    为 None 时行为与之前版本完全一致。
    """

    def __init__(
        self,
        repo_root: str | Path,
        config: Optional[SkynetConfig] = None,
        verifier: Optional[FlowVerifier] = None,
        agent: Optional[AgentFlowResolver] = None,
        state_db: "StateDB | None" = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.config = config or get_config()
        self.builder = GraphBuilder(self.repo_root, self.config)
        self.verifier = verifier or FlowVerifier(self.repo_root, self.config)
        self.agent = agent or AgentFlowResolver(self.repo_root, self.config)
        self.gap_detector = GraphGapDetector(self.repo_root, self.config.taint)
        self.composite = CompositeAnalyzer(self.repo_root, self.config)
        self.state_db = state_db
        self._agent_budget = 0
        self._lsp: Optional[LSPToolkit] = None

    async def run(
        self,
        run_composite: bool = True,
        save: bool = True,
        sink_filter: Optional[list[str]] = None,
        chunk_findings: Optional[list[dict]] = None,
        run_id: str | None = None,
    ) -> FlowTraceSummary:
        tcfg = self.config.taint
        use_lsp = tcfg.agent_fallback and self.config.lsp.enabled

        if use_lsp:
            async with LSPToolkit(self.repo_root, self.config.lsp) as lsp:
                self._lsp = lsp
                return await self._run_trace(
                    run_composite, save, sink_filter, chunk_findings, run_id,
                )
        return await self._run_trace(run_composite, save, sink_filter, chunk_findings, run_id)

    async def _run_trace(
        self,
        run_composite: bool,
        save: bool,
        sink_filter: Optional[list[str]],
        chunk_findings: Optional[list[dict]] = None,
        run_id: str | None = None,
    ) -> FlowTraceSummary:
        tcfg = self.config.taint
        summary = FlowTraceSummary(repo_root=str(self.repo_root))
        self._agent_budget = tcfg.max_agent_per_run

        store = self.builder.open_store()
        with store:
            catalog = TaintCatalog(tcfg.knowledge_dir or None).build_from_store(
                store,
                self.repo_root,
                skip_tests=not self.config.analyze.include_tests,
            )
            logger.info(
                "污点目录: {} sources, {} sinks",
                len(catalog.sources),
                len(catalog.sinks),
            )

            candidates = enumerate_flow_candidates(
                store,
                catalog,
                self.repo_root,
                max_hops=tcfg.max_hops,
                max_paths_per_sink=tcfg.max_paths_per_sink,
                max_candidates=tcfg.max_flow_traces,
                min_criticality=tcfg.min_criticality,
                gap_detector=self.gap_detector,
            )

            if sink_filter:
                allowed = set(sink_filter)
                candidates = [c for c in candidates if c.sink_qn in allowed]

            summary.candidates = len(candidates)
            summary.high_gap_candidates = sum(1 for c in candidates if c.needs_agent)

            if not candidates:
                logger.info("未发现候选流")
                if run_composite and tcfg.enable_composite:
                    summary.composite_findings = await self.composite.run(
                        store, chunk_findings=chunk_findings,
                    )
                if save:
                    summary.output_path = str(self._save(summary))
                return summary

            if summary.high_gap_candidates:
                logger.info(
                    "GraphGap: {} 条候选超阈值 (threshold={})",
                    summary.high_gap_candidates,
                    tcfg.gap_agent_threshold,
                )
            if self._lsp and self._lsp.available:
                logger.info("LSP 就绪: language={}", self._lsp.language)

            sem = asyncio.Semaphore(self.config.analyze.max_concurrency)

            async def _one(cand: FlowCandidate) -> None:
                async with sem:
                    try:
                        if tcfg.cache_flow_results:
                            cached = self.verifier.memory.should_skip(cand)
                            if cached:
                                summary.skipped_cached += 1
                                summary.records.append(cached)
                                if cached.verdict == "vulnerable" and not cached.false_positive:
                                    summary.vulnerable += 1
                                # StateDB: 从缓存恢复的 trace
                                if self.state_db and run_id:
                                    self._record_trace_to_statedb(
                                        run_id, cached, cand.flow_id,
                                    )
                                return

                        record = await self._analyze_one(store, cand, tcfg)
                        if record.evidence.get("agent_used"):
                            summary.agent_invoked += 1
                        else:
                            summary.traced += 1
                        summary.records.append(record)
                        if record.verdict == "vulnerable":
                            summary.vulnerable += 1
                        # StateDB: 记录 trace 结果
                        if self.state_db and run_id:
                            self._record_trace_to_statedb(
                                run_id, record, cand.flow_id,
                            )
                    except Exception as e:
                        msg = f"{cand.flow_id}: {e}"
                        logger.warning("流分析失败: {}", msg)
                        summary.errors.append(msg)

            await asyncio.gather(*[_one(c) for c in candidates])

            if run_composite and tcfg.enable_composite:
                summary.composite_findings = await self.composite.run(store)

        if save:
            summary.output_path = str(self._save(summary))

        # ── StateDB: 记录产物 ──
        if self.state_db and run_id and summary.output_path:
            self.state_db.add_artifact(
                run_id, "trace", None,
                kind="flow_trace", path=summary.output_path,
            )

        logger.info(
            "流追踪完成: {} 候选, {} 分析, {} 缓存, {} Agent, {} 漏洞流",
            summary.candidates,
            summary.traced,
            summary.skipped_cached,
            summary.agent_invoked,
            summary.vulnerable,
        )
        return summary

    async def _analyze_one(
        self,
        store,
        cand: FlowCandidate,
        tcfg,
    ) -> FlowRecord:
        if tcfg.cache_flow_results:
            cached = self.verifier.memory.should_skip(cand)
            if cached:
                return cached

        use_agent = (
            tcfg.agent_fallback
            and cand.needs_agent
            and self._agent_budget > 0
        )

        if use_agent:
            self._agent_budget -= 1
            return await self.agent.resolve(store, cand, lsp=self._lsp)

        record = await self.verifier.verify(store, cand)

        if (
            tcfg.agent_fallback
            and tcfg.agent_after_inconclusive
            and self._agent_budget > 0
            and record.verdict in ("inconclusive", "unknown")
        ):
            score, reasons, needs = self.gap_detector.apply_flow_record_gaps(
                record.verdict,
                record.reachability,
                record.confidence,
                record.open_questions,
                cand.gap_score,
                cand.gap_reasons,
            )
            if needs and score >= tcfg.gap_agent_threshold:
                cand.gap_score = score
                cand.gap_reasons = reasons
                cand.needs_agent = True
                self._agent_budget -= 1
                record = await self.agent.resolve(store, cand, lsp=self._lsp)

        return record

    def _record_trace_to_statedb(
        self,
        run_id: str,
        record: FlowRecord,
        flow_id: str,
    ) -> None:
        """将 FlowRecord 转写到 StateDB。"""
        if self.state_db is None:
            return
        payload = {
            "flow_id": flow_id,
            "source_qn": record.source_qn,
            "sink_qn": record.sink_qn,
            "verdict": record.verdict,
            "reachable": record.verdict == "vulnerable" and not record.false_positive,
            "confidence": record.confidence,
            "severity": record.severity,
            "rationale": record.summary or "",
            "open_questions": record.open_questions,
            "tags": record.tags,
        }
        # 每个 flow 作为一个 finding 记录
        fid = f"flow_{flow_id}"
        finding_data = {
            "finding_id": fid,
            "file": record.sink_qn.rsplit("::", 1)[0] if "::" in record.sink_qn else "",
            "line_start": 0,
            "line_end": 0,
            "vuln_class": ",".join(record.tags) if record.tags else "taint_flow",
            "severity": record.severity or "medium",
            "title": f"{record.source_qn.rsplit('::',1)[-1] if '::' in record.source_qn else record.source_qn} → {record.sink_qn.rsplit('::',1)[-1] if '::' in record.sink_qn else record.sink_qn}",
            "description": record.summary or "",
            "evidence": "",
            "confidence": record.confidence,
        }
        task_id = self.state_db.add_task(
            run_id,
            {
                "task_id": f"trace_{flow_id}",
                "source": "trace",
                "attack_class": "taint_flow",
                "scope_hint": record.sink_qn,
                "target_files": [finding_data["file"]] if finding_data["file"] else [],
                "rationale": record.summary or "taint flow trace",
                "priority": 2,
                "chunk_qn": record.sink_qn,
            },
        )
        self.state_db.update_task_status(task_id, "done")
        self.state_db.add_finding(run_id, task_id, finding_data, finding_type="flow")
        self.state_db.add_trace(fid, payload, flow_id=flow_id)

    def _save(self, summary: FlowTraceSummary) -> Path:
        out_dir = Path(self.config.analyze.output_dir)
        if not out_dir.is_absolute():
            out_dir = Path.cwd() / out_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = self.repo_root.name or "project"
        path = out_dir / f"flow_trace_{name}_{ts}.json"
        payload = {
            "generated_at": datetime.now().isoformat(),
            **summary.to_dict(),
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("流追踪报告: {}", path)
        return path
