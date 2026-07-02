"""批量 chunk 分析调度。"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

from loguru import logger

from skynet.analyze.chunk_analyzer import ChunkAnalyzer
from skynet.analyze.models import ChunkAnalysisResult
from skynet.config import SkynetConfig, get_config
from skynet.graph import GraphBuilder, get_structural_context, iter_chunks
from skynet.graph.chunks import CodeChunk

try:
    from skynet.tools.external_scanners import (
        ExternalScanner,
        ExternalScannerConfig as ScannerConfig,
    )
    _SCANNER_AVAILABLE = True
except ImportError:
    _SCANNER_AVAILABLE = False

if TYPE_CHECKING:
    from skynet.state import StateDB


@dataclass
class RunSummary:
    repo_root: Path
    run_id: Optional[str] = None
    total_chunks: int = 0
    analyzed: int = 0
    with_findings: int = 0
    total_findings: int = 0
    errors: int = 0
    results: list[ChunkAnalysisResult] = field(default_factory=list)
    output_path: Optional[Path] = None
    model: str = ""
    flow_trace: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "repo_root": str(self.repo_root),
            "run_id": self.run_id,
            "total_chunks": self.total_chunks,
            "analyzed": self.analyzed,
            "with_findings": self.with_findings,
            "total_findings": self.total_findings,
            "errors": self.errors,
            "model": self.model,
            "output_path": str(self.output_path) if self.output_path else None,
            "results": [r.to_dict() for r in self.results],
        }
        if self.flow_trace:
            data["flow_trace"] = self.flow_trace
        return data


class AnalysisRunner:
    """遍历图谱 chunk 并并发调用 LLM 分析。

    可选 state_db 参数：传入 StateDB 实例后会自动记录运行状态、
    任务进度、发现结果和 LLM 成本，支持 resume。
    为 None 时行为与之前版本完全一致。
    """

    def __init__(
        self,
        repo_root: str | Path,
        config: Optional[SkynetConfig] = None,
        analyzer: Optional[ChunkAnalyzer] = None,
        state_db: "StateDB | None" = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.config = config or get_config()
        self.builder = GraphBuilder(self.repo_root, self.config)
        self.analyzer = analyzer or ChunkAnalyzer(
            config=self.config,
            repo_root=self.repo_root,
        )
        self.state_db = state_db
        self._external_scanner = None
        if _SCANNER_AVAILABLE and self.config.external_scanner.enabled:
            scanner_cfg = ScannerConfig(
                enabled=self.config.external_scanner.enabled,
                tools=self.config.external_scanner.tools,
                timeout=self.config.external_scanner.timeout,
                semgrep_config=self.config.external_scanner.semgrep_config,
            )
            self._external_scanner = ExternalScanner(scanner_cfg)

    async def run(
        self,
        limit: int = 0,
        offset: int = 0,
        index: Optional[int] = None,
        save: bool = True,
        trace_flows: bool = False,
        composite: bool = False,
        use_priority: bool = True,
        write_module_memory: bool = True,
        run_id: str | None = None,
    ) -> RunSummary:
        store = self.builder.open_store()
        summary = RunSummary(
            repo_root=self.repo_root,
            model=self.analyzer.llm.config.model_name,
        )

        # ── StateDB: run 生命周期 ──
        _rid: str | None = run_id
        if self.state_db:
            _rid = self.state_db.create_run(str(self.repo_root), run_id=_rid)
        if _rid:
            summary.run_id = _rid
            logger.info("StateDB run: {}", _rid)

        try:
            with store:
                chunks = list(
                    iter_chunks(
                        store,
                        self.repo_root,
                        skip_tests=not self.config.analyze.include_tests,
                        config=self.config,
                    )
                )

                # ── StateDB: resume 跳过已完成的 chunk ──
                completed_chunks: set[str] = set()
                if self.state_db and _rid:
                    completed_chunks = self.state_db.get_completed_chunks(_rid)
                if completed_chunks:
                    before = len(chunks)
                    chunks = [c for c in chunks if c.qualified_name not in completed_chunks]
                    logger.info("StateDB resume: 跳过 {} 个已完成 chunk，剩余 {}",
                                before - len(chunks), len(chunks))

                if index is not None:
                    if index < 0 or index >= len(chunks):
                        raise IndexError(f"chunk index 越界: {index} (共 {len(chunks)} 个)")
                    chunks = [chunks[index]]
                else:
                    if use_priority:
                        from skynet.analyze.priority import prioritize_chunks, chunk_criticality

                        chunks = prioritize_chunks(store, chunks)
                        preview = chunks[: min(limit or 5, 10)]
                        for c in preview:
                            logger.info(
                                "priority chunk crit={:.2f} {}",
                                chunk_criticality(store, c),
                                c.qualified_name.rsplit("::", 1)[-1],
                            )
                    if offset:
                        chunks = chunks[offset:]
                    if limit > 0:
                        chunks = chunks[:limit]

                summary.total_chunks = len(chunks)
                sem = asyncio.Semaphore(self.config.analyze.max_concurrency)

                async def _one(chunk: CodeChunk) -> ChunkAnalysisResult:
                    async with sem:
                        task_id: str | None = None
                        if self.state_db and _rid:
                            task_id = self.state_db.add_task(
                                _rid,
                                {
                                    "task_id": f"analyze_{hashlib.sha1(chunk.qualified_name.encode('utf-8')).hexdigest()[:12]}",
                                    "source": "analyze",
                                    "attack_class": "chunk_analysis",
                                    "scope_hint": chunk.qualified_name,
                                    "target_files": [chunk.file_path],
                                    "rationale": "skynet chunk analysis",
                                    "priority": 3,
                                    "chunk_qn": chunk.qualified_name,
                                },
                            )
                            self.state_db.update_task_status(task_id, "running")

                        ctx = get_structural_context(store, chunk, self.config)
                        import_time = asyncio.get_event_loop().time()
                        result = await self.analyzer.analyze(chunk, ctx)
                        elapsed_ms = int((asyncio.get_event_loop().time() - import_time) * 1000)

                        if self.state_db and _rid and task_id:
                            status = "failed" if result.error else "done"
                            self.state_db.update_task_status(task_id, status)
                            # 记录发现
                            for finding in result.findings:
                                fdict = finding.to_dict()
                                fdict.setdefault("qualified_name", result.qualified_name)
                                fdict.setdefault("file", result.file_path)
                                self.state_db.add_finding(
                                    _rid, task_id, fdict, finding_type="chunk",
                                )
                            # 记录 LLM 成本（如果能从 analyzer 获取）
                            usage = getattr(result, "usage", None) or {}
                            if usage:
                                self.state_db.record_cost(
                                    _rid, "analyze", chunk.qualified_name,
                                    usage=usage, num_turns=1, duration_ms=elapsed_ms,
                                )

                        return result

                tasks = [_one(c) for c in chunks]
                results = await asyncio.gather(*tasks)
                summary.results = list(results)

                if write_module_memory and self.config.knowledge.persist_internal:
                    from skynet.analyze.module_memory import ModuleMemoryWriter

                    try:
                        writer = ModuleMemoryWriter(self.repo_root, self.config)
                        await writer.write_from_results(store, summary.results)
                    except Exception as e:
                        logger.warning("模块记忆写回失败: {}", e)

            chunk_finding_items = self._high_chunk_findings(summary.results)

            for r in summary.results:
                summary.analyzed += 1
                if r.error:
                    summary.errors += 1
                if r.findings:
                    summary.with_findings += 1
                    summary.total_findings += len(r.findings)

            do_trace = trace_flows or self.config.taint.auto_trace_on_analyze
            if do_trace and self.config.taint.enabled:
                from skynet.taint.runner import TraceRunner

                sink_qns = [r.qualified_name for r in summary.results if r.needs_flow_trace]
                if sink_qns or trace_flows:
                    logger.info("开始流追踪 ({} 个 sink chunk)", len(sink_qns) or "all")
                    trace_runner = TraceRunner(self.repo_root, self.config,
                                               state_db=self.state_db)
                    trace_summary = await trace_runner.run(
                        run_composite=composite or self.config.taint.enable_composite,
                        save=save,
                        sink_filter=sink_qns if sink_qns else None,
                        chunk_findings=chunk_finding_items,
                        run_id=_rid,
                    )
                    summary.flow_trace = trace_summary.to_dict()

            if self._external_scanner is not None:
                scanner_findings = await self._run_external_scanner()
                if scanner_findings:
                    logger.info("外部扫描器发现 {} 个问题", len(scanner_findings))

            if save:
                summary.output_path = self._save_report(summary)

            # ── StateDB: 记录产物 & 完成 ──
            if self.state_db and _rid:
                if summary.output_path:
                    self.state_db.add_artifact(
                        _rid, "analyze", None,
                        kind="analysis_report", path=str(summary.output_path),
                    )
                self.state_db.finish_run(_rid, "completed")

            return summary

        except Exception:
            if self.state_db and _rid:
                self.state_db.finish_run(_rid, "failed")
            raise

    async def _run_external_scanner(self) -> list[dict]:
        """运行外部扫描器并返回发现结果。"""
        if self._external_scanner is None:
            return []
        try:
            results = await self._external_scanner.run_all(str(self.repo_root))
            all_findings = []
            for result in results:
                for finding in result.findings:
                    all_findings.append({
                        "tool": result.tool,
                        "file": finding.get("file", ""),
                        "line": finding.get("line", 0),
                        "severity": finding.get("severity", "medium"),
                        "message": finding.get("message", ""),
                        "rule_id": finding.get("rule_id", ""),
                    })
            return all_findings
        except Exception as e:
            logger.warning("外部扫描器失败: {}", e)
            return []

    @staticmethod
    def _high_chunk_findings(results: list[ChunkAnalysisResult]) -> list[dict]:
        items: list[dict] = []
        for result in results:
            for finding in result.findings:
                if finding.severity not in ("critical", "high", "medium"):
                    continue
                items.append({
                    **finding.to_dict(),
                    "qualified_name": result.qualified_name,
                    "file_path": result.file_path,
                })
        return items

    def _save_report(self, summary: RunSummary) -> Path:
        out_dir = Path(self.config.analyze.output_dir)
        if not out_dir.is_absolute():
            out_dir = Path.cwd() / out_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = self.repo_root.name or "project"
        path = out_dir / f"analysis_{name}_{ts}.json"

        payload = {
            "generated_at": datetime.now().isoformat(),
            "model": summary.model,
            **{k: v for k, v in summary.to_dict().items()},
        }
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("分析报告已保存: {}", path)
        return path
