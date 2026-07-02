"""Pipeline driver: Recon → (Hunt → Validate → Gapfill)* → Dedupe → Trace
                  → Feedback → (Hunt → Validate → Dedupe → Trace)* → Report

增强版：支持 skynet 图谱上下文注入（可选）和组合漏洞分析阶段。

可选能力：
- TokenTracker：结构化 token 统计
- TokenBudget：token 预算管控
- LocationResolver：确定性行号校验
- GlobalFilter：后置误报过滤
- Compression：三区内存压缩（供 runner 使用）
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from skynet.audit import stages
from skynet.audit.config import HarnessConfig
from skynet.audit.graph_context import GraphInfo, build_graph_info
from skynet.audit.runner import QuotaExhaustedError
from skynet.audit.state import StateDB
from skynet.audit.stages._common import StageContext

# ── 沙箱验证（可选依赖） ──
try:
    from skynet.verify.verifier import (
        SandboxVerifier,
        VerifyConfig as SandboxVerifyConfig,
        VerifyStatus,
    )
    _VERIFY_AVAILABLE = True
except ImportError:
    _VERIFY_AVAILABLE = False

# 可选模块（import 失败不影响管线）
try:
    from skynet.audit.token_tracker import TokenTracker
except ImportError:
    TokenTracker = None  # type: ignore[assignment,misc]

try:
    from skynet.audit.token_budget import TokenBudget
except ImportError:
    TokenBudget = None  # type: ignore[assignment,misc]

try:
    from skynet.audit.location_resolver import resolve_finding_location
except ImportError:
    resolve_finding_location = None  # type: ignore[assignment,misc]

log = logging.getLogger(__name__)


class CostExceeded(RuntimeError):
    pass


async def run_pipeline(
    *,
    repo_path: Path,
    run_id: str,
    db: StateDB,
    config: HarnessConfig,
    max_cost_usd: float | None = None,
    resume: bool = False,
    max_recon_tasks: int | None = None,
    live_target: dict | None = None,
    scope_notes: str | None = None,
    graph_enhanced: bool = True,
    run_composite: bool = True,
    chunk_findings: list[dict[str, Any]] | None = None,
    # ── 可选：token 预算与追踪 ──
    token_tracker: Any | None = None,
    token_budget: Any | None = None,
    enable_global_filter: bool = False,
    enable_location_resolver: bool = True,
) -> Path:
    # ── Graph enhancement ──
    graph_info: GraphInfo | None = None
    if graph_enhanced:
        graph_info = build_graph_info(repo_path)
        if graph_info.available:
            log.info("[%s] graph-enhanced mode: %d communities, %d entry points",
                     run_id, graph_info.community_count, len(graph_info.entry_points))

    ctx = StageContext(
        run_id=run_id,
        repo_path=repo_path.resolve(),
        config=config,
        live_target=live_target,
        scope_notes=scope_notes,
        graph_info=graph_info,
    )

    if db.get_run(run_id) is None:
        db.create_run(str(repo_path.resolve()), run_id)
        log.info("[%s] starting fresh pipeline run against %s", run_id, repo_path)
    elif resume:
        # Flip status back to 'running' so subsequent /status calls don't
        # report a stale 'aborted'/'failed' while resume work is ongoing.
        db._conn.execute(  # type: ignore[attr-defined]
            "UPDATE runs SET status = 'running', finished_at = NULL WHERE run_id = ?",
            (run_id,),
        )
        db._conn.commit()  # type: ignore[attr-defined]
        # Re-queue any task left 'running' (interrupted mid-flight by a quota
        # abort or crash) or 'failed' (transient/quota error) so resume
        # actually re-attempts the incomplete work instead of skipping it —
        # Hunt only dispatches 'pending' tasks.
        requeued = db.reset_incomplete_tasks(run_id)
        if requeued:
            log.info("[%s] resume: re-queued %d interrupted/failed tasks", run_id, requeued)
        log.info("[%s] resuming existing run", run_id)
    else:
        raise RuntimeError(
            f"run_id {run_id!r} already exists; pass --resume to continue it."
        )

    def _budget_check(stage_name: str) -> None:
        if max_cost_usd is None:
            return
        spent = db.total_cost(run_id)
        if spent >= max_cost_usd:
            raise CostExceeded(
                f"[{run_id}] budget exhausted before {stage_name}: "
                f"${spent:.4f} >= ${max_cost_usd:.4f}"
            )

    try:
        # ---- Stage 1: Recon ----
        _budget_check("recon")
        recon_kwargs = {} if max_recon_tasks is None else {"max_tasks": max_recon_tasks}
        await stages.run_recon(ctx, db, **recon_kwargs)

        # ---- Stages 2-3-4 loop: Hunt → Validate → Gapfill ----
        for i in range(config.gapfill_iterations + 1):
            _budget_check(f"hunt(iter={i})")
            findings_added = await stages.run_hunt(ctx, db, budget_check=_budget_check)
            if findings_added == 0 and i > 0:
                log.info("[%s] no new findings — exiting Hunt/Gapfill loop", run_id)
                break

            _budget_check(f"validate(iter={i})")
            await stages.run_validate(ctx, db)

            # ── 行号解析 + 后置过滤 ──
            if enable_location_resolver and resolve_finding_location is not None:
                _apply_location_resolver(ctx, db, token_tracker)

            if enable_global_filter and i == config.gapfill_iterations:
                # 只在最后一轮 validate 后执行全局过滤
                await _run_global_filter_with_tracking(
                    ctx, db, token_tracker, token_budget,
                )

            if i >= config.gapfill_iterations:
                break  # final iteration: don't gapfill again
            _budget_check(f"gapfill(iter={i})")
            new_tasks = await stages.run_gapfill(ctx, db)
            if new_tasks == 0:
                log.info("[%s] gapfill produced 0 tasks — exiting loop", run_id)
                break

        # ---- Stage 5: Dedupe ----
        _budget_check("dedupe")
        await stages.run_dedupe(ctx, db)

        # ---- Stage 5.5: Composite (skynet graph-powered) ----
        if run_composite and graph_info and graph_info.available:
            _budget_check("composite")
            try:
                from skynet.analyze.composite import CompositeAnalyzer

                composite_analyzer = CompositeAnalyzer(repo_path)
                composite_findings = await composite_analyzer.run(
                    chunk_findings=chunk_findings,
                )
                if composite_findings:
                    log.info("[%s] composite: %d cross-module findings",
                             run_id, len(composite_findings))
                    for cf in composite_findings:
                        fid = f"comp_{cf.get('title', '?')[:20]}"
                        actual_task_id = f"task_composite_{fid[:16]}"
                        db.add_task(run_id, {
                            "task_id": actual_task_id,
                            "attack_class": "logic_chain",
                            "scope_hint": cf.get("description", ""),
                            "target_files": cf.get("involved_chunks", []),
                            "rationale": cf.get("description", ""),
                            "priority": 1,
                        })
                        db.add_finding(run_id, actual_task_id, {
                            "finding_id": fid,
                            "file": "",
                            "line_start": 0,
                            "line_end": 0,
                            "vuln_class": cf.get("vulnerability_type", "logic_chain"),
                            "severity": cf.get("severity", "medium"),
                            "title": cf.get("title", ""),
                            "description": cf.get("description", ""),
                            "evidence": "",
                            "confidence": cf.get("confidence", 0.5),
                        }, finding_type="composite")
            except Exception as e:
                log.warning("[%s] composite analysis skipped: %s", run_id, e)

        # ---- Stage 6: Trace ----
        _budget_check("trace")
        await stages.run_trace(ctx, db)

        # ---- Stage 6.5: Sandbox Verification (可选) ----
        if _VERIFY_AVAILABLE and config.verify_enabled:
            _budget_check("verify")
            await _run_sandbox_verification(ctx, db, config)

        # ---- Stage 7: Feedback (re-runs Hunt/Validate/Dedupe/Trace) ----
        for i in range(config.feedback_iterations):
            _budget_check(f"feedback(iter={i})")
            new_tasks = await stages.run_feedback(ctx, db)
            if new_tasks == 0:
                break
            _budget_check(f"feedback-hunt(iter={i})")
            await stages.run_hunt(ctx, db)
            _budget_check(f"feedback-validate(iter={i})")
            await stages.run_validate(ctx, db)
            _budget_check(f"feedback-dedupe(iter={i})")
            await stages.run_dedupe(ctx, db)
            _budget_check(f"feedback-trace(iter={i})")
            await stages.run_trace(ctx, db)

        # ---- Stage 8: Report ----
        _budget_check("report")
        report_path = await stages.run_report(ctx, db)

        db.finish_run(run_id, "completed")

        # 输出 token 统计摘要
        if token_tracker is not None:
            ts = token_tracker.summary()
            log.info(
                "[%s] token summary: %d calls, %d tokens (%d in / %d out)",
                run_id, ts["total_calls"], ts["total_tokens"],
                ts["total_input"], ts["total_output"],
            )
        if token_budget is not None:
            bs = token_budget.summary()
            log.info(
                "[%s] budget summary: %d/%d tokens used, %d tasks, %d rejected",
                run_id, bs["total_tokens"], bs["max_total"],
                bs["task_count"], bs["rejected_count"],
            )

        log.info(
            "[%s] pipeline complete: total cost $%.4f — report at %s",
            run_id, db.total_cost(run_id), report_path,
        )
        return report_path

    except CostExceeded as e:
        log.error(str(e))
        db.finish_run(run_id, "aborted")
        raise
    except QuotaExhaustedError as e:
        # Subscription quota exhausted — surface clearly; user must wait
        # for the reset window. Run is resumable via --resume once quota
        # returns.
        log.error(
            "[%s] subscription quota exhausted — aborting (resumable with --resume): %s",
            run_id, str(e)[:300],
        )
        db.finish_run(run_id, "aborted")
        raise
    except Exception:
        db.finish_run(run_id, "failed")
        raise


# ── 沙箱验证辅助 ──


async def _run_sandbox_verification(
    ctx: StageContext,
    db: StateDB,
    config: HarnessConfig,
) -> int:
    """对已确认的 finding 进行沙箱 PoC 验证。

    Returns
    -------
    int
        已验证的 finding 数量。
    """
    if not _VERIFY_AVAILABLE:
        return 0

    try:
        verifier = SandboxVerifier()
        if not verifier.is_available():
            log.info("[%s] sandbox verification skipped: Docker not available", ctx.run_id)
            return 0

        # 获取已确认的 finding
        confirmed = db.get_findings(ctx.run_id, validation_status="confirmed")
        if not confirmed:
            log.debug("[%s] no confirmed findings to verify", ctx.run_id)
            return 0

        log.info("[%s] sandbox verification: %d findings to verify", ctx.run_id, len(confirmed))
        verified = 0
        for finding in confirmed:
            # 构建 flow 数据（从 finding 提取基本信息）
            flow_data = {
                "sink_type": finding.vuln_class or "unknown",
                "source_code": finding.evidence or "",
                "file": finding.file,
                "line": finding.line_start,
            }
            try:
                result = await verifier.verify_flow(flow_data)
                if result.status == VerifyStatus.CONFIRMED:
                    log.info("[%s] ✓ vulnerability confirmed: %s", ctx.run_id, finding.finding_id)
                    verified += 1
                elif result.status == VerifyStatus.UNCONFIRMED:
                    log.debug("[%s] ✗ unconfirmed: %s", ctx.run_id, finding.finding_id)
            except Exception as e:
                log.debug("[%s] verify failed for %s: %s", ctx.run_id, finding.finding_id, e)

        if verified:
            log.info("[%s] sandbox verification: %d/%d confirmed", ctx.run_id, verified, len(confirmed))
        return verified

    except Exception as e:
        log.warning("[%s] sandbox verification failed: %s", ctx.run_id, e)
        return 0


# ── 辅助函数 ──


def _apply_location_resolver(
    ctx: StageContext,
    db: StateDB,
    tracker: Any | None = None,
) -> int:
    """对所有已确认 finding 做行号校验/修正。

    Returns
    -------
    int
        被修正的 finding 数量。
    """
    if resolve_finding_location is None:
        return 0

    confirmed = db.get_findings(ctx.run_id, validation_status="confirmed")
    if not confirmed:
        return 0

    resolved_count = 0
    for f in confirmed:
        finding_dict = {
            "finding_id": f.finding_id,
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "evidence": f.evidence,
        }
        try:
            start, end, was_resolved = resolve_finding_location(
                finding_dict, str(ctx.repo_path),
            )
            if was_resolved:
                db.update_finding_location(f.finding_id, start, end)
                resolved_count += 1
                if tracker:
                    tracker.record("location_resolver", f.finding_id, 0, 0)
        except Exception as e:
            log.debug(
                "[%s] location_resolver failed for %s: %s",
                ctx.run_id, f.finding_id, e,
            )

    if resolved_count:
        log.info(
            "[%s] location_resolver: corrected %d/%d findings",
            ctx.run_id, resolved_count, len(confirmed),
        )
    return resolved_count


async def _run_global_filter_with_tracking(
    ctx: StageContext,
    db: StateDB,
    tracker: Any | None = None,
    budget: Any | None = None,
) -> int:
    """运行全局过滤器，并跟踪 token 使用。"""
    # 预算检查
    if budget is not None and not budget.check_global_budget():
        log.info("[%s] global_filter skipped: budget exhausted", ctx.run_id)
        return 0

    try:
        from skynet.audit.stages.global_filter import run_global_filter
        rejected = await run_global_filter(ctx, db)

        # 记录 token（global_filter 内部做了 1 次 LLM 调用）
        if tracker and rejected >= 0:
            tracker.record("global_filter", "_global", 0, 0)

        return rejected
    except Exception as e:
        log.warning("[%s] global_filter failed: %s", ctx.run_id, e)
        return 0
