"""Stage 8: Report — schema-validated final document.

增强版：生成 JSON 报告后自动生成 HTML 报告，兼容 skynet scan 格式。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from skynet.audit.runner import AgentRunError, TransientAgentError, run_agent
from skynet.audit.state import StateDB
from skynet.audit.stages._common import StageContext

log = logging.getLogger(__name__)


async def run_report(ctx: StageContext, db: StateDB) -> Path:
    reachable = db.get_reachable_canonical_findings(ctx.run_id)
    ready = []
    # Build confidence map from validation data
    confidence_map: dict[str, float] = {}
    for f, trace in reachable:
        conf = _extract_validation_confidence(f.validation_json)
        if conf is not None:
            confidence_map[f.finding_id] = conf
        ready.append({
            "finding": f.raw_json,
            "validation": f.validation_json,
            "trace": trace,
            "variants": _group_members_excluding(db, ctx.run_id, f.group_id, f.finding_id)
                       if f.group_id else [],
        })

    sc = ctx.stage("report")
    target = {"repo_path": str(ctx.repo_path)}
    user_input = {"run_id": ctx.run_id, "target": target, "ready_findings": ready,
                  **ctx.extras()}

    out_path = ctx.results_dir("report") / "report.json"

    if not ready:
        empty = {
            "run_id": ctx.run_id,
            "target": target,
            "summary": {"total": 0, "by_severity": {}},
            "findings": [],
        }
        out_path.write_text(json.dumps(empty, indent=2))
        log.info("[%s] report: no reachable findings — wrote empty report to %s",
                 ctx.run_id, out_path)
        try:
            _generate_html_report(ctx, empty)
        except Exception as e:
            log.warning("[%s] HTML report skipped (empty): %s", ctx.run_id, e)
        return out_path

    try:
        result = await run_agent(
            stage="report",
            prompt_file=ctx.prompt("08-report"),
            user_input=user_input,
            schema_file=ctx.schema("report"),
            allowed_tools=sc.tools,
            model=sc.model,
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("report"),
            artifact_name="report_agent",
            repair_attempts=max(sc.repair_attempts, 2),  # report MUST validate
        )
    except (AgentRunError, TransientAgentError) as e:
        log.error("[%s] report agent failed: %s — emitting fallback report",
                  ctx.run_id, e)
        fallback = _build_fallback_report(ctx, db, reachable, target)
        _inject_confidence(fallback, confidence_map)
        out_path.write_text(json.dumps(fallback, indent=2))
        try:
            _generate_html_report(ctx, fallback)
        except Exception as e:
            log.warning("[%s] HTML report skipped (fallback): %s", ctx.run_id, e)
        return out_path

    db.record_cost(ctx.run_id, "report", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "report", None, "jsonl", str(result.artifact_path))
    # Inject confidence from validation into report findings
    _inject_confidence(result.payload, confidence_map)
    out_path.write_text(json.dumps(result.payload, indent=2))
    log.info("[%s] report: %d findings written to %s",
             ctx.run_id, len(result.payload.get("findings", [])), out_path)

    # ── 生成 HTML 报告（使用 skynet 渲染器）──
    try:
        html_path = _generate_html_report(ctx, result.payload)
        if html_path:
            log.info("[%s] HTML report: %s", ctx.run_id, html_path)
    except Exception as e:
        log.warning("[%s] HTML report generation skipped: %s", ctx.run_id, e)

    return out_path


def _group_members_excluding(db: StateDB, run_id: str, group_id: str,
                             exclude: str) -> list[str]:
    rows = db._conn.execute(  # type: ignore[attr-defined]
        "SELECT finding_id FROM findings WHERE run_id = ? AND group_id = ? AND finding_id != ?",
        (run_id, group_id, exclude),
    ).fetchall()
    return [r["finding_id"] for r in rows]


def _build_fallback_report(ctx: StageContext, db: StateDB,
                           reachable, target: dict) -> dict:
    by_sev: dict[str, int] = {}
    findings_out = []
    for f, trace in reachable:
        sev = f.severity
        by_sev[sev] = by_sev.get(sev, 0) + 1
        findings_out.append({
            "finding_id": f.finding_id,
            "title": f"{f.vuln_class} in {f.file}",
            "severity": sev,
            "vuln_class": f.vuln_class,
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "description": f.description,
            "evidence": f.evidence,
            "trace": {
                "entry_points": trace.get("entry_points", []),
                "call_chain": trace.get("call_chain", []),
            },
            "recommendation": "Review the sink and add input validation / use a safe API.",
        })
    return {
        "run_id": ctx.run_id,
        "target": target,
        "summary": {"total": len(findings_out), "by_severity": by_sev},
        "findings": findings_out,
    }


def audit_to_scan_report(audit_report: dict, repo_root: str = "") -> dict:
    """将 audit report 转换为 skynet scan report 格式。

    使得 audit 管线的输出可以被 skynet 的 HTML 渲染器直接消费。
    """
    findings = audit_report.get("findings", [])
    merged = []
    for f in findings:
        severity = (f.get("severity") or "info").lower()
        raw_ev = f.get("evidence", "")
        evidence = raw_ev if isinstance(raw_ev, dict) else ({"code": str(raw_ev)} if raw_ev else {})
        merged.append({
            "title": f.get("title", "Untitled"),
            "severity": severity,
            "cwe_id": f.get("cwe", ""),
            "description": f.get("description", ""),
            "location": f.get("file", ""),
            "line_start": f.get("line_start", 0),
            "line_end": f.get("line_end", 0),
            "vuln_class": f.get("vuln_class", ""),
            "confidence": f.get("confidence", 0.0),
            "sources": ["audit"],
            "evidence": evidence,
            "recommendation": f.get("recommendation", ""),
            "trace": f.get("trace", {}),
        })

    summary = audit_report.get("summary", {})
    target = audit_report.get("target", {})

    return {
        "generated_at": datetime.now().isoformat(),
        "generator": "skynet-audit (8-stage pipeline)",
        "run_id": audit_report.get("run_id", ""),
        "repo_root": target.get("repo_path", repo_root),
        "merged": merged,
        "chunk_findings": [],
        "flow_findings": [],
        "composite_findings": [],
        "stats": {
            "total": summary.get("total", len(findings)),
            "by_source": {"audit": len(findings)},
            "by_severity": summary.get("by_severity", {}),
        },
    }


def _extract_validation_confidence(validation_data: dict | None) -> float | None:
    """Extract validator_confidence (0.0-1.0) from validation data.

    StateDB already deserializes validation_json via json.loads, so the
    input is a dict, not a JSON string.
    """
    if not validation_data:
        return None
    try:
        conf = validation_data.get("validator_confidence")
        if conf is not None:
            return float(conf)
        # Fallback: verdict-based heuristic
        verdict = str(validation_data.get("verdict", "")).lower()
        if verdict == "confirmed":
            return 0.85
        elif verdict == "needs_more_info":
            return 0.50
        elif verdict == "rejected":
            return 0.15
    except (ValueError, TypeError):
        pass
    return None


def _inject_confidence(payload: dict, confidence_map: dict[str, float]) -> None:
    """Inject confidence into each finding in the report payload."""
    findings = payload.get("findings", [])
    for f in findings:
        fid = f.get("finding_id", "")
        if fid in confidence_map:
            f["confidence"] = confidence_map[fid]
        elif "confidence" not in f:
            f["confidence"] = 0.7  # default for reachable findings


def _generate_html_report(ctx: StageContext, audit_payload: dict) -> Path | None:
    """使用 skynet HTML 渲染器生成 HTML 报告。"""
    try:
        from skynet.report.renderer import build_scan_context, load_template, render_template
    except ImportError:
        log.debug("skynet report renderer not available")
        return None

    scan_data = audit_to_scan_report(
        audit_payload,
        repo_root=str(ctx.repo_path),
    )

    template = load_template("report.html")
    context = build_scan_context(scan_data)
    html_body = render_template(template, context)

    html_path = ctx.results_dir("report") / "report.html"
    html_path.write_text(html_body, encoding="utf-8")
    return html_path
