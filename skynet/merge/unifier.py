"""合并 analysis / flow_trace / composite 为 ScanReport。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from skynet.merge.dedup import is_actionable, merge_findings
from skynet.merge.cvss_enrich import enrich_findings
from skynet.merge.models import UnifiedFinding, ScanReport
from skynet.knowledge.internal.store import InternalKnowledgeStore

_CWE_FROM_SINK = {
    "sql_string_format": "CWE-89",
    "sql_execute_variable": "CWE-89",
    "shell_invoke": "CWE-78",
    "path_join_user": "CWE-22",
    "pickle_load": "CWE-502",
    "eval_usage": "CWE-94",
}


def _infer_cwe(vulnerability_type: str, sink_type: str = "", evidence: Optional[dict] = None) -> Optional[str]:
    if evidence and evidence.get("cwe_id"):
        return str(evidence["cwe_id"])
    text = f"{vulnerability_type} {sink_type}".lower()
    if sink_type and sink_type in _CWE_FROM_SINK:
        return _CWE_FROM_SINK[sink_type]
    if "sql" in text or "sqli" in text:
        return "CWE-89"
    if "xss" in text:
        return "CWE-79"
    if "command" in text or "shell" in text:
        return "CWE-78"
    if "path" in text and "traversal" in text:
        return "CWE-22"
    return None


def _vuln_type_from_flow(record: dict[str, Any]) -> str:
    fp = record.get("fingerprint", {})
    sink_type = fp.get("sink_type", "")
    if sink_type.startswith("sql"):
        return "SQL Injection"
    if sink_type == "shell_invoke":
        return "OS Command Injection"
    summary = (record.get("analysis") or {}).get("summary", "")
    if "SQL" in summary or "sql" in summary:
        return "SQL Injection"
    return sink_type.replace("_", " ").title() or "Security Issue"


def findings_from_analysis(
    data: dict[str, Any],
    fp_chunks: Optional[set[str]] = None,
) -> list[UnifiedFinding]:
    results: list[UnifiedFinding] = []
    fp_chunks = fp_chunks or set()
    for chunk in data.get("results", []):
        qn = str(chunk.get("qualified_name", ""))
        if qn in fp_chunks:
            continue
        for item in chunk.get("findings", []):
            if not isinstance(item, dict):
                continue
            vtype = str(item.get("vulnerability_type", "Unknown"))
            f = UnifiedFinding(
                title=str(item.get("title", "Security issue")),
                severity=str(item.get("severity", "medium")).lower(),
                vulnerability_type=vtype,
                description=str(item.get("description", "")),
                sources=["chunk"],
                confidence=float(item.get("confidence", 0.5)),
                cwe_id=item.get("cwe_id"),
                recommendation=str(item.get("recommendation", "")),
                qualified_name=qn,
                evidence={
                    "chunk": {
                        "qualified_name": qn,
                        "file_path": chunk.get("file_path"),
                        "line_start": chunk.get("line_start"),
                        "line_end": chunk.get("line_end"),
                        "line_hint": item.get("line_hint"),
                    }
                },
            )
            if not f.cwe_id:
                f.cwe_id = _infer_cwe(vtype)
            if is_actionable(f):
                results.append(f)
    return results


def _load_false_positive_sets(repo_root: str) -> tuple[set[str], set[str], set[str]]:
    store = InternalKnowledgeStore(repo_root)
    fp_chunks = {
        qn for qn, hist in store._data.get("chunk_history", {}).items()
        if hist.get("false_positive")
    }
    fp_flows: set[str] = set()
    fp_sinks: set[str] = set()
    for fid, rec in store._data.get("flow_records", {}).items():
        if not rec.get("false_positive"):
            continue
        fp_flows.add(fid)
        sink = (rec.get("fingerprint") or {}).get("sink_qn", "")
        if sink:
            fp_sinks.add(sink)
    return fp_chunks, fp_flows, fp_sinks


def filter_false_positives(
    findings: list[UnifiedFinding],
    fp_chunks: set[str],
    fp_flows: set[str],
    fp_sinks: set[str],
) -> list[UnifiedFinding]:
    kept: list[UnifiedFinding] = []
    for f in findings:
        if f.flow_id and f.flow_id in fp_flows:
            continue
        if f.qualified_name and f.qualified_name in fp_chunks:
            continue
        if f.sink_qn and f.sink_qn in fp_sinks:
            continue
        if f.qualified_name and f.qualified_name in fp_sinks:
            continue
        kept.append(f)
    return kept


def findings_from_flow_trace(data: dict[str, Any]) -> list[UnifiedFinding]:
    results: list[UnifiedFinding] = []
    for record in data.get("records", []):
        if record.get("false_positive"):
            continue
        verdict = str(record.get("verdict", "")).lower()
        if verdict not in ("vulnerable", "inconclusive", "sanitized", "unknown"):
            continue
        if verdict in ("sanitized", "unknown") and not record.get("analysis", {}).get("summary"):
            continue

        fp = record.get("fingerprint", {})
        sink_qn = fp.get("sink_qn", "")
        analysis = record.get("analysis") or {}
        summary = analysis.get("summary", "")
        vtype = _vuln_type_from_flow(record)
        severity = str(record.get("severity", "medium")).lower()
        if verdict == "vulnerable" and severity == "medium":
            severity = "high"

        f = UnifiedFinding(
            title=f"Flow: {sink_qn.rsplit('::', 1)[-1] if sink_qn else 'sink'}",
            severity=severity,
            vulnerability_type=vtype,
            description=summary or f"Flow verdict: {verdict}",
            sources=["flow"],
            confidence=float(record.get("confidence", 0.5)),
            cwe_id=_infer_cwe(vtype, fp.get("sink_type", ""), record.get("evidence")),
            sink_qn=sink_qn,
            flow_id=record.get("flow_id", ""),
            evidence={
                "flow": {
                    "flow_id": record.get("flow_id"),
                    "verdict": verdict,
                    "reachability": record.get("reachability"),
                    "path_qns": fp.get("path_qns", []),
                    "sink_type": fp.get("sink_type"),
                    "gap_reasons": (record.get("evidence") or {}).get("gap_reasons", []),
                    "agent_used": (record.get("evidence") or {}).get("agent_used"),
                    "lsp_used": (record.get("evidence") or {}).get("lsp_used"),
                }
            },
        )
        if verdict == "vulnerable" or summary:
            results.append(f)
    return results


def findings_from_composite(data: dict[str, Any]) -> list[UnifiedFinding]:
    results: list[UnifiedFinding] = []
    for item in data.get("composite_findings", []):
        if not isinstance(item, dict):
            continue
        f = UnifiedFinding(
            title=str(item.get("title", "Composite issue")),
            severity=str(item.get("severity", "medium")).lower(),
            vulnerability_type=str(item.get("vulnerability_type", "Logic Issue")),
            description=str(item.get("description", "")),
            sources=["composite"],
            confidence=float(item.get("confidence", 0.5)),
            recommendation=str(item.get("recommendation", "")),
            evidence={"composite": item},
        )
        if is_actionable(f):
            results.append(f)
    return results


def findings_from_project_memory(repo_root: str) -> list[UnifiedFinding]:
    store = InternalKnowledgeStore(repo_root)
    items = store._data.get("system_memory", {}).get("composite_findings", [])
    return findings_from_composite({"composite_findings": items})


def build_scan_report(
    repo_root: str,
    analysis: Optional[dict[str, Any]] = None,
    flow_trace: Optional[dict[str, Any]] = None,
    analysis_path: Optional[str] = None,
    flow_trace_path: Optional[str] = None,
) -> ScanReport:
    if flow_trace is None and analysis:
        embedded = analysis.get("flow_trace")
        if isinstance(embedded, dict):
            flow_trace = embedded
            if not flow_trace_path and embedded.get("output_path"):
                flow_trace_path = str(embedded["output_path"])

    fp_chunks, fp_flows, fp_sinks = _load_false_positive_sets(repo_root)

    chunk_findings = findings_from_analysis(analysis or {}, fp_chunks)
    flow_findings = findings_from_flow_trace(flow_trace or {})
    composite_from_flow = findings_from_composite(flow_trace or {})
    composite_from_analysis = findings_from_composite(analysis or {})
    composite_from_memory = findings_from_project_memory(repo_root)
    composite_findings = composite_from_flow + composite_from_analysis + composite_from_memory

    merged = merge_findings([chunk_findings, flow_findings, composite_findings])
    merged = filter_false_positives(merged, fp_chunks, fp_flows, fp_sinks)
    merged = enrich_findings(merged)

    model = ""
    if analysis:
        model = str(analysis.get("model", ""))
    if not model and flow_trace:
        for rec in flow_trace.get("records", []):
            model = (rec.get("analysis") or {}).get("model", "")
            if model:
                break

    report = ScanReport(
        repo_root=repo_root,
        model=model,
        chunk_findings=chunk_findings,
        flow_findings=flow_findings,
        composite_findings=composite_findings,
        merged=merged,
        analysis_path=analysis_path,
        flow_trace_path=flow_trace_path,
        stats={
            "chunk_count": len(chunk_findings),
            "flow_count": len(flow_findings),
            "composite_count": len(composite_findings),
            "merged_count": len(merged),
            "by_severity": _count_by_severity(merged),
            "false_positive_filtered": len(fp_flows) + len(fp_chunks),
        },
    )
    return report


def _count_by_severity(findings: list[UnifiedFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _load_json(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def find_latest_report(
    reports_dir: Path,
    prefix: str,
    repo_root: Optional[Path] = None,
) -> Optional[Path]:
    candidates = sorted(
        reports_dir.glob(f"{prefix}_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return None
    if repo_root is None:
        return candidates[0]

    want = str(repo_root.resolve())
    for path in candidates:
        data = _load_json(path)
        got = str(Path(data.get("repo_root", "")).resolve())
        if got == want:
            return path
    return None


def merge_from_reports_dir(
    repo_root: str | Path,
    reports_dir: str | Path,
    analysis_file: Optional[str | Path] = None,
    flow_trace_file: Optional[str | Path] = None,
) -> ScanReport:
    root = Path(repo_root).resolve()
    rdir = Path(reports_dir)
    if not rdir.is_absolute():
        rdir = Path.cwd() / rdir

    apath = Path(analysis_file) if analysis_file else find_latest_report(rdir, "analysis", root)
    fpath = Path(flow_trace_file) if flow_trace_file else find_latest_report(rdir, "flow_trace", root)

    analysis = _load_json(apath) if apath and apath.is_file() else None
    flow_trace = _load_json(fpath) if fpath and fpath.is_file() else None

    if analysis and analysis.get("repo_root"):
        root = Path(analysis["repo_root"])
    elif flow_trace and flow_trace.get("repo_root"):
        root = Path(flow_trace["repo_root"])

    return build_scan_report(
        repo_root=str(root),
        analysis=analysis,
        flow_trace=flow_trace,
        analysis_path=str(apath) if apath else None,
        flow_trace_path=str(fpath) if fpath else None,
    )


def save_scan_report(report: ScanReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return path


def main() -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Skynet findings 合并")
    parser.add_argument("repo_root", nargs="?", default=".", help="项目根目录")
    parser.add_argument("--reports-dir", default="./reports")
    parser.add_argument("--analysis", default=None, help="analysis JSON 路径")
    parser.add_argument("--flow-trace", default=None, help="flow_trace JSON 路径")
    parser.add_argument("--dry-run", action="store_true", help="仅打印 merged 摘要")
    parser.add_argument("-o", "--output", default=None, help="输出 scan JSON 路径")
    args = parser.parse_args()

    report = merge_from_reports_dir(
        args.repo_root,
        args.reports_dir,
        analysis_file=args.analysis,
        flow_trace_file=args.flow_trace,
    )

    if args.dry_run:
        print(f"repo_root: {report.repo_root}")
        print(f"chunk: {len(report.chunk_findings)} flow: {len(report.flow_findings)} "
              f"composite: {len(report.composite_findings)} merged: {len(report.merged)}")
        for f in report.merged:
            print(f"  [{f.severity}] {f.title} sources={f.sources} cwe={f.cwe_id}")
        return 0 if report.merged else 1

    if args.output:
        save_scan_report(report, args.output)
        print(f"saved: {args.output}")
    else:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
