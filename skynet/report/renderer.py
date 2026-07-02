"""HTML 模板加载与内容渲染。"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

from skynet.report.theme import SEVERITY_META, SEVERITY_ORDER, SOURCE_META

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _esc(text: Any) -> str:
    return html.escape(str(text)) if text is not None else ""


def _short_qn(qn: str) -> str:
    if "::" in qn:
        file_part, name = qn.rsplit("::", 1)
        file_name = Path(file_part).name
        return f"{file_name}::{name}"
    return qn


def _severity_rank(severity: str) -> int:
    s = severity.lower()
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 99


def load_template(name: str) -> str:
    path = _TEMPLATES_DIR / name
    if not path.is_file():
        raise FileNotFoundError(f"报告模板不存在: {path}")
    return path.read_text(encoding="utf-8")


def render_template(template: str, mapping: dict[str, str]) -> str:
    """替换 {{KEY}} 占位符。"""
    def _sub(match: re.Match[str]) -> str:
        key = match.group(1)
        return mapping.get(key, "")

    return re.sub(r"\{\{(\w+)\}\}", _sub, template)


def render_source_tags(sources: list[str]) -> str:
    parts: list[str] = []
    for src in sources:
        meta = SOURCE_META.get(src, {"label": src, "color": "#64748b"})
        parts.append(
            f'<span class="tag tag-source" style="--tag-color:{meta["color"]}">'
            f'{_esc(meta["label"])}</span>'
        )
    return "".join(parts) or '<span class="tag tag-muted">—</span>'


def render_flow_evidence(flow: dict[str, Any]) -> str:
    if not flow:
        return ""
    path_qns = flow.get("path_qns") or []
    steps = "".join(
        f'<li><span class="step-index">{i + 1}</span>'
        f'<code>{_esc(_short_qn(str(p)))}</code></li>'
        for i, p in enumerate(path_qns)
    )
    gap_reasons = flow.get("gap_reasons") or []
    gaps = ", ".join(_esc(str(g)) for g in gap_reasons[:8]) or "—"
    if len(gap_reasons) > 8:
        gaps += f" … +{len(gap_reasons) - 8}"

    return f"""
    <div class="evidence-block flow-evidence">
      <div class="evidence-title">流证据链</div>
      <ol class="flow-steps">{steps or '<li class="muted">无路径数据</li>'}</ol>
      <div class="evidence-grid">
        <div><span class="label">Verdict</span><span class="value">{_esc(flow.get('verdict', '-'))}</span></div>
        <div><span class="label">Agent</span><span class="value">{'是' if flow.get('agent_used') else '否'}</span></div>
        <div><span class="label">LSP</span><span class="value">{'是' if flow.get('lsp_used') else '否'}</span></div>
        <div><span class="label">Reachability</span><span class="value">{_esc(flow.get('reachability', '-'))}</span></div>
      </div>
      <div class="gap-line"><span class="label">Gap</span> {gaps}</div>
    </div>"""


def render_composite_evidence(comp: dict[str, Any]) -> str:
    if not comp:
        return ""
    impacted = comp.get("impacted_files") or []
    files = ", ".join(_esc(str(f)) for f in impacted[:6]) or "—"
    return f"""
    <div class="evidence-block composite-evidence">
      <div class="evidence-title">组合分析</div>
      <p class="evidence-text">{_esc(comp.get('description', comp.get('title', '')))}</p>
      {f'<div class="gap-line"><span class="label">影响文件</span> {files}</div>' if impacted else ''}
    </div>"""


def render_chunk_evidence(chunk: dict[str, Any]) -> str:
    if not chunk:
        return ""
    loc = ""
    if chunk.get("file_path"):
        loc = f'{_esc(Path(str(chunk["file_path"])).name)}'
        if chunk.get("line_start"):
            loc += f':{chunk.get("line_start")}'
    return f"""
    <div class="evidence-block chunk-evidence">
      <div class="evidence-title">代码位置</div>
      <code class="location-code">{_esc(_short_qn(str(chunk.get('qualified_name', ''))))}</code>
      {f'<div class="gap-line"><span class="label">文件</span> {loc}</div>' if loc else ''}
    </div>"""


def render_finding_card(finding: dict[str, Any], index: int) -> str:
    sev = str(finding.get("severity", "info")).lower()
    meta = SEVERITY_META.get(sev, SEVERITY_META["info"])
    evidence = finding.get("evidence") or {}
    flow_html = render_flow_evidence(evidence.get("flow") or {})
    comp_html = render_composite_evidence(evidence.get("composite") or {})
    chunk_html = render_chunk_evidence(evidence.get("chunk") or {})

    cvss = finding.get("cvss_score")
    cvss_html = ""
    if cvss is not None:
        cvss_html = (
            f'<span class="tag tag-cvss">CVSS {float(cvss):.1f}</span>'
            f'<div class="cvss-vector"><code>{_esc(finding.get("cvss_vector", ""))}</code></div>'
        )

    rec = finding.get("recommendation", "")
    rec_html = f'<div class="recommendation"><span class="label">修复建议</span><p>{_esc(rec)}</p></div>' if rec else ""

    return f"""
    <article class="finding-card" style="--sev-color:{meta['color']};--sev-bg:{meta['bg']};--sev-border:{meta['border']}">
      <header class="finding-header">
        <div class="finding-rank">#{index}</div>
        <div class="finding-main">
          <div class="finding-badges">
            <span class="badge-sev">{_esc(meta['label'])}</span>
            {render_source_tags(finding.get("sources") or [])}
            {f'<span class="tag tag-cwe">{_esc(finding.get("cwe_id"))}</span>' if finding.get("cwe_id") else ''}
          </div>
          <h3 class="finding-title">{_esc(finding.get("title", "Security finding"))}</h3>
          <div class="finding-meta">
            <span>{_esc(finding.get("vulnerability_type", ""))}</span>
            <span class="dot">·</span>
            <span>置信度 {float(finding.get("confidence", 0)):.0%}</span>
          </div>
        </div>
      </header>
      <div class="finding-body">
        <p class="finding-desc">{_esc(finding.get("description", ""))}</p>
        {cvss_html}
        {chunk_html}
        {flow_html}
        {comp_html}
        {rec_html}
      </div>
    </article>"""


def render_summary_cards(items: list[tuple[str, str, str]]) -> str:
    """items: (label, value, accent_color)"""
    return "".join(
        f'<div class="summary-card" style="--accent:{color}">'
        f'<div class="summary-value">{_esc(value)}</div>'
        f'<div class="summary-label">{_esc(label)}</div></div>'
        for label, value, color in items
    )


def render_severity_bar(by_severity: dict[str, int], total: int) -> str:
    if total <= 0:
        return '<div class="severity-bar empty">暂无发现</div>'
    segments: list[str] = []
    legend: list[str] = []
    for sev in SEVERITY_ORDER:
        count = int(by_severity.get(sev, 0))
        if count <= 0:
            continue
        pct = max(count / total * 100, 4)
        color = SEVERITY_META[sev]["color"]
        segments.append(
            f'<div class="seg" style="width:{pct:.1f}%;background:{color}" '
            f'title="{SEVERITY_META[sev]["label"]}: {count}"></div>'
        )
        legend.append(
            f'<span class="legend-item"><i style="background:{color}"></i>'
            f'{SEVERITY_META[sev]["label"]} {count}</span>'
        )
    return f'<div class="severity-bar">{"".join(segments)}</div><div class="severity-legend">{"".join(legend)}</div>'


def render_findings_list(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return """
        <div class="empty-state">
          <div class="empty-icon">✓</div>
          <h3>未发现安全问题</h3>
          <p>本次扫描未产生合并后的安全发现。</p>
        </div>"""
    sorted_items = sorted(findings, key=lambda x: _severity_rank(str(x.get("severity", "info"))))
    return "".join(render_finding_card(f, i + 1) for i, f in enumerate(sorted_items))


def build_scan_context(data: dict[str, Any]) -> dict[str, str]:
    stats = data.get("stats") or {}
    merged = data.get("merged") or []
    by_sev = stats.get("by_severity") or {}
    total = int(stats.get("merged_count", len(merged)))

    summary = render_summary_cards([
        ("合并发现", str(total), "#6366f1"),
        ("Chunk", str(stats.get("chunk_count", 0)), "#3b82f6"),
        ("Flow", str(stats.get("flow_count", 0)), "#14b8a6"),
        ("Composite", str(stats.get("composite_count", 0)), "#a855f7"),
    ])

    project_name = Path(str(data.get("repo_root", "project"))).name or "project"

    return {
        "REPORT_TITLE": "Skynet 安全扫描报告",
        "PROJECT_NAME": _esc(project_name),
        "REPO_ROOT": _esc(data.get("repo_root", "")),
        "MODEL": _esc(data.get("model", "—")),
        "GENERATED_AT": _esc(data.get("generated_at", "")),
        "SUMMARY_CARDS": summary,
        "SEVERITY_SECTION": render_severity_bar(by_sev, total),
        "FINDINGS_HTML": render_findings_list(merged),
        "FINDING_COUNT": str(total),
        "ANALYSIS_PATH": _esc(data.get("analysis_path") or "—"),
        "FLOW_TRACE_PATH": _esc(data.get("flow_trace_path") or "—"),
    }


def build_analysis_context(data: dict[str, Any]) -> dict[str, str]:
    all_findings: list[dict[str, Any]] = []
    for result in data.get("results", []):
        qn = str(result.get("qualified_name", ""))
        for f in result.get("findings", []):
            item = dict(f)
            item["qualified_name"] = qn
            item["sources"] = ["chunk"]
            chunk_ev = {
                "qualified_name": qn,
                "file_path": result.get("file_path"),
                "line_start": result.get("line_start"),
                "line_end": result.get("line_end"),
            }
            item["evidence"] = {"chunk": chunk_ev}
            all_findings.append(item)

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in all_findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    total = len(all_findings)
    by_sev = {k: v for k, v in counts.items() if v > 0}
    project_name = Path(str(data.get("repo_root", "project"))).name or "project"

    summary = render_summary_cards([
        ("漏洞条目", str(total), "#6366f1"),
        ("分析 Chunk", str(data.get("analyzed", 0)), "#3b82f6"),
        ("有问题 Chunk", str(data.get("with_findings", 0)), "#f59e0b"),
        ("失败", str(data.get("errors", 0)), "#ef4444"),
    ])

    return {
        "REPORT_TITLE": "Skynet 安全分析报告",
        "PROJECT_NAME": _esc(project_name),
        "REPO_ROOT": _esc(data.get("repo_root", "")),
        "MODEL": _esc(data.get("model", "—")),
        "GENERATED_AT": _esc(data.get("generated_at", "")),
        "SUMMARY_CARDS": summary,
        "SEVERITY_SECTION": render_severity_bar(by_sev, total),
        "FINDINGS_HTML": render_findings_list(all_findings),
        "FINDING_COUNT": str(total),
        "ANALYSIS_PATH": "—",
        "FLOW_TRACE_PATH": "—",
    }
