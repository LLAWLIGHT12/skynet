"""从 scan_*.json 生成统一 HTML 报告。"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from skynet.report.renderer import (
    build_analysis_context,
    build_scan_context,
    load_template,
    render_template,
)


def _load_scan(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _find_latest_scan(reports_dir: Path) -> Optional[Path]:
    candidates = sorted(
        reports_dir.glob("scan_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _render_report(context: dict[str, str]) -> str:
    template = load_template("report.html")
    return render_template(template, context)


def generate_scan_html_report(
    scan_path: str | Path,
    output_path: Optional[str | Path] = None,
) -> Path:
    src = Path(scan_path)
    data = _load_scan(src)
    out = Path(output_path) if output_path else src.with_suffix(".html")

    html_body = _render_report(build_scan_context(data))
    out.write_text(html_body, encoding="utf-8")
    return out


def generate_analysis_html_report(
    analysis_path: str | Path,
    output_path: Optional[str | Path] = None,
) -> Path:
    src = Path(analysis_path)
    data = _load_scan(src)  # same JSON load
    if not data.get("generated_at"):
        data["generated_at"] = datetime.now().isoformat()
    out = Path(output_path) if output_path else src.with_suffix(".html")

    html_body = _render_report(build_analysis_context(data))
    out.write_text(html_body, encoding="utf-8")
    return out


def generate_scan_from_reports_dir(
    reports_dir: str | Path = "./reports",
    scan_file: Optional[str] = None,
) -> Path:
    reports = Path(reports_dir)
    if scan_file:
        src = Path(scan_file)
    else:
        src = _find_latest_scan(reports)
        if src is None:
            raise FileNotFoundError(f"在 {reports} 中未找到 scan_*.json")
    return generate_scan_html_report(src)


def generate_audit_html_report(
    audit_report_path: str | Path,
    output_path: Optional[str | Path] = None,
) -> Path:
    """从 audit 管线 report.json 生成 HTML 报告。

    使用 audit_to_scan_report 转换器将 audit 格式转为 scan 格式，
    然后通过 skynet 渲染器生成 HTML。
    """
    from skynet.audit.stages.report import audit_to_scan_report

    src = Path(audit_report_path)
    with open(src, encoding="utf-8") as f:
        audit_data = json.loads(f.read())

    scan_data = audit_to_scan_report(audit_data)
    out = Path(output_path) if output_path else src.with_suffix(".html")

    html_body = _render_report(build_scan_context(scan_data))
    out.write_text(html_body, encoding="utf-8")
    return out
