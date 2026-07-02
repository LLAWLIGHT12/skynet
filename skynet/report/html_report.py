"""从分析 JSON 生成 HTML 报告。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


def _load_analysis(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _find_latest_report(reports_dir: Path) -> Optional[Path]:
    scan = sorted(reports_dir.glob("scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if scan:
        return scan[0]
    candidates = sorted(reports_dir.glob("analysis_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def generate_html_report(
    analysis_path: str | Path,
    output_path: Optional[str | Path] = None,
) -> Path:
    """将 analyze / scan 命令输出的 JSON 转为 HTML 报告。"""
    src = Path(analysis_path)
    if src.name.startswith("scan_"):
        from skynet.report.scan_report import generate_scan_html_report

        return generate_scan_html_report(src, output_path)

    from skynet.report.scan_report import generate_analysis_html_report

    return generate_analysis_html_report(src, output_path)


def generate_from_reports_dir(
    reports_dir: str | Path = "./reports",
    analysis_file: Optional[str] = None,
) -> Path:
    reports = Path(reports_dir)
    if analysis_file:
        src = Path(analysis_file)
    else:
        src = _find_latest_report(reports)
        if src is None:
            raise FileNotFoundError(f"在 {reports} 中未找到 analysis_*.json 或 scan_*.json")
    return generate_html_report(src)
