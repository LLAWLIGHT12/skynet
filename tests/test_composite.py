#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""组合漏洞 benchmark 回归测试。"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BENCHMARK = ROOT / "tests" / "benchmark" / "composite"
PYTHON = sys.executable

SCENARIO_A_KEYWORDS = ("access", "authorization", "auth", "role", "privilege", "越权", "权限")
SCENARIO_B_KEYWORDS = ("logic", "state", "paid", "payment", "status", "business", "逻辑", "状态", "支付")


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def _text_blob(report: dict) -> str:
    parts: list[str] = []
    for key in ("merged", "composite_findings", "chunk_findings", "flow_findings"):
        for item in report.get(key, []):
            if not isinstance(item, dict):
                continue
            parts.extend([
                str(item.get("title", "")),
                str(item.get("description", "")),
                str(item.get("vulnerability_type", "")),
            ])
            comp = (item.get("evidence") or {}).get("composite") or {}
            parts.extend([
                str(comp.get("title", "")),
                str(comp.get("description", "")),
            ])
    flow = report.get("flow_trace") or {}
    for item in flow.get("composite_findings", []):
        if isinstance(item, dict):
            parts.extend([
                str(item.get("title", "")),
                str(item.get("description", "")),
            ])
    return " ".join(parts).lower()


def _has_keywords(text: str, keywords: tuple[str, ...]) -> bool:
    return any(k.lower() in text for k in keywords)


def _ensure_graph() -> None:
    db = BENCHMARK / ".skynet" / "graph.db"
    if db.is_file():
        return
    print("Building composite benchmark graph...")
    result = subprocess.run(
        [PYTHON, "main.py", "build", "-d", str(BENCHMARK), "--full"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"build failed: {result.stderr or result.stdout}")


def _latest_scan() -> Path:
    reports = sorted(
        (ROOT / "reports").glob("scan_composite_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not reports:
        fail("no scan_composite_*.json — run: python main.py scan -d tests/benchmark/composite")
    return reports[0]


def test_cluster_unit() -> None:
    from code_review_graph.graph import GraphStore
    from skynet.analyze.composite import CompositeAnalyzer

    db = BENCHMARK / ".skynet" / "graph.db"
    if not db.is_file():
        print("[SKIP] cluster unit — graph not built")
        return

    chunk_items = [
        {
            "qualified_name": "scenario_a/auth_roles.py::assign_role",
            "file_path": str(BENCHMARK / "scenario_a" / "auth_roles.py"),
            "title": "Missing authorization on role assignment",
            "severity": "high",
            "vulnerability_type": "Broken Access Control",
            "description": "assign_role writes roles without admin check",
        },
        {
            "qualified_name": "scenario_a/api_handlers.py::handle_admin_action",
            "file_path": str(BENCHMARK / "scenario_a" / "api_handlers.py"),
            "title": "Trust in client-side role",
            "severity": "high",
            "vulnerability_type": "Broken Access Control",
            "description": "admin action trusts stored role only",
        },
    ]
    with GraphStore(db) as store:
        analyzer = CompositeAnalyzer(BENCHMARK)
        clusters = analyzer._build_clusters(store, [], chunk_items)
    assert clusters, "expected composite cluster from cross-module chunks"
    ok(f"cluster unit: {len(clusters)} cluster(s)")


def test_scan_report_keywords() -> None:
    _ensure_graph()
    result = subprocess.run(
        [PYTHON, "main.py", "scan", "-d", str(BENCHMARK), "--skip-build"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"scan failed: {result.stderr or result.stdout}")

    report = json.loads(_latest_scan().read_text(encoding="utf-8"))
    blob = _text_blob(report)

    if not report.get("merged"):
        fail("merged findings empty")

    composite_items = [
        f for f in report.get("merged", [])
        if "composite" in (f.get("sources") or [])
    ]
    if not composite_items:
        composite_items = report.get("composite_findings", [])

    if not composite_items and not _has_keywords(blob, SCENARIO_A_KEYWORDS + SCENARIO_B_KEYWORDS):
        fail("no composite findings and no scenario keywords in report")

    if not _has_keywords(blob, SCENARIO_A_KEYWORDS):
        fail(f"scenario A keywords not found in report text: {blob[:300]}")
    if not _has_keywords(blob, SCENARIO_B_KEYWORDS):
        fail(f"scenario B keywords not found in report text: {blob[:300]}")

    ok(f"scan report keywords (merged={len(report.get('merged', []))}, composite={len(composite_items)})")


def main() -> int:
    from skynet.config import load_config, load_dotenv_if_present

    load_dotenv_if_present()
    cfg = ROOT / "config" / "skynet.yaml"
    if cfg.exists():
        load_config(cfg)

    print("=== test_cluster_unit ===")
    test_cluster_unit()

    print("=== test_scan_report_keywords ===")
    test_scan_report_keywords()

    print("\nAll composite tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
