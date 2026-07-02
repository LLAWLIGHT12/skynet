#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""合并层单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.merge.dedup import merge_findings
from skynet.merge.models import UnifiedFinding
from skynet.merge.unifier import build_scan_report


def test_dedup_chunk_and_flow() -> None:
    chunk_f = UnifiedFinding(
        title="SQL injection in run_query",
        severity="high",
        vulnerability_type="SQL Injection",
        description="User input concatenated into SQL.",
        sources=["chunk"],
        confidence=0.85,
        cwe_id="CWE-89",
        qualified_name="vuln_sample.py::run_query",
        sink_qn="vuln_sample.py::run_query",
    )
    flow_f = UnifiedFinding(
        title="Flow: run_query",
        severity="high",
        vulnerability_type="SQL Injection",
        description="User input flows to sqlite3.execute without parameterization.",
        sources=["flow"],
        confidence=0.95,
        cwe_id="CWE-89",
        sink_qn="vuln_sample.py::run_query",
        flow_id="abc123",
    )
    merged = merge_findings([[chunk_f], [flow_f]])
    assert len(merged) == 1, f"expected 1 merged finding, got {len(merged)}"
    assert "chunk" in merged[0].sources and "flow" in merged[0].sources
    print("[PASS] chunk+flow dedup -> 1 merged with both sources")


def test_build_from_fixture_flow() -> None:
    flow = {
        "records": [{
            "flow_id": "test_flow_sqli",
            "fingerprint": {
                "sink_qn": "vuln_sample.py::run_query",
                "path_qns": ["vuln_sample.py::handle_request", "vuln_sample.py::run_query"],
                "sink_type": "sql_execute_variable",
            },
            "verdict": "vulnerable",
            "severity": "high",
            "confidence": 0.95,
            "analysis": {"summary": "SQL injection via unparameterized query."},
            "false_positive": False,
        }]
    }
    report = build_scan_report(str(ROOT / "tests" / "fixtures"), flow_trace=flow)
    assert report.merged, "fixture flow should produce merged findings"
    sql = [f for f in report.merged if f.cwe_id == "CWE-89" or "sql" in f.vulnerability_type.lower()]
    assert sql, "expected SQLi in merged"
    print(f"[PASS] fixture flow -> {len(report.merged)} merged ({sql[0].title})")


def main() -> int:
    test_dedup_chunk_and_flow()
    test_build_from_fixture_flow()
    print("\nAll merge tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
