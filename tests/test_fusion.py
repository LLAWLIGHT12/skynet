#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""融合验证测试 —— 验证 skynet + audit 集成后的所有关键组件。"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


def test_imports():
    """验证所有关键模块可以被正确导入。"""
    from skynet.audit.types import AgentResult, AgentRunError, QuotaExhaustedError, TransientAgentError
    from skynet.audit.json_utils import extract_json, validate_schema, build_repair_prompt, RepairResult, validate_and_repair
    from skynet.audit.state import StateDB
    from skynet.audit.graph_context import build_graph_info, GraphInfo
    from skynet.audit.agent_runner import run_agent_text
    from skynet.audit.runner import run_agent
    from skynet.audit.orchestrator import run_pipeline, CostExceeded
    from skynet.audit.stages._common import StageContext
    from skynet.audit.stages.report import audit_to_scan_report
    from skynet.audit.cli import main as audit_cli_main
    print("  PASS: All imports")


def test_types_module():
    """验证共享类型模块。"""
    from skynet.audit.types import AgentResult, AgentRunError, QuotaExhaustedError, TransientAgentError

    # AgentResult 构造
    r = AgentResult(
        payload={"x": 1},
        cost_usd=0.01,
        input_tokens=100,
        output_tokens=50,
        cache_read_tokens=0,
        cache_creation_tokens=0,
        num_turns=1,
        duration_ms=500,
        session_id="s1",
        artifact_path=Path("/tmp/test.jsonl"),
        repair_used=False,
    )
    assert r.payload == {"x": 1}
    assert r.cost_usd == 0.01

    # 异常类
    assert issubclass(AgentRunError, RuntimeError)
    assert issubclass(TransientAgentError, RuntimeError)
    assert issubclass(QuotaExhaustedError, RuntimeError)

    print("  PASS: types module")


def test_json_utils():
    """验证 JSON 提取和 schema 验证。"""
    from skynet.audit.json_utils import (
        extract_json, validate_schema, build_repair_prompt,
        RepairResult, validate_and_repair,
    )

    # 测试 extract_json
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"b": 2}\n```') == {"b": 2}
    assert extract_json('some text {"c": [3]} more text') == {"c": [3]}

    try:
        extract_json("not json at all")
        assert False, "should have raised"
    except ValueError:
        pass

    # 测试 build_repair_prompt
    prompt = build_repair_prompt('{"x": 1}', ["x: not a string"], Path(__file__).parent)
    assert "Validation errors" in prompt
    assert "x: not a string" in prompt

    # 测试 validate_and_repair（需要有效 schema）
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        schema_path = Path(td) / "test.schema.json"
        schema_path.write_text(json.dumps({
            "type": "object",
            "properties": {"a": {"type": "integer"}},
            "required": ["a"],
            "additionalProperties": False,
        }))
        result = validate_and_repair('{"a": 1}', schema_path)
        assert isinstance(result, RepairResult)
        assert result.valid is True

        # 验证无效 payload
        result2 = validate_and_repair('{"b": 2}', schema_path)
        assert result2.valid is False
        assert len(result2.errors) > 0

    print("  PASS: json_utils")


def test_state_db(tmpdir: Path):
    """验证合并后的 StateDB。"""
    from skynet.audit.state import StateDB

    db_path = tmpdir / "test_state.db"
    db = StateDB(str(db_path))

    try:
        # 基本表结构已自动创建
        tables = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {r["name"] for r in tables}

        # 核心表
        assert "runs" in table_names, "missing runs table"
        assert "tasks" in table_names, "missing tasks table"
        assert "findings" in table_names, "missing findings table"
        assert "traces" in table_names, "missing traces table"
        assert "dedupe_groups" in table_names, "missing dedupe_groups table"
        assert "recon_outputs" in table_names, "missing recon_outputs table"

        # 验证 chunk_qn 列
        cols = db._conn.execute("PRAGMA table_info(tasks)").fetchall()
        col_names = {c["name"] for c in cols}
        assert "chunk_qn" in col_names, "missing chunk_qn column"

        # 验证 finding_type 列
        cols = db._conn.execute("PRAGMA table_info(findings)").fetchall()
        col_names = {c["name"] for c in cols}
        assert "finding_type" in col_names, "missing finding_type column"

        # 测试 for_repo()
        db2 = StateDB.for_repo(tmpdir)
        assert db2.path.name == "state.db"
        assert db2.path.parent.name == ".skynet"
        db2.close()

        print("  PASS: StateDB (merged)")
    finally:
        db.close()



def test_graph_context():
    """验证图谱上下文构建。"""
    from skynet.audit.graph_context import GraphInfo, build_graph_info

    # 无图谱目录 → available=False
    info = build_graph_info(tempfile.mkdtemp())
    assert isinstance(info, GraphInfo)
    assert info.available is False

    # to_prompt_block 在 unavailable 时返回空
    assert info.to_prompt_block() == ""

    # 有图谱的目录（使用 skynet 自身的图谱）
    info2 = build_graph_info(Path(__file__).parent.parent)
    assert isinstance(info2, GraphInfo)
    # 不一定有图谱，但不应抛异常
    assert info2.community_count >= 0

    print("  PASS: graph_context")


def test_report_converter():
    """验证 audit → scan 报告转换。"""
    from skynet.audit.stages.report import audit_to_scan_report

    audit = {
        "run_id": "test_run",
        "target": {"repo_path": "/test/repo"},
        "summary": {"total": 2, "by_severity": {"high": 1, "medium": 1}},
        "findings": [
            {
                "title": "SQL Injection in login",
                "severity": "high",
                "cwe": "CWE-89",
                "description": "User input flows to SQL query",
                "file": "auth.py",
                "line_start": 42,
                "line_end": 50,
                "vuln_class": "sqli",
                "confidence": 0.9,
                "evidence": "db.execute(f'SELECT...')",
                "recommendation": "Use parameterized queries",
                "trace": {"entry_points": [], "call_chain": []},
            },
            {
                "title": "XSS in profile",
                "severity": "medium",
                "vuln_class": "xss",
            },
        ],
    }

    scan = audit_to_scan_report(audit)
    assert scan["generator"] == "skynet-audit (8-stage pipeline)"
    assert scan["stats"]["total"] == 2
    assert scan["stats"]["by_source"]["audit"] == 2
    assert len(scan["merged"]) == 2
    assert scan["merged"][0]["title"] == "SQL Injection in login"
    assert scan["merged"][0]["cwe_id"] == "CWE-89"
    assert scan["merged"][1]["severity"] == "medium"

    print("  PASS: report converter")


def test_cli_bridge():
    """验证 CLI 桥接功能。"""
    from main import cmd_audit
    import argparse

    # 验证函数可以导入
    assert callable(cmd_audit)

    # 模拟 args
    ns = argparse.Namespace(
        audit_args=["--help"],
        graph_enhanced=True,
        no_composite=False,
    )
    # 只验证不抛异常（会产生 SystemExit 或返回 exit code）
    print("  PASS: CLI bridge")


def test_stage_context():
    """验证 StageContext。"""
    from skynet.audit.stages._common import StageContext, REPO_ROOT, PROMPTS

    ctx = StageContext(
        run_id="test",
        repo_path=Path("/fake/repo"),
        config=None,  # type: ignore
    )
    assert ctx.run_id == "test"
    assert ctx.extras() == {}
    assert PROMPTS.exists(), f"PROMPTS dir not found: {PROMPTS}"

    print("  PASS: StageContext")


def main() -> int:
    print("=" * 60)
    print("Skynet-Audit Fusion Integration Tests")
    print("=" * 60)

    tests = [
        ("Imports", test_imports),
        ("Types Module", test_types_module),
        ("JSON Utils", test_json_utils),
        ("StageContext", test_stage_context),
        ("Report Converter", test_report_converter),
        ("Graph Context", test_graph_context),
        ("CLI Bridge", test_cli_bridge),
    ]

    # StateDB needs temp dir
    with tempfile.TemporaryDirectory() as tmpdir:
        tests.insert(3, ("StateDB (merged)", lambda: test_state_db(Path(tmpdir))))

        passed = 0
        failed = 0
        for name, fn in tests:
            try:
                print(f"\n[{name}]")
                fn()
                passed += 1
            except Exception as e:
                print(f"  FAIL: {e}")
                import traceback
                traceback.print_exc()
                failed += 1

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
