#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""漏洞模式知识库单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.knowledge.external.vuln_knowledge import (
    VulnPatternRetriever,
    VulnPattern,
    get_vuln_pattern_retriever,
    _SINK_TO_VULN_MAP,
)


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def test_data_loaded():
    """漏洞模式数据正确加载。"""
    retriever = VulnPatternRetriever()
    assert retriever.is_loaded() is True
    ids = retriever.get_all_vuln_ids()
    assert len(ids) == 13, f"应有 13 种漏洞类型，实际 {len(ids)}"
    ok(f"加载 {len(ids)} 种漏洞模式")


def test_retrieve_by_sink_type():
    """根据 sink 类型检索返回对应知识。"""
    retriever = VulnPatternRetriever()

    # SQL 注入
    results = retriever.retrieve("sql_execute")
    assert len(results) > 0, "sql_execute 应返回结果"
    assert results[0].id == "vuln_sql_injection"
    assert "SQL Injection" in results[0].title

    # 命令注入
    results = retriever.retrieve("os_system")
    assert len(results) > 0
    assert results[0].id == "vuln_command_injection"

    # XSS
    results = retriever.retrieve("innerHTML")
    assert len(results) > 0
    assert results[0].id == "vuln_xss"
    ok("按 sink 类型检索正确")


def test_retrieve_unknown_sink():
    """未知 sink 类型返回空列表。"""
    retriever = VulnPatternRetriever()
    results = retriever.retrieve("unknown_sink_type")
    assert results == []
    ok("未知 sink 返回空列表")


def test_vuln_pattern_structure():
    """VulnPattern 数据结构正确。"""
    retriever = VulnPatternRetriever()
    results = retriever.retrieve("eval")
    assert len(results) > 0

    pattern = results[0]
    assert isinstance(pattern, VulnPattern)
    assert pattern.id == "vuln_code_injection"
    assert len(pattern.cwe_ids) > 0
    assert "CWE-94" in pattern.cwe_ids
    assert len(pattern.owasp_ids) > 0
    assert len(pattern.dangerous_patterns) > 0
    assert len(pattern.safe_patterns) > 0
    assert len(pattern.payloads) > 0
    assert pattern.remediation != ""
    ok("VulnPattern 结构正确")


def test_get_context_for_prompt():
    """prompt 上下文格式正确。"""
    retriever = VulnPatternRetriever()
    context = retriever.get_context_for_prompt("sql_execute")

    assert "Vulnerability Pattern Knowledge" in context
    assert "SQL Injection" in context
    assert "Dangerous Patterns" in context
    assert "Safe Patterns" in context
    assert "Remediation" in context
    assert "CWE-89" in context
    ok("prompt 上下文格式正确")


def test_get_context_unknown():
    """未知 sink 返回空字符串。"""
    retriever = VulnPatternRetriever()
    context = retriever.get_context_for_prompt("unknown")
    assert context == ""
    ok("未知 sink prompt 上下文为空")


def test_sink_to_vuln_map_coverage():
    """sink 映射覆盖主要漏洞类型。"""
    # 检查主要 sink 类型都有映射
    expected_sinks = [
        "sql_execute", "eval", "os_system", "http_request",
        "file_open", "innerHTML", "redirect", "pickle_load",
    ]
    for sink in expected_sinks:
        assert sink in _SINK_TO_VULN_MAP, f"sink '{sink}' 缺少映射"
    ok(f"sink 映射覆盖 {len(_SINK_TO_VULN_MAP)} 种类型")


def test_all_vuln_types_have_data():
    """所有 13 种漏洞类型都有完整数据。"""
    retriever = VulnPatternRetriever()
    for vuln_id in retriever.get_all_vuln_ids():
        pattern = retriever._get_pattern(vuln_id)
        assert pattern is not None, f"漏洞 {vuln_id} 数据缺失"
        assert pattern.title != "", f"漏洞 {vuln_id} 缺少标题"
        assert len(pattern.cwe_ids) > 0, f"漏洞 {vuln_id} 缺少 CWE"
        assert len(pattern.dangerous_patterns) > 0, f"漏洞 {vuln_id} 缺少危险模式"
    ok("所有 13 种漏洞类型数据完整")


def test_global_retriever():
    """全局检索器单例。"""
    r1 = get_vuln_pattern_retriever()
    r2 = get_vuln_pattern_retriever()
    assert r1 is r2
    ok("全局检索器单例正确")


def main():
    print("=" * 60)
    print("漏洞模式知识库测试")
    print("=" * 60)

    test_data_loaded()
    test_retrieve_by_sink_type()
    test_retrieve_unknown_sink()
    test_vuln_pattern_structure()
    test_get_context_for_prompt()
    test_get_context_unknown()
    test_sink_to_vuln_map_coverage()
    test_all_vuln_types_have_data()
    test_global_retriever()

    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
