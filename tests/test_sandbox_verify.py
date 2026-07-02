#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""沙箱 PoC 验证单元测试。"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.verify.sandbox import SandboxManager, SandboxConfig, SandboxResult
from skynet.verify.harness import HarnessGenerator, HarnessTemplate, _HARNESS_TEMPLATES
from skynet.verify.verifier import (
    SandboxVerifier, VerifyResult, VerifyConfig, VerifyStatus,
    _SINK_TO_VULN_TYPE,
)


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


# ─────────────────────────────────────────────
# SandboxManager 测试
# ─────────────────────────────────────────────

def test_sandbox_not_available():
    """Docker 不可用时 graceful degradation。"""
    manager = SandboxManager()

    with patch("shutil.which", return_value=None):
        manager._docker_available = None
        assert manager.is_available() is False
    ok("Docker 不可用时返回 False")


def test_sandbox_result():
    """SandboxResult 数据结构正确。"""
    result = SandboxResult(
        success=True,
        stdout="[VULNERABLE] SQL injection",
        stderr="",
        exit_code=0,
        elapsed_seconds=1.5,
    )
    assert result.success is True
    assert result.timed_out is False

    timeout_result = SandboxResult(
        success=False,
        error="Execution timeout after 30s",
    )
    assert timeout_result.timed_out is True
    ok("SandboxResult 结构正确")


def test_sandbox_config_defaults():
    """SandboxConfig 默认配置正确。"""
    config = SandboxConfig()
    assert config.memory_limit == "256m"
    assert config.network_mode == "none"
    assert config.timeout == 30
    assert "ALL" in config.cap_drop
    ok("SandboxConfig 默认配置正确")


# ─────────────────────────────────────────────
# HarnessGenerator 测试
# ─────────────────────────────────────────────

def test_harness_generator_types():
    """HarnessGenerator 支持多种漏洞类型。"""
    gen = HarnessGenerator()
    types = gen.get_supported_types()

    assert "sql_injection" in types
    assert "command_injection" in types
    assert "xss" in types
    assert "path_traversal" in types
    assert "ssrf" in types
    ok(f"支持 {len(types)} 种漏洞类型")


def test_harness_generate_python():
    """生成 Python Harness 代码。"""
    gen = HarnessGenerator()
    code = gen.generate("sql_injection", language="python")

    assert code is not None
    assert "SQL Injection" in code
    assert "def test_sql_injection" in code
    assert "payloads" in code
    ok("Python SQL 注入 Harness 生成正确")


def test_harness_generate_javascript():
    """生成 JavaScript Harness 代码。"""
    gen = HarnessGenerator()
    code = gen.generate("sql_injection", language="javascript")

    assert code is not None
    assert "SQL Injection" in code or "payload" in code.lower()
    ok("JavaScript Harness 生成正确")


def test_harness_generate_unknown():
    """未知漏洞类型返回 None。"""
    gen = HarnessGenerator()
    code = gen.generate("unknown_vuln_type")
    assert code is None
    ok("未知漏洞类型返回 None")


def test_harness_has_template():
    """has_template 正确检查模板存在性。"""
    gen = HarnessGenerator()

    assert gen.has_template("sql_injection", "python") is True
    assert gen.has_template("sql_injection", "javascript") is True
    assert gen.has_template("unknown_type", "python") is False
    ok("has_template 检查正确")


def test_harness_get_languages():
    """获取指定漏洞类型支持的语言。"""
    gen = HarnessGenerator()
    langs = gen.get_supported_languages("sql_injection")
    assert "python" in langs
    assert "javascript" in langs
    ok(f"sql_injection 支持语言: {langs}")


def test_harness_custom_payloads():
    """自定义载荷注入。"""
    gen = HarnessGenerator()
    custom = ["custom_payload_1", "custom_payload_2"]
    code = gen.generate("sql_injection", "python", custom_payloads=custom)

    assert code is not None
    assert "custom_payload_1" in code
    assert "custom_payload_2" in code
    ok("自定义载荷注入正确")


# ─────────────────────────────────────────────
# SandboxVerifier 测试
# ─────────────────────────────────────────────

def test_verifier_not_available():
    """验证器不可用时返回 SKIPPED。"""
    config = VerifyConfig(enabled=False)
    verifier = SandboxVerifier(config)
    assert verifier.is_available() is False
    ok("禁用时 is_available 返回 False")


@pytest.mark.asyncio
async def test_verify_flow_skipped():
    """Docker 不可用时 verify_flow 返回 SKIPPED。"""
    config = VerifyConfig(enabled=True)
    verifier = SandboxVerifier(config)

    with patch.object(verifier._sandbox, "is_available", return_value=False):
        flow = {"sink_type": "sql_execute", "vuln_type": "sql_injection"}
        result = await verifier.verify_flow(flow)
        assert result.status == VerifyStatus.SKIPPED
    ok("Docker 不可用时返回 SKIPPED")


@pytest.mark.asyncio
async def test_verify_flow_unknown_sink():
    """未知 sink 类型返回 SKIPPED。"""
    config = VerifyConfig(enabled=True)
    verifier = SandboxVerifier(config)

    with patch.object(verifier._sandbox, "is_available", return_value=True):
        flow = {"sink_type": "unknown_sink"}
        result = await verifier.verify_flow(flow)
        assert result.status == VerifyStatus.SKIPPED
    ok("未知 sink 返回 SKIPPED")


def test_verify_result():
    """VerifyResult 数据结构正确。"""
    result = VerifyResult(
        status=VerifyStatus.CONFIRMED,
        vuln_type="sql_injection",
        confidence=0.9,
        evidence="[VULNERABLE] SQL injection successful",
    )
    assert result.is_confirmed is True
    assert result.confidence == 0.9
    ok("VerifyResult 结构正确")


def test_sink_to_vuln_type_map():
    """sink 到漏洞类型映射正确。"""
    assert _SINK_TO_VULN_TYPE["sql_execute"] == "sql_injection"
    assert _SINK_TO_VULN_TYPE["os_system"] == "command_injection"
    assert _SINK_TO_VULN_TYPE["innerHTML"] == "xss"
    assert _SINK_TO_VULN_TYPE["file_open"] == "path_traversal"
    assert _SINK_TO_VULN_TYPE["http_request"] == "ssrf"
    ok("sink 映射正确")


def test_verifier_get_summary():
    """验证摘要正确生成。"""
    config = VerifyConfig(enabled=False)
    verifier = SandboxVerifier(config)

    results = [
        VerifyResult(status=VerifyStatus.CONFIRMED, vuln_type="sql_injection", confidence=0.9),
        VerifyResult(status=VerifyStatus.UNCONFIRMED, vuln_type="xss", confidence=0.4),
        VerifyResult(status=VerifyStatus.ERROR, vuln_type="ssrf", confidence=0.0, error="timeout"),
        VerifyResult(status=VerifyStatus.SKIPPED, vuln_type="path_traversal", confidence=0.5),
    ]

    summary = verifier.get_summary(results)
    assert summary["total"] == 4
    assert summary["confirmed"] == 1
    assert summary["unconfirmed"] == 1
    assert summary["errors"] == 1
    assert summary["skipped"] == 1
    ok("验证摘要正确")


def test_analyze_result_confirmed():
    """分析结果：确认漏洞。"""
    config = VerifyConfig(enabled=False)
    verifier = SandboxVerifier(config)

    sandbox_result = SandboxResult(
        success=True,
        stdout="[VULNERABLE] SQL injection successful\nQuery: SELECT...",
        exit_code=0,
        elapsed_seconds=1.0,
    )

    result = verifier._analyze_result("sql_injection", "code...", sandbox_result, 1.0)
    assert result.status == VerifyStatus.CONFIRMED
    assert result.confidence == 0.9
    ok("确认漏洞分析正确")


def test_analyze_result_unconfirmed():
    """分析结果：无法确认。"""
    config = VerifyConfig(enabled=False)
    verifier = SandboxVerifier(config)

    sandbox_result = SandboxResult(
        success=True,
        stdout="Some output without markers",
        exit_code=0,
        elapsed_seconds=1.0,
    )

    result = verifier._analyze_result("sql_injection", "code...", sandbox_result, 1.0)
    assert result.status == VerifyStatus.UNCONFIRMED
    assert result.confidence == 0.4
    ok("无法确认分析正确")


def test_analyze_result_timeout():
    """分析结果：超时。"""
    config = VerifyConfig(enabled=False)
    verifier = SandboxVerifier(config)

    sandbox_result = SandboxResult(
        success=False,
        error="Execution timeout after 30s",
        elapsed_seconds=30.0,
    )

    result = verifier._analyze_result("sql_injection", "code...", sandbox_result, 30.0)
    assert result.status == VerifyStatus.TIMEOUT
    ok("超时分析正确")


def main():
    print("=" * 60)
    print("沙箱 PoC 验证测试")
    print("=" * 60)

    # SandboxManager
    test_sandbox_not_available()
    test_sandbox_result()
    test_sandbox_config_defaults()

    # HarnessGenerator
    test_harness_generator_types()
    test_harness_generate_python()
    test_harness_generate_javascript()
    test_harness_generate_unknown()
    test_harness_has_template()
    test_harness_get_languages()
    test_harness_custom_payloads()

    # SandboxVerifier
    test_verifier_not_available()
    asyncio.run(test_verify_flow_skipped())
    asyncio.run(test_verify_flow_unknown_sink())
    test_verify_result()
    test_sink_to_vuln_type_map()
    test_verifier_get_summary()
    test_analyze_result_confirmed()
    test_analyze_result_unconfirmed()
    test_analyze_result_timeout()

    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
