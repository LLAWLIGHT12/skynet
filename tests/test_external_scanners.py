#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""外部安全扫描工具集成单元测试。"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.tools.external_scanners import (
    ExternalScanner,
    ExternalScannerConfig,
    ScannerResult,
)


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def test_is_available_mock():
    """is_available 正确检测工具可用性。"""
    scanner = ExternalScanner()

    with patch("shutil.which") as mock_which:
        mock_which.return_value = "/usr/bin/semgrep"
        assert scanner.is_available("semgrep") is True

        mock_which.return_value = None
        scanner._availability_cache.clear()
        assert scanner.is_available("semgrep") is False

    ok("is_available 检测正确")


def test_is_available_cache():
    """is_available 结果被缓存。"""
    scanner = ExternalScanner()

    with patch("shutil.which") as mock_which:
        mock_which.return_value = "/usr/bin/semgrep"
        scanner.is_available("semgrep")
        scanner.is_available("semgrep")
        # 应该只调用一次 which
        assert mock_which.call_count == 1

    ok("is_available 缓存正确")


def test_scanner_result():
    """ScannerResult 数据结构正确。"""
    result = ScannerResult(
        tool="semgrep",
        success=True,
        findings=[
            {"tool": "semgrep", "rule_id": "test", "message": "test finding"},
        ],
    )
    assert result.finding_count == 1
    assert result.tool == "semgrep"
    assert result.success is True
    ok("ScannerResult 结构正确")


def test_parse_semgrep_findings():
    """Semgrep 输出解析正确。"""
    scanner = ExternalScanner()
    data = {
        "results": [
            {
                "check_id": "python.sql-injection",
                "extra": {
                    "message": "SQL injection detected",
                    "severity": "ERROR",
                    "lines": "cursor.execute(f'SELECT...')",
                },
                "path": "app/views.py",
                "start": {"line": 42},
            }
        ]
    }

    findings = scanner._parse_findings("semgrep", data)
    assert len(findings) == 1
    assert findings[0]["tool"] == "semgrep"
    assert findings[0]["rule_id"] == "python.sql-injection"
    assert findings[0]["file"] == "app/views.py"
    assert findings[0]["line"] == 42
    assert findings[0]["severity"] == "ERROR"
    ok("Semgrep 解析正确")


def test_parse_bandit_findings():
    """Bandit 输出解析正确。"""
    scanner = ExternalScanner()
    data = {
        "results": [
            {
                "test_id": "B101",
                "issue_text": "Use of eval detected",
                "issue_severity": "HIGH",
                "filename": "app/utils.py",
                "line_number": 10,
                "code": "eval(user_input)",
                "issue_cwe": {"id": "CWE-94"},
            }
        ]
    }

    findings = scanner._parse_findings("bandit", data)
    assert len(findings) == 1
    assert findings[0]["tool"] == "bandit"
    assert findings[0]["rule_id"] == "B101"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["cwe"] == "CWE-94"
    ok("Bandit 解析正确")


def test_parse_gitleaks_findings():
    """Gitleaks 输出解析正确。"""
    scanner = ExternalScanner()
    data = [
        {
            "RuleID": "aws-access-key-id",
            "Description": "AWS Access Key ID",
            "File": "config.py",
            "StartLine": 5,
            "Line": "AWS_KEY = 'AKIA...'",
            "Commit": "abc123",
        }
    ]

    findings = scanner._parse_findings("gitleaks", data)
    assert len(findings) == 1
    assert findings[0]["tool"] == "gitleaks"
    assert findings[0]["rule_id"] == "aws-access-key-id"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["commit"] == "abc123"
    ok("Gitleaks 解析正确")


@pytest.mark.asyncio
async def test_run_all_disabled():
    """配置禁用时 run_all 返回空列表。"""
    config = ExternalScannerConfig(enabled=False)
    scanner = ExternalScanner(config)
    results = await scanner.run_all("/tmp/test")
    assert results == []
    ok("禁用时 run_all 返回空")


@pytest.mark.asyncio
async def test_run_all_no_tools():
    """无可用工具时返回空列表。"""
    config = ExternalScannerConfig(enabled=True, tools=["nonexistent_tool"])
    scanner = ExternalScanner(config)
    results = await scanner.run_all("/tmp/test")
    assert results == []
    ok("无可用工具时返回空")


def test_get_summary():
    """扫描摘要正确生成。"""
    scanner = ExternalScanner()
    results = [
        ScannerResult(
            tool="semgrep", success=True,
            findings=[
                {"severity": "HIGH"},
                {"severity": "MEDIUM"},
                {"severity": "HIGH"},
            ],
        ),
        ScannerResult(
            tool="bandit", success=True,
            findings=[
                {"severity": "LOW"},
            ],
        ),
        ScannerResult(
            tool="gitleaks", success=False,
            error="not installed",
        ),
    ]

    summary = scanner.get_summary(results)
    assert summary["total_findings"] == 4
    assert "semgrep" in summary["tools_run"]
    assert "bandit" in summary["tools_run"]
    assert "gitleaks" in summary["tools_failed"]
    assert summary["by_severity"]["HIGH"] == 2
    assert summary["by_severity"]["MEDIUM"] == 1
    assert summary["by_severity"]["LOW"] == 1
    ok("扫描摘要正确")


def test_count_by_severity():
    """按严重程度统计正确。"""
    scanner = ExternalScanner()
    results = [
        ScannerResult(
            tool="semgrep", success=True,
            findings=[
                {"severity": "CRITICAL"},
                {"severity": "HIGH"},
                {"severity": "high"},  # 小写
                {"severity": "UNKNOWN"},  # 未知 -> MEDIUM
            ],
        ),
    ]

    counts = scanner._count_by_severity(results)
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 2  # HIGH + high
    assert counts["MEDIUM"] == 1  # UNKNOWN -> MEDIUM
    ok("严重程度统计正确")


def test_config_defaults():
    """默认配置正确。"""
    config = ExternalScannerConfig()
    assert config.enabled is False
    assert "semgrep" in config.tools
    assert "bandit" in config.tools
    assert "gitleaks" in config.tools
    assert config.timeout == 120
    ok("默认配置正确")


def main():
    print("=" * 60)
    print("外部安全扫描工具测试")
    print("=" * 60)

    test_is_available_mock()
    test_is_available_cache()
    test_scanner_result()
    test_parse_semgrep_findings()
    test_parse_bandit_findings()
    test_parse_gitleaks_findings()
    asyncio.run(test_run_all_disabled())
    asyncio.run(test_run_all_no_tools())
    test_get_summary()
    test_count_by_severity()
    test_config_defaults()

    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
