"""外部安全扫描工具集成 — 作为 LLM 分析的补充信号。

支持 Semgrep / Bandit / Gitleaks 等外部工具，
工具不可用时静默跳过（graceful degradation）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScannerResult:
    """单个扫描工具的结果。"""
    tool: str
    success: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_seconds: float = 0.0

    @property
    def finding_count(self) -> int:
        return len(self.findings)


@dataclass
class ExternalScannerConfig:
    """外部扫描器配置。"""
    enabled: bool = False
    tools: List[str] = field(default_factory=lambda: ["semgrep", "bandit", "gitleaks"])
    timeout: int = 120  # 每个工具的超时时间（秒）
    semgrep_config: str = "auto"  # Semgrep 规则集


class ExternalScanner:
    """外部安全扫描工具管理器。

    用法::

        scanner = ExternalScanner()
        if scanner.is_available("semgrep"):
            result = await scanner.run_semgrep("/path/to/project")
        # 或一次性运行所有工具
        all_results = await scanner.run_all("/path/to/project")
    """

    def __init__(self, config: Optional[ExternalScannerConfig] = None):
        self.config = config or ExternalScannerConfig()
        self._availability_cache: Dict[str, bool] = {}

    def is_available(self, tool: str) -> bool:
        """检测工具是否已安装。

        除系统 PATH 外，还会检查当前 Python 虚拟环境的 Scripts/bin 目录。
        """
        if tool in self._availability_cache:
            return self._availability_cache[tool]

        available = shutil.which(tool) is not None

        # 额外检查 venv 的 Scripts/bin 目录
        if not available:
            import sys
            venv_bin = os.path.dirname(sys.executable)
            if venv_bin:
                candidate = os.path.join(venv_bin, tool)
                if os.name == "nt":
                    candidate += ".exe"
                if os.path.isfile(candidate):
                    available = True
                    logger.debug("Found '%s' in venv: %s", tool, candidate)

        self._availability_cache[tool] = available

        if not available:
            logger.debug("External tool '%s' not found in PATH or venv", tool)

        return available

    def _resolve_tool_path(self, tool: str) -> str:
        """解析工具的可执行文件路径（优先 venv）。"""
        import sys
        venv_bin = os.path.dirname(sys.executable)
        if venv_bin:
            candidate = os.path.join(venv_bin, tool)
            if os.name == "nt":
                candidate += ".exe"
            if os.path.isfile(candidate):
                return candidate
        return shutil.which(tool) or tool

    async def run_semgrep(self, target_dir: str) -> ScannerResult:
        """运行 Semgrep 静态分析。"""
        if not self.is_available("semgrep"):
            return ScannerResult(tool="semgrep", success=False, error="semgrep not installed")

        cmd = [
            self._resolve_tool_path("semgrep"),
            "--json",
            "--config", self.config.semgrep_config,
            "--quiet",
            target_dir,
        ]

        return await self._run_tool("semgrep", cmd, target_dir)

    async def run_bandit(self, target_dir: str) -> ScannerResult:
        """运行 Bandit Python 安全扫描。"""
        if not self.is_available("bandit"):
            return ScannerResult(tool="bandit", success=False, error="bandit not installed")

        cmd = [
            self._resolve_tool_path("bandit"),
            "-f", "json",
            "-r",
            "--quiet",
            target_dir,
        ]

        return await self._run_tool("bandit", cmd, target_dir)

    async def run_gitleaks(self, target_dir: str) -> ScannerResult:
        """运行 Gitleaks 密钥泄露检测。"""
        if not self.is_available("gitleaks"):
            return ScannerResult(tool="gitleaks", success=False, error="gitleaks not installed")

        output_file = os.path.join(target_dir, ".gitleaks_report.json")
        cmd = [
            self._resolve_tool_path("gitleaks"),
            "detect",
            "--source", target_dir,
            "--report-format", "json",
            "--report-path", output_file,
            "--no-git",
            "--quiet",
        ]

        result = await self._run_tool("gitleaks", cmd, target_dir, output_file=output_file)

        # 清理临时文件
        try:
            if os.path.exists(output_file):
                os.remove(output_file)
        except OSError as e:
            logger.warning("临时文件清理失败: {}", e)

        return result

    async def run_all(self, target_dir: str) -> List[ScannerResult]:
        """并发运行所有已配置且可用的工具。"""
        if not self.config.enabled:
            logger.info("External scanner disabled by config")
            return []

        tasks = []
        tool_map = {
            "semgrep": self.run_semgrep,
            "bandit": self.run_bandit,
            "gitleaks": self.run_gitleaks,
        }

        for tool_name in self.config.tools:
            if tool_name in tool_map and self.is_available(tool_name):
                tasks.append(tool_map[tool_name](target_dir))
            else:
                logger.debug("Skipping unavailable tool: %s", tool_name)

        if not tasks:
            logger.warning("No external scanner tools available")
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                tool_name = self.config.tools[i] if i < len(self.config.tools) else "unknown"
                final_results.append(ScannerResult(
                    tool=tool_name, success=False, error=str(result)
                ))
            else:
                final_results.append(result)

        return final_results

    async def _run_tool(
        self,
        tool_name: str,
        cmd: List[str],
        target_dir: str,
        output_file: Optional[str] = None,
    ) -> ScannerResult:
        """运行外部工具并解析结果。"""
        import time
        start_time = time.time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=target_dir,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.config.timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                elapsed = time.time() - start_time
                return ScannerResult(
                    tool=tool_name, success=False,
                    error=f"Timeout after {self.config.timeout}s",
                    elapsed_seconds=elapsed,
                )

            elapsed = time.time() - start_time

            # 解析结果
            findings = []
            if output_file and os.path.exists(output_file):
                # 从文件读取结果（如 gitleaks）
                try:
                    with open(output_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    findings = self._parse_findings(tool_name, data)
                except Exception as e:
                    logger.warning("Failed to parse %s output file: %s", tool_name, e)
            elif stdout:
                # 从 stdout 解析结果
                try:
                    data = json.loads(stdout.decode("utf-8", errors="replace"))
                    findings = self._parse_findings(tool_name, data)
                except json.JSONDecodeError:
                    # 某些工具返回非 JSON 格式
                    if stderr:
                        error_msg = stderr.decode("utf-8", errors="replace")[:500]
                        logger.warning("%s output not JSON: %s", tool_name, error_msg)

            # 检查退出码（某些工具用退出码表示发现数量）
            success = proc.returncode in (0, 1)  # semgrep/gitleaks 返回 1 表示有发现

            return ScannerResult(
                tool=tool_name,
                success=success,
                findings=findings,
                error=stderr.decode("utf-8", errors="replace")[:200] if stderr and proc.returncode != 0 else None,
                elapsed_seconds=elapsed,
            )

        except FileNotFoundError:
            return ScannerResult(
                tool=tool_name, success=False,
                error=f"Tool '{tool_name}' not found",
                elapsed_seconds=time.time() - start_time,
            )
        except Exception as e:
            return ScannerResult(
                tool=tool_name, success=False,
                error=str(e),
                elapsed_seconds=time.time() - start_time,
            )

    def _parse_findings(self, tool_name: str, data: Any) -> List[Dict[str, Any]]:
        """解析工具输出为标准格式。"""
        findings = []

        if tool_name == "semgrep":
            # Semgrep JSON 格式
            for result in data.get("results", []):
                findings.append({
                    "tool": "semgrep",
                    "rule_id": result.get("check_id", ""),
                    "message": result.get("extra", {}).get("message", ""),
                    "severity": result.get("extra", {}).get("severity", "WARNING"),
                    "file": result.get("path", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "code": result.get("extra", {}).get("lines", ""),
                })

        elif tool_name == "bandit":
            # Bandit JSON 格式
            for result in data.get("results", []):
                findings.append({
                    "tool": "bandit",
                    "rule_id": result.get("test_id", ""),
                    "message": result.get("issue_text", ""),
                    "severity": result.get("issue_severity", "MEDIUM"),
                    "file": result.get("filename", ""),
                    "line": result.get("line_number", 0),
                    "code": result.get("code", ""),
                    "cwe": result.get("issue_cwe", {}).get("id", ""),
                })

        elif tool_name == "gitleaks":
            # Gitleaks JSON 格式（数组）
            if isinstance(data, list):
                for result in data:
                    findings.append({
                        "tool": "gitleaks",
                        "rule_id": result.get("RuleID", ""),
                        "message": result.get("Description", ""),
                        "severity": "HIGH",
                        "file": result.get("File", ""),
                        "line": result.get("StartLine", 0),
                        "code": result.get("Line", ""),
                        "commit": result.get("Commit", ""),
                    })

        return findings

    def get_summary(self, results: List[ScannerResult]) -> Dict[str, Any]:
        """生成扫描结果摘要。"""
        total_findings = sum(r.finding_count for r in results)
        tools_run = [r.tool for r in results if r.success]
        tools_failed = [r.tool for r in results if not r.success]

        return {
            "total_findings": total_findings,
            "tools_run": tools_run,
            "tools_failed": tools_failed,
            "by_tool": {r.tool: r.finding_count for r in results},
            "by_severity": self._count_by_severity(results),
        }

    def _count_by_severity(self, results: List[ScannerResult]) -> Dict[str, int]:
        """按严重程度统计。"""
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for result in results:
            for finding in result.findings:
                severity = finding.get("severity", "MEDIUM").upper()
                if severity in counts:
                    counts[severity] += 1
                else:
                    counts["MEDIUM"] += 1
        return {k: v for k, v in counts.items() if v > 0}
