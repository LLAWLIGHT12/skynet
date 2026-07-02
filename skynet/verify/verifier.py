"""漏洞验证编排器 — 串联 taint 结果 → sandbox 验证。

接收 taint 追踪的 flow 结果，生成 Fuzzing Harness，
在 Docker 沙箱中执行验证，返回验证结果。
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from skynet.verify.sandbox import SandboxManager, SandboxConfig, SandboxResult
from skynet.verify.harness import HarnessGenerator

try:
    from skynet.tools.input_validator import ToolInputValidator, InputValidationError
    _VALIDATOR_AVAILABLE = True
except ImportError:
    _VALIDATOR_AVAILABLE = False
    InputValidationError = ValueError  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)


class VerifyStatus(str, Enum):
    """验证状态。"""
    CONFIRMED = "confirmed"          # 漏洞已确认
    UNCONFIRMED = "unconfirmed"      # 无法确认（可能误报）
    ERROR = "error"                  # 验证过程出错
    SKIPPED = "skipped"              # 跳过（Docker 不可用等）
    TIMEOUT = "timeout"              # 执行超时


@dataclass
class VerifyResult:
    """验证结果。"""
    status: VerifyStatus
    vuln_type: str
    confidence: float = 0.5  # 0.0 - 1.0
    evidence: str = ""
    harness_code: str = ""
    sandbox_output: str = ""
    elapsed_seconds: float = 0.0
    error: Optional[str] = None

    @property
    def is_confirmed(self) -> bool:
        return self.status == VerifyStatus.CONFIRMED


@dataclass
class VerifyConfig:
    """验证配置。"""
    enabled: bool = False
    auto_verify: bool = False  # 是否自动验证所有 flow
    min_severity: str = "high"  # 最低验证严重级别
    max_verifications: int = 10  # 单次扫描最大验证数
    sandbox_config: Optional[SandboxConfig] = None


# 漏洞类型关键词映射（从 taint sink 到 harness vuln_type）
_SINK_TO_VULN_TYPE: Dict[str, str] = {
    "sql_execute": "sql_injection",
    "db_query": "sql_injection",
    "raw_sql": "sql_injection",
    "os_system": "command_injection",
    "subprocess_call": "command_injection",
    "shell_exec": "command_injection",
    "eval": "command_injection",
    "innerHTML": "xss",
    "document_write": "xss",
    "render_html": "xss",
    "file_open": "path_traversal",
    "file_read": "path_traversal",
    "send_file": "path_traversal",
    "http_request": "ssrf",
    "url_fetch": "ssrf",
    "open_url": "ssrf",
}


class SandboxVerifier:
    """沙箱漏洞验证器。

    用法::

        verifier = SandboxVerifier()
        if verifier.is_available():
            result = await verifier.verify_flow(flow_data)
    """

    def __init__(self, config: Optional[VerifyConfig] = None, project_root: str = "."):
        self.config = config or VerifyConfig()
        sandbox_cfg = self.config.sandbox_config or SandboxConfig()
        self._sandbox = SandboxManager(sandbox_cfg)
        self._harness_gen = HarnessGenerator()
        self._validator: Optional[Any] = None
        if _VALIDATOR_AVAILABLE:
            try:
                self._validator = ToolInputValidator(project_root)
            except Exception as e:
                logger.debug("ToolInputValidator init failed: %s", e)

    def is_available(self) -> bool:
        """检测验证环境是否可用。"""
        return self.config.enabled and self._sandbox.is_available()

    async def verify_flow(self, flow: Dict[str, Any]) -> VerifyResult:
        """验证单个 taint flow。

        Args:
            flow: taint 追踪的 flow 数据，包含：
                - sink_type: sink 类型
                - vuln_type: 漏洞类型（可选，自动推断）
                - source_code: 源代码片段
                - payloads: 攻击载荷（可选）
                - file: 文件路径（可选，会进行校验）

        Returns:
            VerifyResult 验证结果。
        """
        start_time = time.time()

        if not self.is_available():
            return VerifyResult(
                status=VerifyStatus.SKIPPED,
                vuln_type=flow.get("vuln_type", "unknown"),
                error="Sandbox not available or verification disabled",
            )

        if self._validator is not None:
            file_path = flow.get("file", "")
            if file_path:
                try:
                    self._validator.validate_file_path(str(file_path))
                except InputValidationError as e:
                    return VerifyResult(
                        status=VerifyStatus.ERROR,
                        vuln_type=flow.get("vuln_type", "unknown"),
                        error=f"Input validation failed: {e}",
                    )

        # 确定漏洞类型
        vuln_type = flow.get("vuln_type") or self._infer_vuln_type(flow.get("sink_type", ""))
        if not vuln_type:
            return VerifyResult(
                status=VerifyStatus.SKIPPED,
                vuln_type="unknown",
                error=f"Cannot determine vuln type for sink: {flow.get('sink_type')}",
            )

        # 确定语言
        language = flow.get("language", "python")

        # 生成 Harness
        custom_payloads = flow.get("payloads")
        harness_code = self._harness_gen.generate(vuln_type, language, custom_payloads)

        if harness_code is None:
            return VerifyResult(
                status=VerifyStatus.SKIPPED,
                vuln_type=vuln_type,
                error=f"No harness template for {vuln_type}/{language}",
            )

        # 在沙箱中执行
        sandbox_result = await self._sandbox.execute(harness_code, language)
        elapsed = time.time() - start_time

        # 分析结果
        return self._analyze_result(vuln_type, harness_code, sandbox_result, elapsed)

    async def verify_flows(self, flows: List[Dict[str, Any]]) -> List[VerifyResult]:
        """批量验证多个 flow。"""
        if not self.is_available():
            return [
                VerifyResult(
                    status=VerifyStatus.SKIPPED,
                    vuln_type=f.get("vuln_type", "unknown"),
                    error="Sandbox not available",
                )
                for f in flows
            ]

        results = []
        for i, flow in enumerate(flows[:self.config.max_verifications]):
            result = await self.verify_flow(flow)
            results.append(result)
            logger.info(
                "Flow %d/%d: %s (%s)",
                i + 1, len(flows), result.status.value, result.vuln_type,
            )

        return results

    def _infer_vuln_type(self, sink_type: str) -> Optional[str]:
        """从 sink 类型推断漏洞类型。"""
        return _SINK_TO_VULN_TYPE.get(sink_type)

    def _analyze_result(
        self,
        vuln_type: str,
        harness_code: str,
        sandbox_result: SandboxResult,
        elapsed: float,
    ) -> VerifyResult:
        """分析沙箱执行结果。"""
        if sandbox_result.timed_out:
            return VerifyResult(
                status=VerifyStatus.TIMEOUT,
                vuln_type=vuln_type,
                harness_code=harness_code,
                error=sandbox_result.error,
                elapsed_seconds=elapsed,
            )

        if sandbox_result.error and not sandbox_result.stdout:
            return VerifyResult(
                status=VerifyStatus.ERROR,
                vuln_type=vuln_type,
                harness_code=harness_code,
                error=sandbox_result.error,
                elapsed_seconds=elapsed,
            )

        # 分析输出判断漏洞是否确认
        output = sandbox_result.stdout.lower()
        confirmed_markers = [
            "[vulnerable]",
            "injection successful",
            "injection detected",
            "traversal detected",
            "xss payload detected",
            "ssrf to internal",
            "command injection detected",
        ]

        is_confirmed = any(marker in output for marker in confirmed_markers)

        if is_confirmed:
            confidence = 0.9
            status = VerifyStatus.CONFIRMED
        elif sandbox_result.success:
            # 执行成功但未发现明确标记
            confidence = 0.4
            status = VerifyStatus.UNCONFIRMED
        else:
            # 执行失败
            confidence = 0.3
            status = VerifyStatus.UNCONFIRMED

        return VerifyResult(
            status=status,
            vuln_type=vuln_type,
            confidence=confidence,
            evidence=self._extract_evidence(sandbox_result.stdout),
            harness_code=harness_code,
            sandbox_output=sandbox_result.stdout[:1000],  # 限制输出大小
            elapsed_seconds=elapsed,
        )

    def _extract_evidence(self, output: str) -> str:
        """从输出中提取关键证据。"""
        lines = output.split("\n")
        evidence_lines = []
        for line in lines:
            line_lower = line.lower()
            if any(kw in line_lower for kw in ["vulnerable", "injection", "detected", "traversal"]):
                evidence_lines.append(line.strip())
        return "\n".join(evidence_lines[:5])  # 最多 5 行证据

    def get_summary(self, results: List[VerifyResult]) -> Dict[str, Any]:
        """生成验证摘要。"""
        confirmed = [r for r in results if r.status == VerifyStatus.CONFIRMED]
        unconfirmed = [r for r in results if r.status == VerifyStatus.UNCONFIRMED]
        errors = [r for r in results if r.status == VerifyStatus.ERROR]
        skipped = [r for r in results if r.status == VerifyStatus.SKIPPED]

        return {
            "total": len(results),
            "confirmed": len(confirmed),
            "unconfirmed": len(unconfirmed),
            "errors": len(errors),
            "skipped": len(skipped),
            "by_type": {r.vuln_type: r.status.value for r in results},
            "avg_confidence": sum(r.confidence for r in results) / len(results) if results else 0,
        }
