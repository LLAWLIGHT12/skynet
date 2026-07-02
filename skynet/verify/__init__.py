"""沙箱 PoC 验证模块。

对 taint 追踪发现的高危 flow，在 Docker 沙箱中生成并执行
Fuzzing Harness 验证漏洞真实性。Docker 不可用时静默跳过。
"""

from skynet.verify.sandbox import SandboxManager, SandboxConfig, SandboxResult
from skynet.verify.harness import HarnessGenerator, HarnessTemplate
from skynet.verify.verifier import SandboxVerifier, VerifyResult, VerifyConfig

__all__ = [
    "SandboxManager",
    "SandboxConfig",
    "SandboxResult",
    "HarnessGenerator",
    "HarnessTemplate",
    "SandboxVerifier",
    "VerifyResult",
    "VerifyConfig",
]
