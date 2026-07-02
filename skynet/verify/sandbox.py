"""Docker 沙箱管理器 — 安全隔离的代码执行环境。

提供受限的 Docker 容器用于执行 PoC 验证代码，
包含内存限制、CPU 限制、网络隔离等安全配置。
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """沙箱配置。"""
    # 容器配置
    image: str = "python:3.11-slim"
    memory_limit: str = "256m"
    cpu_quota: int = 50000  # 50% of one CPU
    network_mode: str = "none"  # 禁用网络
    timeout: int = 30  # 执行超时（秒）

    # 安全配置
    cap_drop: List[str] = field(default_factory=lambda: [
        "ALL",  # 丢弃所有 capabilities
    ])
    no_new_privileges: bool = True
    read_only: bool = True

    # 工作目录
    work_dir: str = "/workspace"


@dataclass
class SandboxResult:
    """沙箱执行结果。"""
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    elapsed_seconds: float = 0.0
    error: Optional[str] = None
    container_id: Optional[str] = None

    @property
    def timed_out(self) -> bool:
        return self.error is not None and "timeout" in self.error.lower()


class SandboxManager:
    """Docker 沙箱管理器。

    用法::

        manager = SandboxManager()
        if manager.is_available():
            result = await manager.execute("print('hello')")
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._docker_available: Optional[bool] = None

    def is_available(self) -> bool:
        """检测 Docker 是否可用。"""
        if self._docker_available is not None:
            return self._docker_available

        docker_path = shutil.which("docker")
        if docker_path is None:
            self._docker_available = False
            logger.debug("Docker not found in PATH")
            return False

        # 检查 docker info
        try:
            import subprocess
            proc = subprocess.run(
                ["docker", "info"],
                capture_output=True, timeout=5,
            )
            self._docker_available = proc.returncode == 0
        except Exception:
            self._docker_available = False

        return self._docker_available

    async def execute(
        self,
        code: str,
        language: str = "python",
        extra_files: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """在沙箱中执行代码。

        Args:
            code: 要执行的代码。
            language: 编程语言（python/php/js/go/java/bash）。
            extra_files: 额外文件 {文件名: 内容}。

        Returns:
            SandboxResult 执行结果。
        """
        if not self.is_available():
            return SandboxResult(
                success=False,
                error="Docker not available",
            )

        # 构建执行命令
        cmd, filename = self._get_command(code, language)

        # 构建 docker run 命令
        docker_cmd = self._build_docker_cmd(cmd, filename, code, extra_files)

        start_time = time.time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.config.timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = time.time() - start_time
                return SandboxResult(
                    success=False,
                    error=f"Execution timeout after {self.config.timeout}s",
                    elapsed_seconds=elapsed,
                )

            elapsed = time.time() - start_time
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            return SandboxResult(
                success=proc.returncode == 0,
                stdout=stdout_str,
                stderr=stderr_str,
                exit_code=proc.returncode,
                elapsed_seconds=elapsed,
            )

        except Exception as e:
            elapsed = time.time() - start_time
            return SandboxResult(
                success=False,
                error=str(e),
                elapsed_seconds=elapsed,
            )

    def _get_command(self, code: str, language: str) -> tuple[List[str], str]:
        """获取执行命令和文件名。"""
        commands = {
            "python": (["python", "/workspace/main.py"], "main.py"),
            "php": (["php", "/workspace/main.php"], "main.php"),
            "javascript": (["node", "/workspace/main.js"], "main.js"),
            "js": (["node", "/workspace/main.js"], "main.js"),
            "go": (["go", "run", "/workspace/main.go"], "main.go"),
            "java": (["java", "/workspace/Main.java"], "Main.java"),
            "bash": (["bash", "/workspace/main.sh"], "main.sh"),
            "ruby": (["ruby", "/workspace/main.rb"], "main.rb"),
        }

        if language not in commands:
            # 默认使用 Python
            return commands["python"]

        return commands[language]

    def _build_docker_cmd(
        self,
        cmd: List[str],
        filename: str,
        code: str,
        extra_files: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """构建 docker run 命令。"""
        docker_cmd = [
            "docker", "run", "--rm",
            "--memory", self.config.memory_limit,
            "--cpu-quota", str(self.config.cpu_quota),
            "--network", self.config.network_mode,
            "--read-only",
            "--security-opt", "no-new-privileges",
        ]

        # 添加 cap-drop
        for cap in self.config.cap_drop:
            docker_cmd.extend(["--cap-drop", cap])

        # 添加工作目录
        docker_cmd.extend(["-w", self.config.work_dir])

        # 镜像
        docker_cmd.append(self.config.image)

        # 使用 sh -c 写入文件并执行（安全转义单引号防止命令注入）
        def _shell_escape(s: str) -> str:
            return s.replace("'", "'\\''")

        safe_code = _shell_escape(code)
        safe_filename = _shell_escape(filename)
        write_cmd = f"echo '{safe_code}' > {self.config.work_dir}/{safe_filename}"
        if extra_files:
            for fname, content in extra_files.items():
                safe_fname = _shell_escape(fname)
                safe_content = _shell_escape(content)
                write_cmd += f" && echo '{safe_content}' > {self.config.work_dir}/{safe_fname}"

        exec_cmd = " ".join(cmd)
        full_cmd = f"{write_cmd} && {exec_cmd}"

        docker_cmd.extend(["sh", "-c", full_cmd])

        return docker_cmd

    async def cleanup(self) -> None:
        """清理残留容器（如有）。"""
        # 由于使用 --rm，容器会自动清理
        pass
