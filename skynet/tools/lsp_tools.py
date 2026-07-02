"""LSP 工具封装（基于 Microsoft multilspy）。"""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from loguru import logger

from skynet.config import LSPConfig, get_config


def ensure_lsp_on_path() -> None:
    """Windows/conda 下 jedi-language-server 常在 Scripts 目录。"""
    exe = Path(sys.executable).resolve()
    candidates = [
        exe.parent / "Scripts",
        exe.parent / "bin",
    ]
    extra: list[str] = []
    for d in candidates:
        if d.is_dir():
            extra.append(str(d))
    if extra:
        current = os.environ.get("PATH", "")
        prefix = os.pathsep.join(extra)
        if not any(p.lower() in current.lower() for p in extra):
            os.environ["PATH"] = prefix + os.pathsep + current


def detect_code_language(repo_root: Path, override: str = "") -> str:
    """从配置或仓库文件推断 multilspy 语言。"""
    if override:
        return override.lower()

    root = repo_root.resolve()
    markers = [
        ("python", ["pyproject.toml", "setup.py", "requirements.txt"]),
        ("typescript", ["tsconfig.json"]),
        ("javascript", ["package.json"]),
        ("java", ["pom.xml", "build.gradle"]),
        ("go", ["go.mod"]),
        ("rust", ["Cargo.toml"]),
        ("csharp", []),  # detected via *.csproj below
        ("kotlin", ["build.gradle.kts"]),
        ("ruby", ["Gemfile"]),
        ("dart", ["pubspec.yaml"]),
    ]
    for lang, files in markers:
        for name in files:
            if (root / name).exists():
                return lang
    if list(root.rglob("*.csproj")):
        return "csharp"
    if list(root.rglob("*.py")):
        return "python"
    if list(root.rglob("*.ts")):
        return "typescript"
    if list(root.rglob("*.js")):
        return "javascript"
    return "python"


def relative_file_path(repo_root: Path, file_path: str) -> str:
    p = Path(file_path)
    root = repo_root.resolve()
    if p.is_absolute():
        try:
            return p.relative_to(root).as_posix()
        except ValueError:
            return p.name
    return p.as_posix()


def lsp_line(node_line_start: int) -> int:
    """图谱行号 (1-based) → LSP line (0-based)。"""
    return max((node_line_start or 1) - 1, 0)


def find_symbol_column(line_text: str, symbol: str) -> int:
    if not line_text or not symbol:
        return 0
    idx = line_text.find(symbol)
    return idx if idx >= 0 else 0


def format_locations(locations: list[dict[str, Any]], limit: int = 12) -> str:
    if not locations:
        return "(no locations)"
    lines: list[str] = []
    for loc in locations[:limit]:
        rel = loc.get("relativePath") or loc.get("relative_path") or loc.get("uri", "")
        rng = loc.get("range") or {}
        start = rng.get("start") or {}
        line = int(start.get("line", 0)) + 1
        col = int(start.get("character", 0)) + 1
        lines.append(f"- {rel}:{line}:{col}")
    if len(locations) > limit:
        lines.append(f"... ({len(locations) - limit} more)")
    return "\n".join(lines)


class LSPToolkit:
    """multilspy LanguageServer 异步生命周期封装。"""

    def __init__(
        self,
        repo_root: str | Path,
        config: Optional[LSPConfig] = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.config = config or get_config().lsp
        self._language = detect_code_language(self.repo_root, self.config.code_language)
        self._lsp: Any = None
        self._ctx: Any = None
        self._available = False
        self._lock: Optional[asyncio.Lock] = None

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    @property
    def available(self) -> bool:
        return self._available and self._lsp is not None

    @property
    def language(self) -> str:
        return self._language

    async def __aenter__(self) -> "LSPToolkit":
        if not self.config.enabled:
            return self
        ensure_lsp_on_path()
        try:
            from multilspy import LanguageServer
            from multilspy.multilspy_config import MultilspyConfig
            from multilspy.multilspy_logger import MultilspyLogger

            mcfg = MultilspyConfig.from_dict({"code_language": self._language})
            mlog = MultilspyLogger()
            self._lsp = LanguageServer.create(
                mcfg,
                mlog,
                str(self.repo_root),
            )
            self._ctx = self._lsp.start_server()
            await asyncio.wait_for(
                self._ctx.__aenter__(),
                timeout=self.config.startup_timeout,
            )
            self._lock = asyncio.Lock()
            self._available = True
            logger.debug("LSP 已启动: language={}", self._language)
        except asyncio.TimeoutError:
            logger.warning("LSP 启动超时 ({}s)", self.config.startup_timeout)
            self._available = False
        except Exception as e:
            logger.warning("LSP 启动失败 ({}): {}", self._language, e)
            self._available = False
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._ctx is not None:
            try:
                await self._ctx.__aexit__(exc_type, exc, tb)
            except Exception as e:
                logger.debug("LSP 关闭: {}", e)
        self._lsp = None
        self._ctx = None
        self._available = False
        self._lock = None

    async def definition(
        self,
        relative_path: str,
        line: int,
        column: int,
    ) -> list[dict[str, Any]]:
        return await self._request("definition", relative_path, line, column)

    async def references(
        self,
        relative_path: str,
        line: int,
        column: int,
    ) -> list[dict[str, Any]]:
        return await self._request("references", relative_path, line, column)

    async def hover(
        self,
        relative_path: str,
        line: int,
        column: int,
    ) -> str:
        if not self.available:
            return "(LSP unavailable)"
        try:
            assert self._lock is not None
            async with self._lock:
                result = await self._lsp.request_hover(relative_path, line, column)
            if not result:
                return "(no hover info)"
            contents = result.get("contents")
            if isinstance(contents, dict):
                return str(contents.get("value", contents))
            if isinstance(contents, list):
                parts = []
                for c in contents:
                    if isinstance(c, dict):
                        parts.append(str(c.get("value", c)))
                    else:
                        parts.append(str(c))
                return "\n".join(parts)
            return str(contents)
        except Exception as e:
            return f"(hover error: {e})"

    async def document_symbols(self, relative_path: str) -> str:
        if not self.available:
            return "(LSP unavailable)"
        try:
            assert self._lock is not None
            async with self._lock:
                symbols, _tree = await self._lsp.request_document_symbols(relative_path)
            lines: list[str] = []
            for sym in symbols[:30]:
                name = sym.get("name", "?")
                kind = sym.get("kind", "")
                rng = sym.get("range") or {}
                start = rng.get("start") or {}
                line = int(start.get("line", 0)) + 1
                lines.append(f"- [{kind}] {name} @ line {line}")
            return "\n".join(lines) if lines else "(no symbols)"
        except Exception as e:
            return f"(document_symbols error: {e})"

    async def _request(
        self,
        method: str,
        relative_path: str,
        line: int,
        column: int,
    ) -> list[dict[str, Any]]:
        if not self.available:
            return []
        try:
            assert self._lock is not None
            async with self._lock:
                if method == "definition":
                    locs = await self._lsp.request_definition(relative_path, line, column)
                elif method == "references":
                    locs = await self._lsp.request_references(relative_path, line, column)
                else:
                    return []
            return [dict(loc) if not isinstance(loc, dict) else loc for loc in locs]
        except Exception as e:
            logger.debug("LSP {} 失败: {}:{} — {}", method, relative_path, line, e)
            return []


@asynccontextmanager
async def open_lsp(
    repo_root: str | Path,
    config: Optional[LSPConfig] = None,
) -> AsyncIterator[LSPToolkit]:
    toolkit = LSPToolkit(repo_root, config)
    async with toolkit:
        yield toolkit
