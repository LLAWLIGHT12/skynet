"""Preview 预览模式 —— 预览将被分析的内容，不调用 LLM。

- preview_analysis() — 预览将被分析的 chunk
- preview_audit() — 预览 audit pipeline 将生成的任务
- 输出：文件列表、预估 token、跳过原因
- 不调用 LLM，纯本地计算
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skynet.audit.token_budget import estimate_tokens

log = logging.getLogger(__name__)

# 默认跳过的目录/文件模式
_DEFAULT_SKIP_DIRS = {
    "__pycache__", ".git", ".svn", "node_modules", ".venv", "venv",
    "env", ".mypy_cache", ".pytest_cache", "dist", "build", ".eggs",
}

_DEFAULT_SKIP_EXTS = {
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".dat",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".db", ".sqlite", ".sqlite3",
}


@dataclass
class PreviewItem:
    """一个将被分析的文件的预览信息。"""
    file_path: str
    estimated_tokens: int = 0
    file_size: int = 0
    language: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "estimated_tokens": self.estimated_tokens,
            "file_size": self.file_size,
            "language": self.language,
        }


@dataclass
class PreviewResult:
    """预览结果汇总。"""
    repo_root: str
    items: list[PreviewItem] = field(default_factory=list)
    skipped_files: list[dict[str, str]] = field(default_factory=list)
    total_estimated_tokens: int = 0
    total_files: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_root": self.repo_root,
            "total_files": self.total_files,
            "total_estimated_tokens": self.total_estimated_tokens,
            "items": [i.to_dict() for i in self.items],
            "skipped_count": len(self.skipped_files),
            "skipped_samples": self.skipped_files[:20],
        }

    def summary_text(self) -> str:
        """生成人类可读的摘要文本。"""
        lines = [
            f"Repository: {self.repo_root}",
            f"Files to analyze: {self.total_files}",
            f"Estimated tokens: {self.total_estimated_tokens:,}",
            f"Skipped files: {len(self.skipped_files)}",
        ]
        if self.items:
            lines.append("\nTop files by estimated tokens:")
            sorted_items = sorted(self.items, key=lambda x: x.estimated_tokens, reverse=True)
            for item in sorted_items[:10]:
                lines.append(
                    f"  {item.file_path}: ~{item.estimated_tokens:,} tokens "
                    f"({item.file_size:,} bytes)"
                )
        return "\n".join(lines)


def preview_analysis(
    repo_root: str | Path,
    *,
    skip_tests: bool = True,
    extra_skip_dirs: set[str] | None = None,
    max_files: int = 0,
) -> PreviewResult:
    """预览将被分析的 chunk（不调用 LLM）。

    Parameters
    ----------
    repo_root : str | Path
        仓库根目录。
    skip_tests : bool
        是否跳过测试文件。
    extra_skip_dirs : set[str] | None
        额外跳过的目录名。
    max_files : int
        最多返回的文件数。0 = 不限制。

    Returns
    -------
    PreviewResult
    """
    root = Path(repo_root).resolve()
    skip_dirs = _DEFAULT_SKIP_DIRS | (extra_skip_dirs or set())

    result = PreviewResult(repo_root=str(root))

    if not root.is_dir():
        log.warning("preview: %s is not a directory", root)
        return result

    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file():
            continue

        rel_path = file_path.relative_to(root)

        # 检查是否应跳过
        skip_reason = _should_skip(rel_path, skip_dirs, skip_tests)
        if skip_reason:
            result.skipped_files.append({
                "file": str(rel_path),
                "reason": skip_reason,
            })
            continue

        # 读取文件并估算 token
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            file_size = len(content.encode("utf-8"))
            est_tokens = estimate_tokens(content)
        except Exception as e:
            result.skipped_files.append({
                "file": str(rel_path),
                "reason": f"read error: {e}",
            })
            continue

        item = PreviewItem(
            file_path=str(rel_path),
            estimated_tokens=est_tokens,
            file_size=file_size,
            language=_detect_language(file_path.suffix),
        )
        result.items.append(item)
        result.total_estimated_tokens += est_tokens

    result.total_files = len(result.items)

    if max_files > 0:
        result.items = sorted(
            result.items, key=lambda x: x.estimated_tokens, reverse=True,
        )[:max_files]

    return result


def preview_audit(
    repo_root: str | Path,
    *,
    skip_tests: bool = True,
) -> dict[str, Any]:
    """预览 audit pipeline 将生成的任务（不调用 LLM）。

    返回一个字典，包含：
    - 将被 recon 分析的文件列表
    - 预估的 hunt 任务数（基于文件数和 attack class 数）
    - 预估总 token
    """
    preview = preview_analysis(repo_root, skip_tests=skip_tests)

    # 估算 hunt 任务数（假设每个 attack class 对每个高风险文件生成一个任务）
    # 这是一个粗略估计
    attack_classes = [
        "sql_injection", "xss", "command_injection", "path_traversal",
        "ssrf", "auth_bypass", "crypto_weakness",
    ]
    high_risk_files = [
        i for i in preview.items
        if i.language in ("python", "javascript", "typescript", "java", "go", "php")
    ]

    estimated_tasks = len(high_risk_files) * len(attack_classes)

    return {
        "preview": preview.to_dict(),
        "estimated_hunt_tasks": estimated_tasks,
        "high_risk_files": len(high_risk_files),
        "attack_classes": len(attack_classes),
    }


def _should_skip(
    rel_path: Path,
    skip_dirs: set[str],
    skip_tests: bool,
) -> str | None:
    """判断文件是否应被跳过，返回跳过原因或 None。"""
    parts = rel_path.parts

    # 检查目录
    for part in parts[:-1]:
        if part in skip_dirs:
            return f"skip dir: {part}"

    # 检查扩展名
    if rel_path.suffix.lower() in _DEFAULT_SKIP_EXTS:
        return f"skip ext: {rel_path.suffix}"

    # 检查测试文件
    if skip_tests:
        name_lower = rel_path.name.lower()
        if (name_lower.startswith("test_") or name_lower.endswith("_test.py")
                or "tests" in parts or "test" in parts):
            return "test file"

    return None


def _detect_language(suffix: str) -> str:
    """根据文件扩展名检测语言。"""
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".rs": "rust",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".html": "html",
        ".css": "css",
        ".sql": "sql",
        ".sh": "shell",
        ".bash": "shell",
    }
    return lang_map.get(suffix.lower(), "other")
