"""输入安全校验器 — 防止路径遍历、危险命令、超大文件等安全风险。"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ── 常量 ─────────────────────────────────────────────────────────

class InputValidationError(ValueError):
    """输入校验失败基类。"""


class PathTraversalError(InputValidationError):
    """路径遍历检测。"""


class FileSizeExceededError(InputValidationError):
    """文件大小超限。"""


# 危险路径模式
DANGEROUS_PATH_PATTERNS: List[str] = [
    r"\.\.",           # 父目录遍历
    r"\.\./",
    r"\.\.\\",
    r"/\.\.",
    r"\\\.\.",
    r"^/",             # 绝对路径 (Unix)
    r"^[A-Za-z]:",     # 绝对路径 (Windows)
    r"~",              # Home 目录
    r"\$",             # 环境变量
    r"%",              # Windows 环境变量
]

# 禁止的文件扩展名
BLOCKED_EXTENSIONS: Set[str] = {
    ".exe", ".dll", ".so", ".dylib",   # 可执行文件
    ".bin", ".dat",                      # 二进制数据
    ".key", ".pem", ".p12", ".pfx",    # 私钥
    ".env",                              # 环境变量文件
}

# 默认限制
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024       # 10 MB
DEFAULT_MAX_PATH_LENGTH = 500
DEFAULT_MAX_CONTENT_LENGTH = 100_000

# 危险命令模式
DANGEROUS_COMMANDS: Set[str] = {
    "rm", "rm -rf", "del", "rmdir",
    "mkfs", "format", "fdisk",
    "chmod", "chown", "icacls",
    "shutdown", "reboot", "halt", "poweroff",
    "kill", "killall",
    "curl", "wget",  # 防止下载外部资源
}

# 危险命令前缀
DANGEROUS_COMMAND_PATTERNS: List[str] = [
    r"\brm\s+-rf\b",
    r"\bdel\s+/[fqs]",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r">\s*/dev/",
    r"\bshutdown\b",
    r"\breboot\b",
]


# ── 路径校验 ─────────────────────────────────────────────────────

def validate_path(
    path: str,
    project_root: str,
    allow_absolute: bool = False,
) -> str:
    """校验并规范化文件路径。

    Args:
        path: 待校验路径。
        project_root: 项目根目录。
        allow_absolute: 是否允许绝对路径。

    Returns:
        规范化后的绝对路径。

    Raises:
        PathTraversalError: 检测到路径遍历。
        InputValidationError: 路径无效。
    """
    if not path or not path.strip():
        raise InputValidationError("路径不能为空")

    path = path.strip()

    # 检查危险模式
    for pattern in DANGEROUS_PATH_PATTERNS:
        if re.search(pattern, path):
            raise PathTraversalError(f"检测到危险路径模式: {path}")

    # 规范化项目根目录
    project_root = os.path.abspath(os.path.normpath(project_root))

    # 处理绝对/相对路径
    if os.path.isabs(path):
        if not allow_absolute:
            raise PathTraversalError(f"不允许绝对路径: {path}")
        abs_path = os.path.normpath(path)
    else:
        abs_path = os.path.normpath(os.path.join(project_root, path))

    # 确保路径在项目根目录内
    try:
        resolved_path = str(Path(abs_path).resolve())
        resolved_root = str(Path(project_root).resolve())

        if not resolved_path.startswith(resolved_root + os.sep) and resolved_path != resolved_root:
            raise PathTraversalError(f"路径逃逸出项目根目录: {path}")
    except (OSError, ValueError) as e:
        raise InputValidationError(f"无效路径: {path} - {e}")

    return abs_path


def validate_file_extension(
    path: str,
    allowed_extensions: Optional[Set[str]] = None,
    blocked_extensions: Optional[Set[str]] = None,
) -> None:
    """校验文件扩展名。

    Raises:
        InputValidationError: 扩展名不允许。
    """
    ext = os.path.splitext(path)[1].lower()

    blocked = blocked_extensions or BLOCKED_EXTENSIONS
    if ext in blocked:
        raise InputValidationError(f"文件扩展名不允许: {ext}")

    if allowed_extensions is not None and ext not in allowed_extensions:
        raise InputValidationError(f"文件扩展名不在允许列表中: {ext}")


def validate_file_size(
    path: str,
    max_size: int = DEFAULT_MAX_FILE_SIZE,
) -> int:
    """校验文件大小。

    Returns:
        文件大小（字节）。

    Raises:
        FileSizeExceededError: 文件超过大小限制。
    """
    try:
        size = os.path.getsize(path)
        if size > max_size:
            raise FileSizeExceededError(
                f"文件大小 {size} 超过限制 {max_size}: {path}"
            )
        return size
    except OSError as e:
        raise InputValidationError(f"无法检查文件大小: {e}")


# ── 命令校验 ─────────────────────────────────────────────────────

def validate_command(command: str) -> str:
    """校验命令是否安全。

    Raises:
        InputValidationError: 命令包含危险操作。
    """
    if not command or not command.strip():
        raise InputValidationError("命令不能为空")

    command = command.strip()

    # 检查危险命令模式
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            raise InputValidationError(f"检测到危险命令模式: {command}")

    # 检查基础危险命令
    cmd_lower = command.lower().strip()
    for dangerous in DANGEROUS_COMMANDS:
        if cmd_lower == dangerous or cmd_lower.startswith(dangerous + " "):
            raise InputValidationError(f"命令被禁止: {command}")

    return command


# ── 字符串清理 ────────────────────────────────────────────────────

def sanitize_string(value: str, max_length: int = DEFAULT_MAX_CONTENT_LENGTH) -> str:
    """清理字符串：移除控制字符、截断过长内容。"""
    if not isinstance(value, str):
        value = str(value)

    # 移除 null 字节和控制字符
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)

    # 截断
    if len(value) > max_length:
        value = value[:max_length] + "..."

    return value


def sanitize_dict(data: Dict[str, Any], max_depth: int = 5) -> Dict[str, Any]:
    """递归清理字典数据。"""
    if max_depth <= 0:
        return {"_truncated": True}

    result: Dict[str, Any] = {}
    for key, value in data.items():
        key = sanitize_string(str(key), 100)

        if isinstance(value, str):
            result[key] = sanitize_string(value)
        elif isinstance(value, dict):
            result[key] = sanitize_dict(value, max_depth - 1)
        elif isinstance(value, list):
            result[key] = [
                sanitize_dict(v, max_depth - 1) if isinstance(v, dict)
                else sanitize_string(str(v)) if isinstance(v, str)
                else v
                for v in value[:100]
            ]
        else:
            result[key] = value

    return result


# ── ToolInputValidator ───────────────────────────────────────────

class ToolInputValidator:
    """工具输入校验器。

    在执行工具操作前校验输入，防止路径遍历、超大文件、危险命令等。

    用法::

        validator = ToolInputValidator("/path/to/project")
        safe_path = validator.validate_file_path("../../etc/passwd")  # raises
        safe_path = validator.validate_file_for_read("src/main.py")   # OK
    """

    def __init__(self, project_root: str):
        self.project_root = os.path.abspath(project_root)

    def validate_file_path(self, path: str) -> str:
        """校验并规范化文件路径。"""
        return validate_path(path, self.project_root)

    def validate_file_for_read(
        self,
        path: str,
        max_size: int = DEFAULT_MAX_FILE_SIZE,
        allowed_extensions: Optional[Set[str]] = None,
    ) -> str:
        """校验文件可读：路径 + 存在性 + 扩展名 + 大小。"""
        abs_path = self.validate_file_path(path)

        if not os.path.isfile(abs_path):
            raise InputValidationError(f"文件不存在: {path}")

        validate_file_extension(abs_path, allowed_extensions)
        validate_file_size(abs_path, max_size)

        return abs_path

    def validate_directory(self, path: str) -> str:
        """校验目录路径。"""
        abs_path = self.validate_file_path(path)

        if not os.path.isdir(abs_path):
            raise InputValidationError(f"目录不存在: {path}")

        return abs_path

    def validate_output_path(self, path: str) -> str:
        """校验输出路径：父目录必须存在。"""
        abs_path = self.validate_file_path(path)

        parent = os.path.dirname(abs_path)
        if not os.path.isdir(parent):
            raise InputValidationError(f"父目录不存在: {parent}")

        return abs_path

    def validate_command(self, command: str) -> str:
        """校验命令安全性。"""
        return validate_command(command)

    def sanitize(self, value: Any) -> Any:
        """清理任意输入值。"""
        if isinstance(value, str):
            return sanitize_string(value)
        if isinstance(value, dict):
            return sanitize_dict(value)
        return value
