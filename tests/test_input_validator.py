"""ToolInputValidator 单元测试。"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from skynet.tools.input_validator import (
    ToolInputValidator,
    InputValidationError,
    PathTraversalError,
    FileSizeExceededError,
    validate_path,
    validate_file_extension,
    validate_file_size,
    validate_command,
    sanitize_string,
    sanitize_dict,
    DANGEROUS_PATH_PATTERNS,
    BLOCKED_EXTENSIONS,
)


class TestValidatePath:
    """路径校验测试。"""

    def test_valid_relative_path(self, tmp_path):
        """有效相对路径。"""
        result = validate_path("src/main.py", str(tmp_path))
        assert str(tmp_path) in result
        assert result.endswith("main.py")

    def test_path_traversal_detected(self, tmp_path):
        """检测路径遍历。"""
        with pytest.raises(PathTraversalError):
            validate_path("../../etc/passwd", str(tmp_path))

    def test_absolute_path_rejected(self, tmp_path):
        """拒绝绝对路径。"""
        with pytest.raises(PathTraversalError):
            validate_path("/etc/passwd", str(tmp_path))

    def test_empty_path_rejected(self, tmp_path):
        """拒绝空路径。"""
        with pytest.raises(InputValidationError):
            validate_path("", str(tmp_path))

    def test_whitespace_path_rejected(self, tmp_path):
        """拒绝纯空白路径。"""
        with pytest.raises(InputValidationError):
            validate_path("   ", str(tmp_path))


class TestValidateFileExtension:
    """文件扩展名校验测试。"""

    def test_allowed_extension(self):
        """允许的扩展名。"""
        validate_file_extension("test.py")  # 不应抛出

    def test_blocked_extension(self):
        """阻止的扩展名。"""
        with pytest.raises(InputValidationError):
            validate_file_extension("test.exe")

    def test_blocked_key_extension(self):
        """阻止的密钥扩展名。"""
        with pytest.raises(InputValidationError):
            validate_file_extension("test.pem")

    def test_custom_blocked(self):
        """自定义阻止列表。"""
        with pytest.raises(InputValidationError):
            validate_file_extension("test.txt", blocked_extensions={".txt"})


class TestValidateCommand:
    """命令校验测试。"""

    def test_safe_command(self):
        """安全命令。"""
        result = validate_command("echo hello")
        assert result == "echo hello"

    def test_dangerous_rm(self):
        """危险 rm 命令。"""
        with pytest.raises(InputValidationError):
            validate_command("rm -rf /")

    def test_dangerous_shutdown(self):
        """危险 shutdown 命令。"""
        with pytest.raises(InputValidationError):
            validate_command("shutdown -h now")

    def test_empty_command(self):
        """空命令。"""
        with pytest.raises(InputValidationError):
            validate_command("")


class TestSanitize:
    """字符串清理测试。"""

    def test_sanitize_normal(self):
        """正常字符串。"""
        result = sanitize_string("hello world")
        assert result == "hello world"

    def test_sanitize_control_chars(self):
        """控制字符。"""
        result = sanitize_string("hello\x00world\x08")
        assert result == "helloworld"

    def test_sanitize_truncate(self):
        """截断过长字符串。"""
        long_str = "a" * 200
        result = sanitize_string(long_str, max_length=100)
        assert len(result) == 103  # 100 + "..."
        assert result.endswith("...")

    def test_sanitize_dict(self):
        """字典清理。"""
        data = {"key": "value", "nested": {"inner": "data"}}
        result = sanitize_dict(data)
        assert result["key"] == "value"
        assert result["nested"]["inner"] == "data"

    def test_sanitize_dict_truncate(self):
        """字典深度截断。"""
        data = {"a": {"b": {"c": {"d": "deep"}}}}
        result = sanitize_dict(data, max_depth=2)
        assert "_truncated" in str(result)


class TestToolInputValidator:
    """ToolInputValidator 类测试。"""

    def test_init(self, tmp_path):
        """初始化。"""
        validator = ToolInputValidator(str(tmp_path))
        assert validator.project_root == str(tmp_path)

    def test_validate_file_path(self, tmp_path):
        """文件路径校验。"""
        validator = ToolInputValidator(str(tmp_path))
        result = validator.validate_file_path("src/main.py")
        assert str(tmp_path) in result

    def test_validate_file_for_read_nonexistent(self, tmp_path):
        """读取不存在的文件。"""
        validator = ToolInputValidator(str(tmp_path))
        with pytest.raises(InputValidationError):
            validator.validate_file_for_read("nonexistent.py")

    def test_validate_file_for_read_exists(self, tmp_path):
        """读取存在的文件。"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        validator = ToolInputValidator(str(tmp_path))
        result = validator.validate_file_for_read("test.py")
        assert result == str(test_file)

    def test_validate_directory(self, tmp_path):
        """目录校验。"""
        validator = ToolInputValidator(str(tmp_path))
        result = validator.validate_directory(".")
        assert result == str(tmp_path)

    def test_validate_directory_nonexistent(self, tmp_path):
        """不存在目录。"""
        validator = ToolInputValidator(str(tmp_path))
        with pytest.raises(InputValidationError):
            validator.validate_directory("nonexistent_dir")

    def test_validate_output_path(self, tmp_path):
        """输出路径校验。"""
        validator = ToolInputValidator(str(tmp_path))
        result = validator.validate_output_path("output.txt")
        assert str(tmp_path) in result

    def test_validate_command(self, tmp_path):
        """命令校验。"""
        validator = ToolInputValidator(str(tmp_path))
        result = validator.validate_command("echo hello")
        assert result == "echo hello"

    def test_sanitize_string(self, tmp_path):
        """字符串清理。"""
        validator = ToolInputValidator(str(tmp_path))
        result = validator.sanitize("hello\x00world")
        assert result == "helloworld"

    def test_sanitize_dict(self, tmp_path):
        """字典清理。"""
        validator = ToolInputValidator(str(tmp_path))
        result = validator.sanitize({"key": "value"})
        assert result == {"key": "value"}

    def test_sanitize_other(self, tmp_path):
        """其他类型清理。"""
        validator = ToolInputValidator(str(tmp_path))
        assert validator.sanitize(123) == 123
        assert validator.sanitize([1, 2, 3]) == [1, 2, 3]


class TestConstants:
    """常量测试。"""

    def test_dangerous_path_patterns(self):
        """危险路径模式。"""
        assert len(DANGEROUS_PATH_PATTERNS) > 0
        assert r"\.\." in DANGEROUS_PATH_PATTERNS

    def test_blocked_extensions(self):
        """阻止的扩展名。"""
        assert ".exe" in BLOCKED_EXTENSIONS
        assert ".pem" in BLOCKED_EXTENSIONS
        assert ".py" not in BLOCKED_EXTENSIONS
