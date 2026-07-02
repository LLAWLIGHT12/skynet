"""Task 1: 确定性行号解析器测试。"""

from __future__ import annotations

import pytest
from pathlib import Path

from skynet.audit.location_resolver import (
    normalize_line,
    resolve_finding_location,
    resolve_findings_locations,
    _split_and_normalize,
)


# ── normalize_line ──────────────────────────────────────────────

class TestNormalizeLine:
    def test_plain_line(self):
        assert normalize_line("  hello world  ") == "hello world"

    def test_diff_plus_marker(self):
        assert normalize_line("+added line") == "added line"

    def test_diff_minus_marker(self):
        assert normalize_line("-removed line") == "removed line"

    def test_empty_line(self):
        assert normalize_line("") == ""

    def test_only_whitespace(self):
        assert normalize_line("   ") == ""

    def test_plus_with_spaces(self):
        assert normalize_line("  + indented add") == "indented add"


# ── _split_and_normalize ───────────────────────────────────────

class TestSplitAndNormalize:
    def test_basic(self):
        result = _split_and_normalize("line1\nline2\nline3")
        assert result == ["line1", "line2", "line3"]

    def test_skips_empty_lines(self):
        result = _split_and_normalize("line1\n\n\nline2")
        assert result == ["line1", "line2"]

    def test_strips_diff_markers(self):
        result = _split_and_normalize("+added\n-removed\ncontext")
        assert result == ["added", "removed", "context"]


# ── resolve_finding_location ───────────────────────────────────

@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """创建一个临时仓库目录，包含测试文件。"""
    # 创建测试文件
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "import os\n"
        "\n"
        "def handle_request(user_input):\n"
        "    # vulnerable: no sanitization\n"
        "    result = os.system(user_input)\n"
        "    return result\n"
        "\n"
        "def safe_handler(user_input):\n"
        "    cleaned = user_input.strip()\n"
        "    return cleaned\n",
        encoding="utf-8",
    )
    (src / "utils.py").write_text(
        "def helper():\n"
        "    pass\n",
        encoding="utf-8",
    )
    return tmp_path


class TestResolveFindingLocation:
    def test_exact_match(self, sample_repo: Path):
        """evidence 完全匹配文件中的连续行。"""
        finding = {
            "file": "src/app.py",
            "evidence": "result = os.system(user_input)",
            "line_start": 0,
            "line_end": 0,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is True
        assert start == 5
        assert end == 5

    def test_multiline_match(self, sample_repo: Path):
        """多行 evidence 匹配正确行号范围。"""
        finding = {
            "file": "src/app.py",
            "evidence": "def handle_request(user_input):\n    # vulnerable: no sanitization\n    result = os.system(user_input)",
            "line_start": 0,
            "line_end": 0,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is True
        assert start == 3
        assert end == 5

    def test_whitespace_difference(self, sample_repo: Path):
        """带空白差异匹配 — 缩进/尾部空格不同。"""
        finding = {
            "file": "src/app.py",
            "evidence": "  result = os.system(user_input)  ",
            "line_start": 0,
            "line_end": 0,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is True
        assert start == 5

    def test_diff_marker_match(self, sample_repo: Path):
        """带 diff 标记匹配 — evidence 含 +/- 前缀。"""
        finding = {
            "file": "src/app.py",
            "evidence": "+    result = os.system(user_input)",
            "line_start": 0,
            "line_end": 0,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is True
        assert start == 5

    def test_no_match(self, sample_repo: Path):
        """未匹配 — evidence 不在文件中。"""
        finding = {
            "file": "src/app.py",
            "evidence": "this_code_does_not_exist_anywhere()",
            "line_start": 99,
            "line_end": 99,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is False
        # 保留原始值
        assert start == 99
        assert end == 99

    def test_empty_evidence(self, sample_repo: Path):
        """空 evidence — 直接返回 False。"""
        finding = {
            "file": "src/app.py",
            "evidence": "",
            "line_start": 10,
            "line_end": 12,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is False
        assert start == 10

    def test_missing_file(self, sample_repo: Path):
        """文件不存在。"""
        finding = {
            "file": "src/nonexistent.py",
            "evidence": "some code",
            "line_start": 1,
            "line_end": 1,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is False

    def test_missing_file_field(self, sample_repo: Path):
        """缺少 file 字段。"""
        finding = {"evidence": "some code", "line_start": 1, "line_end": 1}
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is False

    def test_evidence_as_dict(self, sample_repo: Path):
        """evidence 是 dict 格式（如 {"code": "..."}）。"""
        finding = {
            "file": "src/app.py",
            "evidence": {"code": "result = os.system(user_input)"},
            "line_start": 0,
            "line_end": 0,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is True
        assert start == 5

    def test_match_in_different_file(self, sample_repo: Path):
        """匹配 utils.py 中的内容。"""
        finding = {
            "file": "src/utils.py",
            "evidence": "def helper():",
            "line_start": 0,
            "line_end": 0,
        }
        start, end, resolved = resolve_finding_location(finding, sample_repo)
        assert resolved is True
        assert start == 1
        assert end == 1


# ── resolve_findings_locations (批量) ──────────────────────────

class TestResolveFindingsLocations:
    def test_batch_resolve(self, sample_repo: Path):
        """批量解析多个 finding。"""
        findings = [
            {
                "finding_id": "f1",
                "file": "src/app.py",
                "evidence": "result = os.system(user_input)",
                "line_start": 0,
                "line_end": 0,
            },
            {
                "finding_id": "f2",
                "file": "src/app.py",
                "evidence": "nonexistent_code()",
                "line_start": 50,
                "line_end": 50,
            },
        ]
        resolved = resolve_findings_locations(findings, sample_repo)
        assert len(resolved) == 2
        # f1 被解析
        assert resolved[0]["_location_resolved"] is True
        assert resolved[0]["line_start"] == 5
        # f2 未解析，保留原值
        assert resolved[1]["_location_resolved"] is False
        assert resolved[1]["line_start"] == 50

    def test_does_not_modify_original(self, sample_repo: Path):
        """不修改原始 finding dict。"""
        finding = {
            "finding_id": "f1",
            "file": "src/app.py",
            "evidence": "result = os.system(user_input)",
            "line_start": 0,
            "line_end": 0,
        }
        original_start = finding["line_start"]
        resolve_findings_locations([finding], sample_repo)
        # 原始 dict 不变
        assert finding["line_start"] == original_start

    def test_corrected_count_logged(self, sample_repo: Path):
        """当行号被修正时，corrected_count 正确。"""
        findings = [
            {
                "finding_id": "f1",
                "file": "src/app.py",
                "evidence": "result = os.system(user_input)",
                "line_start": 99,  # 错误的行号
                "line_end": 99,
            },
        ]
        resolved = resolve_findings_locations(findings, sample_repo)
        assert resolved[0]["line_start"] == 5  # 被修正
        assert resolved[0]["line_end"] == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
