"""Task 5: Preview 预览模式测试。"""

from __future__ import annotations

import pytest
from pathlib import Path

from skynet.audit.preview import (
    preview_analysis,
    preview_audit,
    PreviewItem,
    PreviewResult,
    _should_skip,
    _detect_language,
)


# ── 测试 fixture ────────────────────────────────────────────────

@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """创建一个模拟仓库。"""
    # 源代码
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("def main():\n    print('hello')\n", encoding="utf-8")
    (src / "utils.py").write_text("def helper():\n    pass\n", encoding="utf-8")

    # 测试文件
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_app.py").write_text("def test_main():\n    pass\n", encoding="utf-8")

    # 应跳过的文件
    (tmp_path / "data.db").write_text("binary", encoding="utf-8")
    cache_dir = tmp_path / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "app.cpython-311.pyc").write_text("bytecode", encoding="utf-8")

    # JS 文件
    (src / "index.js").write_text("console.log('hello');\n", encoding="utf-8")

    return tmp_path


# ── PreviewItem / PreviewResult ─────────────────────────────────

class TestDataclasses:
    def test_preview_item_to_dict(self):
        item = PreviewItem(file_path="src/app.py", estimated_tokens=50, file_size=150, language="python")
        d = item.to_dict()
        assert d["file_path"] == "src/app.py"
        assert d["estimated_tokens"] == 50
        assert d["language"] == "python"

    def test_preview_result_summary_text(self):
        result = PreviewResult(
            repo_root="/tmp/test",
            items=[
                PreviewItem(file_path="a.py", estimated_tokens=100, file_size=300, language="python"),
            ],
            total_files=1,
            total_estimated_tokens=100,
        )
        text = result.summary_text()
        assert "Files to analyze: 1" in text
        assert "a.py" in text


# ── _should_skip ────────────────────────────────────────────────

class TestShouldSkip:
    def test_skip_pycache(self):
        reason = _should_skip(Path("__pycache__/foo.pyc"), {"__pycache__"}, skip_tests=False)
        assert reason is not None
        assert "__pycache__" in reason

    def test_skip_binary_ext(self):
        reason = _should_skip(Path("data.db"), set(), skip_tests=False)
        assert reason is not None
        assert "ext" in reason

    def test_skip_test_file(self):
        reason = _should_skip(Path("test_app.py"), set(), skip_tests=True)
        assert reason is not None
        assert "test" in reason

    def test_skip_tests_dir(self):
        reason = _should_skip(Path("tests/test_app.py"), set(), skip_tests=True)
        assert reason is not None

    def test_no_skip_normal_file(self):
        reason = _should_skip(Path("src/app.py"), set(), skip_tests=True)
        assert reason is None

    def test_no_skip_when_tests_allowed(self):
        reason = _should_skip(Path("test_app.py"), set(), skip_tests=False)
        assert reason is None


# ── _detect_language ────────────────────────────────────────────

class TestDetectLanguage:
    def test_python(self):
        assert _detect_language(".py") == "python"

    def test_javascript(self):
        assert _detect_language(".js") == "javascript"

    def test_typescript(self):
        assert _detect_language(".ts") == "typescript"

    def test_unknown(self):
        assert _detect_language(".xyz") == "other"


# ── preview_analysis ────────────────────────────────────────────

class TestPreviewAnalysis:
    def test_basic(self, sample_repo: Path):
        """有文件 — 返回 chunk 列表和预估 token。"""
        result = preview_analysis(sample_repo, skip_tests=False)
        assert result.total_files > 0
        assert result.total_estimated_tokens > 0
        # 应包含 app.py
        paths = [i.file_path for i in result.items]
        assert any("app.py" in p for p in paths)

    def test_skip_tests(self, sample_repo: Path):
        """排除测试文件 — 正确过滤。"""
        result_with = preview_analysis(sample_repo, skip_tests=False)
        result_without = preview_analysis(sample_repo, skip_tests=True)
        assert result_without.total_files <= result_with.total_files
        # test_app.py 不应出现在 skip_tests=True 的结果中
        paths = [i.file_path for i in result_without.items]
        assert not any("test_app.py" in p for p in paths)

    def test_skip_binary_and_cache(self, sample_repo: Path):
        """二进制文件和缓存目录被跳过。"""
        result = preview_analysis(sample_repo, skip_tests=False)
        paths = [i.file_path for i in result.items]
        assert not any("data.db" in p for p in paths)
        assert not any("__pycache__" in p for p in paths)
        # 应记录在 skipped 中
        skip_reasons = [s["reason"] for s in result.skipped_files]
        assert any("ext" in r for r in skip_reasons)

    def test_empty_repo(self, tmp_path: Path):
        """空仓库 — 返回空列表。"""
        result = preview_analysis(tmp_path)
        assert result.total_files == 0
        assert result.total_estimated_tokens == 0

    def test_nonexistent_repo(self, tmp_path: Path):
        """不存在的目录。"""
        result = preview_analysis(tmp_path / "nonexistent")
        assert result.total_files == 0

    def test_max_files(self, sample_repo: Path):
        """max_files 限制返回数量。"""
        result = preview_analysis(sample_repo, skip_tests=False, max_files=2)
        assert len(result.items) <= 2

    def test_to_dict(self, sample_repo: Path):
        """输出格式正确。"""
        result = preview_analysis(sample_repo, skip_tests=False)
        d = result.to_dict()
        assert "repo_root" in d
        assert "total_files" in d
        assert "items" in d
        assert isinstance(d["items"], list)


# ── preview_audit ───────────────────────────────────────────────

class TestPreviewAudit:
    def test_basic(self, sample_repo: Path):
        """返回预估信息。"""
        result = preview_audit(sample_repo, skip_tests=False)
        assert "preview" in result
        assert "estimated_hunt_tasks" in result
        assert "high_risk_files" in result
        assert result["estimated_hunt_tasks"] >= 0

    def test_estimated_tasks_proportional(self, sample_repo: Path):
        """预估任务数与高风险文件数成正比。"""
        result = preview_audit(sample_repo, skip_tests=False)
        assert result["estimated_hunt_tasks"] == (
            result["high_risk_files"] * result["attack_classes"]
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
