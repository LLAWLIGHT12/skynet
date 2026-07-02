"""Audit 工具层单元测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from skynet.tools.audit_tools import (
    AuditToolExecutor,
    format_audit_tool_specs,
    normalize_tool_names,
)


@pytest.fixture
def mini_repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def login(user):\n    query = f'SELECT * FROM u WHERE name={user}'\n    return query\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")
    return tmp_path


def test_normalize_tool_names_maps_legacy_claude_names():
    assert normalize_tool_names(["Read", "Grep", "Glob", "Bash"]) == [
        "read_file", "grep", "glob",
    ]


def test_format_audit_tool_specs_includes_submit_final():
    text = format_audit_tool_specs(["read_file", "grep"])
    assert "submit_final" in text
    assert "read_file" in text


@pytest.mark.asyncio
async def test_read_file_tool(mini_repo: Path):
    ex = AuditToolExecutor(mini_repo, allowed_tools=["read_file"])
    obs, is_final, payload = await ex.execute({
        "action": "read_file",
        "file_path": "src/app.py",
    })
    assert not is_final
    assert payload is None
    assert "login" in obs
    assert "SELECT" in obs


@pytest.mark.asyncio
async def test_grep_tool(mini_repo: Path):
    ex = AuditToolExecutor(mini_repo, allowed_tools=["grep"])
    obs, _, _ = await ex.execute({"action": "grep", "pattern": "SELECT"})
    assert "app.py" in obs


@pytest.mark.asyncio
async def test_glob_tool(mini_repo: Path):
    ex = AuditToolExecutor(mini_repo, allowed_tools=["glob"])
    obs, _, _ = await ex.execute({"action": "glob", "pattern": "**/*.py"})
    assert "src/app.py" in obs


@pytest.mark.asyncio
async def test_preload_target_files(mini_repo: Path):
    ex = AuditToolExecutor(mini_repo, allowed_tools=["read_file"])
    ex.preload_context({"target_files": ["src/app.py"], "repo_path": str(mini_repo)})
    assert any("Preloaded target" in o for o in ex.observations)
    assert any("login" in o for o in ex.observations)


@pytest.mark.asyncio
async def test_submit_final(mini_repo: Path):
    ex = AuditToolExecutor(mini_repo)
    _, is_final, payload = await ex.execute({
        "action": "submit_final",
        "payload": {"task_id": "t_x", "findings": [], "gaps_observed": []},
    })
    assert is_final
    assert payload["task_id"] == "t_x"


@pytest.mark.asyncio
async def test_disallowed_tool(mini_repo: Path):
    ex = AuditToolExecutor(mini_repo, allowed_tools=["read_file"])
    obs, is_final, _ = await ex.execute({"action": "grep", "pattern": "x"})
    assert "not allowed" in obs
    assert not is_final
