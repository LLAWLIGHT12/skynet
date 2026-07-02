"""Audit agent_runner 单元测试（mock LLM）。"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from skynet.audit.agent_runner import run_agent


@pytest.fixture
def mini_repo(tmp_path: Path) -> Path:
    (tmp_path / "vuln.py").write_text("x = input()\nexec(x)\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def schema_file(tmp_path: Path) -> Path:
    p = tmp_path / "out.schema.json"
    p.write_text(json.dumps({
        "type": "object",
        "required": ["status"],
        "properties": {"status": {"type": "string"}},
        "additionalProperties": True,
    }), encoding="utf-8")
    return p


@pytest.fixture
def prompt_file(tmp_path: Path) -> Path:
    p = tmp_path / "prompt.md"
    p.write_text("# Task\nAnalyze the repo.", encoding="utf-8")
    return p


@pytest.mark.asyncio
async def test_run_agent_submit_final_via_tool_loop(
    mini_repo: Path,
    schema_file: Path,
    prompt_file: Path,
    tmp_path: Path,
):
    final_payload = {"status": "ok", "note": "done"}

    calls = {"n": 0}

    async def fake_chat_json(system_prompt: str, user_prompt: str):
        calls["n"] += 1
        if "Final step" in user_prompt or calls["n"] >= 2:
            return json.dumps({"action": "submit_final", "payload": final_payload}), {
                "input_tokens": 10,
                "output_tokens": 5,
            }
        return json.dumps({"action": "read_file", "file_path": "vuln.py"}), {
            "input_tokens": 20,
            "output_tokens": 8,
        }

    mock_llm = AsyncMock()
    mock_llm.chat_json = fake_chat_json
    mock_llm.config.model_name = "test-model"

    with patch("skynet.audit.agent_runner._make_llm", return_value=mock_llm):
        result = await run_agent(
            stage="test",
            prompt_file=prompt_file,
            user_input={"repo_path": str(mini_repo), "target_files": ["vuln.py"]},
            schema_file=schema_file,
            allowed_tools=["read_file"],
            max_turns=3,
            artifact_dir=tmp_path / "artifacts",
            artifact_name="t1",
            transient_retries=0,
        )

    assert result.payload["status"] == "ok"
    assert result.num_turns >= 1
    assert result.artifact_path.is_file()
