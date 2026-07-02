"""Task 2: 后置误报过滤器测试。"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skynet.audit.stages.global_filter import (
    run_global_filter,
    _parse_reject_ids,
)
from skynet.audit.stages._common import StageContext
from skynet.audit.config import HarnessConfig, StageConfig


# ── 测试辅助 ────────────────────────────────────────────────────

@dataclass
class FakeFinding:
    finding_id: str
    file: str = "app.py"
    line_start: int = 1
    line_end: int = 5
    vuln_class: str = "sql_injection"
    severity: str = "high"
    title: str = "SQL Injection"
    description: str = "Unsanitized input"
    evidence: str = "db.execute(user_input)"
    raw_json: str = ""
    validation_status: str = "confirmed"
    validation_json: str = ""
    group_id: str = ""
    is_canonical: int = 1
    task_id: str = "task_1"
    run_id: str = "run_1"
    finding_type: str = "chunk"
    confidence: float = 0.8
    poc_succeeded: int = 0


class FakeDB:
    """模拟 StateDB，提供 global_filter 需要的接口。"""

    def __init__(self, findings: list[FakeFinding] | None = None,
                 recon_output: dict | None = None):
        self._findings = findings or []
        self._recon = recon_output or {}
        self._rejected: dict[str, dict] = {}

    def get_findings(self, run_id: str, *, validation_status: str | None = None,
                     canonical_only: bool = False,
                     finding_type: str | None = None) -> list[FakeFinding]:
        result = self._findings
        if validation_status:
            result = [f for f in result if f.validation_status == validation_status]
        return result

    def get_recon_output(self, run_id: str) -> dict:
        return self._recon

    def set_finding_validation(self, finding_id: str, status: str, payload: dict) -> None:
        self._rejected[finding_id] = payload
        # 更新 finding 的 validation_status
        for f in self._findings:
            if f.finding_id == finding_id:
                f.validation_status = status


def _make_ctx(run_id: str = "run_1") -> StageContext:
    return StageContext(
        run_id=run_id,
        repo_path=Path("/tmp/fake_repo"),
        config=HarnessConfig(
            stages={"global_filter": StageConfig(
                name="global_filter", model="test", concurrency=1,
                tools=[], max_turns=5, permission_mode="acceptEdits",
                repair_attempts=1,
            )},
        ),
    )


class FakeLLMClient:
    """模拟 LLM 客户端。"""

    def __init__(self, response: str = '{"reject_ids": []}'):
        self._response = response
        self.call_count = 0
        self.last_system_prompt = ""
        self.last_user_prompt = ""

    async def chat_json(self, system_prompt: str, user_prompt: str,
                        temperature: float | None = None) -> tuple[str, dict]:
        self.call_count += 1
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        return self._response, {"input_tokens": 100, "output_tokens": 50}


class FailingLLMClient:
    """总是抛出异常的 LLM 客户端。"""

    async def chat_json(self, **kwargs) -> tuple[str, dict]:
        raise RuntimeError("LLM unavailable")


# ── _parse_reject_ids 单元测试 ──────────────────────────────────

class TestParseRejectIds:
    def test_valid_json(self):
        result = _parse_reject_ids('{"reject_ids": ["f1", "f2"]}')
        assert result == {"f1", "f2"}

    def test_empty_list(self):
        result = _parse_reject_ids('{"reject_ids": []}')
        assert result == set()

    def test_markdown_fence(self):
        result = _parse_reject_ids('```json\n{"reject_ids": ["f1"]}\n```')
        assert result == {"f1"}

    def test_json_embedded_in_text(self):
        text = 'Here is my analysis...\n{"reject_ids": ["f3"]}\nDone.'
        result = _parse_reject_ids(text)
        assert result == {"f3"}

    def test_invalid_json(self):
        result = _parse_reject_ids("not json at all")
        assert result == set()

    def test_missing_key(self):
        result = _parse_reject_ids('{"other_key": ["f1"]}')
        assert result == set()

    def test_non_string_ids(self):
        result = _parse_reject_ids('{"reject_ids": [123, null, "f1"]}')
        assert result == {"f1"}

    def test_reject_ids_not_list(self):
        result = _parse_reject_ids('{"reject_ids": "f1"}')
        assert result == set()


# ── run_global_filter 集成测试 ──────────────────────────────────

class TestRunGlobalFilter:
    def test_no_confirmed_findings(self):
        """无 confirmed findings — 直接返回 0。"""
        db = FakeDB(findings=[])
        ctx = _make_ctx()
        result = asyncio.run(run_global_filter(ctx, db, llm_client=FakeLLMClient()))
        assert result == 0

    def test_llm_returns_empty_rejections(self):
        """LLM 返回空列表 — 不剔除任何 finding。"""
        findings = [
            FakeFinding(finding_id="f1", validation_status="confirmed"),
            FakeFinding(finding_id="f2", validation_status="confirmed"),
        ]
        db = FakeDB(findings=findings)
        ctx = _make_ctx()
        llm = FakeLLMClient('{"reject_ids": []}')
        result = asyncio.run(run_global_filter(ctx, db, llm_client=llm))
        assert result == 0
        assert llm.call_count == 1

    def test_llm_returns_partial_rejections(self):
        """LLM 返回部分 ID — 只剔除指定的。"""
        findings = [
            FakeFinding(finding_id="f1", validation_status="confirmed"),
            FakeFinding(finding_id="f2", validation_status="confirmed"),
            FakeFinding(finding_id="f3", validation_status="confirmed"),
        ]
        db = FakeDB(findings=findings)
        ctx = _make_ctx()
        llm = FakeLLMClient('{"reject_ids": ["f1", "f3"]}')
        result = asyncio.run(run_global_filter(ctx, db, llm_client=llm))
        assert result == 2
        assert "f1" in db._rejected
        assert "f3" in db._rejected
        assert "f2" not in db._rejected

    def test_llm_call_failure(self):
        """LLM 调用失败 — 静默跳过，所有 finding 保留。"""
        findings = [
            FakeFinding(finding_id="f1", validation_status="confirmed"),
        ]
        db = FakeDB(findings=findings)
        ctx = _make_ctx()
        result = asyncio.run(run_global_filter(ctx, db, llm_client=FailingLLMClient()))
        assert result == 0
        assert len(db._rejected) == 0

    def test_ignores_unknown_ids(self):
        """LLM 返回不存在的 ID — 被忽略。"""
        findings = [
            FakeFinding(finding_id="f1", validation_status="confirmed"),
        ]
        db = FakeDB(findings=findings)
        ctx = _make_ctx()
        llm = FakeLLMClient('{"reject_ids": ["f1", "nonexistent"]}')
        result = asyncio.run(run_global_filter(ctx, db, llm_client=llm))
        assert result == 1  # 只有 f1 被剔除
        assert "f1" in db._rejected

    def test_prompt_contains_findings(self):
        """验证 findings JSON 被正确注入到 prompt。"""
        findings = [
            FakeFinding(
                finding_id="f1",
                file="src/app.py",
                vuln_class="xss",
                validation_status="confirmed",
            ),
        ]
        db = FakeDB(findings=findings, recon_output={"architecture": "Flask"})
        ctx = _make_ctx()
        llm = FakeLLMClient('{"reject_ids": []}')
        asyncio.run(run_global_filter(ctx, db, llm_client=llm))
        # 验证 prompt 包含 finding 信息
        assert "f1" in llm.last_user_prompt
        assert "src/app.py" in llm.last_user_prompt
        assert "xss" in llm.last_user_prompt
        # 验证 prompt 包含 recon summary
        assert "Flask" in llm.last_user_prompt

    def test_rejected_finding_status_updated(self):
        """被剔除的 finding 的 validation_status 被更新。"""
        findings = [
            FakeFinding(finding_id="f1", validation_status="confirmed"),
        ]
        db = FakeDB(findings=findings)
        ctx = _make_ctx()
        llm = FakeLLMClient('{"reject_ids": ["f1"]}')
        asyncio.run(run_global_filter(ctx, db, llm_client=llm))
        assert findings[0].validation_status == "rejected_by_filter"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
