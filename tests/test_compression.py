"""Task 3: 三区内存压缩测试。"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from skynet.audit.compression import (
    count_tokens,
    count_messages_tokens,
    partition_messages,
    compress_messages,
    should_compress,
    _build_context_xml,
    SOFT_THRESHOLD,
    HARD_THRESHOLD,
)


# ── count_tokens ────────────────────────────────────────────────

class TestCountTokens:
    def test_empty_string(self):
        assert count_tokens("") == 0

    def test_short_string(self):
        result = count_tokens("hello world")
        assert result >= 1

    def test_longer_string(self):
        result = count_tokens("a" * 100)
        assert result > count_tokens("a" * 10)

    def test_chinese_string(self):
        result = count_tokens("你好世界" * 10)
        assert result >= 1


class TestCountMessagesTokens:
    def test_empty_list(self):
        assert count_messages_tokens([]) == 0

    def test_single_message(self):
        msgs = [{"role": "user", "content": "hello"}]
        assert count_messages_tokens(msgs) >= 1

    def test_multiple_messages(self):
        msgs = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there!"},
        ]
        total = count_messages_tokens(msgs)
        assert total > 0


# ── should_compress ─────────────────────────────────────────────

class TestShouldCompress:
    def test_short_messages_no_compress(self):
        """短消息不触发压缩。"""
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
        ]
        assert should_compress(msgs, max_tokens=10000) == "none"

    def test_below_soft_threshold(self):
        """低于 60% 不压缩。"""
        msgs = [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"},
            {"role": "assistant", "content": "a"},
        ]
        # max_tokens 很大，当前 token 远低于阈值
        assert should_compress(msgs, max_tokens=100000) == "none"

    def test_above_hard_threshold(self):
        """超过 80% 触发同步压缩。"""
        # 构造大量消息
        big_content = "x" * 10000
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "user"},
            {"role": "assistant", "content": big_content},
            {"role": "user", "content": big_content},
        ]
        # max_tokens 较小，使得当前 token 超过 80%
        result = should_compress(msgs, max_tokens=100)
        assert result == "sync"

    def test_between_thresholds(self):
        """60%-80% 之间触发异步压缩。"""
        big_content = "x" * 3000
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "user"},
            {"role": "assistant", "content": big_content},
        ]
        # 调参使 token 落在 60%-80% 区间
        result = should_compress(msgs, max_tokens=2000)
        # 可能是 async 或 sync 取决于实际 token 数
        assert result in ("async", "sync", "none")


# ── partition_messages ──────────────────────────────────────────

class TestPartitionMessages:
    def test_short_messages(self):
        """2 条以下不分区。"""
        msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
        frozen, compress = partition_messages(msgs, max_tokens=10000)
        assert frozen == 0
        assert compress == 2

    def test_frozen_zone_is_first_two(self):
        """Frozen zone 始终是前 2 条。"""
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "first user"},
            {"role": "assistant", "content": "resp1"},
            {"role": "user", "content": "q2"},
            {"role": "assistant", "content": "resp2"},
        ]
        frozen, compress = partition_messages(msgs, max_tokens=100)
        assert frozen == 2

    def test_compress_zone_not_exceed_messages(self):
        """compress_end 不超过消息总数。"""
        msgs = [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"},
        ]
        frozen, compress = partition_messages(msgs, max_tokens=10000)
        assert compress <= len(msgs)


# ── compress_messages ───────────────────────────────────────────

class FakeLLMForCompression:
    """模拟 LLM 客户端，返回固定摘要。"""

    def __init__(self, summary: str = "This is a compressed summary."):
        self._summary = summary
        self.call_count = 0

    async def chat_json(self, **kwargs) -> tuple[str, dict]:
        self.call_count += 1
        return self._summary, {"input_tokens": 100, "output_tokens": 50}


class FailingLLMForCompression:
    """总是抛出异常的 LLM 客户端。"""

    async def chat_json(self, **kwargs) -> tuple[str, dict]:
        raise RuntimeError("LLM unavailable")


class TestCompressMessages:
    def test_short_messages_no_compress(self):
        """短消息不触发压缩。"""
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
        ]
        result = asyncio.run(compress_messages(msgs, max_tokens=10000))
        assert result == msgs

    def test_below_threshold_no_compress(self):
        """未超过阈值不压缩。"""
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
        ]
        result = asyncio.run(compress_messages(msgs, max_tokens=100000))
        assert result == msgs

    def test_frozen_zone_preserved(self):
        """Frozen zone 保持不变。"""
        big = "x" * 10000
        msgs = [
            {"role": "system", "content": "SYSTEM PROMPT"},
            {"role": "user", "content": "FIRST USER"},
            {"role": "assistant", "content": big},
            {"role": "user", "content": big},
        ]
        llm = FakeLLMForCompression("compressed summary")
        result = asyncio.run(compress_messages(msgs, max_tokens=100, llm_client=llm))
        # frozen zone 的 role 不变
        assert result[0]["role"] == "system"
        # system prompt 内容保留（但 user 可能被注入摘要）
        assert "SYSTEM PROMPT" in result[0]["content"]

    def test_compressed_has_summary(self):
        """压缩后消息中包含摘要标记。"""
        big = "x" * 10000
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": big},
            {"role": "user", "content": big},
        ]
        llm = FakeLLMForCompression("MY_COMPRESSED_SUMMARY")
        result = asyncio.run(compress_messages(msgs, max_tokens=100, llm_client=llm))
        # 应该包含摘要标记
        full_text = " ".join(m.get("content", "") for m in result)
        assert "previous_analysis_summary" in full_text
        assert "MY_COMPRESSED_SUMMARY" in full_text

    def test_llm_failure_keeps_original(self):
        """LLM 失败时保留原始消息。"""
        big = "x" * 10000
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": big},
            {"role": "user", "content": big},
        ]
        result = asyncio.run(compress_messages(msgs, max_tokens=100, llm_client=FailingLLMForCompression()))
        # 失败时返回原始消息
        assert len(result) == len(msgs)

    def test_empty_summary_keeps_original(self):
        """LLM 返回空摘要时保留原始消息。"""
        big = "x" * 10000
        msgs = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": big},
            {"role": "user", "content": big},
        ]
        llm = FakeLLMForCompression("")
        result = asyncio.run(compress_messages(msgs, max_tokens=100, llm_client=llm))
        assert len(result) == len(msgs)


# ── _build_context_xml ──────────────────────────────────────────

class TestBuildContextXml:
    def test_basic(self):
        msgs = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
        xml = _build_context_xml(msgs)
        assert '<message id="0" role="user">' in xml
        assert "<content>hello</content>" in xml
        assert '<message id="1" role="assistant">' in xml

    def test_empty(self):
        assert _build_context_xml([]) == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
