#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""对话记忆压缩器单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.llm.memory_compressor import (
    MemoryCompressor,
    CompressorConfig,
    ExtractedInfo,
    _SECURITY_KEYWORDS,
)


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def test_short_messages_no_compress():
    """短消息列表不触发压缩。"""
    compressor = MemoryCompressor(CompressorConfig(max_tokens=100, threshold_ratio=0.9))

    messages = [
        {"role": "system", "content": "You are a security auditor."},
        {"role": "user", "content": "Analyze this code."},
        {"role": "assistant", "content": "OK, I'll analyze it."},
    ]

    result = compressor.compress_history(messages)
    assert len(result) == 3, f"短消息不应被压缩，实际长度 {len(result)}"
    assert result == messages, "短消息应原样返回"
    ok("短消息列表不触发压缩")


def test_should_compress():
    """should_compress 正确判断是否需要压缩。"""
    # 低阈值，容易触发
    compressor = MemoryCompressor(CompressorConfig(max_tokens=50, threshold_ratio=0.5))

    short_messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
    ]
    assert compressor.should_compress(short_messages) is False

    # 长消息，超过阈值
    long_messages = [
        {"role": "system", "content": "system prompt " * 20},
    ]
    for i in range(20):
        long_messages.append({"role": "user", "content": f"message {i} " * 10})
        long_messages.append({"role": "assistant", "content": f"response {i} " * 10})

    assert compressor.should_compress(long_messages) is True
    ok("should_compress 判断正确")


def test_compress_preserves_system():
    """压缩后保留所有系统消息。"""
    compressor = MemoryCompressor(CompressorConfig(max_tokens=100, threshold_ratio=0.3))

    messages = [
        {"role": "system", "content": "System prompt 1"},
        {"role": "system", "content": "System prompt 2"},
    ]
    # 添加足够多的消息触发压缩
    for i in range(30):
        messages.append({"role": "user", "content": f"User message {i} with some content"})
        messages.append({"role": "assistant", "content": f"Assistant response {i} with analysis"})

    result = compressor.compress_history(messages)

    # 检查系统消息保留
    system_msgs = [m for m in result if m.get("role") == "system"]
    assert len(system_msgs) == 2, f"应保留 2 条系统消息，实际 {len(system_msgs)}"
    assert system_msgs[0]["content"] == "System prompt 1"
    assert system_msgs[1]["content"] == "System prompt 2"
    ok("压缩后保留所有系统消息")


def test_compress_keeps_recent():
    """压缩后保留最近 N 条消息。"""
    config = CompressorConfig(max_tokens=100, threshold_ratio=0.3, keep_recent=5)
    compressor = MemoryCompressor(config)

    messages = [{"role": "system", "content": "sys"}]
    for i in range(20):
        messages.append({"role": "user", "content": f"msg_{i}"})
        messages.append({"role": "assistant", "content": f"resp_{i}"})

    result = compressor.compress_history(messages)

    # 检查最近消息保留（最后 5 条非系统消息）
    non_system = [m for m in result if m.get("role") != "system"]
    # 应该有 1 条压缩摘要 + 5 条最近消息 = 6 条
    assert len(non_system) == 6, f"应有 6 条非系统消息，实际 {len(non_system)}"

    # 最后 5 条应是原始消息
    last_5 = non_system[-5:]
    assert last_5[-1]["content"] == "resp_19"
    assert last_5[-2]["content"] == "msg_19"
    ok("压缩后保留最近 5 条消息")


def test_compress_extracts_security_keywords():
    """压缩时提取安全审计关键词。"""
    compressor = MemoryCompressor(CompressorConfig(max_tokens=100, threshold_ratio=0.3))

    messages = [{"role": "system", "content": "Security audit assistant."}]
    # 添加包含安全关键词的消息
    messages.append({"role": "user", "content": "Check for SQL injection vulnerabilities."})
    messages.append({"role": "assistant", "content": "Found potential SQL injection: cursor.execute(f\"SELECT...\")"})
    messages.append({"role": "user", "content": "Analyze skynet/audit/runner.py for XSS risks."})
    messages.append({"role": "assistant", "content": "No XSS found in runner.py, but found SSRF potential."})

    # 添加更多消息触发压缩
    for i in range(20):
        messages.append({"role": "user", "content": f"Additional question {i}"})
        messages.append({"role": "assistant", "content": f"Additional answer {i}"})

    result = compressor.compress_history(messages)

    # 检查压缩摘要包含关键信息
    summary_msg = None
    for m in result:
        if m.get("role") == "assistant" and "[Conversation compressed]" in m.get("content", ""):
            summary_msg = m
            break

    assert summary_msg is not None, "应有压缩摘要消息"
    content = summary_msg["content"].lower()
    # 应包含一些安全关键词
    assert "sql" in content or "injection" in content or "ssrf" in content, \
        f"摘要应包含安全关键词，实际内容: {content[:200]}"
    ok("压缩时提取安全审计关键词")


def test_compress_reduces_token_count():
    """压缩后 token 数减少。"""
    from skynet.llm.tokenizer import TokenEstimator

    compressor = MemoryCompressor(CompressorConfig(max_tokens=200, threshold_ratio=0.5))

    messages = [{"role": "system", "content": "You are a helpful assistant."}]
    for i in range(50):
        messages.append({"role": "user", "content": f"Question {i}: " + "x" * 100})
        messages.append({"role": "assistant", "content": f"Answer {i}: " + "y" * 100})

    original_tokens = TokenEstimator.estimate_messages_tokens(messages)
    result = compressor.compress_history(messages)
    compressed_tokens = TokenEstimator.estimate_messages_tokens(result)

    assert compressed_tokens < original_tokens, \
        f"压缩后 token 应减少: {compressed_tokens} >= {original_tokens}"
    reduction = (1 - compressed_tokens / original_tokens) * 100
    assert reduction > 30, f"压缩率应 > 30%，实际 {reduction:.1f}%"
    ok(f"压缩后 token 减少: {original_tokens} -> {compressed_tokens} ({reduction:.1f}%)")


def test_extract_info():
    """_extract_info 正确提取关键信息。"""
    compressor = MemoryCompressor()

    messages = [
        {"role": "user", "content": "Found SQL injection in app/views.py at line 42"},
        {"role": "assistant", "content": "Confirmed SQL injection vulnerability. Also found XSS in templates/index.html"},
        {"role": "user", "content": "Run semgrep on skynet/analyze/runner.py"},
    ]

    info = compressor._extract_info(messages)

    assert len(info.findings) > 0, "应提取到发现"
    assert len(info.files_analyzed) > 0, "应提取到文件路径"

    # 检查文件路径提取
    file_str = " ".join(info.files_analyzed)
    assert "views.py" in file_str or "index.html" in file_str or "runner.py" in file_str, \
        f"应提取到文件路径，实际: {info.files_analyzed}"
    ok(f"_extract_info: 提取 {len(info.findings)} 条发现, {len(info.files_analyzed)} 个文件")


def test_build_summary():
    """_build_summary 生成可读摘要。"""
    compressor = MemoryCompressor()

    info = ExtractedInfo(
        findings=["SQL injection found", "XSS vulnerability"],
        files_analyzed=["app.py", "views.py"],
    )

    summary = compressor._build_summary(info, 10)

    assert "10 messages" in summary
    assert "SQL injection" in summary or "sql injection" in summary.lower()
    assert "app.py" in summary or "views.py" in summary
    ok("_build_summary 生成可读摘要")


def main():
    print("=" * 60)
    print("对话记忆压缩器测试")
    print("=" * 60)

    test_short_messages_no_compress()
    test_should_compress()
    test_compress_preserves_system()
    test_compress_keeps_recent()
    test_compress_extracts_security_keywords()
    test_compress_reduces_token_count()
    test_extract_info()
    test_build_summary()

    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
