#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Token 估算器单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.llm.tokenizer import TokenEstimator


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def test_empty_string():
    """空字符串返回 0。"""
    result = TokenEstimator.count_tokens("", model="gpt-4")
    assert result == 0, f"空字符串应返回 0，实际返回 {result}"
    ok("空字符串返回 0")


def test_short_text():
    """短文本返回正数。"""
    result = TokenEstimator.count_tokens("hello world", model="gpt-4")
    assert result > 0, f"短文本应返回正数，实际返回 {result}"
    ok(f"短文本 'hello world' 估算为 {result} tokens")


def test_long_text():
    """长文本返回更大值。"""
    short = TokenEstimator.count_tokens("hello", model="gpt-4")
    long = TokenEstimator.count_tokens("hello " * 100, model="gpt-4")
    assert long > short, f"长文本 token 应大于短文本: {long} <= {short}"
    ok(f"长文本估算为 {long} tokens，大于短文本 {short}")


def test_chinese_text():
    """中文文本使用更小的 chars/token 比例。"""
    # 纯中文
    chinese = "这是一段中文文本用于测试token估算功能"
    # 纯英文（相同字符数）
    english = "a" * len(chinese)

    chinese_tokens = TokenEstimator._count_with_ratio(chinese)
    english_tokens = TokenEstimator._count_with_ratio(english)

    # 中文应该比英文 token 更多（因为 chars_per_token 更小）
    assert chinese_tokens > english_tokens, (
        f"中文 token 数应大于英文: {chinese_tokens} <= {english_tokens}"
    )
    ok(f"中文 {chinese_tokens} tokens > 英文 {english_tokens} tokens")


def test_model_encoding_selection():
    """不同模型选择正确的编码器。"""
    assert TokenEstimator._get_encoding_name("gpt-4") == "cl100k_base"
    assert TokenEstimator._get_encoding_name("gpt-4o") == "o200k_base"
    assert TokenEstimator._get_encoding_name("gpt-3.5-turbo") == "cl100k_base"
    assert TokenEstimator._get_encoding_name("deepseek-chat") == "cl100k_base"
    assert TokenEstimator._get_encoding_name("unknown-model") == "cl100k_base"
    ok("模型编码器选择正确")


def test_estimate_messages_tokens():
    """消息列表 token 估算。"""
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Hello!"},
        {"role": "assistant", "content": "Hi there!"},
    ]
    total = TokenEstimator.estimate_messages_tokens(messages, model="gpt-4")
    assert total > 0, f"消息列表 token 应大于 0，实际返回 {total}"
    # 至少包含 3 条消息的开销（3 * 4 = 12 token）
    assert total >= 12, f"消息列表 token 应至少 12，实际返回 {total}"
    ok(f"消息列表估算为 {total} tokens")


def test_estimate_messages_with_content_blocks():
    """content block 格式的消息 token 估算。"""
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Hello world"},
                {"type": "image", "source": "base64..."},  # 非 text 类型应被忽略
            ],
        }
    ]
    total = TokenEstimator.estimate_messages_tokens(messages, model="gpt-4")
    assert total > 0, f"content block 消息 token 应大于 0"
    ok(f"content block 消息估算为 {total} tokens")


def test_fallback_path():
    """测试 fallback 路径（不依赖 tiktoken）。"""
    # 直接调用 _count_with_ratio 测试 fallback 逻辑
    result = TokenEstimator._count_with_ratio("hello world")
    assert result > 0, f"fallback 应返回正数，实际返回 {result}"
    ok(f"fallback 路径正常，估算为 {result} tokens")


def test_tiktoken_availability_check():
    """测试 tiktoken 可用性检查。"""
    result = TokenEstimator.is_tiktoken_available()
    assert isinstance(result, bool), "应返回布尔值"
    ok(f"tiktoken 可用: {result}")


def main():
    print("=" * 60)
    print("Token 估算器测试")
    print("=" * 60)

    test_empty_string()
    test_short_text()
    test_long_text()
    test_chinese_text()
    test_model_encoding_selection()
    test_estimate_messages_tokens()
    test_estimate_messages_with_content_blocks()
    test_fallback_path()
    test_tiktoken_availability_check()

    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
