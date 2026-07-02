#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Prompt Cache 单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.llm.prompt_cache import (
    PromptCacheManager,
    CacheStrategy,
    CacheStats,
    CACHE_CONTROL_MARKER,
    get_prompt_cache_manager,
)


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def test_supports_caching():
    """正确检测支持缓存的模型。"""
    manager = PromptCacheManager()

    # Claude 支持
    assert manager.supports_caching("claude-3-opus-20240229") is True
    assert manager.supports_caching("claude-3-sonnet") is True
    assert manager.supports_caching("anthropic/claude-3") is True

    # 非 Claude 不支持
    assert manager.supports_caching("gpt-4") is False
    assert manager.supports_caching("deepseek-chat") is False
    assert manager.supports_caching("gpt-4o") is False

    # provider 参数
    assert manager.supports_caching("some-model", provider="anthropic") is True
    ok("supports_caching 检测正确")


def test_strategy_selection():
    """根据对话长度选择正确的缓存策略。"""
    manager = PromptCacheManager()

    # 空消息
    assert manager.get_strategy([]) == CacheStrategy.NONE

    # 短对话（1-2 条非系统消息）
    short = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hi"},
    ]
    assert manager.get_strategy(short) == CacheStrategy.SYSTEM_ONLY

    # 中等对话（3-10 条）
    medium = [{"role": "system", "content": "sys"}]
    for i in range(5):
        medium.append({"role": "user", "content": f"msg{i}"})
        medium.append({"role": "assistant", "content": f"resp{i}"})
    assert manager.get_strategy(medium) == CacheStrategy.SYSTEM_AND_EARLY

    # 长对话（>10 条）
    long = [{"role": "system", "content": "sys"}]
    for i in range(15):
        long.append({"role": "user", "content": f"msg{i}"})
        long.append({"role": "assistant", "content": f"resp{i}"})
    assert manager.get_strategy(long) == CacheStrategy.MULTI_POINT
    ok("缓存策略选择正确")


def test_process_messages_non_claude():
    """非 Claude 模型不添加缓存标记。"""
    manager = PromptCacheManager()
    messages = [
        {"role": "system", "content": "sys prompt"},
        {"role": "user", "content": "hello"},
    ]
    result, cached = manager.process_messages(messages, model="gpt-4")
    assert cached is False
    assert result == messages  # 不应修改原始消息
    ok("非 Claude 模型不添加缓存标记")


def test_process_messages_system_only():
    """短对话只缓存 system prompt。"""
    manager = PromptCacheManager()
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Hello!"},
    ]
    result, cached = manager.process_messages(messages, model="claude-3-opus")
    assert cached is True

    # 检查 system 消息有缓存标记
    system_msg = result[0]
    content = system_msg.get("content", [])
    assert isinstance(content, list), "content 应转换为 list 格式"
    assert len(content) > 0
    assert content[0].get("cache_control") == CACHE_CONTROL_MARKER

    # user 消息不应有缓存标记
    user_msg = result[1]
    user_content = user_msg.get("content", [])
    if isinstance(user_content, list):
        for block in user_content:
            if isinstance(block, dict):
                assert block.get("cache_control") is None
    ok("短对话只缓存 system prompt")


def test_process_messages_multi_point():
    """长对话添加多个缓存点。"""
    manager = PromptCacheManager()
    messages = [{"role": "system", "content": "System prompt"}]
    for i in range(20):
        messages.append({"role": "user", "content": f"Question {i}"})
        messages.append({"role": "assistant", "content": f"Answer {i}"})

    result, cached = manager.process_messages(messages, model="claude-3-opus")
    assert cached is True

    # 统计缓存标记数量
    cache_count = 0
    for msg in result:
        content = msg.get("content", [])
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("cache_control"):
                    cache_count += 1

    assert cache_count >= 2, f"多缓存点策略应有 >= 2 个缓存标记，实际 {cache_count}"
    ok(f"长对话多缓存点策略: {cache_count} 个缓存标记")


def test_process_messages_preserves_original():
    """处理消息不修改原始数据。"""
    manager = PromptCacheManager()
    original_content = "Original system prompt"
    messages = [
        {"role": "system", "content": original_content},
        {"role": "user", "content": "Hello"},
    ]
    original_copy = [dict(m) for m in messages]

    result, _ = manager.process_messages(messages, model="claude-3-opus")

    # 原始消息的 content 不应改变
    assert messages[0]["content"] == original_content
    ok("处理消息不修改原始数据")


def test_update_stats():
    """缓存统计正确更新。"""
    manager = PromptCacheManager()

    manager.update_stats(cache_read_tokens=1000, total_tokens=2000)
    manager.update_stats(cache_read_tokens=500, total_tokens=1500)
    manager.update_stats(cache_creation_tokens=200)

    stats = manager.get_stats()
    assert stats["cache_hits"] == 2
    assert stats["cached_tokens"] == 1700  # 1000 + 500 from hits + 200 from creation
    assert stats["total_tokens"] == 3500
    ok(f"缓存统计正确: {stats}")


def test_reset_stats():
    """重置统计。"""
    manager = PromptCacheManager()
    manager.update_stats(cache_read_tokens=1000, total_tokens=2000)
    manager.reset_stats()
    stats = manager.get_stats()
    assert stats["cache_hits"] == 0
    assert stats["cached_tokens"] == 0
    ok("重置统计正确")


def test_global_manager():
    """全局管理器单例。"""
    m1 = get_prompt_cache_manager()
    m2 = get_prompt_cache_manager()
    assert m1 is m2, "应返回同一实例"
    ok("全局管理器单例正确")


def test_empty_messages():
    """空消息列表处理。"""
    manager = PromptCacheManager()
    result, cached = manager.process_messages([], model="claude-3-opus")
    assert result == []
    assert cached is False
    ok("空消息列表处理正确")


def main():
    print("=" * 60)
    print("Prompt Cache 测试")
    print("=" * 60)

    test_supports_caching()
    test_strategy_selection()
    test_process_messages_non_claude()
    test_process_messages_system_only()
    test_process_messages_multi_point()
    test_process_messages_preserves_original()
    test_update_stats()
    test_reset_stats()
    test_global_manager()
    test_empty_messages()

    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
