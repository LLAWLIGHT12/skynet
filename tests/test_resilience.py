#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""LLM 韧性三件套单元测试（熔断器 + 重试 + 降级）。"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.llm.resilience import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
    CircuitBreakerRegistry,
    CircuitOpenError,
    RetryConfig,
    RetryResult,
    BackoffStrategy,
    retry_with_backoff,
    retry_with_result,
    LLM_RETRY_CONFIG,
    NO_RETRY_CONFIG,
    FallbackHandler,
    FallbackConfig,
    FallbackAction,
    get_circuit_registry,
    get_fallback_handler,
)


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


# ─────────────────────────────────────────────
# CircuitBreaker 测试
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_circuit_breaker_closed_state():
    """初始状态为 CLOSED，调用成功保持 CLOSED。"""
    cb = CircuitBreaker("test", CircuitBreakerConfig(failure_threshold=3))
    assert cb.state == CircuitState.CLOSED
    assert cb.is_closed

    async def success_func():
        return "ok"

    result = await cb.call(success_func)
    assert result == "ok"
    assert cb.state == CircuitState.CLOSED
    ok("CircuitBreaker: CLOSED 状态正常调用")


@pytest.mark.asyncio
async def test_circuit_breaker_open_after_failures():
    """连续失败达到阈值后，熔断器变为 OPEN。"""
    config = CircuitBreakerConfig(failure_threshold=3, recovery_timeout=10.0)
    cb = CircuitBreaker("test_open", config)

    async def fail_func():
        raise ConnectionError("fail")

    for i in range(3):
        try:
            await cb.call(fail_func)
        except ConnectionError:
            pass

    assert cb.state == CircuitState.OPEN, f"应为 OPEN，实际为 {cb.state}"
    assert cb.is_open
    ok("CircuitBreaker: 连续 3 次失败后 OPEN")


@pytest.mark.asyncio
async def test_circuit_breaker_rejects_when_open():
    """OPEN 状态下调用抛出 CircuitOpenError。"""
    config = CircuitBreakerConfig(failure_threshold=2, recovery_timeout=100.0)
    cb = CircuitBreaker("test_reject", config)

    async def fail_func():
        raise ConnectionError("fail")

    for _ in range(2):
        try:
            await cb.call(fail_func)
        except ConnectionError:
            pass

    assert cb.is_open

    try:
        await cb.call(fail_func)
        assert False, "应抛出 CircuitOpenError"
    except CircuitOpenError as e:
        assert e.name == "test_reject"
        ok("CircuitBreaker: OPEN 状态拒绝调用")


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_recovery():
    """OPEN 后等待 recovery_timeout，进入 HALF_OPEN，成功后恢复 CLOSED。"""
    config = CircuitBreakerConfig(
        failure_threshold=2,
        success_threshold=2,
        recovery_timeout=0.1,  # 100ms
    )
    cb = CircuitBreaker("test_recovery", config)

    async def fail_func():
        raise ConnectionError("fail")

    for _ in range(2):
        try:
            await cb.call(fail_func)
        except ConnectionError:
            pass

    assert cb.is_open

    # 等待恢复
    await asyncio.sleep(0.15)

    # 下一次调用应进入 HALF_OPEN
    call_count = 0

    async def success_func():
        nonlocal call_count
        call_count += 1
        return "recovered"

    result = await cb.call(success_func)
    assert result == "recovered"
    assert call_count == 1
    ok("CircuitBreaker: OPEN -> HALF_OPEN -> 成功调用")


@pytest.mark.asyncio
async def test_circuit_breaker_registry():
    """全局注册表正确管理熔断器。"""
    registry = CircuitBreakerRegistry()
    cb1 = registry.get_or_create("llm")
    cb2 = registry.get_or_create("llm")
    cb3 = registry.get_or_create("tool_semgrep")

    assert cb1 is cb2, "同名应返回同一实例"
    assert cb1 is not cb3
    assert registry.get("llm") is cb1
    assert registry.get("nonexistent") is None

    status = registry.get_all_status()
    assert "llm" in status
    assert "tool_semgrep" in status
    ok("CircuitBreakerRegistry: 注册表管理正确")


# ─────────────────────────────────────────────
# RetryConfig 测试
# ─────────────────────────────────────────────

def test_retry_config_should_retry():
    """RetryConfig 正确判断可恢复/不可恢复错误。"""
    config = RetryConfig()

    # 可恢复
    assert config.should_retry(ConnectionError("conn")) is True
    assert config.should_retry(TimeoutError("timeout")) is True

    # 不可恢复
    class QuotaExhaustedError(RuntimeError):
        pass

    class ContextLengthError(RuntimeError):
        pass

    assert config.should_retry(QuotaExhaustedError("quota")) is False
    assert config.should_retry(ContextLengthError("context")) is False

    # 瞬态错误（Skynet 风格）
    class TransientAgentError(RuntimeError):
        pass

    assert config.should_retry(TransientAgentError("transient")) is True
    ok("RetryConfig: 错误分类正确")


def test_retry_config_calculate_delay():
    """RetryConfig 正确计算退避时间。"""
    config = RetryConfig(
        base_delay=1.0,
        max_delay=60.0,
        exponential_base=2.0,
        jitter=False,  # 关闭 jitter 便于精确验证
        backoff_strategy=BackoffStrategy.EXPONENTIAL,
    )

    assert config.calculate_delay(0) == 1.0   # 1 * 2^0
    assert config.calculate_delay(1) == 2.0   # 1 * 2^1
    assert config.calculate_delay(2) == 4.0   # 1 * 2^2
    assert config.calculate_delay(3) == 8.0   # 1 * 2^3

    # LINEAR 策略
    linear_config = RetryConfig(
        base_delay=2.0, jitter=False,
        backoff_strategy=BackoffStrategy.LINEAR,
    )
    assert linear_config.calculate_delay(0) == 2.0   # 2 * (0+1)
    assert linear_config.calculate_delay(1) == 4.0   # 2 * (1+1)

    # CONSTANT 策略
    const_config = RetryConfig(
        base_delay=3.0, jitter=False,
        backoff_strategy=BackoffStrategy.CONSTANT,
    )
    assert const_config.calculate_delay(0) == 3.0
    assert const_config.calculate_delay(5) == 3.0
    ok("RetryConfig: 退避时间计算正确")


@pytest.mark.asyncio
async def test_retry_with_backoff_success():
    """retry_with_backoff 在重试后成功。"""
    call_count = 0

    async def flaky_func():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("transient")
        return "success"

    config = RetryConfig(max_attempts=3, base_delay=0.01, jitter=False)
    result = await retry_with_backoff(flaky_func, config, operation_name="test")
    assert result == "success"
    assert call_count == 3
    ok("retry_with_backoff: 第 3 次重试成功")


@pytest.mark.asyncio
async def test_retry_with_backoff_exhausted():
    """retry_with_backoff 重试耗尽后抛出异常。"""
    async def always_fail():
        raise ConnectionError("permanent")

    config = RetryConfig(max_attempts=2, base_delay=0.01, jitter=False)
    try:
        await retry_with_backoff(always_fail, config, operation_name="test")
        assert False, "应抛出异常"
    except ConnectionError:
        ok("retry_with_backoff: 重试耗尽后抛出异常")


@pytest.mark.asyncio
async def test_retry_with_backoff_non_retryable():
    """不可恢复错误不重试，立即抛出。"""
    call_count = 0

    class QuotaExhaustedError(RuntimeError):
        pass

    async def quota_fail():
        nonlocal call_count
        call_count += 1
        raise QuotaExhaustedError("quota")

    config = RetryConfig(max_attempts=3, base_delay=0.01)
    try:
        await retry_with_backoff(quota_fail, config)
        assert False, "应抛出异常"
    except QuotaExhaustedError:
        assert call_count == 1, f"不可恢复错误不应重试，实际调用 {call_count} 次"
        ok("retry_with_backoff: 不可恢复错误立即抛出")


@pytest.mark.asyncio
async def test_retry_with_result():
    """retry_with_result 返回 RetryResult。"""
    call_count = 0

    async def flaky_func():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise ConnectionError("transient")
        return "ok"

    config = RetryConfig(max_attempts=3, base_delay=0.01, jitter=False)
    result = await retry_with_result(flaky_func, config)
    assert result.success is True
    assert result.value == "ok"
    assert result.attempts == 2
    ok("retry_with_result: 返回正确的 RetryResult")


# ─────────────────────────────────────────────
# FallbackHandler 测试
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fallback_handler_timeout():
    """超时错误触发缩减上下文重试。"""
    handler = FallbackHandler()

    class LLMTimeoutError(RuntimeError):
        pass

    error = LLMTimeoutError("timeout")
    
    # 有 retry_func 时 -> RETRY_WITH_REDUCED_CONTEXT
    async def mock_retry():
        return "retried"
    
    result = await handler.handle_llm_failure(
        error, {"can_reduce_context": True}, retry_func=mock_retry
    )
    assert result.action == FallbackAction.RETRY_WITH_REDUCED_CONTEXT
    ok("FallbackHandler: 超时 + retry_func -> RETRY_WITH_REDUCED_CONTEXT")
    
    # 无 retry_func 时 -> CONTINUE_PARTIAL
    result2 = await handler.handle_llm_failure(error, {"can_reduce_context": True})
    assert result2.action == FallbackAction.CONTINUE_PARTIAL
    ok("FallbackHandler: 超时无 retry_func -> CONTINUE_PARTIAL")


@pytest.mark.asyncio
async def test_fallback_handler_quota():
    """配额耗尽触发中止。"""
    handler = FallbackHandler()

    class QuotaExhaustedError(RuntimeError):
        pass

    error = QuotaExhaustedError("quota")
    result = await handler.handle_llm_failure(error)
    assert result.action == FallbackAction.ABORT
    ok("FallbackHandler: 配额耗尽 -> ABORT")


@pytest.mark.asyncio
async def test_fallback_handler_tool_fallback():
    """工具失败后切换到备选工具。"""
    config = FallbackConfig(tool_fallbacks={"semgrep_scan": "pattern_match"})
    handler = FallbackHandler(config)

    async def mock_executor(tool_name, tool_input):
        return {"findings": ["mock_result"]}

    result = await handler.handle_tool_failure(
        "semgrep_scan",
        Exception("tool error"),
        {"path": "/test"},
        fallback_executor=mock_executor,
    )
    assert result.action == FallbackAction.USE_FALLBACK_TOOL
    assert result.success is True
    assert result.fallback_used == "pattern_match"
    ok("FallbackHandler: 工具失败 -> 切换备选工具")


def test_fallback_reduce_context():
    """reduce_context 正确缩减消息列表。"""
    handler = FallbackHandler(FallbackConfig(max_context_reduction_ratio=0.5))

    messages = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "msg1"},
        {"role": "assistant", "content": "msg2"},
        {"role": "user", "content": "msg3"},
        {"role": "assistant", "content": "msg4"},
    ]

    reduced = handler.reduce_context(messages)
    # 应保留 system + 最近 2 条（50% of 4 = 2）
    assert len(reduced) == 3  # 1 system + 2 recent
    assert reduced[0]["role"] == "system"
    assert reduced[-1]["content"] == "msg4"
    ok("FallbackHandler: reduce_context 正确缩减")


def test_fallback_truncate_content():
    """truncate_content 正确截断长内容。"""
    handler = FallbackHandler()
    content = "a" * 100000
    truncated = handler.truncate_content(content, max_length=10000)
    assert len(truncated) <= 10000
    assert "[CONTENT TRUNCATED]" in truncated
    ok("FallbackHandler: truncate_content 正确截断")


@pytest.mark.asyncio
async def test_fallback_disabled():
    """禁用降级时直接返回 ABORT。"""
    handler = FallbackHandler(FallbackConfig(enabled=False))
    result = await handler.handle_llm_failure(Exception("test"))
    assert result.action == FallbackAction.ABORT
    ok("FallbackHandler: 禁用时返回 ABORT")


# ─────────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────────

async def run_all():
    print("=" * 60)
    print("LLM 韧性三件套测试")
    print("=" * 60)

    # CircuitBreaker
    await test_circuit_breaker_closed_state()
    await test_circuit_breaker_open_after_failures()
    await test_circuit_breaker_rejects_when_open()
    await test_circuit_breaker_half_open_recovery()
    await test_circuit_breaker_registry()

    # RetryConfig
    test_retry_config_should_retry()
    test_retry_config_calculate_delay()
    await test_retry_with_backoff_success()
    await test_retry_with_backoff_exhausted()
    await test_retry_with_backoff_non_retryable()
    await test_retry_with_result()

    # FallbackHandler
    await test_fallback_handler_timeout()
    await test_fallback_handler_quota()
    await test_fallback_handler_tool_fallback()
    test_fallback_reduce_context()
    test_fallback_truncate_content()
    await test_fallback_disabled()

    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)


def main():
    asyncio.run(run_all())


if __name__ == "__main__":
    main()
