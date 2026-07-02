"""LLM 韧性三件套：熔断器 + 结构化重试 + 降级处理。"""

from __future__ import annotations

import asyncio
import random
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Awaitable, Callable, Dict, Generic, List, Optional, Tuple, Type, TypeVar

from loguru import logger

T = TypeVar("T")


# ─────────────────────────────────────────────
# 自定义异常
# ─────────────────────────────────────────────

class CircuitOpenError(RuntimeError):
    """熔断器打开时抛出。"""

    def __init__(self, name: str):
        self.name = name
        super().__init__(f"Circuit breaker '{name}' is OPEN")


# ─────────────────────────────────────────────
# 1. CircuitBreaker — 三态熔断器
# ─────────────────────────────────────────────

class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    """熔断器配置。"""
    failure_threshold: int = 5        # 连续失败 N 次 → OPEN
    success_threshold: int = 3        # HALF_OPEN 连续成功 N 次 → CLOSED
    recovery_timeout: float = 30.0    # OPEN 后等待 N 秒 → HALF_OPEN
    half_open_max_calls: int = 3      # HALF_OPEN 最多允许 N 次试探调用
    excluded_exceptions: Tuple[Type[Exception], ...] = ()


@dataclass
class CircuitStats:
    """熔断器统计。"""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: Optional[float] = None

    @property
    def failure_rate(self) -> float:
        return self.failed_calls / self.total_calls if self.total_calls > 0 else 0.0

    def record_success(self) -> None:
        self.total_calls += 1
        self.successful_calls += 1
        self.consecutive_successes += 1
        self.consecutive_failures = 0

    def record_failure(self) -> None:
        self.total_calls += 1
        self.failed_calls += 1
        self.consecutive_failures += 1
        self.consecutive_successes = 0
        self.last_failure_time = time.time()

    def record_rejection(self) -> None:
        self.rejected_calls += 1

    def reset(self) -> None:
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.consecutive_failures = 0
        self.consecutive_successes = 0


class CircuitBreaker:
    """LLM 调用熔断器。

    用法::

        cb = CircuitBreaker("llm")
        result = await cb.call(lambda: my_llm_call())
    """

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._lock = asyncio.Lock()
        self._half_open_calls = 0
        self._last_state_change = time.time()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def stats(self) -> CircuitStats:
        return self._stats

    @property
    def is_closed(self) -> bool:
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        return self._state == CircuitState.OPEN

    async def _transition_to(self, new_state: CircuitState) -> None:
        if self._state == new_state:
            return
        logger.debug("CircuitBreaker[%s] %s -> %s", self.name, self._state.value, new_state.value)
        self._state = new_state
        self._last_state_change = time.time()
        if new_state == CircuitState.HALF_OPEN:
            self._half_open_calls = 0
        elif new_state == CircuitState.CLOSED:
            self._stats.reset()

    async def _check_state(self) -> bool:
        async with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            elif self._state == CircuitState.OPEN:
                if time.time() - self._last_state_change >= self.config.recovery_timeout:
                    await self._transition_to(CircuitState.HALF_OPEN)
                    return True
                self._stats.record_rejection()
                return False
            elif self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                self._stats.record_rejection()
                return False
        return False

    async def _on_success(self) -> None:
        async with self._lock:
            self._stats.record_success()
            if self._state == CircuitState.HALF_OPEN:
                if self._stats.consecutive_successes >= self.config.success_threshold:
                    await self._transition_to(CircuitState.CLOSED)

    async def _on_failure(self, error: Exception) -> None:
        if isinstance(error, self.config.excluded_exceptions):
            return
        async with self._lock:
            self._stats.record_failure()
            if self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self.config.failure_threshold:
                    await self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.HALF_OPEN:
                await self._transition_to(CircuitState.OPEN)

    async def call(self, func: Callable[[], Awaitable[T]]) -> T:
        """通过熔断器调用异步函数。"""
        if not await self._check_state():
            raise CircuitOpenError(self.name)
        try:
            result = await func()
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure(e)
            raise

    async def __aenter__(self) -> "CircuitBreaker":
        if not await self._check_state():
            raise CircuitOpenError(self.name)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_val is not None:
            await self._on_failure(exc_val)
        else:
            await self._on_success()
        return False

    def protect(self, func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        """装饰器模式。"""
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            return await self.call(lambda: func(*args, **kwargs))
        return wrapper

    async def reset(self) -> None:
        async with self._lock:
            await self._transition_to(CircuitState.CLOSED)
            self._stats = CircuitStats()

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self._state.value,
            "stats": {
                "total_calls": self._stats.total_calls,
                "successful_calls": self._stats.successful_calls,
                "failed_calls": self._stats.failed_calls,
                "rejected_calls": self._stats.rejected_calls,
                "failure_rate": self._stats.failure_rate,
            },
        }


class CircuitBreakerRegistry:
    """全局熔断器注册表。"""

    def __init__(self, default_config: Optional[CircuitBreakerConfig] = None):
        self._circuits: Dict[str, CircuitBreaker] = {}
        self._default_config = default_config or CircuitBreakerConfig()

    def get_or_create(self, name: str, config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        if name not in self._circuits:
            self._circuits[name] = CircuitBreaker(name, config or self._default_config)
        return self._circuits[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        return self._circuits.get(name)

    async def reset_all(self) -> None:
        for circuit in self._circuits.values():
            await circuit.reset()

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        return {name: cb.get_status() for name, cb in self._circuits.items()}


# 全局注册表
_global_registry: Optional[CircuitBreakerRegistry] = None
_registry_lock = threading.Lock()


def get_circuit_registry() -> CircuitBreakerRegistry:
    global _global_registry
    if _global_registry is None:
        with _registry_lock:
            if _global_registry is None:
                _global_registry = CircuitBreakerRegistry()
    return _global_registry


def get_llm_circuit() -> CircuitBreaker:
    """获取 LLM 调用专用熔断器。"""
    return get_circuit_registry().get_or_create(
        "llm", CircuitBreakerConfig(failure_threshold=5, recovery_timeout=30.0)
    )


# ─────────────────────────────────────────────
# 2. RetryConfig — 结构化重试
# ─────────────────────────────────────────────

class BackoffStrategy(str, Enum):
    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"


# Skynet 可恢复错误
_RETRYABLE_EXCEPTIONS: Tuple[Type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    asyncio.TimeoutError,
)


@dataclass
class RetryConfig:
    """重试配置。

    用法::

        config = RetryConfig(max_attempts=3)
        result = await retry_with_backoff(my_func, config)
    """
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    jitter_factor: float = 0.5
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL
    retryable_exceptions: Tuple[Type[Exception], ...] = _RETRYABLE_EXCEPTIONS

    def should_retry(self, error: Exception) -> bool:
        """判断错误是否可重试。"""
        if isinstance(error, self.retryable_exceptions):
            return True
        # 检查错误名（兼容 Skynet 的 TransientAgentError 等）
        error_name = type(error).__name__.lower()
        if any(kw in error_name for kw in ("transient", "ratelimit", "timeout", "connection")):
            return True
        # 不可恢复错误
        if any(kw in error_name for kw in ("quota", "contextlength", "auth")):
            return False
        return False

    def calculate_delay(self, attempt: int, error: Optional[Exception] = None) -> float:
        """计算第 attempt 次重试的等待时间。"""
        # 检查 retry-after
        if error:
            retry_after = getattr(error, "retry_after", None)
            if retry_after:
                return min(float(retry_after), self.max_delay)

        if self.backoff_strategy == BackoffStrategy.CONSTANT:
            delay = self.base_delay
        elif self.backoff_strategy == BackoffStrategy.LINEAR:
            delay = self.base_delay * (attempt + 1)
        else:
            delay = self.base_delay * (self.exponential_base ** attempt)

        delay = min(delay, self.max_delay)

        if self.jitter:
            jitter_range = delay * self.jitter_factor
            delay = delay + random.uniform(-jitter_range, jitter_range)
            delay = max(0.1, delay)

        return delay


@dataclass
class RetryResult(Generic[T]):
    """重试结果。"""
    success: bool
    value: Optional[T] = None
    error: Optional[Exception] = None
    attempts: int = 0
    total_delay: float = 0.0


# 预定义配置
LLM_RETRY_CONFIG = RetryConfig(max_attempts=3, base_delay=1.0, max_delay=60.0)
TOOL_RETRY_CONFIG = RetryConfig(max_attempts=2, base_delay=2.0, max_delay=30.0)
NO_RETRY_CONFIG = RetryConfig(max_attempts=1, base_delay=0, max_delay=0)


async def retry_with_backoff(
    func: Callable[[], Awaitable[T]],
    config: Optional[RetryConfig] = None,
    on_retry: Optional[Callable[[int, Exception, float], Awaitable[None]]] = None,
    operation_name: str = "operation",
) -> T:
    """带指数退避的重试执行。"""
    cfg = config or RetryConfig()
    last_exception: Optional[Exception] = None

    for attempt in range(cfg.max_attempts):
        try:
            return await func()
        except Exception as e:
            last_exception = e
            if not cfg.should_retry(e):
                raise
            if attempt >= cfg.max_attempts - 1:
                raise

            delay = cfg.calculate_delay(attempt, e)
            logger.info(
                "[%s] attempt %d failed (%s), retrying in %.1fs",
                operation_name, attempt + 1, e, delay,
            )
            if on_retry:
                await on_retry(attempt + 1, e, delay)
            await asyncio.sleep(delay)

    if last_exception:
        raise last_exception
    raise RuntimeError(f"{operation_name} failed after {cfg.max_attempts} attempts")


async def retry_with_result(
    func: Callable[[], Awaitable[T]],
    config: Optional[RetryConfig] = None,
) -> RetryResult[T]:
    """带重试的执行，返回 RetryResult 而非抛异常。"""
    cfg = config or RetryConfig()
    total_delay = 0.0
    last_exception: Optional[Exception] = None

    for attempt in range(cfg.max_attempts):
        try:
            result = await func()
            return RetryResult(success=True, value=result, attempts=attempt + 1, total_delay=total_delay)
        except Exception as e:
            last_exception = e
            if not cfg.should_retry(e) or attempt >= cfg.max_attempts - 1:
                return RetryResult(success=False, error=e, attempts=attempt + 1, total_delay=total_delay)
            delay = cfg.calculate_delay(attempt, e)
            total_delay += delay
            await asyncio.sleep(delay)

    return RetryResult(success=False, error=last_exception, attempts=cfg.max_attempts, total_delay=total_delay)


# ─────────────────────────────────────────────
# 3. FallbackHandler — 降级处理
# ─────────────────────────────────────────────

class FallbackAction(str, Enum):
    RETRY = "retry"
    RETRY_WITH_REDUCED_CONTEXT = "retry_reduced"
    USE_FALLBACK_TOOL = "use_fallback"
    SKIP = "skip"
    CONTINUE_PARTIAL = "continue_partial"
    ABORT = "abort"


@dataclass
class FallbackResult:
    """降级结果。"""
    action: FallbackAction
    success: bool
    result: Optional[Any] = None
    error: Optional[Exception] = None
    fallback_used: Optional[str] = None
    message: str = ""


@dataclass
class FallbackConfig:
    """降级配置。"""
    enabled: bool = True
    max_context_reduction_ratio: float = 0.5
    continue_on_partial: bool = True
    tool_fallbacks: Dict[str, str] = field(default_factory=lambda: {
        "semgrep_scan": "pattern_match",
        "bandit_scan": "pattern_match",
        "gitleaks_scan": "search_code",
    })


class FallbackHandler:
    """降级处理器。

    用法::

        handler = FallbackHandler()
        result = await handler.handle_llm_failure(error, context)
    """

    def __init__(self, config: Optional[FallbackConfig] = None):
        self.config = config or FallbackConfig()

    async def handle_llm_failure(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        retry_func: Optional[Callable[[], Awaitable[Any]]] = None,
    ) -> FallbackResult:
        """处理 LLM 调用失败。"""
        if not self.config.enabled:
            return FallbackResult(action=FallbackAction.ABORT, success=False, error=error)

        ctx = context or {}
        error_name = type(error).__name__.lower()

        # 超时 → 缩减上下文重试
        if "timeout" in error_name:
            if retry_func and ctx.get("can_reduce_context", True):
                return FallbackResult(
                    action=FallbackAction.RETRY_WITH_REDUCED_CONTEXT,
                    success=False, error=error,
                    message="Timeout, will retry with reduced context",
                )
            return FallbackResult(
                action=FallbackAction.CONTINUE_PARTIAL,
                success=False, error=error,
                message="Timeout, continuing with partial results",
            )

        # 上下文过长 → 缩减上下文
        if "contextlength" in error_name or "context" in error_name and "long" in error_name:
            return FallbackResult(
                action=FallbackAction.RETRY_WITH_REDUCED_CONTEXT,
                success=False, error=error,
                message="Context too long, reducing and retrying",
            )

        # 速率限制 → 等待重试
        if "ratelimit" in error_name or "rate" in error_name and "limit" in error_name:
            return FallbackResult(
                action=FallbackAction.RETRY, success=False, error=error,
                message="Rate limited, will retry",
            )

        # 配额耗尽 → 中止
        if "quota" in error_name:
            return FallbackResult(
                action=FallbackAction.ABORT, success=False, error=error,
                message="Quota exhausted, aborting",
            )

        # 可恢复错误 → 重试
        if "transient" in error_name or "connection" in error_name:
            return FallbackResult(
                action=FallbackAction.RETRY, success=False, error=error,
                message="Recoverable error, will retry",
            )

        # 未知错误 → 中止
        return FallbackResult(
            action=FallbackAction.ABORT, success=False, error=error,
            message=f"Unknown LLM error: {error}",
        )

    async def handle_tool_failure(
        self,
        tool_name: str,
        error: Exception,
        tool_input: Optional[Dict[str, Any]] = None,
        fallback_executor: Optional[Callable[[str, Dict], Awaitable[Any]]] = None,
    ) -> FallbackResult:
        """处理工具执行失败。"""
        if not self.config.enabled:
            return FallbackResult(action=FallbackAction.ABORT, success=False, error=error)

        fallback_tool = self.config.tool_fallbacks.get(tool_name)
        inp = tool_input or {}

        if fallback_tool and fallback_executor:
            try:
                result = await fallback_executor(fallback_tool, inp)
                return FallbackResult(
                    action=FallbackAction.USE_FALLBACK_TOOL,
                    success=True, result=result,
                    fallback_used=fallback_tool,
                    message=f"Used fallback tool: {fallback_tool}",
                )
            except Exception as fallback_error:
                logger.warning("Fallback tool %s also failed: %s", fallback_tool, fallback_error)
                return FallbackResult(
                    action=FallbackAction.SKIP, success=False,
                    error=fallback_error, fallback_used=fallback_tool,
                    message=f"Fallback tool also failed: {fallback_error}",
                )

        return FallbackResult(
            action=FallbackAction.SKIP, success=False, error=error,
            message=f"Tool failed, skipping: {error}",
        )

    def reduce_context(
        self,
        messages: List[Dict[str, Any]],
        reduction_ratio: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """缩减上下文：保留 system 消息 + 最近 N 条。"""
        ratio = reduction_ratio or self.config.max_context_reduction_ratio

        if len(messages) <= 2:
            return messages

        system_messages = [m for m in messages if m.get("role") == "system"]
        other_messages = [m for m in messages if m.get("role") != "system"]

        keep_count = max(1, int(len(other_messages) * ratio))
        kept_messages = other_messages[-keep_count:]

        return system_messages + kept_messages

    def truncate_content(
        self,
        content: str,
        max_length: int = 50000,
        keep_start: int = 20000,
        keep_end: int = 20000,
    ) -> str:
        """截断长内容，保留首尾。"""
        if len(content) <= max_length:
            return content

        notice = "\n\n... [CONTENT TRUNCATED] ...\n\n"
        available = max_length - len(notice)
        start_len = min(keep_start, available // 2)
        end_len = min(keep_end, available - start_len)

        return content[:start_len] + notice + content[-end_len:]


# 全局降级处理器
_global_handler: Optional[FallbackHandler] = None
_handler_lock = threading.Lock()


def get_fallback_handler() -> FallbackHandler:
    global _global_handler
    if _global_handler is None:
        with _handler_lock:
            if _global_handler is None:
                _global_handler = FallbackHandler()
    return _global_handler


def configure_fallback(config: FallbackConfig) -> None:
    global _global_handler
    _global_handler = FallbackHandler(config)
