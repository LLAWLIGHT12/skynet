"""OpenAI 兼容 LLM 客户端（含韧性层：熔断/重试/Prompt Cache）。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from loguru import logger
from openai import AsyncOpenAI

from skynet.config import LLMConfig as SkynetLLMConfig, SkynetConfig, get_config, load_dotenv_if_present

# ── 韧性层（可选依赖，import 失败不影响基础功能） ──
try:
    from skynet.llm.resilience import (
        CircuitBreaker, CircuitBreakerConfig as CBConfig,
        RetryConfig, retry_with_backoff,
        get_llm_circuit,
    )
    _RESILIENCE_AVAILABLE = True
except ImportError:
    _RESILIENCE_AVAILABLE = False

try:
    from skynet.llm.prompt_cache import get_prompt_cache_manager
    _PROMPT_CACHE_AVAILABLE = True
except ImportError:
    _PROMPT_CACHE_AVAILABLE = False


@dataclass
class LLMConfig:
    api_base_url: str
    api_key: str
    model_name: str
    temperature: float = 0.1
    max_tokens: int = 8000
    timeout: float = 60.0


def load_llm_config(config: Optional[SkynetConfig] = None) -> LLMConfig:
    load_dotenv_if_present()
    cfg = (config or get_config()).llm.resolve()
    return LLMConfig(
        api_base_url=cfg.api_base_url,
        api_key=cfg.api_key,
        model_name=cfg.model_name,
        temperature=cfg.temperature,
        max_tokens=cfg.max_tokens,
        timeout=cfg.timeout,
    )


class LLMClient:
    """异步 OpenAI 兼容客户端（DeepSeek 等）。

    可选韧性层（通过 skynet_config 启用）：
    - CircuitBreaker：连续失败自动熔断
    - RetryConfig：指数退避重试
    - PromptCache：Claude 缓存标记
    """

    def __init__(
        self,
        config: Optional[LLMConfig] = None,
        skynet_config: Optional[SkynetConfig] = None,
    ) -> None:
        self.config = config or load_llm_config()
        self._skynet_config = skynet_config or get_config()
        self._client = AsyncOpenAI(
            api_key=self.config.api_key,
            base_url=self.config.api_base_url,
            timeout=self.config.timeout,
        )
        logger.debug(
            "LLM 客户端: model={}, base={}",
            self.config.model_name,
            self.config.api_base_url,
        )

        # ── 韧性层初始化 ──
        self._circuit: Optional[Any] = None
        self._retry_config: Optional[Any] = None
        self._prompt_cache_mgr: Optional[Any] = None
        self._init_resilience()

    def _init_resilience(self) -> None:
        """初始化韧性层（熔断/重试/Prompt Cache）。"""
        rcfg = self._skynet_config.resilience

        # 熔断器
        if _RESILIENCE_AVAILABLE and rcfg.circuit_breaker_enabled:
            self._circuit = get_llm_circuit()
            self._circuit.config.failure_threshold = rcfg.failure_threshold
            self._circuit.config.recovery_timeout = rcfg.recovery_timeout
            logger.debug("LLM 韧性: 熔断器已启用 (threshold={})", rcfg.failure_threshold)

        # 重试
        if _RESILIENCE_AVAILABLE and rcfg.retry_enabled:
            self._retry_config = RetryConfig(
                max_attempts=rcfg.max_attempts,
                base_delay=rcfg.base_delay,
                max_delay=rcfg.max_delay,
            )
            logger.debug("LLM 韧性: 重试已启用 (max_attempts={})", rcfg.max_attempts)

        # Prompt Cache
        if _PROMPT_CACHE_AVAILABLE and rcfg.prompt_cache_enabled:
            self._prompt_cache_mgr = get_prompt_cache_manager()
            logger.debug("LLM 韧性: Prompt Cache 已启用")

    def _process_messages_for_cache(self, messages: list[dict]) -> list[dict]:
        """为 Claude 模型添加缓存标记。"""
        if self._prompt_cache_mgr is None:
            return messages
        processed, cached = self._prompt_cache_mgr.process_messages(
            messages, model=self.config.model_name,
        )
        return processed

    async def _create_completion(self, messages: list[dict], **kwargs: Any) -> Any:
        """底层 API 调用，熔断 + 重试叠加。

        重试嵌套在熔断器内部：每次重试尝试都会经过熔断器状态检查，
        熔断器打开时直接拒绝，避免无效重试。
        """
        async def _do_call() -> Any:
            return await self._client.chat.completions.create(
                model=self.config.model_name,
                messages=messages,
                **kwargs,
            )

        async def _call_with_retry() -> Any:
            """重试包裹的调用（被熔断器包裹）。"""
            if self._retry_config is not None:
                return await retry_with_backoff(_do_call, self._retry_config, operation_name="llm_call")
            return await _do_call()

        # 熔断器包裹重试逻辑
        if self._circuit is not None:
            return await self._circuit.call(_call_with_retry)

        return await _call_with_retry()

    async def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: Optional[float] = None,
    ) -> tuple[str, dict[str, Any]]:
        """调用 chat completion，返回 (assistant文本, token_usage)。"""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        # Prompt Cache 处理
        messages = self._process_messages_for_cache(messages)

        response = await self._create_completion(
            messages,
            temperature=temperature if temperature is not None else self.config.temperature,
            max_tokens=self.config.max_tokens,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        if not content:
            raise RuntimeError("LLM 返回空内容")
        raw_usage = response.usage.model_dump() if response.usage else {}
        usage = {
            "input_tokens": raw_usage.get("prompt_tokens", raw_usage.get("input_tokens", 0)),
            "output_tokens": raw_usage.get("completion_tokens", raw_usage.get("output_tokens", 0)),
            "cache_read_input_tokens": raw_usage.get("prompt_cache_hit_tokens", raw_usage.get("cache_read_input_tokens", 0)),
            "cache_creation_input_tokens": raw_usage.get("prompt_cache_miss_tokens", raw_usage.get("cache_creation_input_tokens", 0)),
        }
        # 更新 Prompt Cache 统计
        if self._prompt_cache_mgr is not None:
            self._prompt_cache_mgr.update_stats(
                cache_read_tokens=usage.get("cache_read_input_tokens", 0),
                cache_creation_tokens=usage.get("cache_creation_input_tokens", 0),
                total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            )
        return content, usage

    async def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        **kwargs: Any,
    ) -> str:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        messages = self._process_messages_for_cache(messages)

        response = await self._create_completion(
            messages,
            temperature=kwargs.get("temperature", self.config.temperature),
            max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
        )
        content = response.choices[0].message.content
        if not content:
            raise RuntimeError("LLM 返回空内容")
        return content
