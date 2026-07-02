"""Claude Prompt 缓存管理器 — 自动添加缓存标记降低 token 消耗。

检测 Claude 系列模型，根据对话长度选择缓存策略，
为 system prompt 和早期消息添加 cache_control 标记。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CacheStrategy(str, Enum):
    """缓存策略。"""
    NONE = "none"                    # 不缓存
    SYSTEM_ONLY = "system_only"      # 仅缓存 system prompt
    SYSTEM_AND_EARLY = "system_early"  # 缓存 system + 早期对话
    MULTI_POINT = "multi_point"      # 多个缓存点


# 支持缓存的模型前缀
_CACHEABLE_MODEL_PREFIXES = [
    "claude-",
    "anthropic/claude",
]

# 缓存标记
CACHE_CONTROL_MARKER = {"type": "ephemeral"}


@dataclass
class CacheStats:
    """缓存统计。"""
    cache_hits: int = 0
    cache_misses: int = 0
    cached_tokens: int = 0
    total_tokens: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0

    @property
    def token_savings(self) -> int:
        """估算节省的 token（缓存命中时不重新计算）。"""
        return self.cached_tokens

    def record_hit(self, cached_tokens: int) -> None:
        self.cache_hits += 1
        self.cached_tokens += cached_tokens

    def record_miss(self, total_tokens: int) -> None:
        self.cache_misses += 1
        self.total_tokens += total_tokens

    def reset(self) -> None:
        self.cache_hits = 0
        self.cache_misses = 0
        self.cached_tokens = 0
        self.total_tokens = 0


class PromptCacheManager:
    """Claude Prompt 缓存管理器。

    用法::

        manager = PromptCacheManager()
        messages, was_cached = manager.process_messages(messages, model="claude-3-opus")
        # 发送处理后的消息到 API
        # 收到响应后更新统计
        manager.update_stats(cache_read_tokens=1000, total_tokens=2000)
    """

    def __init__(self):
        self.stats = CacheStats()

    def supports_caching(self, model: str, provider: str = "") -> bool:
        """检测模型是否支持 prompt caching。"""
        model_lower = model.lower()
        provider_lower = provider.lower()

        # Anthropic Claude
        if "anthropic" in provider_lower:
            return True
        for prefix in _CACHEABLE_MODEL_PREFIXES:
            if model_lower.startswith(prefix) or prefix in model_lower:
                return True

        return False

    def get_strategy(self, messages: List[Dict[str, Any]]) -> CacheStrategy:
        """根据对话长度选择缓存策略。"""
        if not messages:
            return CacheStrategy.NONE

        # 计算消息数（排除 system）
        non_system_count = sum(1 for m in messages if m.get("role") != "system")

        if non_system_count <= 2:
            return CacheStrategy.SYSTEM_ONLY
        elif non_system_count <= 10:
            return CacheStrategy.SYSTEM_AND_EARLY
        else:
            return CacheStrategy.MULTI_POINT

    def process_messages(
        self,
        messages: List[Dict[str, Any]],
        model: str = "",
        provider: str = "",
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """处理消息，添加缓存标记。

        Args:
            messages: 原始消息列表。
            model: 模型名称。
            provider: 提供商名称。

        Returns:
            (处理后的消息列表, 是否添加了缓存标记)
        """
        if not self.supports_caching(model, provider):
            return messages, False

        if not messages:
            return messages, False

        strategy = self.get_strategy(messages)
        if strategy == CacheStrategy.NONE:
            return messages, False

        # 深拷贝消息以避免修改原始数据
        processed = []
        for msg in messages:
            processed.append(self._copy_message(msg))

        # 根据策略添加缓存标记
        cache_added = False

        if strategy == CacheStrategy.SYSTEM_ONLY:
            cache_added = self._add_system_cache(processed)

        elif strategy == CacheStrategy.SYSTEM_AND_EARLY:
            cache_added = self._add_system_cache(processed)
            # 为早期消息添加缓存标记
            self._add_early_message_cache(processed)

        elif strategy == CacheStrategy.MULTI_POINT:
            cache_added = self._add_system_cache(processed)
            self._add_multi_point_cache(processed)

        return processed, cache_added

    def _copy_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """深拷贝消息。"""
        copied = dict(msg)
        content = copied.get("content")
        if isinstance(content, str):
            # 转换为 content block 格式以支持缓存标记
            copied["content"] = [{"type": "text", "text": content}]
        elif isinstance(content, list):
            copied["content"] = [dict(block) if isinstance(block, dict) else block for block in content]
        return copied

    def _add_system_cache(self, messages: List[Dict[str, Any]]) -> bool:
        """为 system prompt 添加缓存标记。"""
        for msg in messages:
            if msg.get("role") == "system":
                content = msg.get("content", [])
                if isinstance(content, list) and content:
                    # 为最后一个 text block 添加缓存标记
                    for block in reversed(content):
                        if isinstance(block, dict) and block.get("type") == "text":
                            block["cache_control"] = CACHE_CONTROL_MARKER
                            return True
                break
        return False

    def _add_early_message_cache(self, messages: List[Dict[str, Any]]) -> None:
        """为早期非系统消息添加缓存标记。"""
        non_system = [(i, m) for i, m in enumerate(messages) if m.get("role") != "system"]
        if len(non_system) < 3:
            return

        # 为前 1/3 的最后一条消息添加缓存标记
        early_count = max(1, len(non_system) // 3)
        target_idx = non_system[early_count - 1][0]
        msg = messages[target_idx]
        content = msg.get("content", [])
        if isinstance(content, list) and content:
            for block in reversed(content):
                if isinstance(block, dict) and block.get("type") == "text":
                    block["cache_control"] = CACHE_CONTROL_MARKER
                    break

    def _add_multi_point_cache(self, messages: List[Dict[str, Any]]) -> None:
        """添加多个缓存点。"""
        non_system = [(i, m) for i, m in enumerate(messages) if m.get("role") != "system"]
        if len(non_system) < 4:
            return

        # 每隔 1/4 添加一个缓存点
        step = max(1, len(non_system) // 4)
        for j in range(step - 1, len(non_system), step):
            if j >= len(non_system):
                break
            msg_idx = non_system[j][0]
            msg = messages[msg_idx]
            content = msg.get("content", [])
            if isinstance(content, list) and content:
                for block in reversed(content):
                    if isinstance(block, dict) and block.get("type") == "text":
                        block["cache_control"] = CACHE_CONTROL_MARKER
                        break

    def update_stats(
        self,
        cache_read_tokens: int = 0,
        cache_creation_tokens: int = 0,
        total_tokens: int = 0,
    ) -> None:
        """更新缓存统计。

        Args:
            cache_read_tokens: 从缓存读取的 token 数。
            cache_creation_tokens: 创建缓存的 token 数。
            total_tokens: 总 token 数。
        """
        if cache_read_tokens > 0:
            self.stats.record_hit(cache_read_tokens)
        if cache_creation_tokens > 0:
            self.stats.cached_tokens += cache_creation_tokens
        if total_tokens > 0:
            self.stats.total_tokens += total_tokens

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计。"""
        return {
            "cache_hits": self.stats.cache_hits,
            "cache_misses": self.stats.cache_misses,
            "hit_rate": f"{self.stats.hit_rate:.1%}",
            "cached_tokens": self.stats.cached_tokens,
            "total_tokens": self.stats.total_tokens,
            "estimated_savings": f"{self.stats.token_savings} tokens",
        }

    def reset_stats(self) -> None:
        """重置统计。"""
        self.stats.reset()


# 全局实例
_global_manager: Optional[PromptCacheManager] = None


def get_prompt_cache_manager() -> PromptCacheManager:
    """获取全局 PromptCacheManager 实例。"""
    global _global_manager
    if _global_manager is None:
        _global_manager = PromptCacheManager()
    return _global_manager
