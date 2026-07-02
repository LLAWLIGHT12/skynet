"""Token 估算器 — prompt 构建时提前计算 token 数。

优先使用 tiktoken 精确计数，不可用时 fallback 到字符比例估算。
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# tiktoken 可选导入
try:
    import tiktoken

    _TIKTOKEN_AVAILABLE = True
except ImportError:
    tiktoken = None  # type: ignore[assignment]
    _TIKTOKEN_AVAILABLE = False


# 模型名 -> tiktoken 编码器名映射
_MODEL_ENCODING_MAP = {
    # 长名称优先匹配，避免 gpt-4 匹配到 gpt-4o
    "gpt-4o-mini": "o200k_base",
    "gpt-4o": "o200k_base",
    "gpt-4-turbo": "cl100k_base",
    "gpt-4": "cl100k_base",
    "gpt-3.5-turbo": "cl100k_base",
    "deepseek-coder": "cl100k_base",
    "deepseek-chat": "cl100k_base",
    "deepseek": "cl100k_base",
}

# Fallback: 1 token 约等于多少字符（英文约 4，中文约 1.5）
_DEFAULT_CHARS_PER_TOKEN = 4.0


class TokenEstimator:
    """Token 估算器。

    用法::

        count = TokenEstimator.count_tokens("hello world", model="gpt-4")
    """

    @staticmethod
    def count_tokens(text: str, model: str = "gpt-4") -> int:
        """估算文本的 token 数量。

        Args:
            text: 要估算的文本。
            model: 模型名称，用于选择编码器。

        Returns:
            估算的 token 数量（>= 0）。
        """
        if not text:
            return 0

        if _TIKTOKEN_AVAILABLE:
            return TokenEstimator._count_with_tiktoken(text, model)

        return TokenEstimator._count_with_ratio(text)

    @staticmethod
    def _count_with_tiktoken(text: str, model: str) -> int:
        """使用 tiktoken 精确计数。"""
        encoding_name = TokenEstimator._get_encoding_name(model)
        try:
            enc = tiktoken.get_encoding(encoding_name)
            return len(enc.encode(text))
        except Exception:
            # 编码器获取失败，fallback 到比例估算
            return TokenEstimator._count_with_ratio(text)

    @staticmethod
    def _count_with_ratio(text: str) -> int:
        """使用字符比例估算（fallback）。

        粗略规则：
        - 如果中文字符占比 > 30%，使用 1.5 chars/token
        - 否则使用 4.0 chars/token
        """
        if not text:
            return 0

        chinese_chars = sum(1 for c in text if "\u4e00" <= c <= "\u9fff")
        chinese_ratio = chinese_chars / len(text) if len(text) > 0 else 0

        if chinese_ratio > 0.3:
            chars_per_token = 1.5
        else:
            chars_per_token = _DEFAULT_CHARS_PER_TOKEN

        return max(1, int(len(text) / chars_per_token))

    @staticmethod
    def _get_encoding_name(model: str) -> str:
        """根据模型名获取 tiktoken 编码器名。"""
        model_lower = model.lower()
        for key, encoding in _MODEL_ENCODING_MAP.items():
            if key in model_lower:
                return encoding
        # 默认使用 cl100k_base（最通用的编码器）
        return "cl100k_base"

    @staticmethod
    def is_tiktoken_available() -> bool:
        """检查 tiktoken 是否可用。"""
        return _TIKTOKEN_AVAILABLE

    @staticmethod
    def estimate_messages_tokens(messages: list[dict], model: str = "gpt-4") -> int:
        """估算消息列表的总 token 数。

        Args:
            messages: OpenAI 格式的消息列表 [{"role": ..., "content": ...}, ...]
            model: 模型名称。

        Returns:
            总 token 数。
        """
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total += TokenEstimator.count_tokens(content, model)
                # 每条消息额外 4 token 开销（role + 分隔符）
                total += 4
            elif isinstance(content, list):
                # content block 格式
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        total += TokenEstimator.count_tokens(
                            block.get("text", ""), model
                        )
                total += 4
        return total
