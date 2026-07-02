"""三区内存压缩 —— 对多轮对话历史进行智能压缩。

- Frozen Zone: messages[0:2]（system + 首条 user）永不压缩
- Compress Zone: 中间历史，由 LLM 总结为摘要
- Active Zone: 最近 K 轮完整保留
- 阈值：60% 触发异步压缩，80% 触发同步压缩
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# ── 常量 ────────────────────────────────────────────────────────

SOFT_THRESHOLD = 0.60    # 异步后台压缩触发点
HARD_THRESHOLD = 0.80    # 同步立即压缩触发点

# ── Token 估算 ──────────────────────────────────────────────────

def count_tokens(text: str) -> int:
    """粗略估算 token 数。

    优先使用 tiktoken（如已安装），否则使用 len(text)/4 估算。
    """
    if not text:
        return 0
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except (ImportError, Exception):
        # 粗略估算：1 token ≈ 4 字符（英文）或 2 字符（中文）
        # 取折中值 3
        return max(1, len(text) // 3)


def count_messages_tokens(messages: list[dict[str, str]]) -> int:
    """计算消息列表的总 token 数。"""
    return sum(count_tokens(m.get("content", "")) for m in messages)


# ── 压缩 Prompt ────────────────────────────────────────────────

COMPRESSION_SYSTEM = """\
You are a conversation compressor. Your task is to summarize the middle \
portion of a conversation while preserving all important facts, decisions, \
and context.

Rules:
- Keep the summary concise but complete.
- Preserve all technical details, file paths, code references, and findings.
- Remove redundant back-and-forth, but keep the conclusions.
- Output ONLY the summary text, no preamble.
"""

COMPRESSION_USER = """\
Summarize the following conversation excerpt. Focus on:
1. What was analyzed (files, functions, patterns)
2. What findings were made (vulnerabilities, issues)
3. What decisions were reached
4. Any important code references or line numbers

--- Conversation Excerpt ---
{context}
--- End Excerpt ---

Provide a concise summary:
"""


# ── 三区划分 ────────────────────────────────────────────────────

def partition_messages(
    messages: list[dict[str, str]],
    max_tokens: int,
) -> tuple[int, int]:
    """将消息列表划分为 (frozen_end, compress_end)。

    Returns
    -------
    (frozen_end, compress_end)
        - frozen zone: messages[0:frozen_end]
        - compress zone: messages[frozen_end:compress_end]
        - active zone: messages[compress_end:]
    """
    if len(messages) <= 2:
        return 0, len(messages)

    frozen_end = 2  # system + first user message

    # 计算 active zone 需要保留多少轮
    budget = int(max_tokens * HARD_THRESHOLD)

    # 从后往前计算 active zone 大小
    active_tokens = 0
    active_start = len(messages)
    for i in range(len(messages) - 1, frozen_end - 1, -1):
        msg_tokens = count_tokens(messages[i].get("content", ""))
        if active_tokens + msg_tokens > budget * 0.4:  # active zone 用 40% 预算
            break
        active_tokens += msg_tokens
        active_start = i

    compress_end = active_start
    if compress_end <= frozen_end:
        # 没有可压缩的内容
        return frozen_end, frozen_end

    return frozen_end, compress_end


# ── 核心压缩函数 ────────────────────────────────────────────────

async def compress_messages(
    messages: list[dict[str, str]],
    max_tokens: int,
    llm_client: Any = None,
) -> list[dict[str, str]]:
    """三区压缩消息列表。

    Parameters
    ----------
    messages : list[dict]
        消息列表，每条包含 "role" 和 "content"。
    max_tokens : int
        模型的最大 token 限制。
    llm_client : optional
        LLM 客户端实例。为 None 时自动创建。

    Returns
    -------
    list[dict]
        压缩后的消息列表。
    """
    if len(messages) <= 2:
        return messages

    current_tokens = count_messages_tokens(messages)
    hard_limit = int(max_tokens * HARD_THRESHOLD)

    if current_tokens <= hard_limit:
        # 未超限，不需要压缩
        return messages

    frozen_end, compress_end = partition_messages(messages, max_tokens)
    if compress_end <= frozen_end:
        # 没有可压缩的内容
        return messages

    # 提取 compress zone 内容
    compress_zone = messages[frozen_end:compress_end]
    context_xml = _build_context_xml(compress_zone)

    # 调用 LLM 压缩
    summary = await _call_compression_llm(context_xml, llm_client)
    if not summary:
        log.warning("compression: LLM returned empty summary, keeping original")
        return messages

    # 重建消息列表: frozen + summary注入 + active
    rebuilt = list(messages[:frozen_end])

    # 将摘要注入到 frozen zone 的最后一条消息
    last_frozen = dict(rebuilt[-1])
    last_frozen["content"] = (
        last_frozen.get("content", "")
        + "\n\n<previous_analysis_summary>\n"
        + summary
        + "\n</previous_analysis_summary>"
    )
    rebuilt[-1] = last_frozen

    # 追加 active zone
    rebuilt.extend(messages[compress_end:])

    new_tokens = count_messages_tokens(rebuilt)
    log.info(
        "compression: %d -> %d tokens (%.1f%% reduction)",
        current_tokens, new_tokens,
        (1 - new_tokens / max(current_tokens, 1)) * 100,
    )
    return rebuilt


def should_compress(
    messages: list[dict[str, str]],
    max_tokens: int,
) -> str:
    """判断是否需要压缩。

    Returns
    -------
    str
        "none" — 不需要压缩
        "async" — 建议异步压缩（超过 60%）
        "sync" — 需要立即同步压缩（超过 80%）
    """
    if len(messages) <= 2:
        return "none"

    current_tokens = count_messages_tokens(messages)
    soft_limit = int(max_tokens * SOFT_THRESHOLD)
    hard_limit = int(max_tokens * HARD_THRESHOLD)

    if current_tokens > hard_limit:
        return "sync"
    elif current_tokens > soft_limit:
        return "async"
    return "none"


# ── 内部辅助 ────────────────────────────────────────────────────

def _build_context_xml(messages: list[dict[str, str]]) -> str:
    """将消息序列化为 XML 格式，供压缩 prompt 使用。"""
    lines = []
    for i, m in enumerate(messages):
        role = m.get("role", "unknown")
        content = m.get("content", "")
        lines.append(f'<message id="{i}" role="{role}">')
        lines.append(f"  <content>{content}</content>")
        lines.append("</message>")
    return "\n".join(lines)


async def _call_compression_llm(
    context_xml: str,
    llm_client: Any = None,
) -> str:
    """调用 LLM 生成压缩摘要。"""
    try:
        if llm_client is None:
            from skynet.llm.client import LLMClient
            llm_client = LLMClient()

        user_prompt = COMPRESSION_USER.format(context=context_xml)
        response, _usage = await llm_client.chat_json(
            system_prompt=COMPRESSION_SYSTEM,
            user_prompt=user_prompt,
            temperature=0.0,
        )
        return response.strip()
    except Exception as e:
        log.warning("compression: LLM call failed: %s", e)
        return ""
