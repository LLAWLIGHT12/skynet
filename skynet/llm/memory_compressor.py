"""对话记忆压缩器 — 长 Agent 会话自动压缩早期消息。

当对话 token 超过阈值时，保留系统消息 + 最近 N 条，
对早期消息提取关键信息压缩为摘要。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from skynet.llm.tokenizer import TokenEstimator

logger = logging.getLogger(__name__)


# 安全审计关键词（用于提取关键信息）
_SECURITY_KEYWORDS = [
    # 注入类
    "sql injection", "sql注入", "command injection", "命令注入",
    "code injection", "代码注入", "xss", "ssrf", "xxe",
    "path traversal", "路径遍历", "directory traversal",
    # 认证授权
    "authentication", "认证", "authorization", "授权",
    "idor", "privilege escalation", "权限提升",
    "session hijack", "会话劫持",
    # 数据泄露
    "sensitive data", "敏感数据", "secret", "密钥",
    "credential", "凭证", "password", "密码",
    "token leak", "token 泄露",
    # 其他
    "deserialization", "反序列化", "csrf", "open redirect",
    "race condition", "竞态条件", "business logic", "业务逻辑",
    # 工具名
    "semgrep", "bandit", "gitleaks", "pattern_match",
    # 决策关键词
    "confirmed", "false positive", "误报", "true positive",
    "high severity", "高危", "critical", "严重",
]

# 用于提取文件路径的正则
_FILE_PATH_PATTERN = re.compile(r"[\w/\\.-]+\.(?:py|js|ts|go|java|php|rb|c|cpp|h|hpp)")


@dataclass
class CompressorConfig:
    """压缩器配置。"""
    # 当 token 超过 max_tokens 的此比例时触发压缩
    threshold_ratio: float = 0.9
    # 默认最大 token（对应模型的上下文窗口）
    max_tokens: int = 8000
    # 保留最近 N 条非系统消息
    keep_recent: int = 15
    # 压缩摘要的最大 token
    summary_max_tokens: int = 500


@dataclass
class ExtractedInfo:
    """从对话中提取的关键信息。"""
    findings: List[str] = field(default_factory=list)       # 发现的漏洞
    tools_used: List[str] = field(default_factory=list)     # 使用的工具
    decisions: List[str] = field(default_factory=list)      # 做出的决策
    errors: List[str] = field(default_factory=list)         # 遇到的错误
    files_analyzed: List[str] = field(default_factory=list) # 分析的文件


class MemoryCompressor:
    """对话历史压缩器。

    用法::

        compressor = MemoryCompressor()
        compressed = compressor.compress_history(messages, model="gpt-4")
    """

    def __init__(self, config: Optional[CompressorConfig] = None):
        self.config = config or CompressorConfig()

    def compress_history(
        self,
        messages: List[Dict[str, Any]],
        model: str = "gpt-4",
    ) -> List[Dict[str, Any]]:
        """压缩对话历史。

        Args:
            messages: OpenAI 格式消息列表。
            model: 模型名（用于 token 估算）。

        Returns:
            压缩后的消息列表。如果未超阈值，返回原始列表。
        """
        if len(messages) <= 3:
            return messages

        total_tokens = TokenEstimator.estimate_messages_tokens(messages, model)
        threshold = int(self.config.max_tokens * self.config.threshold_ratio)

        if total_tokens <= threshold:
            return messages

        logger.info(
            "Compressing history: %d tokens > %d threshold, %d messages",
            total_tokens, threshold, len(messages),
        )

        # 分离系统消息和普通消息
        system_messages = [m for m in messages if m.get("role") == "system"]
        regular_messages = [m for m in messages if m.get("role") != "system"]

        if len(regular_messages) <= self.config.keep_recent:
            return messages

        # 保留最近 N 条
        old_messages = regular_messages[:-self.config.keep_recent]
        recent_messages = regular_messages[-self.config.keep_recent:]

        # 从旧消息中提取关键信息
        info = self._extract_info(old_messages)

        # 生成压缩摘要
        summary = self._build_summary(info, len(old_messages))

        # 构建压缩后的消息列表
        compressed = list(system_messages)

        # 插入压缩摘要作为一条 assistant 消息
        compressed.append({
            "role": "assistant",
            "content": f"[Conversation compressed] Earlier {len(old_messages)} messages summarized:\n{summary}",
        })

        compressed.extend(recent_messages)

        # 验证压缩后 token 数
        new_tokens = TokenEstimator.estimate_messages_tokens(compressed, model)
        logger.info(
            "Compression complete: %d tokens -> %d tokens (%.1f%% reduction)",
            total_tokens, new_tokens,
            (1 - new_tokens / total_tokens) * 100 if total_tokens > 0 else 0,
        )

        return compressed

    def _extract_info(self, messages: List[Dict[str, Any]]) -> ExtractedInfo:
        """从旧消息中提取关键信息。"""
        info = ExtractedInfo()
        all_text = ""

        for msg in messages:
            content = msg.get("content", "")
            if not isinstance(content, str):
                continue
            all_text += content + "\n"

            # 提取文件路径
            files = _FILE_PATH_PATTERN.findall(content)
            info.files_analyzed.extend(files[:5])  # 每条消息最多 5 个文件

        # 检测安全关键词
        text_lower = all_text.lower()
        for keyword in _SECURITY_KEYWORDS:
            if keyword.lower() in text_lower:
                # 提取包含关键词的短句
                pattern = re.compile(rf"[^.]*{re.escape(keyword)}[^.]*\.", re.IGNORECASE)
                matches = pattern.findall(all_text)
                info.findings.extend(matches[:3])  # 每种关键词最多 3 条

        # 去重
        info.findings = list(dict.fromkeys(info.findings))[:10]
        info.files_analyzed = list(dict.fromkeys(info.files_analyzed))[:20]

        return info

    def _build_summary(self, info: ExtractedInfo, msg_count: int) -> str:
        """构建压缩摘要文本。"""
        parts = []

        parts.append(f"Processed {msg_count} messages.")

        if info.findings:
            parts.append("\nKey findings:")
            for finding in info.findings[:5]:
                parts.append(f"  - {finding.strip()}")

        if info.files_analyzed:
            parts.append(f"\nFiles analyzed: {', '.join(info.files_analyzed[:10])}")

        return "\n".join(parts)

    def should_compress(
        self,
        messages: List[Dict[str, Any]],
        model: str = "gpt-4",
    ) -> bool:
        """判断是否需要压缩。"""
        if len(messages) <= 3:
            return False

        total_tokens = TokenEstimator.estimate_messages_tokens(messages, model)
        threshold = int(self.config.max_tokens * self.config.threshold_ratio)
        return total_tokens > threshold
