"""Auth 兼容层 — Audit 已迁移至 Skynet LLMClient（FALLBACK_LLM_*）。

历史 Claude Code SDK 认证逻辑已移除；请使用 skynet.audit.llm_auth.check_llm_auth。
"""

from __future__ import annotations

from skynet.audit.llm_auth import LLMAuthError, LLMAuthStatus, check_llm_auth

# 向后兼容旧名称
AuthError = LLMAuthError


def configure_auth(*_args, **_kwargs) -> LLMAuthStatus:
    """兼容旧接口：等价于 check_llm_auth()。"""
    return check_llm_auth()
