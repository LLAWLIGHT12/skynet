"""LLM 配置检查 — Audit 管线使用 Skynet LLMClient，不依赖 Claude Code。"""

from __future__ import annotations

from dataclasses import dataclass

from skynet.llm.client import load_llm_config


@dataclass
class LLMAuthStatus:
    ok: bool
    model_name: str
    api_base_url: str
    api_key_set: bool
    message: str = ""


class LLMAuthError(RuntimeError):
    """LLM 未正确配置。"""


def check_llm_auth() -> LLMAuthStatus:
    """验证 FALLBACK_LLM_* 环境变量是否可用于 Audit/Analyze。"""
    try:
        cfg = load_llm_config()
    except ValueError as e:
        raise LLMAuthError(str(e)) from e
    masked = f"{cfg.api_key[:4]}...{cfg.api_key[-4:]}" if len(cfg.api_key) >= 8 else "(set)"
    return LLMAuthStatus(
        ok=True,
        model_name=cfg.model_name,
        api_base_url=cfg.api_base_url,
        api_key_set=bool(cfg.api_key),
        message=f"model={cfg.model_name}, base={cfg.api_base_url}, key={masked}",
    )
