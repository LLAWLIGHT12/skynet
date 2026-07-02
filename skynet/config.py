"""Skynet 配置。"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field
import yaml


class GraphConfig(BaseModel):
    """代码图谱存储与构建配置。"""

    dir_name: str = ".skynet"
    db_name: str = "graph.db"
    full_rebuild: bool = False
    analyzable_kinds: list[str] = Field(
        default_factory=lambda: ["Function", "Class"]
    )
    context_max_neighbors: int = 12
    context_max_depth: int = 1


class LLMConfig(BaseModel):
    """LLM 配置（密钥优先从环境变量读取）。"""

    api_base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    model_name: str = "deepseek-chat"
    temperature: float = 0.1
    max_tokens: int = 8000
    timeout: float = 60.0

    # 环境变量名（与现有部署保持一致）
    api_base_url_env: str = "FALLBACK_LLM_API_BASE_URL"
    api_key_env: str = "FALLBACK_LLM_API_KEY"
    model_name_env: str = "FALLBACK_LLM_MODEL_NAME"
    temperature_env: str = "FALLBACK_LLM_TEMPERATURE"
    max_tokens_env: str = "FALLBACK_LLM_MAX_TOKENS"
    timeout_env: str = "FALLBACK_LLM_TIMEOUT"

    def resolve(self) -> "LLMConfig":
        """合并环境变量，返回生效配置。"""
        def _env(name: str, fallback: str) -> str:
            return os.environ.get(name, fallback)

        def _env_float(name: str, fallback: float) -> float:
            raw = os.environ.get(name)
            if raw is None or raw == "":
                return fallback
            return float(raw)

        def _env_int(name: str, fallback: int) -> int:
            raw = os.environ.get(name)
            if raw is None or raw == "":
                return fallback
            return int(raw)

        api_key = _env(self.api_key_env, self.api_key)
        if not api_key:
            raise ValueError(
                f"未配置 LLM API Key，请设置环境变量 {self.api_key_env}"
            )

        return LLMConfig(
            api_base_url=_env(self.api_base_url_env, self.api_base_url),
            api_key=api_key,
            model_name=_env(self.model_name_env, self.model_name),
            temperature=_env_float(self.temperature_env, self.temperature),
            max_tokens=_env_int(self.max_tokens_env, self.max_tokens),
            timeout=_env_float(self.timeout_env, self.timeout),
            api_base_url_env=self.api_base_url_env,
            api_key_env=self.api_key_env,
            model_name_env=self.model_name_env,
            temperature_env=self.temperature_env,
            max_tokens_env=self.max_tokens_env,
            timeout_env=self.timeout_env,
        )


class AnalyzeConfig(BaseModel):
    """Chunk 分析配置。"""

    max_concurrency: int = 3
    max_source_lines: int = 400
    include_tests: bool = False
    output_dir: str = "./reports"
    confidence_search_threshold: float = 0.55


class KnowledgeConfig(BaseModel):
    """知识 RAG 配置。"""

    external_dir: str = ""  # 空则使用 data/knowledge/external
    max_external_items: int = 8
    persist_internal: bool = True
    enable_external: bool = True
    enable_internal: bool = True


class WebSearchConfig(BaseModel):
    """Web 搜索配置（疑惑消解）。"""

    enabled: bool = True
    provider: str = "duckduckgo"  # duckduckgo | tavily
    max_results: int = 5
    max_queries: int = 2
    api_key_env: str = "TAVILY_API_KEY"


class LSPConfig(BaseModel):
    """LSP 工具配置（multilspy）。"""

    enabled: bool = True
    code_language: str = ""  # 空则按仓库自动检测
    trace_lsp_communication: bool = False
    startup_timeout: float = 45.0


class TaintConfig(BaseModel):
    """污点流追踪配置。"""

    enabled: bool = True
    knowledge_dir: str = ""
    max_hops: int = 8
    max_paths_per_sink: int = 5
    max_flow_traces: int = 30
    min_criticality: float = 0.0
    cache_flow_results: bool = True
    enable_composite: bool = True
    max_composite_clusters: int = 10
    auto_trace_on_analyze: bool = True

    # Graph gap 检测
    gap_bare_call_weight: int = 30
    gap_dangling_target_weight: int = 40
    gap_path_break_weight: int = 35
    gap_dynamic_call_weight: int = 25
    gap_sink_unreachable_weight: int = 15
    gap_low_confidence_weight: int = 20
    gap_cross_community_weight: int = 10
    gap_missing_node_weight: int = 25
    gap_agent_threshold: int = 50
    gap_ignore_prefixes: list[str] = Field(
        default_factory=lambda: ["sqlite3.", "os.", "_io.", "builtins."]
    )
    gap_ignore_bare_names: list[str] = Field(
        default_factory=lambda: [
            "connect", "cursor", "execute", "fetchall", "fetchone", "commit", "close",
            "open", "read", "write", "print", "len", "str", "int", "dict", "list",
            "range", "enumerate", "isinstance", "getattr", "setattr", "super",
        ]
    )
    gap_builtin_downweight: float = 0.0

    # Bounded mini-Agent
    agent_fallback: bool = True
    agent_max_steps: int = 5
    max_agent_per_run: int = 20
    agent_after_inconclusive: bool = True


class ScanConfig(BaseModel):
    """scan 命令默认参数。"""

    limit_chunks: int = 0
    skip_build: bool = False
    no_trace: bool = False
    no_composite: bool = False


class ResilienceConfig(BaseModel):
    """LLM 韧性配置（熔断/重试/降级/Prompt Cache）。"""

    # 熔断器
    circuit_breaker_enabled: bool = True
    failure_threshold: int = 5
    recovery_timeout: float = 30.0

    # 重试
    retry_enabled: bool = True
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0

    # 降级
    fallback_enabled: bool = True

    # Prompt Cache（Claude）
    prompt_cache_enabled: bool = True

    # 对话记忆压缩
    memory_compressor_enabled: bool = False
    memory_max_tokens: int = 8000
    memory_threshold_ratio: float = 0.9


class ExternalScannerConfig(BaseModel):
    """外部安全扫描工具配置。"""

    enabled: bool = False
    tools: list[str] = Field(default_factory=lambda: ["semgrep", "bandit", "gitleaks"])
    timeout: int = 120
    semgrep_config: str = "auto"


class VerifyConfig(BaseModel):
    """沙箱 PoC 验证配置。"""

    enabled: bool = False
    auto_verify: bool = False
    min_severity: str = "high"
    max_verifications: int = 10
    sandbox_image: str = "python:3.11-slim"
    sandbox_memory_limit: str = "256m"
    sandbox_timeout: int = 30


class FrameworkKnowledgeConfig(BaseModel):
    """框架安全知识配置。"""

    enabled: bool = True


class VulnPatternConfig(BaseModel):
    """漏洞模式知识配置。"""

    enabled: bool = True


class SkynetConfig(BaseModel):
    """全局配置。"""

    project_name: str = "Skynet"
    target_dir: str = "./goalfile"
    output_dir: str = "./reports"
    scan: ScanConfig = Field(default_factory=ScanConfig)
    graph: GraphConfig = Field(default_factory=GraphConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    analyze: AnalyzeConfig = Field(default_factory=AnalyzeConfig)
    knowledge: KnowledgeConfig = Field(default_factory=KnowledgeConfig)
    web_search: WebSearchConfig = Field(default_factory=WebSearchConfig)
    taint: TaintConfig = Field(default_factory=TaintConfig)
    lsp: LSPConfig = Field(default_factory=LSPConfig)
    resilience: ResilienceConfig = Field(default_factory=ResilienceConfig)
    external_scanner: ExternalScannerConfig = Field(default_factory=ExternalScannerConfig)
    verify: VerifyConfig = Field(default_factory=VerifyConfig)
    framework_knowledge: FrameworkKnowledgeConfig = Field(default_factory=FrameworkKnowledgeConfig)
    vuln_pattern: VulnPatternConfig = Field(default_factory=VulnPatternConfig)


_config: Optional[SkynetConfig] = None


def get_config() -> SkynetConfig:
    if _config is None:
        return SkynetConfig()
    return _config


def load_config(path: str | Path) -> SkynetConfig:
    global _config
    config_path = Path(path)
    if not config_path.exists():
        _config = SkynetConfig()
        return _config

    with open(config_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    skynet_section = raw.get("skynet", raw)
    _config = SkynetConfig.model_validate(skynet_section)
    return _config


def load_dotenv_if_present() -> None:
    """若存在 .env 则加载（不覆盖已有环境变量）。"""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    for candidate in (
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[1] / ".env",
    ):
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            break


def graph_db_path(repo_root: str | Path, cfg: Optional[SkynetConfig] = None) -> Path:
    cfg = cfg or get_config()
    root = Path(repo_root).resolve()
    return root / cfg.graph.dir_name / cfg.graph.db_name
