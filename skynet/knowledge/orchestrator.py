"""调度外部 + 内部知识检索。"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from skynet.config import SkynetConfig, get_config
from skynet.graph.chunks import CodeChunk
from skynet.graph.context import StructuralContext
from skynet.knowledge.context import KnowledgeContext
from skynet.knowledge.external.retriever import ExternalKnowledgeRetriever
from skynet.knowledge.internal.retriever import InternalKnowledgeRetriever


class KnowledgeOrchestrator:
    """为 chunk 分析聚合三层知识（不含 web，web 在疑惑时二次调用）。"""

    def __init__(
        self,
        repo_root: str | Path,
        config: Optional[SkynetConfig] = None,
    ) -> None:
        self.config = config or get_config()
        self.repo_root = Path(repo_root).resolve()
        kcfg = self.config.knowledge
        self.external = ExternalKnowledgeRetriever(knowledge_dir=kcfg.external_dir or None)
        self.internal = InternalKnowledgeRetriever(
            self.repo_root,
            graph_dir_name=self.config.graph.dir_name,
        )

    def gather(
        self,
        chunk: CodeChunk,
        structural_ctx: StructuralContext,
    ) -> KnowledgeContext:
        kcfg = self.config.knowledge
        ctx_text = structural_ctx.to_prompt_block()
        signals: list = []
        external: list = []
        internal: list = []

        if kcfg.enable_external:
            signals = self.external.detect_code_signals(chunk.source)
            external = self.external.retrieve_for_chunk(
                chunk.source,
                ctx_text,
                max_items=kcfg.max_external_items,
            )
        if kcfg.enable_internal:
            internal = self.internal.retrieve(chunk, structural_ctx)

        return KnowledgeContext(
            external=external,
            internal=internal,
            code_signals=signals,
        )

    def persist(
        self,
        chunk: CodeChunk,
        structural_ctx: StructuralContext,
        findings: list[dict],
        summary: str,
    ) -> None:
        if not self.config.knowledge.persist_internal:
            return
        self.internal.persist_analysis(
            chunk,
            structural_ctx,
            findings,
            summary,
        )
