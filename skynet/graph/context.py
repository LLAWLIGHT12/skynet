"""为 chunk 分析提供确定性结构上下文（非 RAG）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from code_review_graph.graph import GraphStore

from skynet.config import SkynetConfig, get_config
from skynet.graph.chunks import CodeChunk


_EDGE_LABELS = {
    "CALLS": "calls",
    "IMPORTS_FROM": "imports",
    "INHERITS": "inherits",
    "IMPLEMENTS": "implements",
    "CONTAINS": "contains",
    "TESTED_BY": "tested_by",
    "DEPENDS_ON": "depends_on",
    "REFERENCES": "references",
}


@dataclass
class NeighborRef:
    qualified_name: str
    name: str
    kind: str
    file_path: str
    relation: str
    direction: str  # "in" | "out"
    line: int = 0


@dataclass
class StructuralContext:
    """chunk 的结构化邻域信息，供 LLM 分析使用。"""

    chunk: CodeChunk
    callers: list[NeighborRef] = field(default_factory=list)
    callees: list[NeighborRef] = field(default_factory=list)
    imports: list[NeighborRef] = field(default_factory=list)
    community_id: Optional[int] = None
    flow_criticality: list[float] = field(default_factory=list)

    def to_prompt_block(self) -> str:
        """格式化为 prompt 中的结构上下文段落。"""
        lines = [
            f"## Structural context for `{self.chunk.qualified_name}`",
            f"- Kind: {self.chunk.kind}",
            f"- File: {self.chunk.file_path}:{self.chunk.line_start}-{self.chunk.line_end}",
        ]
        if self.community_id is not None:
            lines.append(f"- Community: {self.community_id}")
        if self.flow_criticality:
            max_crit = max(self.flow_criticality)
            lines.append(f"- Max flow criticality: {max_crit:.2f}")

        if self.callers:
            lines.append("\n### Callers")
            for n in self.callers:
                lines.append(f"- [{n.direction}] {n.name} ({n.kind}) @ {n.file_path}")

        if self.callees:
            lines.append("\n### Callees")
            for n in self.callees:
                lines.append(f"- {n.name} ({n.kind}) @ {n.file_path}:{n.line}")

        if self.imports:
            lines.append("\n### Imports / dependencies")
            for n in self.imports:
                lines.append(f"- {n.qualified_name}")

        return "\n".join(lines)


def _neighbor_from_edge(
    store: GraphStore,
    qualified_name: str,
    edge_kind: str,
    direction: str,
    line: int,
) -> Optional[NeighborRef]:
    node = store.get_node(qualified_name)
    if node is None:
        return NeighborRef(
            qualified_name=qualified_name,
            name=qualified_name.rsplit("::", 1)[-1],
            kind="Unknown",
            file_path="",
            relation=_EDGE_LABELS.get(edge_kind, edge_kind.lower()),
            direction=direction,
            line=line,
        )
    return NeighborRef(
        qualified_name=node.qualified_name,
        name=node.name,
        kind=node.kind,
        file_path=node.file_path,
        relation=_EDGE_LABELS.get(edge_kind, edge_kind.lower()),
        direction=direction,
        line=line,
    )


def get_structural_context(
    store: GraphStore,
    chunk: CodeChunk,
    config: Optional[SkynetConfig] = None,
) -> StructuralContext:
    """收集 chunk 的调用者、被调用者与 import 关系。"""
    cfg = config or get_config()
    max_n = cfg.graph.context_max_neighbors
    qn = chunk.qualified_name

    callers: list[NeighborRef] = []
    for edge in store.get_edges_by_target(qn):
        if edge.kind not in ("CALLS", "IMPORTS_FROM", "REFERENCES"):
            continue
        ref = _neighbor_from_edge(store, edge.source_qualified, edge.kind, "in", edge.line)
        if ref:
            callers.append(ref)
        if len(callers) >= max_n:
            break

    callees: list[NeighborRef] = []
    imports: list[NeighborRef] = []
    for edge in store.get_edges_by_source(qn):
        if edge.kind == "CALLS":
            ref = _neighbor_from_edge(store, edge.target_qualified, edge.kind, "out", edge.line)
            if ref:
                callees.append(ref)
        elif edge.kind in ("IMPORTS_FROM", "DEPENDS_ON", "REFERENCES"):
            ref = _neighbor_from_edge(store, edge.target_qualified, edge.kind, "out", edge.line)
            if ref:
                imports.append(ref)
        if len(callees) + len(imports) >= max_n:
            break

    community_id = store.get_node_community_id(chunk.node_id)
    flow_crit = store.get_flow_criticalities_for_node(chunk.node_id)

    return StructuralContext(
        chunk=chunk,
        callers=callers[:max_n],
        callees=callees[:max_n],
        imports=imports[:max_n],
        community_id=community_id,
        flow_criticality=flow_crit,
    )
