"""按 flow criticality 对 chunk 排序。"""

from __future__ import annotations

from code_review_graph.graph import GraphStore

from skynet.graph.chunks import CodeChunk


def chunk_criticality(store: GraphStore, chunk: CodeChunk) -> float:
    crit = store.get_flow_criticalities_for_node(chunk.node_id)
    return max(crit) if crit else 0.0


def prioritize_chunks(store: GraphStore, chunks: list[CodeChunk]) -> list[CodeChunk]:
    """criticality 降序，同分按 qualified_name 稳定排序。"""
    scored = [(chunk_criticality(store, c), c) for c in chunks]
    scored.sort(key=lambda x: (-x[0], x[1].qualified_name))
    return [c for _, c in scored]
