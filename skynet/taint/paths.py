"""图上双向剪枝枚举 source→sink 候选路径。"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Optional

from code_review_graph.graph import FlowAdjacency, GraphStore

from skynet.taint.catalog import TaintCatalog
from skynet.graph.overrides import GraphOverridesStore
from skynet.taint.gap_detector import GraphGapDetector
from skynet.taint.models import FlowCandidate


def _build_calls_in(adj: FlowAdjacency) -> dict[str, list[str]]:
    calls_in: dict[str, list[str]] = {}
    for src, targets in adj.calls_out.items():
        for tgt in targets:
            calls_in.setdefault(tgt, []).append(src)
    return calls_in


def _communities_for_path(store: GraphStore, path_qns: list[str]) -> list[int]:
    ids: list[int] = []
    seen: set[int] = set()
    for qn in path_qns:
        node = store.get_node(qn)
        if node is None:
            continue
        cid = store.get_node_community_id(node.id)
        if cid is not None and cid not in seen:
            seen.add(cid)
            ids.append(cid)
    return ids


def _path_criticality(store: GraphStore, path_qns: list[str]) -> float:
    scores: list[float] = []
    for qn in path_qns:
        node = store.get_node(qn)
        if node is None:
            continue
        crit = store.get_flow_criticalities_for_node(node.id)
        if crit:
            scores.append(max(crit))
    return max(scores) if scores else 0.0


def backward_paths_to_sources(
    sink_qn: str,
    source_qns: set[str],
    calls_in: dict[str, list[str]],
    max_hops: int,
    max_paths: int,
) -> list[list[str]]:
    """从 sink 反向 BFS，收集到达 source 的路径（path[0]=source, path[-1]=sink）。"""
    results: list[list[str]] = []
    queue: deque[tuple[str, list[str]]] = deque([(sink_qn, [sink_qn])])

    while queue and len(results) < max_paths:
        current, path_rev = queue.popleft()
        depth = len(path_rev) - 1

        if current in source_qns:
            results.append(list(reversed(path_rev)))
            continue

        if depth >= max_hops:
            continue

        for caller in calls_in.get(current, []):
            if caller in path_rev:
                continue
            queue.append((caller, path_rev + [caller]))

    return results


def enumerate_flow_candidates(
    store: GraphStore,
    catalog: TaintCatalog,
    repo_root: str | Path,
    max_hops: int = 8,
    max_paths_per_sink: int = 5,
    max_candidates: int = 50,
    min_criticality: float = 0.0,
    gap_detector: Optional[GraphGapDetector] = None,
) -> list[FlowCandidate]:
    """枚举 source→sink 候选流，并计算 GraphGapScore。"""
    adj = store.load_flow_adjacency()
    calls_in = _build_calls_in(adj)

    overrides = GraphOverridesStore(repo_root)
    if overrides.calls:
        calls_in = overrides.merge_into_calls_in(calls_in)

    source_qns = {a.qualified_name for a in catalog.sources}
    sink_nodes = catalog.sinks

    if not sink_nodes:
        return []

    if not source_qns:
        for qn in adj.nodes_by_qn:
            if qn not in calls_in or not calls_in.get(qn):
                source_qns.add(qn)

    detector = gap_detector or GraphGapDetector(repo_root)
    detector.build_index(store)

    candidates: list[FlowCandidate] = []
    seen_ids: set[str] = set()

    for sink_ann in sink_nodes:
        sink_qn = sink_ann.qualified_name
        sink_type = sink_ann.sink_types[0] if sink_ann.sink_types else "unknown_sink"

        paths = backward_paths_to_sources(
            sink_qn,
            source_qns,
            calls_in,
            max_hops=max_hops,
            max_paths=max_paths_per_sink,
        )

        sink_had_no_path = not paths

        if not paths:
            paths = [[sink_qn]]

        for path_qns in paths:
            src = path_qns[0]
            no_path = sink_had_no_path and len(path_qns) == 1
            cand = FlowCandidate(
                source_qn=src,
                sink_qn=sink_qn,
                path_qns=path_qns,
                sink_type=sink_type,
                hop_count=len(path_qns) - 1,
                communities=_communities_for_path(store, path_qns),
                criticality=_path_criticality(store, path_qns),
                sink_had_no_path=no_path,
            )
            detector.apply_to_candidate(store, cand, sink_had_no_path=no_path)

            if cand.criticality < min_criticality and min_criticality > 0:
                continue
            if cand.flow_id in seen_ids:
                continue
            seen_ids.add(cand.flow_id)
            candidates.append(cand)
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    candidates.sort(key=lambda c: (c.gap_score, c.criticality), reverse=True)
    return candidates
