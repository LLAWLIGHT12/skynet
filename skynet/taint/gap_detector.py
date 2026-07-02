"""图断边 / 动态调用检测与 GapScore 打分。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from code_review_graph.graph import FlowAdjacency, GraphStore

from skynet.config import TaintConfig, get_config
from skynet.graph.chunks import read_node_source
from skynet.graph.overrides import GraphOverridesStore
from skynet.taint.models import FlowCandidate

# 源码中出现则静态图可能不完整
_DYNAMIC_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("getattr", re.compile(r"\bgetattr\s*\(", re.MULTILINE)),
    ("setattr", re.compile(r"\bsetattr\s*\(", re.MULTILINE)),
    ("eval_exec", re.compile(r"\b(eval|exec)\s*\(", re.MULTILINE)),
    ("importlib", re.compile(r"(importlib|__import__)\s*[.(]", re.MULTILINE)),
    ("globals_lookup", re.compile(r"\bglobals\s*\(\s*\)\s*\[", re.MULTILINE)),
    ("dict_dispatch", re.compile(r"\w+\s*\[\s*\w+\s*\]\s*\(", re.MULTILINE)),
    ("apply_invoke", re.compile(r"\.(apply|invoke)\s*\(", re.MULTILINE)),
    ("depends_inject", re.compile(r"(Depends\s*\(|inject\s*\(|@inject)", re.MULTILINE)),
    ("registry", re.compile(r"(register|add_handler|connect)\s*\(", re.MULTILINE)),
]


@dataclass
class GapScoreResult:
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    @property
    def needs_agent(self) -> bool:
        return False  # set by detector after threshold compare


@dataclass
class GraphGapIndex:
    """构图后一次性扫描的全局断边索引。"""

    node_qns: set[str] = field(default_factory=set)
    bare_calls: list[tuple[str, str, int]] = field(default_factory=list)
    dangling_targets: set[str] = field(default_factory=set)
    low_confidence_calls: list[tuple[str, str, float]] = field(default_factory=list)


class GraphGapDetector:
    """对候选流计算 GraphGapScore，判断是否需要 mini-Agent 补边。"""

    def __init__(
        self,
        repo_root: str | Path,
        config: Optional[TaintConfig] = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        cfg = config or get_config().taint
        self.threshold = cfg.gap_agent_threshold
        self.ignore_prefixes = tuple(cfg.gap_ignore_prefixes)
        self.ignore_bare_names = frozenset(cfg.gap_ignore_bare_names)
        self.builtin_downweight = cfg.gap_builtin_downweight
        self.weights = {
            "bare_call_target": cfg.gap_bare_call_weight,
            "dangling_edge_target": cfg.gap_dangling_target_weight,
            "path_hop_no_calls_edge": cfg.gap_path_break_weight,
            "dynamic_call_site_on_path": cfg.gap_dynamic_call_weight,
            "sink_unreachable": cfg.gap_sink_unreachable_weight,
            "low_confidence_edge": cfg.gap_low_confidence_weight,
            "cross_community": cfg.gap_cross_community_weight,
            "missing_node": cfg.gap_missing_node_weight,
        }
        self._index: Optional[GraphGapIndex] = None
        self._dynamic_cache: dict[str, list[str]] = {}
        self._adj: Optional[FlowAdjacency] = None
        self._overrides = GraphOverridesStore(self.repo_root)

    def build_index(self, store: GraphStore) -> GraphGapIndex:
        if self._index is not None:
            return self._index

        node_qns = {n.qualified_name for n in store.get_all_nodes()}
        bare_calls: list[tuple[str, str, int]] = []
        dangling: set[str] = set()
        low_conf: list[tuple[str, str, float]] = []

        for edge in store.get_all_edges():
            if edge.kind != "CALLS":
                continue
            tgt = edge.target_qualified
            if "::" not in tgt:
                bare_calls.append((edge.source_qualified, tgt, edge.line))
            if tgt not in node_qns and not tgt.startswith("__"):
                dangling.add(tgt)
            if edge.confidence < 1.0 or edge.confidence_tier.upper() != "EXTRACTED":
                low_conf.append((edge.source_qualified, tgt, edge.confidence))

        self._index = GraphGapIndex(
            node_qns=node_qns,
            bare_calls=bare_calls,
            dangling_targets=dangling,
            low_confidence_calls=low_conf,
        )
        self._adj = store.load_flow_adjacency()
        return self._index

    def _dynamic_sites(self, store: GraphStore, qn: str) -> list[str]:
        if qn in self._dynamic_cache:
            return self._dynamic_cache[qn]
        node = store.get_node(qn)
        if node is None:
            self._dynamic_cache[qn] = []
            return []
        source = read_node_source(node, self.repo_root)
        hits: list[str] = []
        for name, pattern in _DYNAMIC_PATTERNS:
            if pattern.search(source):
                hits.append(f"dynamic:{name}")
        self._dynamic_cache[qn] = hits
        return hits

    def _has_calls_edge(self, store: GraphStore, src: str, tgt: str) -> bool:
        if self._overrides.has_calls_edge(src, tgt):
            return True
        for edge in store.get_edges_by_source(src):
            if edge.kind == "CALLS" and edge.target_qualified == tgt:
                return True
        # bare name 可能匹配
        tgt_name = tgt.rsplit("::", 1)[-1]
        for edge in store.get_edges_by_source(src):
            if edge.kind == "CALLS" and edge.target_qualified == tgt_name:
                return True
        return False

    def score_candidate(
        self,
        store: GraphStore,
        candidate: FlowCandidate,
        sink_had_no_path: bool = False,
    ) -> GapScoreResult:
        index = self.build_index(store)
        result = GapScoreResult()
        path = candidate.path_qns
        path_set = set(path)

        if sink_had_no_path or (
            len(path) == 1 and candidate.source_qn == candidate.sink_qn
        ):
            self._add(result, "sink_unreachable", "sink_unreachable:no_path_to_source")

        for qn in path:
            if qn not in index.node_qns:
                self._add(result, "missing_node", f"missing_node:{qn.rsplit('::', 1)[-1]}")

        for src, tgt, _line in index.bare_calls:
            if self._is_ignorable_target(tgt):
                continue
            if src in path_set and (tgt in path_set or tgt in index.dangling_targets):
                self._add(result, "bare_call_target", f"bare_call:{src.rsplit('::', 1)[-1]}->{tgt}")

        for tgt in index.dangling_targets:
            if self._is_ignorable_target(tgt):
                continue
            for qn in path:
                for edge in store.get_edges_by_source(qn):
                    if edge.kind == "CALLS" and edge.target_qualified == tgt:
                        self._add(
                            result,
                            "dangling_edge_target",
                            f"dangling:{qn.rsplit('::', 1)[-1]}->{tgt}",
                        )

        for i in range(len(path) - 1):
            a, b = path[i], path[i + 1]
            if not self._has_calls_edge(store, a, b):
                self._add(
                    result,
                    "path_hop_no_calls_edge",
                    f"path_break:{a.rsplit('::', 1)[-1]}->{b.rsplit('::', 1)[-1]}",
                )

        for qn in path:
            for site in self._dynamic_sites(store, qn):
                self._add(result, "dynamic_call_site_on_path", f"{site}@{qn.rsplit('::', 1)[-1]}")

        for src, tgt, conf in index.low_confidence_calls:
            if src in path_set and tgt in path_set:
                self._add(
                    result,
                    "low_confidence_edge",
                    f"low_conf:{src.rsplit('::', 1)[-1]}->{tgt}({conf:.2f})",
                )

        if len(candidate.communities) > 1:
            self._add(
                result,
                "cross_community",
                f"cross_community:{candidate.communities}",
            )

        return result

    def _is_ignorable_target(self, tgt: str) -> bool:
        if tgt in self.ignore_bare_names:
            return True
        if "::" in tgt:
            return False
        for prefix in self.ignore_prefixes:
            if tgt.startswith(prefix):
                return True
        return False

    def _add(self, result: GapScoreResult, weight_key: str, reason: str) -> None:
        if reason in result.reasons:
            return
        weight = self.weights.get(weight_key, 0)
        if self.builtin_downweight <= 0 and self._reason_targets_ignorable(reason):
            return
        if 0 < self.builtin_downweight < 1 and self._reason_targets_ignorable(reason):
            weight = int(weight * self.builtin_downweight)
            if weight <= 0:
                return
        result.reasons.append(reason)
        result.score += weight

    def _reason_targets_ignorable(self, reason: str) -> bool:
        if "->" not in reason:
            return False
        tgt = reason.rsplit("->", 1)[-1]
        if "(" in tgt:
            tgt = tgt.split("(", 1)[0]
        return self._is_ignorable_target(tgt)

    def apply_to_candidate(
        self,
        store: GraphStore,
        candidate: FlowCandidate,
        sink_had_no_path: bool = False,
    ) -> FlowCandidate:
        scored = self.score_candidate(store, candidate, sink_had_no_path)
        candidate.gap_score = scored.score
        candidate.gap_reasons = scored.reasons
        candidate.needs_agent = scored.score >= self.threshold
        return candidate

    def apply_flow_record_gaps(
        self,
        record_verdict: str,
        record_reachability: str,
        record_confidence: float,
        open_questions: list[str],
        base_score: int,
        base_reasons: list[str],
    ) -> tuple[int, list[str], bool]:
        """流 LLM 结果上的语义 gap 加分（用于二次判定是否 Agent）。"""
        score = base_score
        reasons = list(base_reasons)

        if record_verdict == "inconclusive":
            score += self.weights.get("flow_inconclusive", 20)
            reasons.append("flow:inconclusive")
        if record_reachability == "unknown":
            score += self.weights.get("flow_reachability_unknown", 15)
            reasons.append("flow:reachability_unknown")
        if record_confidence < 0.6:
            score += 10
            reasons.append(f"flow:low_confidence:{record_confidence:.2f}")

        gap_keywords = ("dynamic", "unknown callee", "framework", "middleware", "无法确认")
        for q in open_questions:
            if any(kw in q.lower() for kw in gap_keywords):
                score += 10
                reasons.append(f"flow:open_question:{q[:60]}")
                break

        return score, reasons, score >= self.threshold
