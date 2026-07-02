"""Source / Sink / Sanitizer 目录扫描。"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from code_review_graph.graph import GraphStore

from skynet.graph.chunks import CodeChunk, iter_chunks
from skynet.knowledge.loader import external_knowledge_dir, load_code_signals, clear_knowledge_cache
from skynet.taint.models import NodeAnnotation, TaintHit


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def load_taint_rules(knowledge_dir: Optional[str] = None) -> dict:
    path = external_knowledge_dir(knowledge_dir) / "taint_rules.json"
    if not path.is_file():
        return {"sources": [], "sanitizers": []}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def clear_taint_rules_cache() -> None:
    load_taint_rules.cache_clear()


def _compile_rules(rules: list[dict]) -> list[tuple[dict, re.Pattern]]:
    compiled: list[tuple[dict, re.Pattern]] = []
    for rule in rules:
        pattern = rule.get("pattern")
        if not pattern:
            continue
        try:
            compiled.append((rule, re.compile(pattern, re.IGNORECASE | re.MULTILINE)))
        except re.error:
            continue
    return compiled


class TaintCatalog:
    """扫描 chunk 源码，标注 source/sink/sanitizer 节点。"""

    def __init__(self, knowledge_dir: Optional[str] = None) -> None:
        self.knowledge_dir = knowledge_dir
        clear_knowledge_cache()
        clear_taint_rules_cache()
        self._sink_rules = _compile_rules([
            {**s, "role": "sink"} for s in load_code_signals(knowledge_dir)
        ])
        taint = load_taint_rules(knowledge_dir)
        self._source_rules = _compile_rules([
            {**s, "role": "source"} for s in taint.get("sources", [])
        ])
        self._sanitizer_rules = _compile_rules([
            {**s, "role": "sanitizer"} for s in taint.get("sanitizers", [])
        ])
        self._annotations: dict[str, NodeAnnotation] = {}

    def scan_source(self, source: str, qualified_name: str, node_id: int = 0) -> NodeAnnotation:
        hits: list[TaintHit] = []
        for rule_list in (self._source_rules, self._sink_rules, self._sanitizer_rules):
            for rule, pattern in rule_list:
                if pattern.search(source):
                    role = rule.get("role", "sink")
                    hits.append(TaintHit(
                        role=role,
                        rule_id=str(rule.get("id", "unknown")),
                        description=str(rule.get("description", "")),
                        tags=list(rule.get("tags", [])),
                        depth=str(rule.get("depth", "")),
                    ))
        ann = NodeAnnotation(qualified_name=qualified_name, node_id=node_id, hits=hits)
        self._annotations[qualified_name] = ann
        return ann

    def build_from_store(
        self,
        store: GraphStore,
        repo_root: str | Path,
        skip_tests: bool = True,
    ) -> "TaintCatalog":
        for chunk in iter_chunks(store, repo_root, skip_tests=skip_tests):
            self.scan_source(chunk.source, chunk.qualified_name, chunk.node_id)
        return self

    def get(self, qualified_name: str) -> Optional[NodeAnnotation]:
        return self._annotations.get(qualified_name)

    @property
    def sources(self) -> list[NodeAnnotation]:
        return [a for a in self._annotations.values() if a.is_source]

    @property
    def sinks(self) -> list[NodeAnnotation]:
        return [a for a in self._annotations.values() if a.is_sink]

    def chunk_has_sink(self, chunk: CodeChunk) -> bool:
        ann = self._annotations.get(chunk.qualified_name)
        if ann:
            return ann.is_sink
        ann = self.scan_source(chunk.source, chunk.qualified_name, chunk.node_id)
        return ann.is_sink

    def chunk_sink_types(self, chunk: CodeChunk) -> list[str]:
        ann = self._annotations.get(chunk.qualified_name)
        if not ann:
            ann = self.scan_source(chunk.source, chunk.qualified_name, chunk.node_id)
        return ann.sink_types
