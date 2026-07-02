#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""graph_overrides 单元测试。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from code_review_graph.graph import GraphStore
from skynet.graph.overrides import GraphOverridesStore, edges_from_resolved_path, persist_agent_resolved_path
from skynet.taint.catalog import TaintCatalog
from skynet.taint.gap_detector import GraphGapDetector
from skynet.taint.paths import enumerate_flow_candidates


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def test_persist_and_merge() -> None:
    fixture = ROOT / "tests" / "fixtures"
    db = fixture / ".skynet" / "graph.db"
    if not db.is_file():
        fail("请先 build fixtures")

    with GraphStore(db) as store:
        nodes = [n for n in store.get_all_nodes() if n.name in ("handle_request", "run_query")]
        by_name = {n.name: n.qualified_name for n in nodes}
        if "handle_request" not in by_name or "run_query" not in by_name:
            fail("fixture 缺少 handle_request / run_query 节点")

        path = [by_name["handle_request"], by_name["run_query"]]
        added = persist_agent_resolved_path(store, fixture, path, flow_id="test_override")

        ostore = GraphOverridesStore(fixture)
        calls_in: dict[str, list[str]] = {}
        merged = ostore.merge_into_calls_in(calls_in)
        tgt = by_name["run_query"]
        if by_name["handle_request"] not in merged.get(tgt, []):
            fail("override 应出现在 calls_in")

        edges = edges_from_resolved_path(path, store, fixture)
        if len(edges) != 1:
            fail(f"expected 1 edge from path, got {len(edges)}")
        if added < 1 and not ostore.has_calls_edge(by_name["handle_request"], tgt):
            fail(f"expected new or existing override edge, added={added}")
    ok(f"persist + merge calls_in (added={added})")


def test_gap_with_override() -> None:
    fixture = ROOT / "tests" / "fixtures"
    db = fixture / ".skynet" / "graph.db"
    override_path = fixture / ".skynet" / "graph_overrides.json"

    with GraphStore(db) as store:
        catalog = TaintCatalog().build_from_store(store, fixture)
        det = GraphGapDetector(fixture)
        before = enumerate_flow_candidates(store, catalog, fixture, max_candidates=5, gap_detector=det)
        if not before:
            fail("fixture 无流候选")
        score_before = before[0].gap_score

        nodes = {n.name: n.qualified_name for n in store.get_all_nodes()}
        persist_agent_resolved_path(
            store,
            fixture,
            [nodes["handle_request"], nodes["run_query"]],
            flow_id="gap_test",
        )

        det2 = GraphGapDetector(fixture)
        after = enumerate_flow_candidates(store, catalog, fixture, max_candidates=5, gap_detector=det2)
        score_after = after[0].gap_score

        if score_after > score_before:
            fail(f"gap 未下降: before={score_before} after={score_after}")
        ok(f"gap with override: {score_before} -> {score_after}")


def main() -> int:
    fixture = ROOT / "tests" / "fixtures"
    override_path = fixture / ".skynet" / "graph_overrides.json"
    backup = override_path.read_text(encoding="utf-8") if override_path.is_file() else None
    try:
        test_persist_and_merge()
        test_gap_with_override()
        print("\nAll override tests passed.")
        return 0
    finally:
        if backup is None:
            if override_path.is_file():
                override_path.unlink()
        else:
            override_path.write_text(backup, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
