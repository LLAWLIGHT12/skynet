#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Skynet 集成冒烟测试（无需 pytest）。"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.config import load_config, load_dotenv_if_present, get_config
from skynet.graph import GraphBuilder
from skynet.taint.catalog import TaintCatalog
from skynet.taint.gap_detector import GraphGapDetector
from skynet.taint.paths import enumerate_flow_candidates
from skynet.tools.lsp_tools import LSPToolkit, detect_code_language


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def test_catalog_and_gap(fixture: Path) -> None:
    builder = GraphBuilder(fixture)
    store = builder.open_store()
    with store:
        catalog = TaintCatalog().build_from_store(store, fixture)
        sinks = len(catalog.sinks)
        sources = len(catalog.sources)
        print(f"  catalog: {sources} sources, {sinks} sinks")
        if sinks == 0:
            fail("fixture 应检测到 sink")
        det = GraphGapDetector(fixture)
        cands = enumerate_flow_candidates(store, catalog, fixture, max_candidates=10, gap_detector=det)
        print(f"  candidates: {len(cands)}")
        if not cands:
            fail("fixture 应产生流候选")
        top = cands[0]
        print(f"  top gap_score={top.gap_score} needs_agent={top.needs_agent}")
        ok(f"catalog+gap: {len(cands)} flows, gap={top.gap_score}")


async def test_lsp(fixture: Path) -> None:
    lang = detect_code_language(fixture)
    print(f"  detected language: {lang}")
    async with LSPToolkit(fixture) as lsp:
        if not lsp.available:
            print("  [WARN] LSP 不可用，跳过 definition 断言")
            return
        locs = await lsp.definition("vuln_sample.py", 21, 8)
        print(f"  definition results: {len(locs)}")
        if not locs:
            fail("LSP definition 应返回至少 1 个位置")
        ok(f"LSP definition on handle_request -> {len(locs)} locs")


async def test_agent_tools_execute(fixture: Path) -> None:
    from code_review_graph.graph import GraphStore
    from skynet.tools.agent_tools import AgentToolExecutor

    db = fixture / ".skynet" / "graph.db"
    with GraphStore(db) as store:
        ex = AgentToolExecutor(fixture, store, lsp=None)
        obs, done = await ex.execute({
            "action": "read_node",
            "qualified_name": next(
                n.qualified_name
                for n in store.get_nodes_by_kind(["Function"])
                if n.name == "handle_request"
            ),
        })
        if done:
            fail("read_node 不应 conclude")
        if "handle_request" not in obs:
            fail("read_node 应返回源码")
        ok("AgentToolExecutor read_node")


def main() -> int:
    load_dotenv_if_present()
    cfg = ROOT / "config" / "skynet.yaml"
    if cfg.exists():
        load_config(cfg)

    fixture = ROOT / "tests" / "fixtures"
    if not (fixture / ".skynet" / "graph.db").exists():
        fail(f"请先 build: python main.py build -d {fixture} --full")

    print("=== test_catalog_and_gap ===")
    test_catalog_and_gap(fixture)

    print("=== test_agent_tools ===")
    asyncio.run(test_agent_tools_execute(fixture))

    print("=== test_lsp ===")
    asyncio.run(test_lsp(fixture))

    print("\nAll smoke tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
