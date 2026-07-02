#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""多语言 LSP 冒烟（JS，可选 Python 对照）。"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


@pytest.mark.asyncio
async def test_js_definition() -> None:
    from skynet.config import LSPConfig
    from skynet.tools.lsp_tools import LSPToolkit, detect_code_language

    js_root = ROOT / "tests" / "benchmark" / "js"
    if not (js_root / "app.js").is_file():
        fail("JS benchmark 不存在")

    lang = detect_code_language(js_root, "")
    if lang != "javascript":
        fail(f"expected javascript, got {lang}")

    async with LSPToolkit(js_root, LSPConfig(enabled=True, code_language="javascript")) as lsp:
        if not lsp.available:
            print("[SKIP] JS LSP 不可用（需安装 typescript-language-server 等）")
            return
        locs = await lsp.definition("app.js", 14, 15)
        if not locs:
            fail("JS LSP definition 应返回至少 1 个位置")
        ok(f"JS definition getUserInput -> {len(locs)} locs")


@pytest.mark.asyncio
async def test_python_definition() -> None:
    from skynet.tools.lsp_tools import LSPToolkit, detect_code_language

    fixture = ROOT / "tests" / "fixtures"
    lang = detect_code_language(fixture, "python")
    if lang != "python":
        fail(f"expected python, got {lang}")

    async with LSPToolkit(fixture) as lsp:
        if not lsp.available:
            print("[SKIP] Python LSP 不可用")
            return
        locs = await lsp.definition("vuln_sample.py", 21, 8)
        if not locs:
            fail("Python LSP definition 应返回至少 1 个位置")
        ok(f"Python definition -> {len(locs)} locs")


def main() -> int:
    from skynet.config import load_config, load_dotenv_if_present

    load_dotenv_if_present()
    cfg = ROOT / "config" / "skynet.yaml"
    if cfg.exists():
        load_config(cfg)

    only_js = os.environ.get("SKYNET_TEST_JS_ONLY", "") == "1"

    print("=== test_js_definition ===")
    asyncio.run(test_js_definition())

    if not only_js:
        print("=== test_python_definition ===")
        asyncio.run(test_python_definition())

    print("\nLSP language tests finished.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
