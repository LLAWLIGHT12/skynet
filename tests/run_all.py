#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""本地 CI：顺序执行 smoke → merge → scan fixture。"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run(cmd: list[str], label: str) -> None:
    print(f"\n=== {label} ===")
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> int:
    run([PYTHON, "tests/test_smoke.py"], "smoke")
    run([PYTHON, "tests/test_merge.py"], "merge")
    run([PYTHON, "tests/test_overrides.py"], "overrides")
    run([PYTHON, "tests/test_composite.py"], "composite")
    run([PYTHON, "main.py", "scan", "-d", "tests/fixtures", "--skip-build"], "scan fixture")
    print("\nAll run_all checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
