import json
import re
from pathlib import Path

src = Path("tests/fixtures/vuln_sample.py").read_text(encoding="utf-8")
run_only = Path("tests/fixtures/vuln_sample.py").read_text(encoding="utf-8").split("def run_query")[1]

root = Path("data/knowledge/external")
for s in json.load(open(root / "taint_rules.json"))["sources"]:
    if re.search(s["pattern"], src, re.I):
        print("source", s["id"], "full")
for s in json.load(open(root / "taint_rules.json"))["sanitizers"]:
    if re.search(s["pattern"], run_only, re.I):
        print("san", s["id"], "run_query")
for s in json.load(open(root / "code_signals.json"))["signals"]:
    if re.search(s["pattern"], src, re.I):
        print("sink", s["id"], "full")
