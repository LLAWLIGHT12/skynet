"""从 JSON 加载外部安全知识库。"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def external_knowledge_dir(custom: Optional[str | Path] = None) -> Path:
    if custom:
        return Path(custom)
    return _project_root() / "data" / "knowledge" / "external"


@lru_cache(maxsize=1)
def load_cwe_db(knowledge_dir: Optional[str] = None) -> dict[str, dict[str, Any]]:
    path = external_knowledge_dir(knowledge_dir) / "cwe.json"
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_owasp_db(knowledge_dir: Optional[str] = None) -> dict[str, dict[str, Any]]:
    path = external_knowledge_dir(knowledge_dir) / "owasp.json"
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_keyword_map(knowledge_dir: Optional[str] = None) -> dict[str, list[str]]:
    path = external_knowledge_dir(knowledge_dir) / "keyword_map.json"
    if not path.is_file():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def load_code_signals(knowledge_dir: Optional[str] = None) -> list[dict[str, Any]]:
    path = external_knowledge_dir(knowledge_dir) / "code_signals.json"
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("signals", [])


@lru_cache(maxsize=1)
def load_attack_patterns(knowledge_dir: Optional[str] = None) -> list[dict[str, Any]]:
    path = external_knowledge_dir(knowledge_dir) / "patterns.json"
    if not path.is_file():
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("patterns", [])


def lookup_cwe(cwe_id: Optional[str], knowledge_dir: Optional[str] = None) -> Optional[dict[str, Any]]:
    if not cwe_id:
        return None
    key = cwe_id.upper()
    if not key.startswith("CWE-"):
        key = f"CWE-{key}"
    entry = load_cwe_db(knowledge_dir).get(key)
    if entry:
        return {"type": "cwe", "id": key, **entry}
    return None


def lookup_owasp(owasp_id: str, knowledge_dir: Optional[str] = None) -> Optional[dict[str, Any]]:
    entry = load_owasp_db(knowledge_dir).get(owasp_id)
    if entry:
        return {"type": "owasp", "id": owasp_id, **entry}
    return None


def resolve_ref(ref_id: str, knowledge_dir: Optional[str] = None) -> Optional[dict[str, Any]]:
    if ref_id.upper().startswith("CWE"):
        return lookup_cwe(ref_id, knowledge_dir)
    if ref_id.startswith("A"):
        return lookup_owasp(ref_id, knowledge_dir)
    return None


def clear_knowledge_cache() -> None:
    load_cwe_db.cache_clear()
    load_owasp_db.cache_clear()
    load_keyword_map.cache_clear()
    load_code_signals.cache_clear()
    load_attack_patterns.cache_clear()
