"""外部知识检索（CWE / OWASP / 代码信号 / 新花样）。"""

from __future__ import annotations

import re
from typing import Any, Optional

from skynet.knowledge.loader import (
    load_attack_patterns,
    load_code_signals,
    load_keyword_map,
    resolve_ref,
)


class ExternalKnowledgeRetriever:
    """基于代码信号与关键词检索外部安全知识。"""

    def __init__(self, knowledge_dir: Optional[str] = None) -> None:
        self.knowledge_dir = knowledge_dir

    def detect_code_signals(self, source: str) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for sig in load_code_signals(self.knowledge_dir):
            pattern = sig.get("pattern")
            if not pattern:
                continue
            try:
                if re.search(pattern, source, re.IGNORECASE | re.MULTILINE):
                    hits.append({
                        "signal_id": sig.get("id"),
                        "description": sig.get("description", ""),
                        "refs": sig.get("refs", []),
                    })
            except re.error:
                continue
        return hits

    def retrieve_by_text(self, text: str, max_items: int = 8) -> list[dict[str, Any]]:
        """根据文本中的关键词检索外部知识条目。"""
        text_lower = text.lower()
        seen: set[str] = set()
        results: list[dict[str, Any]] = []

        for keyword, refs in load_keyword_map(self.knowledge_dir).items():
            if keyword in text_lower:
                for ref in refs:
                    if ref in seen:
                        continue
                    entry = resolve_ref(ref, self.knowledge_dir)
                    if entry:
                        seen.add(ref)
                        results.append(entry)
                    if len(results) >= max_items:
                        return results

        for pat in load_attack_patterns(self.knowledge_dir):
            kws = pat.get("keywords", [])
            if any(kw in text_lower for kw in kws):
                results.append({
                    "type": "pattern",
                    "id": pat.get("id"),
                    "name": pat.get("title"),
                    "description": pat.get("description"),
                    "mitigation": pat.get("mitigation"),
                })
                for ref in pat.get("refs", []):
                    if ref not in seen:
                        entry = resolve_ref(ref, self.knowledge_dir)
                        if entry:
                            seen.add(ref)
                            results.append(entry)
            if len(results) >= max_items:
                break

        return results[:max_items]

    def retrieve_for_chunk(
        self,
        source: str,
        structural_context_text: str = "",
        max_items: int = 8,
    ) -> list[dict[str, Any]]:
        """综合代码信号 + 上下文文本检索外部知识。"""
        seen: set[str] = set()
        results: list[dict[str, Any]] = []

        for hit in self.detect_code_signals(source):
            results.append({
                "type": "signal",
                "id": hit["signal_id"],
                "name": hit["description"],
                "description": f"代码信号: {hit['description']}",
            })
            for ref in hit.get("refs", []):
                if ref in seen:
                    continue
                entry = resolve_ref(ref, self.knowledge_dir)
                if entry:
                    seen.add(ref)
                    results.append(entry)

        combined = f"{source}\n{structural_context_text}"
        for entry in self.retrieve_by_text(combined, max_items=max_items):
            key = entry.get("id", entry.get("name", ""))
            if key and key not in seen:
                seen.add(str(key))
                results.append(entry)

        return results[:max_items]
