"""知识上下文数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class KnowledgeContext:
    """单次 chunk 分析聚合的知识上下文。"""

    external: list[dict[str, Any]] = field(default_factory=list)
    internal: list[dict[str, Any]] = field(default_factory=list)
    web: list[dict[str, Any]] = field(default_factory=list)
    code_signals: list[dict[str, Any]] = field(default_factory=list)

    def to_prompt_block(self) -> str:
        lines = ["## Retrieved knowledge (use as reference, not as sole evidence)"]

        if self.code_signals:
            lines.append("\n### Code signals detected")
            for s in self.code_signals:
                lines.append(f"- [{s.get('signal_id')}] {s.get('description', '')}")

        if self.external:
            lines.append("\n### External security knowledge")
            for e in self.external:
                etype = e.get("type", "entry")
                eid = e.get("id", "")
                name = e.get("name", "")
                desc = e.get("description", "")
                mit = e.get("mitigation", "")
                lines.append(f"- [{etype}] {eid} {name}: {desc}")
                if mit:
                    lines.append(f"  Mitigation: {mit}")

        if self.internal:
            lines.append("\n### Project internal knowledge")
            for i in self.internal:
                itype = i.get("type", "internal")
                name = i.get("name", "")
                desc = i.get("description", "")
                lines.append(f"- [{itype}] {name}: {desc}")
                if i.get("false_positive"):
                    lines.append("  Note: previously marked as potential false positive")

        if self.web:
            lines.append("\n### Web search results (verify relevance)")
            for w in self.web:
                lines.append(f"- {w.get('title', 'Result')}: {w.get('snippet', '')}")
                if w.get("url"):
                    lines.append(f"  URL: {w['url']}")

        if not (self.external or self.internal or self.web or self.code_signals):
            lines.append("\n(No additional knowledge retrieved)")

        return "\n".join(lines)
