"""报告主题常量。"""

from __future__ import annotations

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_META = {
    "critical": {"label": "严重", "color": "#dc2626", "bg": "#fef2f2", "border": "#fecaca"},
    "high": {"label": "高危", "color": "#ea580c", "bg": "#fff7ed", "border": "#fed7aa"},
    "medium": {"label": "中危", "color": "#ca8a04", "bg": "#fefce8", "border": "#fef08a"},
    "low": {"label": "低危", "color": "#2563eb", "bg": "#eff6ff", "border": "#bfdbfe"},
    "info": {"label": "信息", "color": "#64748b", "bg": "#f8fafc", "border": "#e2e8f0"},
}

SOURCE_META = {
    "chunk": {"label": "Chunk", "color": "#6366f1"},
    "flow": {"label": "Flow", "color": "#0d9488"},
    "composite": {"label": "Composite", "color": "#a855f7"},
}
