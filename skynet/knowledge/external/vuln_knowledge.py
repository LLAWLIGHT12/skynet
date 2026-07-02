"""漏洞模式知识检索。

根据 sink 类型检索对应的漏洞模式知识（危险模式 + 安全实践），
作为 LLM prompt 的补充上下文，不替代 taint_rules.json。
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 数据文件路径
_DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "knowledge" / "external"
_VULN_PATTERNS_FILE = _DATA_DIR / "vuln_patterns.json"

# Sink 类型 -> 漏洞模式 ID 映射
_SINK_TO_VULN_MAP: Dict[str, List[str]] = {
    # SQL 注入
    "sql_execute": ["vuln_sql_injection"],
    "db_execute": ["vuln_sql_injection"],
    "db_query": ["vuln_sql_injection"],
    "raw_sql": ["vuln_sql_injection"],
    # NoSQL 注入
    "nosql_query": ["vuln_nosql_injection"],
    "mongo_find": ["vuln_nosql_injection"],
    # 命令注入
    "os_system": ["vuln_command_injection"],
    "subprocess_call": ["vuln_command_injection"],
    "exec_command": ["vuln_command_injection"],
    "shell_exec": ["vuln_command_injection"],
    # 代码注入
    "eval": ["vuln_code_injection"],
    "exec": ["vuln_code_injection"],
    # XSS
    "innerHTML": ["vuln_xss"],
    "document_write": ["vuln_xss"],
    "render_html": ["vuln_xss"],
    "echo_output": ["vuln_xss"],
    # SSRF
    "http_request": ["vuln_ssrf"],
    "url_fetch": ["vuln_ssrf"],
    "open_url": ["vuln_ssrf"],
    # 路径遍历
    "file_open": ["vuln_path_traversal"],
    "file_read": ["vuln_path_traversal"],
    "file_include": ["vuln_path_traversal"],
    "send_file": ["vuln_path_traversal"],
    # XXE
    "xml_parse": ["vuln_xxe"],
    "xml_load": ["vuln_xxe"],
    # 反序列化
    "pickle_load": ["vuln_deserialization"],
    "yaml_load": ["vuln_deserialization"],
    "unserialize": ["vuln_deserialization"],
    "deserialize": ["vuln_deserialization"],
    # 认证绕过
    "auth_check": ["vuln_auth_bypass"],
    "session_check": ["vuln_auth_bypass"],
    # CSRF
    "state_change": ["vuln_csrf"],
    "form_submit": ["vuln_csrf"],
    # 开放重定向
    "redirect": ["vuln_open_redirect"],
    # 竞态条件
    "check_then_use": ["vuln_race_condition"],
    "balance_check": ["vuln_race_condition"],
}


@dataclass
class VulnPattern:
    """漏洞模式条目。"""
    id: str
    title: str
    cwe_ids: List[str]
    owasp_ids: List[str]
    dangerous_patterns: List[Dict[str, str]]
    safe_patterns: List[Dict[str, str]]
    payloads: List[str]
    remediation: str


class VulnPatternRetriever:
    """漏洞模式检索器。

    用法::

        retriever = VulnPatternRetriever()
        patterns = retriever.retrieve("sql_execute")
        context = retriever.get_context_for_prompt("sql_execute")
    """

    def __init__(self, data_file: Optional[Path] = None):
        self._file = data_file or _VULN_PATTERNS_FILE
        self._data: Dict[str, Any] = {}
        self._cache: Dict[str, VulnPattern] = {}
        self._load()

    def _load(self) -> None:
        """加载漏洞模式 JSON。"""
        if not self._file.exists():
            logger.warning("Vuln patterns data not found: %s", self._file)
            return

        try:
            with open(self._file, "r", encoding="utf-8") as f:
                self._data = json.load(f)
            logger.info("Loaded %d vulnerability patterns", len(self._data))
        except Exception as e:
            logger.error("Failed to load vuln patterns: %s", e)

    def retrieve(self, sink_type: str) -> List[VulnPattern]:
        """根据 sink 类型检索漏洞模式。

        Args:
            sink_type: sink 类型标识（如 "sql_execute", "eval", "http_request"）。

        Returns:
            匹配的漏洞模式列表。
        """
        vuln_ids = _SINK_TO_VULN_MAP.get(sink_type, [])
        if not vuln_ids:
            return []

        results = []
        for vid in vuln_ids:
            pattern = self._get_pattern(vid)
            if pattern:
                results.append(pattern)
        return results

    def retrieve_by_text(self, text: str) -> List[VulnPattern]:
        """根据文本内容检索漏洞模式（关键词匹配）。"""
        text_lower = text.lower()
        results = []
        seen = set()

        for vuln_id, vuln_data in self._data.items():
            if vuln_id in seen:
                continue

            title = vuln_data.get("title", "").lower()
            # 检查标题关键词
            title_keywords = title.split()
            if any(kw in text_lower for kw in title_keywords if len(kw) > 3):
                pattern = self._get_pattern(vuln_id)
                if pattern:
                    results.append(pattern)
                    seen.add(vuln_id)

        return results

    def _get_pattern(self, vuln_id: str) -> Optional[VulnPattern]:
        """获取单个漏洞模式（带缓存）。"""
        if vuln_id in self._cache:
            return self._cache[vuln_id]

        data = self._data.get(vuln_id)
        if data is None:
            return None

        pattern = VulnPattern(
            id=vuln_id,
            title=data.get("title", ""),
            cwe_ids=data.get("cwe_ids", []),
            owasp_ids=data.get("owasp_ids", []),
            dangerous_patterns=data.get("dangerous_patterns", []),
            safe_patterns=data.get("safe_patterns", []),
            payloads=data.get("payloads", []),
            remediation=data.get("remediation", ""),
        )

        self._cache[vuln_id] = pattern
        return pattern

    def get_context_for_prompt(self, sink_type: str) -> str:
        """获取漏洞模式的 prompt 上下文。

        返回格式化的文本，可注入到 LLM prompt 中。
        """
        patterns = self.retrieve(sink_type)
        if not patterns:
            return ""

        parts = ["## Vulnerability Pattern Knowledge\n"]

        for p in patterns:
            parts.append(f"### {p.title}")
            parts.append(f"CWE: {', '.join(p.cwe_ids)} | OWASP: {', '.join(p.owasp_ids)}")
            parts.append("")

            parts.append("**Dangerous Patterns:**")
            for dp in p.dangerous_patterns[:5]:  # 最多 5 个
                parts.append(f"- [{dp.get('lang', '')}] `{dp.get('pattern', '')}`")
                parts.append(f"  → {dp.get('description', '')}")

            parts.append("")
            parts.append("**Safe Patterns:**")
            for sp in p.safe_patterns[:3]:  # 最多 3 个
                parts.append(f"- [{sp.get('lang', '')}] `{sp.get('pattern', '')}`")
                parts.append(f"  → {sp.get('description', '')}")

            parts.append("")
            parts.append(f"**Remediation:** {p.remediation}")
            parts.append("")

        return "\n".join(parts)

    def get_all_vuln_ids(self) -> List[str]:
        """获取所有漏洞模式 ID。"""
        return list(self._data.keys())

    def is_loaded(self) -> bool:
        """检查数据是否已加载。"""
        return len(self._data) > 0


# 全局实例
_global_retriever: Optional[VulnPatternRetriever] = None


def get_vuln_pattern_retriever() -> VulnPatternRetriever:
    """获取全局漏洞模式检索器。"""
    global _global_retriever
    if _global_retriever is None:
        _global_retriever = VulnPatternRetriever()
    return _global_retriever
