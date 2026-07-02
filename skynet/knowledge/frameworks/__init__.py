"""框架安全知识库。

根据代码中的 import 语句自动检测框架，
加载对应的安全知识（危险模式 + 安全实践）。
不替代现有 CWE/OWASP 知识。
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 数据文件路径
_DATA_DIR = Path(__file__).resolve().parents[3] / "data" / "knowledge" / "external"
_FRAMEWORK_FILE = _DATA_DIR / "framework_security.json"


@dataclass
class DangerousPattern:
    """危险模式。"""
    id: str
    title: str
    cwe_ids: List[str]
    owasp_ids: List[str]
    severity: str
    patterns: List[Dict[str, str]]
    safe_alternatives: List[Dict[str, str]]


@dataclass
class FrameworkKnowledge:
    """框架安全知识。"""
    name: str
    detection_patterns: List[str]
    dangerous_patterns: List[DangerousPattern]
    security_best_practices: List[str]


class FrameworkDetector:
    """框架检测器。

    根据代码内容（主要是 import 语句）检测使用的框架。
    """

    def __init__(self, framework_data: Optional[Dict[str, Any]] = None):
        self._data = framework_data or {}
        self._compilers: Dict[str, List[re.Pattern]] = {}
        for fw_id, fw_info in self._data.items():
            patterns = fw_info.get("detection_patterns", [])
            self._compilers[fw_id] = [re.compile(re.escape(p)) for p in patterns]

    def detect(self, code_content: str) -> List[str]:
        """检测代码中使用的框架。

        Args:
            code_content: 代码内容（通常是一个 chunk）。

        Returns:
            检测到的框架 ID 列表，如 ["flask", "django"]。
        """
        detected = []
        for fw_id, patterns in self._compilers.items():
            for pattern in patterns:
                if pattern.search(code_content):
                    detected.append(fw_id)
                    break
        return detected

    def detect_from_file(self, file_path: str | Path) -> List[str]:
        """从文件内容检测框架。"""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            return self.detect(content)
        except Exception as e:
            logger.warning("Failed to read file %s: %s", file_path, e)
            return []


class FrameworkKnowledgeBase:
    """框架安全知识库。

    用法::

        kb = FrameworkKnowledgeBase()
        frameworks = kb.detect("from flask import Flask")
        knowledge = kb.get_knowledge("flask")
        prompt_context = kb.get_prompt_context("flask")
    """

    def __init__(self, data_file: Optional[Path] = None):
        self._file = data_file or _FRAMEWORK_FILE
        self._data: Dict[str, Any] = {}
        self._detector: Optional[FrameworkDetector] = None
        self._knowledge_cache: Dict[str, FrameworkKnowledge] = {}
        self._load()

    def _load(self) -> None:
        """加载框架安全知识 JSON。"""
        if not self._file.exists():
            logger.warning("Framework security data not found: %s", self._file)
            return

        try:
            with open(self._file, "r", encoding="utf-8") as f:
                self._data = json.load(f)
            self._detector = FrameworkDetector(self._data)
            logger.info("Loaded framework knowledge for %d frameworks", len(self._data))
        except Exception as e:
            logger.error("Failed to load framework knowledge: %s", e)

    def detect(self, code_content: str) -> List[str]:
        """检测代码中使用的框架。"""
        if self._detector is None:
            return []
        return self._detector.detect(code_content)

    def get_knowledge(self, framework_id: str) -> Optional[FrameworkKnowledge]:
        """获取指定框架的安全知识。"""
        if framework_id in self._knowledge_cache:
            return self._knowledge_cache[framework_id]

        fw_data = self._data.get(framework_id)
        if fw_data is None:
            return None

        patterns = []
        for p in fw_data.get("dangerous_patterns", []):
            patterns.append(DangerousPattern(
                id=p.get("id", ""),
                title=p.get("title", ""),
                cwe_ids=p.get("cwe_ids", []),
                owasp_ids=p.get("owasp_ids", []),
                severity=p.get("severity", "medium"),
                patterns=p.get("patterns", []),
                safe_alternatives=p.get("safe_alternatives", []),
            ))

        knowledge = FrameworkKnowledge(
            name=fw_data.get("name", framework_id),
            detection_patterns=fw_data.get("detection_patterns", []),
            dangerous_patterns=patterns,
            security_best_practices=fw_data.get("security_best_practices", []),
        )

        self._knowledge_cache[framework_id] = knowledge
        return knowledge

    def get_prompt_context(self, framework_id: str) -> str:
        """获取框架安全知识的 prompt 上下文。

        返回格式化的文本，可注入到 LLM prompt 中。
        """
        knowledge = self.get_knowledge(framework_id)
        if knowledge is None:
            return ""

        parts = [f"## {knowledge.name} Security Knowledge\n"]

        if knowledge.dangerous_patterns:
            parts.append("### Dangerous Patterns\n")
            for dp in knowledge.dangerous_patterns:
                parts.append(f"- **{dp.title}** ({dp.severity})")
                parts.append(f"  CWE: {', '.join(dp.cwe_ids)}")
                for p in dp.patterns:
                    parts.append(f"  Pattern: `{p.get('code', '')}`")
                    parts.append(f"  Risk: {p.get('description', '')}")
                if dp.safe_alternatives:
                    parts.append("  Safe:")
                    for alt in dp.safe_alternatives:
                        parts.append(f"    `{alt.get('code', '')}`")
                parts.append("")

        if knowledge.security_best_practices:
            parts.append("### Best Practices\n")
            for bp in knowledge.security_best_practices:
                parts.append(f"- {bp}")
            parts.append("")

        return "\n".join(parts)

    def get_all_framework_ids(self) -> List[str]:
        """获取所有已知框架 ID。"""
        return list(self._data.keys())

    def is_loaded(self) -> bool:
        """检查知识库是否已加载。"""
        return len(self._data) > 0


# 全局实例
_global_kb: Optional[FrameworkKnowledgeBase] = None


def get_framework_kb() -> FrameworkKnowledgeBase:
    """获取全局框架知识库实例。"""
    global _global_kb
    if _global_kb is None:
        _global_kb = FrameworkKnowledgeBase()
    return _global_kb
