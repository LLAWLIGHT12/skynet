"""Agent 可调用的 Tool Use 层（read_node + LSP）。"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from code_review_graph.graph import GraphStore

from skynet.config import SkynetConfig, get_config
from skynet.graph.chunks import read_node_source
from skynet.tools.lsp_tools import (
    LSPToolkit,
    find_symbol_column,
    format_locations,
    lsp_line,
    relative_file_path,
)

try:
    from skynet.tools.input_validator import ToolInputValidator, InputValidationError
    _VALIDATOR_AVAILABLE = True
except ImportError:
    _VALIDATOR_AVAILABLE = False
    InputValidationError = ValueError  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)

# 供 LLM system prompt 使用的工具说明
AGENT_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "action": "read_node",
        "description": "读取图谱中某函数的源码（qualified_name）",
        "params": {"qualified_name": "str", "reason": "str (optional)"},
    },
    {
        "action": "lsp_definition",
        "description": "LSP 跳转到符号定义（补全 bare_call / 动态调用断边）",
        "params": {
            "file_path": "相对或绝对路径",
            "line": "1-based 行号",
            "column": "0-based 列号，可选",
            "symbol": "符号名，用于自动定位列",
        },
    },
    {
        "action": "lsp_references",
        "description": "LSP 查找符号的所有引用（找 source 或 caller）",
        "params": {"file_path": "str", "line": "int", "column": "int (optional)", "symbol": "str (optional)"},
    },
    {
        "action": "lsp_hover",
        "description": "LSP 查看符号类型/文档",
        "params": {"file_path": "str", "line": "int", "column": "int (optional)", "symbol": "str (optional)"},
    },
    {
        "action": "lsp_document_symbols",
        "description": "LSP 列出文件内符号大纲",
        "params": {"file_path": "str"},
    },
    {
        "action": "conclude",
        "description": "给出最终流分析结论",
        "params": {
            "verdict": "vulnerable|sanitized|inconclusive|unknown",
            "severity": "critical|high|medium|low|info",
            "confidence": "0-1",
            "reachability": "confirmed|likely|rejected|unknown",
            "summary": "str",
            "resolved_path": ["qualified_name", "..."],
        },
    },
]


def format_tool_specs_for_prompt() -> str:
    lines = ["可用动作（返回 JSON，字段 action 指定工具名）："]
    for i, spec in enumerate(AGENT_TOOL_SPECS, 1):
        params = ", ".join(f"{k}: {v}" for k, v in spec.get("params", {}).items())
        lines.append(f"{i}. action={spec['action']} — {spec['description']}")
        lines.append(f"   params: {{{params}}}")
    lines.append(
        "优先：gap 为 bare_call/dynamic 时用 lsp_definition；找 source 用 lsp_references；"
        "仍不确定再 read_node；最后 conclude。"
    )
    return "\n".join(lines)


class AgentToolExecutor:
    """执行 Agent 的 tool use 并返回 observation 文本。"""

    def __init__(
        self,
        repo_root: str | Path,
        store: GraphStore,
        lsp: Optional[LSPToolkit] = None,
        config: Optional[SkynetConfig] = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.store = store
        self.lsp = lsp
        self.config = config or get_config()
        self._observations: list[str] = []
        self._validator: Optional[Any] = None
        if _VALIDATOR_AVAILABLE:
            try:
                self._validator = ToolInputValidator(str(self.repo_root))
            except Exception as e:
                logger.debug("ToolInputValidator init failed: %s", e)

    @property
    def observations(self) -> list[str]:
        return self._observations

    def _record(self, action: str, observation: str) -> str:
        block = f"### Tool: {action}\n{observation}"
        self._observations.append(block)
        return block

    async def execute(self, parsed: dict[str, Any]) -> tuple[str, bool]:
        """执行工具，返回 (observation, is_conclusion)。"""
        action = str(parsed.get("action", "")).lower()

        if action == "conclude":
            return "", True

        if self._validator is not None:
            file_path = parsed.get("file_path", "")
            if file_path:
                try:
                    self._validator.validate_file_path(str(file_path))
                except InputValidationError as e:
                    return self._record(action, f"(input validation failed: {e})"), False

        if action == "read_node":
            qn = str(parsed.get("qualified_name", ""))
            obs = self._read_node(qn)
            return self._record(action, obs), False

        if action.startswith("lsp_"):
            if not self.lsp or not self.lsp.available:
                return self._record(action, "(LSP 未启用或启动失败，请改用 read_node)"), False
            obs = await self._run_lsp(action, parsed)
            return self._record(action, obs), False

        return self._record(action, f"(unknown action: {action})"), False

    def _read_node(self, qn: str) -> str:
        if not qn:
            return "(missing qualified_name)"
        node = self.store.get_node(qn)
        if node is None:
            return f"{qn}\n(not in graph)"
        src = read_node_source(node, self.repo_root)
        lines = src.splitlines()
        if len(lines) > 150:
            src = "\n".join(lines[:150]) + f"\n# ... ({len(lines) - 150} more)"
        return f"### {qn.rsplit('::', 1)[-1]}\n```\n{src}\n```"

    async def _run_lsp(self, action: str, parsed: dict[str, Any]) -> str:
        file_path = str(parsed.get("file_path", ""))
        if not file_path and parsed.get("qualified_name"):
            node = self.store.get_node(str(parsed["qualified_name"]))
            if node:
                file_path = node.file_path
                if parsed.get("line") is None:
                    parsed = {**parsed, "line": node.line_start or 1}
                if not parsed.get("symbol"):
                    parsed = {**parsed, "symbol": node.name}

        if not file_path:
            return "(missing file_path or qualified_name)"

        rel = relative_file_path(self.repo_root, file_path)
        line_1based = int(parsed.get("line", 1))
        line_0 = max(line_1based - 1, 0)

        symbol = str(parsed.get("symbol", ""))
        column = parsed.get("column")
        if column is None and symbol:
            try:
                abs_path = self.repo_root / rel
                if abs_path.is_file():
                    file_lines = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if 0 <= line_0 < len(file_lines):
                        column = find_symbol_column(file_lines[line_0], symbol)
            except OSError:
                column = 0
        col = int(column or 0)

        if action == "lsp_definition":
            locs = await self.lsp.definition(rel, line_0, col)
            return format_locations(locs)

        if action == "lsp_references":
            locs = await self.lsp.references(rel, line_0, col)
            return format_locations(locs)

        if action == "lsp_hover":
            return await self.lsp.hover(rel, line_0, col)

        if action == "lsp_document_symbols":
            return await self.lsp.document_symbols(rel)

        return f"(unsupported lsp action: {action})"

    def resolve_position_from_node(self, qualified_name: str) -> Optional[dict[str, Any]]:
        """从图谱节点生成 LSP 查询参数。"""
        node = self.store.get_node(qualified_name)
        if node is None:
            return None
        return {
            "file_path": relative_file_path(self.repo_root, node.file_path),
            "line": node.line_start or 1,
            "symbol": node.name,
        }
