"""Audit 管线专用 Tool Use 层（read_file / grep / glob / list_dir / read_node）。"""

from __future__ import annotations

import fnmatch
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Optional

from skynet.graph.chunks import read_node_source

try:
    from code_review_graph.graph import GraphStore
except ImportError:
    GraphStore = None  # type: ignore[misc, assignment]

try:
    from skynet.tools.input_validator import InputValidationError, ToolInputValidator
    _VALIDATOR_AVAILABLE = True
except ImportError:
    _VALIDATOR_AVAILABLE = False
    InputValidationError = ValueError  # type: ignore[misc, assignment]

logger = logging.getLogger(__name__)

# stages.yaml / legacy Claude Code 名称 → Skynet action
_TOOL_ALIASES: dict[str, str] = {
    "read": "read_file",
    "grep": "grep",
    "glob": "glob",
    "bash": "bash",
    "list_dir": "list_dir",
    "read_file": "read_file",
    "read_node": "read_node",
}

# 各 action 的 prompt 说明（按 allowed_tools 过滤后注入 system prompt）
AUDIT_TOOL_SPECS: dict[str, dict[str, Any]] = {
    "read_file": {
        "description": "读取仓库内单个文件的源码片段",
        "params": {
            "file_path": "相对 repo 根目录的路径",
            "offset": "起始行号 (1-based，可选)",
            "limit": "最多读取行数 (可选，默认 200)",
        },
    },
    "grep": {
        "description": "在仓库内搜索正则或字面量（类似 ripgrep）",
        "params": {
            "pattern": "搜索模式 (regex)",
            "path": "子目录或文件 (可选，默认整个仓库)",
            "max_matches": "最多返回匹配数 (可选，默认 40)",
        },
    },
    "glob": {
        "description": "按 glob 模式列出匹配的文件路径",
        "params": {
            "pattern": "如 **/*.py",
            "max_results": "最多返回路径数 (可选，默认 80)",
        },
    },
    "list_dir": {
        "description": "列出目录下的文件和子目录",
        "params": {
            "path": "相对 repo 根目录的目录 (可选，默认 .)",
            "max_entries": "最多条目数 (可选，默认 60)",
        },
    },
    "read_node": {
        "description": "按图谱 qualified_name 读取函数/类源码（需已 build 图谱）",
        "params": {"qualified_name": "str"},
    },
    "submit_final": {
        "description": "提交最终 JSON 结果（必须符合 Output schema）",
        "params": {"payload": "object — 完整 schema 合规输出"},
    },
}


def normalize_tool_names(tools: list[str] | None) -> list[str]:
    """将 stages.yaml 中的工具名规范化为 Skynet action。"""
    if not tools:
        return ["read_file", "grep", "glob", "list_dir"]
    out: list[str] = []
    for name in tools:
        key = str(name).strip()
        if not key:
            continue
        canonical = _TOOL_ALIASES.get(key, _TOOL_ALIASES.get(key.lower(), key.lower()))
        if canonical == "bash":
            continue  # Tier 2 不提供 Bash；预注入 + read/grep 替代
        if canonical not in out and canonical != "submit_final":
            out.append(canonical)
    if not out:
        out = ["read_file", "grep", "glob", "list_dir"]
    return out


def format_audit_tool_specs(allowed_tools: list[str] | None) -> str:
    """生成注入 audit Agent system prompt 的工具说明。"""
    names = normalize_tool_names(allowed_tools)
    lines = [
        "可用动作（每一步返回单个 JSON 对象，必须含 `action` 字段）：",
        "",
    ]
    for i, name in enumerate(names, 1):
        spec = AUDIT_TOOL_SPECS.get(name)
        if not spec:
            continue
        params = ", ".join(f"{k}: {v}" for k, v in spec.get("params", {}).items())
        lines.append(f"{i}. action={name!r} — {spec['description']}")
        lines.append(f"   params: {{{params}}}")
    final_n = len(names) + 1
    sf = AUDIT_TOOL_SPECS["submit_final"]
    lines.append(f"{final_n}. action='submit_final' — {sf['description']}")
    lines.append(f"   params: {{payload: object}}")
    lines.append("")
    lines.append(
        "流程：先用 read_file / grep / glob / list_dir / read_node 收集证据；"
        "证据足够后 action=submit_final 并给出完整 payload。"
        "不要在没有读过相关文件的情况下 submit_final。"
    )
    return "\n".join(lines)


class AuditToolExecutor:
    """执行 audit Agent 的 tool use 并累积 observation。"""

    def __init__(
        self,
        repo_root: str | Path,
        allowed_tools: list[str] | None = None,
        store: Any | None = None,
        max_file_lines: int = 200,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.allowed = set(normalize_tool_names(allowed_tools))
        self.store = store
        self.max_file_lines = max_file_lines
        self._observations: list[str] = []
        self._validator: Any | None = None
        if _VALIDATOR_AVAILABLE:
            try:
                self._validator = ToolInputValidator(str(self.repo_root))
            except Exception as e:
                logger.debug("ToolInputValidator init failed: %s", e)

    @property
    def observations(self) -> list[str]:
        return self._observations

    def preload_context(self, user_input: dict[str, Any]) -> None:
        """预注入 target_files、仓库顶层 listing、graph 摘要。"""
        repo = str(self.repo_root)
        self._record("preload", f"Repository root: {repo}")

        listing = self._list_dir(".", max_entries=40)
        self._record("preload", f"### Top-level listing\n{listing}")

        target_files = user_input.get("target_files") or []
        if isinstance(target_files, list):
            for fp in target_files[:12]:
                if not isinstance(fp, str) or not fp.strip():
                    continue
                content = self._read_file(fp.strip())
                self._record("preload", f"### Preloaded target: {fp}\n{content}")

        graph = user_input.get("graph_analysis")
        if graph and isinstance(graph, str) and graph.strip():
            self._record("preload", graph.strip()[:8000])

    def _record(self, action: str, observation: str) -> str:
        block = f"### Tool: {action}\n{observation}"
        self._observations.append(block)
        return block

    def _resolve_path(self, file_path: str) -> Path | None:
        if not file_path or not str(file_path).strip():
            return None
        raw = str(file_path).strip().replace("\\", "/")
        if self._validator is not None:
            try:
                rel = self._validator.validate_file_path(raw)
                return (self.repo_root / rel).resolve()
            except InputValidationError as e:
                raise ValueError(str(e)) from e
        candidate = (self.repo_root / raw).resolve()
        try:
            candidate.relative_to(self.repo_root)
        except ValueError:
            raise ValueError(f"path escapes repo: {file_path}") from None
        return candidate

    async def execute(self, parsed: dict[str, Any]) -> tuple[str, bool, dict[str, Any] | None]:
        """返回 (observation, is_final, payload_or_none)。"""
        action_raw = str(parsed.get("action", "")).strip()
        action = _TOOL_ALIASES.get(action_raw, _TOOL_ALIASES.get(action_raw.lower(), action_raw.lower()))

        if action == "submit_final":
            payload = parsed.get("payload")
            if payload is None and "findings" in parsed:
                payload = {k: v for k, v in parsed.items() if k != "action"}
            if payload is None and "initial_tasks" in parsed:
                payload = {k: v for k, v in parsed.items() if k != "action"}
            if not isinstance(payload, dict):
                return self._record("submit_final", "(missing or invalid payload object)"), False, None
            return "", True, payload

        if action not in self.allowed and action != "preload":
            return self._record(action, f"(tool {action!r} not allowed in this stage)"), False, None

        try:
            if action == "read_file":
                obs = self._read_file(
                    str(parsed.get("file_path", "")),
                    offset=int(parsed.get("offset") or 1),
                    limit=int(parsed.get("limit") or self.max_file_lines),
                )
            elif action == "grep":
                obs = self._grep(
                    str(parsed.get("pattern", "")),
                    str(parsed.get("path", "") or "."),
                    max_matches=int(parsed.get("max_matches") or 40),
                )
            elif action == "glob":
                obs = self._glob(
                    str(parsed.get("pattern", "")),
                    max_results=int(parsed.get("max_results") or 80),
                )
            elif action == "list_dir":
                obs = self._list_dir(
                    str(parsed.get("path", "") or "."),
                    max_entries=int(parsed.get("max_entries") or 60),
                )
            elif action == "read_node":
                obs = self._read_node(str(parsed.get("qualified_name", "")))
            elif action == "bash":
                obs = "(bash 未启用：请使用 read_file / grep / glob / list_dir)"
            else:
                obs = f"(unknown action: {action_raw})"
        except ValueError as e:
            obs = f"(error: {e})"
        except OSError as e:
            obs = f"(io error: {e})"

        return self._record(action, obs), False, None

    def _read_file(self, file_path: str, offset: int = 1, limit: int | None = None) -> str:
        if not file_path:
            return "(missing file_path)"
        path = self._resolve_path(file_path)
        if path is None:
            return "(invalid path)"
        if not path.is_file():
            return f"{file_path}\n(file not found)"
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return f"(cannot read: {e})"
        lines = text.splitlines()
        start = max(offset - 1, 0)
        cap = limit or self.max_file_lines
        chunk = lines[start : start + cap]
        numbered = "\n".join(f"{start + i + 1}| {line}" for i, line in enumerate(chunk))
        suffix = ""
        if start + cap < len(lines):
            suffix = f"\n# ... ({len(lines) - start - cap} more lines)"
        return f"```{file_path}\n{numbered}{suffix}\n```"

    def _list_dir(self, dir_path: str, max_entries: int = 60) -> str:
        try:
            base = self._resolve_path(dir_path) if dir_path and dir_path != "." else self.repo_root
        except ValueError as e:
            return str(e)
        if base is None or not base.is_dir():
            return f"{dir_path}\n(directory not found)"
        entries: list[str] = []
        try:
            for p in sorted(base.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                rel = p.relative_to(self.repo_root)
                kind = "dir" if p.is_dir() else "file"
                entries.append(f"  [{kind}] {rel.as_posix()}")
                if len(entries) >= max_entries:
                    entries.append(f"  ... (truncated,>{max_entries} entries)")
                    break
        except OSError as e:
            return f"(list error: {e})"
        return "\n".join(entries) if entries else "(empty directory)"

    def _glob(self, pattern: str, max_results: int = 80) -> str:
        if not pattern:
            return "(missing pattern)"
        pattern = pattern.replace("\\", "/")
        matches: list[str] = []
        try:
            for p in self.repo_root.rglob("*"):
                if not p.is_file():
                    continue
                rel = p.relative_to(self.repo_root).as_posix()
                if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(p.name, pattern):
                    matches.append(rel)
                    if len(matches) >= max_results:
                        matches.append(f"... (truncated,>{max_results} matches)")
                        break
        except OSError as e:
            return f"(glob error: {e})"
        return "\n".join(matches) if matches else "(no matches)"

    def _grep(self, pattern: str, path: str, max_matches: int = 40) -> str:
        if not pattern:
            return "(missing pattern)"
        # 优先 ripgrep
        search_path = path.strip() or "."
        try:
            target = self._resolve_path(search_path)
        except ValueError as e:
            return str(e)
        if target is None:
            return "(invalid path)"
        rg = _run_rg(pattern, target, self.repo_root, max_matches)
        if rg is not None:
            return rg
        return _grep_python(pattern, target, self.repo_root, max_matches)

    def _read_node(self, qualified_name: str) -> str:
        if not qualified_name:
            return "(missing qualified_name)"
        if self.store is None or GraphStore is None:
            return "(graph not available — run `python main.py build` first, or use read_file)"
        node = self.store.get_node(qualified_name)
        if node is None:
            return f"{qualified_name}\n(not in graph)"
        src = read_node_source(node, self.repo_root)
        lines = src.splitlines()
        if len(lines) > self.max_file_lines:
            src = "\n".join(lines[: self.max_file_lines]) + f"\n# ... ({len(lines) - self.max_file_lines} more)"
        return f"### {qualified_name}\n```\n{src}\n```"


def _run_rg(
    pattern: str,
    target: Path,
    repo_root: Path,
    max_matches: int,
) -> str | None:
    rg_bin = "rg"
    args = [
        rg_bin,
        "--line-number",
        "--no-heading",
        "--color=never",
        "-m",
        str(max_matches),
        pattern,
    ]
    if target.is_file():
        args.append(str(target))
    else:
        args.extend(["--glob", "!**/.git/**", str(target)])
    try:
        proc = subprocess.run(
            args,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1):
        return None
    out = proc.stdout.strip()
    return out if out else "(no matches)"


def _grep_python(pattern: str, target: Path, repo_root: Path, max_matches: int) -> str:
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return f"(invalid regex: {e})"

    files: list[Path]
    if target.is_file():
        files = [target]
    else:
        files = [p for p in target.rglob("*") if p.is_file() and ".git" not in p.parts]

    hits: list[str] = []
    for fp in files:
        try:
            rel = fp.relative_to(repo_root).as_posix()
            for i, line in enumerate(fp.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{rel}:{i}: {line[:200]}")
                    if len(hits) >= max_matches:
                        hits.append(f"... (truncated,>{max_matches} matches)")
                        return "\n".join(hits)
        except OSError:
            continue
    return "\n".join(hits) if hits else "(no matches)"
