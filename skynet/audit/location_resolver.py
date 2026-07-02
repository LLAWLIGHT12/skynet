"""确定性行号解析器 —— 对 LLM 输出的 finding 做行号校验/修正。

- 从 finding 的 evidence（代码片段）在目标文件中滑动窗口匹配
- 行号一致则不修改；不一致则以确定性结果修正
- 支持 normalize（去空白、去 diff 标记 +/-）
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def normalize_line(s: str) -> str:
    """去除行首尾空白及 diff 标记（+/-）。"""
    s = s.strip()
    if s.startswith("+") or s.startswith("-"):
        s = s[1:].strip()
    return s


def _split_and_normalize(code: str) -> list[str]:
    """将代码拆分为行并逐行 normalize，跳过空行。"""
    result: list[str] = []
    for line in code.split("\n"):
        n = normalize_line(line)
        if n:
            result.append(n)
    return result


def resolve_finding_location(
    finding: dict[str, Any],
    repo_path: str | Path,
) -> tuple[int, int, bool]:
    """对单个 finding 做确定性行号解析。

    Parameters
    ----------
    finding : dict
        LLM 输出的 finding JSON，需包含 ``file`` 和 ``evidence`` 字段。
    repo_path : str | Path
        仓库根目录。

    Returns
    -------
    (start_line, end_line, was_resolved)
        若 ``was_resolved`` 为 True，则 ``start_line`` / ``end_line``
        为确定性匹配结果；否则保留 LLM 原始值。
    """
    evidence = finding.get("evidence") or ""
    # evidence 可能是 dict（如 {"code": "..."}），需提取字符串
    if isinstance(evidence, dict):
        evidence = evidence.get("code", "") or evidence.get("snippet", "") or ""
    if not evidence:
        return (
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            False,
        )

    file_path = finding.get("file", "")
    if not file_path:
        return (
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            False,
        )

    repo = Path(repo_path)
    target = repo / file_path
    if not target.is_file():
        log.debug("location_resolver: file not found: %s", target)
        return (
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            False,
        )

    try:
        file_content = target.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        log.debug("location_resolver: read error %s: %s", target, e)
        return (
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            False,
        )

    return _match_evidence_in_content(evidence, file_content, finding)


def _match_evidence_in_content(
    evidence: str,
    file_content: str,
    finding: dict[str, Any],
) -> tuple[int, int, bool]:
    """在文件内容中滑动窗口匹配 evidence，返回行号和是否成功。"""
    target_lines = _split_and_normalize(evidence)
    if not target_lines:
        return (
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            False,
        )

    file_lines_raw = file_content.split("\n")
    # 构建 (normalized_content, original_line_number) 列表
    indexed_lines: list[tuple[int, str]] = []
    for i, line in enumerate(file_lines_raw, start=1):
        n = normalize_line(line.rstrip("\r"))
        if n:
            indexed_lines.append((i, n))

    if len(indexed_lines) < len(target_lines):
        return (
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            False,
        )

    # 滑动窗口匹配
    for i in range(len(indexed_lines) - len(target_lines) + 1):
        matched = True
        for j, target in enumerate(target_lines):
            if indexed_lines[i + j][1] != target:
                matched = False
                break
        if matched:
            start_line = indexed_lines[i][0]
            end_line = indexed_lines[i + len(target_lines) - 1][0]
            return start_line, end_line, True

    return (
        finding.get("line_start", 0),
        finding.get("line_end", 0),
        False,
    )


def resolve_findings_locations(
    findings: list[dict[str, Any]],
    repo_path: str | Path,
) -> list[dict[str, Any]]:
    """批量解析 finding 列表的行号，返回修正后的副本。

    不修改原始 finding dict，而是返回浅拷贝 + 修正后的行号。
    """
    resolved = []
    corrected_count = 0
    for f in findings:
        start, end, was_resolved = resolve_finding_location(f, repo_path)
        new_f = dict(f)
        if was_resolved:
            old_start = f.get("line_start", 0)
            old_end = f.get("line_end", 0)
            if old_start != start or old_end != end:
                corrected_count += 1
                log.debug(
                    "location_resolver: corrected %s lines %d-%d -> %d-%d",
                    f.get("finding_id", f.get("file", "?")),
                    old_start, old_end, start, end,
                )
            new_f["line_start"] = start
            new_f["line_end"] = end
            new_f["_location_resolved"] = True
        else:
            new_f["_location_resolved"] = False
        resolved.append(new_f)

    if corrected_count:
        log.info(
            "location_resolver: corrected %d/%d finding locations",
            corrected_count, len(findings),
        )
    return resolved
