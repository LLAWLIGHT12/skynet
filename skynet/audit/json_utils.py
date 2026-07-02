"""Robust JSON extraction + schema validation for agent outputs.

升级版：新增 validate_and_repair() 公共函数，可供 text 模式和 SDK 模式
共用；改进修复提示包含具体 schema 约束。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from loguru import logger

log = logger


_FENCE_RE = re.compile(r"```(?:json)?\s*(.+?)\s*```", re.DOTALL)


def extract_json(text: str) -> Any:
    """Pull a JSON object out of an assistant message.

    Order of attempts:
      1. The full text is valid JSON.
      2. The text contains a ```json ... ``` fenced block.
      3. The largest balanced {...} or [...] substring is valid JSON.

    Raises ValueError if no JSON can be extracted.
    """
    text = text.strip()
    if not text:
        raise ValueError("Empty assistant output.")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    m = _FENCE_RE.search(text)
    if m:
        # 在 fence 内容中使用平衡括号提取（处理嵌套 JSON）
        candidate = _largest_balanced(m.group(1))
        if candidate is not None:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

    candidate = _largest_balanced(text)
    if candidate is not None:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    raise ValueError(
        f"Could not extract JSON from assistant output (len={len(text)}). "
        f"Head: {text[:200]!r}"
    )


def _largest_balanced(text: str) -> str | None:
    """Return the largest balanced {...} or [...] substring, or None."""
    best: str | None = None
    for open_c, close_c in (("{", "}"), ("[", "]")):
        for i, ch in enumerate(text):
            if ch != open_c:
                continue
            depth = 0
            in_str = False
            esc = False
            for j in range(i, len(text)):
                c = text[j]
                if esc:
                    esc = False
                    continue
                if c == "\\":
                    esc = True
                    continue
                if c == '"' and not esc:
                    in_str = not in_str
                if in_str:
                    continue
                if c == open_c:
                    depth += 1
                elif c == close_c:
                    depth -= 1
                    if depth == 0:
                        candidate = text[i : j + 1]
                        if best is None or len(candidate) > len(best):
                            best = candidate
                        break
    return best


def validate_schema(payload: Any, schema_path: Path) -> list[str]:
    """Validate `payload` against the schema at `schema_path`.

    Sibling schemas in the same directory are loaded into a referencing
    Registry so `$ref` entries like `"hunt_task.schema.json"` resolve.

    Returns a list of human-readable error strings; empty means valid.
    """
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schemas_dir = schema_path.parent.resolve()

    registry: Registry = Registry()
    for sf in schemas_dir.glob("*.schema.json"):
        raw = json.loads(sf.read_text(encoding="utf-8"))
        registry = registry.with_resource(
            sf.name, Resource.from_contents(raw, default_specification=DRAFT7)
        )

    validator = Draft7Validator(schema, registry=registry)
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(payload), key=lambda e: e.path)
    ]


def _extract_schema_constraints(schema_path: Path, errors: list[str] | None = None) -> str:
    """从 schema 和错误中提取关键约束提示。"""
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        parts: list[str] = []

        # 必填字段
        required = schema.get("required", [])
        if required:
            parts.append(f"Required fields: {', '.join(required)}")

        # 类型
        typ = schema.get("type", "")
        if typ:
            parts.append(f"Expected type: {typ}")

        # 顶层 properties 的简要说明
        props = schema.get("properties", {})
        if props:
            prop_hints = []
            for k, v in list(props.items())[:10]:
                vtype = v.get("type", "?")
                items_type = ""
                if "items" in v and isinstance(v["items"], dict):
                    items_type = f" of {v['items'].get('type', '?')}"
                prop_hints.append(f"`{k}`: {vtype}{items_type}")
            parts.append("Key properties: " + "; ".join(prop_hints))

        # additionalProperties
        if schema.get("additionalProperties") is False:
            parts.append("No extra fields allowed (additionalProperties: false)")

        return "\n".join(f"- {p}" for p in parts)
    except Exception:
        return ""


@dataclass
class RepairResult:
    """Schema 验证 + 修复的统计信息。"""
    valid: bool
    errors: list[str]
    repair_attempts: int = 0
    repair_succeeded: bool = False


def validate_and_repair(
    text: str,
    schema_path: Path,
    *,
    repair_fn=None,
    repair_attempts: int = 2,
) -> RepairResult:
    """一站式验证 + 修复：提取 JSON → 验证 → 可选修复。

    Args:
        text: LLM 原始输出文本
        schema_path: JSON Schema 文件路径
        repair_fn: 可选，async callable(text, errors) -> new_text
        repair_attempts: 最大修复尝试次数

    Returns:
        RepairResult 包含验证状态、错误列表和修复统计
    """
    try:
        payload = extract_json(text)
    except ValueError as e:
        return RepairResult(valid=False, errors=[f"json_extract: {e}"])

    errors = validate_schema(payload, schema_path)
    if not errors or repair_fn is None:
        return RepairResult(
            valid=len(errors) == 0,
            errors=errors,
            repair_attempts=0,
            repair_succeeded=False,
        )

    # repair loop
    import asyncio
    repair_count = 0
    current_text = text
    for attempt in range(repair_attempts):
        repair_count += 1
        try:
            new_text = asyncio.get_event_loop().run_until_complete(
                repair_fn(current_text, errors)
            )
        except Exception as exc:
            log.warning("repair_fn failed: %s", exc)
            break
        current_text = new_text
        try:
            payload = extract_json(current_text)
        except ValueError as e:
            errors = [f"json_extract: {e}"]
            continue
        errors = validate_schema(payload, schema_path)
        if not errors:
            return RepairResult(
                valid=True, errors=[],
                repair_attempts=repair_count,
                repair_succeeded=True,
            )

    return RepairResult(
        valid=False,
        errors=errors,
        repair_attempts=repair_count,
        repair_succeeded=False,
    )


def build_repair_prompt(prev_output: str, errors: list[str], schema_path: Path) -> str:
    """构建 schema-aware 修复提示，包含具体约束。

    比简单列举错误更有效：告诉 LLM 哪些字段必填、期望什么类型。
    """
    constraints = _extract_schema_constraints(schema_path, errors)
    err_block = "\n".join(f"- {e}" for e in errors[:15])

    prompt = (
        "Your previous output failed schema validation against "
        f"`{schema_path.name}`.\n\n"
        "### Validation errors\n"
        f"{err_block}\n\n"
    )
    if constraints:
        prompt += f"### Schema constraints\n{constraints}\n\n"
    prompt += (
        "Re-emit the SAME response with ONLY these fixes applied. "
        "Output a single JSON object — no prose, no markdown fence, "
        "no surrounding text."
    )
    return prompt
