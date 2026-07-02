"""Skynet Audit Agent Runner — LLMClient + 多轮 Tool Use。

统一使用 Skynet 自有工具（read_file / grep / glob / list_dir / read_node），
不依赖 Claude Code SDK 或任何厂商 Agent 运行时。
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from skynet.audit.json_utils import build_repair_prompt, extract_json, validate_schema
from skynet.llm.client import LLMClient, LLMConfig, load_llm_config
from skynet.tools.audit_tools import AuditToolExecutor, format_audit_tool_specs, normalize_tool_names

log = logging.getLogger(__name__)

from skynet.audit.types import (
    AgentResult,
    AgentRunError,
    QuotaExhaustedError,
    TransientAgentError,
)


def _make_llm(model: str) -> LLMClient:
    """按 stage 配置创建 LLMClient；model=default 时使用环境变量。"""
    cfg = load_llm_config()
    if model and model.strip().lower() not in ("", "default"):
        cfg = LLMConfig(
            api_base_url=cfg.api_base_url,
            api_key=cfg.api_key,
            model_name=model.strip(),
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
            timeout=cfg.timeout,
        )
    return LLMClient(config=cfg)


def _open_graph_store(repo_path: Path | None) -> Any | None:
    if repo_path is None:
        return None
    try:
        from skynet.graph import GraphBuilder

        builder = GraphBuilder(repo_path)
        if not builder.db_path.exists():
            return None
        return builder.open_store()
    except Exception as e:
        log.debug("graph store unavailable for audit tools: %s", e)
        return None


async def run_agent(
    *,
    stage: str,
    prompt_file: Path,
    user_input: dict,
    schema_file: Path,
    allowed_tools: list[str] | None = None,
    model: str = "",
    cwd: Path | None = None,
    add_dirs: list[Path] | None = None,
    max_turns: int = 25,
    permission_mode: str = "acceptEdits",
    artifact_dir: Path | None = None,
    artifact_name: str = "agent",
    repair_attempts: int = 1,
    transient_retries: int = 3,
    transient_base_delay: float = 30.0,
) -> AgentResult:
    """运行 audit 阶段 Agent（多轮 Tool Use + schema 校验）。"""
    import asyncio

    artifact_dir = artifact_dir or Path.cwd() / "results" / artifact_name
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{artifact_name}.jsonl"

    last_exc: Exception | None = None
    for attempt in range(transient_retries + 1):
        try:
            return await _run_agent_once(
                stage=stage,
                prompt_file=prompt_file,
                user_input=user_input,
                schema_file=schema_file,
                allowed_tools=allowed_tools,
                model=model,
                cwd=cwd,
                add_dirs=add_dirs,
                max_turns=max_turns,
                artifact_path=artifact_path,
                artifact_name=artifact_name,
                repair_attempts=repair_attempts,
            )
        except QuotaExhaustedError:
            raise
        except TransientAgentError as e:
            last_exc = e
            if attempt >= transient_retries:
                break
            delay = min(transient_base_delay * (2 ** attempt), 240.0)
            log.warning(
                "[%s/%s] transient error (attempt %d/%d): %s — retrying in %.0fs",
                stage, artifact_name, attempt + 1, transient_retries + 1,
                str(e)[:160], delay,
            )
            await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


async def _run_agent_once(
    *,
    stage: str,
    prompt_file: Path,
    user_input: dict,
    schema_file: Path,
    allowed_tools: list[str] | None,
    model: str,
    cwd: Path | None,
    add_dirs: list[Path] | None,
    max_turns: int,
    artifact_path: Path,
    artifact_name: str,
    repair_attempts: int,
) -> AgentResult:
    started_at = time.time()
    repo_path = _resolve_repo_path(user_input, cwd, add_dirs)
    llm = _make_llm(model)
    effective_model = llm.config.model_name

    system_prompt = prompt_file.read_text(encoding="utf-8")
    schema_text = schema_file.read_text(encoding="utf-8")
    tool_block = format_audit_tool_specs(allowed_tools)
    system_prompt += (
        "\n\n# Skynet Agent Tools\n\n"
        f"{tool_block}\n\n"
        "# Output schema\n\n"
        "When you have gathered enough evidence, respond with "
        '`{"action":"submit_final","payload":{...}}` where `payload` '
        "validates against this JSON Schema:\n\n"
        f"```json\n{schema_text}\n```\n"
    )

    _write_artifact(artifact_path, {
        "kind": "meta",
        "stage": stage,
        "model": effective_model,
        "tools": normalize_tool_names(allowed_tools),
        "max_turns": max_turns,
        "started_at": started_at,
    })
    _write_artifact(artifact_path, {
        "kind": "user",
        "text": json.dumps(user_input, ensure_ascii=False)[:50000],
    })

    store_cm = _open_graph_store(repo_path)
    if store_cm is not None:
        with store_cm as store:
            payload, usage, agent_turns = await _run_tool_phase(
                llm=llm,
                system_prompt=system_prompt,
                user_input=user_input,
                allowed_tools=allowed_tools,
                repo_path=repo_path or Path.cwd(),
                store=store,
                max_turns=max(1, max_turns),
                artifact_path=artifact_path,
            )
    else:
        payload, usage, agent_turns = await _run_tool_phase(
            llm=llm,
            system_prompt=system_prompt,
            user_input=user_input,
            allowed_tools=allowed_tools,
            repo_path=repo_path or Path.cwd(),
            store=None,
            max_turns=max(1, max_turns),
            artifact_path=artifact_path,
        )

    repair_used = False
    errors = validate_schema(payload, schema_file)

    for _ in range(repair_attempts):
        if not errors:
            break
        repair_used = True
        repair_prompt = build_repair_prompt(json.dumps(payload, ensure_ascii=False), errors, schema_file)
        _write_artifact(artifact_path, {"kind": "repair_request", "text": repair_prompt[:50000]})
        try:
            repair_text, repair_usage = await llm.chat_json(system_prompt, repair_prompt)
        except Exception as e:
            _raise_mapped_error(e, stage, artifact_name)
        _write_artifact(artifact_path, {"kind": "assistant_repair", "text": repair_text[:50000]})
        try:
            payload = extract_json(repair_text)
        except ValueError:
            payload = {"_raw": repair_text}
        usage = _merge_usage(usage, repair_usage)
        errors = validate_schema(payload, schema_file)

    if errors:
        _write_artifact(artifact_path, {"kind": "schema_errors", "errors": errors})
        raise AgentRunError(
            f"[{stage}/{artifact_name}] schema validation failed after "
            f"{repair_attempts} repair attempts: {errors[:5]}"
        )

    _write_artifact(artifact_path, {"kind": "final_payload", "payload": payload})

    duration_ms = int((time.time() - started_at) * 1000)
    num_turns = agent_turns + (1 if repair_used else 0)
    raw_result = {
        "usage": {
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
            "cache_read_input_tokens": usage.get("cache_read_input_tokens"),
            "cache_creation_input_tokens": usage.get("cache_creation_input_tokens"),
        },
        "num_turns": num_turns,
        "duration_ms": duration_ms,
        "total_cost_usd": None,
        "session_id": None,
        "is_error": False,
    }

    return AgentResult(
        payload=payload,
        cost_usd=None,
        input_tokens=usage.get("input_tokens"),
        output_tokens=usage.get("output_tokens"),
        cache_read_tokens=usage.get("cache_read_input_tokens"),
        cache_creation_tokens=usage.get("cache_creation_input_tokens"),
        num_turns=num_turns,
        duration_ms=duration_ms,
        session_id=None,
        artifact_path=artifact_path,
        repair_used=repair_used,
        raw_result_message=raw_result,
    )


async def _run_tool_phase(
    *,
    llm: LLMClient,
    system_prompt: str,
    user_input: dict,
    allowed_tools: list[str] | None,
    repo_path: Path,
    store: Any | None,
    max_turns: int,
    artifact_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    executor = AuditToolExecutor(repo_path, allowed_tools=allowed_tools, store=store)
    executor.preload_context(user_input)
    return await _tool_loop(
        llm=llm,
        system_prompt=system_prompt,
        user_input=user_input,
        executor=executor,
        max_turns=max_turns,
        artifact_path=artifact_path,
    )


async def _tool_loop(
    *,
    llm: LLMClient,
    system_prompt: str,
    user_input: dict,
    executor: AuditToolExecutor,
    max_turns: int,
    artifact_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    usage_total: dict[str, Any] = {}
    agent_turns = 0
    payload: dict[str, Any] | None = None

    for step in range(max_turns):
        step_prompt = _build_step_prompt(user_input, executor.observations, step, max_turns)
        try:
            raw, usage = await llm.chat_json(system_prompt, step_prompt)
        except Exception as e:
            _raise_mapped_error(e, "agent", artifact_path.stem)
        agent_turns += 1
        usage_total = _merge_usage(usage_total, usage)
        _write_artifact(artifact_path, {"kind": "assistant", "step": step, "text": raw[:50000]})

        parsed = _parse_action_json(raw)
        obs, is_final, final_payload = await executor.execute(parsed)
        if is_final and final_payload is not None:
            payload = final_payload
            break
        if obs:
            _write_artifact(artifact_path, {"kind": "tool_observation", "step": step, "text": obs[:20000]})

        if step == max_turns - 1 and payload is None:
            payload = await _force_submit(
                llm, system_prompt, user_input, executor.observations, schema_hint=True,
            )
            agent_turns += 1

    if payload is None:
        payload = await _force_submit(
            llm, system_prompt, user_input, executor.observations, schema_hint=True,
        )
        agent_turns += 1

    return payload, usage_total, agent_turns


async def _force_submit(
    llm: LLMClient,
    system_prompt: str,
    user_input: dict,
    observations: list[str],
    schema_hint: bool = False,
) -> dict[str, Any]:
    prompt_parts = [
        "## Final step — you MUST submit_final now",
        "Original task input:",
        json.dumps(user_input, ensure_ascii=False)[:20000],
        "## Tool observations",
        "\n\n".join(observations[-12:]) if observations else "(none)",
        'Return JSON: {"action":"submit_final","payload":{...}} matching the Output schema.',
    ]
    if schema_hint:
        prompt_parts.append("Do not call any more tools. Put the complete result in payload.")
    raw, _ = await llm.chat_json(system_prompt, "\n\n".join(prompt_parts))
    parsed = _parse_action_json(raw)
    if parsed.get("action") == "submit_final" and isinstance(parsed.get("payload"), dict):
        return parsed["payload"]
    if "findings" in parsed or "initial_tasks" in parsed or "groups" in parsed:
        return {k: v for k, v in parsed.items() if k != "action"}
    try:
        return extract_json(raw)
    except ValueError:
        return {"_parse_error": raw[:2000]}


def _build_step_prompt(
    user_input: dict,
    observations: list[str],
    step: int,
    max_turns: int,
) -> str:
    return "\n\n".join([
        f"## Agent step {step + 1}/{max_turns}",
        "## Task input",
        json.dumps(user_input, ensure_ascii=False)[:30000],
        "## Tool observations so far",
        "\n\n".join(observations[-16:]) if observations else "(preloaded context only)",
        "Respond with one JSON object (`action` required). "
        "Use tools to read code before your final submission.",
    ])


def _resolve_repo_path(
    user_input: dict,
    cwd: Path | None,
    add_dirs: list[Path] | None,
) -> Path | None:
    for key in ("repo_path",):
        val = user_input.get(key)
        if val:
            return Path(str(val)).resolve()
    if add_dirs:
        for d in add_dirs:
            if d.is_dir():
                return d.resolve()
    if cwd and cwd.is_dir():
        return cwd.resolve()
    return None


def _parse_action_json(text: str) -> dict[str, Any]:
    try:
        return extract_json(text)
    except ValueError:
        return {}


def _merge_usage(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "input_tokens", "output_tokens",
        "cache_read_input_tokens", "cache_creation_input_tokens",
    )
    out = dict(a)
    for k in keys:
        out[k] = int(out.get(k) or 0) + int(b.get(k) or 0)
    return out


def _validate_text(text: str, schema_file: Path) -> list[str]:
    try:
        payload = extract_json(text)
    except ValueError as e:
        return [f"json_extract: {e}"]
    return validate_schema(payload, schema_file)


def _write_artifact(path: Path, obj: Any) -> None:
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(obj, ensure_ascii=False) + "\n")
        fp.flush()


def _raise_mapped_error(exc: Exception, stage: str, name: str) -> None:
    msg = str(exc).lower()
    status_code: int | None = getattr(exc, "status_code", None) or getattr(exc, "http_status", None)
    if status_code is None:
        if "429" in msg or "rate limit" in msg or "quota" in msg:
            status_code = 429
        elif "5" in msg[:10] and ("error" in msg or "unavailable" in msg):
            status_code = 503
    if status_code == 429:
        raise QuotaExhaustedError(
            f"[{stage}/{name}] rate limit / quota exhausted: {exc}"
        ) from exc
    if status_code and 500 <= status_code < 600:
        raise TransientAgentError(
            f"[{stage}/{name}] API error {status_code}: {exc}"
        ) from exc
    raise TransientAgentError(
        f"[{stage}/{name}] unexpected API error: {exc}"
    ) from exc


run_agent_text = run_agent
