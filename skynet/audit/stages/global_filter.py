"""后置误报过滤器 —— 在 validate 之后、dedupe 之前执行全局一致性检查。

- 收集所有 confirmed findings，构造一次 LLM 调用
- 输入：findings JSON + recon summary
- 输出：应剔除的 finding_id 列表（只删"确定误报"）
- 失败时静默跳过（不影响管线）
"""

from __future__ import annotations

import json
import logging
from typing import Any

from skynet.audit.stages._common import StageContext, truncated_recon_summary

log = logging.getLogger(__name__)

# ── Prompt 模板 ─────────────────────────────────────────────────

_GLOBAL_FILTER_SYSTEM = """\
You are a senior security analyst performing a final quality check on \
vulnerability findings from an automated code audit.

Your task: review the list of confirmed findings and identify any that are \
**provably false positives** — i.e., the reported vulnerability clearly does \
not exist based on the evidence provided.

Rules:
- Only reject findings that are DEFINITELY wrong (e.g., the code shown is \
  safe, the vulnerability type is impossible given the context, or the \
  evidence contradicts the claim).
- Do NOT reject findings just because they seem low-severity or uncertain.
- When in doubt, keep the finding.

Return a JSON object with a single key "reject_ids" containing an array of \
finding_id strings that should be removed.
"""

_GLOBAL_FILTER_USER = """\
## Recon Summary
{recon_summary}

## Confirmed Findings ({count})
{findings_json}

Return a JSON object: {{"reject_ids": ["finding_id_1", ...]}}
If no findings should be rejected, return: {{"reject_ids": []}}
"""


async def run_global_filter(
    ctx: StageContext,
    db: Any,  # StateDB — 用 Any 避免循环导入
    llm_client: Any | None = None,
) -> int:
    """对所有 confirmed findings 做全局误报过滤。

    Parameters
    ----------
    ctx : StageContext
        管线上下文。
    db : StateDB
        状态数据库。
    llm_client : optional
        Skynet LLMClient 实例。为 None 时自动创建。

    Returns
    -------
    int
        被剔除的 finding 数量。失败或无 finding 时返回 0。
    """
    confirmed = db.get_findings(ctx.run_id, validation_status="confirmed")
    if not confirmed:
        log.info("[%s] global_filter: no confirmed findings to filter", ctx.run_id)
        return 0

    log.info(
        "[%s] global_filter: filtering %d confirmed findings",
        ctx.run_id, len(confirmed),
    )

    # 构造 findings JSON
    findings_items = []
    for f in confirmed:
        findings_items.append({
            "finding_id": f.finding_id,
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "vuln_class": f.vuln_class,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
        })

    recon_summary = db.get_recon_output(ctx.run_id) or {}
    recon_text = json.dumps(
        truncated_recon_summary(recon_summary), ensure_ascii=False, indent=2,
    )
    findings_json = json.dumps(findings_items, ensure_ascii=False, indent=2)

    user_prompt = _GLOBAL_FILTER_USER.format(
        recon_summary=recon_text,
        count=len(findings_items),
        findings_json=findings_json,
    )

    # 调用 LLM
    try:
        if llm_client is None:
            from skynet.llm.client import LLMClient
            llm_client = LLMClient()

        response_text, _usage = await llm_client.chat_json(
            system_prompt=_GLOBAL_FILTER_SYSTEM,
            user_prompt=user_prompt,
            temperature=0.0,
        )
    except Exception as e:
        log.warning(
            "[%s] global_filter: LLM call failed: %s — skipping filter",
            ctx.run_id, e,
        )
        return 0

    # 解析响应
    reject_ids = _parse_reject_ids(response_text)
    if not reject_ids:
        log.info("[%s] global_filter: LLM returned no rejections", ctx.run_id)
        return 0

    # 验证 reject_ids 确实在 confirmed 列表中
    valid_ids = {f.finding_id for f in confirmed}
    to_reject = reject_ids & valid_ids
    invalid_ids = reject_ids - valid_ids
    if invalid_ids:
        log.debug(
            "[%s] global_filter: ignoring %d unknown IDs: %s",
            ctx.run_id, len(invalid_ids), invalid_ids,
        )

    # 执行剔除：将 validation_status 改为 "rejected_by_filter"
    for fid in to_reject:
        db.set_finding_validation(fid, "rejected_by_filter", {
            "finding_id": fid,
            "verdict": "rejected_by_filter",
            "rationale": "Rejected by global false-positive filter",
            "validator_confidence": 0.0,
        })

    log.info(
        "[%s] global_filter: rejected %d/%d findings as false positives",
        ctx.run_id, len(to_reject), len(confirmed),
    )
    return len(to_reject)


def _parse_reject_ids(response_text: str) -> set[str]:
    """从 LLM 响应中解析 reject_ids 集合。"""
    text = response_text.strip()
    # 去除 markdown 代码块
    if text.startswith("```"):
        nl = text.find("\n")
        if nl >= 0:
            text = text[nl + 1:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # 尝试从文本中提取 JSON 对象
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                log.warning("global_filter: failed to parse LLM response as JSON")
                return set()
        else:
            log.warning("global_filter: no JSON found in LLM response")
            return set()

    ids = data.get("reject_ids", [])
    if not isinstance(ids, list):
        return set()
    return {str(i) for i in ids if isinstance(i, str) and i}
