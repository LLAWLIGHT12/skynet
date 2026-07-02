"""流污点验证 prompt。"""

FLOW_SYSTEM_PROMPT = """你是代码安全审计助手，专注数据流（source→sink）污点分析。

你将收到：
1. 调用路径上各函数的源码片段
2. 历史流分析记忆（同项目）
3. 外部安全知识

任务：
1. 判断用户可控数据是否可从 source 到达 sink
2. 识别路径上的 sanitizer 及其深度（strong/medium/shallow/none）
3. 给出 verdict：vulnerable | sanitized | inconclusive | unknown
4. 对逻辑/组合类疑点写入 open_questions（供后续组合分析）
5. 若需假设跨模块约束，写入 hypothesis

返回 JSON：
{
  "verdict": "vulnerable|sanitized|inconclusive|unknown",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "reachability": "confirmed|likely|rejected|unknown",
  "sanitizers": [{"qn": "函数名", "depth": "strong|medium|shallow", "note": "说明"}],
  "evidence": {"source_line": null, "sink_line": null, "key_hops": ["描述"]},
  "tags": ["missing_parametrize", "cross_community", "logic_risk"],
  "open_questions": ["未闭合的疑问"],
  "hypothesis": "跨模块/逻辑假设，无则空字符串",
  "summary": "一句话结论",
  "cwe_id": "CWE-XXX 或 null"
}"""


def build_flow_prompt(
    candidate_summary: str,
    path_blocks: str,
    history_block: str,
    knowledge_block: str = "",
    gap_block: str = "",
) -> str:
    parts = [
        "## Flow candidate",
        candidate_summary,
        history_block,
    ]
    if gap_block:
        parts.append(gap_block)
    if knowledge_block:
        parts.append(knowledge_block)
    parts.append("## Path code (source → sink)")
    parts.append(path_blocks)
    parts.append("\n请返回 JSON。")
    return "\n\n".join(parts)


def format_history_block(records: list[dict]) -> str:
    if not records:
        return "## Historical flow memory\n(No prior flow analysis for this path)"
    lines = ["## Historical flow memory (same project)"]
    for r in records:
        lines.append(
            f"- [{r.get('verdict')}] {r.get('path')}: {r.get('summary', '')}"
        )
        if r.get("sanitizers"):
            lines.append(f"  Sanitizers: {r['sanitizers']}")
        if r.get("open_questions"):
            lines.append(f"  Open: {r['open_questions']}")
    return "\n".join(lines)
