#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Skynet CLI — 代码图谱构建与 chunk 分析入口。"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from loguru import logger

from skynet.config import load_config, get_config, load_dotenv_if_present
from skynet.graph import GraphBuilder, iter_chunks, get_structural_context
from skynet.state import StateDB


def _setup_logging(verbose: bool) -> None:
    logger.remove()
    level = "DEBUG" if verbose else "INFO"
    logger.add(sys.stderr, level=level, format="{time:HH:mm:ss} | {level} | {message}")


def _resolve_target(path: str) -> Path:
    target = Path(path)
    if not target.is_absolute():
        target = Path.cwd() / target
    return target.resolve()



def _state_db_enabled(args):
    """用户是否启用了 StateDB（指定了 --run-id / --resume / --max-cost）。"""
    if getattr(args, 'run_id', None):
        return True
    if getattr(args, 'resume', False):
        return True
    if getattr(args, 'max_cost', None):
        return True
    return False

def cmd_build(args: argparse.Namespace) -> int:
    target = _resolve_target(args.directory)
    if not target.is_dir():
        logger.error("目标目录不存在: {}", target)
        return 1

    builder = GraphBuilder(target)
    result = builder.build(full_rebuild=args.full)

    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        logger.info("图谱数据库: {}", result.db_path)
        logger.info("构建类型: {}", result.build_type)
        logger.info("文件: {}, 节点: {}, 边: {}", result.files_parsed, result.total_nodes, result.total_edges)
        if result.post_processing:
            logger.info("后处理: {}", result.post_processing)
        if result.errors:
            logger.warning("{} 个文件解析失败", len(result.errors))

    return 0


def cmd_chunks(args: argparse.Namespace) -> int:
    target = _resolve_target(args.directory)
    builder = GraphBuilder(target)

    try:
        store = builder.open_store()
    except FileNotFoundError as e:
        logger.error("{} — 请先运行: python main.py build -d {}", e, args.directory)
        return 1

    with store:
        chunks = list(iter_chunks(store, target, skip_tests=not args.include_tests))
        if args.limit:
            chunks = chunks[: args.limit]

        if args.json:
            payload = [
                {
                    "qualified_name": c.qualified_name,
                    "kind": c.kind,
                    "file": c.file_path,
                    "lines": [c.line_start, c.line_end],
                    "loc": c.loc,
                    "language": c.language,
                }
                for c in chunks
            ]
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            logger.info("共 {} 个可分析 chunk", len(chunks))
            for c in chunks:
                print(f"  [{c.kind}] {c.qualified_name} ({c.loc} lines)")

    return 0


def cmd_preview(args: argparse.Namespace) -> int:
    """预览 chunk + 结构上下文（分析前的 dry-run）。"""
    target = _resolve_target(args.directory)
    builder = GraphBuilder(target)

    try:
        store = builder.open_store()
    except FileNotFoundError as e:
        logger.error("{} — 请先运行 build", e)
        return 1

    with store:
        chunks = list(iter_chunks(store, target))
        if not chunks:
            logger.warning("未找到可分析 chunk")
            return 0

        idx = min(args.index, len(chunks) - 1)
        chunk = chunks[idx]
        ctx = get_structural_context(store, chunk)

        print("=" * 60)
        print(f"Chunk [{idx + 1}/{len(chunks)}]: {chunk.qualified_name}")
        print("=" * 60)
        print(ctx.to_prompt_block())
        print("\n### Source preview (first 40 lines)")
        lines = chunk.source.splitlines()
        preview = "\n".join(lines[:40])
        print(preview)
        if len(lines) > 40:
            print(f"\n... ({len(lines) - 40} more lines)")

    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    target = _resolve_target(args.directory)
    builder = GraphBuilder(target)

    try:
        store = builder.open_store()
    except FileNotFoundError as e:
        logger.error("{}", e)
        return 1

    with store:
        stats = store.get_stats()
        chunk_count = len(
            list(iter_chunks(store, target, skip_tests=True))
        )

    data = {
        "db_path": str(builder.db_path),
        "total_nodes": stats.total_nodes,
        "total_edges": stats.total_edges,
        "nodes_by_kind": stats.nodes_by_kind,
        "edges_by_kind": stats.edges_by_kind,
        "languages": stats.languages,
        "files_count": stats.files_count,
        "analyzable_chunks": chunk_count,
        "last_updated": stats.last_updated,
    }

    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        for k, v in data.items():
            print(f"{k}: {v}")

    return 0


async def _cmd_analyze_async(args: argparse.Namespace) -> int:
    from skynet.analyze import AnalysisRunner

    target = _resolve_target(args.directory)
    cfg = get_config()
    if args.output:
        cfg.analyze.output_dir = args.output
    if args.concurrency:
        cfg.analyze.max_concurrency = args.concurrency

    # ── StateDB 初始化 ──
    state_db: StateDB | None = None
    if _state_db_enabled(args):
        state_db = StateDB.for_repo(target)
        if args.resume and not args.run_id:
            # 自动恢复最近一次运行
            runs = state_db.list_runs(str(target))
            if runs:
                args.run_id = runs[0]["run_id"]
                logger.info("StateDB resume: 恢复最近运行 {}", args.run_id)
            else:
                logger.info("StateDB resume: 无历史运行，开始新运行")

    try:
        runner = AnalysisRunner(target, config=cfg, state_db=state_db)
        summary = await runner.run(
            limit=args.limit,
            offset=args.offset,
            index=args.index,
            save=not args.no_save,
            trace_flows=args.trace_flows,
            composite=args.composite,
            use_priority=not args.full_chunks,
            run_id=args.run_id if state_db else None,
        )
        # StateDB: capture cost before finally closes db
        state_cost = None
        if state_db and summary.run_id:
            state_cost = state_db.total_cost(summary.run_id)
    except FileNotFoundError as e:
        logger.error("{} — 请先运行: python main.py build -d {}", e, args.directory)
        return 1
    except IndexError as e:
        logger.error("{}", e)
        return 1
    except ValueError as e:
        logger.error("{}", e)
        return 1
    finally:
        if state_db:
            state_db.close()

    if args.json:
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
    else:
        logger.info("分析完成: {}/{} chunk", summary.analyzed, summary.total_chunks)
        logger.info("发现问题的 chunk: {}", summary.with_findings)
        logger.info("漏洞条目总数: {}", summary.total_findings)
        if summary.errors:
            logger.warning("失败: {}", summary.errors)
        if summary.output_path:
            logger.info("报告: {}", summary.output_path)
        if summary.flow_trace:
            ft = summary.flow_trace
            logger.info(
                "流追踪: {} 候选, {} 分析, {} 漏洞流",
                ft.get("candidates", 0),
                ft.get("traced", 0),
                ft.get("vulnerable", 0),
            )
            if ft.get("output_path"):
                logger.info("流报告: {}", ft["output_path"])
        # StateDB 成本汇总
        if state_cost is not None and state_cost > 0:
            logger.info("LLM 总成本: ${:.4f}", state_cost)

        for r in summary.results:
            if not r.findings:
                continue
            print(f"\n{r.qualified_name}")
            for f in r.findings:
                print(f"  - [{f.severity}] {f.title} (conf={f.confidence:.2f})")

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from skynet.report import generate_from_reports_dir, generate_html_report
    from skynet.report.scan_report import generate_audit_html_report

    try:
        if args.input:
            # 自动检测 audit report.json
            input_path = Path(args.input)
            if input_path.is_file() and input_path.name == "report.json":
                out = generate_audit_html_report(input_path, args.output)
            else:
                out = generate_html_report(input_path, args.output)
        else:
            out = generate_from_reports_dir(
                reports_dir=args.reports_dir or get_config().analyze.output_dir,
                analysis_file=None,
            )
        logger.info("HTML 报告: {}", out)
    except FileNotFoundError as e:
        logger.error("{}", e)
        return 1
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """桥接到 audit Click CLI —— 深度 8 阶段审计管线。"""
    from skynet.audit.cli import main as audit_main

    # 构建传递给 click CLI 的参数列表（不含程序名）
    audit_args = list(args.audit_args)
    # 只在 run 子命令时注入图谱/组合选项
    is_run = audit_args and audit_args[0] == "run"
    if is_run and args.graph_enhanced:
        audit_args.append("--graph-enhanced")
    if is_run and args.no_composite:
        audit_args.append("--no-composite")

    # 如果没有子命令，显示 help
    if not audit_args:
        audit_args = ["--help"]

    try:
        return audit_main(args=audit_args, prog_name="audit", standalone_mode=False) or 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1


async def _cmd_scan_async(args: argparse.Namespace) -> int:
    from datetime import datetime

    from skynet.analyze import AnalysisRunner
    from skynet.merge.unifier import build_scan_report, save_scan_report

    target = _resolve_target(args.directory)
    cfg = get_config()
    reports_dir = Path(args.output or cfg.analyze.output_dir)
    if not reports_dir.is_absolute():
        reports_dir = Path.cwd() / reports_dir
    cfg.analyze.output_dir = str(reports_dir)

    if not args.skip_build:
        logger.info("构建图谱: {}", target)
        builder = GraphBuilder(target)
        builder.build(full_rebuild=False)

    limit = args.limit_chunks or cfg.scan.limit_chunks
    logger.info("Chunk 分析 (limit={})", limit or "all")
    # ── StateDB 初始化 ──
    state_db: StateDB | None = None
    if _state_db_enabled(args):
        state_db = StateDB.for_repo(target)

    try:
        runner = AnalysisRunner(target, config=cfg, state_db=state_db)
        analysis_summary = await runner.run(
            limit=limit,
            save=True,
            trace_flows=not args.no_trace,
            composite=not args.no_composite,
            use_priority=not args.full_chunks,
            run_id=args.run_id if state_db else None,
        )
        # StateDB: capture cost before finally closes db
        state_cost = None
        if state_db and analysis_summary.run_id:
            state_cost = state_db.total_cost(analysis_summary.run_id)

        analysis_path = analysis_summary.output_path
        flow_data = analysis_summary.flow_trace
        flow_trace_path = None
        if isinstance(flow_data, dict):
            flow_trace_path = flow_data.get("output_path")

        analysis_data = None
        if analysis_path and analysis_path.is_file():
            analysis_data = json.loads(analysis_path.read_text(encoding="utf-8"))

        report = build_scan_report(
            repo_root=str(target),
            analysis=analysis_data,
            flow_trace=flow_data,
            analysis_path=str(analysis_path) if analysis_path else None,
            flow_trace_path=str(flow_trace_path) if flow_trace_path else None,
        )

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = target.name or "project"
        scan_path = reports_dir / f"scan_{name}_{ts}.json"
        save_scan_report(report, scan_path)

        # ── StateDB: 记录扫描产物 ──
        if state_db and args.run_id:
            state_db.add_artifact(
                args.run_id, "scan", None,
                kind="scan_report", path=str(scan_path),
            )
    except FileNotFoundError as e:
        logger.error("{} — 请先运行: python main.py build -d {}", e, args.directory)
        return 1
    finally:
        if state_db:
            state_db.close()

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        logger.info("扫描完成: merged={}", len(report.merged))
        logger.info("  chunk: {}  flow: {}  composite: {}",
                    len(report.chunk_findings), len(report.flow_findings), len(report.composite_findings))
        if analysis_path:
            logger.info("  analysis: {}", analysis_path)
        if flow_trace_path:
            logger.info("  flow_trace: {}", flow_trace_path)
        logger.info("  scan: {}", scan_path)
        if state_cost is not None and state_cost > 0:
            logger.info("  LLM 总成本: ${:.4f}", state_cost)
            if args.max_cost is not None and state_cost > args.max_cost:
                logger.warning("  LLM 成本超过上限: ${:.4f} > ${:.4f}", state_cost, args.max_cost)
        for f in report.merged[:10]:
            print(f"  - [{f.severity}] {f.title} ({','.join(f.sources)})")

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    return asyncio.run(_cmd_scan_async(args))


def cmd_mark_fp(args: argparse.Namespace) -> int:
    from skynet.knowledge.flow_memory import FlowMemoryStore

    target = _resolve_target(args.directory)
    memory = FlowMemoryStore(target)
    reason = args.reason or ""

    if args.flow_id:
        if not memory.mark_flow_false_positive(args.flow_id, reason):
            logger.error("未找到 flow_id: {}", args.flow_id)
            return 1
        logger.info("已标记 flow 误报: {}", args.flow_id)
        return 0

    if args.qualified_name:
        memory.mark_chunk_false_positive(args.qualified_name, reason)
        logger.info("已标记 chunk 误报: {}", args.qualified_name)
        return 0

    logger.error("请指定 --flow-id 或 --qualified-name")
    return 1


def cmd_analyze(args: argparse.Namespace) -> int:
    return asyncio.run(_cmd_analyze_async(args))


async def _cmd_trace_async(args: argparse.Namespace) -> int:
    from skynet.taint import TraceRunner

    target = _resolve_target(args.directory)
    cfg = get_config()
    if args.output:
        cfg.analyze.output_dir = args.output

    # ── StateDB 初始化 ──
    state_db: StateDB | None = None
    if _state_db_enabled(args):
        state_db = StateDB.for_repo(target)

    try:
        runner = TraceRunner(target, config=cfg, state_db=state_db)
        summary = await runner.run(
            run_composite=not args.no_composite,
            save=not args.no_save,
            run_id=args.run_id if state_db else None,
        )
        # StateDB: capture cost before finally closes db
        state_cost = None
        if state_db and summary.run_id:
            state_cost = state_db.total_cost(summary.run_id)
    except FileNotFoundError as e:
        logger.error("{} — 请先运行: python main.py build -d {}", e, args.directory)
        return 1
    finally:
        if state_db:
            state_db.close()

    if args.json:
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
    else:
        logger.info("候选流: {}", summary.candidates)
        logger.info("已分析: {} (缓存跳过 {})", summary.traced, summary.skipped_cached)
        logger.info("漏洞流: {}", summary.vulnerable)
        logger.info("组合发现: {}", len(summary.composite_findings))
        logger.info("Gap 超阈值: {}", summary.high_gap_candidates)
        logger.info("Agent 调用: {}", summary.agent_invoked)
        if summary.output_path:
            logger.info("报告: {}", summary.output_path)
        if state_db and args.run_id:
            total = state_db.total_cost(summary.run_id)
            if total > 0:
                logger.info("LLM 总成本: ${:.4f}", total)

    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    return asyncio.run(_cmd_trace_async(args))


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="skynet",
        description="Skynet — 基于代码知识图谱的安全审计系统",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="配置文件路径（默认 config/skynet.yaml）",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="构建/更新代码知识图谱")
    p_build.add_argument("-d", "--directory", required=True, help="目标项目目录")
    p_build.add_argument("--full", action="store_true", help="强制全量重建")
    p_build.add_argument("--json", action="store_true")
    p_build.set_defaults(func=cmd_build)

    p_chunks = sub.add_parser("chunks", help="列出可分析的代码 chunk")
    p_chunks.add_argument("-d", "--directory", required=True)
    p_chunks.add_argument("--limit", type=int, default=0)
    p_chunks.add_argument("--include-tests", action="store_true")
    p_chunks.add_argument("--json", action="store_true")
    p_chunks.set_defaults(func=cmd_chunks)

    p_preview = sub.add_parser("preview", help="预览单个 chunk 的结构上下文")
    p_preview.add_argument("-d", "--directory", required=True)
    p_preview.add_argument("--index", type=int, default=0, help="chunk 序号（从 0 开始）")
    p_preview.set_defaults(func=cmd_preview)

    p_stats = sub.add_parser("stats", help="图谱统计信息")
    p_stats.add_argument("-d", "--directory", required=True)
    p_stats.add_argument("--json", action="store_true")
    p_stats.set_defaults(func=cmd_stats)

    p_analyze = sub.add_parser("analyze", help="LLM 安全分析（按 chunk）")
    p_analyze.add_argument("-d", "--directory", required=True)
    p_analyze.add_argument("--limit", type=int, default=0, help="最多分析 N 个 chunk")
    p_analyze.add_argument("--offset", type=int, default=0)
    p_analyze.add_argument("--index", type=int, default=None, help="只分析指定序号 chunk")
    p_analyze.add_argument("-o", "--output", type=str, default=None, help="报告输出目录")
    p_analyze.add_argument("-w", "--concurrency", type=int, default=0)
    p_analyze.add_argument("--no-save", action="store_true")
    p_analyze.add_argument("--trace-flows", action="store_true", help="chunk 分析后追踪 sink 流")
    p_analyze.add_argument("--composite", action="store_true", help="流追踪后进行组合漏洞分析")
    p_analyze.add_argument("--full-chunks", action="store_true", help="不按 criticality 排序，使用默认 chunk 顺序")
    p_analyze.add_argument("--json", action="store_true")
    p_analyze.add_argument("--run-id", type=str, default=None, help="指定 run_id（启用 StateDB 持久化）")
    p_analyze.add_argument("--resume", action="store_true", help="从上次中断恢复（需要 --run-id 或自动检测）")
    p_analyze.add_argument("--max-cost", type=float, default=None, help="LLM 调用成本上限 (USD)")
    p_analyze.set_defaults(func=cmd_analyze)

    p_trace = sub.add_parser("trace", help="污点流追踪（source→sink + Flow Memory）")
    p_trace.add_argument("-d", "--directory", required=True)
    p_trace.add_argument("-o", "--output", type=str, default=None)
    p_trace.add_argument("--no-composite", action="store_true", help="跳过组合漏洞分析")
    p_trace.add_argument("--no-save", action="store_true")
    p_trace.add_argument("--json", action="store_true")
    p_trace.add_argument("--run-id", type=str, default=None, help="指定 run_id（启用 StateDB 持久化）")
    p_trace.add_argument("--resume", action="store_true", help="从上次中断恢复")
    p_trace.set_defaults(func=cmd_trace)

    p_scan = sub.add_parser("scan", help="一键扫描：build → analyze → trace → merge")
    p_scan.add_argument("-d", "--directory", required=True)
    p_scan.add_argument("-o", "--output", type=str, default=None, help="报告输出目录")
    p_scan.add_argument("--limit-chunks", type=int, default=0, help="最多分析 N 个 chunk")
    p_scan.add_argument("--skip-build", action="store_true", help="跳过图谱构建")
    p_scan.add_argument("--no-trace", action="store_true", help="跳过污点流追踪")
    p_scan.add_argument("--no-composite", action="store_true", help="跳过组合漏洞分析")
    p_scan.add_argument("--full-chunks", action="store_true", help="不按 criticality 排序 chunk")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--run-id", type=str, default=None, help="指定 run_id（启用 StateDB 持久化）")
    p_scan.add_argument("--resume", action="store_true", help="从上次中断恢复")
    p_scan.add_argument("--max-cost", type=float, default=None, help="LLM 调用成本上限 (USD)")
    p_scan.set_defaults(func=cmd_scan)

    p_mark_fp = sub.add_parser("mark-fp", help="标记误报（写入 project.json）")
    p_mark_fp.add_argument("-d", "--directory", required=True)
    p_mark_fp.add_argument("--flow-id", type=str, default=None)
    p_mark_fp.add_argument("--qualified-name", type=str, default=None)
    p_mark_fp.add_argument("--reason", type=str, default="")
    p_mark_fp.set_defaults(func=cmd_mark_fp)

    p_report = sub.add_parser("report", help="从分析/扫描 JSON 生成 HTML 报告")
    p_report.add_argument("-i", "--input", type=str, default=None, help="analysis_*.json 或 scan_*.json 路径")
    p_report.add_argument("-o", "--output", type=str, default=None)
    p_report.add_argument("--reports-dir", type=str, default=None)
    p_report.set_defaults(func=cmd_report)

    p_audit = sub.add_parser("audit", help="深度审计: 8-stage LLM 管线 (Recon→Hunt→Validate→Gapfill→Dedupe→Composite→Trace→Feedback→Report)")
    p_audit.add_argument("audit_args", nargs=argparse.REMAINDER, help="传递给 audit 管线的参数 (--help 查看子命令)")
    p_audit.add_argument("--graph-enhanced", action="store_true", default=True, dest="graph_enhanced",
                         help="启用 skynet 图谱增强 (默认开启)")
    p_audit.add_argument("--no-graph-enhanced", action="store_false", dest="graph_enhanced",
                         help="禁用 skynet 图谱增强")
    p_audit.add_argument("--no-composite", action="store_true", help="跳过组合漏洞分析阶段")
    p_audit.set_defaults(func=cmd_audit)

    args = parser.parse_args()
    _setup_logging(args.verbose)

    load_dotenv_if_present()

    config_path = args.config
    if config_path is None:
        default_cfg = Path(__file__).parent / "config" / "skynet.yaml"
        if default_cfg.exists():
            config_path = str(default_cfg)
    if config_path:
        load_config(config_path)
        logger.debug("已加载配置: {}", config_path)

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
