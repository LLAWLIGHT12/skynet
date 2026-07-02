"""SQLite-backed run state. JSONL artifacts in results/ are the source of
truth for raw agent output; this DB is the queryable index used for
orchestration, resume, and reporting."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS recon_outputs (
    run_id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    source TEXT NOT NULL,
    attack_class TEXT NOT NULL,
    scope_hint TEXT NOT NULL,
    target_files TEXT NOT NULL,
    rationale TEXT,
    priority INTEGER NOT NULL DEFAULT 3,
    chunk_qn TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    raw_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    finding_type TEXT NOT NULL DEFAULT 'chunk',
    file TEXT NOT NULL,
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    vuln_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    poc_succeeded INTEGER DEFAULT 0,
    confidence REAL,
    raw_json TEXT NOT NULL,
    validation_status TEXT,
    validation_json TEXT,
    group_id TEXT,
    is_canonical INTEGER DEFAULT 0,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id)
);

CREATE TABLE IF NOT EXISTS traces (
    finding_id TEXT NOT NULL,
    flow_id TEXT NOT NULL DEFAULT '',
    reachable INTEGER NOT NULL,
    confidence REAL,
    rationale TEXT NOT NULL DEFAULT '',
    raw_json TEXT NOT NULL,
    PRIMARY KEY (finding_id, flow_id),
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS dedupe_groups (
    group_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    canonical_finding_id TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS costs (
    cost_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ref_id TEXT,
    usd REAL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_creation_tokens INTEGER,
    num_turns INTEGER,
    duration_ms INTEGER,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    ref_id TEXT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tasks_run_status ON tasks(run_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_run_chunk  ON tasks(run_id, chunk_qn);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_validation ON findings(validation_status);
CREATE INDEX IF NOT EXISTS idx_findings_group ON findings(group_id);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_costs_run_stage ON costs(run_id, stage);
"""


@dataclass
class Task:
    task_id: str
    run_id: str
    source: str
    attack_class: str
    scope_hint: str
    target_files: list[str]
    rationale: str
    priority: int
    status: str
    raw_json: dict


@dataclass
class Finding:
    finding_id: str
    task_id: str
    run_id: str
    finding_type: str = "chunk"
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    vuln_class: str = ""
    severity: str = ""
    title: str = ""
    description: str = ""
    evidence: str = ""
    poc_succeeded: bool = False
    confidence: float | None = None
    raw_json: dict | None = None
    validation_status: str | None = None
    validation_json: dict | None = None
    group_id: str | None = None
    is_canonical: bool = False


class StateDB:
    """运行状态持久化引擎。

    支持两种构造方式::

        # 直接指定 db 路径（audit 管线）
        db = StateDB(Path("state.db"))

        # 基于 repo_root 自动创建（skynet 风格）
        db = StateDB.for_repo(Path("/path/to/repo"))

    并发安全：使用 threading.Lock 保护所有写操作，
    确保在 asyncio.gather 等并发场景下 SQLite 连接安全。
    """

    def __init__(self, db_path: Path | str):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    @classmethod
    def for_repo(cls, repo_root: str | Path, db_name: str = "state.db",
                 graph_dir: str = ".skynet") -> "StateDB":
        """基于 repo_root 创建 StateDB（skynet 风格）。"""
        root = Path(repo_root).resolve()
        db_path = root / graph_dir / db_name
        return cls(db_path)

    # ---------- runs ----------

    def create_run(self, repo_path: str, run_id: str | None = None) -> str:
        run_id = run_id or f"run_{uuid.uuid4().hex[:8]}"
        with self._lock:
            self._conn.execute(
                "INSERT INTO runs (run_id, repo_path, started_at, status) VALUES (?, ?, ?, ?)",
                (run_id, repo_path, time.time(), "running"),
            )
            self._conn.commit()
        return run_id

    def finish_run(self, run_id: str, status: str = "completed") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runs SET status = ?, finished_at = ? WHERE run_id = ?",
                (status, time.time(), run_id),
            )
            self._conn.commit()

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    def list_runs(self, repo_path: str | None = None) -> list[sqlite3.Row]:
        if repo_path:
            return list(
                self._conn.execute(
                    "SELECT * FROM runs WHERE repo_path = ? ORDER BY started_at DESC",
                    (repo_path,),
                ).fetchall()
            )
        return list(
            self._conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC"
            ).fetchall()
        )

    def run_exists(self, run_id: str) -> bool:
        return self.get_run(run_id) is not None

    # ---------- recon ----------

    def save_recon_output(self, run_id: str, payload: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO recon_outputs (run_id, raw_json) VALUES (?, ?)",
                (run_id, json.dumps(payload)),
            )
            self._conn.commit()

    def get_recon_output(self, run_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM recon_outputs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    # ---------- tasks ----------

    def add_task(self, run_id: str, task: dict) -> str:
        task_id = task["task_id"]
        now = time.time()
        with self._lock:
            self._conn.execute(
                """INSERT OR IGNORE INTO tasks
                (task_id, run_id, source, attack_class, scope_hint, target_files,
                 rationale, priority, chunk_qn, status, raw_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)""",
                (
                    task_id,
                    run_id,
                    task.get("source", "recon"),
                    task["attack_class"],
                    task["scope_hint"],
                    json.dumps(task["target_files"]),
                    task.get("rationale", ""),
                    int(task.get("priority", 3)),
                    task.get("chunk_qn"),
                    json.dumps(task),
                    now,
                    now,
                ),
            )
            self._conn.commit()
        return task_id

    def get_pending_tasks(self, run_id: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? AND status = 'pending' ORDER BY priority, created_at",
            (run_id,),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def get_all_tasks(self, run_id: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? ORDER BY created_at",
            (run_id,),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def update_task_status(self, task_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE task_id = ?",
                (status, time.time(), task_id),
            )
            self._conn.commit()

    def reset_incomplete_tasks(self, run_id: str) -> int:
        """Flip 'running' and 'failed' tasks back to 'pending' so a resumed
        run re-attempts work that was interrupted (quota/crash, left
        'running') or that failed on a transient/quota error (marked
        'failed'). Returns the number of tasks reset."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE tasks SET status = 'pending', updated_at = ? "
                "WHERE run_id = ? AND status IN ('running', 'failed')",
                (time.time(), run_id),
            )
            self._conn.commit()
        return cur.rowcount

    def get_completed_chunks(self, run_id: str) -> set[str]:
        """返回已完成分析的 chunk_qn 集合（用于 skynet resume 跳过）。"""
        rows = self._conn.execute(
            "SELECT chunk_qn FROM tasks WHERE run_id = ? AND status = 'done' AND chunk_qn IS NOT NULL",
            (run_id,),
        ).fetchall()
        return {r["chunk_qn"] for r in rows}

    def get_tasks_by_stage(self, run_id: str, stage: str) -> list[Task]:
        rows = self._conn.execute(
            "SELECT * FROM tasks WHERE run_id = ? AND source = ? ORDER BY created_at",
            (run_id, stage),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    @staticmethod
    def _row_to_task(r: sqlite3.Row) -> Task:
        return Task(
            task_id=r["task_id"],
            run_id=r["run_id"],
            source=r["source"],
            attack_class=r["attack_class"],
            scope_hint=r["scope_hint"],
            target_files=json.loads(r["target_files"]),
            rationale=r["rationale"] or "",
            priority=r["priority"],
            status=r["status"],
            raw_json=json.loads(r["raw_json"]),
        )

    # ---------- findings ----------

    def add_finding(self, run_id: str, task_id: str, finding: dict,
                    finding_type: str = "chunk") -> str:
        """新增安全发现。返回 finding_id。"""
        fid = finding.get("finding_id") or f"find_{uuid.uuid4().hex[:8]}"
        poc = finding.get("poc") or {}
        with self._lock:
            self._conn.execute(
                """INSERT OR IGNORE INTO findings
                (finding_id, task_id, run_id, finding_type, file, line_start, line_end,
                 vuln_class, severity, title, description, evidence, poc_succeeded,
                 confidence, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fid,
                    task_id,
                    run_id,
                    finding_type,
                    finding.get("file", ""),
                    finding.get("line_start", 0),
                    finding.get("line_end", 0),
                    finding.get("vuln_class", finding.get("vulnerability_type", "")),
                    finding.get("severity", ""),
                    finding.get("title", ""),
                    finding.get("description", ""),
                    finding.get("evidence", finding.get("evidence_snippet", "")),
                    1 if poc.get("succeeded") else 0,
                    finding.get("confidence"),
                    json.dumps(finding),
                ),
            )
            self._conn.commit()
        return fid

    def get_findings(self, run_id: str, *, validation_status: str | None = None,
                     canonical_only: bool = False,
                     finding_type: str | None = None) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE run_id = ?"
        args: list[Any] = [run_id]
        if validation_status is not None:
            sql += " AND validation_status = ?"
            args.append(validation_status)
        if canonical_only:
            sql += " AND is_canonical = 1"
        if finding_type is not None:
            sql += " AND finding_type = ?"
            args.append(finding_type)
        sql += " ORDER BY severity DESC"
        rows = self._conn.execute(sql, args).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_unvalidated_findings(self, run_id: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id = ? AND validation_status IS NULL",
            (run_id,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def set_finding_validation(self, finding_id: str, status: str, payload: dict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET validation_status = ?, validation_json = ? WHERE finding_id = ?",
                (status, json.dumps(payload), finding_id),
            )
            self._conn.commit()

    def update_finding_location(self, finding_id: str, line_start: int, line_end: int) -> None:
        """更新 finding 的行号（由 location_resolver 修正后调用）。"""
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET line_start = ?, line_end = ? WHERE finding_id = ?",
                (line_start, line_end, finding_id),
            )
            self._conn.commit()

    def assign_finding_group(
        self, finding_id: str, group_id: str, is_canonical: bool
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE findings SET group_id = ?, is_canonical = ? WHERE finding_id = ?",
                (group_id, 1 if is_canonical else 0, finding_id),
            )
            self._conn.commit()

    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        return Finding(
            finding_id=r["finding_id"],
            task_id=r["task_id"],
            run_id=r["run_id"],
            finding_type=r["finding_type"] if "finding_type" in r.keys() else "chunk",
            file=r["file"],
            line_start=r["line_start"],
            line_end=r["line_end"],
            vuln_class=r["vuln_class"],
            severity=r["severity"],
            title=r["title"] if "title" in r.keys() else "",
            description=r["description"],
            evidence=r["evidence"],
            poc_succeeded=bool(r["poc_succeeded"]),
            confidence=r["confidence"],
            raw_json=json.loads(r["raw_json"]),
            validation_status=r["validation_status"],
            validation_json=json.loads(r["validation_json"]) if r["validation_json"] else None,
            group_id=r["group_id"],
            is_canonical=bool(r["is_canonical"]),
        )

    # ---------- traces ----------

    def add_trace(self, finding_id: str, payload: dict, flow_id: str = "") -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO traces
                (finding_id, flow_id, reachable, confidence, rationale, raw_json)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    flow_id or payload.get("flow_id", ""),
                    1 if payload.get("reachable") else 0,
                    payload.get("confidence"),
                    payload.get("rationale", ""),
                    json.dumps(payload),
                ),
            )
            self._conn.commit()

    def get_trace(self, finding_id: str, flow_id: str = "") -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM traces WHERE finding_id = ? AND flow_id = ?",
            (finding_id, flow_id),
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    def get_traces(self, finding_id: str) -> list[dict]:
        """返回某 finding 的所有 trace（多 flow）。"""
        rows = self._conn.execute(
            "SELECT raw_json FROM traces WHERE finding_id = ?", (finding_id,),
        ).fetchall()
        return [json.loads(r["raw_json"]) for r in rows]

    def get_reachable_canonical_findings(self, run_id: str) -> list[tuple[Finding, dict]]:
        out: list[tuple[Finding, dict]] = []
        for f in self.get_findings(run_id, validation_status="confirmed", canonical_only=True):
            tr = self.get_trace(f.finding_id)
            if tr and tr.get("reachable"):
                out.append((f, tr))
        return out

    # ---------- dedupe ----------

    def add_dedupe_group(self, run_id: str, group: dict) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO dedupe_groups
                (group_id, run_id, root_cause, canonical_finding_id, raw_json)
                VALUES (?, ?, ?, ?, ?)""",
                (
                    group["group_id"],
                    run_id,
                    group["root_cause"],
                    group["canonical_finding_id"],
                    json.dumps(group),
                ),
            )
            self._conn.commit()

    # ---------- costs ----------

    def record_cost(
        self,
        run_id: str,
        stage: str,
        ref_id: str | None,
        result_msg: dict | None = None,
        *,
        usage: dict[str, Any] | None = None,
        usd: float | None = None,
        num_turns: int | None = None,
        duration_ms: int | None = None,
    ) -> None:
        """记录单次 LLM 调用的成本。

        支持两种调用模式::

            # audit 管线模式：传入 result_msg dict
            db.record_cost(run_id, "hunt", task_id, result_msg)

            # skynet 直接模式：传入 keyword args
            db.record_cost(run_id, "analyze", chunk_qn, usage={...}, num_turns=1)
        """
        if result_msg is not None:
            u = result_msg.get("usage") or {}
            _usd = result_msg.get("total_cost_usd")
            _input = u.get("input_tokens")
            _output = u.get("output_tokens")
            _cache_read = u.get("cache_read_input_tokens")
            _cache_create = u.get("cache_creation_input_tokens")
            _turns = result_msg.get("num_turns")
            _dur = result_msg.get("duration_ms")
        else:
            u = usage or {}
            _usd = usd
            _input = u.get("input_tokens")
            _output = u.get("output_tokens")
            _cache_read = u.get("cache_read_input_tokens")
            _cache_create = u.get("cache_creation_input_tokens")
            _turns = num_turns
            _dur = duration_ms

        with self._lock:
            self._conn.execute(
                """INSERT INTO costs
                (run_id, stage, ref_id, usd, input_tokens, output_tokens,
                 cache_read_tokens, cache_creation_tokens, num_turns, duration_ms, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id, stage, ref_id,
                    _usd, _input, _output,
                    _cache_read, _cache_create,
                    _turns, _dur,
                    time.time(),
                ),
            )
            self._conn.commit()

    def total_cost(self, run_id: str) -> float:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(usd), 0) AS total FROM costs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return float(row["total"]) if row else 0.0

    def get_costs(self, run_id: str, stage: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM costs WHERE run_id = ?"
        params: list[Any] = [run_id]
        if stage:
            sql += " AND stage = ?"
            params.append(stage)
        return list(self._conn.execute(sql, params).fetchall())

    # ---------- artifacts ----------

    def add_artifact(
        self, run_id: str, stage: str, ref_id: str | None, kind: str, path: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO artifacts
                (run_id, stage, ref_id, kind, path, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (run_id, stage, ref_id, kind, path, time.time()),
            )
            self._conn.commit()

    def get_artifacts(self, run_id: str, kind: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM artifacts WHERE run_id = ?"
        params: list[Any] = [run_id]
        if kind:
            sql += " AND kind = ?"
            params.append(kind)
        return list(self._conn.execute(sql, params).fetchall())

    # ---------- context manager ----------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "StateDB":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


@contextmanager
def open_db(path: Path | str | None = None, *, repo_root: str | Path | None = None,
           db_name: str = "state.db", graph_dir: str = ".skynet") -> Iterator[StateDB]:
    if repo_root is not None:
        db = StateDB.for_repo(repo_root, db_name=db_name, graph_dir=graph_dir)
    elif path is not None:
        db = StateDB(path)
    else:
        raise ValueError("必须提供 path 或 repo_root 参数")
    try:
        yield db
    finally:
        db.close()
