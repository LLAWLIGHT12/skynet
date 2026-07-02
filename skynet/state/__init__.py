"""Skynet StateDB — 运行状态持久化。

用法::

    from skynet.state import StateDB, open_db

    db = StateDB.for_repo(repo_root)
    run_id = db.create_run(str(repo_root))
    db.add_finding(run_id, task_id, {...})
    db.finish_run(run_id)
    db.close()
"""

from skynet.audit.state import StateDB, open_db, Task, Finding

__all__ = [
    "StateDB",
    "open_db",
    "Task",
    "Finding",
]
