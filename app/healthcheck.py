from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app import db

def main() -> None:
    db.init_db()

    db_path = Path("data/orchestrator.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    total_agents = cur.execute("SELECT COUNT(*) AS c FROM agents").fetchone()["c"]
    idle_agents = cur.execute("SELECT COUNT(*) AS c FROM agents WHERE status='Idle'").fetchone()["c"]

    total_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks").fetchone()["c"]
    completed_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Completed'").fetchone()["c"]
    failed_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Failed'").fetchone()["c"]
    idle_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Idle'").fetchone()["c"]
    review_tasks = cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Review'").fetchone()["c"]

    total_events = cur.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]

    last_task = cur.execute("""
        SELECT task_id, title, status, priority, created_at, updated_at
        FROM tasks
        ORDER BY updated_at DESC
        LIMIT 1
    """).fetchone()

    report = {
        "service": "orchestrator_control_plane_v1",
        "db_exists": db_path.exists(),
        "db_path": str(db_path),
        "agents": {
            "total": total_agents,
            "idle": idle_agents,
        },
        "tasks": {
            "total": total_tasks,
            "completed": completed_tasks,
            "failed": failed_tasks,
            "idle": idle_tasks,
            "review": review_tasks,
        },
        "events": {
            "total": total_events,
        },
        "last_task": dict(last_task) if last_task else None,
        "status": "healthy" if db_path.exists() and total_agents > 0 else "unhealthy",
    }

    print(json.dumps(report, ensure_ascii=False, indent=2))
    conn.close()

if __name__ == "__main__":
    main()
