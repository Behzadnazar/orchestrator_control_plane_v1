from __future__ import annotations

import json
import sqlite3

from .config import DB_PATH
from . import db


def refresh_metrics() -> dict:
    db.init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    metrics = {
        "agents_total": cur.execute("SELECT COUNT(*) AS c FROM agents").fetchone()["c"],
        "tasks_total": cur.execute("SELECT COUNT(*) AS c FROM tasks").fetchone()["c"],
        "tasks_completed": cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Completed'").fetchone()["c"],
        "tasks_failed": cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Failed'").fetchone()["c"],
        "tasks_idle": cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Idle'").fetchone()["c"],
        "tasks_review": cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Review'").fetchone()["c"],
        "events_total": cur.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"],
        "heartbeats_total": cur.execute("SELECT COUNT(*) AS c FROM heartbeats").fetchone()["c"],
        "leases_total": cur.execute("SELECT COUNT(*) AS c FROM worker_leases").fetchone()["c"],
        "leases_active": cur.execute("SELECT COUNT(*) AS c FROM worker_leases WHERE status='active'").fetchone()["c"],
    }
    conn.close()

    for k, v in metrics.items():
        db.upsert_metric(k, float(v))

    return metrics


def main() -> None:
    print(json.dumps(refresh_metrics(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
