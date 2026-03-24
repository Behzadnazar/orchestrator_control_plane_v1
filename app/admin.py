from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

from . import db


def cmd_stats(_: argparse.Namespace) -> None:
    db.init_db()
    db_path = Path("data/orchestrator.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    report = {
        "agents_total": cur.execute("SELECT COUNT(*) AS c FROM agents").fetchone()["c"],
        "tasks_total": cur.execute("SELECT COUNT(*) AS c FROM tasks").fetchone()["c"],
        "tasks_completed": cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Completed'").fetchone()["c"],
        "tasks_failed": cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Failed'").fetchone()["c"],
        "tasks_idle": cur.execute("SELECT COUNT(*) AS c FROM tasks WHERE status='Idle'").fetchone()["c"],
        "events_total": cur.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"],
        "approvals_total": cur.execute("SELECT COUNT(*) AS c FROM approvals").fetchone()["c"],
        "locks_total": cur.execute("SELECT COUNT(*) AS c FROM file_locks").fetchone()["c"],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    conn.close()


def cmd_list_locks(_: argparse.Namespace) -> None:
    db.init_db()
    db_path = Path("data/orchestrator.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT file_path, owner_task_id, owner_agent_id, created_at
        FROM file_locks
        ORDER BY created_at DESC
    """).fetchall()
    print(json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=2))
    conn.close()


def cmd_clear_locks(_: argparse.Namespace) -> None:
    db.init_db()
    db_path = Path("data/orchestrator.db")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM file_locks")
    print(f"CLEARED_LOCKS={cur.rowcount}")
    conn.commit()
    conn.close()


def cmd_list_failed(_: argparse.Namespace) -> None:
    db.init_db()
    db_path = Path("data/orchestrator.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT task_id, title, task_type, priority, last_error, updated_at
        FROM tasks
        WHERE status='Failed'
        ORDER BY updated_at DESC
    """).fetchall()
    print(json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=2))
    conn.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Admin CLI")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("stats")
    s.set_defaults(func=cmd_stats)

    s = sub.add_parser("list-locks")
    s.set_defaults(func=cmd_list_locks)

    s = sub.add_parser("clear-locks")
    s.set_defaults(func=cmd_clear_locks)

    s = sub.add_parser("list-failed")
    s.set_defaults(func=cmd_list_failed)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
