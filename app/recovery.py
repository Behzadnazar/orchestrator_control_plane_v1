from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import db
from .config import DB_PATH


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def cmd_event_replay(args: argparse.Namespace) -> None:
    db.init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rows = cur.execute("""
        SELECT entity_id, event_type, created_at, data_json
        FROM events
        WHERE entity_type='task'
        ORDER BY created_at ASC
    """).fetchall()

    grouped: dict[str, list[dict]] = {}
    for r in rows:
        grouped.setdefault(r["entity_id"], []).append({
            "event_type": r["event_type"],
            "created_at": r["created_at"],
            "data": json.loads(r["data_json"]),
        })

    if args.task_id:
        grouped = {k: v for k, v in grouped.items() if k == args.task_id}

    print(json.dumps(grouped, ensure_ascii=False, indent=2))
    conn.close()


def cmd_find_stale(args: argparse.Namespace) -> None:
    db.init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rows = cur.execute("""
        SELECT task_id, title, status, assigned_agent_id, updated_at
        FROM tasks
        WHERE status IN ('Assigned', 'Executing', 'Review', 'Idle')
        ORDER BY updated_at ASC
    """).fetchall()

    now = datetime.now(timezone.utc)
    stale = []
    for r in rows:
        updated = _parse_ts(r["updated_at"])
        age_sec = (now - updated).total_seconds()
        if age_sec >= args.min_age_seconds:
            stale.append({
                "task_id": r["task_id"],
                "title": r["title"],
                "status": r["status"],
                "assigned_agent_id": r["assigned_agent_id"],
                "updated_at": r["updated_at"],
                "age_seconds": int(age_sec),
            })

    print(json.dumps(stale, ensure_ascii=False, indent=2))
    conn.close()


def cmd_recover_idle(args: argparse.Namespace) -> None:
    db.init_db()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        UPDATE tasks
        SET status='Failed',
            last_error=COALESCE(last_error, 'recovered by admin'),
            updated_at=?
        WHERE status IN ('Assigned', 'Executing', 'Review')
    """, (datetime.now(timezone.utc).isoformat(),))
    changed = cur.rowcount
    conn.commit()
    conn.close()
    print(f"RECOVERED_TASKS={changed}")


def cmd_heartbeats(_: argparse.Namespace) -> None:
    db.init_db()
    print(json.dumps(db.list_heartbeats(), ensure_ascii=False, indent=2))


def cmd_find_stale_workers(args: argparse.Namespace) -> None:
    db.init_db()
    now = datetime.now(timezone.utc)
    stale = []

    for hb in db.list_heartbeats():
        seen = _parse_ts(hb["last_seen"])
        age_sec = (now - seen).total_seconds()
        if hb["status"] != "stopped" and age_sec >= args.timeout_seconds:
            stale.append({
                **hb,
                "age_seconds": int(age_sec),
                "stale": True,
            })

    print(json.dumps(stale, ensure_ascii=False, indent=2))


def cmd_recover_stale_workers(args: argparse.Namespace) -> None:
    db.init_db()
    now = datetime.now(timezone.utc)
    stale_workers = []

    for hb in db.list_heartbeats():
        seen = _parse_ts(hb["last_seen"])
        age_sec = (now - seen).total_seconds()
        if hb["status"] != "stopped" and age_sec >= args.timeout_seconds:
            stale_workers.append(hb["worker_id"])

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    task_changed = 0
    if stale_workers:
        cur.execute("""
            UPDATE tasks
            SET status='Failed',
                last_error=CASE
                    WHEN last_error IS NULL OR last_error=''
                    THEN 'recovered بسبب stale worker'
                    ELSE last_error
                END,
                updated_at=?
            WHERE status IN ('Assigned', 'Executing', 'Review')
        """, (datetime.now(timezone.utc).isoformat(),))
        task_changed = cur.rowcount

        for worker_id in stale_workers:
            cur.execute("""
                UPDATE heartbeats
                SET status='stale',
                    details_json=?
                WHERE worker_id=?
            """, (json.dumps({"recovered": True}, ensure_ascii=False), worker_id))

    conn.commit()
    conn.close()

    print(json.dumps({
        "stale_workers": stale_workers,
        "recovered_tasks": task_changed,
    }, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Recovery tools")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("event-replay")
    s.add_argument("--task-id", default=None)
    s.set_defaults(func=cmd_event_replay)

    s = sub.add_parser("find-stale")
    s.add_argument("--min-age-seconds", type=int, default=60)
    s.set_defaults(func=cmd_find_stale)

    s = sub.add_parser("recover-idle")
    s.set_defaults(func=cmd_recover_idle)

    s = sub.add_parser("heartbeats")
    s.set_defaults(func=cmd_heartbeats)

    s = sub.add_parser("find-stale-workers")
    s.add_argument("--timeout-seconds", type=int, default=10)
    s.set_defaults(func=cmd_find_stale_workers)

    s = sub.add_parser("recover-stale-workers")
    s.add_argument("--timeout-seconds", type=int, default=10)
    s.set_defaults(func=cmd_recover_stale_workers)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
