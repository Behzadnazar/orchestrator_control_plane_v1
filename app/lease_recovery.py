from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone

from .config import DB_PATH


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def cmd_list(_: argparse.Namespace) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT lease_id, worker_id, task_id, status, acquired_at, expires_at, details_json
        FROM worker_leases
        ORDER BY acquired_at DESC
    """).fetchall()
    print(json.dumps([
        {
            "lease_id": r["lease_id"],
            "worker_id": r["worker_id"],
            "task_id": r["task_id"],
            "status": r["status"],
            "acquired_at": r["acquired_at"],
            "expires_at": r["expires_at"],
            "details": json.loads(r["details_json"]),
        }
        for r in rows
    ], ensure_ascii=False, indent=2))
    conn.close()


def cmd_find_stale(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT lease_id, worker_id, task_id, status, acquired_at, expires_at, details_json
        FROM worker_leases
        WHERE status='active'
        ORDER BY acquired_at DESC
    """).fetchall()

    now = datetime.now(timezone.utc)
    stale = []
    for r in rows:
        expires = _parse_ts(r["expires_at"])
        if now >= expires:
            stale.append({
                "lease_id": r["lease_id"],
                "worker_id": r["worker_id"],
                "task_id": r["task_id"],
                "status": r["status"],
                "acquired_at": r["acquired_at"],
                "expires_at": r["expires_at"],
                "details": json.loads(r["details_json"]),
                "stale": True,
            })

    print(json.dumps(stale, ensure_ascii=False, indent=2))
    conn.close()


def cmd_recover(args: argparse.Namespace) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rows = cur.execute("""
        SELECT lease_id, worker_id, task_id, status, acquired_at, expires_at
        FROM worker_leases
        WHERE status='active'
    """).fetchall()

    now = datetime.now(timezone.utc)
    stale_task_ids = []
    stale_lease_ids = []

    for r in rows:
        expires = _parse_ts(r["expires_at"])
        if now >= expires:
            stale_task_ids.append(r["task_id"])
            stale_lease_ids.append(r["lease_id"])

    recovered_tasks = 0
    if stale_task_ids:
        q_marks = ",".join("?" for _ in stale_task_ids)
        cur.execute(
            f"""
            UPDATE tasks
            SET status='Failed',
                last_error=CASE
                    WHEN last_error IS NULL OR last_error=''
                    THEN 'recovered بسبب stale lease'
                    ELSE last_error
                END,
                updated_at=?
            WHERE task_id IN ({q_marks}) AND status IN ('Assigned', 'Executing', 'Review')
            """,
            [datetime.now(timezone.utc).isoformat(), *stale_task_ids],
        )
        recovered_tasks = cur.rowcount

        q2 = ",".join("?" for _ in stale_lease_ids)
        cur.execute(
            f"""
            UPDATE worker_leases
            SET status='stale'
            WHERE lease_id IN ({q2})
            """,
            stale_lease_ids,
        )

    conn.commit()
    conn.close()

    print(json.dumps({
        "stale_task_ids": stale_task_ids,
        "recovered_tasks": recovered_tasks,
    }, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Lease recovery")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("list")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("find-stale")
    s.set_defaults(func=cmd_find_stale)

    s = sub.add_parser("recover")
    s.set_defaults(func=cmd_recover)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
