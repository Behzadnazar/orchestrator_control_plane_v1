from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from .config import DB_PATH
from .integrity import run_integrity_checks


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_recover_before_boot() -> dict:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        UPDATE tasks
        SET status='Failed',
            last_error=CASE
                WHEN last_error IS NULL OR last_error=''
                THEN 'boot recovery: task left in non-terminal state'
                ELSE last_error
            END,
            updated_at=?
        WHERE status IN ('Assigned', 'Executing', 'Review')
    """, (utc_now(),))
    recovered_tasks = cur.rowcount

    cur.execute("""
        UPDATE heartbeats
        SET status='stale',
            details_json='{"boot_recovered": true}'
        WHERE status NOT IN ('stopped', 'stale')
    """)
    recovered_workers = cur.rowcount

    conn.commit()
    conn.close()

    return {
        "recovered_tasks": recovered_tasks,
        "recovered_workers": recovered_workers,
    }


def main() -> None:
    integrity = run_integrity_checks()
    if integrity["status"] != "healthy":
        print(json.dumps({
            "boot_ok": False,
            "phase": "integrity",
            "integrity": integrity,
        }, ensure_ascii=False, indent=2))
        raise SystemExit(1)

    recovery = safe_recover_before_boot()

    print(json.dumps({
        "boot_ok": True,
        "phase": "boot_complete",
        "integrity": integrity,
        "recovery": recovery,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
