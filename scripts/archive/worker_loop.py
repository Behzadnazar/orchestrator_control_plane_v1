import sqlite3
import time
from pathlib import Path

DB_PATH = Path("orchestrator.db")
WORKER_ID = "backend-worker-v2"

def now_expr():
    return "datetime('now')"

def ensure_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS task_queue (
        queue_item_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL UNIQUE,
        task_type TEXT NOT NULL,
        priority INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'queued',
        payload TEXT,
        claimed_by_worker TEXT,
        claimed_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)
    conn.commit()

def claim_one(conn):
    row = conn.execute("""
    UPDATE task_queue
    SET status='claimed',
        claimed_by_worker=?,
        claimed_at=datetime('now'),
        updated_at=datetime('now')
    WHERE queue_item_id = (
        SELECT queue_item_id
        FROM task_queue
        WHERE status='queued'
        ORDER BY priority DESC, created_at
        LIMIT 1
    )
    RETURNING task_id, task_type
    """, (WORKER_ID,)).fetchone()
    conn.commit()
    return row

def complete_task(conn, task_id):
    conn.execute("""
    UPDATE task_queue
    SET status='completed',
        updated_at=datetime('now')
    WHERE task_id=?
    """, (task_id,))
    conn.commit()

def fail_task(conn, task_id):
    conn.execute("""
    UPDATE task_queue
    SET status='failed',
        updated_at=datetime('now')
    WHERE task_id=?
    """, (task_id,))
    conn.commit()

def main():
    conn = sqlite3.connect(DB_PATH)
    ensure_table(conn)
    print(f"[START] worker={WORKER_ID}")
    while True:
        row = claim_one(conn)
        if not row:
            print("[IDLE] no queued task")
            time.sleep(3)
            continue

        task_id, task_type = row
        print(f"[CLAIMED] task_id={task_id} type={task_type}")

        try:
            time.sleep(2)
            complete_task(conn, task_id)
            print(f"[COMPLETED] task_id={task_id}")
        except Exception:
            fail_task(conn, task_id)
            print(f"[FAILED] task_id={task_id}")

if __name__ == "__main__":
    main()
