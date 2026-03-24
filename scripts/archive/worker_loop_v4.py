import sqlite3
import time
import uuid
from pathlib import Path

DB_PATH = Path("orchestrator.db")
WORKER_ID = "backend-worker-v4"

def log_event(conn, task_id, event_type, message):
    conn.execute("""
    INSERT INTO worker_events (
        event_id, worker_id, task_id, event_type, message, created_at
    ) VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f', 'now'))
    """, (str(uuid.uuid4()), WORKER_ID, task_id, event_type, message))
    conn.commit()

def ensure_tables(conn):
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
        updated_at TEXT NOT NULL,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        last_error TEXT
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS worker_events (
        event_id TEXT PRIMARY KEY,
        worker_id TEXT NOT NULL,
        task_id TEXT,
        event_type TEXT NOT NULL,
        message TEXT,
        created_at TEXT NOT NULL
    )
    """)
    conn.commit()

def claim_one(conn):
    row = conn.execute("""
    UPDATE task_queue
    SET status='claimed',
        claimed_by_worker=?,
        claimed_at=strftime('%Y-%m-%d %H:%M:%f', 'now'),
        updated_at=strftime('%Y-%m-%d %H:%M:%f', 'now'),
        attempt_count=attempt_count+1,
        last_error=NULL
    WHERE queue_item_id = (
        SELECT queue_item_id
        FROM task_queue
        WHERE status='queued'
        ORDER BY priority DESC, created_at
        LIMIT 1
    )
    RETURNING task_id, task_type, payload, attempt_count
    """, (WORKER_ID,)).fetchone()
    conn.commit()
    return row

def set_status(conn, task_id, status, last_error=None):
    conn.execute("""
    UPDATE task_queue
    SET status=?,
        updated_at=strftime('%Y-%m-%d %H:%M:%f', 'now'),
        last_error=COALESCE(?, last_error)
    WHERE task_id=?
    """, (status, last_error, task_id))
    conn.commit()

def execute_task(task_id, task_type, payload):
    time.sleep(2)
    if task_type == "fail-test":
        raise RuntimeError("intentional fail-test")
    return True

def main():
    conn = sqlite3.connect(DB_PATH)
    ensure_tables(conn)
    print(f"[START] worker={WORKER_ID}")
    log_event(conn, None, "worker_started", "worker loop started")

    while True:
        row = claim_one(conn)
        if not row:
            print("[IDLE] no queued task")
            time.sleep(3)
            continue

        task_id, task_type, payload, attempt_count = row
        print(f"[CLAIMED] task_id={task_id} type={task_type} attempt={attempt_count}")
        log_event(conn, task_id, "claimed", f"task claimed type={task_type} attempt={attempt_count}")

        try:
            set_status(conn, task_id, "processing")
            print(f"[PROCESSING] task_id={task_id}")
            log_event(conn, task_id, "processing", "task entered processing")

            execute_task(task_id, task_type, payload)

            set_status(conn, task_id, "completed")
            print(f"[COMPLETED] task_id={task_id}")
            log_event(conn, task_id, "completed", "task completed successfully")
        except Exception as e:
            set_status(conn, task_id, "failed", str(e))
            print(f"[FAILED] task_id={task_id} error={e}")
            log_event(conn, task_id, "failed", f"task failed error={e}")

if __name__ == "__main__":
    main()
