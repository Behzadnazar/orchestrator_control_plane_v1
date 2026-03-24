import sqlite3
import time
import uuid
import os
from pathlib import Path

DB_PATH = Path("orchestrator.db")
WORKER_ID = "backend-worker-v7"
MAX_ATTEMPTS = 3

def ts():
    return "strftime('%Y-%m-%d %H:%M:%f', 'now')"

def log_event(conn, task_id, event_type, message):
    conn.execute(f"""
    INSERT INTO worker_events (
        event_id, worker_id, task_id, event_type, message, created_at
    ) VALUES (?, ?, ?, ?, ?, {ts()})
    """, (str(uuid.uuid4()), WORKER_ID, task_id, event_type, message))
    conn.commit()

def ensure_tables(conn):
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
    conn.execute("""
    CREATE TABLE IF NOT EXISTS dead_letter_queue (
        dlq_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL UNIQUE,
        task_type TEXT NOT NULL,
        priority INTEGER NOT NULL,
        payload TEXT,
        last_error TEXT,
        failed_at TEXT NOT NULL,
        moved_at TEXT NOT NULL,
        claimed_by_worker TEXT,
        attempt_count INTEGER NOT NULL DEFAULT 0
    )
    """)
    conn.commit()

def claim_one(conn):
    row = conn.execute(f"""
    UPDATE task_queue
    SET status='claimed',
        claimed_by_worker=?,
        claimed_at={ts()},
        updated_at={ts()},
        heartbeat_at={ts()},
        attempt_count=attempt_count+1,
        last_error=NULL
    WHERE queue_item_id = (
        SELECT queue_item_id
        FROM task_queue
        WHERE status='queued'
        ORDER BY priority DESC, created_at
        LIMIT 1
    )
    RETURNING task_id, task_type, payload, attempt_count, priority
    """, (WORKER_ID,)).fetchone()
    conn.commit()
    return row

def set_processing(conn, task_id):
    conn.execute(f"""
    UPDATE task_queue
    SET status='processing',
        updated_at={ts()},
        heartbeat_at={ts()}
    WHERE task_id=?
    """, (task_id,))
    conn.commit()

def heartbeat(conn, task_id):
    conn.execute(f"""
    UPDATE task_queue
    SET heartbeat_at={ts()},
        updated_at={ts()}
    WHERE task_id=?
    """, (task_id,))
    conn.commit()

def set_completed(conn, task_id):
    conn.execute(f"""
    UPDATE task_queue
    SET status='completed',
        updated_at={ts()},
        heartbeat_at={ts()}
    WHERE task_id=?
    """, (task_id,))
    conn.commit()

def requeue_task(conn, task_id, error_message):
    conn.execute(f"""
    UPDATE task_queue
    SET status='queued',
        updated_at={ts()},
        heartbeat_at={ts()},
        last_error=?
    WHERE task_id=?
    """, (error_message, task_id))
    conn.commit()

def move_to_dlq(conn, task_id, task_type, priority, payload, last_error, attempt_count):
    conn.execute(f"""
    INSERT OR REPLACE INTO dead_letter_queue (
        dlq_id, task_id, task_type, priority, payload, last_error,
        failed_at, moved_at, claimed_by_worker, attempt_count
    ) VALUES (?, ?, ?, ?, ?, ?, {ts()}, {ts()}, ?, ?)
    """, (str(uuid.uuid4()), task_id, task_type, priority, payload, last_error, WORKER_ID, attempt_count))
    conn.execute("DELETE FROM task_queue WHERE task_id=?", (task_id,))
    conn.commit()

def execute_task(conn, task_id, task_type, payload):
    if task_type == "crash-test":
        heartbeat(conn, task_id)
        time.sleep(2)
        os._exit(1)

    for _ in range(5):
        time.sleep(1)
        heartbeat(conn, task_id)

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

        task_id, task_type, payload, attempt_count, priority = row
        print(f"[CLAIMED] task_id={task_id} type={task_type} attempt={attempt_count}")
        log_event(conn, task_id, "claimed", f"task claimed type={task_type} attempt={attempt_count}")

        try:
            set_processing(conn, task_id)
            print(f"[PROCESSING] task_id={task_id}")
            log_event(conn, task_id, "processing", "task entered processing")

            execute_task(conn, task_id, task_type, payload)

            set_completed(conn, task_id)
            print(f"[COMPLETED] task_id={task_id}")
            log_event(conn, task_id, "completed", "task completed successfully")

        except Exception as e:
            error_message = str(e)
            if attempt_count >= MAX_ATTEMPTS:
                move_to_dlq(conn, task_id, task_type, priority, payload, error_message, attempt_count)
                print(f"[DLQ] task_id={task_id} attempts={attempt_count} error={error_message}")
                log_event(conn, task_id, "dead_lettered", f"task moved to dlq after attempt={attempt_count} error={error_message}")
            else:
                requeue_task(conn, task_id, error_message)
                print(f"[REQUEUED] task_id={task_id} attempt={attempt_count} error={error_message}")
                log_event(conn, task_id, "requeued", f"task requeued after attempt={attempt_count} error={error_message}")

if __name__ == "__main__":
    main()
