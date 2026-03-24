import sqlite3
from pathlib import Path

DB_PATH = Path("orchestrator.db")
STALE_SECONDS = 30

conn = sqlite3.connect(DB_PATH)

rows = conn.execute(f"""
SELECT task_id, status, claimed_by_worker, heartbeat_at
FROM task_queue
WHERE status IN ('claimed', 'processing')
  AND heartbeat_at IS NOT NULL
  AND (strftime('%s','now') - strftime('%s', heartbeat_at)) > {STALE_SECONDS}
""").fetchall()

for task_id, status, claimed_by_worker, heartbeat_at in rows:
    conn.execute("""
    UPDATE task_queue
    SET status='queued',
        updated_at=strftime('%Y-%m-%d %H:%M:%f', 'now'),
        last_error='recovered from stale worker state',
        claimed_by_worker=NULL,
        heartbeat_at=NULL
    WHERE task_id=?
    """, (task_id,))
    print(f"[RECOVERED] task_id={task_id} from={status} worker={claimed_by_worker} heartbeat_at={heartbeat_at}")

conn.commit()
print(f"[DONE] recovered_count={len(rows)}")
