import json
import sqlite3
import time
import uuid
from pathlib import Path

from task_handlers import HANDLERS

DB_PATH = Path("orchestrator.db")
WORKER_ID = "backend-worker-final"
SYSTEM_TASK_ID = "__system__"
POLL_SECONDS = 3
HEARTBEAT_INTERVAL_SECONDS = 1
HEARTBEAT_TICKS_PER_TASK = 2


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def ts() -> str:
    return "strftime('%Y-%m-%d %H:%M:%f', 'now')"


def has_column(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS task_queue (
            task_id TEXT PRIMARY KEY,
            task_type TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL CHECK (
                status IN ('queued','claimed','processing','completed','dead_lettered')
            ),
            payload TEXT,
            claimed_by_worker TEXT,
            claimed_at TEXT,
            heartbeat_at TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 3,
            last_error TEXT,
            result_payload TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    if not has_column(conn, "task_queue", "max_attempts"):
        conn.execute(
            """
            ALTER TABLE task_queue
            ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3
            """
        )

    if not has_column(conn, "task_queue", "result_payload"):
        conn.execute(
            """
            ALTER TABLE task_queue
            ADD COLUMN result_payload TEXT
            """
        )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS task_events (
            event_id TEXT PRIMARY KEY,
            task_id TEXT NOT NULL,
            worker_id TEXT,
            event_type TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT,
            message TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_task_queue_claimable
        ON task_queue(status, priority DESC, created_at)
        WHERE status='queued'
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_task_queue_active
        ON task_queue(status, heartbeat_at)
        WHERE status IN ('claimed','processing')
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_task_events_task_id
        ON task_events(task_id, created_at)
        """
    )

    conn.execute("DROP TRIGGER IF EXISTS trg_block_terminal_reactivation")

    conn.execute(
        """
        CREATE TRIGGER trg_block_terminal_reactivation
        BEFORE UPDATE OF status ON task_queue
        FOR EACH ROW
        WHEN OLD.status IN ('completed','dead_lettered')
         AND NEW.status IN ('queued','claimed','processing')
        BEGIN
            SELECT RAISE(ABORT, 'terminal task cannot be reactivated');
        END;
        """
    )

    conn.commit()


def log_event(
    conn: sqlite3.Connection,
    task_id: str,
    event_type: str,
    from_status: str | None,
    to_status: str | None,
    message: str | None,
) -> None:
    conn.execute(
        f"""
        INSERT INTO task_events (
            event_id,
            task_id,
            worker_id,
            event_type,
            from_status,
            to_status,
            message,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, {ts()})
        """,
        (
            str(uuid.uuid4()),
            task_id,
            WORKER_ID,
            event_type,
            from_status,
            to_status,
            message,
        ),
    )
    conn.commit()


def claim_one(conn: sqlite3.Connection) -> sqlite3.Row | None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            f"""
            UPDATE task_queue
            SET status='claimed',
                claimed_by_worker=?,
                claimed_at={ts()},
                heartbeat_at={ts()},
                updated_at={ts()},
                attempt_count=attempt_count+1,
                last_error=NULL
            WHERE task_id = (
                SELECT task_id
                FROM task_queue
                WHERE status='queued'
                ORDER BY priority DESC, created_at ASC
                LIMIT 1
            )
            RETURNING
                task_id,
                task_type,
                priority,
                payload,
                attempt_count,
                max_attempts
            """,
            (WORKER_ID,),
        ).fetchone()
        conn.commit()

        if row is not None:
            log_event(
                conn=conn,
                task_id=row["task_id"],
                event_type="claimed",
                from_status="queued",
                to_status="claimed",
                message=f"task claimed by {WORKER_ID}; attempt={row['attempt_count']}",
            )

        return row
    except Exception:
        conn.rollback()
        raise


def transition_status(
    conn: sqlite3.Connection,
    task_id: str,
    from_status: str,
    to_status: str,
    message: str | None = None,
    clear_claim: bool = False,
    clear_heartbeat: bool = False,
    clear_last_error: bool = False,
    last_error: str | None = None,
    result_payload: str | None = None,
) -> None:
    claimed_by_worker_sql = "NULL" if clear_claim else "claimed_by_worker"
    heartbeat_sql = "NULL" if clear_heartbeat else ts()

    params: list[str] = [to_status]

    if clear_last_error:
        last_error_sql = "NULL"
    elif last_error is not None:
        last_error_sql = "?"
        params.append(last_error)
    else:
        last_error_sql = "last_error"

    if result_payload is not None:
        result_payload_sql = "?"
        params.append(result_payload)
    else:
        result_payload_sql = "result_payload"

    sql = f"""
        UPDATE task_queue
        SET status=?,
            updated_at={ts()},
            claimed_by_worker={claimed_by_worker_sql},
            heartbeat_at={heartbeat_sql},
            last_error={last_error_sql},
            result_payload={result_payload_sql}
        WHERE task_id=?
          AND status=?
    """

    params.extend([task_id, from_status])

    cur = conn.execute(sql, params)
    if cur.rowcount != 1:
        conn.rollback()
        raise RuntimeError(
            f"status transition failed for task_id={task_id}: {from_status} -> {to_status}"
        )
    conn.commit()

    log_event(
        conn=conn,
        task_id=task_id,
        event_type=to_status,
        from_status=from_status,
        to_status=to_status,
        message=message,
    )


def set_processing(conn: sqlite3.Connection, task_id: str) -> None:
    transition_status(
        conn=conn,
        task_id=task_id,
        from_status="claimed",
        to_status="processing",
        message="task entered processing",
        clear_last_error=True,
    )


def heartbeat(conn: sqlite3.Connection, task_id: str) -> None:
    conn.execute(
        f"""
        UPDATE task_queue
        SET heartbeat_at={ts()},
            updated_at={ts()}
        WHERE task_id=?
          AND status='processing'
        """,
        (task_id,),
    )
    conn.commit()

    log_event(
        conn=conn,
        task_id=task_id,
        event_type="heartbeat",
        from_status="processing",
        to_status="processing",
        message="heartbeat updated",
    )


def set_completed(conn: sqlite3.Connection, task_id: str, result_payload: str) -> None:
    transition_status(
        conn=conn,
        task_id=task_id,
        from_status="processing",
        to_status="completed",
        message="task completed successfully",
        clear_heartbeat=True,
        clear_last_error=True,
        result_payload=result_payload,
    )


def requeue_task(conn: sqlite3.Connection, task_id: str, error_message: str) -> None:
    transition_status(
        conn=conn,
        task_id=task_id,
        from_status="processing",
        to_status="queued",
        message=f"task requeued after failure: {error_message}",
        clear_claim=True,
        clear_heartbeat=True,
        last_error=error_message,
    )


def set_dead_lettered(conn: sqlite3.Connection, task_id: str, error_message: str) -> None:
    transition_status(
        conn=conn,
        task_id=task_id,
        from_status="processing",
        to_status="dead_lettered",
        message=f"task dead-lettered: {error_message}",
        clear_heartbeat=True,
        last_error=error_message,
    )


def execute_task(conn: sqlite3.Connection, task_id: str, task_type: str, payload: str | None) -> dict:
    handler = HANDLERS.get(task_type)
    if handler is None:
        raise RuntimeError(f"unknown task_type: {task_type}")

    for _ in range(HEARTBEAT_TICKS_PER_TASK):
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)
        heartbeat(conn, task_id)

    result = handler(payload)
    if not isinstance(result, dict):
        raise RuntimeError("handler result must be dict")

    return result


def process_one(conn: sqlite3.Connection, row: sqlite3.Row) -> None:
    task_id = row["task_id"]
    task_type = row["task_type"]
    payload = row["payload"]
    attempt_count = row["attempt_count"]
    max_attempts = row["max_attempts"]

    print(f"[CLAIMED] task_id={task_id} type={task_type} attempt={attempt_count}/{max_attempts}")

    set_processing(conn, task_id)
    print(f"[PROCESSING] task_id={task_id}")

    try:
        result = execute_task(conn, task_id, task_type, payload)
        set_completed(conn, task_id, json.dumps(result, ensure_ascii=False))
        print(f"[COMPLETED] task_id={task_id}")
    except Exception as exc:
        error_message = str(exc)

        if attempt_count >= max_attempts:
            set_dead_lettered(conn, task_id, error_message)
            print(f"[DEAD_LETTERED] task_id={task_id} attempt={attempt_count}/{max_attempts} error={error_message}")
        else:
            requeue_task(conn, task_id, error_message)
            print(f"[REQUEUED] task_id={task_id} attempt={attempt_count}/{max_attempts} error={error_message}")


def main() -> None:
    conn = connect_db()
    ensure_schema(conn)

    print(f"[START] worker={WORKER_ID}")
    log_event(
        conn=conn,
        task_id=SYSTEM_TASK_ID,
        event_type="worker_started",
        from_status=None,
        to_status=None,
        message="worker loop started",
    )

    while True:
        row = claim_one(conn)
        if row is None:
            print("[IDLE] no queued task")
            time.sleep(POLL_SECONDS)
            continue

        process_one(conn, row)


if __name__ == "__main__":
    main()
