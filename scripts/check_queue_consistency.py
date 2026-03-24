import sqlite3
from pathlib import Path

DB_PATH = Path("orchestrator.db")
STALE_SECONDS = 30


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn


def has_column(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)


def ensure_minimum_schema(conn: sqlite3.Connection) -> None:
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
    conn.commit()


def print_rows(title: str, rows: list[sqlite3.Row]) -> None:
    print(f"[CHECK] {title}")
    if not rows:
        print("OK")
        return
    for row in rows:
        print(" | ".join("" if value is None else str(value) for value in row))


def main() -> None:
    conn = connect_db()
    ensure_minimum_schema(conn)

    terminal_with_heartbeat = conn.execute(
        """
        SELECT task_id, status, heartbeat_at, claimed_by_worker
        FROM task_queue
        WHERE status IN ('completed', 'dead_lettered')
          AND heartbeat_at IS NOT NULL
        ORDER BY task_id
        """
    ).fetchall()

    active_without_worker = conn.execute(
        """
        SELECT task_id, status, claimed_by_worker, heartbeat_at
        FROM task_queue
        WHERE status IN ('claimed', 'processing')
          AND (claimed_by_worker IS NULL OR claimed_by_worker = '')
        ORDER BY task_id
        """
    ).fetchall()

    stale_active = conn.execute(
        f"""
        SELECT task_id, status, attempt_count, claimed_by_worker, heartbeat_at
        FROM task_queue
        WHERE status IN ('claimed', 'processing')
          AND heartbeat_at IS NOT NULL
          AND (strftime('%s','now') - strftime('%s', heartbeat_at)) > {STALE_SECONDS}
        ORDER BY task_id
        """
    ).fetchall()

    dead_lettered_under_limit = conn.execute(
        """
        SELECT task_id, attempt_count, max_attempts, last_error
        FROM task_queue
        WHERE status='dead_lettered'
          AND attempt_count < max_attempts
        ORDER BY task_id
        """
    ).fetchall()

    queued_with_worker = conn.execute(
        """
        SELECT task_id, status, claimed_by_worker, heartbeat_at
        FROM task_queue
        WHERE status='queued'
          AND (claimed_by_worker IS NOT NULL OR heartbeat_at IS NOT NULL)
        ORDER BY task_id
        """
    ).fetchall()

    completed_with_error = conn.execute(
        """
        SELECT task_id, status, last_error
        FROM task_queue
        WHERE status='completed'
          AND last_error IS NOT NULL
        ORDER BY task_id
        """
    ).fetchall()

    print_rows("terminal tasks with heartbeat", terminal_with_heartbeat)
    print_rows("active tasks without worker", active_without_worker)
    print_rows("stale active tasks", stale_active)
    print_rows("dead_lettered tasks below max_attempts", dead_lettered_under_limit)
    print_rows("queued tasks still carrying worker/heartbeat", queued_with_worker)
    print_rows("completed tasks still carrying last_error", completed_with_error)
    print("[DONE]")


if __name__ == "__main__":
    main()
