from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "orchestrator.db"


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now() -> str:
    return utc_now_dt().isoformat(timespec="seconds")


def utc_offset(seconds: int) -> str:
    return (utc_now_dt() + timedelta(seconds=seconds)).isoformat(timespec="seconds")


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _row_factory(cursor: sqlite3.Cursor, row: tuple[Any, ...]) -> dict[str, Any]:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


@contextmanager
def get_conn() -> Iterable[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = _row_factory
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def payload_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _index_exists(conn: sqlite3.Connection, index_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name = ?",
        (index_name,),
    ).fetchone()
    return row is not None


def _get_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def _ensure_column(conn: sqlite3.Connection, table_name: str, column_name: str, column_sql: str) -> None:
    columns = _get_columns(conn, table_name)
    if column_name not in columns:
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def _backfill_payload_hash(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT task_id, payload_json, payload_hash
        FROM task_queue
        """
    ).fetchall()

    for row in rows:
        current_hash = row.get("payload_hash")
        if current_hash:
            continue

        try:
            payload = json.loads(row["payload_json"])
        except Exception:
            payload = {"raw_payload_json": row["payload_json"]}

        conn.execute(
            """
            UPDATE task_queue
            SET payload_hash = ?
            WHERE task_id = ?
            """,
            (payload_hash(payload), row["task_id"]),
        )


def _migrate_task_queue_schema(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "task_queue"):
        return

    _ensure_column(conn, "task_queue", "workflow_run_key", "workflow_run_key TEXT")
    _ensure_column(conn, "task_queue", "parent_task_id", "parent_task_id TEXT")
    _ensure_column(conn, "task_queue", "depends_on_task_id", "depends_on_task_id TEXT")
    _ensure_column(conn, "task_queue", "handoff_from_task_id", "handoff_from_task_id TEXT")
    _ensure_column(
        conn,
        "task_queue",
        "dependency_status",
        "dependency_status TEXT NOT NULL DEFAULT 'none' CHECK (dependency_status IN ('none', 'waiting', 'satisfied', 'failed'))",
    )
    _ensure_column(conn, "task_queue", "payload_hash", "payload_hash TEXT")

    _backfill_payload_hash(conn)

    if not _index_exists(conn, "idx_task_queue_dedup"):
        conn.execute(
            """
            CREATE UNIQUE INDEX idx_task_queue_dedup
            ON task_queue(
                workflow_id,
                COALESCE(parent_task_id, ''),
                COALESCE(depends_on_task_id, ''),
                COALESCE(handoff_from_task_id, ''),
                task_type,
                payload_hash
            )
            """
        )

    if not _index_exists(conn, "idx_task_queue_workflow"):
        conn.execute(
            """
            CREATE INDEX idx_task_queue_workflow
            ON task_queue(workflow_id, created_at ASC)
            """
        )

    if not _index_exists(conn, "idx_task_queue_dependency"):
        conn.execute(
            """
            CREATE INDEX idx_task_queue_dependency
            ON task_queue(depends_on_task_id, status, created_at ASC)
            """
        )

    if not _index_exists(conn, "idx_task_queue_parent"):
        conn.execute(
            """
            CREATE INDEX idx_task_queue_parent
            ON task_queue(parent_task_id, created_at ASC)
            """
        )


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS task_queue (
                queue_item_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL UNIQUE,
                workflow_id TEXT NOT NULL,
                workflow_run_key TEXT,
                correlation_id TEXT NOT NULL,
                parent_task_id TEXT,
                depends_on_task_id TEXT,
                handoff_from_task_id TEXT,
                dependency_status TEXT NOT NULL DEFAULT 'none' CHECK (
                    dependency_status IN ('none', 'waiting', 'satisfied', 'failed')
                ),
                task_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_hash TEXT,
                priority INTEGER NOT NULL DEFAULT 100,
                status TEXT NOT NULL CHECK (
                    status IN ('blocked', 'queued', 'claimed', 'running', 'succeeded', 'failed', 'dead_letter')
                ),
                attempt_count INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 3,
                claimed_by_worker TEXT,
                created_at TEXT NOT NULL,
                claimed_at TEXT,
                started_at TEXT,
                finished_at TEXT,
                updated_at TEXT NOT NULL,
                last_error TEXT,
                claim_deadline_at TEXT,
                running_deadline_at TEXT,
                last_worker_heartbeat_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_task_queue_status_priority
            ON task_queue(status, priority DESC, created_at ASC);

            CREATE TABLE IF NOT EXISTS task_events (
                event_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                workflow_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                worker_id TEXT,
                event_type TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT,
                event_payload_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_task_events_task_id_created
            ON task_events(task_id, created_at ASC);

            CREATE INDEX IF NOT EXISTS idx_task_events_workflow
            ON task_events(workflow_id, created_at ASC);

            CREATE TABLE IF NOT EXISTS worker_state (
                worker_id TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK (
                    status IN ('idle', 'assigned', 'executing', 'reporting')
                ),
                capabilities_json TEXT NOT NULL DEFAULT '[]',
                current_task_id TEXT,
                current_correlation_id TEXT,
                last_heartbeat_at TEXT,
                updated_at TEXT NOT NULL
            );
            """
        )

        _migrate_task_queue_schema(conn)


def ensure_worker(worker_id: str, capabilities: list[str]) -> None:
    now = utc_now()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT worker_id FROM worker_state WHERE worker_id = ?",
            (worker_id,),
        ).fetchone()

        if row:
            conn.execute(
                """
                UPDATE worker_state
                SET capabilities_json = ?, last_heartbeat_at = ?, updated_at = ?
                WHERE worker_id = ?
                """,
                (json.dumps(capabilities), now, now, worker_id),
            )
        else:
            conn.execute(
                """
                INSERT INTO worker_state (
                    worker_id, status, capabilities_json, current_task_id,
                    current_correlation_id, last_heartbeat_at, updated_at
                ) VALUES (?, 'idle', ?, NULL, NULL, ?, ?)
                """,
                (worker_id, json.dumps(capabilities), now, now),
            )


def update_worker_state(
    worker_id: str,
    status: str,
    current_task_id: str | None = None,
    current_correlation_id: str | None = None,
) -> None:
    now = utc_now()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE worker_state
            SET status = ?,
                current_task_id = ?,
                current_correlation_id = ?,
                last_heartbeat_at = ?,
                updated_at = ?
            WHERE worker_id = ?
            """,
            (status, current_task_id, current_correlation_id, now, now, worker_id),
        )


def heartbeat_worker(worker_id: str) -> str:
    now = utc_now()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE worker_state
            SET last_heartbeat_at = ?,
                updated_at = ?
            WHERE worker_id = ?
            """,
            (now, now, worker_id),
        )
    return now


def append_event(
    task_id: str,
    workflow_id: str,
    correlation_id: str,
    event_type: str,
    worker_id: str | None = None,
    from_status: str | None = None,
    to_status: str | None = None,
    payload: dict[str, Any] | None = None,
) -> str:
    event_id = make_id("evt")
    now = utc_now()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO task_events (
                event_id, task_id, workflow_id, correlation_id, worker_id, event_type,
                from_status, to_status, event_payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                task_id,
                workflow_id,
                correlation_id,
                worker_id,
                event_type,
                from_status,
                to_status,
                json.dumps(payload or {}, ensure_ascii=False),
                now,
            ),
        )
    return event_id


def _dependency_initial_state(depends_on_task_id: str | None) -> tuple[str, str]:
    if not depends_on_task_id:
        return "queued", "none"

    dependency = get_task(depends_on_task_id)
    if not dependency:
        return "dead_letter", "failed"

    if dependency["status"] == "succeeded":
        return "queued", "satisfied"

    if dependency["status"] in {"dead_letter", "failed"}:
        return "dead_letter", "failed"

    return "blocked", "waiting"


def _find_existing_task(
    conn: sqlite3.Connection,
    workflow_id: str,
    parent_task_id: str | None,
    depends_on_task_id: str | None,
    handoff_from_task_id: str | None,
    task_type: str,
    phash: str,
) -> dict[str, Any] | None:
    return conn.execute(
        """
        SELECT *
        FROM task_queue
        WHERE workflow_id = ?
          AND COALESCE(parent_task_id, '') = COALESCE(?, '')
          AND COALESCE(depends_on_task_id, '') = COALESCE(?, '')
          AND COALESCE(handoff_from_task_id, '') = COALESCE(?, '')
          AND task_type = ?
          AND payload_hash = ?
        LIMIT 1
        """,
        (
            workflow_id,
            parent_task_id,
            depends_on_task_id,
            handoff_from_task_id,
            task_type,
            phash,
        ),
    ).fetchone()


def create_task(
    task_type: str,
    payload: dict[str, Any],
    priority: int = 100,
    max_attempts: int = 3,
    correlation_id: str | None = None,
    workflow_id: str | None = None,
    workflow_run_key: str | None = None,
    parent_task_id: str | None = None,
    depends_on_task_id: str | None = None,
    handoff_from_task_id: str | None = None,
) -> str:
    now = utc_now()
    task_id = make_id("task")
    queue_item_id = make_id("q")
    corr = correlation_id or make_id("corr")
    wf = workflow_id or make_id("wf")
    phash = payload_hash(payload)
    initial_status, dependency_status = _dependency_initial_state(depends_on_task_id)

    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")

        existing = _find_existing_task(
            conn=conn,
            workflow_id=wf,
            parent_task_id=parent_task_id,
            depends_on_task_id=depends_on_task_id,
            handoff_from_task_id=handoff_from_task_id,
            task_type=task_type,
            phash=phash,
        )
        if existing:
            return existing["task_id"]

        conn.execute(
            """
            INSERT OR IGNORE INTO task_queue (
                queue_item_id, task_id, workflow_id, workflow_run_key, correlation_id, parent_task_id,
                depends_on_task_id, handoff_from_task_id, dependency_status, task_type,
                payload_json, payload_hash, priority, status, attempt_count, max_attempts,
                claimed_by_worker, created_at, claimed_at, started_at, finished_at,
                updated_at, last_error, claim_deadline_at, running_deadline_at, last_worker_heartbeat_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, ?, NULL, NULL, NULL, ?, NULL, NULL, NULL, NULL)
            """,
            (
                queue_item_id,
                task_id,
                wf,
                workflow_run_key,
                corr,
                parent_task_id,
                depends_on_task_id,
                handoff_from_task_id,
                dependency_status,
                task_type,
                json.dumps(payload, ensure_ascii=False),
                phash,
                priority,
                initial_status,
                max_attempts,
                now,
                now,
            ),
        )

        inserted_row = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()

        if inserted_row:
            created_task_id = inserted_row["task_id"]
            inserted = True
        else:
            existing_after_conflict = _find_existing_task(
                conn=conn,
                workflow_id=wf,
                parent_task_id=parent_task_id,
                depends_on_task_id=depends_on_task_id,
                handoff_from_task_id=handoff_from_task_id,
                task_type=task_type,
                phash=phash,
            )
            if not existing_after_conflict:
                raise RuntimeError("Task insert was ignored but no matching existing task was found")
            created_task_id = existing_after_conflict["task_id"]
            inserted = False

    if inserted:
        append_event(
            task_id=created_task_id,
            workflow_id=wf,
            correlation_id=corr,
            event_type="TaskCreated",
            from_status=None,
            to_status=initial_status,
            payload={
                "task_type": task_type,
                "priority": priority,
                "max_attempts": max_attempts,
                "parent_task_id": parent_task_id,
                "depends_on_task_id": depends_on_task_id,
                "handoff_from_task_id": handoff_from_task_id,
                "dependency_status": dependency_status,
                "workflow_run_key": workflow_run_key,
                "payload_hash": phash,
            },
        )
    return created_task_id


def get_task(task_id: str) -> dict[str, Any] | None:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()


def get_latest_tasks(limit: int = 120) -> list[dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT *
            FROM task_queue
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_recent_events(task_id: str, limit: int = 12) -> list[dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT *
            FROM task_events
            WHERE task_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (task_id, limit),
        ).fetchall()


def list_workers() -> list[dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM worker_state ORDER BY worker_id ASC"
        ).fetchall()


def get_queued_tasks(limit: int = 200) -> list[dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT *
            FROM task_queue
            WHERE status = 'queued'
            ORDER BY priority DESC, created_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_workflow_tasks(workflow_id: str) -> list[dict[str, Any]]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT *
            FROM task_queue
            WHERE workflow_id = ?
            ORDER BY created_at ASC
            """,
            (workflow_id,),
        ).fetchall()


def workflow_exists(workflow_id: str, workflow_run_key: str | None = None) -> bool:
    with get_conn() as conn:
        if workflow_run_key:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM task_queue
                WHERE workflow_id = ?
                  AND workflow_run_key = ?
                """,
                (workflow_id, workflow_run_key),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM task_queue
                WHERE workflow_id = ?
                """,
                (workflow_id,),
            ).fetchone()
    return int(row["count"]) > 0


def claim_next_task(worker_id: str, accepted_task_types: list[str], claim_timeout_seconds: int) -> dict[str, Any] | None:
    if not accepted_task_types:
        return None

    now = utc_now()
    claim_deadline_at = utc_offset(claim_timeout_seconds)
    placeholders = ",".join("?" for _ in accepted_task_types)

    with get_conn() as conn:
        row = conn.execute(
            f"""
            SELECT *
            FROM task_queue
            WHERE status = 'queued'
              AND task_type IN ({placeholders})
            ORDER BY priority DESC, created_at ASC
            LIMIT 1
            """,
            tuple(accepted_task_types),
        ).fetchone()

        if not row:
            return None

        conn.execute(
            """
            UPDATE task_queue
            SET status = 'claimed',
                claimed_by_worker = ?,
                claimed_at = ?,
                updated_at = ?,
                claim_deadline_at = ?
            WHERE task_id = ?
              AND status = 'queued'
            """,
            (worker_id, now, now, claim_deadline_at, row["task_id"]),
        )

        updated = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (row["task_id"],),
        ).fetchone()

    if updated:
        append_event(
            task_id=updated["task_id"],
            workflow_id=updated["workflow_id"],
            correlation_id=updated["correlation_id"],
            worker_id=worker_id,
            event_type="TaskClaimed",
            from_status="queued",
            to_status="claimed",
            payload={"worker_id": worker_id, "claim_deadline_at": claim_deadline_at},
        )
    return updated


def set_task_running(task_id: str, worker_id: str, max_runtime_seconds: int) -> dict[str, Any]:
    now = utc_now()
    running_deadline_at = utc_offset(max_runtime_seconds)

    with get_conn() as conn:
        current = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if not current:
            raise ValueError(f"Task not found: {task_id}")
        if current["status"] != "claimed":
            raise ValueError(f"Task {task_id} must be in 'claimed' state, got '{current['status']}'")

        attempt_count = int(current["attempt_count"]) + 1

        conn.execute(
            """
            UPDATE task_queue
            SET status = 'running',
                attempt_count = ?,
                started_at = ?,
                updated_at = ?,
                running_deadline_at = ?,
                last_worker_heartbeat_at = ?
            WHERE task_id = ?
            """,
            (attempt_count, now, now, running_deadline_at, now, task_id),
        )
        updated = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()

    append_event(
        task_id=task_id,
        workflow_id=updated["workflow_id"],
        correlation_id=updated["correlation_id"],
        worker_id=worker_id,
        event_type="TaskStarted",
        from_status="claimed",
        to_status="running",
        payload={
            "attempt_count": updated["attempt_count"],
            "running_deadline_at": running_deadline_at,
        },
    )
    return updated


def record_task_heartbeat(
    task_id: str,
    worker_id: str,
    min_interval_seconds: int = 5,
    force: bool = False,
) -> str:
    now_dt = utc_now_dt()
    now = now_dt.isoformat(timespec="seconds")

    with get_conn() as conn:
        current = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if not current:
            heartbeat_worker(worker_id)
            return now

        previous = parse_ts(current.get("last_worker_heartbeat_at"))
        should_emit = force or previous is None or (now_dt - previous).total_seconds() >= min_interval_seconds

        conn.execute(
            """
            UPDATE task_queue
            SET last_worker_heartbeat_at = ?,
                updated_at = ?
            WHERE task_id = ?
            """,
            (now, now, task_id),
        )

    heartbeat_worker(worker_id)

    if should_emit:
        append_event(
            task_id=current["task_id"],
            workflow_id=current["workflow_id"],
            correlation_id=current["correlation_id"],
            worker_id=worker_id,
            event_type="WorkerHeartbeat",
            from_status=current["status"],
            to_status=current["status"],
            payload={"heartbeat_at": now, "min_interval_seconds": min_interval_seconds},
        )

    return now


def unblock_dependent_tasks(parent_task_id: str, worker_id: str | None = None) -> list[str]:
    unblocked: list[str] = []
    parent = get_task(parent_task_id)
    if not parent:
        return unblocked

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM task_queue
            WHERE depends_on_task_id = ?
              AND status = 'blocked'
            ORDER BY created_at ASC
            """,
            (parent_task_id,),
        ).fetchall()

        for row in rows:
            conn.execute(
                """
                UPDATE task_queue
                SET status = 'queued',
                    dependency_status = 'satisfied',
                    updated_at = ?
                WHERE task_id = ?
                """,
                (utc_now(), row["task_id"]),
            )
            unblocked.append(row["task_id"])

    for task_id in unblocked:
        task = get_task(task_id)
        append_event(
            task_id=task["task_id"],
            workflow_id=task["workflow_id"],
            correlation_id=task["correlation_id"],
            worker_id=worker_id,
            event_type="TaskDependencySatisfied",
            from_status="blocked",
            to_status="queued",
            payload={
                "depends_on_task_id": parent_task_id,
                "handoff_from_task_id": task["handoff_from_task_id"],
            },
        )
    return unblocked


def fail_blocked_dependents(parent_task_id: str, reason: str, worker_id: str | None = None) -> list[str]:
    failed: list[str] = []
    parent = get_task(parent_task_id)
    if not parent:
        return failed

    now = utc_now()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM task_queue
            WHERE depends_on_task_id = ?
              AND status = 'blocked'
            ORDER BY created_at ASC
            """,
            (parent_task_id,),
        ).fetchall()

        for row in rows:
            conn.execute(
                """
                UPDATE task_queue
                SET status = 'dead_letter',
                    dependency_status = 'failed',
                    finished_at = ?,
                    updated_at = ?,
                    last_error = ?
                WHERE task_id = ?
                """,
                (now, now, reason, row["task_id"]),
            )
            failed.append(row["task_id"])

    for task_id in failed:
        task = get_task(task_id)
        append_event(
            task_id=task["task_id"],
            workflow_id=task["workflow_id"],
            correlation_id=task["correlation_id"],
            worker_id=worker_id,
            event_type="TaskDependencyFailed",
            from_status="blocked",
            to_status="dead_letter",
            payload={"depends_on_task_id": parent_task_id, "reason": reason},
        )
    return failed


def finish_task_success(
    task_id: str,
    worker_id: str,
    result_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = utc_now()
    with get_conn() as conn:
        current = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if not current:
            raise ValueError(f"Task not found: {task_id}")
        if current["status"] != "running":
            raise ValueError(f"Task {task_id} must be in 'running' state, got '{current['status']}'")

        conn.execute(
            """
            UPDATE task_queue
            SET status = 'succeeded',
                finished_at = ?,
                updated_at = ?,
                last_error = NULL,
                claim_deadline_at = NULL,
                running_deadline_at = NULL,
                last_worker_heartbeat_at = NULL
            WHERE task_id = ?
            """,
            (now, now, task_id),
        )
        updated = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()

    append_event(
        task_id=task_id,
        workflow_id=updated["workflow_id"],
        correlation_id=updated["correlation_id"],
        worker_id=worker_id,
        event_type="TaskSucceeded",
        from_status="running",
        to_status="succeeded",
        payload=result_payload or {},
    )
    unblock_dependent_tasks(task_id, worker_id=worker_id)
    return updated


def finish_task_failure(
    task_id: str,
    worker_id: str,
    error_message: str,
    result_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = utc_now()
    with get_conn() as conn:
        current = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if not current:
            raise ValueError(f"Task not found: {task_id}")
        if current["status"] != "running":
            raise ValueError(f"Task {task_id} must be in 'running' state, got '{current['status']}'")

        if int(current["attempt_count"]) < int(current["max_attempts"]):
            next_status = "queued"
            claimed_by_worker = None
            claimed_at = None
            started_at = None
            finished_at = None
        else:
            next_status = "dead_letter"
            claimed_by_worker = current["claimed_by_worker"]
            claimed_at = current["claimed_at"]
            started_at = current["started_at"]
            finished_at = now

        conn.execute(
            """
            UPDATE task_queue
            SET status = ?,
                claimed_by_worker = ?,
                claimed_at = ?,
                started_at = ?,
                finished_at = ?,
                updated_at = ?,
                last_error = ?,
                claim_deadline_at = NULL,
                running_deadline_at = NULL,
                last_worker_heartbeat_at = NULL
            WHERE task_id = ?
            """,
            (
                next_status,
                claimed_by_worker,
                claimed_at,
                started_at,
                finished_at,
                now,
                error_message,
                task_id,
            ),
        )
        updated = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()

    if updated["status"] == "queued":
        append_event(
            task_id=task_id,
            workflow_id=updated["workflow_id"],
            correlation_id=updated["correlation_id"],
            worker_id=worker_id,
            event_type="TaskRequeued",
            from_status="running",
            to_status="queued",
            payload={
                "error": error_message,
                "attempt_count": updated["attempt_count"],
                "max_attempts": updated["max_attempts"],
                **(result_payload or {}),
            },
        )
    else:
        append_event(
            task_id=task_id,
            workflow_id=updated["workflow_id"],
            correlation_id=updated["correlation_id"],
            worker_id=worker_id,
            event_type="TaskDeadLettered",
            from_status="running",
            to_status="dead_letter",
            payload={
                "error": error_message,
                "attempt_count": updated["attempt_count"],
                "max_attempts": updated["max_attempts"],
                **(result_payload or {}),
            },
        )
        fail_blocked_dependents(task_id, reason=f"dependency parent failed: {error_message}", worker_id=worker_id)

    return updated


def dead_letter_task_from_queue(
    task_id: str,
    reason: str,
    worker_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = utc_now()
    with get_conn() as conn:
        current = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        if not current:
            raise ValueError(f"Task not found: {task_id}")
        if current["status"] not in {"queued", "blocked"}:
            return current

        conn.execute(
            """
            UPDATE task_queue
            SET status = 'dead_letter',
                finished_at = ?,
                updated_at = ?,
                last_error = ?,
                dependency_status = CASE
                    WHEN status = 'blocked' THEN 'failed'
                    ELSE dependency_status
                END,
                claim_deadline_at = NULL,
                running_deadline_at = NULL,
                last_worker_heartbeat_at = NULL
            WHERE task_id = ?
            """,
            (now, now, reason, task_id),
        )
        updated = conn.execute(
            "SELECT * FROM task_queue WHERE task_id = ?",
            (task_id,),
        ).fetchone()

    append_event(
        task_id=updated["task_id"],
        workflow_id=updated["workflow_id"],
        correlation_id=updated["correlation_id"],
        worker_id=worker_id,
        event_type="TaskDeadLettered",
        from_status=current["status"],
        to_status="dead_letter",
        payload={
            "reason": reason,
            **(details or {}),
        },
    )
    fail_blocked_dependents(task_id, reason=f"dependency parent dead-lettered: {reason}", worker_id=worker_id)
    return updated


def recover_stale_tasks(
    claim_timeout_seconds: int,
    heartbeat_timeout_seconds: int,
    runtime_timeout_seconds: int,
    recovery_decider,
    worker_id: str | None = None,
) -> list[dict[str, Any]]:
    now = utc_now()
    claim_cutoff = utc_offset(-claim_timeout_seconds)
    heartbeat_cutoff = utc_offset(-heartbeat_timeout_seconds)

    recoveries: list[dict[str, Any]] = []

    with get_conn() as conn:
        claimed_rows = conn.execute(
            """
            SELECT *
            FROM task_queue
            WHERE status = 'claimed'
              AND claimed_at IS NOT NULL
              AND claimed_at <= ?
            ORDER BY claimed_at ASC
            """,
            (claim_cutoff,),
        ).fetchall()

        for current in claimed_rows:
            policy = recovery_decider(current, "claim_timeout")
            next_status = policy["next_status"]
            finished_at = None if next_status == "queued" else now

            conn.execute(
                """
                UPDATE task_queue
                SET status = ?,
                    claimed_by_worker = NULL,
                    claimed_at = NULL,
                    started_at = NULL,
                    finished_at = ?,
                    updated_at = ?,
                    last_error = ?,
                    claim_deadline_at = NULL,
                    running_deadline_at = NULL,
                    last_worker_heartbeat_at = NULL
                WHERE task_id = ?
                """,
                (
                    next_status,
                    finished_at,
                    now,
                    policy["reason_text"],
                    current["task_id"],
                ),
            )

            recoveries.append(
                {
                    "task_id": current["task_id"],
                    "workflow_id": current["workflow_id"],
                    "correlation_id": current["correlation_id"],
                    "from_status": "claimed",
                    "to_status": next_status,
                    "reason": "claim_timeout",
                    "intermediate_event": "TaskLeaseExpired",
                    "final_event": "TaskRecoveredToQueue" if next_status == "queued" else "TaskDeadLettered",
                    "payload": {
                        "claim_timeout_seconds": claim_timeout_seconds,
                        "previous_worker": current["claimed_by_worker"],
                        **policy,
                    },
                }
            )

        running_rows = conn.execute(
            """
            SELECT *
            FROM task_queue
            WHERE status = 'running'
              AND (
                    (last_worker_heartbeat_at IS NOT NULL AND last_worker_heartbeat_at <= ?)
                 OR (running_deadline_at IS NOT NULL AND running_deadline_at <= ?)
              )
            ORDER BY started_at ASC
            """,
            (heartbeat_cutoff, now),
        ).fetchall()

        for current in running_rows:
            if current["running_deadline_at"] and current["running_deadline_at"] <= now:
                reason = "runtime_timeout"
                intermediate_event = "TaskTimedOut"
                base_payload = {
                    "runtime_timeout_seconds": runtime_timeout_seconds,
                    "running_deadline_at": current["running_deadline_at"],
                }
            else:
                reason = "heartbeat_timeout"
                intermediate_event = "TaskLeaseExpired"
                base_payload = {
                    "heartbeat_timeout_seconds": heartbeat_timeout_seconds,
                    "last_worker_heartbeat_at": current["last_worker_heartbeat_at"],
                }

            policy = recovery_decider(current, reason)
            next_status = policy["next_status"]
            finished_at = None if next_status == "queued" else now

            conn.execute(
                """
                UPDATE task_queue
                SET status = ?,
                    claimed_by_worker = NULL,
                    claimed_at = NULL,
                    started_at = NULL,
                    finished_at = ?,
                    updated_at = ?,
                    last_error = ?,
                    claim_deadline_at = NULL,
                    running_deadline_at = NULL,
                    last_worker_heartbeat_at = NULL
                WHERE task_id = ?
                """,
                (
                    next_status,
                    finished_at,
                    now,
                    policy["reason_text"],
                    current["task_id"],
                ),
            )

            recoveries.append(
                {
                    "task_id": current["task_id"],
                    "workflow_id": current["workflow_id"],
                    "correlation_id": current["correlation_id"],
                    "from_status": "running",
                    "to_status": next_status,
                    "reason": reason,
                    "intermediate_event": intermediate_event,
                    "final_event": "TaskRecoveredToQueue" if next_status == "queued" else "TaskDeadLettered",
                    "payload": {
                        **base_payload,
                        **policy,
                    },
                }
            )

    for item in recoveries:
        append_event(
            task_id=item["task_id"],
            workflow_id=item["workflow_id"],
            correlation_id=item["correlation_id"],
            worker_id=worker_id,
            event_type=item["intermediate_event"],
            from_status=item["from_status"],
            to_status=item["from_status"],
            payload=item["payload"],
        )
        append_event(
            task_id=item["task_id"],
            workflow_id=item["workflow_id"],
            correlation_id=item["correlation_id"],
            worker_id=worker_id,
            event_type=item["final_event"],
            from_status=item["from_status"],
            to_status=item["to_status"],
            payload=item["payload"],
        )

    return recoveries

def reset_demo_data() -> None:
    import shutil

    run_dir = BASE_DIR / "artifacts" / "runs" / "phase_h_demo_v2"

    with get_conn() as conn:
        conn.execute("DELETE FROM task_events")
        conn.execute("DELETE FROM task_queue")
        conn.execute("DELETE FROM worker_state")
        conn.commit()

    if run_dir.exists():
        shutil.rmtree(run_dir)
#def reset_demo_data() -> None:
#    import shutil
#
#    run_dir = BASE_DIR / "artifacts" / "runs" / "phase_h_demo_v2"
#
#    with get_conn() as conn:
#        conn.execute("DELETE FROM task_events")
#        conn.execute("DELETE FROM task_queue")
#        conn.execute("DELETE FROM dead_letter_queue")
#        conn.execute("DELETE FROM tasks")
#        conn.execute("DELETE FROM workflow_runs")
#        conn.execute("DELETE FROM worker_state")
#        conn.commit()
#
#    if run_dir.exists():
#        shutil.rmtree(run_dir)

def seed_demo_tasks_if_empty() -> None:
    workflow_id = "wf_phase_h_demo"
    workflow_run_key = "phase_h_demo_v2"
    root_corr = "corr_phase_h_demo_v2"
    run_dir = BASE_DIR / "artifacts" / "runs" / workflow_run_key

    if workflow_exists(workflow_id, workflow_run_key=workflow_run_key):
        return

    research_task = create_task(
        task_type="research.collect_notes",
        payload={
            "topic": "control plane routing",
            "workflow_run_key": workflow_run_key,
            "notes_path": str(run_dir / "research" / "control-plane-routing.md"),
        },
        priority=120,
        max_attempts=2,
        correlation_id=root_corr,
        workflow_id=workflow_id,
        workflow_run_key=workflow_run_key,
    )

    frontend_task = create_task(
        task_type="frontend.write_component",
        payload={
            "component_name": "HeroFromResearch",
            "workflow_run_key": workflow_run_key,
            "source_notes_path": str(run_dir / "research" / "control-plane-routing.md"),
            "component_path": str(run_dir / "frontend" / "HeroFromResearch.tsx"),
        },
        priority=110,
        max_attempts=2,
        workflow_id=workflow_id,
        workflow_run_key=workflow_run_key,
        correlation_id=root_corr,
        parent_task_id=research_task,
        depends_on_task_id=research_task,
        handoff_from_task_id=research_task,
    )

    create_task(
        task_type="backend.write_file",
        payload={
            "workflow_run_key": workflow_run_key,
            "path": str(run_dir / "workflows" / "phase_h_bundle.txt"),
            "content": "bundle generated after frontend component handoff\n",
        },
        priority=100,
        max_attempts=2,
        workflow_id=workflow_id,
        workflow_run_key=workflow_run_key,
        correlation_id=root_corr,
        parent_task_id=frontend_task,
        depends_on_task_id=frontend_task,
        handoff_from_task_id=frontend_task,
    )

    create_task(
        task_type="backend.fail_test",
        payload={"note": "retry then dead-letter still works"},
        priority=90,
        max_attempts=2,
        workflow_id="wf_fail_path",
        workflow_run_key="fail_path_v1",
        correlation_id="corr_fail_path",
    )

    create_task(
        task_type="unknown.ghost_task",
        payload={"note": "should still be dead-lettered by route guard"},
        priority=130,
        max_attempts=1,
        workflow_id="wf_unknown",
        workflow_run_key="unknown_v1",
        correlation_id="corr_unknown",
    )
