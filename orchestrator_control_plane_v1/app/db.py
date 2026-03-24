from __future__ import annotations
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from .config import DB_PATH
from .models import PRIORITY_SCORE, LifecycleState

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                agent_type TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                allowed_tools_json TEXT NOT NULL,
                status TEXT NOT NULL,
                last_activity TEXT,
                current_task_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                parent_task_id TEXT,
                task_type TEXT NOT NULL,
                title TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                done_criteria_json TEXT NOT NULL,
                assigned_agent_id TEXT,
                attempt_no INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 2,
                requires_human INTEGER NOT NULL DEFAULT 0,
                review_status TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                approver TEXT,
                decision TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_locks (
                lock_id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL UNIQUE,
                owner_task_id TEXT NOT NULL,
                owner_agent_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )

def append_event(entity_type: str, entity_id: str, event_type: str, data: dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO events (event_id, entity_type, entity_id, event_type, data_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), entity_type, entity_id, event_type, json.dumps(data, ensure_ascii=False), utc_now()),
        )

def upsert_agent(agent: dict[str, Any]) -> None:
    now = utc_now()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO agents (
                agent_id, agent_type, capabilities_json, allowed_tools_json, status,
                last_activity, current_task_id, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                agent_type=excluded.agent_type,
                capabilities_json=excluded.capabilities_json,
                allowed_tools_json=excluded.allowed_tools_json,
                status=excluded.status,
                last_activity=excluded.last_activity,
                current_task_id=excluded.current_task_id,
                updated_at=excluded.updated_at
            """,
            (
                agent["agent_id"],
                agent["agent_type"],
                json.dumps(agent["capabilities"], ensure_ascii=False),
                json.dumps(agent["allowed_tools"], ensure_ascii=False),
                agent["status"],
                agent.get("last_activity"),
                agent.get("current_task_id"),
                now,
                now,
            ),
        )

def get_agent(agent_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return row_to_agent(row) if row else None

def row_to_agent(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "agent_id": row["agent_id"],
        "agent_type": row["agent_type"],
        "capabilities": json.loads(row["capabilities_json"]),
        "allowed_tools": json.loads(row["allowed_tools_json"]),
        "status": row["status"],
        "last_activity": row["last_activity"],
        "current_task_id": row["current_task_id"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }

def list_agents() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY agent_type, agent_id").fetchall()
        return [row_to_agent(r) for r in rows]

def update_agent_status(agent_id: str, status: str, current_task_id: str | None = None) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE agents SET status=?, current_task_id=?, last_activity=?, updated_at=? WHERE agent_id=?",
            (status, current_task_id, utc_now(), utc_now(), agent_id),
        )

def create_task(
    task_type: str,
    title: str,
    priority: str,
    payload: dict[str, Any],
    done_criteria: list[dict[str, Any]],
    max_retries: int = 2,
    parent_task_id: str | None = None,
    attempt_no: int = 0,
    requires_human: bool = False,
) -> str:
    task_id = str(uuid.uuid4())
    now = utc_now()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO tasks (
                task_id, parent_task_id, task_type, title, priority, status, payload_json,
                done_criteria_json, assigned_agent_id, attempt_no, max_retries, requires_human,
                review_status, last_error, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task_id,
                parent_task_id,
                task_type,
                title,
                priority,
                LifecycleState.IDLE.value,
                json.dumps(payload, ensure_ascii=False),
                json.dumps(done_criteria, ensure_ascii=False),
                None,
                attempt_no,
                max_retries,
                1 if requires_human else 0,
                None,
                None,
                now,
                now,
            ),
        )
    return task_id

def get_task(task_id: str) -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        return row_to_task(row) if row else None

def row_to_task(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "task_id": row["task_id"],
        "parent_task_id": row["parent_task_id"],
        "task_type": row["task_type"],
        "title": row["title"],
        "priority": row["priority"],
        "status": row["status"],
        "payload": json.loads(row["payload_json"]),
        "done_criteria": json.loads(row["done_criteria_json"]),
        "assigned_agent_id": row["assigned_agent_id"],
        "attempt_no": row["attempt_no"],
        "max_retries": row["max_retries"],
        "requires_human": bool(row["requires_human"]),
        "review_status": row["review_status"],
        "last_error": row["last_error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }

def list_tasks() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()
        return [row_to_task(r) for r in rows]

def update_task(
    task_id: str,
    *,
    status: str | None = None,
    assigned_agent_id: str | None = None,
    review_status: str | None = None,
    last_error: str | None = None,
) -> None:
    with connect() as conn:
        current = get_task(task_id)
        if not current:
            raise ValueError(f"task not found: {task_id}")
        conn.execute(
            """
            UPDATE tasks
            SET status=?, assigned_agent_id=?, review_status=?, last_error=?, updated_at=?
            WHERE task_id=?
            """,
            (
                status if status is not None else current["status"],
                assigned_agent_id if assigned_agent_id is not None else current["assigned_agent_id"],
                review_status if review_status is not None else current["review_status"],
                last_error if last_error is not None else current["last_error"],
                utc_now(),
                task_id,
            ),
        )

def next_runnable_task() -> Optional[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM tasks WHERE status=?", (LifecycleState.IDLE.value,)).fetchall()
        tasks = [row_to_task(r) for r in rows]
        if not tasks:
            return None
        tasks.sort(key=lambda t: (-PRIORITY_SCORE.get(t["priority"], 0), t["created_at"]))
        return tasks[0]

def create_approval(task_id: str, operation: str, approver: str, decision: str, reason: str | None) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO approvals (approval_id, task_id, operation, approver, decision, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), task_id, operation, approver, decision, reason, utc_now()),
        )

def latest_approval(task_id: str, operation: str = "review") -> Optional[dict[str, Any]]:
    with connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM approvals
            WHERE task_id=? AND operation=?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (task_id, operation),
        ).fetchone()
        return dict(row) if row else None

def acquire_file_locks(task_id: str, agent_id: str, file_paths: Iterable[str]) -> tuple[bool, list[str]]:
    conflicts: list[str] = []
    normalized = [p.strip() for p in file_paths if p and p.strip()]
    with connect() as conn:
        for path in normalized:
            existing = conn.execute("SELECT * FROM file_locks WHERE file_path=?", (path,)).fetchone()
            if existing and existing["owner_task_id"] != task_id:
                conflicts.append(path)
        if conflicts:
            return False, conflicts
        for path in normalized:
            conn.execute(
                """
                INSERT OR REPLACE INTO file_locks (lock_id, file_path, owner_task_id, owner_agent_id, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(uuid.uuid4()), path, task_id, agent_id, utc_now()),
            )
    return True, []

def release_file_locks(task_id: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM file_locks WHERE owner_task_id=?", (task_id,))
