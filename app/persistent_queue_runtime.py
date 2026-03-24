from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.queue_contracts import QueueFailureCode, QueueStatus


@dataclass(frozen=True)
class PersistentQueueResult:
    ok: bool
    code: str
    message: str
    payload: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_persistent_queue_schema(db_path: str | Path) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_queue (
                queue_item_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT,
                claimed_by_worker TEXT,
                claimed_at TEXT,
                last_error_code TEXT,
                last_error_message TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dead_letter_queue (
                dead_letter_id INTEGER PRIMARY KEY AUTOINCREMENT,
                queue_item_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                from_status TEXT NOT NULL,
                to_status TEXT NOT NULL,
                failure_code TEXT NOT NULL,
                failure_message TEXT NOT NULL,
                replayable INTEGER NOT NULL DEFAULT 1,
                replayed_at TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_persistent_queue_item(db_path: str | Path, item: Mapping[str, Any]) -> PersistentQueueResult:
    required = ("queue_item_id", "task_id", "task_type", "status")
    for field in required:
        if field not in item:
            return PersistentQueueResult(
                False,
                QueueFailureCode.MALFORMED_QUEUE_ITEM.value,
                f"Queue item must contain '{field}'.",
                {"field": field},
            )

    now = _utc_now()
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO task_queue (
                queue_item_id, task_id, task_type, status, payload_json,
                claimed_by_worker, claimed_at, last_error_code, last_error_message,
                retry_count, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item["queue_item_id"],
                item["task_id"],
                item["task_type"],
                item["status"],
                item.get("payload_json"),
                item.get("claimed_by_worker"),
                item.get("claimed_at"),
                item.get("last_error_code"),
                item.get("last_error_message"),
                int(item.get("retry_count", 0)),
                now,
                now,
            ),
        )
        conn.commit()
        return PersistentQueueResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Persistent queue item inserted.",
            {
                "queue_item_id": item["queue_item_id"],
                "task_id": item["task_id"],
                "status": item["status"],
            },
        )
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        return PersistentQueueResult(
            False,
            QueueFailureCode.MALFORMED_QUEUE_ITEM.value,
            f"Persistent queue insert failed: {exc}",
            {"queue_item_id": item.get("queue_item_id")},
        )
    finally:
        conn.close()


def get_persistent_queue_item(db_path: str | Path, queue_item_id: str) -> dict[str, Any] | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT queue_item_id, task_id, task_type, status, payload_json,
                   claimed_by_worker, claimed_at, last_error_code, last_error_message,
                   retry_count, created_at, updated_at
            FROM task_queue
            WHERE queue_item_id = ?
            """,
            (queue_item_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def claim_next_queued_item(db_path: str | Path, worker_id: str) -> PersistentQueueResult:
    if not isinstance(worker_id, str) or not worker_id.strip():
        return PersistentQueueResult(
            False,
            QueueFailureCode.CLAIM_CONFLICT.value,
            "worker_id must be a non-empty string.",
            {"field": "worker_id"},
        )

    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT queue_item_id, task_id, task_type, status
            FROM task_queue
            WHERE status = ?
            ORDER BY created_at, queue_item_id
            LIMIT 1
            """,
            (QueueStatus.QUEUED.value,),
        ).fetchone()

        if row is None:
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.CLAIM_CONFLICT.value,
                "No queued item is available for claim.",
                None,
            )

        now = _utc_now()
        conn.execute(
            """
            UPDATE task_queue
            SET status = ?, claimed_by_worker = ?, claimed_at = ?, updated_at = ?
            WHERE queue_item_id = ? AND status = ?
            """,
            (
                QueueStatus.CLAIMED.value,
                worker_id,
                now,
                now,
                row["queue_item_id"],
                QueueStatus.QUEUED.value,
            ),
        )

        if conn.total_changes < 1:
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.CLAIM_CONFLICT.value,
                "Queue item claim lost the race.",
                {"queue_item_id": row["queue_item_id"]},
            )

        conn.commit()
        return PersistentQueueResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Queued item claimed from persistent DB.",
            {
                "queue_item_id": row["queue_item_id"],
                "task_id": row["task_id"],
                "task_type": row["task_type"],
                "from_status": QueueStatus.QUEUED.value,
                "to_status": QueueStatus.CLAIMED.value,
                "claimed_by_worker": worker_id,
            },
        )
    finally:
        conn.close()


def transition_persistent_item(
    db_path: str | Path,
    queue_item_id: str,
    from_status: str,
    to_status: str,
) -> PersistentQueueResult:
    allowed: dict[str, set[str]] = {
        QueueStatus.CLAIMED.value: {QueueStatus.RUNNING.value, QueueStatus.FAILED.value, QueueStatus.DEAD_LETTERED.value},
        QueueStatus.RUNNING.value: {QueueStatus.COMPLETED.value, QueueStatus.FAILED.value, QueueStatus.DEAD_LETTERED.value},
        QueueStatus.FAILED.value: {QueueStatus.DEAD_LETTERED.value},
    }

    if from_status not in allowed or to_status not in allowed[from_status]:
        return PersistentQueueResult(
            False,
            QueueFailureCode.INVALID_STATE_TRANSITION.value,
            "Persistent queue transition is not allowed.",
            {
                "queue_item_id": queue_item_id,
                "from_status": from_status,
                "to_status": to_status,
            },
        )

    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        now = _utc_now()
        conn.execute(
            """
            UPDATE task_queue
            SET status = ?, updated_at = ?
            WHERE queue_item_id = ? AND status = ?
            """,
            (to_status, now, queue_item_id, from_status),
        )
        if conn.total_changes < 1:
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.INVALID_STATE_TRANSITION.value,
                "Persistent queue transition precondition failed.",
                {
                    "queue_item_id": queue_item_id,
                    "from_status": from_status,
                    "to_status": to_status,
                },
            )
        conn.commit()
        return PersistentQueueResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Persistent queue item transitioned.",
            {
                "queue_item_id": queue_item_id,
                "from_status": from_status,
                "to_status": to_status,
            },
        )
    finally:
        conn.close()


def dead_letter_persistent_item(
    db_path: str | Path,
    queue_item_id: str,
    failure_code: str,
    failure_message: str,
    *,
    replayable: bool = True,
) -> PersistentQueueResult:
    if not isinstance(failure_code, str) or not failure_code.strip():
        return PersistentQueueResult(
            False,
            QueueFailureCode.DEAD_LETTER_INVALID.value,
            "failure_code must be a non-empty string.",
            {"field": "failure_code"},
        )
    if not isinstance(failure_message, str) or not failure_message.strip():
        return PersistentQueueResult(
            False,
            QueueFailureCode.DEAD_LETTER_INVALID.value,
            "failure_message must be a non-empty string.",
            {"field": "failure_message"},
        )

    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT queue_item_id, task_id, task_type, status
            FROM task_queue
            WHERE queue_item_id = ?
            """,
            (queue_item_id,),
        ).fetchone()

        if row is None:
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.DEAD_LETTER_INVALID.value,
                "Queue item does not exist for dead-lettering.",
                {"queue_item_id": queue_item_id},
            )

        if row["status"] not in (QueueStatus.FAILED.value, QueueStatus.CLAIMED.value, QueueStatus.RUNNING.value, QueueStatus.QUEUED.value):
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.DEAD_LETTER_INVALID.value,
                "Queue item is not in a dead-letter eligible state.",
                {"queue_item_id": queue_item_id, "status": row["status"]},
            )

        now = _utc_now()
        conn.execute(
            """
            INSERT INTO dead_letter_queue (
                queue_item_id, task_id, task_type, from_status, to_status,
                failure_code, failure_message, replayable, replayed_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["queue_item_id"],
                row["task_id"],
                row["task_type"],
                row["status"],
                QueueStatus.DEAD_LETTERED.value,
                failure_code,
                failure_message,
                1 if replayable else 0,
                None,
                now,
            ),
        )
        conn.execute(
            """
            UPDATE task_queue
            SET status = ?, last_error_code = ?, last_error_message = ?, updated_at = ?
            WHERE queue_item_id = ?
            """,
            (
                QueueStatus.DEAD_LETTERED.value,
                failure_code,
                failure_message,
                now,
                queue_item_id,
            ),
        )
        conn.commit()
        return PersistentQueueResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Persistent queue item moved to dead-letter.",
            {
                "queue_item_id": queue_item_id,
                "failure_code": failure_code,
                "failure_message": failure_message,
                "to_status": QueueStatus.DEAD_LETTERED.value,
                "replayable": replayable,
            },
        )
    finally:
        conn.close()


def replay_dead_letter_item(db_path: str | Path, queue_item_id: str) -> PersistentQueueResult:
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        item = conn.execute(
            """
            SELECT queue_item_id, status, retry_count
            FROM task_queue
            WHERE queue_item_id = ?
            """,
            (queue_item_id,),
        ).fetchone()

        if item is None:
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.DEAD_LETTER_INVALID.value,
                "Queue item does not exist for replay.",
                {"queue_item_id": queue_item_id},
            )

        if item["status"] != QueueStatus.DEAD_LETTERED.value:
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.INVALID_STATE_TRANSITION.value,
                "Replay is only allowed from dead_lettered state.",
                {"queue_item_id": queue_item_id, "status": item["status"]},
            )

        dlq = conn.execute(
            """
            SELECT dead_letter_id, replayable, failure_code, failure_message
            FROM dead_letter_queue
            WHERE queue_item_id = ? AND replayed_at IS NULL
            ORDER BY dead_letter_id DESC
            LIMIT 1
            """,
            (queue_item_id,),
        ).fetchone()

        if dlq is None:
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.DEAD_LETTER_INVALID.value,
                "Replay requires unresolved dead-letter context.",
                {"queue_item_id": queue_item_id},
            )

        if int(dlq["replayable"]) != 1:
            conn.rollback()
            return PersistentQueueResult(
                False,
                QueueFailureCode.DEAD_LETTER_INVALID.value,
                "Dead-letter item is not replayable.",
                {"queue_item_id": queue_item_id},
            )

        now = _utc_now()
        conn.execute(
            """
            UPDATE task_queue
            SET status = ?, claimed_by_worker = NULL, claimed_at = NULL,
                retry_count = retry_count + 1, updated_at = ?
            WHERE queue_item_id = ?
            """,
            (QueueStatus.QUEUED.value, now, queue_item_id),
        )
        conn.execute(
            """
            UPDATE dead_letter_queue
            SET replayed_at = ?
            WHERE dead_letter_id = ?
            """,
            (now, dlq["dead_letter_id"]),
        )
        conn.commit()
        return PersistentQueueResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Dead-letter item replayed to queued state.",
            {
                "queue_item_id": queue_item_id,
                "to_status": QueueStatus.QUEUED.value,
                "retry_count_incremented": True,
            },
        )
    finally:
        conn.close()


def count_persistent_dead_letters(db_path: str | Path) -> int:
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT COUNT(*) FROM dead_letter_queue").fetchone()
        return int(row[0])
    finally:
        conn.close()
