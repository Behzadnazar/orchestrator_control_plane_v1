from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.queue_contracts import (
    QueueFailureCode,
    QueueStatus,
    build_dead_letter_record,
    validate_claim_attempt,
    validate_queue_item,
    validate_state_transition,
)


@dataclass(frozen=True)
class QueueRuntimeResult:
    ok: bool
    code: str
    message: str
    payload: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_queue_schema(db_path: str | Path) -> None:
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS task_queue (
                queue_item_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                status TEXT NOT NULL,
                claimed_by_worker TEXT
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
                failure_message TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_queue_item(db_path: str | Path, item: Mapping[str, Any]) -> QueueRuntimeResult:
    decision = validate_queue_item(item)
    if not decision.accepted:
        return QueueRuntimeResult(False, decision.code, decision.message, decision.to_dict())

    conn = sqlite3.connect(str(db_path), timeout=2.0)
    try:
        conn.execute(
            """
            INSERT INTO task_queue (queue_item_id, task_id, task_type, status, claimed_by_worker)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                item["queue_item_id"],
                item["task_id"],
                item["task_type"],
                item["status"],
                item.get("claimed_by_worker"),
            ),
        )
        conn.commit()
        return QueueRuntimeResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Queue item inserted.",
            {
                "queue_item_id": item["queue_item_id"],
                "task_id": item["task_id"],
                "status": item["status"],
            },
        )
    finally:
        conn.close()


def get_queue_item(db_path: str | Path, queue_item_id: str) -> dict[str, Any] | None:
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT queue_item_id, task_id, task_type, status, claimed_by_worker
            FROM task_queue
            WHERE queue_item_id = ?
            """,
            (queue_item_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def claim_queue_item(db_path: str | Path, queue_item_id: str, worker_id: str) -> QueueRuntimeResult:
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT queue_item_id, task_id, task_type, status, claimed_by_worker
            FROM task_queue
            WHERE queue_item_id = ?
            """,
            (queue_item_id,),
        ).fetchone()

        if row is None:
            conn.rollback()
            return QueueRuntimeResult(
                False,
                QueueFailureCode.MALFORMED_QUEUE_ITEM.value,
                "Queue item does not exist.",
                {
                    "queue_item_id": queue_item_id,
                },
            )

        item = dict(row)
        decision = validate_claim_attempt(
            item,
            worker_id,
            already_claimed_by=item.get("claimed_by_worker"),
        )
        if not decision.accepted:
            conn.rollback()
            return QueueRuntimeResult(False, decision.code, decision.message, decision.to_dict())

        conn.execute(
            """
            UPDATE task_queue
            SET status = ?, claimed_by_worker = ?
            WHERE queue_item_id = ?
            """,
            (QueueStatus.CLAIMED.value, worker_id, queue_item_id),
        )
        conn.commit()
        return QueueRuntimeResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Queue item claimed.",
            {
                "queue_item_id": queue_item_id,
                "task_id": item["task_id"],
                "from_status": item["status"],
                "to_status": QueueStatus.CLAIMED.value,
                "claimed_by_worker": worker_id,
            },
        )
    finally:
        conn.close()


def transition_queue_item(db_path: str | Path, queue_item_id: str, to_status: str) -> QueueRuntimeResult:
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT queue_item_id, task_id, task_type, status, claimed_by_worker
            FROM task_queue
            WHERE queue_item_id = ?
            """,
            (queue_item_id,),
        ).fetchone()

        if row is None:
            conn.rollback()
            return QueueRuntimeResult(
                False,
                QueueFailureCode.MALFORMED_QUEUE_ITEM.value,
                "Queue item does not exist.",
                {"queue_item_id": queue_item_id},
            )

        item = dict(row)
        decision = validate_state_transition(item, to_status)
        if not decision.accepted:
            conn.rollback()
            return QueueRuntimeResult(False, decision.code, decision.message, decision.to_dict())

        conn.execute(
            """
            UPDATE task_queue
            SET status = ?
            WHERE queue_item_id = ?
            """,
            (to_status, queue_item_id),
        )
        conn.commit()
        return QueueRuntimeResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Queue item transitioned.",
            {
                "queue_item_id": queue_item_id,
                "task_id": item["task_id"],
                "from_status": item["status"],
                "to_status": to_status,
            },
        )
    finally:
        conn.close()


def dead_letter_queue_item(
    db_path: str | Path,
    queue_item_id: str,
    failure_code: str,
    failure_message: str,
) -> QueueRuntimeResult:
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT queue_item_id, task_id, task_type, status, claimed_by_worker
            FROM task_queue
            WHERE queue_item_id = ?
            """,
            (queue_item_id,),
        ).fetchone()

        if row is None:
            conn.rollback()
            return QueueRuntimeResult(
                False,
                QueueFailureCode.DEAD_LETTER_INVALID.value,
                "Queue item does not exist for dead-lettering.",
                {"queue_item_id": queue_item_id},
            )

        item = dict(row)

        try:
            record = build_dead_letter_record(item, failure_code, failure_message)
        except Exception as exc:
            conn.rollback()
            return QueueRuntimeResult(
                False,
                QueueFailureCode.DEAD_LETTER_INVALID.value,
                f"Dead-letter normalization failed: {exc}",
                {"queue_item_id": queue_item_id},
            )

        conn.execute(
            """
            INSERT INTO dead_letter_queue (
                queue_item_id, task_id, task_type, from_status, to_status, failure_code, failure_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["queue_item_id"],
                record["task_id"],
                record["task_type"],
                record["from_status"],
                record["to_status"],
                record["failure_code"],
                record["failure_message"],
            ),
        )

        conn.execute(
            """
            UPDATE task_queue
            SET status = ?
            WHERE queue_item_id = ?
            """,
            (QueueStatus.DEAD_LETTERED.value, queue_item_id),
        )
        conn.commit()

        return QueueRuntimeResult(
            True,
            QueueFailureCode.ACCEPTED.value,
            "Queue item moved to dead-letter queue.",
            record,
        )
    finally:
        conn.close()


def count_dead_letters(db_path: str | Path) -> int:
    conn = sqlite3.connect(str(db_path), timeout=2.0)
    try:
        row = conn.execute("SELECT COUNT(*) FROM dead_letter_queue").fetchone()
        return int(row[0])
    finally:
        conn.close()
