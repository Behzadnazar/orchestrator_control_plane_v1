from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class QueueFailureCode(StrEnum):
    MALFORMED_QUEUE_ITEM = "MALFORMED_QUEUE_ITEM"
    MISSING_QUEUE_ITEM_ID = "MISSING_QUEUE_ITEM_ID"
    INVALID_QUEUE_ITEM_ID = "INVALID_QUEUE_ITEM_ID"
    MISSING_TASK_ID = "MISSING_TASK_ID"
    INVALID_TASK_ID = "INVALID_TASK_ID"
    MISSING_TASK_TYPE = "MISSING_TASK_TYPE"
    INVALID_TASK_TYPE = "INVALID_TASK_TYPE"
    INVALID_STATUS = "INVALID_STATUS"
    CLAIM_CONFLICT = "CLAIM_CONFLICT"
    DUPLICATE_CLAIM = "DUPLICATE_CLAIM"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    DEAD_LETTER_REQUIRED = "DEAD_LETTER_REQUIRED"
    DEAD_LETTER_INVALID = "DEAD_LETTER_INVALID"
    ACCEPTED = "ACCEPTED"


class QueueStatus(StrEnum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTERED = "dead_lettered"


ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    QueueStatus.QUEUED.value: {QueueStatus.CLAIMED.value, QueueStatus.DEAD_LETTERED.value},
    QueueStatus.CLAIMED.value: {QueueStatus.RUNNING.value, QueueStatus.FAILED.value, QueueStatus.DEAD_LETTERED.value},
    QueueStatus.RUNNING.value: {QueueStatus.COMPLETED.value, QueueStatus.FAILED.value, QueueStatus.DEAD_LETTERED.value},
    QueueStatus.FAILED.value: {QueueStatus.DEAD_LETTERED.value},
    QueueStatus.COMPLETED.value: set(),
    QueueStatus.DEAD_LETTERED.value: set(),
}


@dataclass(frozen=True)
class QueueViolation:
    code: str
    message: str
    field: str | None = None


@dataclass(frozen=True)
class QueueDecision:
    accepted: bool
    code: str
    message: str
    queue_item_id: str | None = None
    task_id: str | None = None
    from_status: str | None = None
    to_status: str | None = None
    violations: tuple[QueueViolation, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "code": self.code,
            "message": self.message,
            "queue_item_id": self.queue_item_id,
            "task_id": self.task_id,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "violations": [asdict(item) for item in self.violations],
        }


def _decision(
    accepted: bool,
    code: QueueFailureCode,
    message: str,
    *,
    queue_item_id: str | None = None,
    task_id: str | None = None,
    from_status: str | None = None,
    to_status: str | None = None,
    field: str | None = None,
) -> QueueDecision:
    violations: tuple[QueueViolation, ...]
    if accepted:
        violations = ()
    else:
        violations = (QueueViolation(code=code.value, message=message, field=field),)

    return QueueDecision(
        accepted=accepted,
        code=code.value,
        message=message,
        queue_item_id=queue_item_id,
        task_id=task_id,
        from_status=from_status,
        to_status=to_status,
        violations=violations,
    )


def validate_queue_item(item: Any) -> QueueDecision:
    if not isinstance(item, Mapping):
        return _decision(
            False,
            QueueFailureCode.MALFORMED_QUEUE_ITEM,
            "Queue item must be a mapping.",
        )

    queue_item_id = item.get("queue_item_id")
    task_id = item.get("task_id")
    task_type = item.get("task_type")
    status = item.get("status")

    if "queue_item_id" not in item:
        return _decision(False, QueueFailureCode.MISSING_QUEUE_ITEM_ID, "Queue item must contain 'queue_item_id'.", field="queue_item_id")
    if not isinstance(queue_item_id, str) or not queue_item_id.strip():
        return _decision(False, QueueFailureCode.INVALID_QUEUE_ITEM_ID, "Queue item field 'queue_item_id' must be a non-empty string.", field="queue_item_id")

    if "task_id" not in item:
        return _decision(False, QueueFailureCode.MISSING_TASK_ID, "Queue item must contain 'task_id'.", queue_item_id=queue_item_id, field="task_id")
    if not isinstance(task_id, str) or not task_id.strip():
        return _decision(False, QueueFailureCode.INVALID_TASK_ID, "Queue item field 'task_id' must be a non-empty string.", queue_item_id=queue_item_id, field="task_id")

    if "task_type" not in item:
        return _decision(False, QueueFailureCode.MISSING_TASK_TYPE, "Queue item must contain 'task_type'.", queue_item_id=queue_item_id, task_id=task_id, field="task_type")
    if not isinstance(task_type, str) or not task_type.strip():
        return _decision(False, QueueFailureCode.INVALID_TASK_TYPE, "Queue item field 'task_type' must be a non-empty string.", queue_item_id=queue_item_id, task_id=task_id, field="task_type")

    if "status" not in item:
        return _decision(False, QueueFailureCode.INVALID_STATUS, "Queue item must contain 'status'.", queue_item_id=queue_item_id, task_id=task_id, field="status")
    if status not in ALLOWED_TRANSITIONS:
        return _decision(False, QueueFailureCode.INVALID_STATUS, "Queue item field 'status' must be a known queue status.", queue_item_id=queue_item_id, task_id=task_id, field="status")

    return _decision(
        True,
        QueueFailureCode.ACCEPTED,
        "Queue item accepted.",
        queue_item_id=queue_item_id,
        task_id=task_id,
    )


def validate_claim_attempt(item: Any, worker_id: Any, *, already_claimed_by: str | None = None) -> QueueDecision:
    item_decision = validate_queue_item(item)
    if not item_decision.accepted:
        return item_decision

    queue_item_id = item["queue_item_id"]
    task_id = item["task_id"]
    status = item["status"]

    if not isinstance(worker_id, str) or not worker_id.strip():
        return _decision(
            False,
            QueueFailureCode.CLAIM_CONFLICT,
            "Worker identifier must be a non-empty string.",
            queue_item_id=queue_item_id,
            task_id=task_id,
            field="claimed_by_worker",
        )

    if status != QueueStatus.QUEUED.value:
        if status == QueueStatus.CLAIMED.value and already_claimed_by == worker_id:
            return _decision(
                False,
                QueueFailureCode.DUPLICATE_CLAIM,
                "Queue item is already claimed by the same worker.",
                queue_item_id=queue_item_id,
                task_id=task_id,
                from_status=status,
                to_status=QueueStatus.CLAIMED.value,
                field="status",
            )

        return _decision(
            False,
            QueueFailureCode.CLAIM_CONFLICT,
            "Only queued items can be claimed.",
            queue_item_id=queue_item_id,
            task_id=task_id,
            from_status=status,
            to_status=QueueStatus.CLAIMED.value,
            field="status",
        )

    if already_claimed_by and already_claimed_by != worker_id:
        return _decision(
            False,
            QueueFailureCode.CLAIM_CONFLICT,
            "Queue item is already claimed by another worker.",
            queue_item_id=queue_item_id,
            task_id=task_id,
            from_status=status,
            to_status=QueueStatus.CLAIMED.value,
            field="claimed_by_worker",
        )

    return _decision(
        True,
        QueueFailureCode.ACCEPTED,
        "Claim accepted.",
        queue_item_id=queue_item_id,
        task_id=task_id,
        from_status=QueueStatus.QUEUED.value,
        to_status=QueueStatus.CLAIMED.value,
    )


def validate_state_transition(item: Any, to_status: Any) -> QueueDecision:
    item_decision = validate_queue_item(item)
    if not item_decision.accepted:
        return item_decision

    queue_item_id = item["queue_item_id"]
    task_id = item["task_id"]
    from_status = item["status"]

    if not isinstance(to_status, str) or to_status not in ALLOWED_TRANSITIONS:
        return _decision(
            False,
            QueueFailureCode.INVALID_STATE_TRANSITION,
            "Target status must be a known queue status.",
            queue_item_id=queue_item_id,
            task_id=task_id,
            from_status=from_status,
            to_status=str(to_status),
            field="to_status",
        )

    if to_status not in ALLOWED_TRANSITIONS[from_status]:
        return _decision(
            False,
            QueueFailureCode.INVALID_STATE_TRANSITION,
            "State transition is not allowed.",
            queue_item_id=queue_item_id,
            task_id=task_id,
            from_status=from_status,
            to_status=to_status,
            field="to_status",
        )

    return _decision(
        True,
        QueueFailureCode.ACCEPTED,
        "State transition accepted.",
        queue_item_id=queue_item_id,
        task_id=task_id,
        from_status=from_status,
        to_status=to_status,
    )


def build_dead_letter_record(item: Any, failure_code: Any, failure_message: Any) -> dict[str, Any]:
    item_decision = validate_queue_item(item)
    if not item_decision.accepted:
        raise ValueError(item_decision.message)

    transition_decision = validate_state_transition(item, QueueStatus.DEAD_LETTERED.value)
    if not transition_decision.accepted:
        raise ValueError(transition_decision.message)

    if not isinstance(failure_code, str) or not failure_code.strip():
        raise ValueError("Dead-letter failure_code must be a non-empty string.")

    if not isinstance(failure_message, str) or not failure_message.strip():
        raise ValueError("Dead-letter failure_message must be a non-empty string.")

    return {
        "queue_item_id": item["queue_item_id"],
        "task_id": item["task_id"],
        "task_type": item["task_type"],
        "from_status": item["status"],
        "to_status": QueueStatus.DEAD_LETTERED.value,
        "failure_code": failure_code,
        "failure_message": failure_message,
        "dead_letter_reason": {
            "code": failure_code,
            "message": failure_message,
        },
    }
