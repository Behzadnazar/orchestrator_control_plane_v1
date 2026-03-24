from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.execution_contracts import FailureCode
from app.executor_runtime import execute_handler_with_contract
from app.persistent_queue_runtime import (
    claim_next_queued_item,
    dead_letter_persistent_item,
    get_persistent_queue_item,
    transition_persistent_item,
)


@dataclass(frozen=True)
class WorkerLoopResult:
    ok: bool
    code: str
    message: str
    payload: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def process_one_queue_item(
    db_path: str | Path,
    worker_id: str,
    handler: Callable[[dict[str, Any]], Any],
    *,
    payload_factory: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> WorkerLoopResult:
    claimed = claim_next_queued_item(db_path, worker_id)
    if not claimed.ok:
        return WorkerLoopResult(claimed.ok, claimed.code, claimed.message, claimed.payload)

    queue_item_id = claimed.payload["queue_item_id"]
    item = get_persistent_queue_item(db_path, queue_item_id)
    if item is None:
        return WorkerLoopResult(
            False,
            FailureCode.INTERNAL_ERROR.value,
            "Claimed queue item disappeared.",
            {"queue_item_id": queue_item_id},
        )

    moved_to_running = transition_persistent_item(db_path, queue_item_id, "claimed", "running")
    if not moved_to_running.ok:
        return WorkerLoopResult(
            False,
            moved_to_running.code,
            moved_to_running.message,
            moved_to_running.payload,
        )

    if payload_factory is None:
        payload = {
            "task_type": item["task_type"],
            "input": {"queue_item_id": item["queue_item_id"], "task_id": item["task_id"]},
        }
    else:
        payload = payload_factory(item)

    executed = execute_handler_with_contract(payload, handler, handler_name=getattr(handler, "__name__", "handler"))

    if executed.ok:
        moved_to_completed = transition_persistent_item(db_path, queue_item_id, "running", "completed")
        if not moved_to_completed.ok:
            return WorkerLoopResult(
                False,
                moved_to_completed.code,
                moved_to_completed.message,
                moved_to_completed.payload,
            )
        return WorkerLoopResult(
            True,
            "OK",
            "Worker loop processed queue item successfully.",
            {
                "queue_item_id": queue_item_id,
                "execution_result": executed.to_dict(),
                "final_transition": moved_to_completed.to_dict(),
            },
        )

    moved_to_failed = transition_persistent_item(db_path, queue_item_id, "running", "failed")
    if not moved_to_failed.ok:
        return WorkerLoopResult(
            False,
            moved_to_failed.code,
            moved_to_failed.message,
            moved_to_failed.payload,
        )

    dlq = dead_letter_persistent_item(
        db_path,
        queue_item_id,
        executed.code,
        executed.message or "execution failure",
        replayable=True,
    )
    return WorkerLoopResult(
        False,
        executed.code,
        "Worker loop processed queue item with failure and dead-lettered it.",
        {
            "queue_item_id": queue_item_id,
            "execution_result": executed.to_dict(),
            "failed_transition": moved_to_failed.to_dict(),
            "dead_letter_result": dlq.to_dict(),
        },
    )


def reject_transition_bypass(
    db_path: str | Path,
    queue_item_id: str,
    requested_from_status: str,
    requested_to_status: str,
) -> WorkerLoopResult:
    result = transition_persistent_item(db_path, queue_item_id, requested_from_status, requested_to_status)
    return WorkerLoopResult(result.ok, result.code, result.message, result.payload)
