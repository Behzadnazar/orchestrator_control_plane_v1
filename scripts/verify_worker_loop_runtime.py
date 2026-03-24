#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "artifacts" / "test_reports"


def ensure_project_root_on_syspath() -> None:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


ensure_project_root_on_syspath()

from app.persistent_queue_runtime import (  # noqa: E402
    count_persistent_dead_letters,
    dead_letter_persistent_item,
    ensure_persistent_queue_schema,
    get_persistent_queue_item,
    insert_persistent_queue_item,
    replay_dead_letter_item,
)
from app.queue_contracts import QueueStatus  # noqa: E402
from app.worker_loop_runtime import process_one_queue_item, reject_transition_bypass  # noqa: E402


def ok_handler(payload: dict) -> dict:
    return {
        "status": "completed",
        "details": {"received": sorted(payload.keys())},
        "artifacts": [],
    }


def bad_handler(_payload: dict) -> dict:
    return {
        "details": {"missing": "status"},
        "artifacts": [],
    }


def main() -> int:
    os.chdir(PROJECT_ROOT)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "persistent_queue.sqlite3"
        ensure_persistent_queue_schema(db_path)

        inserted_ok = insert_persistent_queue_item(
            db_path,
            {
                "queue_item_id": "pq-1",
                "task_id": "pt-1",
                "task_type": "backend.test",
                "status": QueueStatus.QUEUED.value,
            },
        ).to_dict()

        worker_ok = process_one_queue_item(db_path, "worker-a", ok_handler).to_dict()
        final_ok_item = get_persistent_queue_item(db_path, "pq-1")

        inserted_bad = insert_persistent_queue_item(
            db_path,
            {
                "queue_item_id": "pq-2",
                "task_id": "pt-2",
                "task_type": "backend.test",
                "status": QueueStatus.QUEUED.value,
            },
        ).to_dict()

        worker_bad = process_one_queue_item(db_path, "worker-b", bad_handler).to_dict()
        final_bad_item = get_persistent_queue_item(db_path, "pq-2")
        replay_bad = replay_dead_letter_item(db_path, "pq-2").to_dict()
        replayed_bad_item = get_persistent_queue_item(db_path, "pq-2")
        invalid_replay_state = replay_dead_letter_item(db_path, "pq-1").to_dict()
        bypass_rejected = reject_transition_bypass(db_path, "pq-2", "queued", "completed").to_dict()

        inserted_contextless = insert_persistent_queue_item(
            db_path,
            {
                "queue_item_id": "pq-3",
                "task_id": "pt-3",
                "task_type": "backend.test",
                "status": QueueStatus.DEAD_LETTERED.value,
            },
        ).to_dict()
        replay_without_context = replay_dead_letter_item(db_path, "pq-3").to_dict()

        dead_letter_count = count_persistent_dead_letters(db_path)

        summary = {
            "phase": "J.6",
            "successful": (
                inserted_ok["ok"] is True
                and worker_ok["ok"] is True
                and final_ok_item is not None
                and final_ok_item["status"] == QueueStatus.COMPLETED.value
                and inserted_bad["ok"] is True
                and worker_bad["ok"] is False
                and final_bad_item is not None
                and final_bad_item["status"] == QueueStatus.DEAD_LETTERED.value
                and replay_bad["ok"] is True
                and replayed_bad_item is not None
                and replayed_bad_item["status"] == QueueStatus.QUEUED.value
                and invalid_replay_state["code"] == "INVALID_STATE_TRANSITION"
                and bypass_rejected["code"] == "INVALID_STATE_TRANSITION"
                and inserted_contextless["ok"] is True
                and replay_without_context["code"] == "DEAD_LETTER_INVALID"
                and dead_letter_count == 1
            ),
            "checks": {
                "inserted_ok": inserted_ok,
                "worker_ok": worker_ok,
                "final_ok_item": final_ok_item,
                "inserted_bad": inserted_bad,
                "worker_bad": worker_bad,
                "final_bad_item": final_bad_item,
                "replay_bad": replay_bad,
                "replayed_bad_item": replayed_bad_item,
                "invalid_replay_state": invalid_replay_state,
                "bypass_rejected": bypass_rejected,
                "inserted_contextless": inserted_contextless,
                "replay_without_context": replay_without_context,
                "dead_letter_count": dead_letter_count,
            },
        }

    json_path = REPORT_DIR / "latest_worker_loop_runtime.json"
    txt_path = REPORT_DIR / "latest_worker_loop_runtime.txt"

    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "phase=J.6",
        f"successful={summary['successful']}",
        f"worker_ok={summary['checks']['worker_ok']['ok']}",
        f"worker_bad_code={summary['checks']['worker_bad']['code']}",
        f"replay_bad_ok={summary['checks']['replay_bad']['ok']}",
        f"invalid_replay_state_code={summary['checks']['invalid_replay_state']['code']}",
        f"bypass_rejected_code={summary['checks']['bypass_rejected']['code']}",
        f"replay_without_context_code={summary['checks']['replay_without_context']['code']}",
        f"dead_letter_count={summary['checks']['dead_letter_count']}",
    ]
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
