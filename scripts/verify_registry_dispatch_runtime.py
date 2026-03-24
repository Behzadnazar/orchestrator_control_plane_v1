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
    ensure_persistent_queue_schema,
    get_persistent_queue_item,
    insert_persistent_queue_item,
)
from app.queue_contracts import QueueStatus  # noqa: E402
from app.registry_dispatch_runtime import dispatch_queue_item_via_registry  # noqa: E402


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
        db_path = Path(tmpdir) / "registry_dispatch.sqlite3"
        ensure_persistent_queue_schema(db_path)

        registry = {
            "backend.test": {"handler": "handle_backend_test"},
            "backend.fail_test": {"handler": "handle_backend_fail_test"},
            "backend.missing_handler": {"handler": "handle_missing_handler"},
        }
        handlers = {
            "handle_backend_test": ok_handler,
            "handle_backend_fail_test": bad_handler,
        }

        inserted_success = insert_persistent_queue_item(
            db_path,
            {
                "queue_item_id": "rd-1",
                "task_id": "rt-1",
                "task_type": "backend.test",
                "status": QueueStatus.QUEUED.value,
            },
        ).to_dict()
        dispatch_success = dispatch_queue_item_via_registry(
            db_path,
            "worker-a",
            registry_override=registry,
            handlers_override=handlers,
        ).to_dict()
        final_success_item = get_persistent_queue_item(db_path, "rd-1")

        inserted_unknown = insert_persistent_queue_item(
            db_path,
            {
                "queue_item_id": "rd-2",
                "task_id": "rt-2",
                "task_type": "backend.unknown_task",
                "status": QueueStatus.QUEUED.value,
            },
        ).to_dict()
        dispatch_unknown = dispatch_queue_item_via_registry(
            db_path,
            "worker-b",
            registry_override=registry,
            handlers_override=handlers,
        ).to_dict()
        final_unknown_item = get_persistent_queue_item(db_path, "rd-2")

        inserted_missing_handler = insert_persistent_queue_item(
            db_path,
            {
                "queue_item_id": "rd-3",
                "task_id": "rt-3",
                "task_type": "backend.missing_handler",
                "status": QueueStatus.QUEUED.value,
            },
        ).to_dict()
        dispatch_missing_handler = dispatch_queue_item_via_registry(
            db_path,
            "worker-c",
            registry_override=registry,
            handlers_override=handlers,
        ).to_dict()
        final_missing_handler_item = get_persistent_queue_item(db_path, "rd-3")

        inserted_failure = insert_persistent_queue_item(
            db_path,
            {
                "queue_item_id": "rd-4",
                "task_id": "rt-4",
                "task_type": "backend.fail_test",
                "status": QueueStatus.QUEUED.value,
            },
        ).to_dict()
        dispatch_failure = dispatch_queue_item_via_registry(
            db_path,
            "worker-d",
            registry_override=registry,
            handlers_override=handlers,
        ).to_dict()
        final_failure_item = get_persistent_queue_item(db_path, "rd-4")

        dead_letter_count = count_persistent_dead_letters(db_path)

        summary = {
            "phase": "J.7",
            "successful": (
                inserted_success["ok"] is True
                and dispatch_success["ok"] is True
                and final_success_item is not None
                and final_success_item["status"] == QueueStatus.COMPLETED.value
                and inserted_unknown["ok"] is True
                and dispatch_unknown["code"] == "UNKNOWN_TASK_TYPE"
                and final_unknown_item is not None
                and final_unknown_item["status"] == QueueStatus.DEAD_LETTERED.value
                and inserted_missing_handler["ok"] is True
                and dispatch_missing_handler["code"] == "HANDLER_NOT_CALLABLE"
                and final_missing_handler_item is not None
                and final_missing_handler_item["status"] == QueueStatus.DEAD_LETTERED.value
                and inserted_failure["ok"] is True
                and dispatch_failure["code"] == "HANDLER_RESULT_INVALID"
                and final_failure_item is not None
                and final_failure_item["status"] == QueueStatus.DEAD_LETTERED.value
                and final_failure_item["last_error_code"] == "HANDLER_RESULT_INVALID"
                and dead_letter_count == 3
            ),
            "checks": {
                "inserted_success": inserted_success,
                "dispatch_success": dispatch_success,
                "final_success_item": final_success_item,
                "inserted_unknown": inserted_unknown,
                "dispatch_unknown": dispatch_unknown,
                "final_unknown_item": final_unknown_item,
                "inserted_missing_handler": inserted_missing_handler,
                "dispatch_missing_handler": dispatch_missing_handler,
                "final_missing_handler_item": final_missing_handler_item,
                "inserted_failure": inserted_failure,
                "dispatch_failure": dispatch_failure,
                "final_failure_item": final_failure_item,
                "dead_letter_count": dead_letter_count,
            },
        }

    json_path = REPORT_DIR / "latest_registry_dispatch_runtime.json"
    txt_path = REPORT_DIR / "latest_registry_dispatch_runtime.txt"

    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "phase=J.7",
        f"successful={summary['successful']}",
        f"dispatch_success_ok={summary['checks']['dispatch_success']['ok']}",
        f"dispatch_unknown_code={summary['checks']['dispatch_unknown']['code']}",
        f"dispatch_missing_handler_code={summary['checks']['dispatch_missing_handler']['code']}",
        f"dispatch_failure_code={summary['checks']['dispatch_failure']['code']}",
        f"dead_letter_count={summary['checks']['dead_letter_count']}",
    ]
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
