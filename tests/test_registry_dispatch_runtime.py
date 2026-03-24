from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.persistent_queue_runtime import (
    count_persistent_dead_letters,
    ensure_persistent_queue_schema,
    get_persistent_queue_item,
    insert_persistent_queue_item,
)
from app.queue_contracts import QueueStatus
from app.registry_dispatch_runtime import dispatch_queue_item_via_registry


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def ok_handler(payload: dict) -> dict:
    return {
        "status": "completed",
        "details": {"payload_keys": sorted(payload.keys())},
        "artifacts": [],
    }


def invalid_handler(_payload: dict) -> dict:
    return {
        "details": {"missing": "status"},
        "artifacts": [],
    }


class ControlPlaneRegistryDispatchRuntimeTests(unittest.TestCase):
    def test_registry_dispatch_success_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "dispatch.sqlite3"
            ensure_persistent_queue_schema(db_path)

            registry = {"backend.test": {"handler": "handle_backend_test"}}
            handlers = {"handle_backend_test": ok_handler}

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "d-1",
                    "task_id": "t-1",
                    "task_type": "backend.test",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            result = dispatch_queue_item_via_registry(
                db_path,
                "worker-a",
                registry_override=registry,
                handlers_override=handlers,
            )
            self.assertTrue(result.ok)

            item = get_persistent_queue_item(db_path, "d-1")
            self.assertIsNotNone(item)
            self.assertEqual(item["status"], QueueStatus.COMPLETED.value)

    def test_unknown_task_type_dead_lettered(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "dispatch.sqlite3"
            ensure_persistent_queue_schema(db_path)

            registry = {"backend.test": {"handler": "handle_backend_test"}}
            handlers = {"handle_backend_test": ok_handler}

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "d-2",
                    "task_id": "t-2",
                    "task_type": "backend.unknown",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            result = dispatch_queue_item_via_registry(
                db_path,
                "worker-b",
                registry_override=registry,
                handlers_override=handlers,
            )
            self.assertFalse(result.ok)
            self.assertEqual(result.code, "UNKNOWN_TASK_TYPE")

            item = get_persistent_queue_item(db_path, "d-2")
            self.assertIsNotNone(item)
            self.assertEqual(item["status"], QueueStatus.DEAD_LETTERED.value)

    def test_missing_handler_dead_lettered(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "dispatch.sqlite3"
            ensure_persistent_queue_schema(db_path)

            registry = {"backend.missing_handler": {"handler": "handle_missing_handler"}}
            handlers = {}

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "d-3",
                    "task_id": "t-3",
                    "task_type": "backend.missing_handler",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            result = dispatch_queue_item_via_registry(
                db_path,
                "worker-c",
                registry_override=registry,
                handlers_override=handlers,
            )
            self.assertFalse(result.ok)
            self.assertEqual(result.code, "HANDLER_NOT_CALLABLE")

            item = get_persistent_queue_item(db_path, "d-3")
            self.assertIsNotNone(item)
            self.assertEqual(item["status"], QueueStatus.DEAD_LETTERED.value)

    def test_registry_dispatch_failure_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "dispatch.sqlite3"
            ensure_persistent_queue_schema(db_path)

            registry = {"backend.fail_test": {"handler": "handle_backend_fail_test"}}
            handlers = {"handle_backend_fail_test": invalid_handler}

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "d-4",
                    "task_id": "t-4",
                    "task_type": "backend.fail_test",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            result = dispatch_queue_item_via_registry(
                db_path,
                "worker-d",
                registry_override=registry,
                handlers_override=handlers,
            )
            self.assertFalse(result.ok)
            self.assertEqual(result.code, "HANDLER_RESULT_INVALID")

            item = get_persistent_queue_item(db_path, "d-4")
            self.assertIsNotNone(item)
            self.assertEqual(item["status"], QueueStatus.DEAD_LETTERED.value)
            self.assertEqual(item["last_error_code"], "HANDLER_RESULT_INVALID")

    def test_persistent_dispatch_preserves_failure_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "dispatch.sqlite3"
            ensure_persistent_queue_schema(db_path)

            registry = {"backend.fail_test": {"handler": "handle_backend_fail_test"}}
            handlers = {"handle_backend_fail_test": invalid_handler}

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "d-5",
                    "task_id": "t-5",
                    "task_type": "backend.fail_test",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            dispatch_queue_item_via_registry(
                db_path,
                "worker-e",
                registry_override=registry,
                handlers_override=handlers,
            )

            item = get_persistent_queue_item(db_path, "d-5")
            self.assertIsNotNone(item)
            self.assertEqual(item["last_error_code"], "HANDLER_RESULT_INVALID")
            self.assertEqual(item["last_error_message"], "Handler result must contain 'status'.")
            self.assertEqual(count_persistent_dead_letters(db_path), 1)

    def test_verify_registry_dispatch_runtime_script_regression(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/verify_registry_dispatch_runtime.py"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            completed.returncode,
            0,
            msg=f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}",
        )

        payload = json.loads(completed.stdout)
        self.assertTrue(payload["successful"])

        report_path = PROJECT_ROOT / "artifacts" / "test_reports" / "latest_registry_dispatch_runtime.json"
        self.assertTrue(report_path.exists(), "latest_registry_dispatch_runtime.json must exist after script execution")


if __name__ == "__main__":
    unittest.main()
