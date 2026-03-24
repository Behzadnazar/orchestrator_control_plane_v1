from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.persistent_queue_runtime import (
    count_persistent_dead_letters,
    dead_letter_persistent_item,
    ensure_persistent_queue_schema,
    get_persistent_queue_item,
    insert_persistent_queue_item,
    replay_dead_letter_item,
)
from app.queue_contracts import QueueFailureCode, QueueStatus
from app.worker_loop_runtime import process_one_queue_item, reject_transition_bypass


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


class ControlPlaneWorkerLoopRuntimeTests(unittest.TestCase):
    def test_db_backed_claim_consistency(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "persistent.sqlite3"
            ensure_persistent_queue_schema(db_path)

            inserted = insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "pq-10",
                    "task_id": "pt-10",
                    "task_type": "backend.test",
                    "status": QueueStatus.QUEUED.value,
                },
            )
            self.assertTrue(inserted.ok)

            result = process_one_queue_item(db_path, "worker-a", ok_handler)
            self.assertTrue(result.ok)

            item = get_persistent_queue_item(db_path, "pq-10")
            self.assertIsNotNone(item)
            self.assertEqual(item["status"], QueueStatus.COMPLETED.value)

    def test_worker_loop_transition_bypass_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "persistent.sqlite3"
            ensure_persistent_queue_schema(db_path)

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "pq-11",
                    "task_id": "pt-11",
                    "task_type": "backend.test",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            result = reject_transition_bypass(db_path, "pq-11", "queued", "completed")
            self.assertFalse(result.ok)
            self.assertEqual(result.code, QueueFailureCode.INVALID_STATE_TRANSITION.value)

    def test_replay_from_invalid_state_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "persistent.sqlite3"
            ensure_persistent_queue_schema(db_path)

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "pq-12",
                    "task_id": "pt-12",
                    "task_type": "backend.test",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            result = replay_dead_letter_item(db_path, "pq-12")
            self.assertFalse(result.ok)
            self.assertEqual(result.code, QueueFailureCode.INVALID_STATE_TRANSITION.value)

    def test_replay_without_failure_context_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "persistent.sqlite3"
            ensure_persistent_queue_schema(db_path)

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "pq-13",
                    "task_id": "pt-13",
                    "task_type": "backend.test",
                    "status": QueueStatus.DEAD_LETTERED.value,
                },
            )

            result = replay_dead_letter_item(db_path, "pq-13")
            self.assertFalse(result.ok)
            self.assertEqual(result.code, QueueFailureCode.DEAD_LETTER_INVALID.value)

    def test_dead_letter_replay_normalizes_to_queued(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "persistent.sqlite3"
            ensure_persistent_queue_schema(db_path)

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "pq-14",
                    "task_id": "pt-14",
                    "task_type": "backend.test",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            process_one_queue_item(db_path, "worker-z", invalid_handler)

            dead_count = count_persistent_dead_letters(db_path)
            self.assertEqual(dead_count, 1)

            replay = replay_dead_letter_item(db_path, "pq-14")
            self.assertTrue(replay.ok)

            item = get_persistent_queue_item(db_path, "pq-14")
            self.assertIsNotNone(item)
            self.assertEqual(item["status"], QueueStatus.QUEUED.value)
            self.assertEqual(item["claimed_by_worker"], None)
            self.assertGreaterEqual(int(item["retry_count"]), 1)

    def test_verify_worker_loop_runtime_script_regression(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/verify_worker_loop_runtime.py"],
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

        report_path = PROJECT_ROOT / "artifacts" / "test_reports" / "latest_worker_loop_runtime.json"
        self.assertTrue(report_path.exists(), "latest_worker_loop_runtime.json must exist after script execution")


if __name__ == "__main__":
    unittest.main()
