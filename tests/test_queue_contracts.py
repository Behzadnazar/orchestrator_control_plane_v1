from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.queue_contracts import (
    QueueFailureCode,
    QueueStatus,
    build_dead_letter_record,
    validate_claim_attempt,
    validate_queue_item,
    validate_state_transition,
)
from app.queue_runtime import (
    claim_queue_item,
    count_dead_letters,
    dead_letter_queue_item,
    ensure_queue_schema,
    get_queue_item,
    insert_queue_item,
    transition_queue_item,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ControlPlaneQueueContractsTests(unittest.TestCase):
    def test_malformed_queue_item_is_rejected(self) -> None:
        decision = validate_queue_item({"task_id": "t-1", "task_type": "backend.test", "status": "queued"})
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, QueueFailureCode.MISSING_QUEUE_ITEM_ID.value)

    def test_duplicate_claim_is_rejected(self) -> None:
        item = {
            "queue_item_id": "q-1",
            "task_id": "t-1",
            "task_type": "backend.test",
            "status": QueueStatus.CLAIMED.value,
        }
        decision = validate_claim_attempt(item, "worker-a", already_claimed_by="worker-a")
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, QueueFailureCode.DUPLICATE_CLAIM.value)

    def test_claim_conflict_is_rejected_for_other_worker(self) -> None:
        item = {
            "queue_item_id": "q-1",
            "task_id": "t-1",
            "task_type": "backend.test",
            "status": QueueStatus.CLAIMED.value,
        }
        decision = validate_claim_attempt(item, "worker-b", already_claimed_by="worker-a")
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, QueueFailureCode.CLAIM_CONFLICT.value)

    def test_invalid_state_transition_is_rejected(self) -> None:
        item = {
            "queue_item_id": "q-1",
            "task_id": "t-1",
            "task_type": "backend.test",
            "status": QueueStatus.CLAIMED.value,
        }
        decision = validate_state_transition(item, QueueStatus.COMPLETED.value)
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, QueueFailureCode.INVALID_STATE_TRANSITION.value)

    def test_dead_letter_record_is_normalized(self) -> None:
        item = {
            "queue_item_id": "q-1",
            "task_id": "t-1",
            "task_type": "backend.test",
            "status": QueueStatus.FAILED.value,
        }
        record = build_dead_letter_record(item, "EXECUTION_REJECTED", "terminal failure")
        self.assertEqual(record["to_status"], QueueStatus.DEAD_LETTERED.value)
        self.assertEqual(record["failure_code"], "EXECUTION_REJECTED")

    def test_runtime_claim_transition_and_dead_letter_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "queue.sqlite3"
            ensure_queue_schema(db_path)

            inserted = insert_queue_item(
                db_path,
                {
                    "queue_item_id": "q-200",
                    "task_id": "t-200",
                    "task_type": "backend.test",
                    "status": QueueStatus.QUEUED.value,
                },
            )
            self.assertTrue(inserted.ok)

            claimed = claim_queue_item(db_path, "q-200", "worker-a")
            self.assertTrue(claimed.ok)

            duplicate_claim = claim_queue_item(db_path, "q-200", "worker-a")
            self.assertFalse(duplicate_claim.ok)
            self.assertEqual(duplicate_claim.code, QueueFailureCode.DUPLICATE_CLAIM.value)

            invalid_transition = transition_queue_item(db_path, "q-200", QueueStatus.COMPLETED.value)
            self.assertFalse(invalid_transition.ok)
            self.assertEqual(invalid_transition.code, QueueFailureCode.INVALID_STATE_TRANSITION.value)

            to_running = transition_queue_item(db_path, "q-200", QueueStatus.RUNNING.value)
            self.assertTrue(to_running.ok)

            to_failed = transition_queue_item(db_path, "q-200", QueueStatus.FAILED.value)
            self.assertTrue(to_failed.ok)

            dead_lettered = dead_letter_queue_item(db_path, "q-200", "EXECUTION_REJECTED", "terminal failure")
            self.assertTrue(dead_lettered.ok)

            item = get_queue_item(db_path, "q-200")
            self.assertIsNotNone(item)
            self.assertEqual(item["status"], QueueStatus.DEAD_LETTERED.value)
            self.assertEqual(count_dead_letters(db_path), 1)

    def test_verify_queue_contracts_script_regression(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/verify_queue_contracts.py"],
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

        report_path = PROJECT_ROOT / "artifacts" / "test_reports" / "latest_queue_contracts.json"
        self.assertTrue(report_path.exists(), "latest_queue_contracts.json must exist after script execution")


if __name__ == "__main__":
    unittest.main()
