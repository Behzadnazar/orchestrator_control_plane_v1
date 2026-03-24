from __future__ import annotations

import threading

import pytest

from app.db import create_task, get_workflow_tasks
from tests.common import ControlPlaneBaseTestCase


@pytest.mark.e2e
class ControlPlaneWorkflowE2ETests(ControlPlaneBaseTestCase):
    def test_phase_h_demo_end_to_end_regression(self) -> None:
        workflow = self._run_phase_h_demo_and_get_workflow()

        statuses = {task["task_type"] + "::" + task["task_id"]: task["status"] for task in workflow["tasks"]}
        self.assertTrue(
            any(task["task_type"] == "research.collect_notes" and task["status"] == "succeeded" for task in workflow["tasks"])
        )
        self.assertTrue(
            any(task["task_type"] == "frontend.write_component" and task["status"] == "succeeded" for task in workflow["tasks"])
        )
        self.assertGreaterEqual(
            sum(1 for task in workflow["tasks"] if task["task_type"] == "backend.write_file" and task["status"] == "succeeded"),
            2,
            msg=f"workflow statuses were: {statuses}",
        )

    def test_h3_race_safe_create_task_regression(self) -> None:
        workflow_id = "wf_test_race_safe"
        workflow_run_key = "race_safe_run"
        payload = {
            "workflow_run_key": workflow_run_key,
            "path": "artifacts/runs/race_safe_run/workflows/race.txt",
            "content": "race safe\n",
        }

        task_ids: list[str] = []
        errors: list[str] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            try:
                barrier.wait(timeout=5)
                task_id = create_task(
                    task_type="backend.write_file",
                    payload=payload,
                    priority=100,
                    max_attempts=2,
                    workflow_id=workflow_id,
                    workflow_run_key=workflow_run_key,
                )
                task_ids.append(task_id)
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], msg=f"unexpected race errors: {errors}")
        self.assertGreater(len(task_ids), 0)
        self.assertEqual(len(set(task_ids)), 1, msg=f"expected exactly one deduplicated task id, got: {task_ids}")

        tasks = get_workflow_tasks(workflow_id)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["task_type"], "backend.write_file")
