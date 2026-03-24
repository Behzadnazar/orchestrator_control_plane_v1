from __future__ import annotations

import subprocess
import sys
import time
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.db import init_db
from app.services.control_plane_service import ControlPlaneService
from scripts.task_registry import AGENT_REGISTRY


class ControlPlaneBaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.python = sys.executable
        cls.worker_script = str(BASE_DIR / "worker_loop_final.py")
        init_db()

    def setUp(self) -> None:
        self.service = ControlPlaneService()
        self.service.reset_demo()
        for worker_id in sorted(AGENT_REGISTRY.keys()):
            self.service.register_worker(worker_id)

    def _run_worker(
        self,
        worker_id: str,
        *extra_args: str,
        background: bool = False,
        log_path: str | None = None,
    ):
        cmd = [self.python, self.worker_script, "--worker-id", worker_id, *extra_args]
        if background:
            log_file = open(log_path or f"/tmp/{worker_id}.log", "w", encoding="utf-8")
            proc = subprocess.Popen(
                cmd,
                cwd=BASE_DIR,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )
            return proc, log_file

        return subprocess.run(
            cmd,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            check=False,
        )

    def _terminate_process(self, proc: subprocess.Popen, log_file) -> None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        log_file.close()

    def _workflow_phase_h_is_complete(self, workflow: dict) -> bool:
        tasks = workflow.get("tasks", [])
        research_ok = any(task["task_type"] == "research.collect_notes" and task["status"] == "succeeded" for task in tasks)
        frontend_ok = any(task["task_type"] == "frontend.write_component" and task["status"] == "succeeded" for task in tasks)
        backend_ok = sum(1 for task in tasks if task["task_type"] == "backend.write_file" and task["status"] == "succeeded") >= 2
        return research_ok and frontend_ok and backend_ok

    def _wait_for_phase_h_workflow(self, timeout_seconds: float = 30.0, poll_seconds: float = 0.5) -> dict:
        deadline = time.monotonic() + timeout_seconds
        last_workflow = self.service.get_workflow_details("wf_phase_h_demo")

        while time.monotonic() < deadline:
            last_workflow = self.service.get_workflow_details("wf_phase_h_demo")
            if self._workflow_phase_h_is_complete(last_workflow):
                return last_workflow
            time.sleep(poll_seconds)

        return last_workflow

    def _run_phase_h_demo_and_get_workflow(self) -> dict:
        self.service.seed_demo()

        back_proc, back_log = self._run_worker(
            "backend-worker-v2",
            "--maintenance",
            background=True,
            log_path="/tmp/test-reg-backend.log",
        )
        front_proc, front_log = self._run_worker(
            "frontend-worker-v1",
            background=True,
            log_path="/tmp/test-reg-frontend.log",
        )

        try:
            time.sleep(2)
            research = self._run_worker("research-worker-v1", "--once-idle-exit")
            self.assertEqual(
                research.returncode,
                0,
                msg=f"research worker failed:\nSTDOUT:\n{research.stdout}\nSTDERR:\n{research.stderr}",
            )
            return self._wait_for_phase_h_workflow()
        finally:
            self._terminate_process(back_proc, back_log)
            self._terminate_process(front_proc, front_log)
