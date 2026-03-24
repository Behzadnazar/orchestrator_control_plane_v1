from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from app.execution_contracts import FailureCode, validate_execution_payload, validate_handler_result
from app.executor_runtime import execute_handler_with_contract, run_subprocess_executor


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def ok_handler(payload: dict) -> dict:
    return {
        "status": "completed",
        "details": {"received": payload},
        "artifacts": [],
    }


def invalid_result_handler(_payload: dict) -> dict:
    return {
        "details": {"missing": "status"},
        "artifacts": [],
    }


class ControlPlaneExecutionContractsTests(unittest.TestCase):
    def test_payload_missing_task_type_is_rejected(self) -> None:
        decision = validate_execution_payload({"input": {"value": 1}})
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, FailureCode.MISSING_TASK_TYPE.value)

    def test_payload_invalid_input_type_is_rejected(self) -> None:
        decision = validate_execution_payload({"task_type": "backend.test", "input": "not-a-mapping"})
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, FailureCode.INVALID_INPUT_TYPE.value)

    def test_handler_result_missing_status_is_rejected(self) -> None:
        decision = validate_handler_result({"details": {"ok": True}, "artifacts": []})
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, FailureCode.HANDLER_RESULT_INVALID.value)

    def test_handler_result_invalid_artifacts_type_is_rejected(self) -> None:
        decision = validate_handler_result({"status": "completed", "details": {}, "artifacts": "bad"})
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.code, FailureCode.HANDLER_RESULT_INVALID.value)

    def test_execute_handler_with_valid_payload_and_result_passes(self) -> None:
        result = execute_handler_with_contract(
            {"task_type": "backend.test", "input": {"value": 1}},
            ok_handler,
            handler_name="ok_handler",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.code, "OK")
        self.assertEqual(result.result["status"], "completed")

    def test_execute_handler_with_invalid_result_fails(self) -> None:
        result = execute_handler_with_contract(
            {"task_type": "backend.test", "input": {"value": 1}},
            invalid_result_handler,
            handler_name="invalid_result_handler",
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.code, FailureCode.HANDLER_RESULT_INVALID.value)

    def test_non_callable_handler_is_rejected(self) -> None:
        result = execute_handler_with_contract(
            {"task_type": "backend.test", "input": {"value": 1}},
            None,
            handler_name="none_handler",
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.code, FailureCode.HANDLER_NOT_CALLABLE.value)

    def test_subprocess_non_zero_exit_is_rejected_with_returncode(self) -> None:
        result = run_subprocess_executor(
            [sys.executable, "-c", "import sys; print('boom'); sys.exit(9)"],
            task_type="backend.test",
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.code, FailureCode.SUBPROCESS_FAILED.value)
        self.assertEqual(result.returncode, 9)

    def test_subprocess_zero_exit_passes(self) -> None:
        result = run_subprocess_executor(
            [sys.executable, "-c", "print('hello')"],
            task_type="backend.test",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.code, "OK")
        self.assertEqual(result.returncode, 0)

    def test_verify_execution_contracts_script_regression(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/verify_execution_contracts.py"],
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

        report_path = PROJECT_ROOT / "artifacts" / "test_reports" / "latest_execution_contracts.json"
        self.assertTrue(report_path.exists(), "latest_execution_contracts.json must exist after script execution")


if __name__ == "__main__":
    unittest.main()
