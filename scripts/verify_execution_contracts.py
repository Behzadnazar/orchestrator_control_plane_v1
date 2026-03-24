#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "artifacts" / "test_reports"


def ensure_project_root_on_syspath() -> None:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


ensure_project_root_on_syspath()

from app.execution_contracts import FailureCode  # noqa: E402
from app.executor_runtime import execute_handler_with_contract, run_subprocess_executor  # noqa: E402


def ok_handler(payload: dict) -> dict:
    return {
        "status": "completed",
        "details": {
            "received_keys": sorted(payload.keys()),
        },
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

    checks = {
        "payload_ok": execute_handler_with_contract(
            {"task_type": "backend.test", "input": {"value": 1}},
            ok_handler,
            handler_name="ok_handler",
        ).to_dict(),
        "payload_missing_task_type": execute_handler_with_contract(
            {"input": {"value": 1}},
            ok_handler,
            handler_name="ok_handler",
        ).to_dict(),
        "handler_result_invalid": execute_handler_with_contract(
            {"task_type": "backend.test", "input": {"value": 1}},
            bad_handler,
            handler_name="bad_handler",
        ).to_dict(),
        "subprocess_ok": run_subprocess_executor(
            [sys.executable, "-c", "print('ok-from-subprocess')"],
            task_type="backend.test",
        ).to_dict(),
        "subprocess_fail": run_subprocess_executor(
            [sys.executable, "-c", "import sys; print('fail-from-subprocess'); sys.exit(7)"],
            task_type="backend.test",
        ).to_dict(),
    }

    summary = {
        "phase": "J.4",
        "successful": (
            checks["payload_ok"]["ok"] is True
            and checks["payload_missing_task_type"]["code"] == FailureCode.MISSING_TASK_TYPE.value
            and checks["handler_result_invalid"]["code"] == FailureCode.HANDLER_RESULT_INVALID.value
            and checks["subprocess_ok"]["ok"] is True
            and checks["subprocess_fail"]["code"] == FailureCode.SUBPROCESS_FAILED.value
            and checks["subprocess_fail"]["returncode"] == 7
        ),
        "checks": checks,
    }

    json_path = REPORT_DIR / "latest_execution_contracts.json"
    txt_path = REPORT_DIR / "latest_execution_contracts.txt"

    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "phase=J.4",
        f"successful={summary['successful']}",
        f"payload_ok={checks['payload_ok']['ok']}",
        f"payload_missing_task_type_code={checks['payload_missing_task_type']['code']}",
        f"handler_result_invalid_code={checks['handler_result_invalid']['code']}",
        f"subprocess_ok={checks['subprocess_ok']['ok']}",
        f"subprocess_fail_code={checks['subprocess_fail']['code']}",
        f"subprocess_fail_returncode={checks['subprocess_fail']['returncode']}",
    ]
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
