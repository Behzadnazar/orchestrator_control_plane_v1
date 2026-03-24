from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any

from app.execution_contracts import (
    FailureCode,
    validate_execution_payload,
    validate_executor_target,
    validate_handler_result,
)


@dataclass(frozen=True)
class RuntimeExecutionResult:
    ok: bool
    code: str
    task_type: str | None
    handler_name: str | None
    result: dict[str, Any] | None
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def execute_handler_with_contract(
    payload: Any,
    handler: Callable[[Mapping[str, Any]], Any] | None,
    *,
    handler_name: str | None = None,
) -> RuntimeExecutionResult:
    payload_decision = validate_execution_payload(payload)
    if not payload_decision.accepted:
        return RuntimeExecutionResult(
            ok=False,
            code=payload_decision.code,
            task_type=payload_decision.task_type,
            handler_name=handler_name,
            result=payload_decision.to_dict(),
            message=payload_decision.message,
        )

    task_type = payload["task_type"]
    task_input = payload["input"]

    if not callable(handler):
        return RuntimeExecutionResult(
            ok=False,
            code=FailureCode.HANDLER_NOT_CALLABLE.value,
            task_type=task_type,
            handler_name=handler_name,
            result={
                "accepted": False,
                "code": FailureCode.HANDLER_NOT_CALLABLE.value,
                "message": "Resolved handler is not callable.",
                "task_type": task_type,
                "violations": [
                    {
                        "code": FailureCode.HANDLER_NOT_CALLABLE.value,
                        "message": "Resolved handler is not callable.",
                        "field": "handler",
                    }
                ],
            },
            message="Resolved handler is not callable.",
        )

    try:
        raw_result = handler(task_input)
    except Exception as exc:
        return RuntimeExecutionResult(
            ok=False,
            code=FailureCode.INTERNAL_ERROR.value,
            task_type=task_type,
            handler_name=handler_name,
            result={
                "accepted": False,
                "code": FailureCode.INTERNAL_ERROR.value,
                "message": f"Handler raised an exception: {exc}",
                "task_type": task_type,
                "violations": [
                    {
                        "code": FailureCode.INTERNAL_ERROR.value,
                        "message": f"Handler raised an exception: {exc}",
                        "field": "handler",
                    }
                ],
            },
            message=f"Handler raised an exception: {exc}",
        )

    result_decision = validate_handler_result(raw_result)
    if not result_decision.accepted:
        return RuntimeExecutionResult(
            ok=False,
            code=result_decision.code,
            task_type=task_type,
            handler_name=handler_name,
            result=result_decision.to_dict(),
            message=result_decision.message,
        )

    return RuntimeExecutionResult(
        ok=True,
        code="OK",
        task_type=task_type,
        handler_name=handler_name,
        result=dict(raw_result),
        message="Handler executed successfully.",
    )


def run_subprocess_executor(command: list[str], *, task_type: str | None = None) -> RuntimeExecutionResult:
    target_decision = validate_executor_target(command[0] if command else None, task_type=task_type)
    if not target_decision.accepted:
        return RuntimeExecutionResult(
            ok=False,
            code=target_decision.code,
            task_type=task_type,
            handler_name=None,
            result=target_decision.to_dict(),
            message=target_decision.message,
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        return RuntimeExecutionResult(
            ok=False,
            code=FailureCode.INTERNAL_ERROR.value,
            task_type=task_type,
            handler_name=None,
            result={
                "accepted": False,
                "code": FailureCode.INTERNAL_ERROR.value,
                "message": f"Subprocess execution raised an exception: {exc}",
                "task_type": task_type,
                "violations": [
                    {
                        "code": FailureCode.INTERNAL_ERROR.value,
                        "message": f"Subprocess execution raised an exception: {exc}",
                        "field": "executor",
                    }
                ],
            },
            message=f"Subprocess execution raised an exception: {exc}",
        )

    if completed.returncode != 0:
        return RuntimeExecutionResult(
            ok=False,
            code=FailureCode.SUBPROCESS_FAILED.value,
            task_type=task_type,
            handler_name=None,
            result={
                "accepted": False,
                "code": FailureCode.SUBPROCESS_FAILED.value,
                "message": "Subprocess returned a non-zero exit code.",
                "task_type": task_type,
                "violations": [
                    {
                        "code": FailureCode.SUBPROCESS_FAILED.value,
                        "message": "Subprocess returned a non-zero exit code.",
                        "field": "executor",
                    }
                ],
            },
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
            message="Subprocess returned a non-zero exit code.",
        )

    return RuntimeExecutionResult(
        ok=True,
        code="OK",
        task_type=task_type,
        handler_name=None,
        result={
            "status": "completed",
            "details": {
                "executor": command[0],
                "returncode": completed.returncode,
            },
            "artifacts": [],
        },
        stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        message="Subprocess executed successfully.",
    )
