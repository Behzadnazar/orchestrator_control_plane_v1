from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, TypedDict


class FailureCode(StrEnum):
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    MISSING_TASK_TYPE = "MISSING_TASK_TYPE"
    INVALID_TASK_TYPE = "INVALID_TASK_TYPE"
    UNKNOWN_TASK_TYPE = "UNKNOWN_TASK_TYPE"
    MISSING_INPUT = "MISSING_INPUT"
    INVALID_INPUT_TYPE = "INVALID_INPUT_TYPE"
    INVALID_EXECUTOR_TARGET = "INVALID_EXECUTOR_TARGET"
    HANDLER_NOT_CALLABLE = "HANDLER_NOT_CALLABLE"
    HANDLER_RESULT_INVALID = "HANDLER_RESULT_INVALID"
    EXECUTION_REJECTED = "EXECUTION_REJECTED"
    SUBPROCESS_FAILED = "SUBPROCESS_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ExecutionPayload(TypedDict):
    task_type: str
    input: Mapping[str, Any]


@dataclass(frozen=True)
class ContractViolation:
    code: str
    message: str
    field: str | None = None


@dataclass(frozen=True)
class ExecutionDecision:
    accepted: bool
    code: str
    message: str
    task_type: str | None = None
    violations: tuple[ContractViolation, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "code": self.code,
            "message": self.message,
            "task_type": self.task_type,
            "violations": [asdict(item) for item in self.violations],
        }


def _violation(code: FailureCode, message: str, field: str | None = None) -> ContractViolation:
    return ContractViolation(
        code=code.value,
        message=message,
        field=field,
    )


def reject(code: FailureCode, message: str, *, task_type: str | None = None, field: str | None = None) -> ExecutionDecision:
    violation = _violation(code, message, field)
    return ExecutionDecision(
        accepted=False,
        code=code.value,
        message=message,
        task_type=task_type,
        violations=(violation,),
    )


def accept(task_type: str) -> ExecutionDecision:
    return ExecutionDecision(
        accepted=True,
        code="ACCEPTED",
        message="Payload accepted for execution.",
        task_type=task_type,
        violations=(),
    )


def validate_execution_payload(payload: Any) -> ExecutionDecision:
    if not isinstance(payload, Mapping):
        return reject(
            FailureCode.INVALID_PAYLOAD,
            "Execution payload must be a mapping.",
        )

    if "task_type" not in payload:
        return reject(
            FailureCode.MISSING_TASK_TYPE,
            "Execution payload must contain 'task_type'.",
            field="task_type",
        )

    task_type = payload.get("task_type")
    if not isinstance(task_type, str) or not task_type.strip():
        return reject(
            FailureCode.INVALID_TASK_TYPE,
            "Execution payload field 'task_type' must be a non-empty string.",
            field="task_type",
        )

    if "input" not in payload:
        return reject(
            FailureCode.MISSING_INPUT,
            "Execution payload must contain 'input'.",
            task_type=task_type,
            field="input",
        )

    task_input = payload.get("input")
    if not isinstance(task_input, Mapping):
        return reject(
            FailureCode.INVALID_INPUT_TYPE,
            "Execution payload field 'input' must be a mapping.",
            task_type=task_type,
            field="input",
        )

    return accept(task_type)


def validate_executor_target(executor_target: Any, *, task_type: str | None = None) -> ExecutionDecision:
    if executor_target is None:
        return reject(
            FailureCode.INVALID_EXECUTOR_TARGET,
            "Executor target must not be null.",
            task_type=task_type,
            field="executor",
        )

    if not isinstance(executor_target, str) or not executor_target.strip():
        return reject(
            FailureCode.INVALID_EXECUTOR_TARGET,
            "Executor target must be a non-empty string.",
            task_type=task_type,
            field="executor",
        )

    return ExecutionDecision(
        accepted=True,
        code="ACCEPTED",
        message="Executor target accepted.",
        task_type=task_type,
        violations=(),
    )


def validate_handler_result(result: Any) -> ExecutionDecision:
    if not isinstance(result, Mapping):
        return reject(
            FailureCode.HANDLER_RESULT_INVALID,
            "Handler result must be a mapping.",
        )

    if "status" not in result:
        return reject(
            FailureCode.HANDLER_RESULT_INVALID,
            "Handler result must contain 'status'.",
            field="status",
        )

    status = result.get("status")
    if not isinstance(status, str) or not status.strip():
        return reject(
            FailureCode.HANDLER_RESULT_INVALID,
            "Handler result field 'status' must be a non-empty string.",
            field="status",
        )

    if "artifacts" in result and not isinstance(result.get("artifacts"), list):
        return reject(
            FailureCode.HANDLER_RESULT_INVALID,
            "Handler result field 'artifacts' must be a list when present.",
            field="artifacts",
        )

    if "details" in result and not isinstance(result.get("details"), Mapping):
        return reject(
            FailureCode.HANDLER_RESULT_INVALID,
            "Handler result field 'details' must be a mapping when present.",
            field="details",
        )

    if "error" in result and result.get("error") is not None and not isinstance(result.get("error"), (str, Mapping)):
        return reject(
            FailureCode.HANDLER_RESULT_INVALID,
            "Handler result field 'error' must be a string, mapping, or null when present.",
            field="error",
        )

    return ExecutionDecision(
        accepted=True,
        code="ACCEPTED",
        message="Handler result accepted.",
        task_type=None,
        violations=(),
    )
