from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Optional


class FailureCategory(StrEnum):
    IMPORT_ERROR = "IMPORT_ERROR"
    ASSERTION_FAILURE = "ASSERTION_FAILURE"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    BUSINESS_RULE_ERROR = "BUSINESS_RULE_ERROR"
    GRAPH_INVARIANT_ERROR = "GRAPH_INVARIANT_ERROR"
    REGISTRY_CONTRACT_ERROR = "REGISTRY_CONTRACT_ERROR"
    HANDLER_CONTRACT_ERROR = "HANDLER_CONTRACT_ERROR"
    SUBPROCESS_ERROR = "SUBPROCESS_ERROR"
    DATABASE_ERROR = "DATABASE_ERROR"
    TIMEOUT_ERROR = "TIMEOUT_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass(frozen=True)
class FailureDiagnostic:
    test: str
    kind: str
    category: str
    summary: str
    traceback: str


_CATEGORY_RULES: tuple[tuple[FailureCategory, tuple[str, ...]], ...] = (
    (
        FailureCategory.IMPORT_ERROR,
        (
            "ModuleNotFoundError",
            "ImportError",
            "Failed to import test module",
            "No module named",
        ),
    ),
    (
        FailureCategory.TIMEOUT_ERROR,
        (
            "TimeoutExpired",
            "timed out",
            "timeout",
        ),
    ),
    (
        FailureCategory.DATABASE_ERROR,
        (
            "sqlite3.",
            "database is locked",
            "OperationalError",
            "IntegrityError",
        ),
    ),
    (
        FailureCategory.GRAPH_INVARIANT_ERROR,
        (
            "GRAPH_INVARIANT",
            "WORKFLOW_GRAPH",
            "CYCLE_DETECTED",
            "ORPHAN_NODE",
            "INVALID_DEPENDENCY_EDGE",
        ),
    ),
    (
        FailureCategory.VALIDATION_ERROR,
        (
            "VALIDATION_ERROR",
            "SchemaValidationError",
            "TASK_SCHEMA",
            "REQUEST_CONTRACT",
            "invalid payload",
        ),
    ),
    (
        FailureCategory.BUSINESS_RULE_ERROR,
        (
            "BUSINESS_RULE",
            "PATH_GUARDRAIL",
            "NAMESPACE_GUARDRAIL",
            "DefinitionOfDone",
            "definition of done",
        ),
    ),
    (
        FailureCategory.REGISTRY_CONTRACT_ERROR,
        (
            "REGISTRY_CONTRACT",
            "task registry",
            "unknown task type",
            "task_type not registered",
        ),
    ),
    (
        FailureCategory.HANDLER_CONTRACT_ERROR,
        (
            "HANDLER_CONTRACT",
            "handler not found",
            "missing handler",
            "invalid handler result",
        ),
    ),
    (
        FailureCategory.SUBPROCESS_ERROR,
        (
            "CalledProcessError",
            "subprocess",
            "return code",
            "non-zero exit status",
        ),
    ),
)


def _normalize_text(text: str) -> str:
    return text.strip()


def summarize_traceback(traceback_text: str) -> str:
    normalized = _normalize_text(traceback_text)
    if not normalized:
        return "No traceback captured."

    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
    if not lines:
        return "No traceback captured."

    for line in reversed(lines):
        if re.search(r"(Error|Exception|Failed)", line):
            return line[:300]

    return lines[-1][:300]


def categorize_failure(test_name: str, traceback_text: str, kind: str) -> FailureDiagnostic:
    normalized = _normalize_text(traceback_text)
    summary = summarize_traceback(normalized)
    haystack = f"{test_name}\n{kind}\n{normalized}"

    if kind == "failure":
        category = FailureCategory.ASSERTION_FAILURE
    else:
        category = FailureCategory.UNKNOWN_ERROR
        for candidate, markers in _CATEGORY_RULES:
            if any(marker in haystack for marker in markers):
                category = candidate
                break

    return FailureDiagnostic(
        test=test_name,
        kind=kind,
        category=category.value,
        summary=summary,
        traceback=normalized,
    )
