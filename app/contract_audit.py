from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from importlib import import_module
from typing import Any


DEFAULT_REGISTRY_MODULE = "scripts.task_registry"
DEFAULT_HANDLERS_MODULE = "scripts.task_handlers"


class AuditSeverity(StrEnum):
    ERROR = "ERROR"
    WARNING = "WARNING"


@dataclass(frozen=True)
class ContractIssue:
    code: str
    severity: str
    message: str
    task_type: str | None = None
    handler_name: str | None = None
    executor_name: str | None = None


@dataclass(frozen=True)
class RegistryEntry:
    task_type: str
    handler_name: str | None
    executor_name: str | None
    source_kind: str
    direct_callable: bool = False


@dataclass(frozen=True)
class ContractAuditReport:
    registry_module: str
    handlers_module: str
    registry_entries: int
    handler_entries: int
    issues: tuple[ContractIssue, ...]

    @property
    def error_count(self) -> int:
        return sum(1 for item in self.issues if item.severity == AuditSeverity.ERROR.value)

    @property
    def warning_count(self) -> int:
        return sum(1 for item in self.issues if item.severity == AuditSeverity.WARNING.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_module": self.registry_module,
            "handlers_module": self.handlers_module,
            "registry_entries": self.registry_entries,
            "handler_entries": self.handler_entries,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issues": [asdict(item) for item in self.issues],
        }


def _issue(
    code: str,
    message: str,
    *,
    severity: AuditSeverity = AuditSeverity.ERROR,
    task_type: str | None = None,
    handler_name: str | None = None,
    executor_name: str | None = None,
) -> ContractIssue:
    return ContractIssue(
        code=code,
        severity=severity.value,
        message=message,
        task_type=task_type,
        handler_name=handler_name,
        executor_name=executor_name,
    )


def _can_call_without_args(func: Callable[..., Any]) -> bool:
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return False

    for parameter in signature.parameters.values():
        if parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if parameter.default is inspect.Parameter.empty:
            return False
    return True


def _try_get_mapping_from_module(module: Any, candidate_names: list[str]) -> Mapping[str, Any] | None:
    for name in candidate_names:
        candidate = getattr(module, name, None)

        if isinstance(candidate, Mapping):
            return candidate

        if callable(candidate) and _can_call_without_args(candidate):
            try:
                result = candidate()
            except Exception:
                continue
            if isinstance(result, Mapping):
                return result

    return None


def _find_registry_mapping(module: Any) -> Mapping[str, Any]:
    mapping = _try_get_mapping_from_module(
        module,
        [
            "get_task_registry",
            "load_task_registry",
            "build_task_registry",
            "TASK_REGISTRY",
            "TASK_TYPES",
            "REGISTRY",
            "task_registry",
        ],
    )
    if mapping is None:
        raise LookupError("Could not find a registry mapping in the registry module")
    return mapping


def _find_handler_mapping(module: Any) -> dict[str, Callable[..., Any]]:
    found = _try_get_mapping_from_module(
        module,
        [
            "get_task_handlers",
            "load_task_handlers",
            "build_task_handlers",
            "TASK_HANDLERS",
            "HANDLER_REGISTRY",
            "HANDLERS",
            "task_handlers",
        ],
    )

    handlers: dict[str, Callable[..., Any]] = {}

    if isinstance(found, Mapping):
        for key, value in found.items():
            if isinstance(key, str) and callable(value):
                handlers[key] = value
            elif callable(key) and isinstance(value, str):
                handlers[value] = key

    for attribute_name in dir(module):
        if attribute_name.startswith("_"):
            continue
        candidate = getattr(module, attribute_name)
        if callable(candidate) and (
            attribute_name.startswith("handle_")
            or attribute_name.endswith("_handler")
            or attribute_name.endswith("_task")
        ):
            handlers.setdefault(attribute_name, candidate)

    return handlers


def _normalize_registry_entry(task_type: str, raw_value: Any) -> tuple[RegistryEntry | None, list[ContractIssue]]:
    issues: list[ContractIssue] = []

    if not isinstance(task_type, str) or not task_type.strip():
        issues.append(
            _issue(
                "INVALID_TASK_TYPE",
                "Registry contains a blank or non-string task type.",
                task_type=str(task_type),
            )
        )
        return None, issues

    if callable(raw_value):
        return (
            RegistryEntry(
                task_type=task_type,
                handler_name=getattr(raw_value, "__name__", None),
                executor_name=None,
                source_kind="direct_callable",
                direct_callable=True,
            ),
            issues,
        )

    if isinstance(raw_value, str):
        return (
            RegistryEntry(
                task_type=task_type,
                handler_name=raw_value,
                executor_name=None,
                source_kind="string_handler_name",
                direct_callable=False,
            ),
            issues,
        )

    if isinstance(raw_value, Mapping):
        raw_handler = (
            raw_value.get("handler")
            or raw_value.get("handler_name")
            or raw_value.get("callable")
            or raw_value.get("fn")
            or raw_value.get("function")
        )
        raw_executor = raw_value.get("executor") or raw_value.get("executor_name")

        direct_callable = callable(raw_handler)

        if raw_handler is None:
            issues.append(
                _issue(
                    "MISSING_HANDLER_REFERENCE",
                    "Registry entry does not define a handler reference.",
                    task_type=task_type,
                )
            )
            handler_name = None
        elif callable(raw_handler):
            handler_name = getattr(raw_handler, "__name__", None)
        elif isinstance(raw_handler, str) and raw_handler.strip():
            handler_name = raw_handler
        else:
            issues.append(
                _issue(
                    "INVALID_HANDLER_REFERENCE",
                    "Registry entry contains an invalid handler reference.",
                    task_type=task_type,
                    handler_name=str(raw_handler),
                )
            )
            handler_name = None

        if raw_executor is None:
            executor_name = None
        elif callable(raw_executor):
            executor_name = getattr(raw_executor, "__name__", None)
        elif isinstance(raw_executor, str) and raw_executor.strip():
            executor_name = raw_executor
        else:
            issues.append(
                _issue(
                    "INVALID_EXECUTOR_REFERENCE",
                    "Registry entry contains an invalid executor reference.",
                    task_type=task_type,
                    executor_name=str(raw_executor),
                )
            )
            executor_name = None

        return (
            RegistryEntry(
                task_type=task_type,
                handler_name=handler_name,
                executor_name=executor_name,
                source_kind="mapping",
                direct_callable=direct_callable,
            ),
            issues,
        )

    issues.append(
        _issue(
            "INVALID_REGISTRY_ENTRY",
            "Registry entry must be a callable, string, or mapping.",
            task_type=task_type,
            handler_name=type(raw_value).__name__,
        )
    )
    return None, issues


def validate_handler_result_contract(result: Any) -> list[ContractIssue]:
    issues: list[ContractIssue] = []

    if not isinstance(result, Mapping):
        issues.append(
            _issue(
                "NON_MAPPING_RESULT",
                "Handler result must be a mapping.",
            )
        )
        return issues

    if "status" not in result:
        issues.append(
            _issue(
                "MISSING_STATUS",
                "Handler result must contain a 'status' field.",
            )
        )
    elif not isinstance(result["status"], str) or not result["status"].strip():
        issues.append(
            _issue(
                "INVALID_STATUS_TYPE",
                "Handler result 'status' must be a non-empty string.",
            )
        )

    if "artifacts" in result and not isinstance(result["artifacts"], list):
        issues.append(
            _issue(
                "INVALID_ARTIFACTS_TYPE",
                "Handler result 'artifacts' must be a list when present.",
            )
        )

    if "details" in result and not isinstance(result["details"], Mapping):
        issues.append(
            _issue(
                "INVALID_DETAILS_TYPE",
                "Handler result 'details' must be a mapping when present.",
            )
        )

    if "error" in result and result["error"] is not None and not isinstance(result["error"], (str, Mapping)):
        issues.append(
            _issue(
                "INVALID_ERROR_TYPE",
                "Handler result 'error' must be a string, mapping, or null when present.",
            )
        )

    return issues


def audit_registry_handler_contracts_from_mappings(
    registry: Mapping[str, Any],
    handlers: Mapping[str, Any],
    *,
    registry_module: str = "<in-memory-registry>",
    handlers_module: str = "<in-memory-handlers>",
) -> ContractAuditReport:
    issues: list[ContractIssue] = []

    if not isinstance(registry, Mapping):
        issues.append(
            _issue(
                "REGISTRY_NOT_MAPPING",
                "Resolved registry object is not a mapping.",
            )
        )
        return ContractAuditReport(
            registry_module=registry_module,
            handlers_module=handlers_module,
            registry_entries=0,
            handler_entries=0,
            issues=tuple(issues),
        )

    if not isinstance(handlers, Mapping):
        issues.append(
            _issue(
                "HANDLERS_NOT_MAPPING",
                "Resolved handlers object is not a mapping.",
            )
        )
        return ContractAuditReport(
            registry_module=registry_module,
            handlers_module=handlers_module,
            registry_entries=len(registry),
            handler_entries=0,
            issues=tuple(issues),
        )

    callable_handlers = {name: value for name, value in handlers.items() if isinstance(name, str) and callable(value)}

    if not registry:
        issues.append(
            _issue(
                "EMPTY_REGISTRY",
                "Registry mapping is empty.",
                severity=AuditSeverity.WARNING,
            )
        )

    if not callable_handlers:
        issues.append(
            _issue(
                "EMPTY_HANDLER_REGISTRY",
                "Handler mapping is empty or contains no callables.",
                severity=AuditSeverity.WARNING,
            )
        )

    for task_type, raw_value in registry.items():
        entry, entry_issues = _normalize_registry_entry(task_type, raw_value)
        issues.extend(entry_issues)

        if entry is None:
            continue

        if not entry.handler_name:
            continue

        if entry.direct_callable:
            continue

        if entry.handler_name not in callable_handlers:
            issues.append(
                _issue(
                    "HANDLER_NOT_FOUND",
                    "Registry references a handler name that does not exist in the handlers module.",
                    task_type=entry.task_type,
                    handler_name=entry.handler_name,
                    executor_name=entry.executor_name,
                )
            )

    return ContractAuditReport(
        registry_module=registry_module,
        handlers_module=handlers_module,
        registry_entries=len(registry),
        handler_entries=len(callable_handlers),
        issues=tuple(issues),
    )


def audit_registry_handler_contracts(
    registry_module: str = DEFAULT_REGISTRY_MODULE,
    handlers_module: str = DEFAULT_HANDLERS_MODULE,
) -> ContractAuditReport:
    try:
        registry_mod = import_module(registry_module)
    except Exception as exc:
        return ContractAuditReport(
            registry_module=registry_module,
            handlers_module=handlers_module,
            registry_entries=0,
            handler_entries=0,
            issues=(
                _issue(
                    "REGISTRY_IMPORT_FAILED",
                    f"Could not import registry module: {exc}",
                ),
            ),
        )

    try:
        handlers_mod = import_module(handlers_module)
    except Exception as exc:
        return ContractAuditReport(
            registry_module=registry_module,
            handlers_module=handlers_module,
            registry_entries=0,
            handler_entries=0,
            issues=(
                _issue(
                    "HANDLERS_IMPORT_FAILED",
                    f"Could not import handlers module: {exc}",
                ),
            ),
        )

    try:
        registry = _find_registry_mapping(registry_mod)
    except Exception as exc:
        return ContractAuditReport(
            registry_module=registry_module,
            handlers_module=handlers_module,
            registry_entries=0,
            handler_entries=0,
            issues=(
                _issue(
                    "REGISTRY_RESOLUTION_FAILED",
                    f"Could not resolve registry mapping: {exc}",
                ),
            ),
        )

    handlers = _find_handler_mapping(handlers_mod)

    return audit_registry_handler_contracts_from_mappings(
        registry=registry,
        handlers=handlers,
        registry_module=registry_module,
        handlers_module=handlers_module,
    )


def format_contract_issues(issues: list[ContractIssue] | tuple[ContractIssue, ...]) -> str:
    if not issues:
        return "NO_ISSUES"

    lines: list[str] = []
    for item in issues:
        lines.append(
            f"{item.severity}:{item.code}:task_type={item.task_type}:handler={item.handler_name}:executor={item.executor_name}:message={item.message}"
        )
    return "\n".join(lines)
