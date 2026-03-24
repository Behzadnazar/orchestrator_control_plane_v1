from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from importlib import import_module
from typing import Any


DEFAULT_REGISTRY_MODULE = "scripts.task_registry"
DEFAULT_HANDLERS_MODULE = "scripts.task_handlers"


class ModuleContractCode(StrEnum):
    OK = "OK"
    REGISTRY_MODULE_IMPORT_FAILED = "REGISTRY_MODULE_IMPORT_FAILED"
    HANDLERS_MODULE_IMPORT_FAILED = "HANDLERS_MODULE_IMPORT_FAILED"
    REGISTRY_EXPORT_MISSING = "REGISTRY_EXPORT_MISSING"
    REGISTRY_EXPORT_INVALID = "REGISTRY_EXPORT_INVALID"
    HANDLERS_EXPORT_MISSING = "HANDLERS_EXPORT_MISSING"
    HANDLERS_EXPORT_INVALID = "HANDLERS_EXPORT_INVALID"
    REGISTRY_SHAPE_DRIFT = "REGISTRY_SHAPE_DRIFT"
    REGISTRY_HANDLER_NAME_INVALID = "REGISTRY_HANDLER_NAME_INVALID"
    HANDLER_ENTRY_NOT_CALLABLE = "HANDLER_ENTRY_NOT_CALLABLE"
    CLI_ENTRY_INVALID = "CLI_ENTRY_INVALID"
    WORKER_ENTRY_INVALID = "WORKER_ENTRY_INVALID"


@dataclass(frozen=True)
class ModuleContractIssue:
    code: str
    message: str
    field: str | None = None


@dataclass(frozen=True)
class ModuleContractReport:
    ok: bool
    code: str
    message: str
    registry_module: str
    handlers_module: str
    registry_export_name: str | None
    handlers_export_name: str | None
    issues: tuple[ModuleContractIssue, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
            "registry_module": self.registry_module,
            "handlers_module": self.handlers_module,
            "registry_export_name": self.registry_export_name,
            "handlers_export_name": self.handlers_export_name,
            "issues": [asdict(item) for item in self.issues],
        }


def _issue(code: ModuleContractCode, message: str, field: str | None = None) -> ModuleContractIssue:
    return ModuleContractIssue(code=code.value, message=message, field=field)


def _ok(
    message: str,
    registry_module: str,
    handlers_module: str,
    registry_export_name: str,
    handlers_export_name: str,
) -> ModuleContractReport:
    return ModuleContractReport(
        ok=True,
        code=ModuleContractCode.OK.value,
        message=message,
        registry_module=registry_module,
        handlers_module=handlers_module,
        registry_export_name=registry_export_name,
        handlers_export_name=handlers_export_name,
        issues=(),
    )


def _fail(
    code: ModuleContractCode,
    message: str,
    registry_module: str,
    handlers_module: str,
    registry_export_name: str | None,
    handlers_export_name: str | None,
    issues: list[ModuleContractIssue],
) -> ModuleContractReport:
    return ModuleContractReport(
        ok=False,
        code=code.value,
        message=message,
        registry_module=registry_module,
        handlers_module=handlers_module,
        registry_export_name=registry_export_name,
        handlers_export_name=handlers_export_name,
        issues=tuple(issues),
    )


def _load_module(module_name: str) -> tuple[Any | None, Exception | None]:
    try:
        return import_module(module_name), None
    except Exception as exc:
        return None, exc


def _find_mapping_export(module: Any, candidate_names: tuple[str, ...]) -> tuple[str | None, Mapping[str, Any] | None]:
    for name in candidate_names:
        value = getattr(module, name, None)
        if isinstance(value, Mapping):
            return name, value
        if callable(value):
            try:
                resolved = value()
            except TypeError:
                continue
            if isinstance(resolved, Mapping):
                return name, resolved
    return None, None


def _validate_registry_shape(registry: Mapping[str, Any]) -> list[ModuleContractIssue]:
    issues: list[ModuleContractIssue] = []

    if not registry:
        issues.append(_issue(ModuleContractCode.REGISTRY_SHAPE_DRIFT, "Registry mapping must not be empty.", "registry"))
        return issues

    for task_type, entry in registry.items():
        if not isinstance(task_type, str) or not task_type.strip():
            issues.append(_issue(ModuleContractCode.REGISTRY_SHAPE_DRIFT, "Registry task_type must be a non-empty string.", "task_type"))
            continue

        if not isinstance(entry, Mapping):
            issues.append(_issue(ModuleContractCode.REGISTRY_SHAPE_DRIFT, f"Registry entry for '{task_type}' must be a mapping.", task_type))
            continue

        allowed_keys = {"handler", "executor"}
        entry_keys = set(entry.keys())
        if entry_keys != {"handler"} and entry_keys != allowed_keys:
            issues.append(
                _issue(
                    ModuleContractCode.REGISTRY_SHAPE_DRIFT,
                    f"Registry entry for '{task_type}' must have keys ['handler'] or ['handler', 'executor'].",
                    task_type,
                )
            )

        handler_name = entry.get("handler")
        if not isinstance(handler_name, str) or not handler_name.strip():
            issues.append(
                _issue(
                    ModuleContractCode.REGISTRY_HANDLER_NAME_INVALID,
                    f"Registry entry for '{task_type}' must define a non-empty string handler name.",
                    task_type,
                )
            )

        if "executor" in entry:
            executor_name = entry.get("executor")
            if executor_name is not None and (not isinstance(executor_name, str) or not executor_name.strip()):
                issues.append(
                    _issue(
                        ModuleContractCode.REGISTRY_SHAPE_DRIFT,
                        f"Registry entry for '{task_type}' has an invalid executor value.",
                        task_type,
                    )
                )

    return issues


def _validate_handlers_shape(handlers: Mapping[str, Any]) -> list[ModuleContractIssue]:
    issues: list[ModuleContractIssue] = []

    if not handlers:
        issues.append(_issue(ModuleContractCode.HANDLERS_EXPORT_INVALID, "Handlers mapping must not be empty.", "handlers"))
        return issues

    for name, handler in handlers.items():
        if not isinstance(name, str) or not name.strip():
            issues.append(_issue(ModuleContractCode.HANDLERS_EXPORT_INVALID, "Handler key must be a non-empty string.", "handler_name"))
            continue
        if not callable(handler):
            issues.append(
                _issue(
                    ModuleContractCode.HANDLER_ENTRY_NOT_CALLABLE,
                    f"Handler entry '{name}' must be callable.",
                    name,
                )
            )

    return issues


def lock_module_contracts(
    registry_module_name: str = DEFAULT_REGISTRY_MODULE,
    handlers_module_name: str = DEFAULT_HANDLERS_MODULE,
) -> ModuleContractReport:
    registry_module, registry_error = _load_module(registry_module_name)
    if registry_error is not None:
        return _fail(
            ModuleContractCode.REGISTRY_MODULE_IMPORT_FAILED,
            f"Failed to import registry module: {registry_error}",
            registry_module_name,
            handlers_module_name,
            None,
            None,
            [_issue(ModuleContractCode.REGISTRY_MODULE_IMPORT_FAILED, str(registry_error), "registry_module")],
        )

    handlers_module, handlers_error = _load_module(handlers_module_name)
    if handlers_error is not None:
        return _fail(
            ModuleContractCode.HANDLERS_MODULE_IMPORT_FAILED,
            f"Failed to import handlers module: {handlers_error}",
            registry_module_name,
            handlers_module_name,
            None,
            None,
            [_issue(ModuleContractCode.HANDLERS_MODULE_IMPORT_FAILED, str(handlers_error), "handlers_module")],
        )

    registry_export_name, registry = _find_mapping_export(
        registry_module,
        ("TASK_REGISTRY", "get_task_registry", "load_task_registry", "build_task_registry", "task_registry"),
    )
    if registry is None or registry_export_name is None:
        return _fail(
            ModuleContractCode.REGISTRY_EXPORT_MISSING,
            "Could not find frozen registry export.",
            registry_module_name,
            handlers_module_name,
            None,
            None,
            [_issue(ModuleContractCode.REGISTRY_EXPORT_MISSING, "Frozen registry export is missing.", "registry_export")],
        )

    handlers_export_name, handlers = _find_mapping_export(
        handlers_module,
        ("TASK_HANDLERS", "get_task_handlers", "load_task_handlers", "build_task_handlers", "task_handlers"),
    )
    if handlers is None or handlers_export_name is None:
        return _fail(
            ModuleContractCode.HANDLERS_EXPORT_MISSING,
            "Could not find frozen handlers export.",
            registry_module_name,
            handlers_module_name,
            registry_export_name,
            None,
            [_issue(ModuleContractCode.HANDLERS_EXPORT_MISSING, "Frozen handlers export is missing.", "handlers_export")],
        )

    issues: list[ModuleContractIssue] = []
    issues.extend(_validate_registry_shape(registry))
    issues.extend(_validate_handlers_shape(handlers))

    if issues:
        first_code = ModuleContractCode.REGISTRY_SHAPE_DRIFT
        if any(item.code == ModuleContractCode.HANDLER_ENTRY_NOT_CALLABLE.value for item in issues):
            first_code = ModuleContractCode.HANDLER_ENTRY_NOT_CALLABLE
        elif any(item.code == ModuleContractCode.HANDLERS_EXPORT_INVALID.value for item in issues):
            first_code = ModuleContractCode.HANDLERS_EXPORT_INVALID

        return _fail(
            first_code,
            "Module contract locking failed.",
            registry_module_name,
            handlers_module_name,
            registry_export_name,
            handlers_export_name,
            issues,
        )

    return _ok(
        "Module contracts locked successfully.",
        registry_module_name,
        handlers_module_name,
        registry_export_name,
        handlers_export_name,
    )


def validate_cli_entry_name(entry_name: Any) -> ModuleContractReport:
    if entry_name != "scripts/cli_entry.py":
        return _fail(
            ModuleContractCode.CLI_ENTRY_INVALID,
            "CLI entry path must be scripts/cli_entry.py.",
            DEFAULT_REGISTRY_MODULE,
            DEFAULT_HANDLERS_MODULE,
            None,
            None,
            [_issue(ModuleContractCode.CLI_ENTRY_INVALID, "Invalid CLI entry path.", "cli_entry")],
        )

    return _ok(
        "CLI entry path is valid.",
        DEFAULT_REGISTRY_MODULE,
        DEFAULT_HANDLERS_MODULE,
        "TASK_REGISTRY",
        "TASK_HANDLERS",
    )


def validate_worker_entry_name(entry_name: Any) -> ModuleContractReport:
    if entry_name != "scripts/worker_entry.py":
        return _fail(
            ModuleContractCode.WORKER_ENTRY_INVALID,
            "Worker entry path must be scripts/worker_entry.py.",
            DEFAULT_REGISTRY_MODULE,
            DEFAULT_HANDLERS_MODULE,
            None,
            None,
            [_issue(ModuleContractCode.WORKER_ENTRY_INVALID, "Invalid worker entry path.", "worker_entry")],
        )

    return _ok(
        "Worker entry path is valid.",
        DEFAULT_REGISTRY_MODULE,
        DEFAULT_HANDLERS_MODULE,
        "TASK_REGISTRY",
        "TASK_HANDLERS",
    )
