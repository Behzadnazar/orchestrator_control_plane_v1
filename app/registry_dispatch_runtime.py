from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from importlib import import_module
from pathlib import Path
from typing import Any

from app.execution_contracts import FailureCode
from app.executor_runtime import execute_handler_with_contract
from app.persistent_queue_runtime import (
    claim_next_queued_item,
    dead_letter_persistent_item,
    get_persistent_queue_item,
    transition_persistent_item,
)


DEFAULT_REGISTRY_MODULE = "scripts.task_registry"
DEFAULT_HANDLERS_MODULE = "scripts.task_handlers"


@dataclass(frozen=True)
class RegistryDispatchResult:
    ok: bool
    code: str
    message: str
    payload: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _result(ok: bool, code: str, message: str, payload: dict[str, Any] | None = None) -> RegistryDispatchResult:
    return RegistryDispatchResult(
        ok=ok,
        code=code,
        message=message,
        payload=payload,
    )


def _resolve_registry_mapping(module: Any) -> Mapping[str, Any]:
    candidate_names = (
        "get_task_registry",
        "load_task_registry",
        "build_task_registry",
        "TASK_REGISTRY",
        "TASK_TYPES",
        "REGISTRY",
        "task_registry",
    )

    for name in candidate_names:
        value = getattr(module, name, None)

        if isinstance(value, Mapping):
            return value

        if callable(value):
            try:
                resolved = value()
            except TypeError:
                continue
            if isinstance(resolved, Mapping):
                return resolved

    raise LookupError("Could not resolve registry mapping from module.")


def _resolve_handlers_mapping(module: Any) -> dict[str, Callable[..., Any]]:
    candidate_names = (
        "get_task_handlers",
        "load_task_handlers",
        "build_task_handlers",
        "TASK_HANDLERS",
        "HANDLER_REGISTRY",
        "HANDLERS",
        "task_handlers",
    )

    handlers: dict[str, Callable[..., Any]] = {}

    for name in candidate_names:
        value = getattr(module, name, None)

        if isinstance(value, Mapping):
            for key, candidate in value.items():
                if isinstance(key, str) and callable(candidate):
                    handlers[key] = candidate
                elif callable(key) and isinstance(candidate, str):
                    handlers[candidate] = key

        elif callable(value):
            try:
                resolved = value()
            except TypeError:
                resolved = None
            if isinstance(resolved, Mapping):
                for key, candidate in resolved.items():
                    if isinstance(key, str) and callable(candidate):
                        handlers[key] = candidate
                    elif callable(key) and isinstance(candidate, str):
                        handlers[candidate] = key

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


def _extract_handler_name(raw_entry: Any) -> str | None:
    if callable(raw_entry):
        return getattr(raw_entry, "__name__", None)

    if isinstance(raw_entry, str):
        return raw_entry

    if isinstance(raw_entry, Mapping):
        handler_value = (
            raw_entry.get("handler")
            or raw_entry.get("handler_name")
            or raw_entry.get("callable")
            or raw_entry.get("fn")
            or raw_entry.get("function")
        )
        if callable(handler_value):
            return getattr(handler_value, "__name__", None)
        if isinstance(handler_value, str) and handler_value.strip():
            return handler_value

    return None


def load_registry_and_handlers(
    registry_module_name: str = DEFAULT_REGISTRY_MODULE,
    handlers_module_name: str = DEFAULT_HANDLERS_MODULE,
) -> tuple[Mapping[str, Any], dict[str, Callable[..., Any]]]:
    registry_module = import_module(registry_module_name)
    handlers_module = import_module(handlers_module_name)

    registry = _resolve_registry_mapping(registry_module)
    handlers = _resolve_handlers_mapping(handlers_module)

    return registry, handlers


def resolve_handler_for_task_type(
    task_type: str,
    *,
    registry: Mapping[str, Any],
    handlers: Mapping[str, Callable[..., Any]],
) -> tuple[Callable[[dict[str, Any]], Any] | None, str | None, str]:
    if task_type not in registry:
        return None, None, FailureCode.UNKNOWN_TASK_TYPE.value

    raw_entry = registry[task_type]

    if callable(raw_entry):
        return raw_entry, getattr(raw_entry, "__name__", None), "OK"

    handler_name = _extract_handler_name(raw_entry)
    if not handler_name:
        return None, None, FailureCode.HANDLER_NOT_CALLABLE.value

    handler = handlers.get(handler_name)
    if not callable(handler):
        return None, handler_name, FailureCode.HANDLER_NOT_CALLABLE.value

    return handler, handler_name, "OK"


def _execute_claimed_item(
    db_path: str | Path,
    queue_item_id: str,
    handler: Callable[[dict[str, Any]], Any],
    *,
    handler_name: str | None,
) -> RegistryDispatchResult:
    item = get_persistent_queue_item(db_path, queue_item_id)
    if item is None:
        return _result(
            False,
            FailureCode.INTERNAL_ERROR.value,
            "Claimed queue item disappeared before execution.",
            {"queue_item_id": queue_item_id},
        )

    moved_to_running = transition_persistent_item(db_path, queue_item_id, "claimed", "running")
    if not moved_to_running.ok:
        return _result(
            False,
            moved_to_running.code,
            moved_to_running.message,
            moved_to_running.payload,
        )

    payload = {
        "task_type": item["task_type"],
        "input": {
            "queue_item_id": item["queue_item_id"],
            "task_id": item["task_id"],
        },
    }

    executed = execute_handler_with_contract(payload, handler, handler_name=handler_name)

    if executed.ok:
        moved_to_completed = transition_persistent_item(db_path, queue_item_id, "running", "completed")
        if not moved_to_completed.ok:
            return _result(
                False,
                moved_to_completed.code,
                moved_to_completed.message,
                moved_to_completed.payload,
            )

        return _result(
            True,
            "OK",
            "Registry-to-worker dispatch completed successfully.",
            {
                "queue_item_id": queue_item_id,
                "task_type": item["task_type"],
                "handler_name": handler_name,
                "execution_result": executed.to_dict(),
                "final_transition": moved_to_completed.to_dict(),
            },
        )

    moved_to_failed = transition_persistent_item(db_path, queue_item_id, "running", "failed")
    if not moved_to_failed.ok:
        return _result(
            False,
            moved_to_failed.code,
            moved_to_failed.message,
            {
                "queue_item_id": queue_item_id,
                "execution_result": executed.to_dict(),
                "failed_transition": moved_to_failed.to_dict(),
            },
        )

    dlq = dead_letter_persistent_item(
        db_path,
        queue_item_id,
        executed.code,
        executed.message or "execution failure",
        replayable=True,
    )

    return _result(
        False,
        executed.code,
        "Registry-to-worker dispatch failed and recovery path was executed.",
        {
            "queue_item_id": queue_item_id,
            "task_type": item["task_type"],
            "handler_name": handler_name,
            "execution_result": executed.to_dict(),
            "failed_transition": moved_to_failed.to_dict(),
            "dead_letter_result": dlq.to_dict(),
        },
    )


def dispatch_queue_item_via_registry(
    db_path: str | Path,
    worker_id: str,
    *,
    registry_module_name: str = DEFAULT_REGISTRY_MODULE,
    handlers_module_name: str = DEFAULT_HANDLERS_MODULE,
    registry_override: Mapping[str, Any] | None = None,
    handlers_override: Mapping[str, Callable[..., Any]] | None = None,
) -> RegistryDispatchResult:
    if registry_override is None or handlers_override is None:
        registry, handlers = load_registry_and_handlers(
            registry_module_name=registry_module_name,
            handlers_module_name=handlers_module_name,
        )
    else:
        registry = registry_override
        handlers = dict(handlers_override)

    claimed = claim_next_queued_item(db_path, worker_id)
    if not claimed.ok:
        return _result(
            claimed.ok,
            claimed.code,
            claimed.message,
            claimed.payload,
        )

    queue_item_id = claimed.payload["queue_item_id"]
    item = get_persistent_queue_item(db_path, queue_item_id)
    if item is None:
        return _result(
            False,
            FailureCode.INTERNAL_ERROR.value,
            "Claimed queue item disappeared before registry dispatch.",
            {"queue_item_id": queue_item_id},
        )

    task_type = item["task_type"]
    handler, handler_name, resolution_code = resolve_handler_for_task_type(
        task_type,
        registry=registry,
        handlers=handlers,
    )

    if resolution_code == FailureCode.UNKNOWN_TASK_TYPE.value:
        dlq = dead_letter_persistent_item(
            db_path,
            queue_item_id,
            FailureCode.UNKNOWN_TASK_TYPE.value,
            f"Unknown task type: {task_type}",
            replayable=False,
        )
        return _result(
            False,
            FailureCode.UNKNOWN_TASK_TYPE.value,
            "Queue item dead-lettered because task type is unknown.",
            {
                "queue_item_id": queue_item_id,
                "task_type": task_type,
                "dead_letter_result": dlq.to_dict(),
            },
        )

    if resolution_code == FailureCode.HANDLER_NOT_CALLABLE.value or not callable(handler):
        dlq = dead_letter_persistent_item(
            db_path,
            queue_item_id,
            FailureCode.HANDLER_NOT_CALLABLE.value,
            f"Handler resolution failed for task type: {task_type}",
            replayable=False,
        )
        return _result(
            False,
            FailureCode.HANDLER_NOT_CALLABLE.value,
            "Queue item dead-lettered because handler resolution failed.",
            {
                "queue_item_id": queue_item_id,
                "task_type": task_type,
                "handler_name": handler_name,
                "dead_letter_result": dlq.to_dict(),
            },
        )

    return _execute_claimed_item(
        db_path,
        queue_item_id,
        handler,
        handler_name=handler_name,
    )
