from __future__ import annotations

from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = (BASE_DIR / "artifacts").resolve()


def _require_non_empty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _optional_non_empty_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_non_empty_string(value, field_name)


def _resolve_under_base(raw_path: str) -> Path:
    path = Path(raw_path)
    if not path.is_absolute():
        path = BASE_DIR / path

    resolved = path.resolve(strict=False)

    try:
        resolved.relative_to(ARTIFACTS_DIR)
    except ValueError as exc:
        raise ValueError(f"path escapes artifacts namespace: {resolved}") from exc

    return resolved


def _expected_run_dir(workflow_run_key: str) -> Path:
    return (ARTIFACTS_DIR / "runs" / workflow_run_key).resolve(strict=False)


def _require_under_run_dir(
    path_value: str,
    workflow_run_key: str,
    role: str,
    subdir: str,
) -> str:
    resolved = _resolve_under_base(path_value)
    expected_root = (_expected_run_dir(workflow_run_key) / subdir).resolve(strict=False)

    try:
        resolved.relative_to(expected_root)
    except ValueError as exc:
        raise ValueError(
            f"{role} must stay under {expected_root}, got {resolved}"
        ) from exc

    return str(resolved)


def validate_task_payload(task_type: str, payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if not isinstance(task_type, str) or not task_type.strip():
        return ["task_type must be a non-empty string"]

    if not isinstance(payload, dict):
        return ["payload must be a dictionary"]

    if task_type == "backend.write_file":
        if not isinstance(payload.get("path"), str) or not payload.get("path", "").strip():
            errors.append("payload.path must be a non-empty string")
        if not isinstance(payload.get("content"), str):
            errors.append("payload.content must be a string")

    elif task_type == "frontend.write_component":
        if not isinstance(payload.get("source_notes_path"), str) or not payload.get("source_notes_path", "").strip():
            errors.append("payload.source_notes_path must be a non-empty string")
        if not isinstance(payload.get("component_path"), str) or not payload.get("component_path", "").strip():
            errors.append("payload.component_path must be a non-empty string")
        if not isinstance(payload.get("component_name"), str) or not payload.get("component_name", "").strip():
            errors.append("payload.component_name must be a non-empty string")

    elif task_type == "research.collect_notes":
        if not isinstance(payload.get("notes_path"), str) or not payload.get("notes_path", "").strip():
            errors.append("payload.notes_path must be a non-empty string")
        if "query" in payload and not isinstance(payload.get("query"), str):
            errors.append("payload.query must be a string when provided")

    return errors


def validate_business_rules(
    *,
    task_type: str,
    payload: dict[str, Any],
    correlation_id: str | None,
    workflow_id: str | None,
    workflow_run_key: str | None,
    parent_task_id: str | None,
    depends_on_task_id: str | None,
    handoff_from_task_id: str | None,
) -> dict[str, Any]:
    normalized: dict[str, Any] = dict(payload)

    workflow_id = _optional_non_empty_string(workflow_id, "workflow_id")
    workflow_run_key = _optional_non_empty_string(workflow_run_key, "workflow_run_key")
    correlation_id = _optional_non_empty_string(correlation_id, "correlation_id")
    parent_task_id = _optional_non_empty_string(parent_task_id, "parent_task_id")
    depends_on_task_id = _optional_non_empty_string(depends_on_task_id, "depends_on_task_id")
    handoff_from_task_id = _optional_non_empty_string(handoff_from_task_id, "handoff_from_task_id")

    if parent_task_id and not depends_on_task_id:
        raise ValueError("depends_on_task_id is required when parent_task_id is set")

    if handoff_from_task_id and not parent_task_id:
        raise ValueError("parent_task_id is required when handoff_from_task_id is set")

    payload_run_key = _optional_non_empty_string(
        normalized.get("workflow_run_key"),
        "payload.workflow_run_key",
    )

    if workflow_run_key and payload_run_key and workflow_run_key != payload_run_key:
        raise ValueError("workflow_run_key mismatch between request and payload")

    effective_run_key = workflow_run_key or payload_run_key

    guarded_task_types = {
        "backend.write_file",
        "frontend.write_component",
        "research.collect_notes",
    }

    if task_type in guarded_task_types and not effective_run_key:
        raise ValueError(f"workflow_run_key is required for task_type {task_type}")

    if effective_run_key:
        normalized["workflow_run_key"] = effective_run_key

    if task_type == "backend.write_file":
        normalized["path"] = _require_under_run_dir(
            _require_non_empty_string(normalized.get("path"), "payload.path"),
            effective_run_key,
            "payload.path",
            "workflows",
        )

    elif task_type == "frontend.write_component":
        normalized["source_notes_path"] = _require_under_run_dir(
            _require_non_empty_string(
                normalized.get("source_notes_path"),
                "payload.source_notes_path",
            ),
            effective_run_key,
            "payload.source_notes_path",
            "research",
        )
        normalized["component_path"] = _require_under_run_dir(
            _require_non_empty_string(
                normalized.get("component_path"),
                "payload.component_path",
            ),
            effective_run_key,
            "payload.component_path",
            "frontend",
        )

    elif task_type == "research.collect_notes":
        normalized["notes_path"] = _require_under_run_dir(
            _require_non_empty_string(normalized.get("notes_path"), "payload.notes_path"),
            effective_run_key,
            "payload.notes_path",
            "research",
        )

    return {
        "payload": normalized,
        "workflow_id": workflow_id,
        "workflow_run_key": effective_run_key,
        "correlation_id": correlation_id,
        "parent_task_id": parent_task_id,
        "depends_on_task_id": depends_on_task_id,
        "handoff_from_task_id": handoff_from_task_id,
    }
