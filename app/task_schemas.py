from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator


TASK_SCHEMAS: dict[str, dict[str, Any]] = {
    "backend.write_file": {
        "type": "object",
        "additionalProperties": False,
        "required": ["path", "content"],
        "properties": {
            "workflow_run_key": {"type": "string", "minLength": 1},
            "path": {"type": "string", "minLength": 1},
            "content": {"type": "string"},
        },
    },
    "backend.fail_test": {
        "type": "object",
        "additionalProperties": False,
        "required": ["note"],
        "properties": {
            "note": {"type": "string", "minLength": 1},
        },
    },
    "backend.test": {
        "type": "object",
        "additionalProperties": True,
        "properties": {},
    },
    "frontend.write_component": {
        "type": "object",
        "additionalProperties": False,
        "required": ["component_name", "workflow_run_key", "source_notes_path", "component_path"],
        "properties": {
            "component_name": {
                "type": "string",
                "minLength": 1,
                "pattern": r"^[A-Z][A-Za-z0-9_]*$",
            },
            "workflow_run_key": {"type": "string", "minLength": 1},
            "source_notes_path": {"type": "string", "minLength": 1},
            "component_path": {"type": "string", "minLength": 1},
        },
    },
    "research.collect_notes": {
        "type": "object",
        "additionalProperties": False,
        "required": ["topic", "workflow_run_key", "notes_path"],
        "properties": {
            "topic": {"type": "string", "minLength": 1},
            "workflow_run_key": {"type": "string", "minLength": 1},
            "notes_path": {"type": "string", "minLength": 1},
        },
    },
}


def get_task_schema(task_type: str) -> dict[str, Any]:
    if task_type not in TASK_SCHEMAS:
        raise ValueError(f"No schema registered for task_type: {task_type}")
    return TASK_SCHEMAS[task_type]


def validate_task_payload(task_type: str, payload: dict[str, Any]) -> list[str]:
    schema = get_task_schema(task_type)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))

    messages: list[str] = []
    for error in errors:
        if error.absolute_path:
            path = ".".join(str(part) for part in error.absolute_path)
            messages.append(f"{path}: {error.message}")
        else:
            messages.append(error.message)
    return messages
