from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _success(
    details: dict[str, Any],
    artifacts: list[str] | None = None,
    handoff_tasks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "success",
        "details": details,
        "artifacts": artifacts or [],
    }
    if handoff_tasks:
        result["handoff_tasks"] = handoff_tasks
    return result


def _failed(
    handler_name: str,
    error_message: str,
    extra_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {"handler": handler_name}
    if extra_details:
        details.update(extra_details)

    return {
        "status": "failed",
        "details": details,
        "artifacts": [],
        "error": error_message,
    }


def _first_non_empty_str(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def handle_backend_test(payload: dict[str, Any]) -> dict[str, Any]:
    return _success(
        {
            "handler": "handle_backend_test",
            "received_keys": sorted(payload.keys()),
        }
    )


def handle_backend_fail_test(payload: dict[str, Any]) -> dict[str, Any]:
    return _failed(
        "handle_backend_fail_test",
        "intentional negative-path failure",
        {
            "received_keys": sorted(payload.keys()),
            "reason": "intentional invalid result for negative-path testing",
        },
    )


def handle_backend_write_file(payload: dict[str, Any]) -> dict[str, Any]:
    output_path_raw = _first_non_empty_str(payload, "path", "output_path", "target_path")
    content = payload.get("content", "")

    if not isinstance(output_path_raw, str) or not output_path_raw.strip():
        return _failed(
            "handle_backend_write_file",
            "path must be a non-empty string.",
        )

    output_path = Path(output_path_raw)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(str(content), encoding="utf-8")

    return _success(
        {
            "handler": "handle_backend_write_file",
            "written_to": str(output_path),
        },
        [str(output_path)],
    )


def handle_frontend_write_component(payload: dict[str, Any]) -> dict[str, Any]:
    component_path_raw = _first_non_empty_str(payload, "component_path", "target_path", "output_path")
    component_name = payload.get("component_name", "GeneratedComponent")
    source_notes_path = _first_non_empty_str(payload, "source_notes_path")
    explicit_content = payload.get("content")

    if not isinstance(component_path_raw, str) or not component_path_raw.strip():
        return _failed(
            "handle_frontend_write_component",
            "component_path must be a non-empty string.",
        )

    notes_text = ""
    if isinstance(source_notes_path, str) and source_notes_path.strip():
        notes_file = Path(source_notes_path)
        if notes_file.exists():
            notes_text = notes_file.read_text(encoding="utf-8")

    if explicit_content is None:
        component_code = (
            f"export default function {component_name}() {{\n"
            "  return (\n"
            "    <div>\n"
            f"      <h1>{component_name}</h1>\n"
            f"      <pre>{notes_text}</pre>\n"
            "    </div>\n"
            "  );\n"
            "}\n"
        )
    else:
        component_code = str(explicit_content)

    component_path = Path(component_path_raw)
    component_path.parent.mkdir(parents=True, exist_ok=True)
    component_path.write_text(component_code, encoding="utf-8")

    return _success(
        {
            "handler": "handle_frontend_write_component",
            "written_to": str(component_path),
            "component_name": str(component_name),
            "source_notes_path": str(source_notes_path) if source_notes_path is not None else None,
        },
        [str(component_path)],
    )


def handle_research_collect_notes(payload: dict[str, Any]) -> dict[str, Any]:
    topic = _first_non_empty_str(payload, "topic", "title")
    notes_path_raw = _first_non_empty_str(payload, "notes_path", "output_path", "target_path")
    workflow_run_key = _first_non_empty_str(payload, "workflow_run_key")

    if not isinstance(topic, str) or not topic.strip():
        return _failed(
            "handle_research_collect_notes",
            "topic must be a non-empty string.",
        )

    if not isinstance(notes_path_raw, str) or not notes_path_raw.strip():
        return _failed(
            "handle_research_collect_notes",
            "notes_path must be a non-empty string.",
        )

    notes_path = Path(notes_path_raw)
    notes_path.parent.mkdir(parents=True, exist_ok=True)

    notes_payload = {
        "topic": topic,
        "workflow_run_key": workflow_run_key,
        "notes": [
            {
                "title": "summary",
                "summary": f"Collected notes for topic: {topic}",
            }
        ],
    }

    notes_text = (
        f"# {topic}\n\n"
        f"- workflow_run_key: {workflow_run_key}\n"
        f"- summary: Collected notes for topic: {topic}\n"
    )
    notes_path.write_text(notes_text, encoding="utf-8")

    handoff_tasks: list[dict[str, Any]] = []
    if isinstance(workflow_run_key, str) and workflow_run_key.strip():
        handoff_tasks.append(
            {
                "task_type": "backend.write_file",
                "priority": 105,
                "max_attempts": 2,
                "payload": {
                    "workflow_run_key": workflow_run_key,
                    "path": str(Path("artifacts") / "runs" / workflow_run_key / "workflows" / "research_handoff_manifest.txt"),
                    "content": json.dumps(notes_payload, indent=2, ensure_ascii=False),
                },
            }
        )

    return _success(
        {
            "handler": "handle_research_collect_notes",
            "written_to": str(notes_path),
            "topic": topic,
            "workflow_run_key": workflow_run_key,
            "notes_count": len(notes_payload["notes"]),
        },
        [str(notes_path)],
        handoff_tasks=handoff_tasks,
    )


TASK_HANDLERS: dict[str, Any] = {
    "handle_backend_test": handle_backend_test,
    "handle_backend_fail_test": handle_backend_fail_test,
    "handle_backend_write_file": handle_backend_write_file,
    "handle_frontend_write_component": handle_frontend_write_component,
    "handle_research_collect_notes": handle_research_collect_notes,
}


def get_task_handlers() -> dict[str, Any]:
    return TASK_HANDLERS


def run_handler(task_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    from scripts.task_registry import get_handler_name

    handler_name = get_handler_name(task_type)
    if not isinstance(handler_name, str) or not handler_name.strip():
        return _failed(
            "run_handler",
            f"Unknown task type: {task_type}",
            {"task_type": task_type},
        )

    handler = TASK_HANDLERS.get(handler_name)
    if not callable(handler):
        return _failed(
            "run_handler",
            f"Handler not found: {handler_name}",
            {
                "task_type": task_type,
                "handler_name": handler_name,
            },
        )

    result = handler(payload)
    if not isinstance(result, dict):
        return _failed(
            "run_handler",
            "Handler returned a non-dict result.",
            {
                "task_type": task_type,
                "handler_name": handler_name,
            },
        )

    return result
