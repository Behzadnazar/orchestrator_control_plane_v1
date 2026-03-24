from __future__ import annotations

from typing import Any

from app.db import get_task


def _require_same_workflow(
    ref_name: str,
    ref_task: dict[str, Any],
    workflow_id: str | None,
    workflow_run_key: str | None,
) -> None:
    if workflow_id and ref_task["workflow_id"] != workflow_id:
        raise ValueError(
            f"{ref_name} belongs to workflow_id={ref_task['workflow_id']}, expected {workflow_id}"
        )

    if workflow_run_key and ref_task.get("workflow_run_key") != workflow_run_key:
        raise ValueError(
            f"{ref_name} belongs to workflow_run_key={ref_task.get('workflow_run_key')}, expected {workflow_run_key}"
        )


def _load_reference(
    ref_name: str,
    task_id: str | None,
    workflow_id: str | None,
    workflow_run_key: str | None,
) -> dict[str, Any] | None:
    if not task_id:
        return None

    ref_task = get_task(task_id)
    if not ref_task:
        raise ValueError(f"{ref_name} not found: {task_id}")

    _require_same_workflow(ref_name, ref_task, workflow_id, workflow_run_key)
    return ref_task


def validate_graph_invariants(
    *,
    task_type: str,
    workflow_id: str | None,
    workflow_run_key: str | None,
    parent_task_id: str | None,
    depends_on_task_id: str | None,
    handoff_from_task_id: str | None,
) -> dict[str, Any]:
    refs = {
        "parent_task_id": parent_task_id,
        "depends_on_task_id": depends_on_task_id,
        "handoff_from_task_id": handoff_from_task_id,
    }
    present_ref_count = sum(1 for value in refs.values() if value)

    if present_ref_count not in {0, 3}:
        raise ValueError(
            "graph-linked tasks require parent_task_id, depends_on_task_id, and handoff_from_task_id together"
        )

    if present_ref_count == 3 and (not workflow_id or not workflow_run_key):
        raise ValueError("workflow_id and workflow_run_key are required for graph-linked tasks")

    parent_task = _load_reference("parent_task_id", parent_task_id, workflow_id, workflow_run_key)
    depends_task = _load_reference("depends_on_task_id", depends_on_task_id, workflow_id, workflow_run_key)
    handoff_task = _load_reference("handoff_from_task_id", handoff_from_task_id, workflow_id, workflow_run_key)

    if parent_task_id and depends_on_task_id and parent_task_id != depends_on_task_id:
        raise ValueError("parent_task_id and depends_on_task_id must match for dependent child tasks")

    if handoff_from_task_id and depends_on_task_id and handoff_from_task_id != depends_on_task_id:
        raise ValueError("handoff_from_task_id must match depends_on_task_id")

    if handoff_from_task_id and parent_task_id and handoff_from_task_id != parent_task_id:
        raise ValueError("handoff_from_task_id must match parent_task_id")

    if parent_task:
        if parent_task["status"] in {"dead_letter", "failed"}:
            raise ValueError("cannot attach child task to failed/dead-letter parent task")

    if depends_task:
        if depends_task["status"] in {"dead_letter", "failed"}:
            raise ValueError("cannot depend on failed/dead-letter task")

    if handoff_task:
        allowed_handoff_sources = {
            "research.collect_notes",
            "frontend.write_component",
            "backend.write_file",
        }
        if handoff_task["task_type"] not in allowed_handoff_sources:
            raise ValueError(
                f"handoff_from_task_id task_type={handoff_task['task_type']} is not allowed to create downstream handoff"
            )

    if task_type == "frontend.write_component":
        if depends_task and depends_task["task_type"] != "research.collect_notes":
            raise ValueError("frontend.write_component must depend on research.collect_notes")

    if task_type == "backend.write_file":
        if depends_task and depends_task["task_type"] not in {"frontend.write_component", "research.collect_notes"}:
            raise ValueError("backend.write_file may only depend on frontend.write_component or research.collect_notes")

    return {
        "parent_task": parent_task,
        "depends_task": depends_task,
        "handoff_task": handoff_task,
    }
