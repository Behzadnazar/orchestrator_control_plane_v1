from __future__ import annotations

import json
from typing import Any

from app.db import (
    create_task,
    ensure_worker,
    get_latest_tasks,
    get_task,
    get_workflow_tasks,
    init_db,
    list_workers,
    reset_demo_data,
    seed_demo_tasks_if_empty,
)
from app.graph_invariants import validate_graph_invariants
from app.task_contracts import validate_business_rules, validate_task_payload
from scripts.policy_engine import classify_task_routability, get_policy_snapshot
from scripts.task_registry import AGENT_REGISTRY, get_worker_capabilities


class ControlPlaneService:
    def __init__(self) -> None:
        init_db()

    def health(self) -> dict[str, Any]:
        policy = get_policy_snapshot()
        workers = list_workers()
        tasks = get_latest_tasks(limit=20)
        return {
            "status": "ok",
            "policy_version": policy.get("policy_version"),
            "registered_workers": sorted(AGENT_REGISTRY.keys()),
            "worker_count": len(workers),
            "recent_task_count": len(tasks),
        }

    def register_worker(self, worker_id: str) -> dict[str, Any]:
        ensure_worker(worker_id, get_worker_capabilities(worker_id))
        return {
            "worker_id": worker_id,
            "capabilities": get_worker_capabilities(worker_id),
            "registered": True,
        }

    def reset_demo(self) -> dict[str, Any]:
        reset_demo_data()
        init_db()
        return {"reset": True}

    def seed_demo(self) -> dict[str, Any]:
        seed_demo_tasks_if_empty()
        tasks = get_latest_tasks(limit=50)
        return {
            "seeded": True,
            "count": len(tasks),
            "tasks": [self._serialize_task(task, include_events=False) for task in tasks],
        }

    def get_workers(self) -> dict[str, Any]:
        workers: list[dict[str, Any]] = []
        for worker in list_workers():
            row = dict(worker)
            workers.append(
                {
                    "worker_id": row["worker_id"],
                    "status": row["status"],
                    "current_task_id": row["current_task_id"],
                    "current_correlation_id": row["current_correlation_id"],
                    "last_heartbeat_at": row["last_heartbeat_at"],
                    "capabilities": self._parse_json_field(row.get("capabilities_json")),
                }
            )
        return {
            "count": len(workers),
            "workers": workers,
        }

    def enqueue_task(
        self,
        *,
        task_type: str,
        payload: dict[str, Any],
        priority: int = 100,
        max_attempts: int = 3,
        correlation_id: str | None = None,
        workflow_id: str | None = None,
        workflow_run_key: str | None = None,
        parent_task_id: str | None = None,
        depends_on_task_id: str | None = None,
        handoff_from_task_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(priority, int) or not 1 <= priority <= 1000:
            raise ValueError("priority must be an integer between 1 and 1000")

        if not isinstance(max_attempts, int) or not 1 <= max_attempts <= 20:
            raise ValueError("max_attempts must be an integer between 1 and 20")

        schema_errors = validate_task_payload(task_type, payload)
        if schema_errors:
            raise ValueError("payload schema validation failed: " + " | ".join(schema_errors))

        validated = validate_business_rules(
            task_type=task_type,
            payload=payload,
            correlation_id=correlation_id,
            workflow_id=workflow_id,
            workflow_run_key=workflow_run_key,
            parent_task_id=parent_task_id,
            depends_on_task_id=depends_on_task_id,
            handoff_from_task_id=handoff_from_task_id,
        )

        validate_graph_invariants(
            task_type=task_type,
            workflow_id=validated["workflow_id"],
            workflow_run_key=validated["workflow_run_key"],
            parent_task_id=validated["parent_task_id"],
            depends_on_task_id=validated["depends_on_task_id"],
            handoff_from_task_id=validated["handoff_from_task_id"],
        )

        task_id = create_task(
            task_type=task_type,
            payload=validated["payload"],
            priority=priority,
            max_attempts=max_attempts,
            correlation_id=validated["correlation_id"],
            workflow_id=validated["workflow_id"],
            workflow_run_key=validated["workflow_run_key"],
            parent_task_id=validated["parent_task_id"],
            depends_on_task_id=validated["depends_on_task_id"],
            handoff_from_task_id=validated["handoff_from_task_id"],
        )
        return self.get_task_details(task_id)

    def get_task_details(self, task_id: str) -> dict[str, Any]:
        task = get_task(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        return self._serialize_task(task, include_events=False)

    def get_workflow_details(self, workflow_id: str) -> dict[str, Any]:
        tasks = [dict(task) for task in get_workflow_tasks(workflow_id)]

        tasks.sort(
            key=lambda item: (
                item.get("created_at") or "",
                item.get("task_id") or "",
            )
        )

        serialized = [self._serialize_task(task, include_events=False) for task in tasks]

        return {
            "workflow_id": workflow_id,
            "workflow_run_keys": sorted(
                {
                    task["workflow_run_key"]
                    for task in tasks
                    if task.get("workflow_run_key")
                }
            ),
            "tasks": serialized,
            "count": len(serialized),
        }

    def _serialize_task(
        self,
        task: dict[str, Any] | Any,
        *,
        include_events: bool = False,
    ) -> dict[str, Any]:
        row = dict(task)

        routable, route_info = classify_task_routability(row["task_type"])

        data: dict[str, Any] = {
            "task_id": row["task_id"],
            "task_type": row["task_type"],
            "status": row["status"],
            "priority": row.get("priority"),
            "max_attempts": row.get("max_attempts"),
            "attempt_count": row.get("attempt_count"),
            "worker_id": row.get("worker_id"),
            "workflow_id": row.get("workflow_id"),
            "workflow_run_key": row.get("workflow_run_key"),
            "correlation_id": row.get("correlation_id"),
            "parent_task_id": row.get("parent_task_id"),
            "depends_on_task_id": row.get("depends_on_task_id"),
            "handoff_from_task_id": row.get("handoff_from_task_id"),
            "dependency_status": row.get("dependency_status"),
            "payload": self._parse_json_field(row.get("payload_json")),
            "result_payload": self._parse_json_field(row.get("result_payload_json")),
            "last_error": row.get("last_error"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "started_at": row.get("started_at"),
            "finished_at": row.get("finished_at"),
            "claim_deadline_at": row.get("claim_deadline_at"),
            "running_deadline_at": row.get("running_deadline_at"),
            "last_worker_heartbeat_at": row.get("last_worker_heartbeat_at"),
            "routable": routable,
            "route_info": route_info,
            "events": [],
        }

        if include_events:
            data["events"] = []

        return data

    def _parse_json_field(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
        return value
