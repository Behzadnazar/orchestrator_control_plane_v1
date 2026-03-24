from __future__ import annotations

import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.db import get_latest_tasks, get_recent_events, get_workflow_tasks, init_db, list_workers
from scripts.policy_engine import classify_task_routability


def print_task(task: dict) -> None:
    routable, route_info = classify_task_routability(task["task_type"])

    print("=" * 160)
    print(f"task_id                  : {task['task_id']}")
    print(f"workflow_id              : {task['workflow_id']}")
    print(f"workflow_run_key         : {task['workflow_run_key']}")
    print(f"task_type                : {task['task_type']}")
    print(f"status                   : {task['status']}")
    print(f"dependency_status        : {task['dependency_status']}")
    print(f"parent_task_id           : {task['parent_task_id']}")
    print(f"depends_on_task_id       : {task['depends_on_task_id']}")
    print(f"handoff_from_task_id     : {task['handoff_from_task_id']}")
    print(f"attempt_count            : {task['attempt_count']} / {task['max_attempts']}")
    print(f"worker                   : {task['claimed_by_worker']}")
    print(f"correlation_id           : {task['correlation_id']}")
    print(f"payload_hash             : {task['payload_hash']}")
    print(f"last_error               : {task['last_error']}")
    print(f"routable                 : {routable}")
    print(f"route_info               : {route_info}")
    print(f"created_at               : {task['created_at']}")
    print(f"claimed_at               : {task['claimed_at']}")
    print(f"claim_deadline_at        : {task['claim_deadline_at']}")
    print(f"started_at               : {task['started_at']}")
    print(f"running_deadline_at      : {task['running_deadline_at']}")
    print(f"last_worker_heartbeat_at : {task['last_worker_heartbeat_at']}")
    print(f"finished_at              : {task['finished_at']}")
    print("payload                  :", json.loads(task["payload_json"]))

    workflow_tasks = get_workflow_tasks(task["workflow_id"])
    print("workflow_graph           :")
    for wf_task in workflow_tasks:
        print(
            f"  - {wf_task['task_id']} | type={wf_task['task_type']} | "
            f"status={wf_task['status']} | parent={wf_task['parent_task_id']} | "
            f"depends_on={wf_task['depends_on_task_id']} | handoff_from={wf_task['handoff_from_task_id']} | "
            f"run_key={wf_task['workflow_run_key']}"
        )

    print("\nlast_12_events:")
    events = get_recent_events(task["task_id"], limit=12)
    if not events:
        print("  (no events)")
    else:
        for event in events:
            payload = json.loads(event["event_payload_json"])
            print(
                f"  - {event['created_at']} | {event['event_type']} | "
                f"{event['from_status']} -> {event['to_status']} | worker={event['worker_id']}"
            )
            print(f"    payload={payload}")
    print()


def print_workers() -> None:
    print("# WORKERS")
    workers = list_workers()
    if not workers:
        print("(no workers)")
        print()
        return

    for worker in workers:
        capabilities = json.loads(worker["capabilities_json"])
        print(
            f"- worker_id={worker['worker_id']} | "
            f"worker_state={worker['status']} | "
            f"current_task_id={worker['current_task_id']} | "
            f"correlation_id={worker['current_correlation_id']} | "
            f"heartbeat={worker['last_heartbeat_at']} | "
            f"capabilities={capabilities}"
        )
    print()


def main() -> None:
    init_db()
    print_workers()

    tasks = get_latest_tasks(limit=120)
    if not tasks:
        print("No tasks found.")
        return

    print("# TASKS")
    for task in tasks:
        print_task(task)


if __name__ == "__main__":
    main()
