from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.services.control_plane_service import ControlPlaneService
from scripts.task_registry import AGENT_REGISTRY


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Control Plane CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health")
    sub.add_parser("reset-demo")
    sub.add_parser("seed-demo")
    sub.add_parser("list-workers")

    p_register = sub.add_parser("register-worker")
    p_register.add_argument("--worker-id", required=True, choices=sorted(AGENT_REGISTRY.keys()))

    p_list_tasks = sub.add_parser("list-tasks")
    p_list_tasks.add_argument("--limit", type=int, default=50)

    p_show_task = sub.add_parser("show-task")
    p_show_task.add_argument("--task-id", required=True)

    p_show_workflow = sub.add_parser("show-workflow")
    p_show_workflow.add_argument("--workflow-id", required=True)

    p_enqueue = sub.add_parser("enqueue-task")
    p_enqueue.add_argument("--task-type", required=True)
    p_enqueue.add_argument("--payload-json", required=True)
    p_enqueue.add_argument("--priority", type=int, default=100)
    p_enqueue.add_argument("--max-attempts", type=int, default=3)
    p_enqueue.add_argument("--correlation-id")
    p_enqueue.add_argument("--workflow-id")
    p_enqueue.add_argument("--workflow-run-key")
    p_enqueue.add_argument("--parent-task-id")
    p_enqueue.add_argument("--depends-on-task-id")
    p_enqueue.add_argument("--handoff-from-task-id")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    service = ControlPlaneService()

    if args.command == "health":
        print(json.dumps(service.health(), indent=2, ensure_ascii=False))
        return

    if args.command == "reset-demo":
        print(json.dumps(service.reset_demo(), indent=2, ensure_ascii=False))
        return

    if args.command == "seed-demo":
        print(json.dumps(service.seed_demo(), indent=2, ensure_ascii=False))
        return

    if args.command == "list-workers":
        print(json.dumps(service.list_workers(), indent=2, ensure_ascii=False))
        return

    if args.command == "register-worker":
        print(json.dumps(service.register_worker(args.worker_id), indent=2, ensure_ascii=False))
        return

    if args.command == "list-tasks":
        print(json.dumps(service.list_tasks(limit=args.limit), indent=2, ensure_ascii=False))
        return

    if args.command == "show-task":
        print(json.dumps(service.get_task_details(args.task_id), indent=2, ensure_ascii=False))
        return

    if args.command == "show-workflow":
        print(json.dumps(service.get_workflow_details(args.workflow_id), indent=2, ensure_ascii=False))
        return

    if args.command == "enqueue-task":
        payload = json.loads(args.payload_json)
        print(
            json.dumps(
                service.enqueue_task(
                    task_type=args.task_type,
                    payload=payload,
                    priority=args.priority,
                    max_attempts=args.max_attempts,
                    correlation_id=args.correlation_id,
                    workflow_id=args.workflow_id,
                    workflow_run_key=args.workflow_run_key,
                    parent_task_id=args.parent_task_id,
                    depends_on_task_id=args.depends_on_task_id,
                    handoff_from_task_id=args.handoff_from_task_id,
                ),
                indent=2,
                ensure_ascii=False,
            )
        )
        return


if __name__ == "__main__":
    main()
