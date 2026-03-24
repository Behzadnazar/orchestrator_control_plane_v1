#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.db import create_task, init_db  # noqa: E402
from scripts.task_registry import get_task_spec, is_known_task_type  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enqueue a task into the control plane DB.")
    parser.add_argument("--task-type", required=True)
    parser.add_argument("--payload-json", required=True)
    parser.add_argument("--priority", type=int, default=100)
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--workflow-id")
    parser.add_argument("--workflow-run-key")
    parser.add_argument("--correlation-id")
    parser.add_argument("--parent-task-id")
    parser.add_argument("--depends-on-task-id")
    parser.add_argument("--handoff-from-task-id")
    return parser.parse_args()


def _load_payload(payload_json: str) -> dict[str, Any]:
    payload = json.loads(payload_json)
    if not isinstance(payload, dict):
        raise RuntimeError("payload-json must decode to a JSON object")
    return payload


def _validate_payload(task_type: str, payload: dict[str, Any]) -> None:
    spec = get_task_spec(task_type)
    if spec is None:
        raise RuntimeError(f"unknown task_type: {task_type}")

    required_keys = spec["required_payload_keys"]
    missing = [key for key in required_keys if key not in payload]
    if missing:
        raise RuntimeError(f"missing required payload keys for {task_type}: {missing}")


def main() -> int:
    os.chdir(BASE_DIR)
    args = parse_args()

    if not is_known_task_type(args.task_type):
        raise RuntimeError(f"unknown task_type: {args.task_type}")

    payload = _load_payload(args.payload_json)
    _validate_payload(args.task_type, payload)

    init_db()

    task_id = create_task(
        task_type=args.task_type,
        payload=payload,
        priority=int(args.priority),
        max_attempts=int(args.max_attempts),
        workflow_id=args.workflow_id,
        workflow_run_key=args.workflow_run_key,
        correlation_id=args.correlation_id,
        parent_task_id=args.parent_task_id,
        depends_on_task_id=args.depends_on_task_id,
        handoff_from_task_id=args.handoff_from_task_id,
    )

    print(json.dumps({"task_id": task_id, "task_type": args.task_type}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
