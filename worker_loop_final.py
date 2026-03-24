from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.db import (
    append_event,
    claim_next_task,
    create_task,
    dead_letter_task_from_queue,
    ensure_worker,
    finish_task_failure,
    finish_task_success,
    get_queued_tasks,
    get_task,
    heartbeat_worker,
    init_db,
    record_task_heartbeat,
    recover_stale_tasks,
    reset_demo_data,
    set_task_running,
    update_worker_state,
)
from scripts.policy_engine import (
    classify_task_routability,
    decide_recovery_action,
    evaluate_admission,
    get_global_limits,
    get_global_worker_loop_settings,
    get_policy_snapshot,
    get_policy_source,
    get_task_limits,
)
from scripts.task_handlers import run_handler
from scripts.task_registry import AGENT_REGISTRY, get_handler_name, get_worker_capabilities

_last_idle_heartbeat_monotonic_by_worker: dict[str, float] = {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase I worker loop")
    parser.add_argument("--worker-id", default="backend-worker-v2", choices=sorted(AGENT_REGISTRY.keys()))
    parser.add_argument("--reset-demo", action="store_true")
    parser.add_argument("--maintenance", action="store_true")
    parser.add_argument("--once-idle-exit", action="store_true")
    return parser.parse_args()


def get_runtime_settings() -> dict[str, int]:
    cfg = get_global_worker_loop_settings()
    return {
        "sleep_seconds": int(cfg["sleep_seconds"]),
        "idle_heartbeat_seconds": int(cfg["idle_heartbeat_seconds"]),
        "task_heartbeat_min_interval_seconds": int(cfg["task_heartbeat_min_interval_seconds"]),
    }


def get_worker_global_limits() -> dict[str, int]:
    cfg = get_global_limits()
    return {
        "claim_timeout_seconds": int(cfg["claim_timeout_seconds"]),
        "heartbeat_timeout_seconds": int(cfg["heartbeat_timeout_seconds"]),
        "max_runtime_seconds": int(cfg["max_runtime_seconds"]),
    }


def set_worker_state_with_event(
    worker_id: str,
    task_id: str | None,
    workflow_id: str | None,
    correlation_id: str | None,
    new_status: str,
    old_status: str,
) -> None:
    update_worker_state(
        worker_id=worker_id,
        status=new_status,
        current_task_id=task_id,
        current_correlation_id=correlation_id,
    )
    if task_id and workflow_id and correlation_id:
        append_event(
            task_id=task_id,
            workflow_id=workflow_id,
            correlation_id=correlation_id,
            worker_id=worker_id,
            event_type="WorkerStateChanged",
            from_status=old_status,
            to_status=new_status,
            payload={"from": old_status, "to": new_status},
        )


def bootstrap(worker_id: str, reset: bool = False) -> None:
    init_db()
    if reset:
        reset_demo_data()
        init_db()
    ensure_worker(worker_id, get_worker_capabilities(worker_id))


def emit_idle_heartbeat_if_due(worker_id: str, idle_heartbeat_seconds: int) -> None:
    now_mono = time.monotonic()
    last = _last_idle_heartbeat_monotonic_by_worker.get(worker_id, 0.0)
    if now_mono - last >= idle_heartbeat_seconds:
        heartbeat_worker(worker_id)
        _last_idle_heartbeat_monotonic_by_worker[worker_id] = now_mono


def sweep_unroutable_queued_tasks(worker_id: str) -> int:
    swept = 0
    queued_tasks = get_queued_tasks(limit=200)

    for task in queued_tasks:
        ok, details = classify_task_routability(task["task_type"])
        if ok:
            continue

        dead_letter_task_from_queue(
            task_id=task["task_id"],
            reason=f"Route guard rejected task: {details['reason']}",
            worker_id=worker_id,
            details=details,
        )
        print(f"[route-guard:{worker_id}] dead-lettered task={task['task_id']} type={task['task_type']} reason={details['reason']}")
        swept += 1

    return swept


def sweep_stale_tasks(
    worker_id: str,
    claim_timeout_seconds: int,
    heartbeat_timeout_seconds: int,
    max_runtime_seconds: int,
) -> int:
    recovered = recover_stale_tasks(
        claim_timeout_seconds=claim_timeout_seconds,
        heartbeat_timeout_seconds=heartbeat_timeout_seconds,
        runtime_timeout_seconds=max_runtime_seconds,
        recovery_decider=decide_recovery_action,
        worker_id=worker_id,
    )

    for item in recovered:
        print(
            f"[recovery:{worker_id}] task={item['task_id']} "
            f"from={item['from_status']} to={item['to_status']} "
            f"reason={item['reason']} policy={item['payload']['policy_action']}"
        )

    return len(recovered)


def create_handoff_tasks(
    parent_task: dict[str, str],
    worker_id: str,
    handoff_tasks: list[dict[str, object]],
) -> None:
    for spec in handoff_tasks:
        payload = dict(spec.get("payload", {}))
        if "workflow_run_key" not in payload and parent_task.get("workflow_run_key"):
            payload["workflow_run_key"] = parent_task["workflow_run_key"]

        child_task_id = create_task(
            task_type=str(spec["task_type"]),
            payload=payload,
            priority=int(spec.get("priority", 100)),
            max_attempts=int(spec.get("max_attempts", 2)),
            workflow_id=parent_task["workflow_id"],
            workflow_run_key=parent_task.get("workflow_run_key"),
            correlation_id=parent_task["correlation_id"],
            parent_task_id=parent_task["task_id"],
            depends_on_task_id=parent_task["task_id"],
            handoff_from_task_id=parent_task["task_id"],
        )
        child = get_task(child_task_id)
        append_event(
            task_id=child_task_id,
            workflow_id=child["workflow_id"],
            correlation_id=child["correlation_id"],
            worker_id=worker_id,
            event_type="TaskHandoffCreated",
            from_status=None,
            to_status=child["status"],
            payload={
                "parent_task_id": parent_task["task_id"],
                "handoff_from_task_id": parent_task["task_id"],
                "task_type": child["task_type"],
                "workflow_run_key": child["workflow_run_key"],
            },
        )


def process_one_task(
    worker_id: str,
    claim_timeout_seconds: int,
    task_heartbeat_min_interval_seconds: int,
) -> bool:
    update_worker_state(worker_id, "idle")
    accepted_task_types = get_worker_capabilities(worker_id)
    task = claim_next_task(
        worker_id,
        accepted_task_types=accepted_task_types,
        claim_timeout_seconds=claim_timeout_seconds,
    )

    if not task:
        return False

    task_id = task["task_id"]
    workflow_id = task["workflow_id"]
    correlation_id = task["correlation_id"]
    task_type = task["task_type"]
    payload = json.loads(task["payload_json"])

    print(f"[worker:{worker_id}] claimed task={task_id} workflow={workflow_id} type={task_type}")

    set_worker_state_with_event(
        worker_id=worker_id,
        task_id=task_id,
        workflow_id=workflow_id,
        correlation_id=correlation_id,
        new_status="assigned",
        old_status="idle",
    )

    allowed, decision = evaluate_admission(worker_id, task_type, payload)
    append_event(
        task_id=task_id,
        workflow_id=workflow_id,
        correlation_id=correlation_id,
        worker_id=worker_id,
        event_type="PolicyChecked",
        from_status="claimed",
        to_status="claimed",
        payload={"allowed": allowed, "decision": decision},
    )

    if not allowed:
        set_worker_state_with_event(
            worker_id=worker_id,
            task_id=task_id,
            workflow_id=workflow_id,
            correlation_id=correlation_id,
            new_status="reporting",
            old_status="assigned",
        )
        finish_task_failure(
            task_id=task_id,
            worker_id=worker_id,
            error_message=f"Admission denied: {decision.get('reason', 'unknown')}",
            result_payload={"decision": decision},
        )
        set_worker_state_with_event(
            worker_id=worker_id,
            task_id=task_id,
            workflow_id=workflow_id,
            correlation_id=correlation_id,
            new_status="idle",
            old_status="reporting",
        )
        update_worker_state(worker_id, "idle", None, None)
        return True

    set_worker_state_with_event(
        worker_id=worker_id,
        task_id=task_id,
        workflow_id=workflow_id,
        correlation_id=correlation_id,
        new_status="executing",
        old_status="assigned",
    )

    limits = decision.get("limits") or get_task_limits(task_type)
    set_task_running(
        task_id=task_id,
        worker_id=worker_id,
        max_runtime_seconds=int(limits["max_runtime_seconds"]),
    )

    record_task_heartbeat(
        task_id=task_id,
        worker_id=worker_id,
        min_interval_seconds=task_heartbeat_min_interval_seconds,
        force=True,
    )

    handler_name = get_handler_name(task_type)
    result = run_handler(task_type, payload)
#    handler_name = get_handler_name(task_type)
#    result = run_handler(handler_name, payload)

    record_task_heartbeat(
        task_id=task_id,
        worker_id=worker_id,
        min_interval_seconds=task_heartbeat_min_interval_seconds,
        force=False,
    )

    for event in result.get("events", []):
        append_event(
            task_id=task_id,
            workflow_id=workflow_id,
            correlation_id=correlation_id,
            worker_id=worker_id,
            event_type=event.get("type", "HandlerEvent"),
            from_status="running",
            to_status="running",
            payload=event,
        )

    set_worker_state_with_event(
        worker_id=worker_id,
        task_id=task_id,
        workflow_id=workflow_id,
        correlation_id=correlation_id,
        new_status="reporting",
        old_status="executing",
    )

    if result["status"] == "success":
        finish_task_success(
            task_id=task_id,
            worker_id=worker_id,
            result_payload={"artifacts": result.get("artifacts", [])},
        )
        parent_task = get_task(task_id)
        handoff_tasks = list(result.get("handoff_tasks", []))
        if handoff_tasks:
            create_handoff_tasks(parent_task, worker_id, handoff_tasks)
        final_task = get_task(task_id)
        print(f"[worker:{worker_id}] succeeded task={task_id} workflow={workflow_id} status={final_task['status']}")
    else:
        finish_task_failure(
            task_id=task_id,
            worker_id=worker_id,
            error_message=result.get("error") or "unknown handler error",
            result_payload={
                "artifacts": result.get("artifacts", []),
                "handler_next_state": result.get("next_state"),
            },
        )
        final_task = get_task(task_id)
        print(f"[worker:{worker_id}] non-success task={task_id} workflow={workflow_id} status={final_task['status']}")

    set_worker_state_with_event(
        worker_id=worker_id,
        task_id=task_id,
        workflow_id=workflow_id,
        correlation_id=correlation_id,
        new_status="idle",
        old_status="reporting",
    )
    update_worker_state(worker_id, "idle", None, None)
    return True


def main() -> None:
    args = parse_args()
    worker_id = args.worker_id

    bootstrap(worker_id=worker_id, reset=args.reset_demo)

    runtime_cfg = get_runtime_settings()
    global_limits = get_worker_global_limits()
    policy_snapshot = get_policy_snapshot()

    print(f"[worker] started: {worker_id}")
    print(f"[worker] accepted_task_types={get_worker_capabilities(worker_id)}")
    print(
        f"[worker] policy claim_timeout={global_limits['claim_timeout_seconds']}s "
        f"heartbeat_timeout={global_limits['heartbeat_timeout_seconds']}s "
        f"max_runtime={global_limits['max_runtime_seconds']}s "
        f"task_heartbeat_min_interval={runtime_cfg['task_heartbeat_min_interval_seconds']}s "
        f"idle_heartbeat={runtime_cfg['idle_heartbeat_seconds']}s "
        f"sleep={runtime_cfg['sleep_seconds']}s"
    )
    print(f"[worker] maintenance={args.maintenance} once_idle_exit={args.once_idle_exit}")
    print(f"[worker] policy_source={get_policy_source()} version={policy_snapshot.get('policy_version')}")

    while True:
        emit_idle_heartbeat_if_due(worker_id, runtime_cfg["idle_heartbeat_seconds"])

        if args.maintenance:
            sweep_unroutable_queued_tasks(worker_id)
            sweep_stale_tasks(
                worker_id=worker_id,
                claim_timeout_seconds=global_limits["claim_timeout_seconds"],
                heartbeat_timeout_seconds=global_limits["heartbeat_timeout_seconds"],
                max_runtime_seconds=global_limits["max_runtime_seconds"],
            )

        did_work = process_one_task(
            worker_id=worker_id,
            claim_timeout_seconds=global_limits["claim_timeout_seconds"],
            task_heartbeat_min_interval_seconds=runtime_cfg["task_heartbeat_min_interval_seconds"],
        )

        if not did_work:
            print(f"[worker:{worker_id}] no compatible queued task found")
            if args.once_idle_exit:
                print(f"[worker:{worker_id}] exiting because --once-idle-exit is set")
                break
            time.sleep(runtime_cfg["sleep_seconds"])


if __name__ == "__main__":
    main()
