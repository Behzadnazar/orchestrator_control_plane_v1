from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.db import get_workflow_tasks
from app.services.control_plane_service import ControlPlaneService
from scripts.task_registry import AGENT_REGISTRY


def first_task(workflow_id: str, task_type: str) -> dict:
    tasks = get_workflow_tasks(workflow_id)
    for task in tasks:
        if task["task_type"] == task_type:
            return task
    raise RuntimeError(f"Task not found in workflow {workflow_id}: {task_type}")


def expect_success(name: str, fn: Callable[[], dict]) -> dict:
    try:
        fn()
        print(f"[PASS] {name}")
        return {"name": name, "status": "pass", "mode": "success"}
    except Exception as exc:
        print(f"[FAIL] {name} -> unexpected exception: {exc}")
        return {
            "name": name,
            "status": "fail",
            "mode": "success",
            "message": str(exc),
        }


def expect_failure(name: str, fn: Callable[[], dict], expected_substrings: list[str]) -> dict:
    try:
        fn()
        print(f"[FAIL] {name} -> expected failure, but call succeeded")
        return {
            "name": name,
            "status": "fail",
            "mode": "failure",
            "message": "call succeeded unexpectedly",
        }
    except Exception as exc:
        message = str(exc)
        if all(sub in message for sub in expected_substrings):
            print(f"[PASS] {name} -> {message}")
            return {
                "name": name,
                "status": "pass",
                "mode": "failure",
                "message": message,
            }

        print(f"[FAIL] {name} -> wrong error: {message}")
        return {
            "name": name,
            "status": "fail",
            "mode": "failure",
            "message": message,
            "expected_substrings": expected_substrings,
        }


def main() -> None:
    service = ControlPlaneService()

    service.reset_demo()
    for worker_id in sorted(AGENT_REGISTRY.keys()):
        service.register_worker(worker_id)
    service.seed_demo()

    demo_research = first_task("wf_phase_h_demo", "research.collect_notes")
    demo_frontend = first_task("wf_phase_h_demo", "frontend.write_component")

    results: list[dict] = []

    # Positive control: standalone valid task
    results.append(
        expect_success(
            "positive_standalone_backend_write_file",
            lambda: service.enqueue_task(
                task_type="backend.write_file",
                payload={
                    "workflow_run_key": "phase_i5_ok_standalone",
                    "path": "artifacts/runs/phase_i5_ok_standalone/workflows/manual.txt",
                    "content": "phase i.5 standalone ok\n",
                },
                priority=120,
                max_attempts=2,
                workflow_id="wf_phase_i5_ok_standalone",
                workflow_run_key="phase_i5_ok_standalone",
            ),
        )
    )

    # Positive control: valid graph chain
    positive_research = service.enqueue_task(
        task_type="research.collect_notes",
        payload={
            "topic": "phase i5 positive chain",
            "workflow_run_key": "phase_i5_ok_chain",
            "notes_path": "artifacts/runs/phase_i5_ok_chain/research/notes.md",
        },
        priority=110,
        max_attempts=2,
        workflow_id="wf_phase_i5_ok_chain",
        workflow_run_key="phase_i5_ok_chain",
    )

    results.append(
        expect_success(
            "positive_frontend_depends_on_research",
            lambda: service.enqueue_task(
                task_type="frontend.write_component",
                payload={
                    "component_name": "HeroPositive",
                    "workflow_run_key": "phase_i5_ok_chain",
                    "source_notes_path": "artifacts/runs/phase_i5_ok_chain/research/notes.md",
                    "component_path": "artifacts/runs/phase_i5_ok_chain/frontend/HeroPositive.tsx",
                },
                priority=100,
                max_attempts=2,
                workflow_id="wf_phase_i5_ok_chain",
                workflow_run_key="phase_i5_ok_chain",
                parent_task_id=positive_research["task_id"],
                depends_on_task_id=positive_research["task_id"],
                handoff_from_task_id=positive_research["task_id"],
            ),
        )
    )

    # Create same-workflow refs for mismatch tests
    root_a = service.enqueue_task(
        task_type="research.collect_notes",
        payload={
            "topic": "phase i5 mismatch a",
            "workflow_run_key": "phase_i5_samewf",
            "notes_path": "artifacts/runs/phase_i5_samewf/research/a.md",
        },
        priority=100,
        max_attempts=2,
        workflow_id="wf_phase_i5_samewf",
        workflow_run_key="phase_i5_samewf",
    )

    root_b = service.enqueue_task(
        task_type="research.collect_notes",
        payload={
            "topic": "phase i5 mismatch b",
            "workflow_run_key": "phase_i5_samewf",
            "notes_path": "artifacts/runs/phase_i5_samewf/research/b.md",
        },
        priority=100,
        max_attempts=2,
        workflow_id="wf_phase_i5_samewf",
        workflow_run_key="phase_i5_samewf",
    )

    foreign_task = service.enqueue_task(
        task_type="backend.write_file",
        payload={
            "workflow_run_key": "phase_i5_foreign",
            "path": "artifacts/runs/phase_i5_foreign/workflows/foreign.txt",
            "content": "foreign\n",
        },
        priority=100,
        max_attempts=2,
        workflow_id="wf_phase_i5_foreign",
        workflow_run_key="phase_i5_foreign",
    )

    shared_run_a = service.enqueue_task(
        task_type="research.collect_notes",
        payload={
            "topic": "phase i5 shared run a",
            "workflow_run_key": "run_a",
            "notes_path": "artifacts/runs/run_a/research/shared.md",
        },
        priority=100,
        max_attempts=2,
        workflow_id="wf_phase_i5_shared",
        workflow_run_key="run_a",
    )

    backend_fail_source = service.enqueue_task(
        task_type="backend.fail_test",
        payload={"note": "phase i5 invalid backend source"},
        priority=90,
        max_attempts=2,
        workflow_id="wf_phase_i5_invalid_backend",
        workflow_run_key="phase_i5_invalid_backend",
    )

    frontend_wrong_dep_source = service.enqueue_task(
        task_type="backend.write_file",
        payload={
            "workflow_run_key": "phase_i5_wrong_frontend_dep",
            "path": "artifacts/runs/phase_i5_wrong_frontend_dep/workflows/source.txt",
            "content": "wrong frontend dependency source\n",
        },
        priority=100,
        max_attempts=2,
        workflow_id="wf_phase_i5_wrong_frontend_dep",
        workflow_run_key="phase_i5_wrong_frontend_dep",
    )

    # Negative matrix
    results.append(
        expect_failure(
            "not_found_reference",
            lambda: service.enqueue_task(
                task_type="frontend.write_component",
                payload={
                    "component_name": "HeroMissing",
                    "workflow_run_key": "phase_i5_missing",
                    "source_notes_path": "artifacts/runs/phase_i5_missing/research/notes.md",
                    "component_path": "artifacts/runs/phase_i5_missing/frontend/HeroMissing.tsx",
                },
                priority=100,
                max_attempts=2,
                workflow_id="wf_phase_i5_missing",
                workflow_run_key="phase_i5_missing",
                parent_task_id="task_does_not_exist",
                depends_on_task_id="task_does_not_exist",
                handoff_from_task_id="task_does_not_exist",
            ),
            ["parent_task_id not found"],
        )
    )

    results.append(
        expect_failure(
            "cross_workflow_mismatch",
            lambda: service.enqueue_task(
                task_type="backend.write_file",
                payload={
                    "workflow_run_key": "phase_i5_crosswf",
                    "path": "artifacts/runs/phase_i5_crosswf/workflows/manual.txt",
                    "content": "cross workflow should fail\n",
                },
                priority=120,
                max_attempts=2,
                workflow_id="wf_phase_i5_crosswf",
                workflow_run_key="phase_i5_crosswf",
                parent_task_id=foreign_task["task_id"],
                depends_on_task_id=foreign_task["task_id"],
                handoff_from_task_id=foreign_task["task_id"],
            ),
            ["belongs to workflow_id="],
        )
    )

    results.append(
        expect_failure(
            "cross_run_key_mismatch",
            lambda: service.enqueue_task(
                task_type="frontend.write_component",
                payload={
                    "component_name": "HeroCrossRun",
                    "workflow_run_key": "run_b",
                    "source_notes_path": "artifacts/runs/run_b/research/notes.md",
                    "component_path": "artifacts/runs/run_b/frontend/HeroCrossRun.tsx",
                },
                priority=100,
                max_attempts=2,
                workflow_id="wf_phase_i5_shared",
                workflow_run_key="run_b",
                parent_task_id=shared_run_a["task_id"],
                depends_on_task_id=shared_run_a["task_id"],
                handoff_from_task_id=shared_run_a["task_id"],
            ),
            ["belongs to workflow_run_key=run_a, expected run_b"],
        )
    )

    results.append(
        expect_failure(
            "invalid_frontend_dependency_type",
            lambda: service.enqueue_task(
                task_type="frontend.write_component",
                payload={
                    "component_name": "HeroWrongType",
                    "workflow_run_key": "phase_i5_wrong_frontend_dep",
                    "source_notes_path": "artifacts/runs/phase_i5_wrong_frontend_dep/research/notes.md",
                    "component_path": "artifacts/runs/phase_i5_wrong_frontend_dep/frontend/HeroWrongType.tsx",
                },
                priority=100,
                max_attempts=2,
                workflow_id="wf_phase_i5_wrong_frontend_dep",
                workflow_run_key="phase_i5_wrong_frontend_dep",
                parent_task_id=frontend_wrong_dep_source["task_id"],
                depends_on_task_id=frontend_wrong_dep_source["task_id"],
                handoff_from_task_id=frontend_wrong_dep_source["task_id"],
            ),
            ["frontend.write_component must depend on research.collect_notes"],
        )
    )

    results.append(
        expect_failure(
            "invalid_backend_dependency_type",
            lambda: service.enqueue_task(
                task_type="backend.write_file",
                payload={
                    "workflow_run_key": "phase_i5_invalid_backend",
                    "path": "artifacts/runs/phase_i5_invalid_backend/workflows/manual.txt",
                    "content": "invalid backend dependency type\n",
                },
                priority=120,
                max_attempts=2,
                workflow_id="wf_phase_i5_invalid_backend",
                workflow_run_key="phase_i5_invalid_backend",
                parent_task_id=backend_fail_source["task_id"],
                depends_on_task_id=backend_fail_source["task_id"],
                handoff_from_task_id=backend_fail_source["task_id"],
            ),
            ["handoff_from_task_id task_type=backend.fail_test is not allowed to create downstream handoff"],
        )
    )

    results.append(
        expect_failure(
            "parent_depends_mismatch",
            lambda: service.enqueue_task(
                task_type="frontend.write_component",
                payload={
                    "component_name": "HeroMismatchParentDepends",
                    "workflow_run_key": "phase_i5_samewf",
                    "source_notes_path": "artifacts/runs/phase_i5_samewf/research/c.md",
                    "component_path": "artifacts/runs/phase_i5_samewf/frontend/HeroMismatchParentDepends.tsx",
                },
                priority=100,
                max_attempts=2,
                workflow_id="wf_phase_i5_samewf",
                workflow_run_key="phase_i5_samewf",
                parent_task_id=root_a["task_id"],
                depends_on_task_id=root_b["task_id"],
                handoff_from_task_id=root_a["task_id"],
            ),
            ["parent_task_id and depends_on_task_id must match"],
        )
    )

    results.append(
        expect_failure(
            "handoff_depends_mismatch",
            lambda: service.enqueue_task(
                task_type="frontend.write_component",
                payload={
                    "component_name": "HeroMismatchHandoff",
                    "workflow_run_key": "phase_i5_samewf",
                    "source_notes_path": "artifacts/runs/phase_i5_samewf/research/d.md",
                    "component_path": "artifacts/runs/phase_i5_samewf/frontend/HeroMismatchHandoff.tsx",
                },
                priority=100,
                max_attempts=2,
                workflow_id="wf_phase_i5_samewf",
                workflow_run_key="phase_i5_samewf",
                parent_task_id=root_a["task_id"],
                depends_on_task_id=root_a["task_id"],
                handoff_from_task_id=root_b["task_id"],
            ),
            ["handoff_from_task_id must match depends_on_task_id"],
        )
    )

    results.append(
        expect_failure(
            "partial_graph_triple_missing_field",
            lambda: service.enqueue_task(
                task_type="backend.write_file",
                payload={
                    "workflow_run_key": "phase_i5_partial",
                    "path": "artifacts/runs/phase_i5_partial/workflows/manual.txt",
                    "content": "partial graph triple should fail\n",
                },
                priority=120,
                max_attempts=2,
                workflow_id="wf_phase_i5_partial",
                workflow_run_key="phase_i5_partial",
                parent_task_id=demo_research["task_id"],
                depends_on_task_id=demo_research["task_id"],
                handoff_from_task_id=None,
            ),
            ["graph-linked tasks require parent_task_id, depends_on_task_id, and handoff_from_task_id together"],
        )
    )

    summary = {
        "total": len(results),
        "passed": sum(1 for item in results if item["status"] == "pass"),
        "failed": sum(1 for item in results if item["status"] == "fail"),
        "results": results,
        "references": {
            "demo_research_task_id": demo_research["task_id"],
            "demo_frontend_task_id": demo_frontend["task_id"],
            "foreign_task_id": foreign_task["task_id"],
            "shared_run_a_task_id": shared_run_a["task_id"],
            "backend_fail_source_task_id": backend_fail_source["task_id"],
            "frontend_wrong_dep_source_task_id": frontend_wrong_dep_source["task_id"],
        },
    }

    print("\n=== PHASE I.5 GRAPH HARNESS SUMMARY ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if summary["failed"] > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
