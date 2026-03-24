from __future__ import annotations

import subprocess

import pytest

from app.db import get_workflow_tasks
from tests.common import BASE_DIR, ControlPlaneBaseTestCase


@pytest.mark.regression
class ControlPlaneRegressionMatrixTests(ControlPlaneBaseTestCase):
    def test_schema_business_and_graph_regression_matrix(self) -> None:
        self.service.seed_demo()

        demo_research = next(task for task in get_workflow_tasks("wf_phase_h_demo") if task["task_type"] == "research.collect_notes")

        foreign = self.service.enqueue_task(
            task_type="backend.write_file",
            payload={
                "workflow_run_key": "foreign_run",
                "path": "artifacts/runs/foreign_run/workflows/foreign.txt",
                "content": "foreign\n",
            },
            priority=100,
            max_attempts=2,
            workflow_id="wf_foreign",
            workflow_run_key="foreign_run",
        )

        samewf_a = self.service.enqueue_task(
            task_type="research.collect_notes",
            payload={
                "topic": "samewf a",
                "workflow_run_key": "samewf_run",
                "notes_path": "artifacts/runs/samewf_run/research/a.md",
            },
            priority=100,
            max_attempts=2,
            workflow_id="wf_samewf",
            workflow_run_key="samewf_run",
        )

        samewf_b = self.service.enqueue_task(
            task_type="research.collect_notes",
            payload={
                "topic": "samewf b",
                "workflow_run_key": "samewf_run",
                "notes_path": "artifacts/runs/samewf_run/research/b.md",
            },
            priority=100,
            max_attempts=2,
            workflow_id="wf_samewf",
            workflow_run_key="samewf_run",
        )

        shared_run_a = self.service.enqueue_task(
            task_type="research.collect_notes",
            payload={
                "topic": "shared run a",
                "workflow_run_key": "run_a",
                "notes_path": "artifacts/runs/run_a/research/shared.md",
            },
            priority=100,
            max_attempts=2,
            workflow_id="wf_shared",
            workflow_run_key="run_a",
        )

        backend_fail_source = self.service.enqueue_task(
            task_type="backend.fail_test",
            payload={"note": "invalid backend source"},
            priority=90,
            max_attempts=2,
            workflow_id="wf_invalid_backend",
            workflow_run_key="invalid_backend_run",
        )

        frontend_wrong_dep_source = self.service.enqueue_task(
            task_type="backend.write_file",
            payload={
                "workflow_run_key": "wrong_frontend_dep",
                "path": "artifacts/runs/wrong_frontend_dep/workflows/source.txt",
                "content": "wrong dep source\n",
            },
            priority=100,
            max_attempts=2,
            workflow_id="wf_wrong_frontend_dep",
            workflow_run_key="wrong_frontend_dep",
        )

        negative_cases = [
            (
                "schema_missing_path",
                lambda: self.service.enqueue_task(
                    task_type="backend.write_file",
                    payload={
                        "workflow_run_key": "bad_schema",
                        "content": "missing path",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_bad_schema",
                    workflow_run_key="bad_schema",
                ),
                "payload schema validation failed",
            ),
            (
                "business_path_namespace_escape",
                lambda: self.service.enqueue_task(
                    task_type="backend.write_file",
                    payload={
                        "workflow_run_key": "bad_ns",
                        "path": "artifacts/runs/OTHER/workflows/evil.txt",
                        "content": "bad namespace",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_bad_ns",
                    workflow_run_key="bad_ns",
                ),
                "must stay under",
            ),
            (
                "graph_not_found_reference",
                lambda: self.service.enqueue_task(
                    task_type="frontend.write_component",
                    payload={
                        "component_name": "HeroMissing",
                        "workflow_run_key": "missing_ref",
                        "source_notes_path": "artifacts/runs/missing_ref/research/notes.md",
                        "component_path": "artifacts/runs/missing_ref/frontend/HeroMissing.tsx",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_missing_ref",
                    workflow_run_key="missing_ref",
                    parent_task_id="task_does_not_exist",
                    depends_on_task_id="task_does_not_exist",
                    handoff_from_task_id="task_does_not_exist",
                ),
                "parent_task_id not found",
            ),
            (
                "graph_cross_workflow_mismatch",
                lambda: self.service.enqueue_task(
                    task_type="backend.write_file",
                    payload={
                        "workflow_run_key": "crosswf",
                        "path": "artifacts/runs/crosswf/workflows/manual.txt",
                        "content": "crosswf",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_crosswf",
                    workflow_run_key="crosswf",
                    parent_task_id=foreign["task_id"],
                    depends_on_task_id=foreign["task_id"],
                    handoff_from_task_id=foreign["task_id"],
                ),
                "belongs to workflow_id=",
            ),
            (
                "graph_cross_run_key_mismatch",
                lambda: self.service.enqueue_task(
                    task_type="frontend.write_component",
                    payload={
                        "component_name": "HeroCrossRun",
                        "workflow_run_key": "run_b",
                        "source_notes_path": "artifacts/runs/run_b/research/notes.md",
                        "component_path": "artifacts/runs/run_b/frontend/HeroCrossRun.tsx",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_shared",
                    workflow_run_key="run_b",
                    parent_task_id=shared_run_a["task_id"],
                    depends_on_task_id=shared_run_a["task_id"],
                    handoff_from_task_id=shared_run_a["task_id"],
                ),
                "belongs to workflow_run_key=run_a, expected run_b",
            ),
            (
                "graph_invalid_frontend_dependency_type",
                lambda: self.service.enqueue_task(
                    task_type="frontend.write_component",
                    payload={
                        "component_name": "HeroWrongType",
                        "workflow_run_key": "wrong_frontend_dep",
                        "source_notes_path": "artifacts/runs/wrong_frontend_dep/research/notes.md",
                        "component_path": "artifacts/runs/wrong_frontend_dep/frontend/HeroWrongType.tsx",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_wrong_frontend_dep",
                    workflow_run_key="wrong_frontend_dep",
                    parent_task_id=frontend_wrong_dep_source["task_id"],
                    depends_on_task_id=frontend_wrong_dep_source["task_id"],
                    handoff_from_task_id=frontend_wrong_dep_source["task_id"],
                ),
                "frontend.write_component must depend on research.collect_notes",
            ),
            (
                "graph_invalid_backend_dependency_type",
                lambda: self.service.enqueue_task(
                    task_type="backend.write_file",
                    payload={
                        "workflow_run_key": "invalid_backend_run",
                        "path": "artifacts/runs/invalid_backend_run/workflows/manual.txt",
                        "content": "invalid backend dep",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_invalid_backend",
                    workflow_run_key="invalid_backend_run",
                    parent_task_id=backend_fail_source["task_id"],
                    depends_on_task_id=backend_fail_source["task_id"],
                    handoff_from_task_id=backend_fail_source["task_id"],
                ),
                "handoff_from_task_id task_type=backend.fail_test is not allowed",
            ),
            (
                "graph_parent_depends_mismatch",
                lambda: self.service.enqueue_task(
                    task_type="frontend.write_component",
                    payload={
                        "component_name": "HeroMismatchParentDepends",
                        "workflow_run_key": "samewf_run",
                        "source_notes_path": "artifacts/runs/samewf_run/research/c.md",
                        "component_path": "artifacts/runs/samewf_run/frontend/HeroMismatchParentDepends.tsx",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_samewf",
                    workflow_run_key="samewf_run",
                    parent_task_id=samewf_a["task_id"],
                    depends_on_task_id=samewf_b["task_id"],
                    handoff_from_task_id=samewf_a["task_id"],
                ),
                "parent_task_id and depends_on_task_id must match",
            ),
            (
                "graph_handoff_depends_mismatch",
                lambda: self.service.enqueue_task(
                    task_type="frontend.write_component",
                    payload={
                        "component_name": "HeroMismatchHandoff",
                        "workflow_run_key": "samewf_run",
                        "source_notes_path": "artifacts/runs/samewf_run/research/d.md",
                        "component_path": "artifacts/runs/samewf_run/frontend/HeroMismatchHandoff.tsx",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_samewf",
                    workflow_run_key="samewf_run",
                    parent_task_id=samewf_a["task_id"],
                    depends_on_task_id=samewf_a["task_id"],
                    handoff_from_task_id=samewf_b["task_id"],
                ),
                "handoff_from_task_id must match depends_on_task_id",
            ),
            (
                "graph_partial_triple_missing_field",
                lambda: self.service.enqueue_task(
                    task_type="backend.write_file",
                    payload={
                        "workflow_run_key": "partial_graph",
                        "path": "artifacts/runs/partial_graph/workflows/manual.txt",
                        "content": "partial graph",
                    },
                    priority=100,
                    max_attempts=2,
                    workflow_id="wf_partial_graph",
                    workflow_run_key="partial_graph",
                    parent_task_id=demo_research["task_id"],
                    depends_on_task_id=demo_research["task_id"],
                    handoff_from_task_id=None,
                ),
                "graph-linked tasks require",
            ),
        ]

        for name, fn, expected_message in negative_cases:
            with self.subTest(case=name):
                with self.assertRaises(ValueError) as ctx:
                    fn()
                self.assertIn(expected_message, str(ctx.exception))

    def test_formal_harness_script_regression(self) -> None:
        harness = subprocess.run(
            [self.python, str(BASE_DIR / "scripts" / "phase_i5_graph_harness.py")],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            harness.returncode,
            0,
            msg=f"harness failed\nSTDOUT:\n{harness.stdout}\nSTDERR:\n{harness.stderr}",
        )
        self.assertIn('"failed": 0', harness.stdout)
        self.assertIn('"passed": 10', harness.stdout)
