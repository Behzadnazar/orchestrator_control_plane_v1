from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


UTC = timezone.utc
STATUS_BLOCKED = "blocked"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class SchemaAdapter:
    def __init__(self, conn: sqlite3.Connection, table_name: str = "task_queue") -> None:
        self.conn = conn
        self.table_name = table_name
        self.columns_info = self._load_columns_info()
        self.columns = [c["name"] for c in self.columns_info]

    def _load_columns_info(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute(f"PRAGMA table_info({self.table_name})").fetchall()
        return [
            {
                "cid": row[0],
                "name": str(row[1]),
                "type": str(row[2] or ""),
                "notnull": int(row[3]),
                "dflt_value": row[4],
                "pk": int(row[5]),
            }
            for row in rows
        ]

    def has(self, name: str) -> bool:
        return name in self.columns

    def pick(self, *candidates: str) -> Optional[str]:
        for name in candidates:
            if self.has(name):
                return name
        return None

    def must_pick(self, *candidates: str) -> str:
        value = self.pick(*candidates)
        if value is None:
            raise RuntimeError(f"missing required column: {candidates}")
        return value

    def required_without_default(self) -> List[str]:
        out: List[str] = []
        for item in self.columns_info:
            if item["pk"] == 1:
                continue
            if item["notnull"] == 1 and item["dflt_value"] is None:
                out.append(item["name"])
        return out


def choose_db_path(project_root: Path) -> Path:
    data_db = project_root / "data" / "orchestrator.db"
    return data_db if data_db.exists() else (project_root / "orchestrator.db")


def ensure_seed_inputs(project_root: Path) -> Dict[str, str]:
    run_root = project_root / "artifacts" / "runs" / "phase11_demo_v1"
    (run_root / "research").mkdir(parents=True, exist_ok=True)
    (run_root / "frontend").mkdir(parents=True, exist_ok=True)
    (run_root / "backend").mkdir(parents=True, exist_ok=True)
    (run_root / "debugger").mkdir(parents=True, exist_ok=True)
    (run_root / "devops").mkdir(parents=True, exist_ok=True)
    (run_root / "architect").mkdir(parents=True, exist_ok=True)
    (run_root / "workflows").mkdir(parents=True, exist_ok=True)
    (project_root / "artifacts" / "state" / "phase11").mkdir(parents=True, exist_ok=True)

    failure_log = run_root / "backend" / "simulated_failure.log"
    failure_log.write_text(
        "ERROR: simulated packaging mismatch\nDETAIL: release bundle references unresolved frontend artifact hash\n",
        encoding="utf-8",
    )

    return {
        "run_root": str(run_root),
        "failure_log": str(failure_log),
    }


def build_tasks(project_root: Path, workflow_id: str, workflow_run_id: str) -> List[Dict[str, Any]]:
    paths = ensure_seed_inputs(project_root)
    run_root = Path(paths["run_root"])

    notes_path = run_root / "research" / "market_notes.md"
    component_path = run_root / "frontend" / "ResearchHero.tsx"
    backend_bundle_path = run_root / "workflows" / "backend_bundle.txt"
    memory_state_path = project_root / "artifacts" / "state" / "phase11" / "workflow_state.json"
    rca_path = run_root / "debugger" / "rca.md"
    manifest_path = run_root / "devops" / "release_manifest.json"
    bundle_path = run_root / "devops" / "release_bundle.txt"
    architect_review_path = run_root / "architect" / "review.json"

    return [
        {
            "task_type": "research.collect_notes",
            "priority": 200,
            "payload": {
                "workflow_run_key": "phase11_demo_v1",
                "topic": "Governed onboarding workflow for real agents",
                "notes": "Collect implementation constraints, handoff expectations, and artifact plan for phase11 governed workflow.",
                "notes_output_path": str(notes_path),
            },
        },
        {
            "task_type": "frontend.write_component",
            "priority": 190,
            "payload": {
                "workflow_run_key": "phase11_demo_v1",
                "component_name": "ResearchHero",
                "source_notes_path": str(notes_path),
                "component_path": str(component_path),
            },
        },
        {
            "task_type": "backend.write_file",
            "priority": 180,
            "payload": {
                "workflow_run_key": "phase11_demo_v1",
                "component_path": str(component_path),
                "path": str(backend_bundle_path),
                "content": "backend bundle generated after governed frontend handoff\n",
            },
        },
        {
            "task_type": "memory.write_json",
            "priority": 170,
            "payload": {
                "workflow_run_key": "phase11_demo_v1",
                "path": str(memory_state_path),
                "json_value": {
                    "workflow": "phase11_demo_v1",
                    "state": "backend_generated",
                    "ts": utc_now_iso()
                },
            },
        },
        {
            "task_type": "debugger.analyze_failure",
            "priority": 160,
            "payload": {
                "workflow_run_key": "phase11_demo_v1",
                "incident_title": "Synthetic packaging mismatch",
                "error_source_path": paths["failure_log"],
                "rca_output_path": str(rca_path),
            },
        },
        {
            "task_type": "devops.build_release_bundle",
            "priority": 150,
            "payload": {
                "workflow_run_key": "phase11_demo_v1",
                "release_name": "phase11-demo-release",
                "notes_path": str(notes_path),
                "component_path": str(component_path),
                "backend_bundle_path": str(backend_bundle_path),
                "rca_path": str(rca_path),
                "manifest_output_path": str(manifest_path),
                "bundle_output_path": str(bundle_path),
            },
        },
        {
            "task_type": "architect.review_constraints",
            "priority": 140,
            "payload": {
                "workflow_run_key": "phase11_demo_v1",
                "review_title": "Phase11 governed architecture review",
                "notes_path": str(notes_path),
                "component_path": str(component_path),
                "backend_bundle_path": str(backend_bundle_path),
                "release_manifest_path": str(manifest_path),
                "rca_path": str(rca_path),
                "review_output_path": str(architect_review_path),
            },
        },
    ]


def row_values(adapter: SchemaAdapter, task: Dict[str, Any], workflow_id: str, workflow_run_id: str) -> Dict[str, Any]:
    now = utc_now_iso()
    task_id = f"phase11-{task['task_type'].replace('.', '-')}-{uuid.uuid4().hex[:10]}"
    task_id_col = adapter.must_pick("task_id", "id")
    task_type_col = adapter.must_pick("task_type", "task_name", "task_kind")
    status_col = adapter.must_pick("status")
    payload_col = adapter.pick("payload_json", "payload", "task_payload")

    values: Dict[str, Any] = {
        task_id_col: task_id,
        task_type_col: task["task_type"],
        status_col: STATUS_BLOCKED,
    }
    if payload_col:
        values[payload_col] = json.dumps(task["payload"], ensure_ascii=False, sort_keys=True)

    if adapter.has("workflow_id"):
        values["workflow_id"] = workflow_id
    if adapter.has("workflow_run_id"):
        values["workflow_run_id"] = workflow_run_id
    if adapter.has("workflow_run_key"):
        values["workflow_run_key"] = "phase11_demo_v1"
    if adapter.has("priority"):
        values["priority"] = int(task["priority"])
    if adapter.has("attempt_count"):
        values["attempt_count"] = 0
    if adapter.has("max_attempts"):
        values["max_attempts"] = 2
    if adapter.has("created_at"):
        values["created_at"] = now
    if adapter.has("updated_at"):
        values["updated_at"] = now
    if adapter.has("review_status"):
        values["review_status"] = "pending"
    if adapter.has("requires_human"):
        values["requires_human"] = 1
    if adapter.has("claimed_by_worker"):
        values["claimed_by_worker"] = None
    if adapter.has("claimed_at"):
        values["claimed_at"] = None
    if adapter.has("heartbeat_at"):
        values["heartbeat_at"] = None
    if adapter.has("started_at"):
        values["started_at"] = None
    if adapter.has("finished_at"):
        values["finished_at"] = None
    if adapter.has("last_error"):
        values["last_error"] = None

    for col in adapter.required_without_default():
        if col in values:
            continue
        if col in {"workflow_id"}:
            values[col] = workflow_id
        elif col in {"workflow_run_id"}:
            values[col] = workflow_run_id
        elif col in {"workflow_run_key"}:
            values[col] = "phase11_demo_v1"
        elif col in {"priority", "attempt_count"}:
            values[col] = 0
        elif col in {"max_attempts"}:
            values[col] = 2
        elif col in {"created_at", "updated_at"}:
            values[col] = now
        elif col in {"review_status"}:
            values[col] = "pending"
        elif col in {"requires_human"}:
            values[col] = 1
        else:
            values[col] = ""

    return values


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    db_path = choose_db_path(project_root)
    workflow_id = f"wf-phase11-{uuid.uuid4().hex[:8]}"
    workflow_run_id = f"wfr-phase11-{uuid.uuid4().hex[:8]}"

    conn = sqlite3.connect(str(db_path))
    try:
        adapter = SchemaAdapter(conn, "task_queue")
        tasks = build_tasks(project_root, workflow_id=workflow_id, workflow_run_id=workflow_run_id)

        created: List[Dict[str, Any]] = []
        conn.execute("BEGIN IMMEDIATE")
        for task in tasks:
            values = row_values(adapter, task, workflow_id=workflow_id, workflow_run_id=workflow_run_id)
            cols = list(values.keys())
            sql = f"INSERT INTO task_queue ({', '.join(cols)}) VALUES ({', '.join(['?'] * len(cols))})"
            cur = conn.execute(sql, [values[c] for c in cols])
            created.append({
                "rowid": int(cur.lastrowid),
                "task_type": task["task_type"],
                "priority": int(task["priority"]),
            })
        conn.execute("COMMIT")

        print(json.dumps({
            "ok": True,
            "workflow_id": workflow_id,
            "workflow_run_id": workflow_run_id,
            "created": created,
        }, ensure_ascii=False, indent=2))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
