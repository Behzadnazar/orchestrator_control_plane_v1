from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


UTC = timezone.utc
STATUS_BLOCKED = "blocked"
PHASE12_KEY = "phase12_prod_v1"


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
                "pk": int(row[5])
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


def ensure_dirs(project_root: Path) -> Dict[str, str]:
    run_root = project_root / "artifacts" / "runs" / PHASE12_KEY
    for part in ["intake", "environments", "cicd", "ops", "supply", "architect", "release", "postmortem"]:
        (run_root / part).mkdir(parents=True, exist_ok=True)
    (project_root / "artifacts" / "state" / "phase12").mkdir(parents=True, exist_ok=True)
    return {"run_root": str(run_root)}


def build_tasks(project_root: Path) -> List[Dict[str, Any]]:
    run_root = project_root / "artifacts" / "runs" / PHASE12_KEY
    intake = run_root / "intake" / "project_intake.md"
    env_model = run_root / "environments" / "promotion_model.json"
    pipeline = run_root / "cicd" / "pipeline_spec.yaml"
    observability = run_root / "ops" / "observability_spec.json"
    change_control = run_root / "ops" / "change_control.md"
    sbom = run_root / "supply" / "sbom.json"
    provenance = run_root / "supply" / "provenance.json"
    signing = run_root / "supply" / "signing.json"
    review = run_root / "architect" / "change_review.json"
    deployment = run_root / "release" / "deployment_report.json"
    postmortem = run_root / "postmortem" / "postmortem.md"

    return [
        {
            "task_type": "intake.define_project",
            "priority": 300,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "project_name": "Production Governed Multi-Agent Delivery",
                "business_goal": "Ship a production-grade governed workflow with release controls and safe deployment.",
                "scope": "Intake, environment model, CI/CD hardening, supply chain controls, deployment promotion, postmortem workflow.",
                "constraints": [
                    "Prod requires gated promotion.",
                    "Signed SBOM and provenance are mandatory.",
                    "Rollback must remain ready during rollout."
                ],
                "intake_output_path": str(intake)
            }
        },
        {
            "task_type": "env.define_promotion_model",
            "priority": 290,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "model_name": "phase12-prod-promotion-model",
                "path": str(env_model)
            }
        },
        {
            "task_type": "cicd.write_pipeline_spec",
            "priority": 280,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "pipeline_name": "phase12-governed-prod-pipeline",
                "intake_path": str(intake),
                "environment_model_path": str(env_model),
                "pipeline_output_path": str(pipeline)
            }
        },
        {
            "task_type": "ops.write_observability_spec",
            "priority": 270,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "service_name": "phase12-governed-service",
                "pipeline_path": str(pipeline),
                "observability_output_path": str(observability)
            }
        },
        {
            "task_type": "ops.write_change_control_spec",
            "priority": 260,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "change_window": "Sun 01:00-03:00 UTC",
                "pipeline_path": str(pipeline),
                "environment_model_path": str(env_model),
                "change_control_output_path": str(change_control)
            }
        },
        {
            "task_type": "devops.generate_supply_chain_bundle",
            "priority": 250,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "release_name": "phase12-prod-release",
                "intake_path": str(intake),
                "pipeline_path": str(pipeline),
                "observability_path": str(observability),
                "change_control_path": str(change_control),
                "sbom_output_path": str(sbom),
                "provenance_output_path": str(provenance),
                "signing_output_path": str(signing)
            }
        },
        {
            "task_type": "architect.review_production_change",
            "priority": 240,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "review_title": "Phase12 production change review",
                "intake_path": str(intake),
                "environment_model_path": str(env_model),
                "pipeline_path": str(pipeline),
                "observability_path": str(observability),
                "change_control_path": str(change_control),
                "sbom_path": str(sbom),
                "provenance_path": str(provenance),
                "signing_path": str(signing),
                "review_output_path": str(review)
            }
        },
        {
            "task_type": "release.promote_environment",
            "priority": 230,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "target_environment": "prod",
                "strategy": "ring_canary_safe_deployment",
                "environment_model_path": str(env_model),
                "pipeline_path": str(pipeline),
                "observability_path": str(observability),
                "change_control_path": str(change_control),
                "sbom_path": str(sbom),
                "provenance_path": str(provenance),
                "signing_path": str(signing),
                "change_review_path": str(review),
                "deployment_report_path": str(deployment)
            }
        },
        {
            "task_type": "debugger.write_postmortem",
            "priority": 220,
            "payload": {
                "workflow_run_key": PHASE12_KEY,
                "incident_title": "Phase12 production deployment review",
                "deployment_report_path": str(deployment),
                "change_review_path": str(review),
                "postmortem_output_path": str(postmortem)
            }
        }
    ]


def row_values(adapter: SchemaAdapter, task: Dict[str, Any], workflow_id: str, workflow_run_id: str) -> Dict[str, Any]:
    now = utc_now_iso()
    task_id = f"phase12-{task['task_type'].replace('.', '-')}-{uuid.uuid4().hex[:10]}"
    task_id_col = adapter.must_pick("task_id", "id")
    task_type_col = adapter.must_pick("task_type", "task_name", "task_kind")
    status_col = adapter.must_pick("status")
    payload_col = adapter.pick("payload_json", "payload", "task_payload")

    values: Dict[str, Any] = {
        task_id_col: task_id,
        task_type_col: task["task_type"],
        status_col: STATUS_BLOCKED
    }
    if payload_col:
        values[payload_col] = json.dumps(task["payload"], ensure_ascii=False, sort_keys=True)
    if adapter.has("workflow_id"):
        values["workflow_id"] = workflow_id
    if adapter.has("workflow_run_id"):
        values["workflow_run_id"] = workflow_run_id
    if adapter.has("workflow_run_key"):
        values["workflow_run_key"] = PHASE12_KEY
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
        if col == "workflow_id":
            values[col] = workflow_id
        elif col == "workflow_run_id":
            values[col] = workflow_run_id
        elif col == "workflow_run_key":
            values[col] = PHASE12_KEY
        elif col == "priority":
            values[col] = 0
        elif col == "attempt_count":
            values[col] = 0
        elif col == "max_attempts":
            values[col] = 2
        elif col in {"created_at", "updated_at"}:
            values[col] = now
        elif col == "review_status":
            values[col] = "pending"
        elif col == "requires_human":
            values[col] = 1
        else:
            values[col] = ""
    return values


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    ensure_dirs(project_root)
    db_path = choose_db_path(project_root)
    workflow_id = f"wf-phase12-{uuid.uuid4().hex[:8]}"
    workflow_run_id = f"wfr-phase12-{uuid.uuid4().hex[:8]}"

    conn = sqlite3.connect(str(db_path))
    try:
        adapter = SchemaAdapter(conn, "task_queue")
        tasks = build_tasks(project_root)
        created: List[Dict[str, Any]] = []
        conn.execute("BEGIN IMMEDIATE")
        for task in tasks:
            values = row_values(adapter, task, workflow_id=workflow_id, workflow_run_id=workflow_run_id)
            cols = list(values.keys())
            sql = f"INSERT INTO task_queue ({', '.join(cols)}) VALUES ({', '.join(['?'] * len(cols))})"
            cur = conn.execute(sql, [values[c] for c in cols])
            created.append({"rowid": int(cur.lastrowid), "task_type": task["task_type"], "priority": int(task["priority"])})
        conn.execute("COMMIT")

        print(json.dumps({
            "ok": True,
            "workflow_id": workflow_id,
            "workflow_run_id": workflow_run_id,
            "workflow_run_key": PHASE12_KEY,
            "created": created
        }, ensure_ascii=False, indent=2))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
