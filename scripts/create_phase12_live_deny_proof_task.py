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
            {"cid": row[0], "name": str(row[1]), "type": str(row[2] or ""), "notnull": int(row[3]), "dflt_value": row[4], "pk": int(row[5])}
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


def build_payload(project_root: Path) -> Dict[str, Any]:
    run_root = project_root / "artifacts" / "runs" / PHASE12_KEY
    return {
        "workflow_run_key": PHASE12_KEY,
        "target_environment": "prod",
        "strategy": "ring_canary_safe_deployment",
        "environment_model_path": str(run_root / "environments" / "promotion_model.json"),
        "pipeline_path": str(run_root / "cicd" / "pipeline_spec.yaml"),
        "observability_path": str(run_root / "ops" / "observability_spec.json"),
        "change_control_path": str(run_root / "ops" / "change_control.md"),
        "sbom_path": str(run_root / "supply" / "sbom.json"),
        "provenance_path": str(run_root / "supply" / "provenance.json"),
        "signing_path": str(run_root / "supply" / "signing.json"),
        "change_review_path": str(run_root / "architect" / "change_review.json"),
        "deployment_report_path": str(run_root / "release" / "live_deny_deployment_report.json")
    }


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    db_path = choose_db_path(project_root)
    conn = sqlite3.connect(str(db_path))
    try:
        adapter = SchemaAdapter(conn, "task_queue")
        task_id_col = adapter.must_pick("task_id", "id")
        task_type_col = adapter.must_pick("task_type", "task_name", "task_kind")
        status_col = adapter.must_pick("status")
        payload_col = adapter.pick("payload_json", "payload", "task_payload")

        task_id = f"phase12-live-deny-{uuid.uuid4().hex[:12]}"
        workflow_id = f"wf-phase12-live-deny-{uuid.uuid4().hex[:8]}"
        workflow_run_id = f"wfr-phase12-live-deny-{uuid.uuid4().hex[:8]}"
        now = utc_now_iso()
        values: Dict[str, Any] = {
            task_id_col: task_id,
            task_type_col: "release.promote_environment",
            status_col: STATUS_BLOCKED
        }
        if payload_col:
            values[payload_col] = json.dumps(build_payload(project_root), ensure_ascii=False, sort_keys=True)
        if adapter.has("workflow_id"):
            values["workflow_id"] = workflow_id
        if adapter.has("workflow_run_id"):
            values["workflow_run_id"] = workflow_run_id
        if adapter.has("workflow_run_key"):
            values["workflow_run_key"] = PHASE12_KEY
        if adapter.has("priority"):
            values["priority"] = 999
        if adapter.has("attempt_count"):
            values["attempt_count"] = 0
        if adapter.has("max_attempts"):
            values["max_attempts"] = 1
        if adapter.has("created_at"):
            values["created_at"] = now
        if adapter.has("updated_at"):
            values["updated_at"] = now
        if adapter.has("review_status"):
            values["review_status"] = "pending"
        if adapter.has("requires_human"):
            values["requires_human"] = 1

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
                values[col] = 999
            elif col == "attempt_count":
                values[col] = 0
            elif col == "max_attempts":
                values[col] = 1
            elif col in {"created_at", "updated_at"}:
                values[col] = now
            elif col == "review_status":
                values[col] = "pending"
            elif col == "requires_human":
                values[col] = 1
            else:
                values[col] = ""

        cols = list(values.keys())
        sql = f"INSERT INTO task_queue ({', '.join(cols)}) VALUES ({', '.join(['?'] * len(cols))})"
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(sql, [values[c] for c in cols])
        conn.execute("COMMIT")

        print(json.dumps({
            "ok": True,
            "rowid": int(cur.lastrowid),
            "task_id": task_id,
            "task_type": "release.promote_environment",
            "status": STATUS_BLOCKED
        }, ensure_ascii=False, indent=2))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
