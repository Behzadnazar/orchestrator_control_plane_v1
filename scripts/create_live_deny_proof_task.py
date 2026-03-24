from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
        out: List[Dict[str, Any]] = []
        for row in rows:
            out.append(
                {
                    "cid": row[0],
                    "name": str(row[1]),
                    "type": str(row[2] or ""),
                    "notnull": int(row[3]),
                    "dflt_value": row[4],
                    "pk": int(row[5]),
                }
            )
        return out

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

    def info(self, name: str) -> Dict[str, Any]:
        for item in self.columns_info:
            if item["name"] == name:
                return item
        raise KeyError(name)

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


def build_payload() -> Dict[str, Any]:
    return {
        "component_name": "LiveDenyProofComponent",
        "workflow_run_key": "phase_h_demo_v2",
        "source_notes_path": "artifacts/runs/phase_h_demo_v2/research/control-plane-routing.md",
        "component_path": "artifacts/runs/phase_h_demo_v2/frontend/LiveDenyProofComponent.tsx",
    }


def base_values(adapter: SchemaAdapter, task_id: str, workflow_id: str, workflow_run_id: str) -> Dict[str, Any]:
    now = utc_now_iso()
    payload = build_payload()

    values: Dict[str, Any] = {}

    task_id_col = adapter.must_pick("task_id", "id")
    task_type_col = adapter.must_pick("task_type", "task_name", "task_kind")
    status_col = adapter.must_pick("status")
    payload_col = adapter.pick("payload_json", "payload", "task_payload")

    values[task_id_col] = task_id
    values[task_type_col] = "frontend.write_component"
    values[status_col] = STATUS_BLOCKED

    if payload_col:
        values[payload_col] = json.dumps(payload, ensure_ascii=False, sort_keys=True)

    if adapter.has("workflow_id"):
        values["workflow_id"] = workflow_id
    if adapter.has("workflow_run_id"):
        values["workflow_run_id"] = workflow_run_id
    if adapter.has("workflow_run_key"):
        values["workflow_run_key"] = "phase_h_demo_v2"
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

    return values


def fill_remaining_required(adapter: SchemaAdapter, values: Dict[str, Any], task_id: str, workflow_id: str, workflow_run_id: str) -> Tuple[Dict[str, Any], List[str]]:
    unresolved: List[str] = []

    for column in adapter.required_without_default():
        if column in values:
            continue

        col_type = adapter.info(column)["type"].upper()

        if column in {"task_id", "id"}:
            values[column] = task_id
        elif column == "task_type":
            values[column] = "frontend.write_component"
        elif column == "status":
            values[column] = STATUS_BLOCKED
        elif column == "workflow_id":
            values[column] = workflow_id
        elif column == "workflow_run_id":
            values[column] = workflow_run_id
        elif column == "workflow_run_key":
            values[column] = "phase_h_demo_v2"
        elif column == "review_status":
            values[column] = "pending"
        elif column == "requires_human":
            values[column] = 1
        elif column == "priority":
            values[column] = 999
        elif column == "attempt_count":
            values[column] = 0
        elif column == "max_attempts":
            values[column] = 1
        elif column in {"created_at", "updated_at"}:
            values[column] = utc_now_iso()
        elif "INT" in col_type:
            values[column] = 0
        elif "CHAR" in col_type or "TEXT" in col_type or col_type == "":
            values[column] = ""
        else:
            unresolved.append(column)

    return values, unresolved


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    db_path = choose_db_path(project_root)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    try:
        adapter = SchemaAdapter(conn, "task_queue")

        task_id = f"live-deny-{uuid.uuid4().hex[:12]}"
        workflow_id = f"wf-live-deny-{uuid.uuid4().hex[:8]}"
        workflow_run_id = f"wfr-live-deny-{uuid.uuid4().hex[:8]}"

        values = base_values(adapter, task_id=task_id, workflow_id=workflow_id, workflow_run_id=workflow_run_id)
        values, unresolved = fill_remaining_required(
            adapter,
            values=values,
            task_id=task_id,
            workflow_id=workflow_id,
            workflow_run_id=workflow_run_id,
        )

        if unresolved:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "unresolved required columns",
                        "columns": unresolved,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 1

        insert_cols = list(values.keys())
        insert_vals = [values[c] for c in insert_cols]
        placeholders = ", ".join(["?"] * len(insert_cols))
        sql = f"INSERT INTO task_queue ({', '.join(insert_cols)}) VALUES ({placeholders})"

        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(sql, insert_vals)
        rowid = int(cur.lastrowid)
        conn.execute("COMMIT")

        print(
            json.dumps(
                {
                    "ok": True,
                    "rowid": rowid,
                    "task_id": task_id,
                    "task_type": "frontend.write_component",
                    "status": STATUS_BLOCKED,
                    "workflow_id": workflow_id,
                    "workflow_run_id": workflow_run_id,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
