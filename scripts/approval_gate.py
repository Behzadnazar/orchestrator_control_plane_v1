from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.governance import Governance, GovernanceError  # noqa: E402
from app.governance_audit import GovernanceAudit  # noqa: E402


UTC = timezone.utc

STATUS_BLOCKED = "blocked"
STATUS_QUEUED = "queued"
STATUS_DEAD_LETTER = "dead_letter"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def safe_json_loads(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
            return {"_value": parsed}
        except json.JSONDecodeError:
            return {"_raw": text}
    return {"_value": value}


@dataclass
class TaskRow:
    rowid: int
    task_id: str
    task_type: str
    status: str
    payload: Dict[str, Any]


class ApprovalGateError(Exception):
    pass


class SchemaAdapter:
    def __init__(self, conn: sqlite3.Connection, table_name: str = "task_queue") -> None:
        self.conn = conn
        self.table_name = table_name
        self.columns = self._load_columns()

    def _load_columns(self) -> List[str]:
        rows = self.conn.execute(f"PRAGMA table_info({self.table_name})").fetchall()
        return [str(row[1]) for row in rows]

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
            raise ApprovalGateError(f"Required column not found in {self.table_name}: one of {candidates}")
        return value


class ApprovalGate:
    def __init__(self, project_root: Path, db_path: Path, actor: str) -> None:
        self.project_root = project_root.resolve()
        self.db_path = db_path.resolve()
        self.actor = actor.strip()
        if not self.actor:
            raise ApprovalGateError("actor must not be empty")

        self.approval_audit_path = self.project_root / "artifacts" / "approval_audit" / "approval_events.jsonl"
        self.governance = Governance(self.project_root)
        self.gov_audit = GovernanceAudit(self.project_root)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.isolation_level = None
        return conn

    def _log_approval(self, event_type: str, payload: Dict[str, Any]) -> None:
        append_jsonl(
            self.approval_audit_path,
            {
                "ts": utc_now_iso(),
                "event_type": event_type,
                "actor": self.actor,
                **payload,
            },
        )

    def _find_task(self, conn: sqlite3.Connection, rowid: Optional[int], task_id: Optional[str]) -> TaskRow:
        adapter = SchemaAdapter(conn, "task_queue")
        task_id_col = adapter.must_pick("task_id", "id")
        task_type_col = adapter.must_pick("task_type", "task_name", "task_kind")
        status_col = adapter.must_pick("status")
        payload_col = adapter.pick("payload_json", "payload", "task_payload")

        if rowid is None and not task_id:
            raise ApprovalGateError("Provide --rowid or --task-id")

        if rowid is not None:
            where_sql = "rowid = ?"
            params: List[Any] = [rowid]
        else:
            where_sql = f"{task_id_col} = ?"
            params = [task_id]

        select_cols = [
            "rowid AS __rowid__",
            f"{task_id_col} AS __task_id__",
            f"{task_type_col} AS __task_type__",
            f"{status_col} AS __status__",
        ]
        if payload_col:
            select_cols.append(f"{payload_col} AS __payload__")

        row = conn.execute(
            f"""
            SELECT {", ".join(select_cols)}
            FROM task_queue
            WHERE {where_sql}
            LIMIT 1
            """,
            params,
        ).fetchone()

        if row is None:
            raise ApprovalGateError("task not found")

        payload = safe_json_loads(row["__payload__"]) if "__payload__" in row.keys() else {}
        return TaskRow(
            rowid=int(row["__rowid__"]),
            task_id=str(row["__task_id__"]),
            task_type=str(row["__task_type__"]),
            status=str(row["__status__"]),
            payload=payload,
        )

    def _apply_updates(self, conn: sqlite3.Connection, rowid: int, updates: Dict[str, Any]) -> None:
        adapter = SchemaAdapter(conn, "task_queue")
        filtered: Dict[str, Any] = {}
        for key, value in updates.items():
            if adapter.has(key):
                filtered[key] = value

        if not filtered:
            raise ApprovalGateError("no applicable columns found for update")

        parts = [f"{key} = ?" for key in filtered.keys()]
        params = list(filtered.values()) + [rowid]

        conn.execute("BEGIN IMMEDIATE")
        conn.execute(f"UPDATE task_queue SET {', '.join(parts)} WHERE rowid = ?", params)
        conn.execute("COMMIT")

    def list_blocked(self) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            adapter = SchemaAdapter(conn, "task_queue")
            task_id_col = adapter.must_pick("task_id", "id")
            task_type_col = adapter.must_pick("task_type", "task_name", "task_kind")
            status_col = adapter.must_pick("status")
            payload_col = adapter.pick("payload_json", "payload", "task_payload")

            select_cols = [
                "rowid AS rowid",
                f"{task_id_col} AS task_id",
                f"{task_type_col} AS task_type",
                f"{status_col} AS status",
            ]
            if adapter.has("priority"):
                select_cols.append("priority")
            if adapter.has("created_at"):
                select_cols.append("created_at")
            if payload_col:
                select_cols.append(f"{payload_col} AS payload_json")

            rows = conn.execute(
                f"SELECT {', '.join(select_cols)} FROM task_queue WHERE {status_col} = ? ORDER BY rowid ASC",
                [STATUS_BLOCKED],
            ).fetchall()

            result: List[Dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                payload = safe_json_loads(item.pop("payload_json", None))
                decision = self.governance.decide(
                    task_type=str(item["task_type"]),
                    payload=payload,
                    service_path=str(item["task_type"]),
                    actor=self.actor,
                    mode="approval",
                )
                item["payload"] = payload
                item["approval_preview"] = {
                    "ok": decision.ok,
                    "reasons": decision.reasons,
                    "owner_agent": decision.owner_agent,
                }
                result.append(item)

            self._log_approval("blocked_tasks_listed", {"count": len(result)})
            self.gov_audit.log(
                "blocked_tasks_listed",
                {"count": len(result)},
                actor=self.actor,
            )
            return result
        finally:
            conn.close()

    def approve(self, rowid: Optional[int], task_id: Optional[str], reason: str) -> Dict[str, Any]:
        conn = self._connect()
        try:
            task = self._find_task(conn, rowid=rowid, task_id=task_id)
            if task.status != STATUS_BLOCKED:
                self.gov_audit.log(
                    "approval_denied_wrong_status",
                    {
                        "rowid": task.rowid,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "status": task.status,
                        "reason": "approve requires blocked task",
                    },
                    actor=self.actor,
                )
                raise ApprovalGateError(f"approve requires blocked task, got status={task.status}")

            decision = self.governance.decide(
                task_type=task.task_type,
                payload=task.payload,
                service_path=task.task_type,
                actor=self.actor,
                mode="approval",
            )

            if not decision.ok:
                self.gov_audit.log(
                    "approval_denied_by_policy",
                    {
                        "rowid": task.rowid,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "owner_agent": decision.owner_agent,
                        "reasons": decision.reasons,
                    },
                    actor=self.actor,
                )
                raise ApprovalGateError("; ".join(decision.reasons))

            updates: Dict[str, Any] = {"status": STATUS_QUEUED}
            adapter = SchemaAdapter(conn, "task_queue")
            now = utc_now_iso()

            if adapter.has("review_status"):
                updates["review_status"] = "approved"
            if adapter.has("approval_note"):
                updates["approval_note"] = reason
            if adapter.has("approved_by"):
                updates["approved_by"] = self.actor
            if adapter.has("approved_at"):
                updates["approved_at"] = now
            if adapter.has("updated_at"):
                updates["updated_at"] = now
            if adapter.has("last_error"):
                updates["last_error"] = None

            self._apply_updates(conn, task.rowid, updates)

            result = {
                "ok": True,
                "action": "approve",
                "rowid": task.rowid,
                "task_id": task.task_id,
                "task_type": task.task_type,
                "from_status": task.status,
                "to_status": STATUS_QUEUED,
                "actor": self.actor,
                "reason": reason,
                "owner_agent": decision.owner_agent,
                "ts": now,
            }

            self._log_approval("task_approved", result)
            self.gov_audit.log(
                "approval_allowed_by_policy",
                {
                    "rowid": task.rowid,
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "owner_agent": decision.owner_agent,
                    "matched_paths": decision.matched_paths,
                },
                actor=self.actor,
            )
            return result
        finally:
            conn.close()

    def reject(self, rowid: Optional[int], task_id: Optional[str], reason: str) -> Dict[str, Any]:
        conn = self._connect()
        try:
            task = self._find_task(conn, rowid=rowid, task_id=task_id)
            if task.status != STATUS_BLOCKED:
                self.gov_audit.log(
                    "reject_denied_wrong_status",
                    {
                        "rowid": task.rowid,
                        "task_id": task.task_id,
                        "task_type": task.task_type,
                        "status": task.status,
                        "reason": "reject requires blocked task",
                    },
                    actor=self.actor,
                )
                raise ApprovalGateError(f"reject requires blocked task, got status={task.status}")

            adapter = SchemaAdapter(conn, "task_queue")
            now = utc_now_iso()
            updates: Dict[str, Any] = {"status": STATUS_DEAD_LETTER}

            if adapter.has("review_status"):
                updates["review_status"] = "rejected"
            if adapter.has("approval_note"):
                updates["approval_note"] = reason
            if adapter.has("approved_by"):
                updates["approved_by"] = self.actor
            if adapter.has("approved_at"):
                updates["approved_at"] = now
            if adapter.has("updated_at"):
                updates["updated_at"] = now
            if adapter.has("last_error"):
                updates["last_error"] = f"Rejected by {self.actor}: {reason}"

            self._apply_updates(conn, task.rowid, updates)

            result = {
                "ok": True,
                "action": "reject",
                "rowid": task.rowid,
                "task_id": task.task_id,
                "task_type": task.task_type,
                "from_status": task.status,
                "to_status": STATUS_DEAD_LETTER,
                "actor": self.actor,
                "reason": reason,
                "ts": now,
            }

            self._log_approval("task_rejected", result)
            self.gov_audit.log(
                "task_rejected_by_human_gate",
                {
                    "rowid": task.rowid,
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                },
                actor=self.actor,
            )
            return result
        finally:
            conn.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Policy-bound approval gate")
    parser.add_argument("action", choices=["list-blocked", "approve", "reject"])
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--db-path", default="")
    parser.add_argument("--actor", required=True)
    parser.add_argument("--rowid", type=int)
    parser.add_argument("--task-id", default="")
    parser.add_argument("--reason", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = Path(args.project_root).resolve()
    db_path = Path(args.db_path).resolve() if args.db_path else (
        project_root / "data" / "orchestrator.db"
        if (project_root / "data" / "orchestrator.db").exists()
        else project_root / "orchestrator.db"
    )

    gate = ApprovalGate(project_root=project_root, db_path=db_path, actor=args.actor)

    try:
        if args.action == "list-blocked":
            print(json.dumps(gate.list_blocked(), ensure_ascii=False, indent=2))
            return 0
        if args.action == "approve":
            print(json.dumps(
                gate.approve(args.rowid, args.task_id.strip() or None, args.reason.strip() or "approved"),
                ensure_ascii=False,
                indent=2,
            ))
            return 0
        if args.action == "reject":
            print(json.dumps(
                gate.reject(args.rowid, args.task_id.strip() or None, args.reason.strip() or "rejected"),
                ensure_ascii=False,
                indent=2,
            ))
            return 0
        return 2
    except (ApprovalGateError, GovernanceError) as exc:
        print(json.dumps({
            "ok": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "ts": utc_now_iso(),
        }, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
