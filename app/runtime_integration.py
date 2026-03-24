from __future__ import annotations

import argparse
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.governance import Governance, GovernanceError  # noqa: E402


UTC = timezone.utc

STATUS_BLOCKED = "blocked"
STATUS_QUEUED = "queued"
STATUS_CLAIMED = "claimed"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_DEAD_LETTER = "dead_letter"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_json_file(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json_file(path: Path, data: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)


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
class ServiceSpec:
    name: str
    command: List[str]
    allowed_cwds: List[str]
    timeout_sec: int
    env_allowlist: List[str]


@dataclass
class RuntimeTask:
    rowid: int
    task_id: str
    task_type: str
    status: str
    payload: Dict[str, Any]
    attempt_count: int
    max_attempts: int


class RuntimeIntegrationError(Exception):
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
            raise RuntimeIntegrationError(f"required column missing: {candidates}")
        return value


class RuntimeBridge:
    def __init__(self, project_root: Path, db_path: Path, service_map_path: Path, worker_name: str) -> None:
        self.project_root = project_root.resolve()
        self.db_path = db_path.resolve()
        self.service_map_path = service_map_path.resolve()
        self.worker_name = worker_name
        self.runtime_audit_path = self.project_root / "artifacts" / "runtime_audit" / "runtime_events.jsonl"
        self.governance_audit_path = self.project_root / "artifacts" / "governance_audit" / "governance_events.jsonl"
        self.services = self._load_services()
        self.governance = Governance(self.project_root)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.isolation_level = None
        return conn

    def _load_services(self) -> Dict[str, ServiceSpec]:
        raw = read_json_file(self.service_map_path)
        services = raw.get("services", {})
        result: Dict[str, ServiceSpec] = {}
        for name, value in services.items():
            result[name] = ServiceSpec(
                name=name,
                command=[str(x) for x in value.get("command", [])],
                allowed_cwds=[str(x) for x in value.get("allowed_cwds", ["."])],
                timeout_sec=int(value.get("timeout_sec", 300)),
                env_allowlist=[str(x) for x in value.get("env_allowlist", [])],
            )
        return result

    def list_services(self) -> List[Dict[str, Any]]:
        return [
            {
                "service": spec.name,
                "command": spec.command,
                "allowed_cwds": spec.allowed_cwds,
                "timeout_sec": spec.timeout_sec,
                "env_allowlist": spec.env_allowlist,
            }
            for spec in self.services.values()
        ]

    def _log(self, path: Path, event_type: str, payload: Dict[str, Any]) -> None:
        append_jsonl(
            path,
            {
                "ts": utc_now_iso(),
                "event_type": event_type,
                "worker": self.worker_name,
                **payload,
            },
        )

    def _update_row(self, rowid: int, updates: Dict[str, Any]) -> None:
        conn = self._connect()
        try:
            adapter = SchemaAdapter(conn, "task_queue")
            filtered = {}
            for key, value in updates.items():
                if adapter.has(key):
                    filtered[key] = value
            if adapter.has("updated_at") and "updated_at" not in filtered:
                filtered["updated_at"] = utc_now_iso()
            parts = [f"{key} = ?" for key in filtered.keys()]
            params = list(filtered.values()) + [rowid]
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(f"UPDATE task_queue SET {', '.join(parts)} WHERE rowid = ?", params)
            conn.execute("COMMIT")
        finally:
            conn.close()

    def claim_next_task(self) -> Optional[RuntimeTask]:
        conn = self._connect()
        try:
            adapter = SchemaAdapter(conn, "task_queue")
            task_id_col = adapter.must_pick("task_id", "id")
            task_type_col = adapter.must_pick("task_type", "task_name", "task_kind")
            status_col = adapter.must_pick("status")
            payload_col = adapter.pick("payload_json", "payload", "task_payload")

            select_cols = [
                "rowid AS __rowid__",
                f"{task_id_col} AS __task_id__",
                f"{task_type_col} AS __task_type__",
                f"{status_col} AS __status__",
            ]
            if payload_col:
                select_cols.append(f"{payload_col} AS __payload__")
            if adapter.has("attempt_count"):
                select_cols.append("attempt_count")
            if adapter.has("max_attempts"):
                select_cols.append("max_attempts")

            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                f"""
                SELECT {", ".join(select_cols)}
                FROM task_queue
                WHERE {status_col} = ?
                ORDER BY rowid ASC
                LIMIT 1
                """,
                [STATUS_QUEUED],
            ).fetchone()

            if row is None:
                conn.execute("COMMIT")
                return None

            rowid = int(row["__rowid__"])
            now = utc_now_iso()
            updates = {status_col: STATUS_CLAIMED}
            if adapter.has("claimed_by_worker"):
                updates["claimed_by_worker"] = self.worker_name
            if adapter.has("claimed_at"):
                updates["claimed_at"] = now
            if adapter.has("heartbeat_at"):
                updates["heartbeat_at"] = now
            if adapter.has("updated_at"):
                updates["updated_at"] = now

            parts = [f"{key} = ?" for key in updates.keys()]
            params = list(updates.values()) + [rowid]
            conn.execute(f"UPDATE task_queue SET {', '.join(parts)} WHERE rowid = ?", params)
            conn.execute("COMMIT")

            payload = safe_json_loads(row["__payload__"]) if "__payload__" in row.keys() else {}
            task = RuntimeTask(
                rowid=rowid,
                task_id=str(row["__task_id__"]),
                task_type=str(row["__task_type__"]),
                status=str(row["__status__"]),
                payload=payload,
                attempt_count=int(row["attempt_count"]) if "attempt_count" in row.keys() and row["attempt_count"] is not None else 0,
                max_attempts=int(row["max_attempts"]) if "max_attempts" in row.keys() and row["max_attempts"] is not None else 3,
            )
            self._log(self.runtime_audit_path, "task_claimed", {"rowid": rowid, "task_id": task.task_id, "task_type": task.task_type})
            return task
        finally:
            conn.close()

    def _safe_cwd(self, requested_cwd: str, allowed_roots: List[str]) -> Path:
        requested = (self.project_root / requested_cwd).resolve()
        if not requested.exists():
            raise RuntimeIntegrationError(f"requested cwd does not exist: {requested}")
        for root in allowed_roots:
            allowed = (self.project_root / root).resolve()
            try:
                requested.relative_to(allowed)
                return requested
            except ValueError:
                continue
        raise RuntimeIntegrationError(f"cwd outside allowed roots: {requested}")

    def _build_env(self, requested_env: Dict[str, Any], allowlist: List[str]) -> Dict[str, str]:
        env = {}
        host = dict(os.environ)
        for key in allowlist:
            if key in host:
                env[key] = host[key]
        for key, value in requested_env.items():
            if key in allowlist:
                env[key] = str(value)
        env["PYTHONUNBUFFERED"] = "1"
        env["ORCHESTRATOR_RUNTIME_WORKER"] = self.worker_name
        return env

    def _artifact_dir(self, task_id: str) -> Path:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = uuid.uuid4().hex[:10]
        return self.project_root / "artifacts" / "runtime_runs" / task_id / f"{stamp}_{run_id}"

    def _set_running(self, task: RuntimeTask) -> None:
        updates = {"status": STATUS_RUNNING, "attempt_count": task.attempt_count + 1}
        self._update_row(task.rowid, updates)
        self._log(self.runtime_audit_path, "task_running", {"rowid": task.rowid, "task_id": task.task_id, "task_type": task.task_type})

    def _finish(self, task: RuntimeTask, next_status: str, result: Dict[str, Any], artifact_dir: Optional[Path]) -> None:
        updates: Dict[str, Any] = {
            "status": next_status,
            "last_error": result.get("error_summary"),
            "attempt_count": result.get("attempt_count", task.attempt_count + 1),
        }
        if artifact_dir is not None:
            updates["artifact_path"] = str(artifact_dir)
        updates["result_json"] = json.dumps(result, ensure_ascii=False, sort_keys=True)
        self._update_row(task.rowid, updates)
        self._log(
            self.runtime_audit_path,
            "task_succeeded" if next_status == STATUS_SUCCEEDED else "task_failed",
            {
                "rowid": task.rowid,
                "task_id": task.task_id,
                "task_type": task.task_type,
                "artifact_dir": str(artifact_dir) if artifact_dir else None,
                "next_status": next_status,
                "exit_code": result.get("exit_code"),
            },
        )

    def execute_task(self, task: RuntimeTask) -> Dict[str, Any]:
        payload = task.payload
        service_path = str(payload.get("service_path") or task.task_type).strip() or task.task_type

        decision = self.governance.decide(
            task_type=task.task_type,
            payload=payload,
            service_path=service_path,
            mode="execution",
        )
        if not decision.ok:
            result = {
                "task_id": task.task_id,
                "task_type": task.task_type,
                "service_path": service_path,
                "exit_code": 3,
                "error_summary": "; ".join(decision.reasons),
                "attempt_count": task.attempt_count + 1,
                "finished_at": utc_now_iso(),
            }
            self._log(
                self.governance_audit_path,
                "execution_denied_by_policy",
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "rowid": task.rowid,
                    "reasons": decision.reasons,
                    "owner_agent": decision.owner_agent,
                },
            )
            terminal = (task.attempt_count + 1) >= task.max_attempts
            self._finish(task, STATUS_DEAD_LETTER if terminal else STATUS_FAILED, result, None)
            return result

        if service_path not in self.services:
            result = {
                "task_id": task.task_id,
                "task_type": task.task_type,
                "service_path": service_path,
                "exit_code": 2,
                "error_summary": f"unknown service_path: {service_path}",
                "attempt_count": task.attempt_count + 1,
                "finished_at": utc_now_iso(),
            }
            terminal = (task.attempt_count + 1) >= task.max_attempts
            self._finish(task, STATUS_DEAD_LETTER if terminal else STATUS_FAILED, result, None)
            return result

        spec = self.services[service_path]
        self._set_running(task)

        requested_cwd = str(payload.get("cwd", "."))
        run_cwd = self._safe_cwd(requested_cwd, spec.allowed_cwds)
        requested_env = payload.get("env", {})
        if not isinstance(requested_env, dict):
            requested_env = {}

        command = spec.command + [str(x) for x in payload.get("argv", []) if isinstance(x, str)]
        stdin_json = json.dumps(payload, ensure_ascii=False)
        artifact_dir = self._artifact_dir(task.task_id)
        ensure_dir(artifact_dir)

        request_json = {
            "task_id": task.task_id,
            "task_type": task.task_type,
            "service_path": service_path,
            "command": command,
            "command_shell_escaped": shlex.join(command),
            "cwd": str(run_cwd),
            "payload": payload,
            "governance_owner_agent": decision.owner_agent,
            "governance_paths": decision.matched_paths,
            "started_at": utc_now_iso(),
        }
        write_json_file(artifact_dir / "request.json", request_json)

        start = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=str(run_cwd),
                env=self._build_env(requested_env, spec.env_allowlist),
                input=stdin_json,
                text=True,
                capture_output=True,
                timeout=int(payload.get("timeout_sec", spec.timeout_sec)),
                check=False,
            )
            exit_code = int(completed.returncode)
            stdout_text = completed.stdout or ""
            stderr_text = completed.stderr or ""
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            stdout_text = exc.stdout or ""
            stderr_text = exc.stderr or ""
        except Exception as exc:
            exit_code = 1
            stdout_text = ""
            stderr_text = f"{type(exc).__name__}: {exc}"

        duration_ms = int((time.monotonic() - start) * 1000)
        (artifact_dir / "stdout.log").write_text(stdout_text, encoding="utf-8")
        (artifact_dir / "stderr.log").write_text(stderr_text, encoding="utf-8")

        result = {
            "task_id": task.task_id,
            "task_type": task.task_type,
            "service_path": service_path,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout_tail": stdout_text[-4000:],
            "stderr_tail": stderr_text[-4000:],
            "attempt_count": task.attempt_count + 1,
            "finished_at": utc_now_iso(),
        }
        if exit_code != 0:
            result["error_summary"] = stderr_text[-4000:] or f"command failed with exit code {exit_code}"

        write_json_file(artifact_dir / "result.json", result)

        terminal = (task.attempt_count + 1) >= task.max_attempts
        if exit_code == 0:
            self._finish(task, STATUS_SUCCEEDED, result, artifact_dir)
        else:
            self._finish(task, STATUS_DEAD_LETTER if terminal else STATUS_FAILED, result, artifact_dir)
        return result

    def run_once(self) -> int:
        task = self.claim_next_task()
        if task is None:
            return 0
        self.execute_task(task)
        return 1

    def run_loop(self, poll_interval_sec: float = 2.0) -> None:
        while True:
            processed = self.run_once()
            if processed == 0:
                time.sleep(poll_interval_sec)

    def requeue_failed(self) -> int:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("UPDATE task_queue SET status = ?, updated_at = ? WHERE status = ?", [STATUS_QUEUED, utc_now_iso(), STATUS_FAILED])
            changed = int(cur.rowcount or 0)
            conn.execute("COMMIT")
            return changed
        finally:
            conn.close()


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Governed runtime bridge")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--db-path", default="")
    parser.add_argument("--service-map", default="runtime/service_map.json")
    parser.add_argument("--worker-name", default=f"runtime-worker-{os.getpid()}")
    parser.add_argument("--show-services", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--requeue-failed", action="store_true")
    parser.add_argument("--poll-interval-sec", type=float, default=2.0)
    return parser.parse_args(argv)


def build_bridge(args: argparse.Namespace) -> RuntimeBridge:
    project_root = Path(args.project_root).resolve()
    db_path = Path(args.db_path).resolve() if args.db_path else (
        project_root / "data" / "orchestrator.db"
        if (project_root / "data" / "orchestrator.db").exists()
        else project_root / "orchestrator.db"
    )
    service_map_path = Path(args.service_map).resolve() if Path(args.service_map).is_absolute() else (project_root / args.service_map)
    return RuntimeBridge(project_root=project_root, db_path=db_path, service_map_path=service_map_path, worker_name=args.worker_name)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    bridge = build_bridge(args)

    if args.show_services:
        print(json.dumps(bridge.list_services(), ensure_ascii=False, indent=2))
        return 0
    if args.requeue_failed:
        print(json.dumps({"requeued_failed": bridge.requeue_failed()}, ensure_ascii=False))
        return 0
    if args.once:
        print(json.dumps({"processed": bridge.run_once()}, ensure_ascii=False))
        return 0
    if args.loop:
        bridge.run_loop(args.poll_interval_sec)
        return 0

    print("Use --show-services or --once or --loop or --requeue-failed", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
