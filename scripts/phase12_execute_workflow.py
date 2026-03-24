from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


PHASE12_KEY = "phase12_prod_v1"


def run_cmd(project_root: Path, cmd: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(project_root), capture_output=True, text=True, check=False)


def choose_db_path(project_root: Path) -> Path:
    data_db = project_root / "data" / "orchestrator.db"
    return data_db if data_db.exists() else (project_root / "orchestrator.db")


def state_file(project_root: Path) -> Path:
    path = project_root / "artifacts" / "state" / "phase12" / "current_workflow_run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def save_current_workflow_run(project_root: Path, payload: Dict[str, Any]) -> None:
    state = {
        "workflow_id": str(payload["workflow_id"]),
        "workflow_run_id": str(payload["workflow_run_id"]),
        "workflow_run_key": PHASE12_KEY,
        "created": payload["created"],
        "created_rowids": [int(x["rowid"]) for x in payload["created"]]
    }
    state_file(project_root).write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def load_current_workflow_run(project_root: Path) -> Dict[str, Any]:
    return json.loads(state_file(project_root).read_text(encoding="utf-8"))


def fetch_rows_by_rowids(project_root: Path, rowids: List[int]) -> List[Dict[str, Any]]:
    if not rowids:
        return []
    conn = sqlite3.connect(str(choose_db_path(project_root)))
    conn.row_factory = sqlite3.Row
    try:
        placeholders = ", ".join(["?"] * len(rowids))
        rows = conn.execute(
            f"SELECT rowid, task_id, task_type, status, attempt_count, last_error, priority FROM task_queue WHERE rowid IN ({placeholders}) ORDER BY priority DESC, rowid ASC",
            rowids
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def fetch_current_rows(project_root: Path) -> List[Dict[str, Any]]:
    state = load_current_workflow_run(project_root)
    return fetch_rows_by_rowids(project_root, [int(x) for x in state["created_rowids"]])


def fetch_row(project_root: Path, rowid: int) -> Dict[str, Any]:
    rows = fetch_rows_by_rowids(project_root, [rowid])
    if not rows:
        raise RuntimeError(f"row not found: {rowid}")
    return rows[0]


def approve_row(project_root: Path, rowid: int, task_type: str) -> Tuple[bool, Dict[str, Any]]:
    res = run_cmd(
        project_root,
        ["python3", "scripts/approval_gate.py", "approve", "--actor", "behzad", "--rowid", str(rowid), "--reason", f"phase12 production approval for {task_type}"]
    )
    return res.returncode == 0, {
        "rowid": rowid,
        "task_type": task_type,
        "returncode": res.returncode,
        "stdout": res.stdout,
        "stderr": res.stderr
    }


def run_worker_until_idle(project_root: Path, max_loops: int = 50) -> Tuple[int, List[Dict[str, Any]]]:
    processed_total = 0
    worker_runs: List[Dict[str, Any]] = []
    for _ in range(max_loops):
        res = run_cmd(project_root, ["python3", "scripts/runtime_worker.py", "--once"])
        if res.returncode != 0:
            worker_runs.append({"returncode": res.returncode, "stdout": res.stdout, "stderr": res.stderr})
            break
        try:
            payload = json.loads((res.stdout or "").strip() or "{}")
        except json.JSONDecodeError:
            payload = {}
        processed = int(payload.get("processed", 0))
        processed_total += processed
        worker_runs.append({"returncode": res.returncode, "stdout": res.stdout, "stderr": res.stderr, "processed": processed})
        if processed == 0:
            break
    return processed_total, worker_runs


def status_map(project_root: Path) -> Dict[str, str]:
    return {row["task_type"]: row["status"] for row in fetch_current_rows(project_root)}


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    seed = run_cmd(project_root, ["python3", "scripts/seed_phase12_workflow.py"])
    if seed.returncode != 0:
        print(seed.stdout)
        print(seed.stderr, file=sys.stderr)
        return seed.returncode

    seed_payload = json.loads(seed.stdout)
    save_current_workflow_run(project_root, seed_payload)

    ordered_task_types = [
        "intake.define_project",
        "env.define_promotion_model",
        "cicd.write_pipeline_spec",
        "ops.write_observability_spec",
        "ops.write_change_control_spec",
        "devops.generate_supply_chain_bundle",
        "architect.review_production_change",
        "release.promote_environment",
        "debugger.write_postmortem"
    ]

    approvals: List[Dict[str, Any]] = []
    worker_runs: List[Dict[str, Any]] = []
    rounds: List[Dict[str, Any]] = []

    current_rows = fetch_current_rows(project_root)
    task_by_type = {row["task_type"]: row for row in current_rows}

    for round_no, task_type in enumerate(ordered_task_types, start=1):
        row = task_by_type.get(task_type)
        if not row:
            print(json.dumps({"ok": False, "stage": "lookup", "missing_task_type": task_type}, ensure_ascii=False, indent=2))
            return 1

        latest = fetch_row(project_root, int(row["rowid"]))
        if latest["status"] != "blocked":
            rounds.append({
                "round": round_no,
                "task_type": task_type,
                "rowid": latest["rowid"],
                "status_before": latest["status"],
                "approved": False,
                "processed": 0,
                "status_after": latest["status"]
            })
            continue

        ok, result = approve_row(project_root, rowid=int(latest["rowid"]), task_type=str(latest["task_type"]))
        approvals.append(result)
        if not ok:
            print(json.dumps({
                "ok": False,
                "stage": "approve",
                "failed_task_type": task_type,
                "failed_rowid": latest["rowid"],
                "approvals": approvals,
                "status": fetch_current_rows(project_root)
            }, ensure_ascii=False, indent=2))
            return 1

        processed, runs = run_worker_until_idle(project_root)
        worker_runs.extend(runs)
        refreshed = fetch_row(project_root, int(latest["rowid"]))

        rounds.append({
            "round": round_no,
            "task_type": task_type,
            "rowid": latest["rowid"],
            "status_before": "blocked",
            "approved": True,
            "processed": processed,
            "status_after": refreshed["status"],
            "status_map_after": status_map(project_root)
        })

        if refreshed["status"] != "succeeded":
            print(json.dumps({
                "ok": False,
                "stage": "execute",
                "failed_task_type": task_type,
                "failed_rowid": latest["rowid"],
                "row_after_execution": refreshed,
                "worker_runs": worker_runs[-10:],
                "status": fetch_current_rows(project_root)
            }, ensure_ascii=False, indent=2))
            return 1

    print(json.dumps({
        "ok": True,
        "workflow_id": seed_payload["workflow_id"],
        "workflow_run_id": seed_payload["workflow_run_id"],
        "workflow_run_key": PHASE12_KEY,
        "approvals_count": len(approvals),
        "rounds": rounds,
        "status": fetch_current_rows(project_root)
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
