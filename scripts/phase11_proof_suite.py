from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


UTC = timezone.utc
PHASE11_KEY = "phase11_demo_v1"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def choose_db_path(project_root: Path) -> Path:
    data_db = project_root / "data" / "orchestrator.db"
    return data_db if data_db.exists() else (project_root / "orchestrator.db")


def state_file(project_root: Path) -> Path:
    return project_root / "artifacts" / "state" / "phase11" / "current_workflow_run.json"


def load_current_workflow_run(project_root: Path) -> Dict[str, Any]:
    path = state_file(project_root)
    if not path.exists():
        raise RuntimeError("current phase11 workflow state file missing")
    return json.loads(path.read_text(encoding="utf-8"))


def run(project_root: Path, cmd: List[str], stdin_text: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(project_root), input=stdin_text, capture_output=True, text=True, check=False)


def phase11_rows(project_root: Path, rowids: List[int]) -> List[Dict[str, Any]]:
    if not rowids:
        return []
    conn = sqlite3.connect(str(choose_db_path(project_root)))
    conn.row_factory = sqlite3.Row
    try:
        placeholders = ", ".join(["?"] * len(rowids))
        rows = conn.execute(
            f"""
            SELECT rowid, task_id, task_type, status, attempt_count, last_error
            FROM task_queue
            WHERE rowid IN ({placeholders})
            ORDER BY rowid ASC
            """,
            rowids,
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def path_exists(project_root: Path, rel: str) -> bool:
    return (project_root / rel).exists()


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    handover_dir = project_root / "artifacts" / "phase11_handover"
    handover_dir.mkdir(parents=True, exist_ok=True)

    current = load_current_workflow_run(project_root)
    rowids = [int(x) for x in current["created_rowids"]]
    rows = phase11_rows(project_root, rowids)
    status_map = {row["task_type"]: row["status"] for row in rows}

    proofs: List[Dict[str, Any]] = []

    expected_success = [
        "research.collect_notes",
        "frontend.write_component",
        "backend.write_file",
        "memory.write_json",
        "debugger.analyze_failure",
        "devops.build_release_bundle",
        "architect.review_constraints",
    ]
    for task_type in expected_success:
        actual = status_map.get(task_type)
        proofs.append(
            {
                "proof_id": f"P_status_{task_type}",
                "expected": "succeeded",
                "actual": actual,
                "ok": actual == "succeeded",
            }
        )

    artifact_checks = [
        ("research_notes_exists", "artifacts/runs/phase11_demo_v1/research/market_notes.md"),
        ("frontend_component_exists", "artifacts/runs/phase11_demo_v1/frontend/ResearchHero.tsx"),
        ("backend_bundle_exists", "artifacts/runs/phase11_demo_v1/workflows/backend_bundle.txt"),
        ("memory_state_exists", "artifacts/state/phase11/workflow_state.json"),
        ("debugger_rca_exists", "artifacts/runs/phase11_demo_v1/debugger/rca.md"),
        ("devops_manifest_exists", "artifacts/runs/phase11_demo_v1/devops/release_manifest.json"),
        ("architect_review_exists", "artifacts/runs/phase11_demo_v1/architect/review.json"),
    ]
    for proof_id, rel in artifact_checks:
        ok = path_exists(project_root, rel)
        proofs.append(
            {
                "proof_id": proof_id,
                "expected": True,
                "actual": ok,
                "ok": ok,
            }
        )

    deny_seed = run(project_root, ["python3", "scripts/create_live_deny_proof_task.py"])
    deny_ok = False
    deny_detail = ""
    if deny_seed.returncode == 0:
        deny_seed_payload = json.loads(deny_seed.stdout)
        deny_rowid = int(deny_seed_payload["rowid"])
        deny = run(
            project_root,
            [
                "python3",
                "scripts/approval_gate.py",
                "approve",
                "--actor",
                "ci-bot",
                "--rowid",
                str(deny_rowid),
                "--reason",
                "phase11 unauthorized approval proof",
            ],
        )
        deny_ok = deny.returncode != 0
        deny_detail = (deny.stderr or "").strip()

    proofs.append(
        {
            "proof_id": "P_unauthorized_approval_denied",
            "expected": True,
            "actual": deny_ok,
            "ok": deny_ok,
            "detail": deny_detail,
        }
    )

    memory_positive = run(
        project_root,
        ["python3", "scripts/operational_task_runner.py", "memory.read_json"],
        stdin_text=json.dumps({"path": "artifacts/state/phase11/workflow_state.json"}),
    )
    proofs.append(
        {
            "proof_id": "P_memory_read_positive",
            "expected": 0,
            "actual": memory_positive.returncode,
            "ok": memory_positive.returncode == 0,
        }
    )

    path_escape = run(
        project_root,
        ["python3", "scripts/operational_task_runner.py", "memory.write_json"],
        stdin_text=json.dumps({"path": "/tmp/phase11-evil.json", "json_value": {"bad": True}}),
    )
    proofs.append(
        {
            "proof_id": "P_path_escape_denied",
            "expected": 3,
            "actual": path_escape.returncode,
            "ok": path_escape.returncode == 3,
            "detail": (path_escape.stdout or "").strip(),
        }
    )

    passed = sum(1 for p in proofs if p["ok"])
    summary = {
        "generated_at": utc_now_iso(),
        "workflow_run_id": str(current["workflow_run_id"]),
        "workflow_run_key": PHASE11_KEY,
        "passed": passed,
        "total": len(proofs),
        "proofs": proofs,
        "phase11_status": rows,
    }

    with (handover_dir / "phase11_proof_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, sort_keys=True)

    md = [
        "# Phase11 Proof Summary",
        "",
        f"- generated_at: {summary['generated_at']}",
        f"- workflow_run_id: {summary['workflow_run_id']}",
        f"- passed: {passed}/{len(proofs)}",
        "",
        "## Proofs",
        "",
    ]
    for item in proofs:
        md.append(f"### {item['proof_id']}")
        md.append(f"- expected: {item['expected']}")
        md.append(f"- actual: {item['actual']}")
        md.append(f"- ok: {item['ok']}")
        if item.get("detail"):
            md.append(f"- detail: {item['detail']}")
        md.append("")
    md.append("## Phase11 Status")
    md.append("")
    for row in rows:
        md.append(f"- {row['task_type']} | {row['status']} | attempts={row['attempt_count']}")
    md.append("")
    (handover_dir / "phase11_proof_summary.md").write_text("\n".join(md), encoding="utf-8")

    print(
        json.dumps(
            {
                "ok": True,
                "passed": passed,
                "total": len(proofs),
                "handover_json": str(handover_dir / "phase11_proof_summary.json"),
                "handover_md": str(handover_dir / "phase11_proof_summary.md"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
