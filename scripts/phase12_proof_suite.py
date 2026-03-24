from __future__ import annotations

import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


UTC = timezone.utc
PHASE12_KEY = "phase12_prod_v1"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def choose_db_path(project_root: Path) -> Path:
    data_db = project_root / "data" / "orchestrator.db"
    return data_db if data_db.exists() else (project_root / "orchestrator.db")


def state_file(project_root: Path) -> Path:
    return project_root / "artifacts" / "state" / "phase12" / "current_workflow_run.json"


def load_current_workflow_run(project_root: Path) -> Dict[str, Any]:
    return json.loads(state_file(project_root).read_text(encoding="utf-8"))


def run(project_root: Path, cmd: List[str], stdin_text: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(project_root), input=stdin_text, capture_output=True, text=True, check=False)


def rows_by_rowids(project_root: Path, rowids: List[int]) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(str(choose_db_path(project_root)))
    conn.row_factory = sqlite3.Row
    try:
        placeholders = ", ".join(["?"] * len(rowids))
        rows = conn.execute(
            f"SELECT rowid, task_id, task_type, status, attempt_count, last_error FROM task_queue WHERE rowid IN ({placeholders}) ORDER BY rowid ASC",
            rowids
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def path_exists(project_root: Path, rel: str) -> bool:
    return (project_root / rel).exists()


def read_json_file(project_root: Path, rel: str) -> Any:
    with (project_root / rel).open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    handover_dir = project_root / "artifacts" / "phase12_handover"
    handover_dir.mkdir(parents=True, exist_ok=True)

    state = load_current_workflow_run(project_root)
    rowids = [int(x) for x in state["created_rowids"]]
    rows = rows_by_rowids(project_root, rowids)
    status_map = {row["task_type"]: row["status"] for row in rows}
    proofs: List[Dict[str, Any]] = []

    expected_success = [
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
    for task_type in expected_success:
        actual = status_map.get(task_type)
        proofs.append({"proof_id": f"P_status_{task_type}", "expected": "succeeded", "actual": actual, "ok": actual == "succeeded"})

    artifact_checks = [
        ("intake_exists", "artifacts/runs/phase12_prod_v1/intake/project_intake.md"),
        ("env_model_exists", "artifacts/runs/phase12_prod_v1/environments/promotion_model.json"),
        ("pipeline_exists", "artifacts/runs/phase12_prod_v1/cicd/pipeline_spec.yaml"),
        ("observability_exists", "artifacts/runs/phase12_prod_v1/ops/observability_spec.json"),
        ("change_control_exists", "artifacts/runs/phase12_prod_v1/ops/change_control.md"),
        ("sbom_exists", "artifacts/runs/phase12_prod_v1/supply/sbom.json"),
        ("provenance_exists", "artifacts/runs/phase12_prod_v1/supply/provenance.json"),
        ("signing_exists", "artifacts/runs/phase12_prod_v1/supply/signing.json"),
        ("change_review_exists", "artifacts/runs/phase12_prod_v1/architect/change_review.json"),
        ("deployment_report_exists", "artifacts/runs/phase12_prod_v1/release/deployment_report.json"),
        ("postmortem_exists", "artifacts/runs/phase12_prod_v1/postmortem/postmortem.md")
    ]
    for proof_id, rel in artifact_checks:
        ok = path_exists(project_root, rel)
        proofs.append({"proof_id": proof_id, "expected": True, "actual": ok, "ok": ok})

    deny_seed = run(project_root, ["python3", "scripts/create_phase12_live_deny_proof_task.py"])
    deny_ok = False
    deny_detail = ""
    if deny_seed.returncode == 0:
        deny_seed_payload = json.loads(deny_seed.stdout)
        deny_rowid = int(deny_seed_payload["rowid"])
        deny = run(project_root, ["python3", "scripts/approval_gate.py", "approve", "--actor", "ci-bot", "--rowid", str(deny_rowid), "--reason", "phase12 unauthorized approval proof"])
        deny_ok = deny.returncode != 0
        deny_detail = (deny.stderr or "").strip()
    proofs.append({"proof_id": "P_unauthorized_approval_denied", "expected": True, "actual": deny_ok, "ok": deny_ok, "detail": deny_detail})

    path_escape = run(project_root, ["python3", "scripts/phase12_operational_runner.py", "env.define_promotion_model"], stdin_text=json.dumps({"workflow_run_key": PHASE12_KEY, "model_name": "bad", "path": "/tmp/phase12-evil.json"}))
    proofs.append({"proof_id": "P_path_escape_denied", "expected": 3, "actual": path_escape.returncode, "ok": path_escape.returncode == 3, "detail": (path_escape.stdout or "").strip()})

    deployment_report = read_json_file(project_root, "artifacts/runs/phase12_prod_v1/release/deployment_report.json")
    proofs.append({"proof_id": "P_prod_target_environment", "expected": "prod", "actual": deployment_report.get("target_environment"), "ok": deployment_report.get("target_environment") == "prod"})
    proofs.append({"proof_id": "P_safe_deployment_mode", "expected": "ring_canary", "actual": deployment_report.get("safe_deployment", {}).get("mode"), "ok": deployment_report.get("safe_deployment", {}).get("mode") == "ring_canary"})

    passed = sum(1 for p in proofs if p["ok"])
    summary = {
        "generated_at": utc_now_iso(),
        "workflow_run_id": state["workflow_run_id"],
        "workflow_run_key": PHASE12_KEY,
        "passed": passed,
        "total": len(proofs),
        "proofs": proofs,
        "phase12_status": rows
    }

    with (handover_dir / "phase12_proof_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, sort_keys=True)

    md = [
        "# Phase12 Proof Summary",
        "",
        f"- generated_at: {summary['generated_at']}",
        f"- workflow_run_id: {summary['workflow_run_id']}",
        f"- passed: {passed}/{len(proofs)}",
        "",
        "## Proofs",
        ""
    ]
    for item in proofs:
        md.append(f"### {item['proof_id']}")
        md.append(f"- expected: {item['expected']}")
        md.append(f"- actual: {item['actual']}")
        md.append(f"- ok: {item['ok']}")
        if item.get("detail"):
            md.append(f"- detail: {item['detail']}")
        md.append("")
    md.append("## Phase12 Status")
    md.append("")
    for row in rows:
        md.append(f"- {row['task_type']} | {row['status']} | attempts={row['attempt_count']}")
    md.append("")
    (handover_dir / "phase12_proof_summary.md").write_text("\n".join(md), encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "passed": passed,
        "total": len(proofs),
        "handover_json": str(handover_dir / "phase12_proof_summary.json"),
        "handover_md": str(handover_dir / "phase12_proof_summary.md")
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
