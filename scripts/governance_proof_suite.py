from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.governance import Governance  # noqa: E402


UTC = timezone.utc


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def db_path(project_root: Path) -> Path:
    data_db = project_root / "data" / "orchestrator.db"
    return data_db if data_db.exists() else (project_root / "orchestrator.db")


def sample_existing_or_default(project_root: Path, rel: str, content: str) -> Path:
    p = (project_root / rel).resolve()
    ensure_dir(p.parent)
    if not p.exists():
        p.write_text(content, encoding="utf-8")
    return p


def status_summary(project_root: Path) -> List[Dict[str, Any]]:
    db = db_path(project_root)
    if not db.exists():
        return []
    conn = sqlite3.connect(str(db))
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT task_type, status, COUNT(*) AS count FROM task_queue GROUP BY task_type, status ORDER BY task_type, status"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def main() -> int:
    project_root = PROJECT_ROOT
    gov = Governance(project_root)

    notes_path = sample_existing_or_default(
        project_root,
        "artifacts/runs/phase_h_demo_v2/research/control-plane-routing.md",
        "# routing notes\n\ncontrol plane routing\n",
    )
    component_path = project_root / "artifacts" / "runs" / "phase_h_demo_v2" / "frontend" / "HeroFromResearch.tsx"
    workflow_path = project_root / "artifacts" / "runs" / "phase_h_demo_v2" / "workflows" / "phase_h_bundle.txt"

    proofs: List[Dict[str, Any]] = []

    d1 = gov.decide(
        task_type="frontend.write_component",
        payload={
            "component_name": "HeroFromResearch",
            "workflow_run_key": "phase_h_demo_v2",
            "source_notes_path": str(notes_path),
            "component_path": str(component_path),
        },
        service_path="frontend.write_component",
        actor="behzad",
        mode="approval",
    )
    proofs.append({
        "proof_id": "G1_positive_approval_frontend",
        "expected": True,
        "actual": d1.ok,
        "reasons": d1.reasons,
    })

    d2 = gov.decide(
        task_type="frontend.write_component",
        payload={
            "component_name": "HeroFromResearch",
            "workflow_run_key": "phase_h_demo_v2",
            "source_notes_path": str(notes_path),
            "component_path": str(component_path),
        },
        service_path="frontend.write_component",
        actor="ci-bot",
        mode="approval",
    )
    proofs.append({
        "proof_id": "G2_negative_unauthorized_actor",
        "expected": False,
        "actual": d2.ok,
        "reasons": d2.reasons,
    })

    d3 = gov.decide(
        task_type="backend.write_file",
        payload={
            "workflow_run_key": "phase_h_demo_v2",
            "path": "/tmp/evil.txt",
            "content": "x",
        },
        service_path="backend.write_file",
        mode="execution",
    )
    proofs.append({
        "proof_id": "G3_negative_path_escape",
        "expected": False,
        "actual": d3.ok,
        "reasons": d3.reasons,
    })

    d4 = gov.decide(
        task_type="frontend.write_component",
        payload={
            "component_name": "HeroFromResearch",
            "workflow_run_key": "phase_h_demo_v2",
            "source_notes_path": str(project_root / "artifacts" / "runs" / "phase_h_demo_v2" / "research" / "missing.md"),
            "component_path": str(component_path),
        },
        service_path="frontend.write_component",
        mode="execution",
    )
    proofs.append({
        "proof_id": "G4_negative_missing_dependency",
        "expected": False,
        "actual": d4.ok,
        "reasons": d4.reasons,
    })

    d5 = gov.decide(
        task_type="memory.write_json",
        payload={
            "path": str(project_root / "artifacts" / "state" / "backend" / "state.json"),
            "json_value": {"ok": True},
        },
        service_path="memory.write_json",
        mode="execution",
    )
    proofs.append({
        "proof_id": "G5_positive_memory_write",
        "expected": True,
        "actual": d5.ok,
        "reasons": d5.reasons,
    })

    d6 = gov.decide(
        task_type="memory.write_json",
        payload={
            "path": str(project_root / "artifacts" / "runs" / "phase_h_demo_v2" / "frontend" / "bad.json"),
            "json_value": {"bad": True},
        },
        service_path="memory.write_json",
        mode="execution",
    )
    proofs.append({
        "proof_id": "G6_negative_memory_namespace_violation",
        "expected": False,
        "actual": d6.ok,
        "reasons": d6.reasons,
    })

    passed = 0
    for item in proofs:
        expected = bool(item["expected"])
        actual = bool(item["actual"])
        if expected == actual:
            passed += 1

    summary = {
        "generated_at": utc_now_iso(),
        "project_root": str(project_root),
        "passed": passed,
        "total": len(proofs),
        "proofs": proofs,
        "status_summary": status_summary(project_root),
    }

    handover_dir = project_root / "artifacts" / "governance_handover"
    ensure_dir(handover_dir)

    with (handover_dir / "governance_proof_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, sort_keys=True)

    md_lines = [
        "# Governance Handover Summary",
        "",
        f"- generated_at: {summary['generated_at']}",
        f"- passed: {summary['passed']}/{summary['total']}",
        "",
        "## Proof Results",
        "",
    ]
    for item in proofs:
        md_lines.append(f"### {item['proof_id']}")
        md_lines.append(f"- expected: {item['expected']}")
        md_lines.append(f"- actual: {item['actual']}")
        md_lines.append(f"- reasons: {'; '.join(item['reasons']) if item['reasons'] else '(none)'}")
        md_lines.append("")

    md_lines.append("## Runtime Status Summary")
    md_lines.append("")
    for row in summary["status_summary"]:
        md_lines.append(f"- {row['task_type']} | {row['status']} | {row['count']}")
    md_lines.append("")

    (handover_dir / "governance_handover.md").write_text("\n".join(md_lines), encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "passed": passed,
        "total": len(proofs),
        "handover_json": str(handover_dir / "governance_proof_summary.json"),
        "handover_md": str(handover_dir / "governance_handover.md"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
