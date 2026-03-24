from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


UTC = timezone.utc


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def read_jsonl_tail(path: Path, limit: int = 20) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    handover_dir = project_root / "artifacts" / "governance_handover"
    handover_dir.mkdir(parents=True, exist_ok=True)

    create_cmd = ["python3", "scripts/create_live_deny_proof_task.py"]
    create_res = subprocess.run(create_cmd, cwd=str(project_root), capture_output=True, text=True, check=False)
    if create_res.returncode != 0:
        print(create_res.stdout)
        print(create_res.stderr, file=sys.stderr)
        return create_res.returncode

    created = json.loads(create_res.stdout)
    rowid = int(created["rowid"])

    deny_cmd = [
        "python3",
        "scripts/approval_gate.py",
        "approve",
        "--actor",
        "ci-bot",
        "--rowid",
        str(rowid),
        "--reason",
        "live unauthorized approval deny proof",
    ]
    deny_res = subprocess.run(deny_cmd, cwd=str(project_root), capture_output=True, text=True, check=False)

    db_path = project_root / "data" / "orchestrator.db"
    if not db_path.exists():
        db_path = project_root / "orchestrator.db"

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT rowid, task_id, task_type, status FROM task_queue WHERE rowid = ?",
            [rowid],
        ).fetchone()
        db_snapshot = dict(row) if row is not None else {}
    finally:
        conn.close()

    gov_audit_path = project_root / "artifacts" / "governance_audit" / "governance_events.jsonl"
    gov_tail = read_jsonl_tail(gov_audit_path, limit=30)

    summary: Dict[str, Any] = {
        "generated_at": utc_now_iso(),
        "created_task": created,
        "deny_command": " ".join(deny_cmd),
        "deny_returncode": deny_res.returncode,
        "deny_stdout": deny_res.stdout,
        "deny_stderr": deny_res.stderr,
        "db_snapshot": db_snapshot,
        "governance_audit_path": str(gov_audit_path),
        "governance_audit_tail": gov_tail,
    }

    with (handover_dir / "live_deny_proof_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, sort_keys=True)

    md = [
        "# Live Deny Proof Summary",
        "",
        f"- generated_at: {summary['generated_at']}",
        f"- created_rowid: {created['rowid']}",
        f"- created_task_id: {created['task_id']}",
        f"- deny_returncode: {deny_res.returncode}",
        "",
        "## DB Snapshot",
        "",
        f"- rowid: {db_snapshot.get('rowid')}",
        f"- task_id: {db_snapshot.get('task_id')}",
        f"- task_type: {db_snapshot.get('task_type')}",
        f"- status_after_deny_attempt: {db_snapshot.get('status')}",
        "",
        "## Deny stderr",
        "",
        "```",
        deny_res.stderr.strip(),
        "```",
        "",
        "## Governance Audit Tail",
        "",
    ]
    for item in gov_tail:
        md.append(f"- {json.dumps(item, ensure_ascii=False)}")

    (handover_dir / "live_deny_proof_summary.md").write_text("\n".join(md), encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "live_deny_proof_json": str(handover_dir / "live_deny_proof_summary.json"),
        "live_deny_proof_md": str(handover_dir / "live_deny_proof_summary.md"),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
