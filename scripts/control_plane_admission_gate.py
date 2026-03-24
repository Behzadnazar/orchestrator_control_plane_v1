#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUDIT_ROOT = ROOT / "artifacts" / "audit"
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
ADMISSION_ROOT = OPERATIONS_ROOT / "admission"
READINESS_ROOT = OPERATIONS_ROOT


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path):
    return json.loads(read_text(path))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


def require_dir(path: Path) -> Path:
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Required directory missing: {path}")
    return path


def load_jsonl(path: Path) -> list[dict]:
    entries: list[dict] = []
    with require_file(path).open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            obj["_line_number"] = lineno
            entries.append(obj)
    return entries


def latest_entry(entries: list[dict]) -> dict | None:
    return entries[-1] if entries else None


def find_latest_readiness_report(label: str) -> Path:
    path = READINESS_ROOT / label / "operational_readiness_report.json"
    return require_file(path)


def find_chain_summary(label: str) -> Path:
    path = AUDIT_ROOT / "verification" / label / "audit_chain_verification_summary.json"
    return require_file(path)


def find_rc_record(rc_name: str) -> Path:
    path = AUDIT_ROOT / "release_candidate_records" / rc_name / "release_candidate_record.json"
    return require_file(path)


def find_milestone_record(milestone: str) -> Path:
    path = AUDIT_ROOT / "milestone_records" / milestone / "signed_milestone_record.json"
    return require_file(path)


def evaluate_gate(
    operation: str,
    workflow_id: str,
    readiness_report: dict,
    chain_summary: dict,
    audit_entries: list[dict],
    milestone_record: dict | None,
    rc_record: dict | None,
    require_rc: bool,
) -> tuple[bool, list[dict], dict]:
    checks: list[dict] = []

    def add_check(name: str, passed: bool, detail) -> None:
        checks.append(
            {
                "name": name,
                "passed": bool(passed),
                "detail": detail,
            }
        )

    readiness_status = str(readiness_report.get("status", "")).upper()
    readiness_mode = str(readiness_report.get("readiness", "")).upper()
    add_check(
        "operational_readiness_pass",
        readiness_status == "PASS",
        {"status": readiness_status},
    )
    add_check(
        "operational_mode_controlled_local_ready",
        readiness_mode == "CONTROLLED_LOCAL_OPERATION_READY",
        {"readiness": readiness_mode},
    )

    checks_payload = readiness_report.get("checks", {})
    add_check(
        "readiness_checks_all_true",
        isinstance(checks_payload, dict) and all(bool(v) for v in checks_payload.values()),
        {"checks": checks_payload},
    )

    chain_status = str(chain_summary.get("overall_status", "")).upper()
    failed_entries = int(chain_summary.get("failed_entries", -1))
    add_check(
        "latest_chain_pass",
        chain_status == "PASS",
        {"overall_status": chain_status},
    )
    add_check(
        "latest_chain_failed_entries_zero",
        failed_entries == 0,
        {"failed_entries": failed_entries},
    )

    add_check(
        "audit_index_nonempty",
        len(audit_entries) >= 1,
        {"entry_count": len(audit_entries)},
    )

    latest_audit = latest_entry(audit_entries)
    add_check(
        "latest_audit_entry_present",
        latest_audit is not None,
        {
            "latest_entry_type": None if latest_audit is None else latest_audit.get("entry_type"),
            "latest_line": None if latest_audit is None else latest_audit.get("_line_number"),
        },
    )

    if milestone_record is not None:
        milestone_status = str(milestone_record.get("freeze_gate_overall_status", "")).upper()
        add_check(
            "milestone_record_pass",
            milestone_status == "PASS",
            {"milestone_status": milestone_status, "milestone": milestone_record.get("milestone")},
        )
    else:
        add_check(
            "milestone_record_optional_absent",
            True,
            {"reason": "No milestone supplied"},
        )

    if require_rc:
        if rc_record is None:
            add_check(
                "release_candidate_required_present",
                False,
                {"reason": "require_rc=true but rc record not supplied"},
            )
        else:
            rc_status = str(rc_record.get("promotion_status", "")).upper()
            rc_allowed = bool(rc_record.get("promotion_allowed"))
            add_check(
                "release_candidate_required_present",
                True,
                {"release_candidate": rc_record.get("release_candidate")},
            )
            add_check(
                "release_candidate_pass",
                rc_status == "PASS",
                {"promotion_status": rc_status},
            )
            add_check(
                "release_candidate_allowed",
                rc_allowed is True,
                {"promotion_allowed": rc_allowed},
            )
    else:
        if rc_record is not None:
            rc_status = str(rc_record.get("promotion_status", "")).upper()
            rc_allowed = bool(rc_record.get("promotion_allowed"))
            add_check(
                "release_candidate_optional_if_present_pass",
                rc_status == "PASS" and rc_allowed is True,
                {
                    "release_candidate": rc_record.get("release_candidate"),
                    "promotion_status": rc_status,
                    "promotion_allowed": rc_allowed,
                },
            )
        else:
            add_check(
                "release_candidate_optional_absent",
                True,
                {"reason": "No RC required for this operation"},
            )

    operation_policy = {
        "execute": {
            "require_rc": False,
            "require_milestone": False,
        },
        "promote": {
            "require_rc": True,
            "require_milestone": True,
        },
        "release": {
            "require_rc": True,
            "require_milestone": True,
        },
    }

    policy = operation_policy.get(operation, {"require_rc": require_rc, "require_milestone": False})

    if policy["require_milestone"]:
        add_check(
            "operation_policy_milestone_required_present",
            milestone_record is not None,
            {"operation": operation, "milestone_required": True},
        )
    else:
        add_check(
            "operation_policy_milestone_requirement_satisfied",
            True,
            {"operation": operation, "milestone_required": False},
        )

    if policy["require_rc"]:
        add_check(
            "operation_policy_rc_required_present",
            rc_record is not None,
            {"operation": operation, "rc_required": True},
        )
    else:
        add_check(
            "operation_policy_rc_requirement_satisfied",
            True,
            {"operation": operation, "rc_required": False},
        )

    allow = all(item["passed"] for item in checks)

    decision_meta = {
        "operation": operation,
        "workflow_id": workflow_id,
        "require_rc": require_rc,
        "policy": policy,
        "latest_audit_entry_type": None if latest_audit is None else latest_audit.get("entry_type"),
        "latest_audit_entry_line": None if latest_audit is None else latest_audit.get("_line_number"),
    }

    return allow, checks, decision_meta


def build_markdown_report(
    decision: dict,
    output_dir: Path,
) -> str:
    lines: list[str] = []
    lines.append("# Control Plane Admission Gate Decision")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{decision['generated_at_utc']}`")
    lines.append(f"- Decision: **{decision['decision']}**")
    lines.append(f"- Operation: `{decision['operation']}`")
    lines.append(f"- Workflow ID: `{decision['workflow_id']}`")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Readiness report: `{decision['inputs']['readiness_report_path']}`")
    lines.append(f"- Chain summary: `{decision['inputs']['chain_summary_path']}`")
    lines.append(f"- Audit index: `{decision['inputs']['audit_index_path']}`")
    lines.append(f"- Milestone record: `{decision['inputs']['milestone_record_path']}`")
    lines.append(f"- RC record: `{decision['inputs']['release_candidate_record_path']}`")
    lines.append("")
    lines.append("## Gate Checks")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|---|---|")
    for item in decision["checks"]:
        lines.append(f"| {item['name']} | {'PASS' if item['passed'] else 'FAIL'} |")
    lines.append("")
    lines.append("## Fail-Closed Rule")
    lines.append("")
    lines.append("Any failed mandatory check results in DENY.")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run fail-closed admission gate for control-plane operations using governance and audit artifacts."
    )
    parser.add_argument("--label", default="Q2_admission_gate")
    parser.add_argument("--operation", choices=["execute", "promote", "release"], default="execute")
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--readiness-label", default="Q1_operational_readiness")
    parser.add_argument("--chain-label", default="Q1_post_readiness_chain_check")
    parser.add_argument("--milestone", default="")
    parser.add_argument("--release-candidate", default="")
    parser.add_argument("--require-rc", action="store_true")
    args = parser.parse_args()

    label = args.label.strip()
    operation = args.operation.strip()
    workflow_id = args.workflow_id.strip()
    readiness_label = args.readiness_label.strip()
    chain_label = args.chain_label.strip()
    milestone = args.milestone.strip()
    release_candidate = args.release_candidate.strip()

    if not label:
        raise SystemExit("Label must not be empty.")
    if not workflow_id:
        raise SystemExit("workflow-id must not be empty.")

    output_dir = ADMISSION_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")

    readiness_path = find_latest_readiness_report(readiness_label)
    chain_path = find_chain_summary(chain_label)
    audit_index_path = require_file(AUDIT_ROOT / "immutable_audit_index.jsonl")

    readiness_report = read_json(readiness_path)
    chain_summary = read_json(chain_path)
    audit_entries = load_jsonl(audit_index_path)

    milestone_record = None
    milestone_path = None
    if milestone:
        milestone_path = find_milestone_record(milestone)
        milestone_record = read_json(milestone_path)

    rc_record = None
    rc_path = None
    if release_candidate:
        rc_path = find_rc_record(release_candidate)
        rc_record = read_json(rc_path)

    allow, checks, decision_meta = evaluate_gate(
        operation=operation,
        workflow_id=workflow_id,
        readiness_report=readiness_report,
        chain_summary=chain_summary,
        audit_entries=audit_entries,
        milestone_record=milestone_record,
        rc_record=rc_record,
        require_rc=args.require_rc,
    )

    generated_at = now_utc()
    decision = {
        "decision_version": 1,
        "decision_type": "control_plane_admission_gate",
        "generated_at_utc": generated_at,
        "decision": "ALLOW" if allow else "DENY",
        "fail_closed": True,
        "operation": operation,
        "workflow_id": workflow_id,
        "metadata": decision_meta,
        "inputs": {
            "readiness_report_path": rel(readiness_path),
            "chain_summary_path": rel(chain_path),
            "audit_index_path": rel(audit_index_path),
            "milestone_record_path": rel(milestone_path),
            "release_candidate_record_path": rel(rc_path),
        },
        "checks": checks,
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    decision_json_path = output_dir / "admission_gate_decision.json"
    decision_md_path = output_dir / "admission_gate_decision.md"
    digest_path = output_dir / "admission_gate_digest_report.json"

    write_json(decision_json_path, decision)
    write_text(decision_md_path, build_markdown_report(decision, output_dir))

    digest_report = {
        "generated_at_utc": generated_at,
        "label": label,
        "decision": decision["decision"],
        "artifacts": [
            {
                "path": rel(decision_json_path),
                "size_bytes": decision_json_path.stat().st_size,
                "sha256": sha256_file(decision_json_path),
            },
            {
                "path": rel(decision_md_path),
                "size_bytes": decision_md_path.stat().st_size,
                "sha256": sha256_file(decision_md_path),
            },
        ],
    }
    write_json(digest_path, digest_report)

    print("=" * 72)
    print("CONTROL PLANE ADMISSION GATE")
    print("=" * 72)
    print(f"LABEL         : {label}")
    print(f"DECISION      : {decision['decision']}")
    print(f"OPERATION     : {operation}")
    print(f"WORKFLOW ID   : {workflow_id}")
    print(f"DECISION JSON : {rel(decision_json_path)}")
    print(f"DECISION MD   : {rel(decision_md_path)}")
    print(f"DIGEST REPORT : {rel(digest_path)}")
    print("=" * 72)

    return 0 if allow else 2


if __name__ == "__main__":
    raise SystemExit(main())
