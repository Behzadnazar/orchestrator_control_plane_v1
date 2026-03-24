#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUDIT_ROOT = ROOT / "artifacts" / "audit"
INDEX_PATH = AUDIT_ROOT / "immutable_audit_index.jsonl"
OUTPUT_ROOT = AUDIT_ROOT / "tamper_simulation"


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path):
    return json.loads(read_text(path))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


def run_verifier(label: str) -> dict:
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "verify_immutable_audit_chain.py"),
        "--label",
        label,
    ]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    summary_path = ROOT / "artifacts" / "audit" / "verification" / label / "audit_chain_verification_summary.json"

    summary = None
    if summary_path.exists():
        summary = read_json(summary_path)

    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "summary_path": rel(summary_path) if summary_path.exists() else None,
        "summary": summary,
    }


def load_index_lines() -> list[str]:
    require_file(INDEX_PATH)
    return INDEX_PATH.read_text(encoding="utf-8").splitlines()


def save_index_lines(lines: list[str]) -> None:
    text = "\n".join(lines)
    if lines:
        text += "\n"
    INDEX_PATH.write_text(text, encoding="utf-8")


def tamper_last_entry_record_sha(lines: list[str]) -> tuple[list[str], dict]:
    if not lines:
        raise ValueError("Audit index is empty.")

    obj = json.loads(lines[-1])
    original_value = obj.get("record_sha256")
    if not isinstance(original_value, str) or len(original_value) < 8:
        raise ValueError("Last entry does not contain a valid record_sha256.")

    tampered_value = ("0" if original_value[0] != "0" else "1") + original_value[1:]
    obj["record_sha256"] = tampered_value

    tampered_line = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    mutated = list(lines)
    mutated[-1] = tampered_line

    meta = {
        "tamper_type": "record_sha256_mismatch",
        "target_line_number": len(lines),
        "field": "record_sha256",
        "original_value": original_value,
        "tampered_value": tampered_value,
    }
    return mutated, meta


def restore_file(src: Path, dst: Path) -> None:
    shutil.copy2(src, dst)


def build_markdown_report(summary: dict) -> str:
    lines: list[str] = []
    lines.append("# Tamper Simulation + Negative Verification Proof")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Scenario label: `{summary['scenario_label']}`")
    lines.append(f"- Index path: `{summary['index_path']}`")
    lines.append(f"- Backup path: `{summary['backup_path']}`")
    lines.append(f"- Tamper status: **{summary['tamper_phase']['overall_status']}**")
    lines.append(f"- Restore status: **{summary['restore_phase']['overall_status']}**")
    lines.append(f"- Proof status: **{summary['proof_status']}**")
    lines.append("")
    lines.append("## Tamper Operation")
    lines.append("")
    lines.append(f"- Tamper type: `{summary['tamper_operation']['tamper_type']}`")
    lines.append(f"- Target line number: `{summary['tamper_operation']['target_line_number']}`")
    lines.append(f"- Field: `{summary['tamper_operation']['field']}`")
    lines.append("")
    lines.append("## Verification Results")
    lines.append("")
    lines.append("| Phase | Return Code | Overall Status | Summary Path |")
    lines.append("|---|---:|---|---|")
    lines.append(
        f"| Baseline | {summary['baseline_phase']['returncode']} | {summary['baseline_phase']['overall_status']} | `{summary['baseline_phase']['summary_path']}` |"
    )
    lines.append(
        f"| Tamper | {summary['tamper_phase']['returncode']} | {summary['tamper_phase']['overall_status']} | `{summary['tamper_phase']['summary_path']}` |"
    )
    lines.append(
        f"| Restore | {summary['restore_phase']['returncode']} | {summary['restore_phase']['overall_status']} | `{summary['restore_phase']['summary_path']}` |"
    )
    lines.append("")
    lines.append("## Expected Outcome")
    lines.append("")
    lines.append("- Baseline must be `PASS`.")
    lines.append("- Tampered verification must be `FAIL`.")
    lines.append("- Restored verification must return to `PASS`.")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run tamper simulation against immutable audit index, prove FAIL, restore, and prove PASS."
    )
    parser.add_argument(
        "--label",
        default=dt.datetime.now(dt.timezone.utc).strftime("N3_tamper_simulation_%Y%m%dT%H%M%SZ"),
        help="Scenario output label.",
    )
    args = parser.parse_args()

    label = args.label.strip()
    if not label:
        raise SystemExit("Label must not be empty.")

    require_file(INDEX_PATH)
    verifier_script = ROOT / "scripts" / "verify_immutable_audit_chain.py"
    require_file(verifier_script)

    output_dir = OUTPUT_ROOT / label
    output_dir.mkdir(parents=True, exist_ok=True)

    backup_path = output_dir / "immutable_audit_index.backup.jsonl"
    shutil.copy2(INDEX_PATH, backup_path)

    original_lines = load_index_lines()

    baseline_label = f"{label}_baseline"
    tamper_label = f"{label}_tampered"
    restore_label = f"{label}_restored"

    baseline_run = run_verifier(baseline_label)
    baseline_status = None
    if baseline_run["summary"]:
        baseline_status = str(baseline_run["summary"].get("overall_status", "")).upper()

    tampered_lines, tamper_meta = tamper_last_entry_record_sha(original_lines)
    save_index_lines(tampered_lines)

    tamper_run = run_verifier(tamper_label)
    tamper_status = None
    if tamper_run["summary"]:
        tamper_status = str(tamper_run["summary"].get("overall_status", "")).upper()

    restore_file(backup_path, INDEX_PATH)

    restore_run = run_verifier(restore_label)
    restore_status = None
    if restore_run["summary"]:
        restore_status = str(restore_run["summary"].get("overall_status", "")).upper()

    proof_passed = (
        baseline_status == "PASS"
        and tamper_status == "FAIL"
        and restore_status == "PASS"
    )

    summary = {
        "generated_at_utc": now_utc(),
        "scenario_label": label,
        "index_path": rel(INDEX_PATH),
        "backup_path": rel(backup_path),
        "tamper_operation": tamper_meta,
        "baseline_phase": {
            "label": baseline_label,
            "returncode": baseline_run["returncode"],
            "overall_status": baseline_status,
            "summary_path": baseline_run["summary_path"],
            "stdout_sha256": sha256_bytes((baseline_run["stdout"] or "").encode("utf-8")),
            "stderr_sha256": sha256_bytes((baseline_run["stderr"] or "").encode("utf-8")),
        },
        "tamper_phase": {
            "label": tamper_label,
            "returncode": tamper_run["returncode"],
            "overall_status": tamper_status,
            "summary_path": tamper_run["summary_path"],
            "stdout_sha256": sha256_bytes((tamper_run["stdout"] or "").encode("utf-8")),
            "stderr_sha256": sha256_bytes((tamper_run["stderr"] or "").encode("utf-8")),
        },
        "restore_phase": {
            "label": restore_label,
            "returncode": restore_run["returncode"],
            "overall_status": restore_status,
            "summary_path": restore_run["summary_path"],
            "stdout_sha256": sha256_bytes((restore_run["stdout"] or "").encode("utf-8")),
            "stderr_sha256": sha256_bytes((restore_run["stderr"] or "").encode("utf-8")),
        },
        "proof_passed": proof_passed,
        "proof_status": "PASS" if proof_passed else "FAIL",
        "contract_rule": "previous_entry_sha256 must equal previous entry's entry_sha256",
    }

    summary_path = output_dir / "tamper_simulation_summary.json"
    report_path = output_dir / "tamper_simulation_report.md"
    write_json(summary_path, summary)
    write_text(report_path, build_markdown_report(summary))

    negative_proof = {
        "proof_stage": "Phase N.3",
        "generated_at_utc": now_utc(),
        "proof_passed": proof_passed,
        "expected_failure_observed": tamper_status == "FAIL",
        "restore_pass_observed": restore_status == "PASS",
        "negative_proof_ok": proof_passed,
        "scenario_label": label,
        "summary_path": rel(summary_path),
        "report_path": rel(report_path),
        "backup_sha256": sha256_file(backup_path),
        "restored_index_sha256": sha256_file(INDEX_PATH),
        "tamper_operation": tamper_meta,
    }
    negative_proof_path = output_dir / "tamper_negative_proof.json"
    write_json(negative_proof_path, negative_proof)

    print("=" * 72)
    print("TAMPER SIMULATION + NEGATIVE VERIFICATION PROOF")
    print("=" * 72)
    print(f"LABEL           : {label}")
    print(f"INDEX PATH      : {rel(INDEX_PATH)}")
    print(f"BACKUP PATH     : {rel(backup_path)}")
    print(f"BASELINE STATUS : {baseline_status}")
    print(f"TAMPER STATUS   : {tamper_status}")
    print(f"RESTORE STATUS  : {restore_status}")
    print(f"PROOF STATUS    : {'PASS' if proof_passed else 'FAIL'}")
    print("-" * 72)
    print(f"SUMMARY JSON    : {rel(summary_path)}")
    print(f"REPORT MD       : {rel(report_path)}")
    print(f"NEGATIVE PROOF  : {rel(negative_proof_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
