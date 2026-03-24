#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
OUTPUT_ROOT = OPERATIONS_ROOT / "security_boundary_proof"


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


def rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def run_python(cmd: list[str]) -> dict:
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_sha256": sha256_bytes((proc.stdout or "").encode("utf-8")),
        "stderr_sha256": sha256_bytes((proc.stderr or "").encode("utf-8")),
    }


def build_markdown_report(summary: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Security Boundary Hardening + Signed Execution Attestation Proof")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Proof label: `{summary['proof_label']}`")
    lines.append(f"- Proof status: **{summary['proof_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Signed Runtime Path")
    lines.append("")
    lines.append(f"- Runtime label: `{summary['signed_runtime']['runtime_label']}`")
    lines.append(f"- Gate decision: **{summary['signed_runtime']['gate_decision']}**")
    lines.append(f"- Runtime status: **{summary['signed_runtime']['runtime_status']}**")
    lines.append(f"- Payload marker exists: **{summary['signed_runtime']['payload_marker_exists']}**")
    lines.append("")
    lines.append("## Attestation Verification")
    lines.append("")
    lines.append(f"- Verification status: **{summary['attestation_verification']['verification_status']}**")
    lines.append(f"- Signature matches: **{summary['attestation_verification']['signature_matches']}**")
    lines.append(f"- Receipt hash matches: **{summary['attestation_verification']['receipt_hash_matches']}**")
    lines.append(f"- Gate decision hash matches: **{summary['attestation_verification']['gate_decision_hash_matches']}**")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run signed execution entry and verify its local execution attestation."
    )
    parser.add_argument("--label", default="R1_signed_execution_attestation_proof")
    args = parser.parse_args()

    label = args.label.strip()
    if not label:
        raise SystemExit("label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=False)

    runtime_label = f"{label}__runtime"
    workflow_id = f"{label}__workflow"
    marker_path = output_dir / "signed_execution.marker"
    manifest_path = output_dir / "signed_request_manifest.json"

    command = (
        "python3 -c \"import os, sys; from pathlib import Path; "
        f"p = Path(r'{marker_path}'); "
        "flag = os.environ.get('CONTROL_PLANE_SIGNED_EXECUTION'); "
        "wf = os.environ.get('CONTROL_PLANE_WORKFLOW_ID'); "
        f"expected = r'{workflow_id}'; "
        "ok = (flag == '1' and wf == expected); "
        "sys.exit(11) if not ok else p.write_text('SIGNED_EXECUTION_OK', encoding='utf-8')\""
    )

    manifest = {
        "operation": "release",
        "workflow_id": workflow_id,
        "readiness_label": "Q1_operational_readiness",
        "chain_label": "Q1_post_readiness_chain_check",
        "milestone": "O3_independent_freeze",
        "release_candidate": "RC3",
        "require_rc": True,
        "command": command,
    }
    write_json(manifest_path, manifest)

    signed_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "signed_execution_entry.py"),
            "--label",
            runtime_label,
            "--request-manifest",
            str(manifest_path),
        ]
    )

    verification_label = f"{label}__verification"
    verify_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_signed_execution_attestation.py"),
            "--runtime-label",
            runtime_label,
            "--label",
            verification_label,
        ]
    )

    signed_dir = ROOT / "artifacts" / "operations" / "signed_runtime" / runtime_label
    report_path = signed_dir / "signed_runtime_report.json"
    receipt_path = signed_dir / "signed_execution_receipt.json"
    attestation_path = signed_dir / "signed_execution_attestation.json"
    verify_path = ROOT / "artifacts" / "operations" / "attestation_verification" / verification_label / "signed_execution_attestation_verification.json"

    report = read_json(report_path)
    receipt = read_json(receipt_path)
    attestation = read_json(attestation_path)
    verification = read_json(verify_path)

    payload_marker_exists = marker_path.exists()

    proof_passed = (
        signed_run["returncode"] == 0
        and verify_run["returncode"] == 0
        and str(report.get("gate_decision", "")).upper() == "ALLOW"
        and str(report.get("runtime_status", "")).upper() == "ALLOW_EXECUTED"
        and receipt.get("command_executed") is True
        and payload_marker_exists
        and str(verification.get("verification_status", "")).upper() == "PASS"
        and verification.get("checks", {}).get("signature_matches") is True
        and verification.get("checks", {}).get("receipt_hash_matches") is True
        and verification.get("checks", {}).get("gate_decision_hash_matches") is True
    )

    summary = {
        "report_version": 1,
        "report_type": "security_boundary_hardening_signed_execution_attestation_proof",
        "generated_at_utc": now_utc(),
        "proof_label": label,
        "proof_status": "PASS" if proof_passed else "FAIL",
        "signed_runtime": {
            "runtime_label": runtime_label,
            "manifest_path": rel(manifest_path),
            "run_returncode": signed_run["returncode"],
            "gate_decision": report.get("gate_decision"),
            "runtime_status": report.get("runtime_status"),
            "report_path": rel(report_path),
            "receipt_path": rel(receipt_path),
            "attestation_path": rel(attestation_path),
            "payload_marker_exists": payload_marker_exists,
            "payload_marker_path": rel(marker_path),
        },
        "attestation_verification": {
            "verification_label": verification_label,
            "run_returncode": verify_run["returncode"],
            "verification_status": verification.get("verification_status"),
            "verification_path": rel(verify_path),
            "signature_matches": verification.get("checks", {}).get("signature_matches"),
            "receipt_hash_matches": verification.get("checks", {}).get("receipt_hash_matches"),
            "gate_decision_hash_matches": verification.get("checks", {}).get("gate_decision_hash_matches"),
            "attestation_key_hash_matches": verification.get("checks", {}).get("attestation_key_hash_matches"),
        },
    }

    summary_path = output_dir / "signed_execution_attestation_proof.json"
    report_md_path = output_dir / "signed_execution_attestation_proof.md"
    digest_path = output_dir / "signed_execution_attestation_proof_digest.json"

    write_json(summary_path, summary)
    write_text(report_md_path, build_markdown_report(summary, output_dir))

    digest = {
        "generated_at_utc": summary["generated_at_utc"],
        "label": label,
        "proof_status": summary["proof_status"],
        "artifacts": [
            {
                "path": rel(summary_path),
                "size_bytes": summary_path.stat().st_size,
                "sha256": sha256_file(summary_path),
            },
            {
                "path": rel(report_md_path),
                "size_bytes": report_md_path.stat().st_size,
                "sha256": sha256_file(report_md_path),
            },
            {
                "path": rel(manifest_path),
                "size_bytes": manifest_path.stat().st_size,
                "sha256": sha256_file(manifest_path),
            },
        ],
    }
    write_json(digest_path, digest)

    print("=" * 72)
    print("SECURITY BOUNDARY HARDENING + SIGNED EXECUTION ATTESTATION PROOF")
    print("=" * 72)
    print(f"LABEL              : {label}")
    print(f"PROOF STATUS       : {summary['proof_status']}")
    print(f"SIGNED RUNTIME     : {runtime_label}")
    print(f"ATTESTATION VERIFY : {verification_label}")
    print(f"SUMMARY JSON       : {rel(summary_path)}")
    print(f"REPORT MD          : {rel(report_md_path)}")
    print(f"DIGEST             : {rel(digest_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
