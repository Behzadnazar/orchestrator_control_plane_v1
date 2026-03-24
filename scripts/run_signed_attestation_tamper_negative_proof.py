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
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
SIGNED_RUNTIME_ROOT = OPERATIONS_ROOT / "signed_runtime"
ATTEST_VERIFY_ROOT = OPERATIONS_ROOT / "attestation_verification"
OUTPUT_ROOT = OPERATIONS_ROOT / "signed_attestation_tamper_proof"


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


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


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


def mutate_hex_string(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Expected non-empty string to mutate.")
    first = value[0].lower()
    replacement = "0" if first != "0" else "1"
    return replacement + value[1:]


def build_markdown_report(summary: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Tamper Negative Proof for Signed Attestation")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Proof label: `{summary['proof_label']}`")
    lines.append(f"- Runtime label: `{summary['runtime_label']}`")
    lines.append(f"- Proof status: **{summary['proof_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Baseline Verification")
    lines.append("")
    lines.append(f"- Status: **{summary['baseline_phase']['verification_status']}**")
    lines.append(f"- Return code: `{summary['baseline_phase']['returncode']}`")
    lines.append(f"- Verification path: `{summary['baseline_phase']['verification_path']}`")
    lines.append("")
    lines.append("## Tamper Operation")
    lines.append("")
    lines.append(f"- Tamper type: `{summary['tamper_phase']['tamper_type']}`")
    lines.append(f"- Target file: `{summary['tamper_phase']['target_file']}`")
    lines.append(f"- Field: `{summary['tamper_phase']['field']}`")
    lines.append("")
    lines.append("## Tampered Verification")
    lines.append("")
    lines.append(f"- Status: **{summary['tamper_phase']['verification_status']}**")
    lines.append(f"- Return code: `{summary['tamper_phase']['returncode']}`")
    lines.append(f"- Verification path: `{summary['tamper_phase']['verification_path']}`")
    lines.append("")
    lines.append("## Restore Verification")
    lines.append("")
    lines.append(f"- Status: **{summary['restore_phase']['verification_status']}**")
    lines.append(f"- Return code: `{summary['restore_phase']['returncode']}`")
    lines.append(f"- Verification path: `{summary['restore_phase']['verification_path']}`")
    lines.append("")
    lines.append("## Final Declaration")
    lines.append("")
    if summary["proof_status"] == "PASS":
        lines.append("Baseline attestation verification passed, tampered attestation verification failed as expected, and restored verification returned to PASS.")
    else:
        lines.append("The signed-attestation tamper proof failed because baseline, tampered, or restored verification did not match the expected outcomes.")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run tamper negative proof for local signed execution attestation."
    )
    parser.add_argument("--label", default="R2_signed_attestation_tamper_proof")
    parser.add_argument(
        "--runtime-label",
        default="R1_signed_execution_attestation_proof__runtime",
        help="Existing signed runtime label to tamper and verify.",
    )
    args = parser.parse_args()

    label = args.label.strip()
    runtime_label = args.runtime_label.strip()

    if not label:
        raise SystemExit("label must not be empty.")
    if not runtime_label:
        raise SystemExit("runtime-label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=False)

    signed_dir = SIGNED_RUNTIME_ROOT / runtime_label
    if not signed_dir.exists():
        raise SystemExit(f"Signed runtime directory not found: {signed_dir}")

    attestation_path = require_file(signed_dir / "signed_execution_attestation.json")
    receipt_path = require_file(signed_dir / "signed_execution_receipt.json")
    report_path = require_file(signed_dir / "signed_runtime_report.json")
    manifest_path = require_file(signed_dir / "normalized_request_manifest.json")

    attestation_backup = output_dir / "signed_execution_attestation.backup.json"
    receipt_backup = output_dir / "signed_execution_receipt.backup.json"
    report_backup = output_dir / "signed_runtime_report.backup.json"
    manifest_backup = output_dir / "normalized_request_manifest.backup.json"

    shutil.copy2(attestation_path, attestation_backup)
    shutil.copy2(receipt_path, receipt_backup)
    shutil.copy2(report_path, report_backup)
    shutil.copy2(manifest_path, manifest_backup)

    baseline_label = f"{label}__baseline"
    tampered_label = f"{label}__tampered"
    restored_label = f"{label}__restored"

    baseline_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_signed_execution_attestation.py"),
            "--runtime-label",
            runtime_label,
            "--label",
            baseline_label,
        ]
    )

    baseline_verify_path = require_file(
        ATTEST_VERIFY_ROOT / baseline_label / "signed_execution_attestation_verification.json"
    )
    baseline_verify = read_json(baseline_verify_path)
    baseline_status = str(baseline_verify.get("verification_status", "")).upper()

    attestation = read_json(attestation_path)
    original_signature = str(attestation.get("signature", "")).strip()
    if not original_signature:
        raise SystemExit("Attestation does not contain a signature field to tamper.")

    attestation["signature"] = mutate_hex_string(original_signature)
    write_json(attestation_path, attestation)

    tampered_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_signed_execution_attestation.py"),
            "--runtime-label",
            runtime_label,
            "--label",
            tampered_label,
        ]
    )

    tampered_verify_path = require_file(
        ATTEST_VERIFY_ROOT / tampered_label / "signed_execution_attestation_verification.json"
    )
    tampered_verify = read_json(tampered_verify_path)
    tampered_status = str(tampered_verify.get("verification_status", "")).upper()

    shutil.copy2(attestation_backup, attestation_path)
    shutil.copy2(receipt_backup, receipt_path)
    shutil.copy2(report_backup, report_path)
    shutil.copy2(manifest_backup, manifest_path)

    restored_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_signed_execution_attestation.py"),
            "--runtime-label",
            runtime_label,
            "--label",
            restored_label,
        ]
    )

    restored_verify_path = require_file(
        ATTEST_VERIFY_ROOT / restored_label / "signed_execution_attestation_verification.json"
    )
    restored_verify = read_json(restored_verify_path)
    restored_status = str(restored_verify.get("verification_status", "")).upper()

    proof_passed = (
        baseline_run["returncode"] == 0
        and baseline_status == "PASS"
        and tampered_run["returncode"] != 0
        and tampered_status == "FAIL"
        and restored_run["returncode"] == 0
        and restored_status == "PASS"
        and baseline_verify.get("checks", {}).get("signature_matches") is True
        and tampered_verify.get("checks", {}).get("signature_matches") is False
        and restored_verify.get("checks", {}).get("signature_matches") is True
    )

    summary = {
        "report_version": 1,
        "report_type": "signed_attestation_tamper_negative_proof",
        "generated_at_utc": now_utc(),
        "proof_label": label,
        "runtime_label": runtime_label,
        "proof_status": "PASS" if proof_passed else "FAIL",
        "baseline_phase": {
            "label": baseline_label,
            "returncode": baseline_run["returncode"],
            "verification_status": baseline_status,
            "verification_path": rel(baseline_verify_path),
            "signature_matches": baseline_verify.get("checks", {}).get("signature_matches"),
        },
        "tamper_phase": {
            "label": tampered_label,
            "returncode": tampered_run["returncode"],
            "verification_status": tampered_status,
            "verification_path": rel(tampered_verify_path),
            "tamper_type": "attestation_signature_mutation",
            "target_file": rel(attestation_path),
            "field": "signature",
            "original_signature_sha256": sha256_bytes(original_signature.encode("utf-8")),
            "tampered_signature_sha256": sha256_bytes(str(attestation.get("signature", "")).encode("utf-8")),
            "signature_matches": tampered_verify.get("checks", {}).get("signature_matches"),
        },
        "restore_phase": {
            "label": restored_label,
            "returncode": restored_run["returncode"],
            "verification_status": restored_status,
            "verification_path": rel(restored_verify_path),
            "signature_matches": restored_verify.get("checks", {}).get("signature_matches"),
        },
        "backup_artifacts": {
            "attestation_backup": rel(attestation_backup),
            "receipt_backup": rel(receipt_backup),
            "report_backup": rel(report_backup),
            "manifest_backup": rel(manifest_backup),
        },
    }

    summary_path = output_dir / "signed_attestation_tamper_negative_proof.json"
    report_md_path = output_dir / "signed_attestation_tamper_negative_proof.md"
    digest_path = output_dir / "signed_attestation_tamper_negative_proof_digest.json"

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
                "path": rel(attestation_backup),
                "size_bytes": attestation_backup.stat().st_size,
                "sha256": sha256_file(attestation_backup),
            },
        ],
    }
    write_json(digest_path, digest)

    print("=" * 72)
    print("TAMPER NEGATIVE PROOF FOR SIGNED ATTESTATION")
    print("=" * 72)
    print(f"LABEL           : {label}")
    print(f"RUNTIME LABEL   : {runtime_label}")
    print(f"BASELINE STATUS : {baseline_status}")
    print(f"TAMPER STATUS   : {tampered_status}")
    print(f"RESTORE STATUS  : {restored_status}")
    print(f"PROOF STATUS    : {summary['proof_status']}")
    print("-" * 72)
    print(f"SUMMARY JSON    : {rel(summary_path)}")
    print(f"REPORT MD       : {rel(report_md_path)}")
    print(f"DIGEST          : {rel(digest_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
