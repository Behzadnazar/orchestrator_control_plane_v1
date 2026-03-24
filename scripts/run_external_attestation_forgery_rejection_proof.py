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
EXTERNAL_SIGNED_ROOT = OPERATIONS_ROOT / "external_signed_runtime"
EXTERNAL_VERIFY_ROOT = OPERATIONS_ROOT / "external_attestation_verification"
OUTPUT_ROOT = OPERATIONS_ROOT / "external_attestation_forgery_proof"
KEY_ROOT = ROOT / "artifacts" / "keys" / "attestation"


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


def mutate_b64_string(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Expected non-empty base64 string to mutate.")
    first = value[0]
    replacement = "A" if first != "A" else "B"
    return replacement + value[1:]


def build_markdown_report(summary: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Forgery Rejection Proof for External-Key Attestation")
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
    lines.append("## Forgery Tamper")
    lines.append("")
    lines.append(f"- Tamper type: `{summary['tamper_phase']['tamper_type']}`")
    lines.append(f"- Target file: `{summary['tamper_phase']['target_file']}`")
    lines.append(f"- Field: `{summary['tamper_phase']['field']}`")
    lines.append(f"- Verification status: **{summary['tamper_phase']['verification_status']}**")
    lines.append("")
    lines.append("## Wrong Public Key Check")
    lines.append("")
    lines.append(f"- Status: **{summary['wrong_key_phase']['verification_status']}**")
    lines.append(f"- Return code: `{summary['wrong_key_phase']['returncode']}`")
    lines.append("")
    lines.append("## Restore Verification")
    lines.append("")
    lines.append(f"- Status: **{summary['restore_phase']['verification_status']}**")
    lines.append(f"- Return code: `{summary['restore_phase']['returncode']}`")
    lines.append("")
    lines.append("## Final Declaration")
    lines.append("")
    if summary["proof_status"] == "PASS":
        lines.append("Baseline external attestation verification passed, forged/tampered attestation was rejected, wrong-public-key verification was rejected, and restored verification returned to PASS.")
    else:
        lines.append("Forgery rejection proof failed because one or more expected rejection/restore outcomes did not occur.")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run forgery rejection proof for external-key signed attestation."
    )
    parser.add_argument("--label", default="R4_external_attestation_forgery_rejection_proof")
    parser.add_argument(
        "--runtime-label",
        default="R3_trust_separation_external_key_proof__runtime",
        help="Existing external signed runtime label to tamper and verify.",
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

    signed_dir = EXTERNAL_SIGNED_ROOT / runtime_label
    if not signed_dir.exists():
        raise SystemExit(f"External signed runtime directory not found: {signed_dir}")

    attestation_path = require_file(signed_dir / "external_signed_execution_attestation.json")
    receipt_path = require_file(signed_dir / "external_signed_execution_receipt.json")
    report_path = require_file(signed_dir / "external_signed_runtime_report.json")
    manifest_path = require_file(signed_dir / "normalized_request_manifest.json")

    public_key_path = require_file(KEY_ROOT / "attestation_public.pem")
    wrong_private_path = output_dir / "wrong_attestation_private.pem"
    wrong_public_path = output_dir / "wrong_attestation_public.pem"

    attestation_backup = output_dir / "external_signed_execution_attestation.backup.json"
    receipt_backup = output_dir / "external_signed_execution_receipt.backup.json"
    report_backup = output_dir / "external_signed_runtime_report.backup.json"
    manifest_backup = output_dir / "normalized_request_manifest.backup.json"
    public_key_backup = output_dir / "attestation_public.backup.pem"

    shutil.copy2(attestation_path, attestation_backup)
    shutil.copy2(receipt_path, receipt_backup)
    shutil.copy2(report_path, report_backup)
    shutil.copy2(manifest_path, manifest_backup)
    shutil.copy2(public_key_path, public_key_backup)

    gen_wrong_key = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(wrong_private_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if gen_wrong_key.returncode != 0:
        raise SystemExit(gen_wrong_key.stderr.strip() or "Failed to generate wrong private key.")

    gen_wrong_pub = subprocess.run(
        ["openssl", "pkey", "-in", str(wrong_private_path), "-pubout", "-out", str(wrong_public_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if gen_wrong_pub.returncode != 0:
        raise SystemExit(gen_wrong_pub.stderr.strip() or "Failed to generate wrong public key.")

    baseline_label = f"{label}__baseline"
    tampered_label = f"{label}__tampered"
    wrong_key_label = f"{label}__wrong_key"
    restored_label = f"{label}__restored"

    baseline_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_external_signed_attestation.py"),
            "--runtime-label",
            runtime_label,
            "--label",
            baseline_label,
        ]
    )
    baseline_verify_path = require_file(
        EXTERNAL_VERIFY_ROOT / baseline_label / "external_signed_attestation_verification.json"
    )
    baseline_verify = read_json(baseline_verify_path)
    baseline_status = str(baseline_verify.get("verification_status", "")).upper()

    attestation = read_json(attestation_path)
    original_signature_b64 = str(attestation.get("signature_b64", "")).strip()
    if not original_signature_b64:
        raise SystemExit("Attestation does not contain signature_b64 to tamper.")

    attestation["signature_b64"] = mutate_b64_string(original_signature_b64)
    write_json(attestation_path, attestation)

    tampered_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_external_signed_attestation.py"),
            "--runtime-label",
            runtime_label,
            "--label",
            tampered_label,
        ]
    )
    tampered_verify_path = require_file(
        EXTERNAL_VERIFY_ROOT / tampered_label / "external_signed_attestation_verification.json"
    )
    tampered_verify = read_json(tampered_verify_path)
    tampered_status = str(tampered_verify.get("verification_status", "")).upper()

    shutil.copy2(attestation_backup, attestation_path)
    shutil.copy2(wrong_public_path, public_key_path)

    wrong_key_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_external_signed_attestation.py"),
            "--runtime-label",
            runtime_label,
            "--label",
            wrong_key_label,
        ]
    )
    wrong_key_verify_path = require_file(
        EXTERNAL_VERIFY_ROOT / wrong_key_label / "external_signed_attestation_verification.json"
    )
    wrong_key_verify = read_json(wrong_key_verify_path)
    wrong_key_status = str(wrong_key_verify.get("verification_status", "")).upper()

    shutil.copy2(public_key_backup, public_key_path)
    shutil.copy2(attestation_backup, attestation_path)
    shutil.copy2(receipt_backup, receipt_path)
    shutil.copy2(report_backup, report_path)
    shutil.copy2(manifest_backup, manifest_path)

    restored_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_external_signed_attestation.py"),
            "--runtime-label",
            runtime_label,
            "--label",
            restored_label,
        ]
    )
    restored_verify_path = require_file(
        EXTERNAL_VERIFY_ROOT / restored_label / "external_signed_attestation_verification.json"
    )
    restored_verify = read_json(restored_verify_path)
    restored_status = str(restored_verify.get("verification_status", "")).upper()

    proof_passed = (
        baseline_run["returncode"] == 0
        and baseline_status == "PASS"
        and baseline_verify.get("checks", {}).get("signature_valid") is True
        and tampered_run["returncode"] != 0
        and tampered_status == "FAIL"
        and tampered_verify.get("checks", {}).get("signature_valid") is False
        and wrong_key_run["returncode"] != 0
        and wrong_key_status == "FAIL"
        and wrong_key_verify.get("checks", {}).get("signature_valid") is False
        and restored_run["returncode"] == 0
        and restored_status == "PASS"
        and restored_verify.get("checks", {}).get("signature_valid") is True
    )

    summary = {
        "report_version": 1,
        "report_type": "external_attestation_forgery_rejection_proof",
        "generated_at_utc": now_utc(),
        "proof_label": label,
        "runtime_label": runtime_label,
        "proof_status": "PASS" if proof_passed else "FAIL",
        "baseline_phase": {
            "label": baseline_label,
            "returncode": baseline_run["returncode"],
            "verification_status": baseline_status,
            "verification_path": rel(baseline_verify_path),
            "signature_valid": baseline_verify.get("checks", {}).get("signature_valid"),
        },
        "tamper_phase": {
            "label": tampered_label,
            "returncode": tampered_run["returncode"],
            "verification_status": tampered_status,
            "verification_path": rel(tampered_verify_path),
            "tamper_type": "signature_b64_forgery",
            "target_file": rel(attestation_path),
            "field": "signature_b64",
            "original_signature_sha256": sha256_bytes(original_signature_b64.encode("utf-8")),
            "tampered_signature_sha256": sha256_bytes(str(attestation.get("signature_b64", "")).encode("utf-8")),
            "signature_valid": tampered_verify.get("checks", {}).get("signature_valid"),
        },
        "wrong_key_phase": {
            "label": wrong_key_label,
            "returncode": wrong_key_run["returncode"],
            "verification_status": wrong_key_status,
            "verification_path": rel(wrong_key_verify_path),
            "tamper_type": "wrong_public_key_verification",
            "target_file": rel(public_key_path),
            "replacement_public_key": rel(wrong_public_path),
            "signature_valid": wrong_key_verify.get("checks", {}).get("signature_valid"),
        },
        "restore_phase": {
            "label": restored_label,
            "returncode": restored_run["returncode"],
            "verification_status": restored_status,
            "verification_path": rel(restored_verify_path),
            "signature_valid": restored_verify.get("checks", {}).get("signature_valid"),
        },
        "backup_artifacts": {
            "attestation_backup": rel(attestation_backup),
            "receipt_backup": rel(receipt_backup),
            "report_backup": rel(report_backup),
            "manifest_backup": rel(manifest_backup),
            "public_key_backup": rel(public_key_backup),
            "wrong_public_key": rel(wrong_public_path),
        },
    }

    summary_path = output_dir / "external_attestation_forgery_rejection_proof.json"
    report_md_path = output_dir / "external_attestation_forgery_rejection_proof.md"
    digest_path = output_dir / "external_attestation_forgery_rejection_proof_digest.json"

    write_json(summary_path, summary)
    write_text(report_md_path, build_markdown_report(summary, output_dir))
    write_json(
        digest_path,
        {
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
                {
                    "path": rel(public_key_backup),
                    "size_bytes": public_key_backup.stat().st_size,
                    "sha256": sha256_file(public_key_backup),
                },
            ],
        },
    )

    print("=" * 72)
    print("FORGERY REJECTION PROOF FOR EXTERNAL-KEY ATTESTATION")
    print("=" * 72)
    print(f"LABEL           : {label}")
    print(f"RUNTIME LABEL   : {runtime_label}")
    print(f"BASELINE STATUS : {baseline_status}")
    print(f"TAMPER STATUS   : {tampered_status}")
    print(f"WRONG KEY STATUS: {wrong_key_status}")
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
