#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
KEY_ROOT = ROOT / "artifacts" / "keys" / "attestation"
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
OUTPUT_ROOT = OPERATIONS_ROOT / "key_rotation_revocation_proof"


def now_utc():
    import datetime as dt
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
    import hashlib
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_file(path: Path) -> str:
    import hashlib
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


def run_cmd(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or f"Command failed: {' '.join(cmd)}")


def build_registry(active_pub: Path, revoked_pub: Path, registry_path: Path) -> None:
    registry = {
        "registry_version": 1,
        "registry_type": "attestation_key_registry",
        "generated_at_utc": now_utc(),
        "keys": [
            {
                "key_id": "attestation-key-v1-revoked",
                "public_key_path": rel(revoked_pub),
                "public_key_sha256": sha256_file(revoked_pub),
                "status": "revoked",
                "revoked": True,
            },
            {
                "key_id": "attestation-key-v2-active",
                "public_key_path": rel(active_pub),
                "public_key_sha256": sha256_file(active_pub),
                "status": "active",
                "revoked": False,
            },
        ],
    }
    write_json(registry_path, registry)


def build_markdown_report(summary: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Key Rotation + Revocation Proof")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Proof label: `{summary['proof_label']}`")
    lines.append(f"- Proof status: **{summary['proof_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Rotation")
    lines.append("")
    lines.append(f"- Old runtime revoked verification status: **{summary['revoked_old_runtime']['verification_status']}**")
    lines.append(f"- New runtime active verification status: **{summary['rotated_new_runtime']['verification_status']}**")
    lines.append("")
    lines.append("## Registry")
    lines.append("")
    lines.append(f"- Registry path: `{summary['registry']['registry_path']}`")
    lines.append(f"- Revoked key path: `{summary['registry']['revoked_key_path']}`")
    lines.append(f"- Active key path: `{summary['registry']['active_key_path']}`")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run key rotation and revocation proof for external-key attestation.")
    parser.add_argument("--label", default="R5_key_rotation_revocation_proof")
    parser.add_argument("--old-runtime-label", default="R3_trust_separation_external_key_proof__runtime")
    args = parser.parse_args()

    label = args.label.strip()
    old_runtime_label = args.old_runtime_label.strip()

    if not label:
        raise SystemExit("label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=False)

    old_private = require_file(KEY_ROOT / "attestation_private.pem")
    old_public = require_file(KEY_ROOT / "attestation_public.pem")

    rotated_private = output_dir / "attestation_private_v2.pem"
    rotated_public = output_dir / "attestation_public_v2.pem"
    registry_path = output_dir / "attestation_key_registry.json"
    manifest_path = output_dir / "rotated_external_key_request_manifest.json"
    marker_path = output_dir / "rotated_external_key.marker"

    run_cmd(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(rotated_private)])
    run_cmd(["openssl", "pkey", "-in", str(rotated_private), "-pubout", "-out", str(rotated_public)])

    build_registry(active_pub=rotated_public, revoked_pub=old_public, registry_path=registry_path)

    baseline_old_label = f"{label}__old_revoked_check"
    old_verify_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_external_signed_attestation_with_registry.py"),
            "--runtime-label",
            old_runtime_label,
            "--registry-path",
            str(registry_path),
            "--label",
            baseline_old_label,
        ]
    )
    old_verify_path = require_file(
        ROOT / "artifacts" / "operations" / "external_attestation_registry_verification" / baseline_old_label / "external_signed_attestation_registry_verification.json"
    )
    old_verify = read_json(old_verify_path)
    old_status = str(old_verify.get("verification_status", "")).upper()

    new_runtime_label = f"{label}__runtime"
    verify_new_label = f"{label}__new_active_check"
    workflow_id = f"{label}__workflow"

    command = (
        "python3 -c \"import os, sys; from pathlib import Path; "
        f"p = Path(r'{marker_path}'); "
        "flag = os.environ.get('CONTROL_PLANE_TRUST_SEPARATED_SIGNING'); "
        "pub = os.environ.get('CONTROL_PLANE_PUBLIC_KEY_PATH'); "
        f"expected_pub = r'{rotated_public}'; "
        "wf = os.environ.get('CONTROL_PLANE_WORKFLOW_ID'); "
        f"expected_wf = r'{workflow_id}'; "
        "ok = (flag == '1' and pub == expected_pub and wf == expected_wf); "
        "sys.exit(17) if not ok else p.write_text('ROTATED_KEY_EXECUTION_OK', encoding='utf-8')\""
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
        "private_key_path": str(rotated_private),
        "public_key_path": str(rotated_public),
    }
    write_json(manifest_path, manifest)

    new_runtime_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "signed_execution_entry_external_key.py"),
            "--label",
            new_runtime_label,
            "--request-manifest",
            str(manifest_path),
        ]
    )

    new_verify_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_external_signed_attestation_with_registry.py"),
            "--runtime-label",
            new_runtime_label,
            "--registry-path",
            str(registry_path),
            "--label",
            verify_new_label,
        ]
    )

    new_verify_path = require_file(
        ROOT / "artifacts" / "operations" / "external_attestation_registry_verification" / verify_new_label / "external_signed_attestation_registry_verification.json"
    )
    new_verify = read_json(new_verify_path)
    new_status = str(new_verify.get("verification_status", "")).upper()

    proof_passed = (
        old_verify_run["returncode"] != 0
        and old_status == "FAIL"
        and old_verify.get("checks", {}).get("registry_key_active") is False
        and old_verify.get("checks", {}).get("registry_key_not_revoked") is False
        and new_runtime_run["returncode"] == 0
        and new_verify_run["returncode"] == 0
        and new_status == "PASS"
        and new_verify.get("checks", {}).get("registry_key_active") is True
        and new_verify.get("checks", {}).get("registry_key_not_revoked") is True
        and marker_path.exists()
    )

    summary = {
        "report_version": 1,
        "report_type": "key_rotation_revocation_proof",
        "generated_at_utc": now_utc(),
        "proof_label": label,
        "proof_status": "PASS" if proof_passed else "FAIL",
        "registry": {
            "registry_path": rel(registry_path),
            "revoked_key_path": rel(old_public),
            "active_key_path": rel(rotated_public),
            "revoked_key_sha256": sha256_file(old_public),
            "active_key_sha256": sha256_file(rotated_public),
        },
        "revoked_old_runtime": {
            "runtime_label": old_runtime_label,
            "verification_label": baseline_old_label,
            "returncode": old_verify_run["returncode"],
            "verification_status": old_status,
            "verification_path": rel(old_verify_path),
            "registry_key_active": old_verify.get("checks", {}).get("registry_key_active"),
            "registry_key_not_revoked": old_verify.get("checks", {}).get("registry_key_not_revoked"),
            "signature_valid": old_verify.get("checks", {}).get("signature_valid"),
        },
        "rotated_new_runtime": {
            "runtime_label": new_runtime_label,
            "verification_label": verify_new_label,
            "runtime_returncode": new_runtime_run["returncode"],
            "verification_returncode": new_verify_run["returncode"],
            "verification_status": new_status,
            "verification_path": rel(new_verify_path),
            "registry_key_active": new_verify.get("checks", {}).get("registry_key_active"),
            "registry_key_not_revoked": new_verify.get("checks", {}).get("registry_key_not_revoked"),
            "signature_valid": new_verify.get("checks", {}).get("signature_valid"),
            "marker_exists": marker_path.exists(),
            "marker_path": rel(marker_path),
            "manifest_path": rel(manifest_path),
        },
    }

    summary_path = output_dir / "key_rotation_revocation_proof.json"
    report_md_path = output_dir / "key_rotation_revocation_proof.md"
    digest_path = output_dir / "key_rotation_revocation_proof_digest.json"

    write_json(summary_path, summary)
    write_text(report_md_path, build_markdown_report(summary, output_dir))
    write_json(digest_path, {
        "generated_at_utc": summary["generated_at_utc"],
        "label": label,
        "proof_status": summary["proof_status"],
        "artifacts": [
            {"path": rel(summary_path), "size_bytes": summary_path.stat().st_size, "sha256": sha256_file(summary_path)},
            {"path": rel(report_md_path), "size_bytes": report_md_path.stat().st_size, "sha256": sha256_file(report_md_path)},
            {"path": rel(registry_path), "size_bytes": registry_path.stat().st_size, "sha256": sha256_file(registry_path)},
            {"path": rel(rotated_public), "size_bytes": rotated_public.stat().st_size, "sha256": sha256_file(rotated_public)},
        ],
    })

    print("=" * 72)
    print("KEY ROTATION + REVOCATION PROOF")
    print("=" * 72)
    print(f"LABEL            : {label}")
    print(f"PROOF STATUS     : {summary['proof_status']}")
    print(f"OLD RUNTIME      : {old_runtime_label} -> {old_status}")
    print(f"NEW RUNTIME      : {new_runtime_label} -> {new_status}")
    print(f"REGISTRY         : {rel(registry_path)}")
    print(f"SUMMARY JSON     : {rel(summary_path)}")
    print(f"REPORT MD        : {rel(report_md_path)}")
    print(f"DIGEST           : {rel(digest_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
