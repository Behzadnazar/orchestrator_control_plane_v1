#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
KEY_ROOT = ROOT / "artifacts" / "keys" / "attestation"
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
OUTPUT_ROOT = OPERATIONS_ROOT / "key_policy_validity_proof"


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


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


def run_cmd(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or f"Command failed: {' '.join(cmd)}")


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


def build_registry(active_pub: Path, expired_pub: Path, future_pub: Path, registry_path: Path, verification_time: datetime) -> None:
    registry = {
        "registry_version": 2,
        "registry_type": "attestation_key_policy_registry",
        "generated_at_utc": iso(now_utc()),
        "keys": [
            {
                "key_id": "attestation-key-policy-active",
                "public_key_path": rel(active_pub),
                "public_key_sha256": sha256_file(active_pub),
                "status": "active",
                "revoked": False,
                "usage": "attestation_signing",
                "not_before": iso(verification_time - timedelta(days=1)),
                "not_after": iso(verification_time + timedelta(days=30)),
            },
            {
                "key_id": "attestation-key-policy-expired",
                "public_key_path": rel(expired_pub),
                "public_key_sha256": sha256_file(expired_pub),
                "status": "active",
                "revoked": False,
                "usage": "attestation_signing",
                "not_before": iso(verification_time - timedelta(days=30)),
                "not_after": iso(verification_time - timedelta(seconds=1)),
            },
            {
                "key_id": "attestation-key-policy-future",
                "public_key_path": rel(future_pub),
                "public_key_sha256": sha256_file(future_pub),
                "status": "active",
                "revoked": False,
                "usage": "attestation_signing",
                "not_before": iso(verification_time + timedelta(seconds=1)),
                "not_after": iso(verification_time + timedelta(days=30)),
            },
        ],
    }
    write_json(registry_path, registry)


def build_markdown_report(summary: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Key Policy Enforcement + Expiry / Validity Window Proof")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Proof label: `{summary['proof_label']}`")
    lines.append(f"- Verification time (UTC): `{summary['verification_time_utc']}`")
    lines.append(f"- Proof status: **{summary['proof_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Policy Outcomes")
    lines.append("")
    lines.append(f"- Active runtime status: **{summary['active_runtime']['verification_status']}**")
    lines.append(f"- Expired runtime status: **{summary['expired_runtime']['verification_status']}**")
    lines.append(f"- Future runtime status: **{summary['future_runtime']['verification_status']}**")
    lines.append("")
    lines.append("## Window Verdicts")
    lines.append("")
    lines.append(f"- Active verdict: `{summary['active_runtime']['window_verdict']}`")
    lines.append(f"- Expired verdict: `{summary['expired_runtime']['window_verdict']}`")
    lines.append(f"- Future verdict: `{summary['future_runtime']['window_verdict']}`")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def make_runtime(output_dir: Path, runtime_label: str, workflow_id: str, private_key: Path, public_key: Path, marker_name: str) -> tuple[Path, Path]:
    manifest_path = output_dir / f"{runtime_label}.manifest.json"
    marker_path = output_dir / marker_name

    command = (
        "python3 -c \"import os, sys; from pathlib import Path; "
        f"p = Path(r'{marker_path}'); "
        "flag = os.environ.get('CONTROL_PLANE_TRUST_SEPARATED_SIGNING'); "
        "pub = os.environ.get('CONTROL_PLANE_PUBLIC_KEY_PATH'); "
        f"expected_pub = r'{public_key}'; "
        "wf = os.environ.get('CONTROL_PLANE_WORKFLOW_ID'); "
        f"expected_wf = r'{workflow_id}'; "
        "ok = (flag == '1' and pub == expected_pub and wf == expected_wf); "
        "sys.exit(19) if not ok else p.write_text('POLICY_KEY_EXECUTION_OK', encoding='utf-8')\""
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
        "private_key_path": str(private_key),
        "public_key_path": str(public_key),
    }
    write_json(manifest_path, manifest)

    run_cmd(
        [
            sys.executable,
            str(ROOT / "scripts" / "signed_execution_entry_external_key.py"),
            "--label",
            runtime_label,
            "--request-manifest",
            str(manifest_path),
        ]
    )
    return manifest_path, marker_path


def verify_runtime(runtime_label: str, registry_path: Path, verification_time: datetime, verify_label: str) -> tuple[dict, Path]:
    run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_external_signed_attestation_with_policy.py"),
            "--runtime-label",
            runtime_label,
            "--registry-path",
            str(registry_path),
            "--verification-time",
            iso(verification_time),
            "--label",
            verify_label,
        ]
    )
    verify_path = require_file(
        ROOT / "artifacts" / "operations" / "external_attestation_policy_verification" / verify_label / "external_signed_attestation_policy_verification.json"
    )
    verify = read_json(verify_path)
    verify["_returncode"] = run["returncode"]
    return verify, verify_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run key policy enforcement proof for active, expired, and premature validity windows.")
    parser.add_argument("--label", default="R6_key_policy_validity_window_proof")
    args = parser.parse_args()

    label = args.label.strip()
    if not label:
        raise SystemExit("label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=False)

    verification_time = now_utc()

    active_private = require_file(ROOT / "artifacts/operations/key_rotation_revocation_proof/R5_key_rotation_revocation_proof/attestation_private_v2.pem")
    active_public = require_file(ROOT / "artifacts/operations/key_rotation_revocation_proof/R5_key_rotation_revocation_proof/attestation_public_v2.pem")

    expired_private = output_dir / "attestation_private_expired.pem"
    expired_public = output_dir / "attestation_public_expired.pem"
    future_private = output_dir / "attestation_private_future.pem"
    future_public = output_dir / "attestation_public_future.pem"

    run_cmd(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(expired_private)])
    run_cmd(["openssl", "pkey", "-in", str(expired_private), "-pubout", "-out", str(expired_public)])
    run_cmd(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", str(future_private)])
    run_cmd(["openssl", "pkey", "-in", str(future_private), "-pubout", "-out", str(future_public)])

    registry_path = output_dir / "attestation_key_policy_registry.json"
    build_registry(
        active_pub=active_public,
        expired_pub=expired_public,
        future_pub=future_public,
        registry_path=registry_path,
        verification_time=verification_time,
    )

    active_runtime = f"{label}__active_runtime"
    expired_runtime = f"{label}__expired_runtime"
    future_runtime = f"{label}__future_runtime"

    make_runtime(output_dir, active_runtime, f"{label}__active_workflow", active_private, active_public, "active_runtime.marker")
    make_runtime(output_dir, expired_runtime, f"{label}__expired_workflow", expired_private, expired_public, "expired_runtime.marker")
    make_runtime(output_dir, future_runtime, f"{label}__future_workflow", future_private, future_public, "future_runtime.marker")

    active_verify, active_verify_path = verify_runtime(active_runtime, registry_path, verification_time, f"{label}__active_verify")
    expired_verify, expired_verify_path = verify_runtime(expired_runtime, registry_path, verification_time, f"{label}__expired_verify")
    future_verify, future_verify_path = verify_runtime(future_runtime, registry_path, verification_time, f"{label}__future_verify")

    proof_passed = (
        active_verify["_returncode"] == 0
        and str(active_verify.get("verification_status", "")).upper() == "PASS"
        and active_verify.get("checks", {}).get("registry_key_within_window") is True
        and expired_verify["_returncode"] != 0
        and str(expired_verify.get("verification_status", "")).upper() == "FAIL"
        and expired_verify.get("checks", {}).get("registry_key_within_window") is False
        and str(expired_verify.get("derived", {}).get("window_verdict", "")) == "expired"
        and future_verify["_returncode"] != 0
        and str(future_verify.get("verification_status", "")).upper() == "FAIL"
        and future_verify.get("checks", {}).get("registry_key_within_window") is False
        and str(future_verify.get("derived", {}).get("window_verdict", "")) == "not_yet_valid"
    )

    summary = {
        "report_version": 1,
        "report_type": "key_policy_validity_window_proof",
        "generated_at_utc": iso(now_utc()),
        "proof_label": label,
        "verification_time_utc": iso(verification_time),
        "proof_status": "PASS" if proof_passed else "FAIL",
        "registry": {
            "registry_path": rel(registry_path),
            "active_key_path": rel(active_public),
            "expired_key_path": rel(expired_public),
            "future_key_path": rel(future_public),
        },
        "active_runtime": {
            "runtime_label": active_runtime,
            "verification_status": active_verify.get("verification_status"),
            "verification_path": rel(active_verify_path),
            "window_verdict": active_verify.get("derived", {}).get("window_verdict"),
            "registry_key_within_window": active_verify.get("checks", {}).get("registry_key_within_window"),
        },
        "expired_runtime": {
            "runtime_label": expired_runtime,
            "verification_status": expired_verify.get("verification_status"),
            "verification_path": rel(expired_verify_path),
            "window_verdict": expired_verify.get("derived", {}).get("window_verdict"),
            "registry_key_within_window": expired_verify.get("checks", {}).get("registry_key_within_window"),
        },
        "future_runtime": {
            "runtime_label": future_runtime,
            "verification_status": future_verify.get("verification_status"),
            "verification_path": rel(future_verify_path),
            "window_verdict": future_verify.get("derived", {}).get("window_verdict"),
            "registry_key_within_window": future_verify.get("checks", {}).get("registry_key_within_window"),
        },
    }

    summary_path = output_dir / "key_policy_validity_window_proof.json"
    report_md_path = output_dir / "key_policy_validity_window_proof.md"
    digest_path = output_dir / "key_policy_validity_window_proof_digest.json"

    write_json(summary_path, summary)
    write_text(report_md_path, build_markdown_report(summary, output_dir))
    write_json(
        digest_path,
        {
            "generated_at_utc": summary["generated_at_utc"],
            "label": label,
            "proof_status": summary["proof_status"],
            "artifacts": [
                {"path": rel(summary_path), "size_bytes": summary_path.stat().st_size, "sha256": sha256_file(summary_path)},
                {"path": rel(report_md_path), "size_bytes": report_md_path.stat().st_size, "sha256": sha256_file(report_md_path)},
                {"path": rel(registry_path), "size_bytes": registry_path.stat().st_size, "sha256": sha256_file(registry_path)},
            ],
        },
    )

    print("=" * 72)
    print("KEY POLICY ENFORCEMENT + EXPIRY / VALIDITY WINDOW PROOF")
    print("=" * 72)
    print(f"LABEL          : {label}")
    print(f"PROOF STATUS   : {summary['proof_status']}")
    print(f"ACTIVE STATUS  : {summary['active_runtime']['verification_status']}")
    print(f"EXPIRED STATUS : {summary['expired_runtime']['verification_status']}")
    print(f"FUTURE STATUS  : {summary['future_runtime']['verification_status']}")
    print(f"REGISTRY       : {rel(registry_path)}")
    print(f"SUMMARY JSON   : {rel(summary_path)}")
    print(f"REPORT MD      : {rel(report_md_path)}")
    print(f"DIGEST         : {rel(digest_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
