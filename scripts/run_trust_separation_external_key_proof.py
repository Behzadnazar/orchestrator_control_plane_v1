#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
OUTPUT_ROOT = OPERATIONS_ROOT / "trust_separation_proof"


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


def build_markdown_report(summary: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Trust Separation + Externalized Signing Key Proof")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Proof label: `{summary['proof_label']}`")
    lines.append(f"- Proof status: **{summary['proof_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Signed Runtime")
    lines.append("")
    lines.append(f"- Runtime label: `{summary['signed_runtime']['runtime_label']}`")
    lines.append(f"- Gate decision: **{summary['signed_runtime']['gate_decision']}**")
    lines.append(f"- Runtime status: **{summary['signed_runtime']['runtime_status']}**")
    lines.append(f"- Marker exists: **{summary['signed_runtime']['marker_exists']}**")
    lines.append("")
    lines.append("## Trust Separation Check")
    lines.append("")
    lines.append(f"- Private key hidden during verification: **{summary['trust_separation']['private_key_hidden_during_verify']}**")
    lines.append(f"- Verification status with hidden private key: **{summary['trust_separation']['verification_status']}**")
    lines.append(f"- Signature valid: **{summary['trust_separation']['signature_valid']}**")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove trust separation using external private key signing and public-key-only verification.")
    parser.add_argument("--label", default="R3_trust_separation_external_key_proof")
    parser.add_argument("--private-key", default="artifacts/keys/attestation/attestation_private.pem")
    parser.add_argument("--public-key", default="artifacts/keys/attestation/attestation_public.pem")
    args = parser.parse_args()

    label = args.label.strip()
    private_key_path = (ROOT / args.private_key).resolve() if not Path(args.private_key).is_absolute() else Path(args.private_key).resolve()
    public_key_path = (ROOT / args.public_key).resolve() if not Path(args.public_key).is_absolute() else Path(args.public_key).resolve()

    if not label:
        raise SystemExit("label must not be empty.")

    require_file(private_key_path)
    require_file(public_key_path)

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=False)

    runtime_label = f"{label}__runtime"
    verify_label = f"{label}__verify_public_only"
    workflow_id = f"{label}__workflow"
    marker_path = output_dir / "external_key_signed.marker"
    manifest_path = output_dir / "external_key_request_manifest.json"

    command = (
        "python3 -c \"import os, sys; from pathlib import Path; "
        f"p = Path(r'{marker_path}'); "
        "flag = os.environ.get('CONTROL_PLANE_TRUST_SEPARATED_SIGNING'); "
        "pub = os.environ.get('CONTROL_PLANE_PUBLIC_KEY_PATH'); "
        f"expected_pub = r'{public_key_path}'; "
        "wf = os.environ.get('CONTROL_PLANE_WORKFLOW_ID'); "
        f"expected_wf = r'{workflow_id}'; "
        "ok = (flag == '1' and pub == expected_pub and wf == expected_wf); "
        "sys.exit(13) if not ok else p.write_text('EXTERNAL_KEY_SIGNED_OK', encoding='utf-8')\""
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
        "private_key_path": str(private_key_path),
        "public_key_path": str(public_key_path),
    }
    write_json(manifest_path, manifest)

    signed_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "signed_execution_entry_external_key.py"),
            "--label",
            runtime_label,
            "--request-manifest",
            str(manifest_path),
        ]
    )

    runtime_report_path = require_file(
        ROOT / "artifacts" / "operations" / "external_signed_runtime" / runtime_label / "external_signed_runtime_report.json"
    )
    runtime_report = read_json(runtime_report_path)

    hidden_private_path = private_key_path.with_suffix(private_key_path.suffix + ".hidden_for_verify")
    shutil.move(str(private_key_path), str(hidden_private_path))
    try:
        verify_run = run_python(
            [
                sys.executable,
                str(ROOT / "scripts" / "verify_external_signed_attestation.py"),
                "--runtime-label",
                runtime_label,
                "--label",
                verify_label,
            ]
        )
    finally:
        shutil.move(str(hidden_private_path), str(private_key_path))

    verify_report_path = require_file(
        ROOT / "artifacts" / "operations" / "external_attestation_verification" / verify_label / "external_signed_attestation_verification.json"
    )
    verify_report = read_json(verify_report_path)

    marker_exists = marker_path.exists()

    proof_passed = (
        signed_run["returncode"] == 0
        and str(runtime_report.get("gate_decision", "")).upper() == "ALLOW"
        and str(runtime_report.get("runtime_status", "")).upper() == "ALLOW_EXECUTED"
        and marker_exists
        and verify_run["returncode"] == 0
        and str(verify_report.get("verification_status", "")).upper() == "PASS"
        and verify_report.get("checks", {}).get("signature_valid") is True
        and verify_report.get("checks", {}).get("private_key_material_not_embedded") is True
    )

    summary = {
        "report_version": 1,
        "report_type": "trust_separation_external_key_proof",
        "generated_at_utc": now_utc(),
        "proof_label": label,
        "proof_status": "PASS" if proof_passed else "FAIL",
        "signed_runtime": {
            "runtime_label": runtime_label,
            "run_returncode": signed_run["returncode"],
            "runtime_report_path": rel(runtime_report_path),
            "gate_decision": runtime_report.get("gate_decision"),
            "runtime_status": runtime_report.get("runtime_status"),
            "marker_exists": marker_exists,
            "marker_path": rel(marker_path),
        },
        "trust_separation": {
            "private_key_hidden_during_verify": True,
            "public_key_path": rel(public_key_path),
            "verification_label": verify_label,
            "verification_returncode": verify_run["returncode"],
            "verification_path": rel(verify_report_path),
            "verification_status": verify_report.get("verification_status"),
            "signature_valid": verify_report.get("checks", {}).get("signature_valid"),
            "private_key_material_not_embedded": verify_report.get("checks", {}).get("private_key_material_not_embedded"),
        },
    }

    summary_path = output_dir / "trust_separation_external_key_proof.json"
    report_md_path = output_dir / "trust_separation_external_key_proof.md"
    digest_path = output_dir / "trust_separation_external_key_proof_digest.json"

    write_json(summary_path, summary)
    write_text(report_md_path, build_markdown_report(summary, output_dir))
    write_json(digest_path, {
        "generated_at_utc": summary["generated_at_utc"],
        "label": label,
        "proof_status": summary["proof_status"],
        "artifacts": [
            {"path": rel(summary_path), "size_bytes": summary_path.stat().st_size, "sha256": sha256_file(summary_path)},
            {"path": rel(report_md_path), "size_bytes": report_md_path.stat().st_size, "sha256": sha256_file(report_md_path)},
            {"path": rel(manifest_path), "size_bytes": manifest_path.stat().st_size, "sha256": sha256_file(manifest_path)},
        ],
    })

    print("=" * 72)
    print("TRUST SEPARATION + EXTERNALIZED SIGNING KEY PROOF")
    print("=" * 72)
    print(f"LABEL            : {label}")
    print(f"PROOF STATUS     : {summary['proof_status']}")
    print(f"SIGNED RUNTIME   : {runtime_label}")
    print(f"VERIFY LABEL     : {verify_label}")
    print(f"SUMMARY JSON     : {rel(summary_path)}")
    print(f"REPORT MD        : {rel(report_md_path)}")
    print(f"DIGEST           : {rel(digest_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
