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
OUTPUT_ROOT = OPERATIONS_ROOT / "mandatory_integration_proof"


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


def run_shell(command: str) -> dict:
    proc = subprocess.run(command, cwd=str(ROOT), shell=True, capture_output=True, text=True)
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_sha256": sha256_bytes((proc.stdout or "").encode("utf-8")),
        "stderr_sha256": sha256_bytes((proc.stderr or "").encode("utf-8")),
    }


def build_markdown_report(summary: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Mandatory Runtime Integration Proof + Bypass Resistance Check")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Proof label: `{summary['proof_label']}`")
    lines.append(f"- Proof status: **{summary['proof_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Mandatory Path")
    lines.append("")
    lines.append(f"- Runtime label: `{summary['mandatory_path']['runtime_label']}`")
    lines.append(f"- Gate decision: **{summary['mandatory_path']['gate_decision']}**")
    lines.append(f"- Runtime status: **{summary['mandatory_path']['runtime_status']}**")
    lines.append(f"- Receipt exists: **{summary['mandatory_path']['receipt_exists']}**")
    lines.append(f"- Allowed marker exists: **{summary['mandatory_path']['allowed_marker_exists']}**")
    lines.append("")
    lines.append("## Bypass Check")
    lines.append("")
    lines.append(f"- Bypass return code: `{summary['bypass_path']['returncode']}`")
    lines.append(f"- Bypass marker exists: **{summary['bypass_path']['bypass_marker_exists']}**")
    lines.append(f"- Unauthorized marker blocked: **{summary['bypass_path']['unauthorized_marker_blocked']}**")
    lines.append(f"- Bypass receipt absent: **{summary['bypass_path']['bypass_receipt_absent']}**")
    lines.append("")
    lines.append("## Final Declaration")
    lines.append("")
    if summary["proof_status"] == "PASS":
        lines.append(
            "Mandatory runtime integration proof passed. Authorized execution succeeded only through mandatory entry, a receipt was written, and direct bypass of the guarded payload did not produce the protected marker."
        )
    else:
        lines.append(
            "Mandatory runtime integration proof failed. Either the mandatory path did not produce authorized evidence, or the bypass path was not properly blocked/detected."
        )
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prove mandatory runtime integration and guarded-payload bypass resistance."
    )
    parser.add_argument("--label", default="Q5_mandatory_runtime_integration_proof")
    args = parser.parse_args()

    label = args.label.strip()
    if not label:
        raise SystemExit("label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")

    generated_at = now_utc()
    output_dir.mkdir(parents=True, exist_ok=False)

    allowed_marker = output_dir / "allowed_payload.marker"
    bypass_marker = output_dir / "bypass_payload.marker"
    request_manifest_path = output_dir / "mandatory_request_manifest.json"

    mandatory_runtime_label = f"{label}__mandatory"
    mandatory_workflow_id = f"{label}__workflow"
    bypass_workflow_id = f"{label}__bypass_workflow"

    guarded_payload = (
        "python3 -c \"import os, sys; from pathlib import Path; "
        f"p = Path(r'{allowed_marker}'); "
        "flag = os.environ.get('CONTROL_PLANE_MANDATORY_EXECUTION'); "
        "wf = os.environ.get('CONTROL_PLANE_WORKFLOW_ID'); "
        f"expected = r'{mandatory_workflow_id}'; "
        "ok = (flag == '1' and wf == expected); "
        "sys.exit(7) if not ok else p.write_text('AUTHORIZED_EXECUTION', encoding='utf-8')\""
    )

    bypass_command = (
        "python3 -c \"import os, sys; from pathlib import Path; "
        f"p = Path(r'{bypass_marker}'); "
        "flag = os.environ.get('CONTROL_PLANE_MANDATORY_EXECUTION'); "
        f"expected = r'{bypass_workflow_id}'; "
        "wf = os.environ.get('CONTROL_PLANE_WORKFLOW_ID'); "
        "ok = (flag == '1' and wf == expected); "
        "sys.exit(7) if not ok else p.write_text('BYPASS_EXECUTED', encoding='utf-8')\""
    )

    manifest = {
        "operation": "release",
        "workflow_id": mandatory_workflow_id,
        "readiness_label": "Q1_operational_readiness",
        "chain_label": "Q1_post_readiness_chain_check",
        "milestone": "O3_independent_freeze",
        "release_candidate": "RC3",
        "require_rc": True,
        "command": guarded_payload,
    }
    write_json(request_manifest_path, manifest)

    mandatory_run = run_python(
        [
            sys.executable,
            str(ROOT / "scripts" / "mandatory_runtime_entry.py"),
            "--label",
            mandatory_runtime_label,
            "--request-manifest",
            str(request_manifest_path),
        ]
    )

    mandatory_dir = ROOT / "artifacts" / "operations" / "mandatory_runtime" / mandatory_runtime_label
    receipt_path = require_file(mandatory_dir / "mandatory_execution_receipt.json")
    report_path = require_file(mandatory_dir / "mandatory_runtime_report.json")
    digest_path = require_file(mandatory_dir / "mandatory_runtime_digest_report.json")
    payload_stdout_path = require_file(mandatory_dir / "payload.stdout.txt")
    payload_stderr_path = require_file(mandatory_dir / "payload.stderr.txt")

    receipt = read_json(receipt_path)
    runtime_report = read_json(report_path)

    bypass_run = run_shell(bypass_command)

    gate_decision = str(runtime_report.get("gate_decision", "")).upper()
    runtime_status = str(runtime_report.get("runtime_status", "")).upper()
    receipt_exists = receipt_path.exists()
    allowed_marker_exists = allowed_marker.exists()
    bypass_marker_exists = bypass_marker.exists()
    unauthorized_marker_blocked = not bypass_marker_exists
    bypass_receipt_absent = not (ROOT / "artifacts" / "operations" / "mandatory_runtime" / f"{label}__bypass").exists()

    proof_passed = (
        mandatory_run["returncode"] == 0
        and gate_decision == "ALLOW"
        and runtime_status == "ALLOW_EXECUTED"
        and receipt_exists
        and allowed_marker_exists
        and receipt.get("command_executed") is True
        and bypass_run["returncode"] == 7
        and unauthorized_marker_blocked
        and bypass_receipt_absent
    )

    summary = {
        "report_version": 1,
        "report_type": "mandatory_runtime_integration_proof",
        "generated_at_utc": generated_at,
        "proof_label": label,
        "proof_status": "PASS" if proof_passed else "FAIL",
        "mandatory_path": {
            "runtime_label": mandatory_runtime_label,
            "workflow_id": mandatory_workflow_id,
            "request_manifest_path": rel(request_manifest_path),
            "mandatory_run_returncode": mandatory_run["returncode"],
            "gate_decision": gate_decision,
            "runtime_status": runtime_status,
            "receipt_exists": receipt_exists,
            "receipt_path": rel(receipt_path),
            "report_path": rel(report_path),
            "digest_path": rel(digest_path),
            "allowed_marker_exists": allowed_marker_exists,
            "allowed_marker_path": rel(allowed_marker),
            "payload_stdout_path": rel(payload_stdout_path),
            "payload_stderr_path": rel(payload_stderr_path),
        },
        "bypass_path": {
            "workflow_id": bypass_workflow_id,
            "returncode": bypass_run["returncode"],
            "stdout_sha256": bypass_run["stdout_sha256"],
            "stderr_sha256": bypass_run["stderr_sha256"],
            "bypass_marker_exists": bypass_marker_exists,
            "bypass_marker_path": rel(bypass_marker),
            "unauthorized_marker_blocked": unauthorized_marker_blocked,
            "bypass_receipt_absent": bypass_receipt_absent,
        },
    }

    summary_path = output_dir / "mandatory_runtime_integration_proof.json"
    report_md_path = output_dir / "mandatory_runtime_integration_proof.md"
    digest_report_path = output_dir / "mandatory_runtime_integration_digest_report.json"

    write_json(summary_path, summary)
    write_text(report_md_path, build_markdown_report(summary, output_dir))

    digest_report = {
        "generated_at_utc": generated_at,
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
                "path": rel(request_manifest_path),
                "size_bytes": request_manifest_path.stat().st_size,
                "sha256": sha256_file(request_manifest_path),
            },
        ],
    }
    write_json(digest_report_path, digest_report)

    print("=" * 72)
    print("MANDATORY RUNTIME INTEGRATION PROOF + BYPASS RESISTANCE CHECK")
    print("=" * 72)
    print(f"LABEL            : {label}")
    print(f"PROOF STATUS     : {summary['proof_status']}")
    print(f"MANDATORY GATE   : {gate_decision}")
    print(f"MANDATORY STATUS : {runtime_status}")
    print(f"BYPASS RC        : {bypass_run['returncode']}")
    print(f"AUTHORIZED MARKER: {allowed_marker_exists}")
    print(f"BYPASS MARKER    : {bypass_marker_exists}")
    print("-" * 72)
    print(f"SUMMARY JSON     : {rel(summary_path)}")
    print(f"REPORT MD        : {rel(report_md_path)}")
    print(f"DIGEST REPORT    : {rel(digest_report_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
