#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
MANDATORY_ROOT = OPERATIONS_ROOT / "mandatory_runtime"


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


def run_subprocess(cmd: list[str], env: dict | None = None) -> dict:
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, env=env)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_sha256": sha256_bytes((proc.stdout or "").encode("utf-8")),
        "stderr_sha256": sha256_bytes((proc.stderr or "").encode("utf-8")),
    }


def run_shell_command(command: str, env: dict) -> dict:
    proc = subprocess.run(command, cwd=str(ROOT), shell=True, capture_output=True, text=True, env=env)
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_sha256": sha256_bytes((proc.stdout or "").encode("utf-8")),
        "stderr_sha256": sha256_bytes((proc.stderr or "").encode("utf-8")),
    }


def build_gate_cmd(
    gate_label: str,
    operation: str,
    workflow_id: str,
    readiness_label: str,
    chain_label: str,
    milestone: str,
    release_candidate: str,
    require_rc: bool,
) -> list[str]:
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "control_plane_admission_gate.py"),
        "--label",
        gate_label,
        "--operation",
        operation,
        "--workflow-id",
        workflow_id,
        "--readiness-label",
        readiness_label,
        "--chain-label",
        chain_label,
    ]
    if milestone:
        cmd.extend(["--milestone", milestone])
    if release_candidate:
        cmd.extend(["--release-candidate", release_candidate])
    if require_rc:
        cmd.append("--require-rc")
    return cmd


def build_markdown_report(report: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Mandatory Runtime Entry Report")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{report['generated_at_utc']}`")
    lines.append(f"- Runtime label: `{report['runtime_label']}`")
    lines.append(f"- Operation: `{report['operation']}`")
    lines.append(f"- Workflow ID: `{report['workflow_id']}`")
    lines.append(f"- Gate decision: **{report['gate_decision']}**")
    lines.append(f"- Runtime status: **{report['runtime_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Gate Phase")
    lines.append("")
    lines.append(f"- Gate label: `{report['gate_phase']['gate_label']}`")
    lines.append(f"- Gate decision path: `{report['gate_phase']['gate_decision_path']}`")
    lines.append(f"- Gate return code: `{report['gate_phase']['gate_returncode']}`")
    lines.append("")
    lines.append("## Mandatory Execution Contract")
    lines.append("")
    lines.append("- Payload is executed only when gate returns `ALLOW`.")
    lines.append("- Payload receives mandatory environment variables from the wrapper.")
    lines.append("- A receipt is written for the workflow execution attempt.")
    lines.append("")
    lines.append("## Payload Phase")
    lines.append("")
    lines.append(f"- Command executed: **{report['command_phase']['executed']}**")
    lines.append(f"- Command return code: `{report['command_phase']['returncode']}`")
    lines.append(f"- Receipt path: `{report['receipt_path']}`")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mandatory runtime entry: gate decision + runtime execution + execution receipt."
    )
    parser.add_argument("--label", required=True)
    parser.add_argument("--request-manifest", required=True)
    args = parser.parse_args()

    runtime_label = args.label.strip()
    manifest_path = Path(args.request_manifest).resolve()

    if not runtime_label:
        raise SystemExit("label must not be empty.")

    require_file(manifest_path)
    manifest = read_json(manifest_path)

    operation = str(manifest.get("operation", "")).strip()
    workflow_id = str(manifest.get("workflow_id", "")).strip()
    readiness_label = str(manifest.get("readiness_label", "Q1_operational_readiness")).strip()
    chain_label = str(manifest.get("chain_label", "Q1_post_readiness_chain_check")).strip()
    milestone = str(manifest.get("milestone", "")).strip()
    release_candidate = str(manifest.get("release_candidate", "")).strip()
    require_rc = bool(manifest.get("require_rc", False))
    command = str(manifest.get("command", "")).strip()

    if operation not in {"execute", "promote", "release"}:
        raise SystemExit("manifest.operation must be one of: execute, promote, release")
    if not workflow_id:
        raise SystemExit("manifest.workflow_id must not be empty")
    if not command:
        raise SystemExit("manifest.command must not be empty")

    output_dir = MANDATORY_ROOT / runtime_label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")

    generated_at = now_utc()
    gate_label = f"{runtime_label}__gate"

    gate_cmd = build_gate_cmd(
        gate_label=gate_label,
        operation=operation,
        workflow_id=workflow_id,
        readiness_label=readiness_label,
        chain_label=chain_label,
        milestone=milestone,
        release_candidate=release_candidate,
        require_rc=require_rc,
    )
    gate_run = run_subprocess(gate_cmd)

    gate_decision_path = require_file(
        ROOT / "artifacts" / "operations" / "admission" / gate_label / "admission_gate_decision.json"
    )
    gate_decision = read_json(gate_decision_path)
    gate_value = str(gate_decision.get("decision", "")).upper()

    payload_stdout = ""
    payload_stderr = ""
    payload_returncode = None
    payload_executed = False

    payload_env = os.environ.copy()
    payload_env["CONTROL_PLANE_MANDATORY_EXECUTION"] = "1"
    payload_env["CONTROL_PLANE_WORKFLOW_ID"] = workflow_id
    payload_env["CONTROL_PLANE_OPERATION"] = operation
    payload_env["CONTROL_PLANE_GATE_LABEL"] = gate_label
    payload_env["CONTROL_PLANE_RUNTIME_LABEL"] = runtime_label

    if gate_value == "ALLOW":
        payload_executed = True
        payload_run = run_shell_command(command, env=payload_env)
        payload_stdout = payload_run["stdout"]
        payload_stderr = payload_run["stderr"]
        payload_returncode = payload_run["returncode"]
        runtime_status = "ALLOW_EXECUTED"
        final_exit_code = payload_returncode
    else:
        runtime_status = "DENY_BLOCKED"
        final_exit_code = 3

    output_dir.mkdir(parents=True, exist_ok=False)

    normalized_manifest_path = output_dir / "normalized_request_manifest.json"
    receipt_path = output_dir / "mandatory_execution_receipt.json"
    report_json_path = output_dir / "mandatory_runtime_report.json"
    report_md_path = output_dir / "mandatory_runtime_report.md"
    digest_path = output_dir / "mandatory_runtime_digest_report.json"
    stdout_path = output_dir / "payload.stdout.txt"
    stderr_path = output_dir / "payload.stderr.txt"

    normalized_manifest = {
        "operation": operation,
        "workflow_id": workflow_id,
        "readiness_label": readiness_label,
        "chain_label": chain_label,
        "milestone": milestone,
        "release_candidate": release_candidate,
        "require_rc": require_rc,
        "command": command,
    }
    write_json(normalized_manifest_path, normalized_manifest)

    receipt = {
        "receipt_version": 1,
        "receipt_type": "mandatory_execution_receipt",
        "generated_at_utc": generated_at,
        "runtime_label": runtime_label,
        "workflow_id": workflow_id,
        "operation": operation,
        "gate_label": gate_label,
        "gate_decision": gate_value,
        "runtime_status": runtime_status,
        "manifest_path": rel(normalized_manifest_path),
        "manifest_sha256": sha256_file(normalized_manifest_path),
        "gate_decision_path": rel(gate_decision_path),
        "gate_decision_sha256": sha256_file(gate_decision_path),
        "command_executed": payload_executed,
        "command_returncode": payload_returncode,
        "command_sha256": sha256_bytes(command.encode("utf-8")),
    }
    write_json(receipt_path, receipt)

    report = {
        "report_version": 1,
        "report_type": "mandatory_runtime_entry",
        "generated_at_utc": generated_at,
        "runtime_label": runtime_label,
        "workflow_id": workflow_id,
        "operation": operation,
        "gate_decision": gate_value,
        "runtime_status": runtime_status,
        "gate_phase": {
            "gate_label": gate_label,
            "gate_command": gate_cmd,
            "gate_returncode": gate_run["returncode"],
            "gate_stdout_sha256": gate_run["stdout_sha256"],
            "gate_stderr_sha256": gate_run["stderr_sha256"],
            "gate_decision_path": rel(gate_decision_path),
        },
        "command_phase": {
            "executed": payload_executed,
            "wrapped_command_shell": command,
            "returncode": payload_returncode,
            "stdout_sha256": sha256_bytes(payload_stdout.encode("utf-8")),
            "stderr_sha256": sha256_bytes(payload_stderr.encode("utf-8")),
        },
        "receipt_path": rel(receipt_path),
        "manifest_path": rel(normalized_manifest_path),
        "fail_closed": True,
        "mandatory_execution_env": {
            "CONTROL_PLANE_MANDATORY_EXECUTION": "1",
            "CONTROL_PLANE_WORKFLOW_ID": workflow_id,
            "CONTROL_PLANE_OPERATION": operation,
            "CONTROL_PLANE_GATE_LABEL": gate_label,
            "CONTROL_PLANE_RUNTIME_LABEL": runtime_label,
        },
    }

    write_json(report_json_path, report)
    write_text(report_md_path, build_markdown_report(report, output_dir))
    write_text(stdout_path, payload_stdout)
    write_text(stderr_path, payload_stderr)

    digest_report = {
        "generated_at_utc": generated_at,
        "label": runtime_label,
        "gate_decision": gate_value,
        "runtime_status": runtime_status,
        "artifacts": [
            {
                "path": rel(normalized_manifest_path),
                "size_bytes": normalized_manifest_path.stat().st_size,
                "sha256": sha256_file(normalized_manifest_path),
            },
            {
                "path": rel(receipt_path),
                "size_bytes": receipt_path.stat().st_size,
                "sha256": sha256_file(receipt_path),
            },
            {
                "path": rel(report_json_path),
                "size_bytes": report_json_path.stat().st_size,
                "sha256": sha256_file(report_json_path),
            },
            {
                "path": rel(report_md_path),
                "size_bytes": report_md_path.stat().st_size,
                "sha256": sha256_file(report_md_path),
            },
            {
                "path": rel(stdout_path),
                "size_bytes": stdout_path.stat().st_size,
                "sha256": sha256_file(stdout_path),
            },
            {
                "path": rel(stderr_path),
                "size_bytes": stderr_path.stat().st_size,
                "sha256": sha256_file(stderr_path),
            },
        ],
    }
    write_json(digest_path, digest_report)

    print("=" * 72)
    print("MANDATORY RUNTIME ENTRY")
    print("=" * 72)
    print(f"LABEL         : {runtime_label}")
    print(f"GATE DECISION : {gate_value}")
    print(f"RUNTIME STATUS: {runtime_status}")
    print(f"RECEIPT PATH  : {rel(receipt_path)}")
    print(f"REPORT JSON   : {rel(report_json_path)}")
    print(f"REPORT MD     : {rel(report_md_path)}")
    print(f"DIGEST REPORT : {rel(digest_path)}")
    print("=" * 72)

    raise SystemExit(final_exit_code)


if __name__ == "__main__":
    main()
