#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shlex
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
RUNTIME_ROOT = OPERATIONS_ROOT / "runtime"


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


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


def build_gate_command(
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


def run_subprocess(cmd: list[str]) -> dict:
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_sha256": sha256_bytes((proc.stdout or "").encode("utf-8")),
        "stderr_sha256": sha256_bytes((proc.stderr or "").encode("utf-8")),
    }


def find_gate_decision(label: str) -> Path:
    return require_file(OPERATIONS_ROOT / "admission" / label / "admission_gate_decision.json")


def build_markdown_report(report: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Gate-Enforced Runtime Entry")
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
    lines.append(f"- Gate return code: `{report['gate_phase']['gate_returncode']}`")
    lines.append(f"- Gate decision path: `{report['gate_phase']['gate_decision_path']}`")
    lines.append("")
    lines.append("## Runtime Enforcement")
    lines.append("")
    if report["gate_decision"] == "ALLOW":
        lines.append("Gate returned `ALLOW`, so runtime wrapper executed the requested command.")
    else:
        lines.append("Gate returned `DENY`, so runtime wrapper stopped before executing the requested command.")
    lines.append("")
    lines.append("## Command Result")
    lines.append("")
    lines.append(f"- Wrapped command: `{report['wrapped_command_shell']}`")
    lines.append(f"- Command executed: **{report['command_phase']['executed']}**")
    lines.append(f"- Command return code: `{report['command_phase']['returncode']}`")
    lines.append("")
    lines.append("## Fail-Closed Rule")
    lines.append("")
    lines.append("If the admission gate does not return `ALLOW`, the wrapper exits non-zero and does not run the payload command.")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed runtime entry that executes payload only if admission gate returns ALLOW."
    )
    parser.add_argument("--label", default="Q3_runtime_gate")
    parser.add_argument("--operation", choices=["execute", "promote", "release"], default="execute")
    parser.add_argument("--workflow-id", required=True)
    parser.add_argument("--readiness-label", default="Q1_operational_readiness")
    parser.add_argument("--chain-label", default="Q1_post_readiness_chain_check")
    parser.add_argument("--milestone", default="")
    parser.add_argument("--release-candidate", default="")
    parser.add_argument("--require-rc", action="store_true")
    parser.add_argument("--command", required=True, help="Shell command to execute only when gate decision is ALLOW.")
    args = parser.parse_args()

    runtime_label = args.label.strip()
    workflow_id = args.workflow_id.strip()
    operation = args.operation.strip()
    readiness_label = args.readiness_label.strip()
    chain_label = args.chain_label.strip()
    milestone = args.milestone.strip()
    release_candidate = args.release_candidate.strip()
    wrapped_command = args.command.strip()

    if not runtime_label:
        raise SystemExit("Label must not be empty.")
    if not workflow_id:
        raise SystemExit("workflow-id must not be empty.")
    if not wrapped_command:
        raise SystemExit("command must not be empty.")

    output_dir = RUNTIME_ROOT / runtime_label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")

    gate_label = f"{runtime_label}__gate"

    gate_cmd = build_gate_command(
        gate_label=gate_label,
        operation=operation,
        workflow_id=workflow_id,
        readiness_label=readiness_label,
        chain_label=chain_label,
        milestone=milestone,
        release_candidate=release_candidate,
        require_rc=args.require_rc,
    )
    gate_run = run_subprocess(gate_cmd)
    gate_decision_path = find_gate_decision(gate_label)
    gate_decision = read_json(gate_decision_path)
    gate_decision_value = str(gate_decision.get("decision", "")).upper()

    command_executed = False
    command_returncode = None
    command_stdout = ""
    command_stderr = ""

    if gate_decision_value == "ALLOW":
        command_executed = True
        payload_run = subprocess.run(
            wrapped_command,
            cwd=str(ROOT),
            shell=True,
            capture_output=True,
            text=True,
        )
        command_returncode = payload_run.returncode
        command_stdout = payload_run.stdout
        command_stderr = payload_run.stderr
        runtime_status = "ALLOW_EXECUTED"
        final_exit_code = payload_run.returncode
    else:
        runtime_status = "DENY_BLOCKED"
        final_exit_code = 3

    generated_at = now_utc()
    report = {
        "report_version": 1,
        "report_type": "gate_enforced_runtime_entry",
        "generated_at_utc": generated_at,
        "runtime_label": runtime_label,
        "operation": operation,
        "workflow_id": workflow_id,
        "gate_decision": gate_decision_value,
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
            "executed": command_executed,
            "wrapped_command_shell": wrapped_command,
            "returncode": command_returncode,
            "stdout_sha256": sha256_bytes(command_stdout.encode("utf-8")),
            "stderr_sha256": sha256_bytes(command_stderr.encode("utf-8")),
        },
        "wrapped_command_shell": wrapped_command,
        "fail_closed": True,
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    report_json_path = output_dir / "runtime_gate_report.json"
    report_md_path = output_dir / "runtime_gate_report.md"
    digest_path = output_dir / "runtime_gate_digest_report.json"
    stdout_path = output_dir / "payload.stdout.txt"
    stderr_path = output_dir / "payload.stderr.txt"

    write_json(report_json_path, report)
    write_text(report_md_path, build_markdown_report(report, output_dir))
    write_text(stdout_path, command_stdout)
    write_text(stderr_path, command_stderr)

    digest_report = {
        "generated_at_utc": generated_at,
        "label": runtime_label,
        "gate_decision": gate_decision_value,
        "runtime_status": runtime_status,
        "artifacts": [
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
    print("GATE-ENFORCED RUNTIME ENTRY")
    print("=" * 72)
    print(f"LABEL         : {runtime_label}")
    print(f"GATE DECISION : {gate_decision_value}")
    print(f"RUNTIME STATUS: {runtime_status}")
    print(f"REPORT JSON   : {rel(report_json_path)}")
    print(f"REPORT MD     : {rel(report_md_path)}")
    print(f"DIGEST REPORT : {rel(digest_path)}")
    print("=" * 72)

    raise SystemExit(final_exit_code)


if __name__ == "__main__":
    main()
