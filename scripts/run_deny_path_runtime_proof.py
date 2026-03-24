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
OUTPUT_ROOT = OPERATIONS_ROOT / "deny_path_proof"


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


def run_runtime_wrapper(
    runtime_label: str,
    workflow_id: str,
    readiness_label: str,
    chain_label: str,
    command: str,
) -> dict:
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "gate_enforced_runtime_entry.py"),
        "--label",
        runtime_label,
        "--operation",
        "release",
        "--workflow-id",
        workflow_id,
        "--readiness-label",
        readiness_label,
        "--chain-label",
        chain_label,
        "--require-rc",
        "--command",
        command,
    ]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_sha256": sha256_bytes((proc.stdout or "").encode("utf-8")),
        "stderr_sha256": sha256_bytes((proc.stderr or "").encode("utf-8")),
    }


def build_markdown_report(report: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Deny-Path Runtime Proof + Blocked Payload Evidence")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{report['generated_at_utc']}`")
    lines.append(f"- Proof label: `{report['proof_label']}`")
    lines.append(f"- Runtime label: `{report['runtime_label']}`")
    lines.append(f"- Workflow ID: `{report['workflow_id']}`")
    lines.append(f"- Expected gate decision: **DENY**")
    lines.append(f"- Observed gate decision: **{report['gate_decision']}**")
    lines.append(f"- Runtime status: **{report['runtime_status']}**")
    lines.append(f"- Proof status: **{report['proof_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Runtime Wrapper Result")
    lines.append("")
    lines.append(f"- Wrapper return code: `{report['wrapper_phase']['returncode']}`")
    lines.append(f"- Wrapped command: `{report['wrapped_command_shell']}`")
    lines.append("")
    lines.append("## Gate Evidence")
    lines.append("")
    lines.append(f"- Gate decision path: `{report['gate_decision_path']}`")
    lines.append(f"- Runtime report path: `{report['runtime_report_path']}`")
    lines.append(f"- Payload stdout path: `{report['payload_stdout_path']}`")
    lines.append(f"- Payload stderr path: `{report['payload_stderr_path']}`")
    lines.append("")
    lines.append("## Blocked Payload Assertions")
    lines.append("")
    lines.append(f"- Payload executed: **{report['payload_executed']}**")
    lines.append(f"- Payload stdout empty: **{report['payload_stdout_empty']}**")
    lines.append(f"- Payload stderr empty: **{report['payload_stderr_empty']}**")
    lines.append(f"- Block marker absent: **{report['block_marker_absent']}**")
    lines.append("")
    lines.append("## Final Declaration")
    lines.append("")
    if report["proof_status"] == "PASS":
        lines.append("The deny-path runtime proof passed. The gate returned DENY, the wrapper blocked execution, and no payload marker was emitted.")
    else:
        lines.append("The deny-path runtime proof failed. The wrapper did not demonstrate fail-closed blocking as required.")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prove deny-path runtime enforcement by invoking gate-enforced runtime without required milestone/RC inputs."
    )
    parser.add_argument("--label", default="Q4_deny_path_runtime_proof")
    parser.add_argument("--readiness-label", default="Q1_operational_readiness")
    parser.add_argument("--chain-label", default="Q1_post_readiness_chain_check")
    args = parser.parse_args()

    label = args.label.strip()
    readiness_label = args.readiness_label.strip()
    chain_label = args.chain_label.strip()

    if not label:
        raise SystemExit("Label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")

    runtime_label = f"{label}__runtime"
    workflow_id = f"{label}__workflow"
    blocked_marker = "Q4_BLOCK_MARKER_SHOULD_NOT_APPEAR"

    wrapped_command = f"python3 -c \"print('{blocked_marker}')\""

    wrapper_run = run_runtime_wrapper(
        runtime_label=runtime_label,
        workflow_id=workflow_id,
        readiness_label=readiness_label,
        chain_label=chain_label,
        command=wrapped_command,
    )

    gate_decision_path = require_file(
        ROOT / "artifacts" / "operations" / "admission" / f"{runtime_label}__gate" / "admission_gate_decision.json"
    )
    runtime_report_path = require_file(
        ROOT / "artifacts" / "operations" / "runtime" / runtime_label / "runtime_gate_report.json"
    )
    payload_stdout_path = require_file(
        ROOT / "artifacts" / "operations" / "runtime" / runtime_label / "payload.stdout.txt"
    )
    payload_stderr_path = require_file(
        ROOT / "artifacts" / "operations" / "runtime" / runtime_label / "payload.stderr.txt"
    )
    runtime_digest_path = require_file(
        ROOT / "artifacts" / "operations" / "runtime" / runtime_label / "runtime_gate_digest_report.json"
    )

    gate_decision = read_json(gate_decision_path)
    runtime_report = read_json(runtime_report_path)
    payload_stdout = read_text(payload_stdout_path)
    payload_stderr = read_text(payload_stderr_path)

    observed_gate_decision = str(gate_decision.get("decision", "")).upper()
    observed_runtime_status = str(runtime_report.get("runtime_status", "")).upper()
    payload_executed = bool(runtime_report.get("command_phase", {}).get("executed"))
    wrapper_returncode = wrapper_run["returncode"]

    payload_stdout_empty = payload_stdout == ""
    payload_stderr_empty = payload_stderr == ""
    block_marker_absent = blocked_marker not in payload_stdout and blocked_marker not in payload_stderr

    proof_passed = (
        observed_gate_decision == "DENY"
        and observed_runtime_status == "DENY_BLOCKED"
        and payload_executed is False
        and wrapper_returncode == 3
        and payload_stdout_empty
        and payload_stderr_empty
        and block_marker_absent
    )

    generated_at = now_utc()

    report = {
        "report_version": 1,
        "report_type": "deny_path_runtime_proof",
        "generated_at_utc": generated_at,
        "proof_label": label,
        "runtime_label": runtime_label,
        "workflow_id": workflow_id,
        "wrapped_command_shell": wrapped_command,
        "gate_decision": observed_gate_decision,
        "runtime_status": observed_runtime_status,
        "payload_executed": payload_executed,
        "payload_stdout_empty": payload_stdout_empty,
        "payload_stderr_empty": payload_stderr_empty,
        "block_marker_absent": block_marker_absent,
        "expected_wrapper_returncode": 3,
        "actual_wrapper_returncode": wrapper_returncode,
        "proof_status": "PASS" if proof_passed else "FAIL",
        "wrapper_phase": {
            "cmd": wrapper_run["cmd"],
            "returncode": wrapper_run["returncode"],
            "stdout_sha256": wrapper_run["stdout_sha256"],
            "stderr_sha256": wrapper_run["stderr_sha256"],
        },
        "gate_decision_path": rel(gate_decision_path),
        "runtime_report_path": rel(runtime_report_path),
        "runtime_digest_path": rel(runtime_digest_path),
        "payload_stdout_path": rel(payload_stdout_path),
        "payload_stderr_path": rel(payload_stderr_path),
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    report_json_path = output_dir / "deny_path_runtime_proof.json"
    report_md_path = output_dir / "deny_path_runtime_proof.md"
    digest_path = output_dir / "deny_path_runtime_proof_digest_report.json"

    write_json(report_json_path, report)
    write_text(report_md_path, build_markdown_report(report, output_dir))

    digest_report = {
        "generated_at_utc": generated_at,
        "label": label,
        "proof_status": report["proof_status"],
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
        ],
    }
    write_json(digest_path, digest_report)

    print("=" * 72)
    print("DENY-PATH RUNTIME PROOF + BLOCKED PAYLOAD EVIDENCE")
    print("=" * 72)
    print(f"LABEL           : {label}")
    print(f"RUNTIME LABEL   : {runtime_label}")
    print(f"GATE DECISION   : {observed_gate_decision}")
    print(f"RUNTIME STATUS  : {observed_runtime_status}")
    print(f"WRAPPER RC      : {wrapper_returncode}")
    print(f"PROOF STATUS    : {report['proof_status']}")
    print("-" * 72)
    print(f"REPORT JSON     : {rel(report_json_path)}")
    print(f"REPORT MD       : {rel(report_md_path)}")
    print(f"DIGEST REPORT   : {rel(digest_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
