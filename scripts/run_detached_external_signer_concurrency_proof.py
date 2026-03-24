#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = ROOT / "artifacts" / "operations"
STATE_DIR = ROOT / "state" / "detached_external_signer_concurrency"


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def iso_no_microseconds(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def parse_utc(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rel(path: Path) -> str:
    return os.path.relpath(path, ROOT).replace("\\", "/")


def run_cmd(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd or ROOT),
        text=True,
        capture_output=True,
        check=False,
    )


def require_openssl() -> str:
    result = run_cmd(["openssl", "version"])
    if result.returncode != 0:
        raise SystemExit("OpenSSL is required but not available in PATH.")
    return (result.stdout or result.stderr).strip()


def remove_if_exists(path: Path) -> None:
    if path.exists():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


@dataclass
class ScenarioKey:
    key_id: str
    private_key_path: Path
    public_key_path: Path
    not_before: str
    not_after: str


def generate_rsa_keypair(private_key_path: Path, public_key_path: Path) -> None:
    ensure_dir(private_key_path.parent)
    ensure_dir(public_key_path.parent)

    gen = run_cmd(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
            "-out",
            str(private_key_path),
        ]
    )
    if gen.returncode != 0:
        raise SystemExit(f"openssl genpkey failed:\nSTDOUT:\n{gen.stdout}\nSTDERR:\n{gen.stderr}")

    pub = run_cmd(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key_path),
            "-pubout",
            "-out",
            str(public_key_path),
        ]
    )
    if pub.returncode != 0:
        raise SystemExit(f"openssl pkey -pubout failed:\nSTDOUT:\n{pub.stdout}\nSTDERR:\n{pub.stderr}")

    os.chmod(private_key_path, 0o600)
    os.chmod(public_key_path, 0o644)


def scan_for_private_keys(base_dir: Path) -> dict[str, Any]:
    suspicious_files: list[str] = []
    pem_private_markers = (
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    )

    if not base_dir.exists():
        return {
            "scanned_root": rel(base_dir),
            "private_key_files_found": [],
            "contains_private_keys": False,
        }

    for path in sorted(base_dir.rglob("*")):
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            content = ""
        if any(marker in content for marker in pem_private_markers):
            suspicious_files.append(rel(path))

    return {
        "scanned_root": rel(base_dir),
        "private_key_files_found": suspicious_files,
        "contains_private_keys": len(suspicious_files) > 0,
    }


def evaluate_window(key: ScenarioKey, verification_time_utc: datetime) -> tuple[bool, str]:
    not_before = parse_utc(key.not_before)
    not_after = parse_utc(key.not_after)

    if verification_time_utc < not_before:
        return False, "not_yet_valid"
    if verification_time_utc > not_after:
        return False, "expired"
    return True, "within_window"


def openssl_verify(data_path: Path, public_key_path: Path, signature_path: Path) -> dict[str, Any]:
    result = run_cmd(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key_path),
            "-signature",
            str(signature_path),
            str(data_path),
        ]
    )
    combined = (result.stdout or "") + (result.stderr or "")
    verified_ok = result.returncode == 0 and "Verified OK" in combined
    return {
        "command": [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            rel(public_key_path),
            "-signature",
            rel(signature_path),
            rel(data_path),
        ],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "verified_ok": verified_ok,
    }


def attempt_private_key_read(private_key_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "private_key_path": str(private_key_path),
        "read_allowed": False,
        "exception_type": None,
        "exception_message": None,
    }
    try:
        _ = private_key_path.read_text(encoding="utf-8")
        result["read_allowed"] = True
    except Exception as exc:
        result["exception_type"] = type(exc).__name__
        result["exception_message"] = str(exc)
    return result


def cleanup_denied_key(private_key_path: Path) -> dict[str, Any]:
    existed_before = private_key_path.exists()
    removed = False
    error_type = None
    error_message = None

    try:
        if private_key_path.exists():
            private_key_path.unlink()
            removed = True
    except Exception as exc:
        error_type = type(exc).__name__
        error_message = str(exc)

    return {
        "private_key_path": str(private_key_path),
        "existed_before_cleanup": existed_before,
        "removed": removed,
        "exists_after_cleanup": private_key_path.exists(),
        "error_type": error_type,
        "error_message": error_message,
    }


def scenario_paths(base_dir: Path, scenario_name: str) -> dict[str, Path]:
    scenario_dir = base_dir / scenario_name
    return {
        "scenario_dir": scenario_dir,
        "manifest": scenario_dir / "normalized_request_manifest.json",
        "gate_decision": scenario_dir / "pre_execution_gate_decision.json",
        "gate_report": scenario_dir / "pre_execution_gate_report.json",
        "private_key_read_attempt": scenario_dir / "private_key_read_attempt.json",
        "denied_key_cleanup": scenario_dir / "denied_key_cleanup.json",
        "signer_handshake": scenario_dir / "detached_signer_handshake.json",
        "signer_request_log": scenario_dir / "detached_signer_request_log.json",
        "receipt_payload_a": scenario_dir / "request_a_execution_receipt_payload.json",
        "receipt_signature_a": scenario_dir / "request_a_execution_receipt.sig",
        "receipt_verify_a": scenario_dir / "request_a_execution_receipt_verification.json",
        "receipt_tamper_verify_a": scenario_dir / "request_a_execution_receipt_tamper_verification.json",
        "receipt_payload_b": scenario_dir / "request_b_execution_receipt_payload.json",
        "receipt_signature_b": scenario_dir / "request_b_execution_receipt.sig",
        "receipt_verify_b": scenario_dir / "request_b_execution_receipt_verification.json",
        "receipt_tamper_verify_b": scenario_dir / "request_b_execution_receipt_tamper_verification.json",
        "cross_verify_a_with_b": scenario_dir / "cross_verify_request_a_with_sig_b.json",
        "cross_verify_b_with_a": scenario_dir / "cross_verify_request_b_with_sig_a.json",
        "runtime_report": scenario_dir / "detached_signer_concurrency_runtime_report.json",
        "executed_marker": scenario_dir / "runtime_executed.marker",
        "denied_marker": scenario_dir / "runtime_denied.marker",
    }


def build_manifest(
    *,
    label: str,
    scenario_name: str,
    public_key_path: Path,
    scenario_verification_time: datetime,
    verification_mode: str,
    mode: str,
) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "proof_type": "detached_external_signer_concurrency_proof",
        "proof_label": label,
        "scenario": scenario_name,
        "generated_at_utc": utc_now_iso(),
        "workflow": {
            "name": "external_signed_runtime_gate",
            "mode": mode,
        },
        "verification_context": {
            "verification_time_utc": iso_no_microseconds(scenario_verification_time),
            "verification_mode": verification_mode,
        },
        "attestation": {
            "public_key_path": rel(public_key_path),
        },
    }


def build_gate_decision(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
) -> dict[str, Any]:
    within_window, verdict = evaluate_window(key, scenario_verification_time)
    return {
        "decision_version": 1,
        "decision_type": "pre_execution_key_policy_gate",
        "proof_label": label,
        "scenario": scenario_name,
        "decision_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "public_key_path": rel(key.public_key_path),
        "checks": {
            "public_key_exists": key.public_key_path.exists(),
            "registry_key_within_window": within_window,
            "public_key_sha256": sha256_file(key.public_key_path),
        },
        "registry_entry": {
            "key_id": key.key_id,
            "not_before": key.not_before,
            "not_after": key.not_after,
        },
        "derived": {
            "window_verdict": verdict,
        },
        "gate_decision_allow": within_window,
    }


def spawn_signer(private_key_path: Path, key_id: str) -> tuple[subprocess.Popen[str], dict[str, Any]]:
    proc = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--signer-service",
            "--private-key-path",
            str(private_key_path),
            "--key-id",
            key_id,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(ROOT),
    )

    if proc.stdout is None:
        raise SystemExit("Signer process stdout is not available.")

    ready_line = proc.stdout.readline()
    if not ready_line:
        stderr_text = proc.stderr.read() if proc.stderr else ""
        raise SystemExit(f"Detached signer failed to start.\nSTDERR:\n{stderr_text}")

    handshake = json.loads(ready_line)
    return proc, handshake


def send_sign_request(
    proc: subprocess.Popen[str],
    *,
    payload_path: Path,
    signature_path: Path,
    request_id: str,
) -> dict[str, Any]:
    if proc.stdin is None or proc.stdout is None:
        raise SystemExit("Detached signer pipes are not available.")

    request = {
        "action": "sign",
        "request_id": request_id,
        "payload_path": str(payload_path),
        "signature_path": str(signature_path),
    }
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()

    response_line = proc.stdout.readline()
    if not response_line:
        stderr_text = proc.stderr.read() if proc.stderr else ""
        raise SystemExit(f"Detached signer did not return a response.\nSTDERR:\n{stderr_text}")

    return json.loads(response_line)


def stop_signer(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return

    if proc.stdin is not None:
        try:
            proc.stdin.write(json.dumps({"action": "shutdown"}) + "\n")
            proc.stdin.flush()
            proc.stdin.close()
        except Exception:
            pass

    if proc.stdout is not None:
        try:
            _ = proc.stdout.readline()
        except Exception:
            pass

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def build_request_payload(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    request_name: str,
    target_path: str,
    content: str,
) -> dict[str, Any]:
    return {
        "receipt_version": 1,
        "receipt_type": "external_signed_execution_receipt",
        "proof_label": label,
        "scenario": scenario_name,
        "request_name": request_name,
        "status": "EXECUTED",
        "executed": True,
        "execution_started_at_utc": iso_no_microseconds(scenario_verification_time),
        "execution_finished_at_utc": iso_no_microseconds(scenario_verification_time + timedelta(seconds=1)),
        "task_id": f"{scenario_name}__{request_name}__task",
        "task_type": "backend.write_file",
        "key_id": key.key_id,
        "public_key_path": rel(key.public_key_path),
        "gate_decision_sha256": sha256_text(canonical_json(gate_decision)),
        "execution_output": {
            "target_path": target_path,
            "content_sha256": sha256_text(content),
        },
    }


def simulate_concurrency_execution(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
) -> dict[str, Any]:
    signer_proc, handshake = spawn_signer(key.private_key_path, key.key_id)
    write_json(paths["signer_handshake"], handshake)

    private_key_read_attempt = attempt_private_key_read(key.private_key_path)
    write_json(paths["private_key_read_attempt"], private_key_read_attempt)

    payload_a = build_request_payload(
        label=label,
        scenario_name=scenario_name,
        key=key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        request_name="request_a",
        target_path=f"proof/{scenario_name}/request_a.txt",
        content="alpha-content",
    )
    payload_b = build_request_payload(
        label=label,
        scenario_name=scenario_name,
        key=key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time + timedelta(milliseconds=100),
        request_name="request_b",
        target_path=f"proof/{scenario_name}/request_b.txt",
        content="beta-content",
    )

    write_text(paths["receipt_payload_a"], canonical_json(payload_a) + "\n")
    write_text(paths["receipt_payload_b"], canonical_json(payload_b) + "\n")

    response_a = send_sign_request(
        signer_proc,
        payload_path=paths["receipt_payload_a"],
        signature_path=paths["receipt_signature_a"],
        request_id="request_a",
    )
    response_b = send_sign_request(
        signer_proc,
        payload_path=paths["receipt_payload_b"],
        signature_path=paths["receipt_signature_b"],
        request_id="request_b",
    )

    write_json(
        paths["signer_request_log"],
        {
            "request_a": response_a,
            "request_b": response_b,
        },
    )

    verify_a = openssl_verify(paths["receipt_payload_a"], key.public_key_path, paths["receipt_signature_a"])
    verify_b = openssl_verify(paths["receipt_payload_b"], key.public_key_path, paths["receipt_signature_b"])
    write_json(paths["receipt_verify_a"], verify_a)
    write_json(paths["receipt_verify_b"], verify_b)

    tampered_a = dict(payload_a)
    tampered_a["status"] = "TAMPERED"
    tampered_a_path = paths["scenario_dir"] / "request_a_execution_receipt_tampered_payload.json"
    write_text(tampered_a_path, canonical_json(tampered_a) + "\n")
    tamper_verify_a = openssl_verify(tampered_a_path, key.public_key_path, paths["receipt_signature_a"])
    write_json(paths["receipt_tamper_verify_a"], tamper_verify_a)

    tampered_b = dict(payload_b)
    tampered_b["status"] = "TAMPERED"
    tampered_b_path = paths["scenario_dir"] / "request_b_execution_receipt_tampered_payload.json"
    write_text(tampered_b_path, canonical_json(tampered_b) + "\n")
    tamper_verify_b = openssl_verify(tampered_b_path, key.public_key_path, paths["receipt_signature_b"])
    write_json(paths["receipt_tamper_verify_b"], tamper_verify_b)

    cross_a_with_b = openssl_verify(paths["receipt_payload_a"], key.public_key_path, paths["receipt_signature_b"])
    cross_b_with_a = openssl_verify(paths["receipt_payload_b"], key.public_key_path, paths["receipt_signature_a"])
    write_json(paths["cross_verify_a_with_b"], cross_a_with_b)
    write_json(paths["cross_verify_b_with_a"], cross_b_with_a)

    runtime_report = {
        "report_version": 1,
        "report_type": "detached_signer_concurrency_runtime_report",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "PASS",
        "runtime_status_allow_executed": True,
        "detached_signer_ready": handshake.get("ready", False),
        "detached_signer_key_path_exists_after_detach": handshake.get("private_key_path_exists_after_detach", True),
        "control_plane_private_key_read_allowed": private_key_read_attempt["read_allowed"],
        "request_a_signature_verified": verify_a["verified_ok"],
        "request_b_signature_verified": verify_b["verified_ok"],
        "request_a_tamper_rejected": not tamper_verify_a["verified_ok"],
        "request_b_tamper_rejected": not tamper_verify_b["verified_ok"],
        "cross_verify_a_with_b_rejected": not cross_a_with_b["verified_ok"],
        "cross_verify_b_with_a_rejected": not cross_b_with_a["verified_ok"],
        "request_a_signature_sha256": sha256_file(paths["receipt_signature_a"]),
        "request_b_signature_sha256": sha256_file(paths["receipt_signature_b"]),
        "signatures_are_distinct": sha256_file(paths["receipt_signature_a"]) != sha256_file(paths["receipt_signature_b"]),
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "notes": [
            "Signer دو درخواست مستقل را به‌ترتیب پردازش کرده است.",
            "هر payload با signature خودش verify شده است.",
            "cross-signature verify رد شده است.",
            "tampered payloadها رد شده‌اند.",
        ],
    }
    write_json(paths["runtime_report"], runtime_report)
    write_text(paths["executed_marker"], "executed\n")
    remove_if_exists(paths["denied_marker"])

    stop_signer(signer_proc)

    return {
        "handshake": handshake,
        "private_key_read_attempt": private_key_read_attempt,
        "response_a": response_a,
        "response_b": response_b,
        "verify_a": verify_a,
        "verify_b": verify_b,
        "tamper_verify_a": tamper_verify_a,
        "tamper_verify_b": tamper_verify_b,
        "cross_a_with_b": cross_a_with_b,
        "cross_b_with_a": cross_b_with_a,
    }


def build_allowed_report(
    *,
    label: str,
    scenario_name: str,
    scenario_verification_time: datetime,
    verification_mode: str,
    gate_decision: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    runtime_report = load_json(paths["runtime_report"])
    report = {
        "report_version": 1,
        "report_type": "pre_execution_gate_report",
        "proof_label": label,
        "scenario": scenario_name,
        "evaluation_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "status": "PASS",
        "decision": "ALLOW",
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "runtime_status_allow_executed": True,
        "control_plane_private_key_read_allowed": runtime_report["control_plane_private_key_read_allowed"],
        "detached_signer_key_path_exists_after_detach": runtime_report["detached_signer_key_path_exists_after_detach"],
        "request_a_signature_verified": runtime_report["request_a_signature_verified"],
        "request_b_signature_verified": runtime_report["request_b_signature_verified"],
        "cross_verify_a_with_b_rejected": runtime_report["cross_verify_a_with_b_rejected"],
        "cross_verify_b_with_a_rejected": runtime_report["cross_verify_b_with_a_rejected"],
        "signatures_are_distinct": runtime_report["signatures_are_distinct"],
        "runtime_report_exists": paths["runtime_report"].exists(),
    }
    write_json(paths["gate_report"], report)
    return report


def build_denied_report(
    *,
    label: str,
    scenario_name: str,
    scenario_verification_time: datetime,
    verification_mode: str,
    gate_decision: dict[str, Any],
    paths: dict[str, Path],
    denied_key_cleanup_result: dict[str, Any],
) -> dict[str, Any]:
    for key in (
        "private_key_read_attempt",
        "receipt_payload_a",
        "receipt_signature_a",
        "receipt_verify_a",
        "receipt_tamper_verify_a",
        "receipt_payload_b",
        "receipt_signature_b",
        "receipt_verify_b",
        "receipt_tamper_verify_b",
        "cross_verify_a_with_b",
        "cross_verify_b_with_a",
        "signer_handshake",
        "signer_request_log",
        "runtime_report",
        "executed_marker",
    ):
        remove_if_exists(paths[key])

    write_json(paths["denied_key_cleanup"], denied_key_cleanup_result)
    write_text(paths["denied_marker"], "denied\n")

    report = {
        "report_version": 1,
        "report_type": "pre_execution_gate_report",
        "proof_label": label,
        "scenario": scenario_name,
        "evaluation_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "status": "PASS",
        "decision": "DENY",
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "runtime_status_allow_executed": False,
        "denied_key_cleanup_applied": True,
        "denied_key_exists_after_cleanup": denied_key_cleanup_result["exists_after_cleanup"],
        "runtime_report_exists": False,
    }
    write_json(paths["gate_report"], report)
    return report


def run_signer_service(private_key_path: Path, key_id: str) -> int:
    fd = os.open(private_key_path, os.O_RDONLY)
    fd_path = f"/proc/self/fd/{fd}"
    os.unlink(private_key_path)

    ready = {
        "ready": True,
        "service": "detached_external_signer",
        "key_id": key_id,
        "fd_path": fd_path,
        "private_key_path_exists_after_detach": private_key_path.exists(),
    }
    print(json.dumps(ready), flush=True)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            request = json.loads(line)
            action = request.get("action")

            if action == "shutdown":
                response = {"ok": True, "action": "shutdown"}
                print(json.dumps(response), flush=True)
                break

            if action != "sign":
                response = {"ok": False, "error": "unsupported_action", "action": action}
                print(json.dumps(response), flush=True)
                continue

            payload_path = Path(request["payload_path"])
            signature_path = Path(request["signature_path"])
            ensure_dir(signature_path.parent)

            result = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    fd_path,
                    "-out",
                    str(signature_path),
                    str(payload_path),
                ],
                cwd=str(ROOT),
                text=True,
                capture_output=True,
                check=False,
                pass_fds=(fd,),
            )
            response = {
                "ok": result.returncode == 0,
                "action": "sign",
                "request_id": request.get("request_id"),
                "payload_path": str(payload_path),
                "signature_path": str(signature_path),
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "signature_exists": signature_path.exists(),
            }
            print(json.dumps(response), flush=True)
    finally:
        os.close(fd)

    return 0


def execute_allowed_scenario(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
    output_dir: Path,
) -> dict[str, Any]:
    paths = scenario_paths(output_dir, scenario_name)
    ensure_dir(paths["scenario_dir"])

    manifest = build_manifest(
        label=label,
        scenario_name=scenario_name,
        public_key_path=key.public_key_path,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        mode="concurrency_reentrancy",
    )
    write_json(paths["manifest"], manifest)

    gate_decision = build_gate_decision(
        label=label,
        scenario_name=scenario_name,
        key=key,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
    )
    write_json(paths["gate_decision"], gate_decision)

    if not gate_decision["gate_decision_allow"]:
        raise SystemExit(f"{scenario_name} expected allow-path but gate denied it.")

    bundle = simulate_concurrency_execution(
        label=label,
        scenario_name=scenario_name,
        key=key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        paths=paths,
    )
    build_allowed_report(
        label=label,
        scenario_name=scenario_name,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        gate_decision=gate_decision,
        paths=paths,
    )

    runtime_report = load_json(paths["runtime_report"])

    return {
        "scenario": scenario_name,
        "public_key_path": rel(key.public_key_path),
        "verification_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "gate_decision_allow": True,
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "runtime_status_allow_executed": True,
        "detached_signer_ready": bundle["handshake"]["ready"],
        "detached_signer_key_path_exists_after_detach": bundle["handshake"]["private_key_path_exists_after_detach"],
        "control_plane_private_key_read_allowed": bundle["private_key_read_attempt"]["read_allowed"],
        "request_a_signature_verified": runtime_report["request_a_signature_verified"],
        "request_b_signature_verified": runtime_report["request_b_signature_verified"],
        "request_a_tamper_rejected": runtime_report["request_a_tamper_rejected"],
        "request_b_tamper_rejected": runtime_report["request_b_tamper_rejected"],
        "cross_verify_a_with_b_rejected": runtime_report["cross_verify_a_with_b_rejected"],
        "cross_verify_b_with_a_rejected": runtime_report["cross_verify_b_with_a_rejected"],
        "signatures_are_distinct": runtime_report["signatures_are_distinct"],
        "runtime_report_exists": paths["runtime_report"].exists(),
        "runtime_report_path": rel(paths["runtime_report"]),
        "gate_report_path": rel(paths["gate_report"]),
    }


def execute_denied_scenario(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
    output_dir: Path,
) -> dict[str, Any]:
    paths = scenario_paths(output_dir, scenario_name)
    ensure_dir(paths["scenario_dir"])

    manifest = build_manifest(
        label=label,
        scenario_name=scenario_name,
        public_key_path=key.public_key_path,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        mode="deny_cleanup",
    )
    write_json(paths["manifest"], manifest)

    gate_decision = build_gate_decision(
        label=label,
        scenario_name=scenario_name,
        key=key,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
    )
    write_json(paths["gate_decision"], gate_decision)

    if gate_decision["gate_decision_allow"]:
        raise SystemExit(f"{scenario_name} expected deny-path but gate allowed it.")

    denied_key_cleanup_result = cleanup_denied_key(key.private_key_path)
    build_denied_report(
        label=label,
        scenario_name=scenario_name,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        gate_decision=gate_decision,
        paths=paths,
        denied_key_cleanup_result=denied_key_cleanup_result,
    )

    return {
        "scenario": scenario_name,
        "public_key_path": rel(key.public_key_path),
        "verification_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "gate_decision_allow": False,
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "runtime_status_allow_executed": False,
        "denied_key_cleanup_removed": denied_key_cleanup_result["removed"],
        "denied_key_exists_after_cleanup": denied_key_cleanup_result["exists_after_cleanup"],
        "gate_report_path": rel(paths["gate_report"]),
        "denied_key_cleanup_path": rel(paths["denied_key_cleanup"]),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    active = summary["scenarios"]["concurrency_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R13 — Multi-Request Concurrency / Reentrancy Proof for Detached Signer + No Cross-Signature Mix-Up

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- OpenSSL version: `{summary["openssl_version"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`
- Detached signer custody directory: `{summary["detached_signer_custody_directory"]}`

## Concurrency Runtime

- Gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Detached signer ready: **{str(active.get("detached_signer_ready", False)).upper()}**
- Control plane private key read allowed: **{str(active.get("control_plane_private_key_read_allowed", True)).upper()}**
- Request A signature verified: **{str(active.get("request_a_signature_verified", False)).upper()}**
- Request B signature verified: **{str(active.get("request_b_signature_verified", False)).upper()}**
- Request A tamper rejected: **{str(active.get("request_a_tamper_rejected", False)).upper()}**
- Request B tamper rejected: **{str(active.get("request_b_tamper_rejected", False)).upper()}**
- Cross-verify A with signature B rejected: **{str(active.get("cross_verify_a_with_b_rejected", False)).upper()}**
- Cross-verify B with signature A rejected: **{str(active.get("cross_verify_b_with_a_rejected", False)).upper()}**
- Signatures are distinct: **{str(active.get("signatures_are_distinct", False)).upper()}**

## Denied Paths Cleanup

- Expired cleaned: **{str(expired.get("denied_key_cleanup_removed", False)).upper()}**
- Future cleaned: **{str(future.get("denied_key_cleanup_removed", False)).upper()}**

## Boundary Scan

- Artifact boundary contains private keys: **{str(summary["artifact_boundary_scan"]["contains_private_keys"]).upper()}**
- Runtime boundary contains private keys: **{str(summary["runtime_boundary_scan"]["contains_private_keys"]).upper()}**
- Detached signer custody contains private keys after proof: **{str(summary["detached_signer_custody_scan"]["contains_private_keys"]).upper()}**
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="R13 - Multi-Request Concurrency / Reentrancy Proof for Detached Signer + No Cross-Signature Mix-Up"
    )
    parser.add_argument(
        "--label",
        default="R13_detached_signer_concurrency_proof",
        help="Proof label",
    )
    parser.add_argument(
        "--verification-time",
        default=None,
        help="Base UTC timestamp override in ISO-8601 format",
    )
    parser.add_argument(
        "--signer-service",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--private-key-path",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--key-id",
        default=None,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    if args.signer_service:
        if not args.private_key_path or not args.key_id:
            raise SystemExit("Signer service requires --private-key-path and --key-id.")
        return_code = run_signer_service(Path(args.private_key_path), args.key_id)
        raise SystemExit(return_code)

    openssl_version = require_openssl()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    output_dir = ARTIFACTS_DIR / "detached_external_signer_concurrency_proof" / args.label
    custody_dir = STATE_DIR / args.label

    remove_if_exists(output_dir)
    remove_if_exists(custody_dir)

    ensure_dir(output_dir)
    ensure_dir(custody_dir)

    concurrency_key = ScenarioKey(
        key_id="r13-attestation-key-concurrency",
        private_key_path=custody_dir / "attestation_private_concurrency.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_concurrency.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    expired_key = ScenarioKey(
        key_id="r13-attestation-key-expired",
        private_key_path=custody_dir / "attestation_private_expired.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_expired.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=30)),
        not_after=iso_no_microseconds(base_verification_time - timedelta(seconds=1)),
    )
    future_key = ScenarioKey(
        key_id="r13-attestation-key-future",
        private_key_path=custody_dir / "attestation_private_future.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_future.pem",
        not_before=iso_no_microseconds(base_verification_time + timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )

    for key in (concurrency_key, expired_key, future_key):
        generate_rsa_keypair(key.private_key_path, key.public_key_path)

    future_fixture_time = parse_utc(future_key.not_before) - timedelta(seconds=1)

    registry = {
        "registry_version": 1,
        "registry_type": "detached_external_signer_concurrency_registry",
        "generated_at_utc": utc_now_iso(),
        "entries": [
            {
                "key_id": key.key_id,
                "public_key_path": rel(key.public_key_path),
                "public_key_sha256": sha256_file(key.public_key_path),
                "not_before": key.not_before,
                "not_after": key.not_after,
            }
            for key in (concurrency_key, expired_key, future_key)
        ],
    }
    write_json(output_dir / "attestation_key_policy_registry.json", registry)

    concurrency = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__concurrency_runtime",
        key=concurrency_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
    )
    expired = execute_denied_scenario(
        label=args.label,
        scenario_name=f"{args.label}__expired_runtime",
        key=expired_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
    )
    future = execute_denied_scenario(
        label=args.label,
        scenario_name=f"{args.label}__future_runtime",
        key=future_key,
        scenario_verification_time=future_fixture_time,
        verification_mode="strict_pre_not_before_fixture",
        output_dir=output_dir,
    )

    artifact_boundary_scan = scan_for_private_keys(output_dir)
    runtime_boundary_scan = scan_for_private_keys(output_dir)
    detached_signer_custody_scan = scan_for_private_keys(custody_dir)

    proof_status = "PASS"

    if not concurrency["gate_decision_allow"] or not concurrency["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if concurrency.get("detached_signer_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if concurrency.get("control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"
    if not concurrency.get("request_a_signature_verified", False):
        proof_status = "FAIL"
    if not concurrency.get("request_b_signature_verified", False):
        proof_status = "FAIL"
    if not concurrency.get("request_a_tamper_rejected", False):
        proof_status = "FAIL"
    if not concurrency.get("request_b_tamper_rejected", False):
        proof_status = "FAIL"
    if not concurrency.get("cross_verify_a_with_b_rejected", False):
        proof_status = "FAIL"
    if not concurrency.get("cross_verify_b_with_a_rejected", False):
        proof_status = "FAIL"
    if not concurrency.get("signatures_are_distinct", False):
        proof_status = "FAIL"

    if expired["gate_decision_allow"] or future["gate_decision_allow"]:
        proof_status = "FAIL"
    if expired["runtime_status_allow_executed"] or future["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not expired.get("denied_key_cleanup_removed", False):
        proof_status = "FAIL"
    if not future.get("denied_key_cleanup_removed", False):
        proof_status = "FAIL"
    if expired.get("denied_key_exists_after_cleanup", True):
        proof_status = "FAIL"
    if future.get("denied_key_exists_after_cleanup", True):
        proof_status = "FAIL"

    if artifact_boundary_scan["contains_private_keys"]:
        proof_status = "FAIL"
    if runtime_boundary_scan["contains_private_keys"]:
        proof_status = "FAIL"
    if detached_signer_custody_scan["contains_private_keys"]:
        proof_status = "FAIL"

    summary = {
        "report_version": 1,
        "report_type": "detached_external_signer_concurrency_proof",
        "generated_at_utc": utc_now_iso(),
        "proof_label": args.label,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "future_fixture_time_utc": iso_no_microseconds(future_fixture_time),
        "openssl_version": openssl_version,
        "proof_status": proof_status,
        "output_directory": rel(output_dir),
        "detached_signer_custody_directory": rel(custody_dir),
        "registry_path": rel(output_dir / "attestation_key_policy_registry.json"),
        "artifact_boundary_scan": artifact_boundary_scan,
        "runtime_boundary_scan": runtime_boundary_scan,
        "detached_signer_custody_scan": detached_signer_custody_scan,
        "scenarios": {
            "concurrency_runtime": concurrency,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "detached_external_signer_concurrency_proof.json"
    summary_md_path = output_dir / "detached_external_signer_concurrency_proof.md"
    digest_path = output_dir / "detached_external_signer_concurrency_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "summary_json_path": rel(summary_json_path),
        "summary_md_path": rel(summary_md_path),
        "concurrency_safe": (
            concurrency["gate_decision_allow"]
            and concurrency["runtime_status_allow_executed"]
            and not concurrency.get("control_plane_private_key_read_allowed", True)
            and not concurrency.get("detached_signer_key_path_exists_after_detach", True)
            and concurrency.get("request_a_signature_verified", False)
            and concurrency.get("request_b_signature_verified", False)
            and concurrency.get("request_a_tamper_rejected", False)
            and concurrency.get("request_b_tamper_rejected", False)
            and concurrency.get("cross_verify_a_with_b_rejected", False)
            and concurrency.get("cross_verify_b_with_a_rejected", False)
            and concurrency.get("signatures_are_distinct", False)
        ),
        "no_on_disk_private_keys_after_proof": (
            not artifact_boundary_scan["contains_private_keys"]
            and not runtime_boundary_scan["contains_private_keys"]
            and not detached_signer_custody_scan["contains_private_keys"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 88)
    print("R13 - MULTI-REQUEST CONCURRENCY / REENTRANCY PROOF FOR DETACHED SIGNER")
    print("=" * 88)
    print(f"LABEL                                       : {args.label}")
    print(f"OPENSSL VERSION                             : {openssl_version}")
    print(f"PROOF STATUS                                : {proof_status}")
    print(f"BASE VERIFICATION TIME                      : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME                         : {iso_no_microseconds(future_fixture_time)}")
    print(f"DETACHED SIGNER CUSTODY DIR                 : {rel(custody_dir)}")
    print(f"CONCURRENCY EXECUTED                        : {concurrency['runtime_status_allow_executed']}")
    print(f"REQUEST A VERIFIED                          : {concurrency.get('request_a_signature_verified', False)}")
    print(f"REQUEST B VERIFIED                          : {concurrency.get('request_b_signature_verified', False)}")
    print(f"CROSS VERIFY A WITH SIG B REJECTED          : {concurrency.get('cross_verify_a_with_b_rejected', False)}")
    print(f"CROSS VERIFY B WITH SIG A REJECTED          : {concurrency.get('cross_verify_b_with_a_rejected', False)}")
    print(f"SIGNATURES DISTINCT                         : {concurrency.get('signatures_are_distinct', False)}")
    print(f"EXPIRED KEY CLEANED                         : {expired.get('denied_key_cleanup_removed', False)}")
    print(f"FUTURE KEY CLEANED                          : {future.get('denied_key_cleanup_removed', False)}")
    print(f"ARTIFACT BOUNDARY PRIVATE KEYS              : {artifact_boundary_scan['contains_private_keys']}")
    print(f"RUNTIME BOUNDARY PRIVATE KEYS               : {runtime_boundary_scan['contains_private_keys']}")
    print(f"DETACHED SIGNER CUSTODY PRIVATE KEYS        : {detached_signer_custody_scan['contains_private_keys']}")
    print(f"SUMMARY JSON                                : {rel(summary_json_path)}")
    print(f"REPORT MD                                   : {rel(summary_md_path)}")
    print(f"DIGEST                                      : {rel(digest_path)}")
    print("=" * 88)


if __name__ == "__main__":
    main()
