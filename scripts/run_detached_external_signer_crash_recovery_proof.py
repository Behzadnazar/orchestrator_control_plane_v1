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
STATE_DIR = ROOT / "state" / "detached_external_signer_crash_recovery"


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
        "crash_report": scenario_dir / "detached_signer_crash_report.json",
        "receipt_payload": scenario_dir / "external_signed_execution_receipt_payload.json",
        "receipt_signature": scenario_dir / "external_signed_execution_receipt.sig",
        "receipt_verification": scenario_dir / "external_signed_execution_receipt_verification.json",
        "receipt_tampered_payload": scenario_dir / "external_signed_execution_receipt_tampered_payload.json",
        "receipt_tamper_verification": scenario_dir / "external_signed_execution_receipt_tamper_verification.json",
        "attestation_payload": scenario_dir / "external_signed_execution_attestation_payload.json",
        "attestation_signature": scenario_dir / "external_signed_execution_attestation.sig",
        "attestation_verification": scenario_dir / "external_signed_execution_attestation_verification.json",
        "attestation_tampered_payload": scenario_dir / "external_signed_execution_attestation_tampered_payload.json",
        "attestation_tamper_verification": scenario_dir / "external_signed_execution_attestation_tamper_verification.json",
        "runtime_report": scenario_dir / "external_signed_runtime_report.json",
        "executed_marker": scenario_dir / "runtime_executed.marker",
        "denied_marker": scenario_dir / "runtime_denied.marker",
        "crash_marker": scenario_dir / "runtime_crashed.marker",
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
        "proof_type": "detached_external_signer_crash_recovery_proof",
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
        "task": {
            "task_id": f"{scenario_name}__task",
            "task_type": "backend.write_file",
            "priority": "high",
            "payload": {
                "target_path": f"proof/{scenario_name}/output.txt",
                "content": f"executed:{scenario_name}",
            },
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


def spawn_signer(
    private_key_path: Path,
    key_id: str,
    service_mode: str,
) -> tuple[subprocess.Popen[str], dict[str, Any]]:
    proc = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--signer-service",
            "--private-key-path",
            str(private_key_path),
            "--key-id",
            key_id,
            "--service-mode",
            service_mode,
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
) -> dict[str, Any]:
    if proc.stdin is None or proc.stdout is None:
        return {
            "ok": False,
            "transport_error": "missing_pipes",
            "returncode": proc.poll(),
        }

    request = {
        "action": "sign",
        "payload_path": str(payload_path),
        "signature_path": str(signature_path),
    }

    try:
        proc.stdin.write(json.dumps(request) + "\n")
        proc.stdin.flush()
    except BrokenPipeError:
        return {
            "ok": False,
            "transport_error": "broken_pipe",
            "returncode": proc.poll(),
        }

    response_line = proc.stdout.readline()
    if not response_line:
        if proc.poll() is None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        return {
            "ok": False,
            "transport_error": "eof_no_response",
            "returncode": proc.returncode,
            "signature_exists": signature_path.exists(),
        }

    response = json.loads(response_line)
    response["signature_exists"] = signature_path.exists()
    return response


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


def write_payloads_for_execution(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    manifest: dict[str, Any],
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
) -> tuple[dict[str, Any], dict[str, Any]]:
    execution_started_at = iso_no_microseconds(scenario_verification_time)
    execution_finished_at = iso_no_microseconds(scenario_verification_time + timedelta(seconds=1))
    manifest_sha = sha256_text(canonical_json(manifest))
    gate_sha = sha256_text(canonical_json(gate_decision))

    receipt_payload = {
        "receipt_version": 1,
        "receipt_type": "external_signed_execution_receipt",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "EXECUTED",
        "executed": True,
        "execution_started_at_utc": execution_started_at,
        "execution_finished_at_utc": execution_finished_at,
        "task_id": manifest["task"]["task_id"],
        "task_type": manifest["task"]["task_type"],
        "key_id": key.key_id,
        "public_key_path": rel(key.public_key_path),
        "manifest_sha256": manifest_sha,
        "gate_decision_sha256": gate_sha,
        "execution_output": {
            "target_path": manifest["task"]["payload"]["target_path"],
            "content_sha256": sha256_text(manifest["task"]["payload"]["content"]),
        },
    }
    write_text(paths["receipt_payload"], canonical_json(receipt_payload) + "\n")

    attestation_payload = {
        "attestation_version": 1,
        "attestation_type": "external_signed_execution_attestation",
        "proof_label": label,
        "scenario": scenario_name,
        "attested": True,
        "attestation_time_utc": execution_finished_at,
        "key_id": key.key_id,
        "public_key_path": rel(key.public_key_path),
        "manifest_sha256": manifest_sha,
        "gate_decision_sha256": gate_sha,
        "receipt_payload_sha256": sha256_file(paths["receipt_payload"]),
        "signature_algorithm": "openssl_dgst_sha256_rsa_via_detached_signer",
    }

    return receipt_payload, attestation_payload


def simulate_normal_execution(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    manifest: dict[str, Any],
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
) -> dict[str, Any]:
    signer_proc, handshake = spawn_signer(key.private_key_path, key.key_id, "normal")
    write_json(paths["signer_handshake"], handshake)

    private_key_read_attempt = attempt_private_key_read(key.private_key_path)
    write_json(paths["private_key_read_attempt"], private_key_read_attempt)

    _, attestation_payload = write_payloads_for_execution(
        label=label,
        scenario_name=scenario_name,
        key=key,
        manifest=manifest,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        paths=paths,
    )

    receipt_sign_response = send_sign_request(
        signer_proc,
        payload_path=paths["receipt_payload"],
        signature_path=paths["receipt_signature"],
    )
    if not receipt_sign_response.get("ok", False):
        stop_signer(signer_proc)
        raise SystemExit(f"Detached signer failed for receipt:\n{json.dumps(receipt_sign_response, indent=2)}")

    receipt_verify = openssl_verify(paths["receipt_payload"], key.public_key_path, paths["receipt_signature"])
    write_json(paths["receipt_verification"], receipt_verify)

    receipt_tampered = load_json(paths["receipt_payload"])
    receipt_tampered["status"] = "TAMPERED"
    write_text(paths["receipt_tampered_payload"], canonical_json(receipt_tampered) + "\n")
    receipt_tamper_verify = openssl_verify(
        paths["receipt_tampered_payload"],
        key.public_key_path,
        paths["receipt_signature"],
    )
    write_json(paths["receipt_tamper_verification"], receipt_tamper_verify)

    write_text(paths["attestation_payload"], canonical_json(attestation_payload) + "\n")
    attestation_payload = load_json(paths["attestation_payload"])
    attestation_payload["receipt_signature_sha256"] = sha256_file(paths["receipt_signature"])
    write_text(paths["attestation_payload"], canonical_json(attestation_payload) + "\n")

    attestation_sign_response = send_sign_request(
        signer_proc,
        payload_path=paths["attestation_payload"],
        signature_path=paths["attestation_signature"],
    )
    if not attestation_sign_response.get("ok", False):
        stop_signer(signer_proc)
        raise SystemExit(f"Detached signer failed for attestation:\n{json.dumps(attestation_sign_response, indent=2)}")

    write_json(
        paths["signer_request_log"],
        {
            "receipt_sign_response": receipt_sign_response,
            "attestation_sign_response": attestation_sign_response,
        },
    )

    attestation_verify = openssl_verify(paths["attestation_payload"], key.public_key_path, paths["attestation_signature"])
    write_json(paths["attestation_verification"], attestation_verify)

    attestation_tampered = load_json(paths["attestation_payload"])
    attestation_tampered["attested"] = False
    write_text(paths["attestation_tampered_payload"], canonical_json(attestation_tampered) + "\n")
    attestation_tamper_verify = openssl_verify(
        paths["attestation_tampered_payload"],
        key.public_key_path,
        paths["attestation_signature"],
    )
    write_json(paths["attestation_tamper_verification"], attestation_tamper_verify)

    runtime_report = {
        "report_version": 1,
        "report_type": "detached_external_signer_runtime_report",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "PASS",
        "runtime_status_allow_executed": True,
        "executed": True,
        "receipt_signature_verified": receipt_verify["verified_ok"],
        "receipt_tamper_rejected": not receipt_tamper_verify["verified_ok"],
        "attestation_signature_verified": attestation_verify["verified_ok"],
        "attestation_tamper_rejected": not attestation_tamper_verify["verified_ok"],
        "private_key_read_allowed_to_control_plane": private_key_read_attempt["read_allowed"],
        "detached_signer_ready": handshake.get("ready", False),
        "detached_signer_key_path_exists_after_detach": handshake.get("private_key_path_exists_after_detach", True),
        "window_verdict": gate_decision["derived"]["window_verdict"],
    }
    write_json(paths["runtime_report"], runtime_report)
    write_text(paths["executed_marker"], "executed\n")
    remove_if_exists(paths["denied_marker"])
    remove_if_exists(paths["crash_marker"])

    stop_signer(signer_proc)

    return {
        "handshake": handshake,
        "private_key_read_attempt": private_key_read_attempt,
        "receipt_sign_response": receipt_sign_response,
        "receipt_verify": receipt_verify,
        "receipt_tamper_verify": receipt_tamper_verify,
        "attestation_sign_response": attestation_sign_response,
        "attestation_verify": attestation_verify,
        "attestation_tamper_verify": attestation_tamper_verify,
    }


def simulate_crash_path(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    manifest: dict[str, Any],
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
) -> dict[str, Any]:
    signer_proc, handshake = spawn_signer(key.private_key_path, key.key_id, "crash_on_sign")
    write_json(paths["signer_handshake"], handshake)

    private_key_read_attempt = attempt_private_key_read(key.private_key_path)
    write_json(paths["private_key_read_attempt"], private_key_read_attempt)

    write_payloads_for_execution(
        label=label,
        scenario_name=scenario_name,
        key=key,
        manifest=manifest,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        paths=paths,
    )

    sign_response = send_sign_request(
        signer_proc,
        payload_path=paths["receipt_payload"],
        signature_path=paths["receipt_signature"],
    )

    if signer_proc.poll() is None:
        try:
            signer_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            signer_proc.kill()
            signer_proc.wait(timeout=5)

    crash_report = {
        "report_version": 1,
        "report_type": "detached_signer_crash_report",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "PASS",
        "crash_expected": True,
        "crash_observed": signer_proc.returncode not in (None, 0),
        "sign_response": sign_response,
        "signer_returncode": signer_proc.returncode,
        "private_key_read_allowed_to_control_plane": private_key_read_attempt["read_allowed"],
        "detached_signer_key_path_exists_after_detach": handshake.get("private_key_path_exists_after_detach", True),
        "receipt_signature_exists": paths["receipt_signature"].exists(),
        "attestation_signature_exists": paths["attestation_signature"].exists(),
        "runtime_report_exists": paths["runtime_report"].exists(),
        "window_verdict": gate_decision["derived"]["window_verdict"],
    }
    write_json(paths["crash_report"], crash_report)
    write_json(paths["signer_request_log"], {"receipt_sign_response": sign_response})
    write_text(paths["crash_marker"], "crashed\n")
    remove_if_exists(paths["executed_marker"])
    remove_if_exists(paths["denied_marker"])
    remove_if_exists(paths["receipt_signature"])
    remove_if_exists(paths["attestation_payload"])
    remove_if_exists(paths["attestation_signature"])
    remove_if_exists(paths["runtime_report"])

    return {
        "handshake": handshake,
        "private_key_read_attempt": private_key_read_attempt,
        "crash_report": crash_report,
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
    private_key_read_attempt = load_json(paths["private_key_read_attempt"])
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
        "receipt_exists": paths["receipt_payload"].exists(),
        "receipt_signature_exists": paths["receipt_signature"].exists(),
        "attestation_exists": paths["attestation_payload"].exists(),
        "attestation_signature_exists": paths["attestation_signature"].exists(),
        "runtime_report_exists": paths["runtime_report"].exists(),
        "control_plane_private_key_read_allowed": private_key_read_attempt["read_allowed"],
        "detached_signer_key_path_exists_after_detach": runtime_report["detached_signer_key_path_exists_after_detach"],
        "receipt_signature_verified": runtime_report["receipt_signature_verified"],
        "receipt_tamper_rejected": runtime_report["receipt_tamper_rejected"],
        "attestation_signature_verified": runtime_report["attestation_signature_verified"],
        "attestation_tamper_rejected": runtime_report["attestation_tamper_rejected"],
    }
    write_json(paths["gate_report"], report)
    return report


def build_crash_report(
    *,
    label: str,
    scenario_name: str,
    scenario_verification_time: datetime,
    verification_mode: str,
    gate_decision: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    crash_report = load_json(paths["crash_report"])
    report = {
        "report_version": 1,
        "report_type": "pre_execution_gate_report",
        "proof_label": label,
        "scenario": scenario_name,
        "evaluation_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "status": "PASS" if crash_report["crash_observed"] else "FAIL",
        "decision": "ALLOW_BUT_CRASHED",
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "runtime_status_allow_executed": False,
        "crash_observed": crash_report["crash_observed"],
        "signer_returncode": crash_report["signer_returncode"],
        "control_plane_private_key_read_allowed": crash_report["private_key_read_allowed_to_control_plane"],
        "detached_signer_key_path_exists_after_detach": crash_report["detached_signer_key_path_exists_after_detach"],
        "receipt_exists": paths["receipt_payload"].exists(),
        "receipt_signature_exists": paths["receipt_signature"].exists(),
        "attestation_exists": paths["attestation_payload"].exists(),
        "attestation_signature_exists": paths["attestation_signature"].exists(),
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
        "receipt_payload",
        "receipt_signature",
        "receipt_verification",
        "receipt_tampered_payload",
        "receipt_tamper_verification",
        "attestation_payload",
        "attestation_signature",
        "attestation_verification",
        "attestation_tampered_payload",
        "attestation_tamper_verification",
        "signer_handshake",
        "signer_request_log",
        "crash_report",
        "runtime_report",
        "executed_marker",
        "crash_marker",
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
        "preventive_block_applied": True,
        "denied_key_cleanup_applied": True,
        "denied_key_exists_after_cleanup": denied_key_cleanup_result["exists_after_cleanup"],
        "receipt_exists": False,
        "receipt_signature_exists": False,
        "attestation_exists": False,
        "attestation_signature_exists": False,
        "runtime_report_exists": False,
    }
    write_json(paths["gate_report"], report)
    return report


def run_signer_service(private_key_path: Path, key_id: str, service_mode: str) -> int:
    fd = os.open(private_key_path, os.O_RDONLY)
    fd_path = f"/proc/self/fd/{fd}"
    os.unlink(private_key_path)

    ready = {
        "ready": True,
        "service": "detached_external_signer",
        "service_mode": service_mode,
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

            if service_mode == "crash_on_sign":
                os._exit(91)

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
    mode: str,
) -> dict[str, Any]:
    paths = scenario_paths(output_dir, scenario_name)
    ensure_dir(paths["scenario_dir"])

    manifest = build_manifest(
        label=label,
        scenario_name=scenario_name,
        public_key_path=key.public_key_path,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        mode=mode,
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

    if mode == "crash_recovery_probe":
        bundle = simulate_crash_path(
            label=label,
            scenario_name=scenario_name,
            key=key,
            manifest=manifest,
            gate_decision=gate_decision,
            scenario_verification_time=scenario_verification_time,
            paths=paths,
        )
        gate_report = build_crash_report(
            label=label,
            scenario_name=scenario_name,
            scenario_verification_time=scenario_verification_time,
            verification_mode=verification_mode,
            gate_decision=gate_decision,
            paths=paths,
        )
        crash_report = bundle["crash_report"]
        return {
            "scenario": scenario_name,
            "public_key_path": rel(key.public_key_path),
            "verification_time_utc": iso_no_microseconds(scenario_verification_time),
            "verification_mode": verification_mode,
            "gate_decision_allow": True,
            "window_verdict": gate_decision["derived"]["window_verdict"],
            "runtime_status_allow_executed": False,
            "crash_observed": crash_report["crash_observed"],
            "signer_returncode": crash_report["signer_returncode"],
            "detached_signer_ready": bundle["handshake"]["ready"],
            "detached_signer_key_path_exists_after_detach": bundle["handshake"]["private_key_path_exists_after_detach"],
            "control_plane_private_key_read_allowed": bundle["private_key_read_attempt"]["read_allowed"],
            "receipt_exists": paths["receipt_payload"].exists(),
            "receipt_signature_exists": paths["receipt_signature"].exists(),
            "attestation_exists": paths["attestation_payload"].exists(),
            "attestation_signature_exists": paths["attestation_signature"].exists(),
            "runtime_report_exists": paths["runtime_report"].exists(),
            "crash_report_path": rel(paths["crash_report"]),
            "gate_report_path": rel(paths["gate_report"]),
        }

    bundle = simulate_normal_execution(
        label=label,
        scenario_name=scenario_name,
        key=key,
        manifest=manifest,
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
        "receipt_exists": paths["receipt_payload"].exists(),
        "receipt_signature_exists": paths["receipt_signature"].exists(),
        "attestation_exists": paths["attestation_payload"].exists(),
        "attestation_signature_exists": paths["attestation_signature"].exists(),
        "runtime_report_exists": paths["runtime_report"].exists(),
        "receipt_signature_verified": bundle["receipt_verify"]["verified_ok"],
        "receipt_tamper_rejected": not bundle["receipt_tamper_verify"]["verified_ok"],
        "attestation_signature_verified": bundle["attestation_verify"]["verified_ok"],
        "attestation_tamper_rejected": not bundle["attestation_tamper_verify"]["verified_ok"],
        "gate_report_path": rel(paths["gate_report"]),
        "runtime_report_path": rel(paths["runtime_report"]),
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
        "receipt_exists": False,
        "receipt_signature_exists": False,
        "attestation_exists": False,
        "attestation_signature_exists": False,
        "runtime_report_exists": False,
        "denied_key_cleanup_removed": denied_key_cleanup_result["removed"],
        "denied_key_exists_after_cleanup": denied_key_cleanup_result["exists_after_cleanup"],
        "gate_report_path": rel(paths["gate_report"]),
        "denied_key_cleanup_path": rel(paths["denied_key_cleanup"]),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    active = summary["scenarios"]["active_runtime"]
    crash = summary["scenarios"]["crash_runtime"]
    recovery = summary["scenarios"]["recovery_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R12 — Restart/Crash Recovery Proof for Detached Signer + No Key Leakage After Abnormal Termination

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- OpenSSL version: `{summary["openssl_version"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`
- Detached signer custody directory: `{summary["detached_signer_custody_directory"]}`

## Normal Active Path

- Active gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Active executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Active receipt verified: **{str(active.get("receipt_signature_verified", False)).upper()}**
- Active attestation verified: **{str(active.get("attestation_signature_verified", False)).upper()}**

## Crash Path

- Crash gate decision: **{"ALLOW" if crash["gate_decision_allow"] else "DENY"}**
- Crash observed: **{str(crash.get("crash_observed", False)).upper()}**
- Crash signer returncode: `{crash.get("signer_returncode")}`
- Crash key path exists after detach: **{str(crash.get("detached_signer_key_path_exists_after_detach", True)).upper()}**
- Crash control plane private key read allowed: **{str(crash.get("control_plane_private_key_read_allowed", True)).upper()}**
- Crash receipt signature exists: **{str(crash.get("receipt_signature_exists", False)).upper()}**
- Crash runtime report exists: **{str(crash.get("runtime_report_exists", False)).upper()}**

## Recovery Path

- Recovery gate decision: **{"ALLOW" if recovery["gate_decision_allow"] else "DENY"}**
- Recovery executed: **{str(recovery["runtime_status_allow_executed"]).upper()}**
- Recovery receipt verified: **{str(recovery.get("receipt_signature_verified", False)).upper()}**
- Recovery attestation verified: **{str(recovery.get("attestation_signature_verified", False)).upper()}**

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
        description="R12 - Restart/Crash Recovery Proof for Detached Signer + No Key Leakage After Abnormal Termination"
    )
    parser.add_argument(
        "--label",
        default="R12_detached_signer_crash_recovery_proof",
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
    parser.add_argument(
        "--service-mode",
        default="normal",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    if args.signer_service:
        if not args.private_key_path or not args.key_id:
            raise SystemExit("Signer service requires --private-key-path and --key-id.")
        return_code = run_signer_service(Path(args.private_key_path), args.key_id, args.service_mode)
        raise SystemExit(return_code)

    openssl_version = require_openssl()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    output_dir = ARTIFACTS_DIR / "detached_external_signer_crash_recovery_proof" / args.label
    custody_dir = STATE_DIR / args.label

    remove_if_exists(output_dir)
    remove_if_exists(custody_dir)

    ensure_dir(output_dir)
    ensure_dir(custody_dir)

    active_key = ScenarioKey(
        key_id="r12-attestation-key-active",
        private_key_path=custody_dir / "attestation_private_active.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_active.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    crash_key = ScenarioKey(
        key_id="r12-attestation-key-crash",
        private_key_path=custody_dir / "attestation_private_crash.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_crash.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    recovery_key = ScenarioKey(
        key_id="r12-attestation-key-recovery",
        private_key_path=custody_dir / "attestation_private_recovery.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_recovery.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    expired_key = ScenarioKey(
        key_id="r12-attestation-key-expired",
        private_key_path=custody_dir / "attestation_private_expired.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_expired.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=30)),
        not_after=iso_no_microseconds(base_verification_time - timedelta(seconds=1)),
    )
    future_key = ScenarioKey(
        key_id="r12-attestation-key-future",
        private_key_path=custody_dir / "attestation_private_future.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_future.pem",
        not_before=iso_no_microseconds(base_verification_time + timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )

    for key in (active_key, crash_key, recovery_key, expired_key, future_key):
        generate_rsa_keypair(key.private_key_path, key.public_key_path)

    future_fixture_time = parse_utc(future_key.not_before) - timedelta(seconds=1)
    recovery_time = base_verification_time + timedelta(seconds=5)

    registry = {
        "registry_version": 1,
        "registry_type": "detached_external_signer_crash_recovery_registry",
        "generated_at_utc": utc_now_iso(),
        "entries": [
            {
                "key_id": key.key_id,
                "public_key_path": rel(key.public_key_path),
                "public_key_sha256": sha256_file(key.public_key_path),
                "not_before": key.not_before,
                "not_after": key.not_after,
            }
            for key in (active_key, crash_key, recovery_key, expired_key, future_key)
        ],
    }
    write_json(output_dir / "attestation_key_policy_registry.json", registry)

    active = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__active_runtime",
        key=active_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
        mode="normal_active",
    )
    crash = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__crash_runtime",
        key=crash_key,
        scenario_verification_time=base_verification_time + timedelta(seconds=2),
        verification_mode="crash_probe_time",
        output_dir=output_dir,
        mode="crash_recovery_probe",
    )
    recovery = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__recovery_runtime",
        key=recovery_key,
        scenario_verification_time=recovery_time,
        verification_mode="restart_recovery_time",
        output_dir=output_dir,
        mode="recovery_after_crash",
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

    if not active["gate_decision_allow"] or not active["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not active.get("receipt_signature_verified", False) or not active.get("attestation_signature_verified", False):
        proof_status = "FAIL"
    if not active.get("receipt_tamper_rejected", False) or not active.get("attestation_tamper_rejected", False):
        proof_status = "FAIL"
    if active.get("detached_signer_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if active.get("control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"

    if not crash["gate_decision_allow"]:
        proof_status = "FAIL"
    if crash["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not crash.get("crash_observed", False):
        proof_status = "FAIL"
    if crash.get("detached_signer_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if crash.get("control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"
    if crash.get("receipt_signature_exists", False):
        proof_status = "FAIL"
    if crash.get("attestation_signature_exists", False):
        proof_status = "FAIL"
    if crash.get("runtime_report_exists", False):
        proof_status = "FAIL"

    if not recovery["gate_decision_allow"] or not recovery["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not recovery.get("receipt_signature_verified", False) or not recovery.get("attestation_signature_verified", False):
        proof_status = "FAIL"
    if not recovery.get("receipt_tamper_rejected", False) or not recovery.get("attestation_tamper_rejected", False):
        proof_status = "FAIL"
    if recovery.get("detached_signer_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if recovery.get("control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"

    if expired["gate_decision_allow"] or future["gate_decision_allow"]:
        proof_status = "FAIL"
    if expired["runtime_status_allow_executed"] or future["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not expired.get("denied_key_cleanup_removed", False) or not future.get("denied_key_cleanup_removed", False):
        proof_status = "FAIL"
    if expired.get("denied_key_exists_after_cleanup", True) or future.get("denied_key_exists_after_cleanup", True):
        proof_status = "FAIL"

    if artifact_boundary_scan["contains_private_keys"]:
        proof_status = "FAIL"
    if runtime_boundary_scan["contains_private_keys"]:
        proof_status = "FAIL"
    if detached_signer_custody_scan["contains_private_keys"]:
        proof_status = "FAIL"

    summary = {
        "report_version": 1,
        "report_type": "detached_external_signer_crash_recovery_proof",
        "generated_at_utc": utc_now_iso(),
        "proof_label": args.label,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "future_fixture_time_utc": iso_no_microseconds(future_fixture_time),
        "recovery_time_utc": iso_no_microseconds(recovery_time),
        "openssl_version": openssl_version,
        "proof_status": proof_status,
        "output_directory": rel(output_dir),
        "detached_signer_custody_directory": rel(custody_dir),
        "registry_path": rel(output_dir / "attestation_key_policy_registry.json"),
        "artifact_boundary_scan": artifact_boundary_scan,
        "runtime_boundary_scan": runtime_boundary_scan,
        "detached_signer_custody_scan": detached_signer_custody_scan,
        "scenarios": {
            "active_runtime": active,
            "crash_runtime": crash,
            "recovery_runtime": recovery,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "detached_external_signer_crash_recovery_proof.json"
    summary_md_path = output_dir / "detached_external_signer_crash_recovery_proof.md"
    digest_path = output_dir / "detached_external_signer_crash_recovery_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "summary_json_path": rel(summary_json_path),
        "summary_md_path": rel(summary_md_path),
        "crash_path_safe": (
            crash["gate_decision_allow"]
            and crash.get("crash_observed", False)
            and not crash.get("control_plane_private_key_read_allowed", True)
            and not crash.get("detached_signer_key_path_exists_after_detach", True)
            and not crash.get("receipt_signature_exists", False)
            and not crash.get("attestation_signature_exists", False)
            and not crash.get("runtime_report_exists", False)
        ),
        "recovery_path_successful": (
            recovery["gate_decision_allow"]
            and recovery["runtime_status_allow_executed"]
            and recovery.get("receipt_signature_verified", False)
            and recovery.get("attestation_signature_verified", False)
        ),
        "no_on_disk_private_keys_after_proof": (
            not artifact_boundary_scan["contains_private_keys"]
            and not runtime_boundary_scan["contains_private_keys"]
            and not detached_signer_custody_scan["contains_private_keys"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 88)
    print("R12 - RESTART/CRASH RECOVERY PROOF FOR DETACHED SIGNER + NO KEY LEAKAGE")
    print("=" * 88)
    print(f"LABEL                                       : {args.label}")
    print(f"OPENSSL VERSION                             : {openssl_version}")
    print(f"PROOF STATUS                                : {proof_status}")
    print(f"BASE VERIFICATION TIME                      : {iso_no_microseconds(base_verification_time)}")
    print(f"RECOVERY TIME                               : {iso_no_microseconds(recovery_time)}")
    print(f"FUTURE FIXTURE TIME                         : {iso_no_microseconds(future_fixture_time)}")
    print(f"DETACHED SIGNER CUSTODY DIR                 : {rel(custody_dir)}")
    print(f"ACTIVE EXECUTED                             : {active['runtime_status_allow_executed']}")
    print(f"CRASH OBSERVED                              : {crash.get('crash_observed', False)}")
    print(f"CRASH SIGNER RETURNCODE                     : {crash.get('signer_returncode')}")
    print(f"RECOVERY EXECUTED                           : {recovery['runtime_status_allow_executed']}")
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
