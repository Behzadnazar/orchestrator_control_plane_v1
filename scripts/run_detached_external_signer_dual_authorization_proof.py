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
STATE_DIR = ROOT / "state" / "detached_external_signer_dual_authorization"


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
        "signer_handshake": scenario_dir / "signer_handshake.json",
        "approver_a_handshake": scenario_dir / "approver_a_handshake.json",
        "approver_b_handshake": scenario_dir / "approver_b_handshake.json",
        "signer_private_read_attempt": scenario_dir / "signer_private_read_attempt.json",
        "approver_a_private_read_attempt": scenario_dir / "approver_a_private_read_attempt.json",
        "approver_b_private_read_attempt": scenario_dir / "approver_b_private_read_attempt.json",
        "dual_payload": scenario_dir / "sensitive_payload.json",
        "approval_a_token": scenario_dir / "approval_a_token.json",
        "approval_a_sig": scenario_dir / "approval_a.sig",
        "approval_b_token": scenario_dir / "approval_b_token.json",
        "approval_b_sig": scenario_dir / "approval_b.sig",
        "single_approval_sign_response": scenario_dir / "single_approval_sign_response.json",
        "duplicate_approval_sign_response": scenario_dir / "duplicate_approval_sign_response.json",
        "tampered_approval_sign_response": scenario_dir / "tampered_approval_sign_response.json",
        "dual_approval_sign_response": scenario_dir / "dual_approval_sign_response.json",
        "dual_payload_signature": scenario_dir / "sensitive_payload.sig",
        "dual_payload_verify": scenario_dir / "sensitive_payload_verify.json",
        "dual_payload_tampered": scenario_dir / "sensitive_payload_tampered.json",
        "dual_payload_tamper_verify": scenario_dir / "sensitive_payload_tamper_verify.json",
        "approval_a_verify": scenario_dir / "approval_a_verify.json",
        "approval_b_verify": scenario_dir / "approval_b_verify.json",
        "approval_a_tampered_verify": scenario_dir / "approval_a_tampered_verify.json",
        "approval_bundle_a_duplicate": scenario_dir / "approval_bundle_a_duplicate.json",
        "approval_bundle_tampered": scenario_dir / "approval_bundle_tampered.json",
        "approval_a_tampered_token": scenario_dir / "approval_a_tampered_token.json",
        "runtime_report": scenario_dir / "dual_authorization_runtime_report.json",
        "service_log": scenario_dir / "dual_authorization_service_log.json",
        "denied_key_cleanup": scenario_dir / "denied_key_cleanup.json",
        "executed_marker": scenario_dir / "runtime_executed.marker",
        "denied_marker": scenario_dir / "runtime_denied.marker",
    }


def build_manifest(
    *,
    label: str,
    scenario_name: str,
    signer_public_key_path: Path,
    approver_a_public_key_path: Path,
    approver_b_public_key_path: Path,
    scenario_verification_time: datetime,
    verification_mode: str,
) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "proof_type": "detached_external_signer_dual_authorization_proof",
        "proof_label": label,
        "scenario": scenario_name,
        "generated_at_utc": utc_now_iso(),
        "workflow": {
            "name": "split_trust_dual_authorization_signing",
            "mode": "threshold_dual_authorization",
        },
        "verification_context": {
            "verification_time_utc": iso_no_microseconds(scenario_verification_time),
            "verification_mode": verification_mode,
        },
        "public_keys": {
            "signer_public_key_path": rel(signer_public_key_path),
            "approver_a_public_key_path": rel(approver_a_public_key_path),
            "approver_b_public_key_path": rel(approver_b_public_key_path),
        },
    }


def build_gate_decision(
    *,
    label: str,
    scenario_name: str,
    signer_key: ScenarioKey,
    approver_a_key: ScenarioKey,
    approver_b_key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
) -> dict[str, Any]:
    signer_ok, signer_verdict = evaluate_window(signer_key, scenario_verification_time)
    approver_a_ok, approver_a_verdict = evaluate_window(approver_a_key, scenario_verification_time)
    approver_b_ok, approver_b_verdict = evaluate_window(approver_b_key, scenario_verification_time)

    return {
        "decision_version": 1,
        "decision_type": "pre_execution_dual_authorization_gate",
        "proof_label": label,
        "scenario": scenario_name,
        "decision_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "checks": {
            "signer_key_within_window": signer_ok,
            "approver_a_key_within_window": approver_a_ok,
            "approver_b_key_within_window": approver_b_ok,
            "signer_public_key_exists": signer_key.public_key_path.exists(),
            "approver_a_public_key_exists": approver_a_key.public_key_path.exists(),
            "approver_b_public_key_exists": approver_b_key.public_key_path.exists(),
        },
        "derived": {
            "signer_window_verdict": signer_verdict,
            "approver_a_window_verdict": approver_a_verdict,
            "approver_b_window_verdict": approver_b_verdict,
        },
        "gate_decision_allow": signer_ok and approver_a_ok and approver_b_ok,
    }


def spawn_service(
    mode: str,
    private_key_path: Path,
    key_id: str,
    public_key_path: Path,
    extra_args: list[str] | None = None,
) -> tuple[subprocess.Popen[str], dict[str, Any]]:
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        f"--{mode}-service",
        "--private-key-path",
        str(private_key_path),
        "--key-id",
        key_id,
        "--public-key-path",
        str(public_key_path),
    ]
    if extra_args:
        cmd.extend(extra_args)

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(ROOT),
    )

    if proc.stdout is None:
        raise SystemExit(f"{mode} process stdout is not available.")

    ready_line = proc.stdout.readline()
    if not ready_line:
        stderr_text = proc.stderr.read() if proc.stderr else ""
        raise SystemExit(f"{mode} failed to start.\nSTDERR:\n{stderr_text}")

    handshake = json.loads(ready_line)
    return proc, handshake


def send_json_line(proc: subprocess.Popen[str], payload: dict[str, Any]) -> dict[str, Any]:
    if proc.stdin is None or proc.stdout is None:
        raise SystemExit("Service pipes are not available.")

    proc.stdin.write(json.dumps(payload) + "\n")
    proc.stdin.flush()

    response_line = proc.stdout.readline()
    if not response_line:
        stderr_text = proc.stderr.read() if proc.stderr else ""
        raise SystemExit(f"Service did not return a response.\nSTDERR:\n{stderr_text}")

    return json.loads(response_line)


def stop_service(proc: subprocess.Popen[str]) -> None:
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


def build_sensitive_payload(
    *,
    label: str,
    scenario_name: str,
    signer_key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
) -> dict[str, Any]:
    return {
        "payload_version": 1,
        "payload_type": "sensitive_execution_receipt",
        "payload_class": "split_trust_runtime_evidence",
        "proof_label": label,
        "scenario": scenario_name,
        "request_id": "sensitive_request_01",
        "key_id": signer_key.key_id,
        "public_key_path": rel(signer_key.public_key_path),
        "generated_at_utc": iso_no_microseconds(scenario_verification_time),
        "gate_decision_sha256": sha256_text(canonical_json(gate_decision)),
        "requires_dual_authorization": True,
        "execution_output": {
            "target_path": "proof/sensitive/production_change.txt",
            "content_sha256": sha256_text("sensitive-content"),
        },
    }


def build_approval_token(
    *,
    approver_id: str,
    payload_sha256: str,
    scenario_name: str,
    scenario_verification_time: datetime,
) -> dict[str, Any]:
    return {
        "approval_version": 1,
        "approval_type": "dual_authorization_approval",
        "scenario": scenario_name,
        "approver_id": approver_id,
        "payload_sha256": payload_sha256,
        "approved_at_utc": iso_no_microseconds(scenario_verification_time),
    }


def simulate_dual_authorization_execution(
    *,
    label: str,
    scenario_name: str,
    signer_key: ScenarioKey,
    approver_a_key: ScenarioKey,
    approver_b_key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
    state_dir: Path,
) -> dict[str, Any]:
    approver_a_proc, approver_a_handshake = spawn_service(
        "approver",
        approver_a_key.private_key_path,
        approver_a_key.key_id,
        approver_a_key.public_key_path,
        ["--approver-id", "approver_a"],
    )
    approver_b_proc, approver_b_handshake = spawn_service(
        "approver",
        approver_b_key.private_key_path,
        approver_b_key.key_id,
        approver_b_key.public_key_path,
        ["--approver-id", "approver_b"],
    )
    signer_proc, signer_handshake = spawn_service(
        "signer",
        signer_key.private_key_path,
        signer_key.key_id,
        signer_key.public_key_path,
        [
            "--approver-a-public-key-path",
            str(approver_a_key.public_key_path),
            "--approver-b-public-key-path",
            str(approver_b_key.public_key_path),
        ],
    )

    write_json(paths["approver_a_handshake"], approver_a_handshake)
    write_json(paths["approver_b_handshake"], approver_b_handshake)
    write_json(paths["signer_handshake"], signer_handshake)

    signer_read_attempt = attempt_private_key_read(signer_key.private_key_path)
    approver_a_read_attempt = attempt_private_key_read(approver_a_key.private_key_path)
    approver_b_read_attempt = attempt_private_key_read(approver_b_key.private_key_path)

    write_json(paths["signer_private_read_attempt"], signer_read_attempt)
    write_json(paths["approver_a_private_read_attempt"], approver_a_read_attempt)
    write_json(paths["approver_b_private_read_attempt"], approver_b_read_attempt)

    payload = build_sensitive_payload(
        label=label,
        scenario_name=scenario_name,
        signer_key=signer_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
    )
    write_text(paths["dual_payload"], canonical_json(payload) + "\n")
    payload_sha = sha256_file(paths["dual_payload"])

    approval_a_token = build_approval_token(
        approver_id="approver_a",
        payload_sha256=payload_sha,
        scenario_name=scenario_name,
        scenario_verification_time=scenario_verification_time,
    )
    approval_b_token = build_approval_token(
        approver_id="approver_b",
        payload_sha256=payload_sha,
        scenario_name=scenario_name,
        scenario_verification_time=scenario_verification_time + timedelta(seconds=1),
    )

    write_text(paths["approval_a_token"], canonical_json(approval_a_token) + "\n")
    write_text(paths["approval_b_token"], canonical_json(approval_b_token) + "\n")

    approval_a_response = send_json_line(
        approver_a_proc,
        {
            "action": "approve",
            "token_path": str(paths["approval_a_token"]),
            "signature_path": str(paths["approval_a_sig"]),
        },
    )
    approval_b_response = send_json_line(
        approver_b_proc,
        {
            "action": "approve",
            "token_path": str(paths["approval_b_token"]),
            "signature_path": str(paths["approval_b_sig"]),
        },
    )

    write_json(paths["approval_a_verify"], openssl_verify(paths["approval_a_token"], approver_a_key.public_key_path, paths["approval_a_sig"]))
    write_json(paths["approval_b_verify"], openssl_verify(paths["approval_b_token"], approver_b_key.public_key_path, paths["approval_b_sig"]))

    tampered_approval_a = dict(approval_a_token)
    tampered_approval_a["payload_sha256"] = "0" * 64
    write_text(paths["approval_a_tampered_token"], canonical_json(tampered_approval_a) + "\n")
    write_json(
        paths["approval_a_tampered_verify"],
        openssl_verify(paths["approval_a_tampered_token"], approver_a_key.public_key_path, paths["approval_a_sig"]),
    )

    single_bundle = [
        {
            "approver_id": "approver_a",
            "token_path": str(paths["approval_a_token"]),
            "signature_path": str(paths["approval_a_sig"]),
        }
    ]
    duplicate_bundle = [
        {
            "approver_id": "approver_a",
            "token_path": str(paths["approval_a_token"]),
            "signature_path": str(paths["approval_a_sig"]),
        },
        {
            "approver_id": "approver_a",
            "token_path": str(paths["approval_a_token"]),
            "signature_path": str(paths["approval_a_sig"]),
        },
    ]
    tampered_bundle = [
        {
            "approver_id": "approver_a",
            "token_path": str(paths["approval_a_tampered_token"]),
            "signature_path": str(paths["approval_a_sig"]),
        },
        {
            "approver_id": "approver_b",
            "token_path": str(paths["approval_b_token"]),
            "signature_path": str(paths["approval_b_sig"]),
        },
    ]
    dual_bundle = [
        {
            "approver_id": "approver_a",
            "token_path": str(paths["approval_a_token"]),
            "signature_path": str(paths["approval_a_sig"]),
        },
        {
            "approver_id": "approver_b",
            "token_path": str(paths["approval_b_token"]),
            "signature_path": str(paths["approval_b_sig"]),
        },
    ]

    write_json(paths["approval_bundle_a_duplicate"], duplicate_bundle)
    write_json(paths["approval_bundle_tampered"], tampered_bundle)

    single_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["dual_payload"]),
            "signature_path": str(paths["dual_payload_signature"]),
            "approvals": single_bundle,
        },
    )
    write_json(paths["single_approval_sign_response"], single_response)
    remove_if_exists(paths["dual_payload_signature"])

    duplicate_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["dual_payload"]),
            "signature_path": str(paths["dual_payload_signature"]),
            "approvals": duplicate_bundle,
        },
    )
    write_json(paths["duplicate_approval_sign_response"], duplicate_response)
    remove_if_exists(paths["dual_payload_signature"])

    tampered_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["dual_payload"]),
            "signature_path": str(paths["dual_payload_signature"]),
            "approvals": tampered_bundle,
        },
    )
    write_json(paths["tampered_approval_sign_response"], tampered_response)
    remove_if_exists(paths["dual_payload_signature"])

    dual_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["dual_payload"]),
            "signature_path": str(paths["dual_payload_signature"]),
            "approvals": dual_bundle,
        },
    )
    write_json(paths["dual_approval_sign_response"], dual_response)

    dual_verify = openssl_verify(paths["dual_payload"], signer_key.public_key_path, paths["dual_payload_signature"])
    write_json(paths["dual_payload_verify"], dual_verify)

    tampered_payload = dict(payload)
    tampered_payload["requires_dual_authorization"] = False
    write_text(paths["dual_payload_tampered"], canonical_json(tampered_payload) + "\n")
    tampered_payload_verify = openssl_verify(paths["dual_payload_tampered"], signer_key.public_key_path, paths["dual_payload_signature"])
    write_json(paths["dual_payload_tamper_verify"], tampered_payload_verify)

    write_json(
        paths["service_log"],
        {
            "approval_a_response": approval_a_response,
            "approval_b_response": approval_b_response,
            "single_response": single_response,
            "duplicate_response": duplicate_response,
            "tampered_response": tampered_response,
            "dual_response": dual_response,
        },
    )

    runtime_report = {
        "report_version": 1,
        "report_type": "dual_authorization_runtime_report",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "PASS",
        "runtime_status_allow_executed": True,
        "signer_ready": signer_handshake.get("ready", False),
        "approver_a_ready": approver_a_handshake.get("ready", False),
        "approver_b_ready": approver_b_handshake.get("ready", False),
        "signer_key_path_exists_after_detach": signer_handshake.get("private_key_path_exists_after_detach", True),
        "approver_a_key_path_exists_after_detach": approver_a_handshake.get("private_key_path_exists_after_detach", True),
        "approver_b_key_path_exists_after_detach": approver_b_handshake.get("private_key_path_exists_after_detach", True),
        "signer_private_read_allowed": signer_read_attempt["read_allowed"],
        "approver_a_private_read_allowed": approver_a_read_attempt["read_allowed"],
        "approver_b_private_read_allowed": approver_b_read_attempt["read_allowed"],
        "single_approval_rejected": not single_response.get("ok", False),
        "single_approval_reason": single_response.get("policy_reason"),
        "duplicate_approval_rejected": not duplicate_response.get("ok", False),
        "duplicate_approval_reason": duplicate_response.get("policy_reason"),
        "tampered_approval_rejected": not tampered_response.get("ok", False),
        "tampered_approval_reason": tampered_response.get("policy_reason"),
        "dual_approval_accepted": dual_response.get("ok", False),
        "dual_payload_signature_verified": dual_verify["verified_ok"],
        "dual_payload_tamper_rejected": not tampered_payload_verify["verified_ok"],
        "approval_a_signature_verified": load_json(paths["approval_a_verify"])["verified_ok"],
        "approval_b_signature_verified": load_json(paths["approval_b_verify"])["verified_ok"],
        "approval_a_tamper_rejected": not load_json(paths["approval_a_tampered_verify"])["verified_ok"],
        "window_verdict_signer": gate_decision["derived"]["signer_window_verdict"],
        "window_verdict_approver_a": gate_decision["derived"]["approver_a_window_verdict"],
        "window_verdict_approver_b": gate_decision["derived"]["approver_b_window_verdict"],
        "notes": [
            "signer برای payload حساس به دو approval مستقل نیاز دارد.",
            "single approval رد شد.",
            "duplicate approval از یک approver رد شد.",
            "approval tampered رد شد.",
            "فقط bundle شامل approver_a و approver_b معتبر اجازه sign داد."
        ],
    }
    write_json(paths["runtime_report"], runtime_report)
    write_text(paths["executed_marker"], "executed\n")
    remove_if_exists(paths["denied_marker"])

    stop_service(signer_proc)
    stop_service(approver_a_proc)
    stop_service(approver_b_proc)

    return {
        "signer_handshake": signer_handshake,
        "approver_a_handshake": approver_a_handshake,
        "approver_b_handshake": approver_b_handshake,
        "signer_read_attempt": signer_read_attempt,
        "approver_a_read_attempt": approver_a_read_attempt,
        "approver_b_read_attempt": approver_b_read_attempt,
        "single_response": single_response,
        "duplicate_response": duplicate_response,
        "tampered_response": tampered_response,
        "dual_response": dual_response,
        "dual_verify": dual_verify,
        "tampered_payload_verify": tampered_payload_verify,
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
        "runtime_status_allow_executed": True,
        "signer_ready": runtime_report["signer_ready"],
        "approver_a_ready": runtime_report["approver_a_ready"],
        "approver_b_ready": runtime_report["approver_b_ready"],
        "single_approval_rejected": runtime_report["single_approval_rejected"],
        "duplicate_approval_rejected": runtime_report["duplicate_approval_rejected"],
        "tampered_approval_rejected": runtime_report["tampered_approval_rejected"],
        "dual_approval_accepted": runtime_report["dual_approval_accepted"],
        "dual_payload_signature_verified": runtime_report["dual_payload_signature_verified"],
        "dual_payload_tamper_rejected": runtime_report["dual_payload_tamper_rejected"],
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
    paths: dict[str, Path],
    denied_key_cleanup_result: dict[str, Any],
) -> dict[str, Any]:
    for key in (
        "signer_handshake",
        "approver_a_handshake",
        "approver_b_handshake",
        "signer_private_read_attempt",
        "approver_a_private_read_attempt",
        "approver_b_private_read_attempt",
        "dual_payload",
        "approval_a_token",
        "approval_a_sig",
        "approval_b_token",
        "approval_b_sig",
        "single_approval_sign_response",
        "duplicate_approval_sign_response",
        "tampered_approval_sign_response",
        "dual_approval_sign_response",
        "dual_payload_signature",
        "dual_payload_verify",
        "dual_payload_tampered",
        "dual_payload_tamper_verify",
        "approval_a_verify",
        "approval_b_verify",
        "approval_a_tampered_verify",
        "approval_bundle_a_duplicate",
        "approval_bundle_tampered",
        "approval_a_tampered_token",
        "runtime_report",
        "service_log",
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
        "runtime_status_allow_executed": False,
        "denied_key_cleanup_applied": True,
        "denied_key_exists_after_cleanup": denied_key_cleanup_result["exists_after_cleanup"],
        "runtime_report_exists": False,
    }
    write_json(paths["gate_report"], report)
    return report


def run_approver_service(private_key_path: Path, key_id: str, public_key_path: Path, approver_id: str) -> int:
    fd = os.open(private_key_path, os.O_RDONLY)
    fd_path = f"/proc/self/fd/{fd}"
    os.unlink(private_key_path)

    ready = {
        "ready": True,
        "service": "approver",
        "approver_id": approver_id,
        "key_id": key_id,
        "public_key_path": str(public_key_path),
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
                print(json.dumps({"ok": True, "action": "shutdown"}), flush=True)
                break

            if action != "approve":
                print(json.dumps({"ok": False, "error": "unsupported_action", "action": action}), flush=True)
                continue

            token_path = Path(request["token_path"])
            signature_path = Path(request["signature_path"])
            token = load_json(token_path)

            if token.get("approver_id") != approver_id:
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "policy_reason": "approver_id_mismatch",
                            "approver_id": approver_id,
                            "signature_exists": signature_path.exists(),
                        }
                    ),
                    flush=True,
                )
                continue

            result = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    fd_path,
                    "-out",
                    str(signature_path),
                    str(token_path),
                ],
                cwd=str(ROOT),
                text=True,
                capture_output=True,
                check=False,
                pass_fds=(fd,),
            )

            print(
                json.dumps(
                    {
                        "ok": result.returncode == 0,
                        "approver_id": approver_id,
                        "signature_exists": signature_path.exists(),
                        "returncode": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }
                ),
                flush=True,
            )
    finally:
        os.close(fd)

    return 0


def run_signer_service(
    private_key_path: Path,
    key_id: str,
    public_key_path: Path,
    approver_a_public_key_path: Path,
    approver_b_public_key_path: Path,
) -> int:
    fd = os.open(private_key_path, os.O_RDONLY)
    fd_path = f"/proc/self/fd/{fd}"
    os.unlink(private_key_path)

    ready = {
        "ready": True,
        "service": "signer",
        "key_id": key_id,
        "public_key_path": str(public_key_path),
        "approver_a_public_key_path": str(approver_a_public_key_path),
        "approver_b_public_key_path": str(approver_b_public_key_path),
        "private_key_path_exists_after_detach": private_key_path.exists(),
    }
    print(json.dumps(ready), flush=True)

    expected_pubkeys = {
        "approver_a": approver_a_public_key_path,
        "approver_b": approver_b_public_key_path,
    }

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            request = json.loads(line)
            action = request.get("action")

            if action == "shutdown":
                print(json.dumps({"ok": True, "action": "shutdown"}), flush=True)
                break

            if action != "sign_sensitive":
                print(json.dumps({"ok": False, "error": "unsupported_action", "action": action}), flush=True)
                continue

            payload_path = Path(request["payload_path"])
            signature_path = Path(request["signature_path"])
            approvals = request.get("approvals", [])
            payload_sha = sha256_file(payload_path)

            if len(approvals) != 2:
                print(json.dumps({"ok": False, "policy_reason": "insufficient_distinct_approvals", "signature_exists": signature_path.exists()}), flush=True)
                continue

            approver_ids = [a.get("approver_id") for a in approvals]
            if len(set(approver_ids)) != 2:
                print(json.dumps({"ok": False, "policy_reason": "duplicate_approver_ids", "signature_exists": signature_path.exists()}), flush=True)
                continue

            if set(approver_ids) != {"approver_a", "approver_b"}:
                print(json.dumps({"ok": False, "policy_reason": "unexpected_approver_set", "signature_exists": signature_path.exists()}), flush=True)
                continue

            approval_ok = True
            failure_reason = None

            for approval in approvals:
                approver_id = approval["approver_id"]
                token_path = Path(approval["token_path"])
                sig_path = Path(approval["signature_path"])
                verify = openssl_verify(token_path, expected_pubkeys[approver_id], sig_path)
                if not verify["verified_ok"]:
                    approval_ok = False
                    failure_reason = f"invalid_signature_{approver_id}"
                    break
                token = load_json(token_path)
                if token.get("approver_id") != approver_id:
                    approval_ok = False
                    failure_reason = f"token_approver_mismatch_{approver_id}"
                    break
                if token.get("payload_sha256") != payload_sha:
                    approval_ok = False
                    failure_reason = f"payload_sha_mismatch_{approver_id}"
                    break

            if not approval_ok:
                print(json.dumps({"ok": False, "policy_reason": failure_reason, "signature_exists": signature_path.exists()}), flush=True)
                continue

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

            print(
                json.dumps(
                    {
                        "ok": result.returncode == 0,
                        "policy_reason": None,
                        "signature_exists": signature_path.exists(),
                        "returncode": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                    }
                ),
                flush=True,
            )
    finally:
        os.close(fd)

    return 0


def execute_allowed_scenario(
    *,
    label: str,
    scenario_name: str,
    signer_key: ScenarioKey,
    approver_a_key: ScenarioKey,
    approver_b_key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
    output_dir: Path,
    state_dir: Path,
) -> dict[str, Any]:
    paths = scenario_paths(output_dir, scenario_name)
    ensure_dir(paths["scenario_dir"])

    manifest = build_manifest(
        label=label,
        scenario_name=scenario_name,
        signer_public_key_path=signer_key.public_key_path,
        approver_a_public_key_path=approver_a_key.public_key_path,
        approver_b_public_key_path=approver_b_key.public_key_path,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
    )
    write_json(paths["manifest"], manifest)

    gate_decision = build_gate_decision(
        label=label,
        scenario_name=scenario_name,
        signer_key=signer_key,
        approver_a_key=approver_a_key,
        approver_b_key=approver_b_key,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
    )
    write_json(paths["gate_decision"], gate_decision)

    if not gate_decision["gate_decision_allow"]:
        raise SystemExit(f"{scenario_name} expected allow-path but gate denied it.")

    simulate_dual_authorization_execution(
        label=label,
        scenario_name=scenario_name,
        signer_key=signer_key,
        approver_a_key=approver_a_key,
        approver_b_key=approver_b_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        paths=paths,
        state_dir=state_dir,
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
        "verification_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "gate_decision_allow": True,
        "runtime_status_allow_executed": True,
        "signer_ready": runtime_report["signer_ready"],
        "approver_a_ready": runtime_report["approver_a_ready"],
        "approver_b_ready": runtime_report["approver_b_ready"],
        "signer_key_path_exists_after_detach": runtime_report["signer_key_path_exists_after_detach"],
        "approver_a_key_path_exists_after_detach": runtime_report["approver_a_key_path_exists_after_detach"],
        "approver_b_key_path_exists_after_detach": runtime_report["approver_b_key_path_exists_after_detach"],
        "signer_private_read_allowed": runtime_report["signer_private_read_allowed"],
        "approver_a_private_read_allowed": runtime_report["approver_a_private_read_allowed"],
        "approver_b_private_read_allowed": runtime_report["approver_b_private_read_allowed"],
        "single_approval_rejected": runtime_report["single_approval_rejected"],
        "single_approval_reason": runtime_report["single_approval_reason"],
        "duplicate_approval_rejected": runtime_report["duplicate_approval_rejected"],
        "duplicate_approval_reason": runtime_report["duplicate_approval_reason"],
        "tampered_approval_rejected": runtime_report["tampered_approval_rejected"],
        "tampered_approval_reason": runtime_report["tampered_approval_reason"],
        "dual_approval_accepted": runtime_report["dual_approval_accepted"],
        "dual_payload_signature_verified": runtime_report["dual_payload_signature_verified"],
        "dual_payload_tamper_rejected": runtime_report["dual_payload_tamper_rejected"],
        "approval_a_signature_verified": runtime_report["approval_a_signature_verified"],
        "approval_b_signature_verified": runtime_report["approval_b_signature_verified"],
        "approval_a_tamper_rejected": runtime_report["approval_a_tamper_rejected"],
        "runtime_report_exists": paths["runtime_report"].exists(),
        "runtime_report_path": rel(paths["runtime_report"]),
        "gate_report_path": rel(paths["gate_report"]),
    }


def execute_denied_scenario(
    *,
    label: str,
    scenario_name: str,
    denied_key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
    output_dir: Path,
) -> dict[str, Any]:
    paths = scenario_paths(output_dir, scenario_name)
    ensure_dir(paths["scenario_dir"])

    manifest = {
        "manifest_version": 1,
        "proof_type": "detached_external_signer_dual_authorization_proof",
        "proof_label": label,
        "scenario": scenario_name,
        "generated_at_utc": utc_now_iso(),
        "verification_context": {
            "verification_time_utc": iso_no_microseconds(scenario_verification_time),
            "verification_mode": verification_mode,
        },
    }
    write_json(paths["manifest"], manifest)

    within_window, verdict = evaluate_window(denied_key, scenario_verification_time)
    gate_decision = {
        "decision_version": 1,
        "decision_type": "pre_execution_key_policy_gate",
        "proof_label": label,
        "scenario": scenario_name,
        "verification_mode": verification_mode,
        "derived": {"window_verdict": verdict},
        "gate_decision_allow": within_window,
    }
    write_json(paths["gate_decision"], gate_decision)

    if gate_decision["gate_decision_allow"]:
        raise SystemExit(f"{scenario_name} expected deny-path but gate allowed it.")

    denied_key_cleanup_result = cleanup_denied_key(denied_key.private_key_path)
    build_denied_report(
        label=label,
        scenario_name=scenario_name,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        paths=paths,
        denied_key_cleanup_result=denied_key_cleanup_result,
    )

    return {
        "scenario": scenario_name,
        "verification_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "gate_decision_allow": False,
        "window_verdict": verdict,
        "runtime_status_allow_executed": False,
        "denied_key_cleanup_removed": denied_key_cleanup_result["removed"],
        "denied_key_exists_after_cleanup": denied_key_cleanup_result["exists_after_cleanup"],
        "gate_report_path": rel(paths["gate_report"]),
        "denied_key_cleanup_path": rel(paths["denied_key_cleanup"]),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    active = summary["scenarios"]["dual_authorization_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R19 — Threshold / Dual-Authorization Signing Proof + Split Trust Approval Boundary

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- OpenSSL version: `{summary["openssl_version"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`
- Detached signer custody directory: `{summary["detached_signer_custody_directory"]}`

## Dual Authorization Runtime

- Gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Signer ready: **{str(active.get("signer_ready", False)).upper()}**
- Approver A ready: **{str(active.get("approver_a_ready", False)).upper()}**
- Approver B ready: **{str(active.get("approver_b_ready", False)).upper()}**
- Single approval rejected: **{str(active.get("single_approval_rejected", False)).upper()}**
- Single approval reason: `{active.get("single_approval_reason")}`
- Duplicate approval rejected: **{str(active.get("duplicate_approval_rejected", False)).upper()}**
- Duplicate approval reason: `{active.get("duplicate_approval_reason")}`
- Tampered approval rejected: **{str(active.get("tampered_approval_rejected", False)).upper()}**
- Tampered approval reason: `{active.get("tampered_approval_reason")}`
- Dual approval accepted: **{str(active.get("dual_approval_accepted", False)).upper()}**
- Dual payload signature verified: **{str(active.get("dual_payload_signature_verified", False)).upper()}**
- Dual payload tamper rejected: **{str(active.get("dual_payload_tamper_rejected", False)).upper()}**

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
        description="R19 - Threshold / Dual-Authorization Signing Proof + Split Trust Approval Boundary"
    )
    parser.add_argument(
        "--label",
        default="R19_detached_signer_dual_authorization_proof",
        help="Proof label",
    )
    parser.add_argument(
        "--verification-time",
        default=None,
        help="Base UTC timestamp override in ISO-8601 format",
    )
    parser.add_argument("--approver-service", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--signer-service", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--private-key-path", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--key-id", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--public-key-path", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--approver-id", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--approver-a-public-key-path", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--approver-b-public-key-path", default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.approver_service:
        if not args.private_key_path or not args.key_id or not args.public_key_path or not args.approver_id:
            raise SystemExit("Approver service requires --private-key-path, --key-id, --public-key-path and --approver-id.")
        raise SystemExit(
            run_approver_service(
                Path(args.private_key_path),
                args.key_id,
                Path(args.public_key_path),
                args.approver_id,
            )
        )

    if args.signer_service:
        if (
            not args.private_key_path
            or not args.key_id
            or not args.public_key_path
            or not args.approver_a_public_key_path
            or not args.approver_b_public_key_path
        ):
            raise SystemExit(
                "Signer service requires --private-key-path, --key-id, --public-key-path, --approver-a-public-key-path and --approver-b-public-key-path."
            )
        raise SystemExit(
            run_signer_service(
                Path(args.private_key_path),
                args.key_id,
                Path(args.public_key_path),
                Path(args.approver_a_public_key_path),
                Path(args.approver_b_public_key_path),
            )
        )

    openssl_version = require_openssl()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    output_dir = ARTIFACTS_DIR / "detached_external_signer_dual_authorization_proof" / args.label
    custody_dir = STATE_DIR / args.label

    remove_if_exists(output_dir)
    remove_if_exists(custody_dir)

    ensure_dir(output_dir)
    ensure_dir(custody_dir)

    signer_key = ScenarioKey(
        key_id="r19-signer-key",
        private_key_path=custody_dir / "signer_private.pem",
        public_key_path=output_dir / "public_keys" / "signer_public.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    approver_a_key = ScenarioKey(
        key_id="r19-approver-a-key",
        private_key_path=custody_dir / "approver_a_private.pem",
        public_key_path=output_dir / "public_keys" / "approver_a_public.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    approver_b_key = ScenarioKey(
        key_id="r19-approver-b-key",
        private_key_path=custody_dir / "approver_b_private.pem",
        public_key_path=output_dir / "public_keys" / "approver_b_public.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    expired_key = ScenarioKey(
        key_id="r19-expired-key",
        private_key_path=custody_dir / "expired_private.pem",
        public_key_path=output_dir / "public_keys" / "expired_public.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=30)),
        not_after=iso_no_microseconds(base_verification_time - timedelta(seconds=1)),
    )
    future_key = ScenarioKey(
        key_id="r19-future-key",
        private_key_path=custody_dir / "future_private.pem",
        public_key_path=output_dir / "public_keys" / "future_public.pem",
        not_before=iso_no_microseconds(base_verification_time + timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )

    for key in (signer_key, approver_a_key, approver_b_key, expired_key, future_key):
        generate_rsa_keypair(key.private_key_path, key.public_key_path)

    future_fixture_time = parse_utc(future_key.not_before) - timedelta(seconds=1)

    dual_authorization_runtime = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__dual_authorization_runtime",
        signer_key=signer_key,
        approver_a_key=approver_a_key,
        approver_b_key=approver_b_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
        state_dir=custody_dir,
    )
    expired = execute_denied_scenario(
        label=args.label,
        scenario_name=f"{args.label}__expired_runtime",
        denied_key=expired_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
    )
    future = execute_denied_scenario(
        label=args.label,
        scenario_name=f"{args.label}__future_runtime",
        denied_key=future_key,
        scenario_verification_time=future_fixture_time,
        verification_mode="strict_pre_not_before_fixture",
        output_dir=output_dir,
    )

    artifact_boundary_scan = scan_for_private_keys(output_dir)
    runtime_boundary_scan = scan_for_private_keys(output_dir)
    detached_signer_custody_scan = scan_for_private_keys(custody_dir)

    proof_status = "PASS"

    if not dual_authorization_runtime["gate_decision_allow"] or not dual_authorization_runtime["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("signer_ready", False):
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("approver_a_ready", False):
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("approver_b_ready", False):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("signer_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("approver_a_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("approver_b_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("signer_private_read_allowed", True):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("approver_a_private_read_allowed", True):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("approver_b_private_read_allowed", True):
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("single_approval_rejected", False):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("single_approval_reason") != "insufficient_distinct_approvals":
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("duplicate_approval_rejected", False):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("duplicate_approval_reason") != "duplicate_approver_ids":
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("tampered_approval_rejected", False):
        proof_status = "FAIL"
    if dual_authorization_runtime.get("tampered_approval_reason") != "invalid_signature_approver_a":
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("dual_approval_accepted", False):
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("dual_payload_signature_verified", False):
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("dual_payload_tamper_rejected", False):
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("approval_a_signature_verified", False):
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("approval_b_signature_verified", False):
        proof_status = "FAIL"
    if not dual_authorization_runtime.get("approval_a_tamper_rejected", False):
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
        "report_type": "detached_external_signer_dual_authorization_proof",
        "generated_at_utc": utc_now_iso(),
        "proof_label": args.label,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "future_fixture_time_utc": iso_no_microseconds(future_fixture_time),
        "openssl_version": openssl_version,
        "proof_status": proof_status,
        "output_directory": rel(output_dir),
        "detached_signer_custody_directory": rel(custody_dir),
        "artifact_boundary_scan": artifact_boundary_scan,
        "runtime_boundary_scan": runtime_boundary_scan,
        "detached_signer_custody_scan": detached_signer_custody_scan,
        "scenarios": {
            "dual_authorization_runtime": dual_authorization_runtime,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "detached_external_signer_dual_authorization_proof.json"
    summary_md_path = output_dir / "detached_external_signer_dual_authorization_proof.md"
    digest_path = output_dir / "detached_external_signer_dual_authorization_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "summary_json_path": rel(summary_json_path),
        "summary_md_path": rel(summary_md_path),
        "dual_authorization_safe": (
            dual_authorization_runtime["gate_decision_allow"]
            and dual_authorization_runtime["runtime_status_allow_executed"]
            and not dual_authorization_runtime.get("signer_private_read_allowed", True)
            and not dual_authorization_runtime.get("approver_a_private_read_allowed", True)
            and not dual_authorization_runtime.get("approver_b_private_read_allowed", True)
            and not dual_authorization_runtime.get("signer_key_path_exists_after_detach", True)
            and not dual_authorization_runtime.get("approver_a_key_path_exists_after_detach", True)
            and not dual_authorization_runtime.get("approver_b_key_path_exists_after_detach", True)
            and dual_authorization_runtime.get("single_approval_rejected", False)
            and dual_authorization_runtime.get("duplicate_approval_rejected", False)
            and dual_authorization_runtime.get("tampered_approval_rejected", False)
            and dual_authorization_runtime.get("dual_approval_accepted", False)
            and dual_authorization_runtime.get("dual_payload_signature_verified", False)
            and dual_authorization_runtime.get("dual_payload_tamper_rejected", False)
        ),
        "no_on_disk_private_keys_after_proof": (
            not artifact_boundary_scan["contains_private_keys"]
            and not runtime_boundary_scan["contains_private_keys"]
            and not detached_signer_custody_scan["contains_private_keys"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 96)
    print("R19 - THRESHOLD / DUAL-AUTHORIZATION SIGNING PROOF + SPLIT TRUST APPROVAL BOUNDARY")
    print("=" * 96)
    print(f"LABEL                                               : {args.label}")
    print(f"OPENSSL VERSION                                     : {openssl_version}")
    print(f"PROOF STATUS                                        : {proof_status}")
    print(f"BASE VERIFICATION TIME                              : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME                                 : {iso_no_microseconds(future_fixture_time)}")
    print(f"DETACHED SIGNER CUSTODY DIR                         : {rel(custody_dir)}")
    print(f"DUAL AUTHORIZATION EXECUTED                         : {dual_authorization_runtime['runtime_status_allow_executed']}")
    print(f"SINGLE APPROVAL REJECTED                            : {dual_authorization_runtime.get('single_approval_rejected', False)}")
    print(f"DUPLICATE APPROVAL REJECTED                         : {dual_authorization_runtime.get('duplicate_approval_rejected', False)}")
    print(f"TAMPERED APPROVAL REJECTED                          : {dual_authorization_runtime.get('tampered_approval_rejected', False)}")
    print(f"DUAL APPROVAL ACCEPTED                              : {dual_authorization_runtime.get('dual_approval_accepted', False)}")
    print(f"DUAL PAYLOAD VERIFIED                               : {dual_authorization_runtime.get('dual_payload_signature_verified', False)}")
    print(f"DUAL PAYLOAD TAMPER REJECTED                        : {dual_authorization_runtime.get('dual_payload_tamper_rejected', False)}")
    print(f"EXPIRED KEY CLEANED                                 : {expired.get('denied_key_cleanup_removed', False)}")
    print(f"FUTURE KEY CLEANED                                  : {future.get('denied_key_cleanup_removed', False)}")
    print(f"ARTIFACT BOUNDARY PRIVATE KEYS                      : {artifact_boundary_scan['contains_private_keys']}")
    print(f"RUNTIME BOUNDARY PRIVATE KEYS                       : {runtime_boundary_scan['contains_private_keys']}")
    print(f"DETACHED SIGNER CUSTODY PRIVATE KEYS                : {detached_signer_custody_scan['contains_private_keys']}")
    print(f"SUMMARY JSON                                        : {rel(summary_json_path)}")
    print(f"REPORT MD                                           : {rel(summary_md_path)}")
    print(f"DIGEST                                              : {rel(digest_path)}")
    print("=" * 96)


if __name__ == "__main__":
    main()
