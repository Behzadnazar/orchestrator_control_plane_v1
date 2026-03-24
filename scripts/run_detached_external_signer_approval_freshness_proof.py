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
STATE_DIR = ROOT / "state" / "detached_external_signer_approval_freshness"


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
        "fresh_payload": scenario_dir / "fresh_payload.json",
        "fresh_payload_sig": scenario_dir / "fresh_payload.sig",
        "fresh_payload_verify": scenario_dir / "fresh_payload_verify.json",
        "fresh_payload_tampered": scenario_dir / "fresh_payload_tampered.json",
        "fresh_payload_tamper_verify": scenario_dir / "fresh_payload_tamper_verify.json",
        "replay_payload": scenario_dir / "replay_payload.json",
        "expired_payload": scenario_dir / "expired_payload.json",
        "nonce_mismatch_payload": scenario_dir / "nonce_mismatch_payload.json",
        "request_mismatch_payload": scenario_dir / "request_mismatch_payload.json",
        "approval_a_fresh_token": scenario_dir / "approval_a_fresh_token.json",
        "approval_a_fresh_sig": scenario_dir / "approval_a_fresh.sig",
        "approval_b_fresh_token": scenario_dir / "approval_b_fresh_token.json",
        "approval_b_fresh_sig": scenario_dir / "approval_b_fresh.sig",
        "approval_a_expired_token": scenario_dir / "approval_a_expired_token.json",
        "approval_b_expired_token": scenario_dir / "approval_b_expired_token.json",
        "approval_a_nonce_mismatch_token": scenario_dir / "approval_a_nonce_mismatch_token.json",
        "approval_b_nonce_mismatch_token": scenario_dir / "approval_b_nonce_mismatch_token.json",
        "approval_a_request_mismatch_token": scenario_dir / "approval_a_request_mismatch_token.json",
        "approval_b_request_mismatch_token": scenario_dir / "approval_b_request_mismatch_token.json",
        "approval_a_fresh_verify": scenario_dir / "approval_a_fresh_verify.json",
        "approval_b_fresh_verify": scenario_dir / "approval_b_fresh_verify.json",
        "single_use_first_response": scenario_dir / "single_use_first_response.json",
        "replay_response": scenario_dir / "replay_response.json",
        "expired_response": scenario_dir / "expired_response.json",
        "nonce_mismatch_response": scenario_dir / "nonce_mismatch_response.json",
        "request_mismatch_response": scenario_dir / "request_mismatch_response.json",
        "approval_replay_ledger": scenario_dir / "approval_replay_ledger.json",
        "service_log": scenario_dir / "approval_freshness_service_log.json",
        "runtime_report": scenario_dir / "approval_freshness_runtime_report.json",
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
        "proof_type": "detached_external_signer_approval_freshness_proof",
        "proof_label": label,
        "scenario": scenario_name,
        "generated_at_utc": utc_now_iso(),
        "workflow": {
            "name": "approval_freshness_expiry_nonce_binding",
            "mode": "anti_replay_authorization_tokens",
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
        "decision_type": "pre_execution_approval_freshness_gate",
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


def build_payload(
    *,
    label: str,
    scenario_name: str,
    signer_key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    request_id: str,
    nonce: str,
    target_path: str,
    content: str,
) -> dict[str, Any]:
    return {
        "payload_version": 1,
        "payload_type": "sensitive_execution_receipt",
        "payload_class": "freshness_bound_runtime_evidence",
        "proof_label": label,
        "scenario": scenario_name,
        "request_id": request_id,
        "nonce": nonce,
        "key_id": signer_key.key_id,
        "public_key_path": rel(signer_key.public_key_path),
        "generated_at_utc": iso_no_microseconds(scenario_verification_time),
        "gate_decision_sha256": sha256_text(canonical_json(gate_decision)),
        "requires_dual_authorization": True,
        "execution_output": {
            "target_path": target_path,
            "content_sha256": sha256_text(content),
        },
    }


def build_approval_token(
    *,
    approver_id: str,
    payload_sha256: str,
    request_id: str,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    scenario_name: str,
) -> dict[str, Any]:
    return {
        "approval_version": 1,
        "approval_type": "freshness_bound_dual_authorization_approval",
        "scenario": scenario_name,
        "approver_id": approver_id,
        "payload_sha256": payload_sha256,
        "request_id": request_id,
        "nonce": nonce,
        "issued_at_utc": iso_no_microseconds(issued_at),
        "expires_at_utc": iso_no_microseconds(expires_at),
    }


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
    replay_ledger_path: Path,
    verification_time: str,
) -> int:
    fd = os.open(private_key_path, os.O_RDONLY)
    fd_path = f"/proc/self/fd/{fd}"
    os.unlink(private_key_path)

    verify_time = parse_utc(verification_time)
    ensure_dir(replay_ledger_path.parent)

    if replay_ledger_path.exists():
        used_token_hashes = set(load_json(replay_ledger_path).get("used_token_hashes", []))
    else:
        used_token_hashes = set()

    ready = {
        "ready": True,
        "service": "signer",
        "key_id": key_id,
        "public_key_path": str(public_key_path),
        "approver_a_public_key_path": str(approver_a_public_key_path),
        "approver_b_public_key_path": str(approver_b_public_key_path),
        "replay_ledger_path": str(replay_ledger_path),
        "verification_time_utc": iso_no_microseconds(verify_time),
        "private_key_path_exists_after_detach": private_key_path.exists(),
    }
    print(json.dumps(ready), flush=True)

    expected_pubkeys = {
        "approver_a": approver_a_public_key_path,
        "approver_b": approver_b_public_key_path,
    }

    def persist_replay_ledger() -> None:
        write_json(
            replay_ledger_path,
            {
                "used_token_hashes": sorted(used_token_hashes),
                "used_token_count": len(used_token_hashes),
                "updated_at_utc": utc_now_iso(),
            },
        )

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
            payload = load_json(payload_path)
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
            current_token_hashes: list[str] = []

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
                token_hash = sha256_file(token_path)
                current_token_hashes.append(token_hash)

                if token_hash in used_token_hashes:
                    approval_ok = False
                    failure_reason = f"approval_token_replay_{approver_id}"
                    break

                if token.get("approver_id") != approver_id:
                    approval_ok = False
                    failure_reason = f"token_approver_mismatch_{approver_id}"
                    break

                if token.get("payload_sha256") != payload_sha:
                    approval_ok = False
                    failure_reason = f"payload_sha_mismatch_{approver_id}"
                    break

                if token.get("request_id") != payload.get("request_id"):
                    approval_ok = False
                    failure_reason = f"request_id_mismatch_{approver_id}"
                    break

                if token.get("nonce") != payload.get("nonce"):
                    approval_ok = False
                    failure_reason = f"nonce_mismatch_{approver_id}"
                    break

                issued_at = parse_utc(token["issued_at_utc"])
                expires_at = parse_utc(token["expires_at_utc"])
                if verify_time < issued_at:
                    approval_ok = False
                    failure_reason = f"approval_not_yet_valid_{approver_id}"
                    break
                if verify_time > expires_at:
                    approval_ok = False
                    failure_reason = f"approval_expired_{approver_id}"
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

            if result.returncode == 0:
                for token_hash in current_token_hashes:
                    used_token_hashes.add(token_hash)
                persist_replay_ledger()

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


def simulate_approval_freshness_execution(
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
    replay_ledger_path = state_dir / "approval_replay_ledger_state.json"
    remove_if_exists(replay_ledger_path)

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
            "--replay-ledger-path",
            str(replay_ledger_path),
            "--verification-time-service",
            iso_no_microseconds(scenario_verification_time),
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

    fresh_payload = build_payload(
        label=label,
        scenario_name=scenario_name,
        signer_key=signer_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        request_id="sensitive_request_01",
        nonce="nonce-001",
        target_path="proof/sensitive/request_01.txt",
        content="fresh-sensitive-content",
    )
    replay_payload = build_payload(
        label=label,
        scenario_name=scenario_name,
        signer_key=signer_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        request_id="sensitive_request_02",
        nonce="nonce-002",
        target_path="proof/sensitive/request_02.txt",
        content="replay-sensitive-content",
    )
    expired_payload = build_payload(
        label=label,
        scenario_name=scenario_name,
        signer_key=signer_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        request_id="sensitive_request_03",
        nonce="nonce-003",
        target_path="proof/sensitive/request_03.txt",
        content="expired-sensitive-content",
    )
    nonce_mismatch_payload = build_payload(
        label=label,
        scenario_name=scenario_name,
        signer_key=signer_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        request_id="sensitive_request_04",
        nonce="nonce-004-real",
        target_path="proof/sensitive/request_04.txt",
        content="nonce-mismatch-content",
    )
    request_mismatch_payload = build_payload(
        label=label,
        scenario_name=scenario_name,
        signer_key=signer_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        request_id="sensitive_request_05-real",
        nonce="nonce-005",
        target_path="proof/sensitive/request_05.txt",
        content="request-mismatch-content",
    )

    write_text(paths["fresh_payload"], canonical_json(fresh_payload) + "\n")
    write_text(paths["replay_payload"], canonical_json(replay_payload) + "\n")
    write_text(paths["expired_payload"], canonical_json(expired_payload) + "\n")
    write_text(paths["nonce_mismatch_payload"], canonical_json(nonce_mismatch_payload) + "\n")
    write_text(paths["request_mismatch_payload"], canonical_json(request_mismatch_payload) + "\n")

    fresh_payload_sha = sha256_file(paths["fresh_payload"])
    expired_payload_sha = sha256_file(paths["expired_payload"])
    nonce_mismatch_payload_sha = sha256_file(paths["nonce_mismatch_payload"])
    request_mismatch_payload_sha = sha256_file(paths["request_mismatch_payload"])

    fresh_a = build_approval_token(
        approver_id="approver_a",
        payload_sha256=fresh_payload_sha,
        request_id="sensitive_request_01",
        nonce="nonce-001",
        issued_at=scenario_verification_time - timedelta(seconds=5),
        expires_at=scenario_verification_time + timedelta(minutes=5),
        scenario_name=scenario_name,
    )
    fresh_b = build_approval_token(
        approver_id="approver_b",
        payload_sha256=fresh_payload_sha,
        request_id="sensitive_request_01",
        nonce="nonce-001",
        issued_at=scenario_verification_time - timedelta(seconds=5),
        expires_at=scenario_verification_time + timedelta(minutes=5),
        scenario_name=scenario_name,
    )

    expired_a = build_approval_token(
        approver_id="approver_a",
        payload_sha256=expired_payload_sha,
        request_id="sensitive_request_03",
        nonce="nonce-003",
        issued_at=scenario_verification_time - timedelta(minutes=10),
        expires_at=scenario_verification_time - timedelta(minutes=1),
        scenario_name=scenario_name,
    )
    expired_b = build_approval_token(
        approver_id="approver_b",
        payload_sha256=expired_payload_sha,
        request_id="sensitive_request_03",
        nonce="nonce-003",
        issued_at=scenario_verification_time - timedelta(minutes=10),
        expires_at=scenario_verification_time - timedelta(minutes=1),
        scenario_name=scenario_name,
    )

    nonce_mismatch_a = build_approval_token(
        approver_id="approver_a",
        payload_sha256=nonce_mismatch_payload_sha,
        request_id="sensitive_request_04",
        nonce="nonce-004-token",
        issued_at=scenario_verification_time - timedelta(seconds=5),
        expires_at=scenario_verification_time + timedelta(minutes=5),
        scenario_name=scenario_name,
    )
    nonce_mismatch_b = build_approval_token(
        approver_id="approver_b",
        payload_sha256=nonce_mismatch_payload_sha,
        request_id="sensitive_request_04",
        nonce="nonce-004-token",
        issued_at=scenario_verification_time - timedelta(seconds=5),
        expires_at=scenario_verification_time + timedelta(minutes=5),
        scenario_name=scenario_name,
    )

    request_mismatch_a = build_approval_token(
        approver_id="approver_a",
        payload_sha256=request_mismatch_payload_sha,
        request_id="sensitive_request_05-token",
        nonce="nonce-005",
        issued_at=scenario_verification_time - timedelta(seconds=5),
        expires_at=scenario_verification_time + timedelta(minutes=5),
        scenario_name=scenario_name,
    )
    request_mismatch_b = build_approval_token(
        approver_id="approver_b",
        payload_sha256=request_mismatch_payload_sha,
        request_id="sensitive_request_05-token",
        nonce="nonce-005",
        issued_at=scenario_verification_time - timedelta(seconds=5),
        expires_at=scenario_verification_time + timedelta(minutes=5),
        scenario_name=scenario_name,
    )

    write_text(paths["approval_a_fresh_token"], canonical_json(fresh_a) + "\n")
    write_text(paths["approval_b_fresh_token"], canonical_json(fresh_b) + "\n")
    write_text(paths["approval_a_expired_token"], canonical_json(expired_a) + "\n")
    write_text(paths["approval_b_expired_token"], canonical_json(expired_b) + "\n")
    write_text(paths["approval_a_nonce_mismatch_token"], canonical_json(nonce_mismatch_a) + "\n")
    write_text(paths["approval_b_nonce_mismatch_token"], canonical_json(nonce_mismatch_b) + "\n")
    write_text(paths["approval_a_request_mismatch_token"], canonical_json(request_mismatch_a) + "\n")
    write_text(paths["approval_b_request_mismatch_token"], canonical_json(request_mismatch_b) + "\n")

    send_json_line(
        approver_a_proc,
        {"action": "approve", "token_path": str(paths["approval_a_fresh_token"]), "signature_path": str(paths["approval_a_fresh_sig"])},
    )
    send_json_line(
        approver_b_proc,
        {"action": "approve", "token_path": str(paths["approval_b_fresh_token"]), "signature_path": str(paths["approval_b_fresh_sig"])},
    )

    write_json(paths["approval_a_fresh_verify"], openssl_verify(paths["approval_a_fresh_token"], approver_a_key.public_key_path, paths["approval_a_fresh_sig"]))
    write_json(paths["approval_b_fresh_verify"], openssl_verify(paths["approval_b_fresh_token"], approver_b_key.public_key_path, paths["approval_b_fresh_sig"]))

    first_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["fresh_payload"]),
            "signature_path": str(paths["fresh_payload_sig"]),
            "approvals": [
                {
                    "approver_id": "approver_a",
                    "token_path": str(paths["approval_a_fresh_token"]),
                    "signature_path": str(paths["approval_a_fresh_sig"]),
                },
                {
                    "approver_id": "approver_b",
                    "token_path": str(paths["approval_b_fresh_token"]),
                    "signature_path": str(paths["approval_b_fresh_sig"]),
                },
            ],
        },
    )
    write_json(paths["single_use_first_response"], first_response)

    replay_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["replay_payload"]),
            "signature_path": str(paths["scenario_dir"] / "replay_payload.sig"),
            "approvals": [
                {
                    "approver_id": "approver_a",
                    "token_path": str(paths["approval_a_fresh_token"]),
                    "signature_path": str(paths["approval_a_fresh_sig"]),
                },
                {
                    "approver_id": "approver_b",
                    "token_path": str(paths["approval_b_fresh_token"]),
                    "signature_path": str(paths["approval_b_fresh_sig"]),
                },
            ],
        },
    )
    write_json(paths["replay_response"], replay_response)

    send_json_line(
        approver_a_proc,
        {"action": "approve", "token_path": str(paths["approval_a_expired_token"]), "signature_path": str(paths["scenario_dir"] / "approval_a_expired.sig")},
    )
    send_json_line(
        approver_b_proc,
        {"action": "approve", "token_path": str(paths["approval_b_expired_token"]), "signature_path": str(paths["scenario_dir"] / "approval_b_expired.sig")},
    )

    expired_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["expired_payload"]),
            "signature_path": str(paths["scenario_dir"] / "expired_payload.sig"),
            "approvals": [
                {
                    "approver_id": "approver_a",
                    "token_path": str(paths["approval_a_expired_token"]),
                    "signature_path": str(paths["scenario_dir"] / "approval_a_expired.sig"),
                },
                {
                    "approver_id": "approver_b",
                    "token_path": str(paths["approval_b_expired_token"]),
                    "signature_path": str(paths["scenario_dir"] / "approval_b_expired.sig"),
                },
            ],
        },
    )
    write_json(paths["expired_response"], expired_response)

    send_json_line(
        approver_a_proc,
        {"action": "approve", "token_path": str(paths["approval_a_nonce_mismatch_token"]), "signature_path": str(paths["scenario_dir"] / "approval_a_nonce_mismatch.sig")},
    )
    send_json_line(
        approver_b_proc,
        {"action": "approve", "token_path": str(paths["approval_b_nonce_mismatch_token"]), "signature_path": str(paths["scenario_dir"] / "approval_b_nonce_mismatch.sig")},
    )

    nonce_mismatch_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["nonce_mismatch_payload"]),
            "signature_path": str(paths["scenario_dir"] / "nonce_mismatch_payload.sig"),
            "approvals": [
                {
                    "approver_id": "approver_a",
                    "token_path": str(paths["approval_a_nonce_mismatch_token"]),
                    "signature_path": str(paths["scenario_dir"] / "approval_a_nonce_mismatch.sig"),
                },
                {
                    "approver_id": "approver_b",
                    "token_path": str(paths["approval_b_nonce_mismatch_token"]),
                    "signature_path": str(paths["scenario_dir"] / "approval_b_nonce_mismatch.sig"),
                },
            ],
        },
    )
    write_json(paths["nonce_mismatch_response"], nonce_mismatch_response)

    send_json_line(
        approver_a_proc,
        {"action": "approve", "token_path": str(paths["approval_a_request_mismatch_token"]), "signature_path": str(paths["scenario_dir"] / "approval_a_request_mismatch.sig")},
    )
    send_json_line(
        approver_b_proc,
        {"action": "approve", "token_path": str(paths["approval_b_request_mismatch_token"]), "signature_path": str(paths["scenario_dir"] / "approval_b_request_mismatch.sig")},
    )

    request_mismatch_response = send_json_line(
        signer_proc,
        {
            "action": "sign_sensitive",
            "payload_path": str(paths["request_mismatch_payload"]),
            "signature_path": str(paths["scenario_dir"] / "request_mismatch_payload.sig"),
            "approvals": [
                {
                    "approver_id": "approver_a",
                    "token_path": str(paths["approval_a_request_mismatch_token"]),
                    "signature_path": str(paths["scenario_dir"] / "approval_a_request_mismatch.sig"),
                },
                {
                    "approver_id": "approver_b",
                    "token_path": str(paths["approval_b_request_mismatch_token"]),
                    "signature_path": str(paths["scenario_dir"] / "approval_b_request_mismatch.sig"),
                },
            ],
        },
    )
    write_json(paths["request_mismatch_response"], request_mismatch_response)

    fresh_verify = openssl_verify(paths["fresh_payload"], signer_key.public_key_path, paths["fresh_payload_sig"])
    write_json(paths["fresh_payload_verify"], fresh_verify)

    tampered_payload = dict(fresh_payload)
    tampered_payload["nonce"] = "nonce-001-tampered"
    write_text(paths["fresh_payload_tampered"], canonical_json(tampered_payload) + "\n")
    tampered_verify = openssl_verify(paths["fresh_payload_tampered"], signer_key.public_key_path, paths["fresh_payload_sig"])
    write_json(paths["fresh_payload_tamper_verify"], tampered_verify)

    replay_ledger = load_json(replay_ledger_path)
    write_json(paths["approval_replay_ledger"], replay_ledger)

    write_json(
        paths["service_log"],
        {
            "first_response": first_response,
            "replay_response": replay_response,
            "expired_response": expired_response,
            "nonce_mismatch_response": nonce_mismatch_response,
            "request_mismatch_response": request_mismatch_response,
        },
    )

    runtime_report = {
        "report_version": 1,
        "report_type": "approval_freshness_runtime_report",
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
        "fresh_dual_approval_accepted": first_response.get("ok", False),
        "fresh_payload_signature_verified": fresh_verify["verified_ok"],
        "fresh_payload_tamper_rejected": not tampered_verify["verified_ok"],
        "token_replay_rejected": not replay_response.get("ok", False),
        "token_replay_reason": replay_response.get("policy_reason"),
        "expired_token_rejected": not expired_response.get("ok", False),
        "expired_token_reason": expired_response.get("policy_reason"),
        "nonce_mismatch_rejected": not nonce_mismatch_response.get("ok", False),
        "nonce_mismatch_reason": nonce_mismatch_response.get("policy_reason"),
        "request_mismatch_rejected": not request_mismatch_response.get("ok", False),
        "request_mismatch_reason": request_mismatch_response.get("policy_reason"),
        "approval_a_signature_verified": load_json(paths["approval_a_fresh_verify"])["verified_ok"],
        "approval_b_signature_verified": load_json(paths["approval_b_fresh_verify"])["verified_ok"],
        "used_token_count_after_first_accept": replay_ledger["used_token_count"],
        "window_verdict_signer": gate_decision["derived"]["signer_window_verdict"],
        "window_verdict_approver_a": gate_decision["derived"]["approver_a_window_verdict"],
        "window_verdict_approver_b": gate_decision["derived"]["approver_b_window_verdict"],
        "notes": [
            "approval tokenها به request_id و nonce و payload_sha256 bind شده‌اند.",
            "tokenهای مصرف‌شده دوباره قابل‌استفاده نیستند.",
            "tokenهای expired رد می‌شوند.",
            "nonce mismatch و request_id mismatch رد می‌شوند.",
        ],
    }
    write_json(paths["runtime_report"], runtime_report)
    write_text(paths["executed_marker"], "executed\n")
    remove_if_exists(paths["denied_marker"])

    stop_service(signer_proc)
    stop_service(approver_a_proc)
    stop_service(approver_b_proc)

    return runtime_report


def build_allowed_report(
    *,
    label: str,
    scenario_name: str,
    scenario_verification_time: datetime,
    verification_mode: str,
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
        "fresh_dual_approval_accepted": runtime_report["fresh_dual_approval_accepted"],
        "token_replay_rejected": runtime_report["token_replay_rejected"],
        "expired_token_rejected": runtime_report["expired_token_rejected"],
        "nonce_mismatch_rejected": runtime_report["nonce_mismatch_rejected"],
        "request_mismatch_rejected": runtime_report["request_mismatch_rejected"],
        "fresh_payload_signature_verified": runtime_report["fresh_payload_signature_verified"],
        "fresh_payload_tamper_rejected": runtime_report["fresh_payload_tamper_rejected"],
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
        "fresh_payload",
        "fresh_payload_sig",
        "fresh_payload_verify",
        "fresh_payload_tampered",
        "fresh_payload_tamper_verify",
        "replay_payload",
        "expired_payload",
        "nonce_mismatch_payload",
        "request_mismatch_payload",
        "approval_a_fresh_token",
        "approval_a_fresh_sig",
        "approval_b_fresh_token",
        "approval_b_fresh_sig",
        "approval_a_expired_token",
        "approval_b_expired_token",
        "approval_a_nonce_mismatch_token",
        "approval_b_nonce_mismatch_token",
        "approval_a_request_mismatch_token",
        "approval_b_request_mismatch_token",
        "approval_a_fresh_verify",
        "approval_b_fresh_verify",
        "single_use_first_response",
        "replay_response",
        "expired_response",
        "nonce_mismatch_response",
        "request_mismatch_response",
        "approval_replay_ledger",
        "service_log",
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
        "runtime_status_allow_executed": False,
        "denied_key_cleanup_applied": True,
        "denied_key_exists_after_cleanup": denied_key_cleanup_result["exists_after_cleanup"],
        "runtime_report_exists": False,
    }
    write_json(paths["gate_report"], report)
    return report


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

    simulate_approval_freshness_execution(
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
        "fresh_dual_approval_accepted": runtime_report["fresh_dual_approval_accepted"],
        "token_replay_rejected": runtime_report["token_replay_rejected"],
        "token_replay_reason": runtime_report["token_replay_reason"],
        "expired_token_rejected": runtime_report["expired_token_rejected"],
        "expired_token_reason": runtime_report["expired_token_reason"],
        "nonce_mismatch_rejected": runtime_report["nonce_mismatch_rejected"],
        "nonce_mismatch_reason": runtime_report["nonce_mismatch_reason"],
        "request_mismatch_rejected": runtime_report["request_mismatch_rejected"],
        "request_mismatch_reason": runtime_report["request_mismatch_reason"],
        "fresh_payload_signature_verified": runtime_report["fresh_payload_signature_verified"],
        "fresh_payload_tamper_rejected": runtime_report["fresh_payload_tamper_rejected"],
        "approval_a_signature_verified": runtime_report["approval_a_signature_verified"],
        "approval_b_signature_verified": runtime_report["approval_b_signature_verified"],
        "used_token_count_after_first_accept": runtime_report["used_token_count_after_first_accept"],
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
        "proof_type": "detached_external_signer_approval_freshness_proof",
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
    active = summary["scenarios"]["approval_freshness_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R20 — Approval Freshness / Expiry / Nonce-Binding Proof + Anti-Replay Across Authorization Tokens

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- OpenSSL version: `{summary["openssl_version"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`
- Detached signer custody directory: `{summary["detached_signer_custody_directory"]}`

## Approval Freshness Runtime

- Gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Fresh dual approval accepted: **{str(active.get("fresh_dual_approval_accepted", False)).upper()}**
- Token replay rejected: **{str(active.get("token_replay_rejected", False)).upper()}**
- Token replay reason: `{active.get("token_replay_reason")}`
- Expired token rejected: **{str(active.get("expired_token_rejected", False)).upper()}**
- Expired token reason: `{active.get("expired_token_reason")}`
- Nonce mismatch rejected: **{str(active.get("nonce_mismatch_rejected", False)).upper()}**
- Nonce mismatch reason: `{active.get("nonce_mismatch_reason")}`
- Request mismatch rejected: **{str(active.get("request_mismatch_rejected", False)).upper()}**
- Request mismatch reason: `{active.get("request_mismatch_reason")}`
- Fresh payload signature verified: **{str(active.get("fresh_payload_signature_verified", False)).upper()}**
- Fresh payload tamper rejected: **{str(active.get("fresh_payload_tamper_rejected", False)).upper()}**
- Used token count after first accept: `{active.get("used_token_count_after_first_accept")}`

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
        description="R20 - Approval Freshness / Expiry / Nonce-Binding Proof + Anti-Replay Across Authorization Tokens"
    )
    parser.add_argument("--label", default="R20_detached_signer_approval_freshness_proof", help="Proof label")
    parser.add_argument("--verification-time", default=None, help="Base UTC timestamp override in ISO-8601 format")
    parser.add_argument("--approver-service", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--signer-service", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--private-key-path", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--key-id", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--public-key-path", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--approver-id", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--approver-a-public-key-path", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--approver-b-public-key-path", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--replay-ledger-path", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--verification-time-service", dest="verification_time_service", default=None, help=argparse.SUPPRESS)
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
            or not args.replay_ledger_path
            or not args.verification_time_service
        ):
            raise SystemExit(
                "Signer service requires --private-key-path, --key-id, --public-key-path, --approver-a-public-key-path, --approver-b-public-key-path, --replay-ledger-path and --verification-time-service."
            )
        raise SystemExit(
            run_signer_service(
                Path(args.private_key_path),
                args.key_id,
                Path(args.public_key_path),
                Path(args.approver_a_public_key_path),
                Path(args.approver_b_public_key_path),
                Path(args.replay_ledger_path),
                args.verification_time_service,
            )
        )

    openssl_version = require_openssl()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    output_dir = ARTIFACTS_DIR / "detached_external_signer_approval_freshness_proof" / args.label
    custody_dir = STATE_DIR / args.label

    remove_if_exists(output_dir)
    remove_if_exists(custody_dir)

    ensure_dir(output_dir)
    ensure_dir(custody_dir)

    signer_key = ScenarioKey(
        key_id="r20-signer-key",
        private_key_path=custody_dir / "signer_private.pem",
        public_key_path=output_dir / "public_keys" / "signer_public.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    approver_a_key = ScenarioKey(
        key_id="r20-approver-a-key",
        private_key_path=custody_dir / "approver_a_private.pem",
        public_key_path=output_dir / "public_keys" / "approver_a_public.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    approver_b_key = ScenarioKey(
        key_id="r20-approver-b-key",
        private_key_path=custody_dir / "approver_b_private.pem",
        public_key_path=output_dir / "public_keys" / "approver_b_public.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    expired_key = ScenarioKey(
        key_id="r20-expired-key",
        private_key_path=custody_dir / "expired_private.pem",
        public_key_path=output_dir / "public_keys" / "expired_public.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=30)),
        not_after=iso_no_microseconds(base_verification_time - timedelta(seconds=1)),
    )
    future_key = ScenarioKey(
        key_id="r20-future-key",
        private_key_path=custody_dir / "future_private.pem",
        public_key_path=output_dir / "public_keys" / "future_public.pem",
        not_before=iso_no_microseconds(base_verification_time + timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )

    for key in (signer_key, approver_a_key, approver_b_key, expired_key, future_key):
        generate_rsa_keypair(key.private_key_path, key.public_key_path)

    future_fixture_time = parse_utc(future_key.not_before) - timedelta(seconds=1)

    approval_freshness_runtime = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__approval_freshness_runtime",
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

    if not approval_freshness_runtime["gate_decision_allow"] or not approval_freshness_runtime["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("signer_ready", False):
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("approver_a_ready", False):
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("approver_b_ready", False):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("signer_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("approver_a_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("approver_b_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("signer_private_read_allowed", True):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("approver_a_private_read_allowed", True):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("approver_b_private_read_allowed", True):
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("fresh_dual_approval_accepted", False):
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("token_replay_rejected", False):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("token_replay_reason") != "approval_token_replay_approver_a":
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("expired_token_rejected", False):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("expired_token_reason") != "approval_expired_approver_a":
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("nonce_mismatch_rejected", False):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("nonce_mismatch_reason") != "nonce_mismatch_approver_a":
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("request_mismatch_rejected", False):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("request_mismatch_reason") != "request_id_mismatch_approver_a":
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("fresh_payload_signature_verified", False):
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("fresh_payload_tamper_rejected", False):
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("approval_a_signature_verified", False):
        proof_status = "FAIL"
    if not approval_freshness_runtime.get("approval_b_signature_verified", False):
        proof_status = "FAIL"
    if approval_freshness_runtime.get("used_token_count_after_first_accept") != 2:
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
        "report_type": "detached_external_signer_approval_freshness_proof",
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
            "approval_freshness_runtime": approval_freshness_runtime,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "detached_external_signer_approval_freshness_proof.json"
    summary_md_path = output_dir / "detached_external_signer_approval_freshness_proof.md"
    digest_path = output_dir / "detached_external_signer_approval_freshness_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "summary_json_path": rel(summary_json_path),
        "summary_md_path": rel(summary_md_path),
        "approval_freshness_safe": (
            approval_freshness_runtime["gate_decision_allow"]
            and approval_freshness_runtime["runtime_status_allow_executed"]
            and not approval_freshness_runtime.get("signer_private_read_allowed", True)
            and not approval_freshness_runtime.get("approver_a_private_read_allowed", True)
            and not approval_freshness_runtime.get("approver_b_private_read_allowed", True)
            and not approval_freshness_runtime.get("signer_key_path_exists_after_detach", True)
            and not approval_freshness_runtime.get("approver_a_key_path_exists_after_detach", True)
            and not approval_freshness_runtime.get("approver_b_key_path_exists_after_detach", True)
            and approval_freshness_runtime.get("fresh_dual_approval_accepted", False)
            and approval_freshness_runtime.get("token_replay_rejected", False)
            and approval_freshness_runtime.get("expired_token_rejected", False)
            and approval_freshness_runtime.get("nonce_mismatch_rejected", False)
            and approval_freshness_runtime.get("request_mismatch_rejected", False)
            and approval_freshness_runtime.get("fresh_payload_signature_verified", False)
            and approval_freshness_runtime.get("fresh_payload_tamper_rejected", False)
        ),
        "no_on_disk_private_keys_after_proof": (
            not artifact_boundary_scan["contains_private_keys"]
            and not runtime_boundary_scan["contains_private_keys"]
            and not detached_signer_custody_scan["contains_private_keys"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 100)
    print("R20 - APPROVAL FRESHNESS / EXPIRY / NONCE-BINDING PROOF + ANTI-REPLAY AUTHORIZATION TOKENS")
    print("=" * 100)
    print(f"LABEL                                                   : {args.label}")
    print(f"OPENSSL VERSION                                         : {openssl_version}")
    print(f"PROOF STATUS                                            : {proof_status}")
    print(f"BASE VERIFICATION TIME                                  : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME                                     : {iso_no_microseconds(future_fixture_time)}")
    print(f"DETACHED SIGNER CUSTODY DIR                             : {rel(custody_dir)}")
    print(f"APPROVAL FRESHNESS EXECUTED                             : {approval_freshness_runtime['runtime_status_allow_executed']}")
    print(f"FRESH DUAL APPROVAL ACCEPTED                            : {approval_freshness_runtime.get('fresh_dual_approval_accepted', False)}")
    print(f"TOKEN REPLAY REJECTED                                   : {approval_freshness_runtime.get('token_replay_rejected', False)}")
    print(f"EXPIRED TOKEN REJECTED                                  : {approval_freshness_runtime.get('expired_token_rejected', False)}")
    print(f"NONCE MISMATCH REJECTED                                 : {approval_freshness_runtime.get('nonce_mismatch_rejected', False)}")
    print(f"REQUEST MISMATCH REJECTED                               : {approval_freshness_runtime.get('request_mismatch_rejected', False)}")
    print(f"FRESH PAYLOAD VERIFIED                                  : {approval_freshness_runtime.get('fresh_payload_signature_verified', False)}")
    print(f"FRESH PAYLOAD TAMPER REJECTED                           : {approval_freshness_runtime.get('fresh_payload_tamper_rejected', False)}")
    print(f"USED TOKEN COUNT AFTER FIRST ACCEPT                     : {approval_freshness_runtime.get('used_token_count_after_first_accept')}")
    print(f"EXPIRED KEY CLEANED                                     : {expired.get('denied_key_cleanup_removed', False)}")
    print(f"FUTURE KEY CLEANED                                      : {future.get('denied_key_cleanup_removed', False)}")
    print(f"ARTIFACT BOUNDARY PRIVATE KEYS                          : {artifact_boundary_scan['contains_private_keys']}")
    print(f"RUNTIME BOUNDARY PRIVATE KEYS                           : {runtime_boundary_scan['contains_private_keys']}")
    print(f"DETACHED SIGNER CUSTODY PRIVATE KEYS                    : {detached_signer_custody_scan['contains_private_keys']}")
    print(f"SUMMARY JSON                                            : {rel(summary_json_path)}")
    print(f"REPORT MD                                               : {rel(summary_md_path)}")
    print(f"DIGEST                                                  : {rel(digest_path)}")
    print("=" * 100)


if __name__ == "__main__":
    main()
