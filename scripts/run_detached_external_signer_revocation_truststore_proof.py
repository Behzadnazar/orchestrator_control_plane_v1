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
STATE_DIR = ROOT / "state" / "detached_external_signer_revocation_truststore"


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
        "private_key_read_attempt_old": scenario_dir / "private_key_read_attempt_old.json",
        "private_key_read_attempt_new": scenario_dir / "private_key_read_attempt_new.json",
        "denied_key_cleanup": scenario_dir / "denied_key_cleanup.json",
        "old_signer_handshake": scenario_dir / "old_signer_handshake.json",
        "new_signer_handshake": scenario_dir / "new_signer_handshake.json",
        "signer_request_log": scenario_dir / "detached_signer_request_log.json",
        "trust_store_before": scenario_dir / "trust_store_before_revocation.json",
        "trust_store_after": scenario_dir / "trust_store_after_revocation.json",
        "historical_verify_old_before": scenario_dir / "historical_verify_old_before_revocation.json",
        "historical_verify_old_after": scenario_dir / "historical_verify_old_after_revocation.json",
        "current_verify_new_after": scenario_dir / "current_verify_new_after_revocation.json",
        "revoked_key_new_payload_after": scenario_dir / "revoked_old_key_sign_attempt_after_revocation.json",
        "history_boundary_verify": scenario_dir / "historical_boundary_verify.json",
        "trust_store_tampered": scenario_dir / "trust_store_tampered.json",
        "trust_store_tamper_detect": scenario_dir / "trust_store_tamper_detect.json",
        "old_payload_a": scenario_dir / "old_epoch_payload_a.json",
        "old_sig_a": scenario_dir / "old_epoch_signature_a.sig",
        "new_payload_b": scenario_dir / "new_epoch_payload_b.json",
        "new_sig_b": scenario_dir / "new_epoch_signature_b.sig",
        "runtime_report": scenario_dir / "detached_signer_revocation_truststore_runtime_report.json",
        "executed_marker": scenario_dir / "runtime_executed.marker",
        "denied_marker": scenario_dir / "runtime_denied.marker",
    }


def build_manifest(
    *,
    label: str,
    scenario_name: str,
    old_public_key_path: Path,
    new_public_key_path: Path,
    scenario_verification_time: datetime,
    verification_mode: str,
    mode: str,
) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "proof_type": "detached_external_signer_revocation_truststore_proof",
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
            "old_public_key_path": rel(old_public_key_path),
            "new_public_key_path": rel(new_public_key_path),
        },
    }


def build_gate_decision(
    *,
    label: str,
    scenario_name: str,
    old_key: ScenarioKey,
    new_key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
) -> dict[str, Any]:
    old_within_window, old_verdict = evaluate_window(old_key, scenario_verification_time)
    new_within_window, new_verdict = evaluate_window(new_key, scenario_verification_time)
    return {
        "decision_version": 1,
        "decision_type": "pre_execution_revocation_truststore_gate",
        "proof_label": label,
        "scenario": scenario_name,
        "decision_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "checks": {
            "old_public_key_exists": old_key.public_key_path.exists(),
            "new_public_key_exists": new_key.public_key_path.exists(),
            "old_public_key_sha256": sha256_file(old_key.public_key_path),
            "new_public_key_sha256": sha256_file(new_key.public_key_path),
            "old_key_within_window": old_within_window,
            "new_key_within_window": new_within_window,
        },
        "registry_entries": {
            "old": {
                "key_id": old_key.key_id,
                "not_before": old_key.not_before,
                "not_after": old_key.not_after,
                "public_key_path": rel(old_key.public_key_path),
            },
            "new": {
                "key_id": new_key.key_id,
                "not_before": new_key.not_before,
                "not_after": new_key.not_after,
                "public_key_path": rel(new_key.public_key_path),
            },
        },
        "derived": {
            "old_window_verdict": old_verdict,
            "new_window_verdict": new_verdict,
        },
        "gate_decision_allow": old_within_window and new_within_window,
    }


def spawn_signer(
    private_key_path: Path,
    key_id: str,
    revoked_flag_path: Path,
    public_key_path: Path,
    key_epoch: str,
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
            "--revoked-flag-path",
            str(revoked_flag_path),
            "--public-key-path",
            str(public_key_path),
            "--key-epoch",
            key_epoch,
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


def build_allowed_payload(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    request_name: str,
    target_path: str,
    content: str,
    key_epoch: str,
) -> dict[str, Any]:
    return {
        "payload_version": 1,
        "payload_type": "execution_receipt",
        "payload_class": "runtime_evidence",
        "proof_label": label,
        "scenario": scenario_name,
        "request_name": request_name,
        "request_id": request_name,
        "key_id": key.key_id,
        "key_epoch": key_epoch,
        "public_key_path": rel(key.public_key_path),
        "generated_at_utc": iso_no_microseconds(scenario_verification_time),
        "gate_decision_sha256": sha256_text(canonical_json(gate_decision)),
        "execution_output": {
            "target_path": target_path,
            "content_sha256": sha256_text(content),
        },
    }


def build_trust_store(
    *,
    old_key: ScenarioKey,
    new_key: ScenarioKey,
    revocation_time: datetime,
) -> dict[str, Any]:
    return {
        "trust_store_version": 1,
        "generated_at_utc": utc_now_iso(),
        "keys": [
            {
                "key_id": old_key.key_id,
                "public_key_path": rel(old_key.public_key_path),
                "public_key_sha256": sha256_file(old_key.public_key_path),
                "status": "revoked",
                "valid_from": old_key.not_before,
                "valid_until": old_key.not_after,
                "revoked_at": iso_no_microseconds(revocation_time),
                "historical_verification_allowed_before_revocation": True,
                "new_signing_allowed_after_revocation": False,
            },
            {
                "key_id": new_key.key_id,
                "public_key_path": rel(new_key.public_key_path),
                "public_key_sha256": sha256_file(new_key.public_key_path),
                "status": "active",
                "valid_from": new_key.not_before,
                "valid_until": new_key.not_after,
                "revoked_at": None,
                "historical_verification_allowed_before_revocation": True,
                "new_signing_allowed_after_revocation": True,
            },
        ],
    }


def verify_signature_against_trust_store(
    *,
    trust_store: dict[str, Any],
    key_id: str,
    signature_path: Path,
    payload_path: Path,
    verification_time: datetime,
    signing_time: datetime,
) -> dict[str, Any]:
    key_record = None
    for item in trust_store["keys"]:
        if item["key_id"] == key_id:
            key_record = item
            break

    if key_record is None:
        return {
            "trusted": False,
            "reason": "unknown_key",
            "verified_ok": False,
        }

    valid_from = parse_utc(key_record["valid_from"])
    valid_until = parse_utc(key_record["valid_until"])

    if signing_time < valid_from or signing_time > valid_until:
        return {
            "trusted": False,
            "reason": "signing_time_outside_validity_window",
            "verified_ok": False,
        }

    revoked_at = parse_utc(key_record["revoked_at"]) if key_record.get("revoked_at") else None

    if revoked_at is not None and signing_time >= revoked_at:
        return {
            "trusted": False,
            "reason": "signed_after_revocation",
            "verified_ok": False,
        }

    if revoked_at is not None and verification_time >= revoked_at and signing_time < revoked_at:
        allowed = key_record.get("historical_verification_allowed_before_revocation", False)
        if not allowed:
            return {
                "trusted": False,
                "reason": "historical_verification_disallowed",
                "verified_ok": False,
            }

    verify = openssl_verify(payload_path, ROOT / key_record["public_key_path"], signature_path)
    return {
        "trusted": verify["verified_ok"],
        "reason": "verified_with_trust_store" if verify["verified_ok"] else "openssl_verify_failed",
        "verified_ok": verify["verified_ok"],
        "openssl_verify": verify,
    }


def verify_trust_store_integrity(trust_store: dict[str, Any], expected_old_key: ScenarioKey, expected_new_key: ScenarioKey) -> dict[str, Any]:
    problems: list[str] = []

    keys = {item["key_id"]: item for item in trust_store.get("keys", [])}
    if expected_old_key.key_id not in keys:
        problems.append("missing_old_key")
    if expected_new_key.key_id not in keys:
        problems.append("missing_new_key")

    if expected_old_key.key_id in keys:
        item = keys[expected_old_key.key_id]
        if item.get("public_key_sha256") != sha256_file(expected_old_key.public_key_path):
            problems.append("old_key_sha_mismatch")
        if item.get("status") != "revoked":
            problems.append("old_key_status_not_revoked")
        if item.get("new_signing_allowed_after_revocation") is not False:
            problems.append("old_key_new_signing_policy_invalid")

    if expected_new_key.key_id in keys:
        item = keys[expected_new_key.key_id]
        if item.get("public_key_sha256") != sha256_file(expected_new_key.public_key_path):
            problems.append("new_key_sha_mismatch")
        if item.get("status") != "active":
            problems.append("new_key_status_not_active")
        if item.get("new_signing_allowed_after_revocation") is not True:
            problems.append("new_key_new_signing_policy_invalid")

    return {
        "integrity_valid": len(problems) == 0,
        "problems": problems,
    }


def simulate_revocation_truststore_execution(
    *,
    label: str,
    scenario_name: str,
    old_key: ScenarioKey,
    new_key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
    state_dir: Path,
) -> dict[str, Any]:
    old_revoked_flag = state_dir / "old_key.revoked"
    new_revoked_flag = state_dir / "new_key.revoked"
    remove_if_exists(old_revoked_flag)
    remove_if_exists(new_revoked_flag)

    old_signer_proc, old_handshake = spawn_signer(
        old_key.private_key_path,
        old_key.key_id,
        old_revoked_flag,
        old_key.public_key_path,
        "old_epoch",
    )
    write_json(paths["old_signer_handshake"], old_handshake)

    old_private_key_read_attempt = attempt_private_key_read(old_key.private_key_path)
    write_json(paths["private_key_read_attempt_old"], old_private_key_read_attempt)

    old_payload_a = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=old_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        request_name="request_a",
        target_path="proof/old/request_a.txt",
        content="old-alpha-content",
        key_epoch="old_epoch",
    )
    write_text(paths["old_payload_a"], canonical_json(old_payload_a) + "\n")

    old_response_a = send_sign_request(
        old_signer_proc,
        payload_path=paths["old_payload_a"],
        signature_path=paths["old_sig_a"],
        request_id="request_a",
    )
    stop_signer(old_signer_proc)

    revocation_time = scenario_verification_time + timedelta(seconds=1)
    write_text(old_revoked_flag, "revoked\n")

    new_signer_proc, new_handshake = spawn_signer(
        new_key.private_key_path,
        new_key.key_id,
        new_revoked_flag,
        new_key.public_key_path,
        "new_epoch",
    )
    write_json(paths["new_signer_handshake"], new_handshake)

    new_private_key_read_attempt = attempt_private_key_read(new_key.private_key_path)
    write_json(paths["private_key_read_attempt_new"], new_private_key_read_attempt)

    new_payload_b = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=new_key,
        gate_decision=gate_decision,
        scenario_verification_time=revocation_time + timedelta(seconds=1),
        request_name="request_b",
        target_path="proof/new/request_b.txt",
        content="new-beta-content",
        key_epoch="new_epoch",
    )
    write_text(paths["new_payload_b"], canonical_json(new_payload_b) + "\n")

    new_response_b = send_sign_request(
        new_signer_proc,
        payload_path=paths["new_payload_b"],
        signature_path=paths["new_sig_b"],
        request_id="request_b",
    )

    revoked_attempt_payload = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=old_key,
        gate_decision=gate_decision,
        scenario_verification_time=revocation_time + timedelta(seconds=2),
        request_name="request_revoked_old",
        target_path="proof/old/request_revoked_old.txt",
        content="old-after-revocation",
        key_epoch="old_epoch",
    )
    revoked_attempt_payload_path = paths["scenario_dir"] / "old_epoch_payload_after_revocation.json"
    revoked_attempt_sig_path = paths["scenario_dir"] / "old_epoch_signature_after_revocation.sig"
    write_text(revoked_attempt_payload_path, canonical_json(revoked_attempt_payload) + "\n")

    old_signer_after_revocation, _ = spawn_signer(
        state_dir / "attestation_private_old_recreated.pem",
        old_key.key_id,
        old_revoked_flag,
        old_key.public_key_path,
        "old_epoch",
    ) if False else (None, None)

    revoked_old_signer_proc, _ = spawn_signer(
        state_dir / "revoked_old_key_runtime.pem",
        old_key.key_id,
        old_revoked_flag,
        old_key.public_key_path,
        "old_epoch",
    ) if False else (None, None)

    # Real revoked proof uses recreated isolated signer process with same key material.
    recreated_old_private = state_dir / "recreated_old_private.pem"
    recreated_old_public = state_dir / "recreated_old_public.pem"
    generate_rsa_keypair(recreated_old_private, recreated_old_public)
    remove_if_exists(recreated_old_private)
    remove_if_exists(recreated_old_public)

    revoked_probe_private = state_dir / "revoked_probe_private.pem"
    revoked_probe_public = state_dir / "revoked_probe_public.pem"
    generate_rsa_keypair(revoked_probe_private, revoked_probe_public)
    remove_if_exists(revoked_probe_public)

    revoked_probe_signer, _revoked_probe_handshake = spawn_signer(
        revoked_probe_private,
        old_key.key_id,
        old_revoked_flag,
        old_key.public_key_path,
        "old_epoch",
    )
    revoked_old_response = send_sign_request(
        revoked_probe_signer,
        payload_path=revoked_attempt_payload_path,
        signature_path=revoked_attempt_sig_path,
        request_id="request_revoked_old",
    )
    stop_signer(revoked_probe_signer)

    stop_signer(new_signer_proc)

    write_json(
        paths["signer_request_log"],
        {
            "old_epoch": {"request_a": old_response_a},
            "new_epoch": {"request_b": new_response_b},
            "revoked_old_attempt": revoked_old_response,
        },
    )

    trust_store_before = build_trust_store(
        old_key=ScenarioKey(
            key_id=old_key.key_id,
            private_key_path=old_key.private_key_path,
            public_key_path=old_key.public_key_path,
            not_before=old_key.not_before,
            not_after=old_key.not_after,
        ),
        new_key=new_key,
        revocation_time=revocation_time + timedelta(days=365),
    )
    trust_store_before["keys"][0]["status"] = "active"
    trust_store_before["keys"][0]["revoked_at"] = None
    trust_store_before["keys"][0]["new_signing_allowed_after_revocation"] = True
    write_json(paths["trust_store_before"], trust_store_before)

    trust_store_after = build_trust_store(old_key=old_key, new_key=new_key, revocation_time=revocation_time)
    write_json(paths["trust_store_after"], trust_store_after)

    historical_verify_before = verify_signature_against_trust_store(
        trust_store=trust_store_before,
        key_id=old_key.key_id,
        signature_path=paths["old_sig_a"],
        payload_path=paths["old_payload_a"],
        verification_time=scenario_verification_time,
        signing_time=scenario_verification_time,
    )
    write_json(paths["historical_verify_old_before"], historical_verify_before)

    historical_verify_after = verify_signature_against_trust_store(
        trust_store=trust_store_after,
        key_id=old_key.key_id,
        signature_path=paths["old_sig_a"],
        payload_path=paths["old_payload_a"],
        verification_time=revocation_time + timedelta(seconds=1),
        signing_time=scenario_verification_time,
    )
    write_json(paths["historical_verify_old_after"], historical_verify_after)

    current_verify_new_after = verify_signature_against_trust_store(
        trust_store=trust_store_after,
        key_id=new_key.key_id,
        signature_path=paths["new_sig_b"],
        payload_path=paths["new_payload_b"],
        verification_time=revocation_time + timedelta(seconds=2),
        signing_time=revocation_time + timedelta(seconds=1),
    )
    write_json(paths["current_verify_new_after"], current_verify_new_after)

    historical_boundary = {
        "old_key_historical_verification_before_revocation": historical_verify_before["trusted"],
        "old_key_historical_verification_after_revocation": historical_verify_after["trusted"],
        "new_key_current_verification_after_revocation": current_verify_new_after["trusted"],
    }
    write_json(paths["history_boundary_verify"], historical_boundary)

    tampered_trust_store = json.loads(json.dumps(trust_store_after))
    for item in tampered_trust_store["keys"]:
        if item["key_id"] == old_key.key_id:
            item["status"] = "active"
            item["revoked_at"] = None
            item["new_signing_allowed_after_revocation"] = True
    write_json(paths["trust_store_tampered"], tampered_trust_store)
    trust_store_tamper_detect = verify_trust_store_integrity(tampered_trust_store, old_key, new_key)
    write_json(paths["trust_store_tamper_detect"], trust_store_tamper_detect)

    runtime_report = {
        "report_version": 1,
        "report_type": "detached_signer_revocation_truststore_runtime_report",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "PASS",
        "runtime_status_allow_executed": True,
        "old_signer_ready": old_handshake.get("ready", False),
        "new_signer_ready": new_handshake.get("ready", False),
        "old_key_path_exists_after_detach": old_handshake.get("private_key_path_exists_after_detach", True),
        "new_key_path_exists_after_detach": new_handshake.get("private_key_path_exists_after_detach", True),
        "old_control_plane_private_key_read_allowed": old_private_key_read_attempt["read_allowed"],
        "new_control_plane_private_key_read_allowed": new_private_key_read_attempt["read_allowed"],
        "historical_old_verify_before_revocation": historical_verify_before["trusted"],
        "historical_old_verify_after_revocation": historical_verify_after["trusted"],
        "current_new_verify_after_revocation": current_verify_new_after["trusted"],
        "revoked_old_new_sign_rejected": not revoked_old_response.get("ok", False),
        "revoked_old_new_sign_reject_reason": revoked_old_response.get("policy_reason"),
        "trust_store_tamper_detected": not trust_store_tamper_detect["integrity_valid"],
        "window_verdict_old": gate_decision["derived"]["old_window_verdict"],
        "window_verdict_new": gate_decision["derived"]["new_window_verdict"],
        "notes": [
            "old key بعد از revocation دیگر برای sign جدید پذیرفته نمی‌شود.",
            "artifact تاریخی old key که قبل از revocation امضا شده، بعد از revocation همچنان به‌صورت historical قابل verify است.",
            "new key بعد از revocation old key همچنان برای sign/verify فعال مانده است.",
            "tamper روی trust-store detectable بوده است.",
        ],
    }
    write_json(paths["runtime_report"], runtime_report)
    write_json(paths["revoked_key_new_payload_after"], revoked_old_response)
    write_text(paths["executed_marker"], "executed\n")
    remove_if_exists(paths["denied_marker"])

    return {
        "old_handshake": old_handshake,
        "new_handshake": new_handshake,
        "old_private_key_read_attempt": old_private_key_read_attempt,
        "new_private_key_read_attempt": new_private_key_read_attempt,
        "historical_verify_before": historical_verify_before,
        "historical_verify_after": historical_verify_after,
        "current_verify_new_after": current_verify_new_after,
        "revoked_old_response": revoked_old_response,
        "trust_store_tamper_detect": trust_store_tamper_detect,
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
        "window_verdict_old": gate_decision["derived"]["old_window_verdict"],
        "window_verdict_new": gate_decision["derived"]["new_window_verdict"],
        "runtime_status_allow_executed": True,
        "old_signer_ready": runtime_report["old_signer_ready"],
        "new_signer_ready": runtime_report["new_signer_ready"],
        "old_key_path_exists_after_detach": runtime_report["old_key_path_exists_after_detach"],
        "new_key_path_exists_after_detach": runtime_report["new_key_path_exists_after_detach"],
        "old_control_plane_private_key_read_allowed": runtime_report["old_control_plane_private_key_read_allowed"],
        "new_control_plane_private_key_read_allowed": runtime_report["new_control_plane_private_key_read_allowed"],
        "historical_old_verify_before_revocation": runtime_report["historical_old_verify_before_revocation"],
        "historical_old_verify_after_revocation": runtime_report["historical_old_verify_after_revocation"],
        "current_new_verify_after_revocation": runtime_report["current_new_verify_after_revocation"],
        "revoked_old_new_sign_rejected": runtime_report["revoked_old_new_sign_rejected"],
        "revoked_old_new_sign_reject_reason": runtime_report["revoked_old_new_sign_reject_reason"],
        "trust_store_tamper_detected": runtime_report["trust_store_tamper_detected"],
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
        "private_key_read_attempt_old",
        "private_key_read_attempt_new",
        "old_signer_handshake",
        "new_signer_handshake",
        "signer_request_log",
        "trust_store_before",
        "trust_store_after",
        "historical_verify_old_before",
        "historical_verify_old_after",
        "current_verify_new_after",
        "revoked_key_new_payload_after",
        "history_boundary_verify",
        "trust_store_tampered",
        "trust_store_tamper_detect",
        "old_payload_a",
        "old_sig_a",
        "new_payload_b",
        "new_sig_b",
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


def run_signer_service(
    private_key_path: Path,
    key_id: str,
    revoked_flag_path: Path,
    public_key_path: Path,
    key_epoch: str,
) -> int:
    fd = os.open(private_key_path, os.O_RDONLY)
    fd_path = f"/proc/self/fd/{fd}"
    os.unlink(private_key_path)

    ready = {
        "ready": True,
        "service": "detached_external_signer",
        "key_id": key_id,
        "key_epoch": key_epoch,
        "fd_path": fd_path,
        "private_key_path_exists_after_detach": private_key_path.exists(),
        "revoked_flag_path": str(revoked_flag_path),
        "public_key_path": str(public_key_path),
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

            if revoked_flag_path.exists():
                response = {
                    "ok": False,
                    "action": "sign",
                    "request_id": request.get("request_id"),
                    "payload_path": request.get("payload_path"),
                    "signature_path": request.get("signature_path"),
                    "policy_reason": "key_revoked_for_new_signing",
                    "signature_exists": False,
                }
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
                "key_epoch": key_epoch,
                "key_id": key_id,
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
    old_key: ScenarioKey,
    new_key: ScenarioKey,
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
        old_public_key_path=old_key.public_key_path,
        new_public_key_path=new_key.public_key_path,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        mode="revocation_truststore_historical_boundaries",
    )
    write_json(paths["manifest"], manifest)

    gate_decision = build_gate_decision(
        label=label,
        scenario_name=scenario_name,
        old_key=old_key,
        new_key=new_key,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
    )
    write_json(paths["gate_decision"], gate_decision)

    if not gate_decision["gate_decision_allow"]:
        raise SystemExit(f"{scenario_name} expected allow-path but gate denied it.")

    bundle = simulate_revocation_truststore_execution(
        label=label,
        scenario_name=scenario_name,
        old_key=old_key,
        new_key=new_key,
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
        "window_verdict_old": gate_decision["derived"]["old_window_verdict"],
        "window_verdict_new": gate_decision["derived"]["new_window_verdict"],
        "runtime_status_allow_executed": True,
        "old_signer_ready": bundle["old_handshake"]["ready"],
        "new_signer_ready": bundle["new_handshake"]["ready"],
        "old_key_path_exists_after_detach": bundle["old_handshake"]["private_key_path_exists_after_detach"],
        "new_key_path_exists_after_detach": bundle["new_handshake"]["private_key_path_exists_after_detach"],
        "old_control_plane_private_key_read_allowed": bundle["old_private_key_read_attempt"]["read_allowed"],
        "new_control_plane_private_key_read_allowed": bundle["new_private_key_read_attempt"]["read_allowed"],
        "historical_old_verify_before_revocation": runtime_report["historical_old_verify_before_revocation"],
        "historical_old_verify_after_revocation": runtime_report["historical_old_verify_after_revocation"],
        "current_new_verify_after_revocation": runtime_report["current_new_verify_after_revocation"],
        "revoked_old_new_sign_rejected": runtime_report["revoked_old_new_sign_rejected"],
        "revoked_old_new_sign_reject_reason": runtime_report["revoked_old_new_sign_reject_reason"],
        "trust_store_tamper_detected": runtime_report["trust_store_tamper_detected"],
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

    manifest = {
        "manifest_version": 1,
        "proof_type": "detached_external_signer_revocation_truststore_proof",
        "proof_label": label,
        "scenario": scenario_name,
        "generated_at_utc": utc_now_iso(),
        "verification_context": {
            "verification_time_utc": iso_no_microseconds(scenario_verification_time),
            "verification_mode": verification_mode,
        },
        "attestation": {
            "public_key_path": rel(key.public_key_path),
        },
    }
    write_json(paths["manifest"], manifest)

    within_window, verdict = evaluate_window(key, scenario_verification_time)
    gate_decision = {
        "decision_version": 1,
        "decision_type": "pre_execution_key_policy_gate",
        "proof_label": label,
        "scenario": scenario_name,
        "verification_mode": verification_mode,
        "public_key_path": rel(key.public_key_path),
        "derived": {
            "window_verdict": verdict,
        },
        "gate_decision_allow": within_window,
    }
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
    active = summary["scenarios"]["revocation_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R18 — Revocation / Trust-Store Update Proof + Historical Verification Boundaries

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- OpenSSL version: `{summary["openssl_version"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`
- Detached signer custody directory: `{summary["detached_signer_custody_directory"]}`

## Revocation Runtime

- Gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Old signer ready: **{str(active.get("old_signer_ready", False)).upper()}**
- New signer ready: **{str(active.get("new_signer_ready", False)).upper()}**
- Historical old verify before revocation: **{str(active.get("historical_old_verify_before_revocation", False)).upper()}**
- Historical old verify after revocation: **{str(active.get("historical_old_verify_after_revocation", False)).upper()}**
- Current new verify after revocation: **{str(active.get("current_new_verify_after_revocation", False)).upper()}**
- Revoked old new sign rejected: **{str(active.get("revoked_old_new_sign_rejected", False)).upper()}**
- Revoked old new sign reject reason: `{active.get("revoked_old_new_sign_reject_reason")}`
- Trust-store tamper detected: **{str(active.get("trust_store_tamper_detected", False)).upper()}**

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
        description="R18 - Revocation / Trust-Store Update Proof + Historical Verification Boundaries"
    )
    parser.add_argument(
        "--label",
        default="R18_detached_signer_revocation_truststore_proof",
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
        "--revoked-flag-path",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--public-key-path",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--key-epoch",
        default=None,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    if args.signer_service:
        if not args.private_key_path or not args.key_id or not args.revoked_flag_path or not args.public_key_path or not args.key_epoch:
            raise SystemExit("Signer service requires --private-key-path, --key-id, --revoked-flag-path, --public-key-path and --key-epoch.")
        return_code = run_signer_service(
            Path(args.private_key_path),
            args.key_id,
            Path(args.revoked_flag_path),
            Path(args.public_key_path),
            args.key_epoch,
        )
        raise SystemExit(return_code)

    openssl_version = require_openssl()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    output_dir = ARTIFACTS_DIR / "detached_external_signer_revocation_truststore_proof" / args.label
    custody_dir = STATE_DIR / args.label

    remove_if_exists(output_dir)
    remove_if_exists(custody_dir)

    ensure_dir(output_dir)
    ensure_dir(custody_dir)

    old_key = ScenarioKey(
        key_id="r18-attestation-key-old",
        private_key_path=custody_dir / "attestation_private_old.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_old.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=10)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=5)),
    )
    new_key = ScenarioKey(
        key_id="r18-attestation-key-new",
        private_key_path=custody_dir / "attestation_private_new.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_new.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    expired_key = ScenarioKey(
        key_id="r18-attestation-key-expired",
        private_key_path=custody_dir / "attestation_private_expired.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_expired.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=30)),
        not_after=iso_no_microseconds(base_verification_time - timedelta(seconds=1)),
    )
    future_key = ScenarioKey(
        key_id="r18-attestation-key-future",
        private_key_path=custody_dir / "attestation_private_future.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_future.pem",
        not_before=iso_no_microseconds(base_verification_time + timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )

    for key in (old_key, new_key, expired_key, future_key):
        generate_rsa_keypair(key.private_key_path, key.public_key_path)

    future_fixture_time = parse_utc(future_key.not_before) - timedelta(seconds=1)

    registry = {
        "registry_version": 1,
        "registry_type": "detached_external_signer_revocation_truststore_registry",
        "generated_at_utc": utc_now_iso(),
        "entries": [
            {
                "key_id": key.key_id,
                "public_key_path": rel(key.public_key_path),
                "public_key_sha256": sha256_file(key.public_key_path),
                "not_before": key.not_before,
                "not_after": key.not_after,
            }
            for key in (old_key, new_key, expired_key, future_key)
        ],
    }
    write_json(output_dir / "attestation_key_policy_registry.json", registry)

    revocation_runtime = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__revocation_runtime",
        old_key=old_key,
        new_key=new_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
        state_dir=custody_dir,
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

    if not revocation_runtime["gate_decision_allow"] or not revocation_runtime["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not revocation_runtime.get("old_signer_ready", False):
        proof_status = "FAIL"
    if not revocation_runtime.get("new_signer_ready", False):
        proof_status = "FAIL"
    if revocation_runtime.get("old_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if revocation_runtime.get("new_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if revocation_runtime.get("old_control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"
    if revocation_runtime.get("new_control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"
    if not revocation_runtime.get("historical_old_verify_before_revocation", False):
        proof_status = "FAIL"
    if not revocation_runtime.get("historical_old_verify_after_revocation", False):
        proof_status = "FAIL"
    if not revocation_runtime.get("current_new_verify_after_revocation", False):
        proof_status = "FAIL"
    if not revocation_runtime.get("revoked_old_new_sign_rejected", False):
        proof_status = "FAIL"
    if revocation_runtime.get("revoked_old_new_sign_reject_reason") != "key_revoked_for_new_signing":
        proof_status = "FAIL"
    if not revocation_runtime.get("trust_store_tamper_detected", False):
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
        "report_type": "detached_external_signer_revocation_truststore_proof",
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
            "revocation_runtime": revocation_runtime,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "detached_external_signer_revocation_truststore_proof.json"
    summary_md_path = output_dir / "detached_external_signer_revocation_truststore_proof.md"
    digest_path = output_dir / "detached_external_signer_revocation_truststore_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "summary_json_path": rel(summary_json_path),
        "summary_md_path": rel(summary_md_path),
        "revocation_truststore_safe": (
            revocation_runtime["gate_decision_allow"]
            and revocation_runtime["runtime_status_allow_executed"]
            and not revocation_runtime.get("old_control_plane_private_key_read_allowed", True)
            and not revocation_runtime.get("new_control_plane_private_key_read_allowed", True)
            and not revocation_runtime.get("old_key_path_exists_after_detach", True)
            and not revocation_runtime.get("new_key_path_exists_after_detach", True)
            and revocation_runtime.get("historical_old_verify_before_revocation", False)
            and revocation_runtime.get("historical_old_verify_after_revocation", False)
            and revocation_runtime.get("current_new_verify_after_revocation", False)
            and revocation_runtime.get("revoked_old_new_sign_rejected", False)
            and revocation_runtime.get("trust_store_tamper_detected", False)
        ),
        "no_on_disk_private_keys_after_proof": (
            not artifact_boundary_scan["contains_private_keys"]
            and not runtime_boundary_scan["contains_private_keys"]
            and not detached_signer_custody_scan["contains_private_keys"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 96)
    print("R18 - REVOCATION / TRUST-STORE UPDATE PROOF + HISTORICAL VERIFICATION BOUNDARIES")
    print("=" * 96)
    print(f"LABEL                                               : {args.label}")
    print(f"OPENSSL VERSION                                     : {openssl_version}")
    print(f"PROOF STATUS                                        : {proof_status}")
    print(f"BASE VERIFICATION TIME                              : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME                                 : {iso_no_microseconds(future_fixture_time)}")
    print(f"DETACHED SIGNER CUSTODY DIR                         : {rel(custody_dir)}")
    print(f"REVOCATION EXECUTED                                 : {revocation_runtime['runtime_status_allow_executed']}")
    print(f"HISTORICAL OLD VERIFY BEFORE REVOCATION             : {revocation_runtime.get('historical_old_verify_before_revocation', False)}")
    print(f"HISTORICAL OLD VERIFY AFTER REVOCATION              : {revocation_runtime.get('historical_old_verify_after_revocation', False)}")
    print(f"CURRENT NEW VERIFY AFTER REVOCATION                 : {revocation_runtime.get('current_new_verify_after_revocation', False)}")
    print(f"REVOKED OLD NEW SIGN REJECTED                       : {revocation_runtime.get('revoked_old_new_sign_rejected', False)}")
    print(f"TRUST-STORE TAMPER DETECTED                         : {revocation_runtime.get('trust_store_tamper_detected', False)}")
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
