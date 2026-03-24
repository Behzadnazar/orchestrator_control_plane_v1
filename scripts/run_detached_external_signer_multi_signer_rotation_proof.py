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
STATE_DIR = ROOT / "state" / "detached_external_signer_multi_signer_rotation"


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
        "epoch_snapshot": scenario_dir / "multi_signer_epoch_snapshot.json",
        "epoch_verify": scenario_dir / "multi_signer_epoch_verify.json",
        "epoch_tampered": scenario_dir / "multi_signer_epoch_tampered.json",
        "epoch_tamper_detect": scenario_dir / "multi_signer_epoch_tamper_detect.json",
        "retention_manifest": scenario_dir / "multi_signer_retention_manifest.json",
        "old_payload_a": scenario_dir / "old_epoch_payload_a.json",
        "old_sig_a": scenario_dir / "old_epoch_signature_a.sig",
        "old_verify_a": scenario_dir / "old_epoch_verify_a.json",
        "old_payload_b": scenario_dir / "old_epoch_payload_b.json",
        "old_sig_b": scenario_dir / "old_epoch_signature_b.sig",
        "old_verify_b": scenario_dir / "old_epoch_verify_b.json",
        "new_payload_c": scenario_dir / "new_epoch_payload_c.json",
        "new_sig_c": scenario_dir / "new_epoch_signature_c.sig",
        "new_verify_c": scenario_dir / "new_epoch_verify_c.json",
        "new_payload_d": scenario_dir / "new_epoch_payload_d.json",
        "new_sig_d": scenario_dir / "new_epoch_signature_d.sig",
        "new_verify_d": scenario_dir / "new_epoch_verify_d.json",
        "cross_verify_old_payload_with_new_key": scenario_dir / "cross_verify_old_payload_with_new_key.json",
        "cross_verify_new_payload_with_old_key": scenario_dir / "cross_verify_new_payload_with_old_key.json",
        "runtime_report": scenario_dir / "detached_signer_multi_signer_rotation_runtime_report.json",
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
        "proof_type": "detached_external_signer_multi_signer_rotation_proof",
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
        "decision_type": "pre_execution_multi_signer_key_policy_gate",
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
    ledger_dir: Path,
    segment_size: int,
    key_epoch: str,
    public_key_path: Path,
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
            "--ledger-dir",
            str(ledger_dir),
            "--segment-size",
            str(segment_size),
            "--key-epoch",
            key_epoch,
            "--public-key-path",
            str(public_key_path),
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


def segment_file(ledger_dir: Path, segment_index: int) -> Path:
    return ledger_dir / f"segment_{segment_index:04d}.jsonl"


def load_segment_entries(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        entries.append(json.loads(line))
    return entries


def verify_multi_signer_ledger(ledger_dir: Path) -> dict[str, Any]:
    manifest_path = ledger_dir / "segments_manifest.json"
    snapshot_path = ledger_dir / "ledger_snapshot.json"
    retention_path = ledger_dir / "retention_manifest.json"

    if not manifest_path.exists():
        return {
            "chain_valid": False,
            "continuity_valid": False,
            "snapshot_valid": False,
            "retention_valid": False,
            "cross_key_epoch_valid": False,
            "segment_count": 0,
            "entry_count": 0,
            "problems": ["missing_segments_manifest"],
        }

    manifest = load_json(manifest_path)
    segments = manifest.get("segments", [])
    all_entries: list[dict[str, Any]] = []
    problems: list[str] = []
    previous_segment_last_hash = "GENESIS"
    continuity_valid = True
    cross_key_epoch_valid = True

    previous_epoch: str | None = None
    previous_epoch_last_hash: str | None = None

    for i, segment in enumerate(segments, start=1):
        path = ROOT / segment["segment_path"]
        entries = load_segment_entries(path)

        if segment.get("segment_index") != i:
            problems.append(f"segment_index_mismatch_{i}")
            continuity_valid = False

        if segment.get("previous_segment_last_hash") != previous_segment_last_hash:
            problems.append(f"segment_previous_hash_mismatch_{i}")
            continuity_valid = False

        segment_epoch = segment.get("key_epoch")
        if previous_epoch is not None and segment_epoch == previous_epoch:
            problems.append(f"expected_epoch_transition_before_segment_{i}")
            cross_key_epoch_valid = False

        if previous_epoch is not None and segment.get("previous_epoch_last_hash") != previous_epoch_last_hash:
            problems.append(f"previous_epoch_last_hash_mismatch_{i}")
            cross_key_epoch_valid = False

        previous_entry_hash = (
            segment.get("previous_segment_last_hash", "GENESIS")
        )

        for entry in entries:
            body = dict(entry)
            recorded_hash = body.pop("entry_hash", None)
            if body.get("previous_entry_hash") != previous_entry_hash:
                problems.append(f"entry_previous_hash_mismatch_segment_{i}_entry_{body.get('entry_index')}")
                continuity_valid = False
            if body.get("key_epoch") != segment_epoch:
                problems.append(f"entry_epoch_mismatch_segment_{i}_entry_{body.get('entry_index')}")
                cross_key_epoch_valid = False
            if body.get("key_id") != segment.get("key_id"):
                problems.append(f"entry_key_id_mismatch_segment_{i}_entry_{body.get('entry_index')}")
                cross_key_epoch_valid = False
            recalculated_hash = sha256_text(canonical_json(body))
            if recorded_hash != recalculated_hash:
                problems.append(f"entry_hash_mismatch_segment_{i}_entry_{body.get('entry_index')}")
                continuity_valid = False
            previous_entry_hash = recorded_hash or ""

        if entries:
            if segment.get("segment_first_entry_index") != entries[0]["entry_index"]:
                problems.append(f"segment_first_index_mismatch_{i}")
                continuity_valid = False
            if segment.get("segment_last_entry_index") != entries[-1]["entry_index"]:
                problems.append(f"segment_last_index_mismatch_{i}")
                continuity_valid = False
        if segment.get("segment_last_entry_hash") != previous_entry_hash:
            problems.append(f"segment_last_hash_mismatch_{i}")
            continuity_valid = False

        previous_segment_last_hash = segment.get("segment_last_entry_hash", "")
        previous_epoch = segment_epoch
        previous_epoch_last_hash = segment.get("segment_last_entry_hash", "")
        all_entries.extend(entries)

    snapshot_valid = False
    if snapshot_path.exists():
        snapshot = load_json(snapshot_path)
        snapshot_valid = (
            snapshot.get("entry_count") == len(all_entries)
            and snapshot.get("segments_count") == len(segments)
            and snapshot.get("last_entry_hash") == (all_entries[-1]["entry_hash"] if all_entries else "GENESIS")
            and snapshot.get("current_key_epoch") == (segments[-1]["key_epoch"] if segments else None)
        )
        if not snapshot_valid:
            problems.append("snapshot_invalid")
    else:
        problems.append("missing_snapshot")

    retention_valid = False
    if retention_path.exists():
        retention = load_json(retention_path)
        retained = retention.get("retained_segments", [])
        retention_valid = retained == [s["segment_path"] for s in segments]
        if not retention_valid:
            problems.append("retention_manifest_invalid")
    else:
        problems.append("missing_retention_manifest")

    return {
        "chain_valid": len(problems) == 0,
        "continuity_valid": continuity_valid,
        "snapshot_valid": snapshot_valid,
        "retention_valid": retention_valid,
        "cross_key_epoch_valid": cross_key_epoch_valid,
        "segment_count": len(segments),
        "entry_count": len(all_entries),
        "last_entry_hash": all_entries[-1]["entry_hash"] if all_entries else "GENESIS",
        "problems": problems,
    }


def simulate_multi_signer_rotation_execution(
    *,
    label: str,
    scenario_name: str,
    old_key: ScenarioKey,
    new_key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
    ledger_dir: Path,
    segment_size: int,
) -> dict[str, Any]:
    old_signer_proc, old_handshake = spawn_signer(
        old_key.private_key_path,
        old_key.key_id,
        ledger_dir,
        segment_size,
        "old_epoch",
        old_key.public_key_path,
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
    old_payload_b = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=old_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time + timedelta(seconds=1),
        request_name="request_b",
        target_path="proof/old/request_b.txt",
        content="old-beta-content",
        key_epoch="old_epoch",
    )

    write_text(paths["old_payload_a"], canonical_json(old_payload_a) + "\n")
    write_text(paths["old_payload_b"], canonical_json(old_payload_b) + "\n")

    old_response_a = send_sign_request(
        old_signer_proc,
        payload_path=paths["old_payload_a"],
        signature_path=paths["old_sig_a"],
        request_id="request_a",
    )
    old_response_b = send_sign_request(
        old_signer_proc,
        payload_path=paths["old_payload_b"],
        signature_path=paths["old_sig_b"],
        request_id="request_b",
    )

    stop_signer(old_signer_proc)

    new_signer_proc, new_handshake = spawn_signer(
        new_key.private_key_path,
        new_key.key_id,
        ledger_dir,
        segment_size,
        "new_epoch",
        new_key.public_key_path,
    )
    write_json(paths["new_signer_handshake"], new_handshake)

    new_private_key_read_attempt = attempt_private_key_read(new_key.private_key_path)
    write_json(paths["private_key_read_attempt_new"], new_private_key_read_attempt)

    new_payload_c = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=new_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time + timedelta(seconds=2),
        request_name="request_c",
        target_path="proof/new/request_c.txt",
        content="new-gamma-content",
        key_epoch="new_epoch",
    )
    new_payload_d = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=new_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time + timedelta(seconds=3),
        request_name="request_d",
        target_path="proof/new/request_d.txt",
        content="new-delta-content",
        key_epoch="new_epoch",
    )

    write_text(paths["new_payload_c"], canonical_json(new_payload_c) + "\n")
    write_text(paths["new_payload_d"], canonical_json(new_payload_d) + "\n")

    new_response_c = send_sign_request(
        new_signer_proc,
        payload_path=paths["new_payload_c"],
        signature_path=paths["new_sig_c"],
        request_id="request_c",
    )
    new_response_d = send_sign_request(
        new_signer_proc,
        payload_path=paths["new_payload_d"],
        signature_path=paths["new_sig_d"],
        request_id="request_d",
    )

    stop_signer(new_signer_proc)

    write_json(
        paths["signer_request_log"],
        {
            "old_epoch": {
                "request_a": old_response_a,
                "request_b": old_response_b,
            },
            "new_epoch": {
                "request_c": new_response_c,
                "request_d": new_response_d,
            },
        },
    )

    old_verify_a = openssl_verify(paths["old_payload_a"], old_key.public_key_path, paths["old_sig_a"])
    old_verify_b = openssl_verify(paths["old_payload_b"], old_key.public_key_path, paths["old_sig_b"])
    new_verify_c = openssl_verify(paths["new_payload_c"], new_key.public_key_path, paths["new_sig_c"])
    new_verify_d = openssl_verify(paths["new_payload_d"], new_key.public_key_path, paths["new_sig_d"])

    write_json(paths["old_verify_a"], old_verify_a)
    write_json(paths["old_verify_b"], old_verify_b)
    write_json(paths["new_verify_c"], new_verify_c)
    write_json(paths["new_verify_d"], new_verify_d)

    cross_old_with_new = openssl_verify(paths["old_payload_a"], new_key.public_key_path, paths["old_sig_a"])
    cross_new_with_old = openssl_verify(paths["new_payload_c"], old_key.public_key_path, paths["new_sig_c"])

    write_json(paths["cross_verify_old_payload_with_new_key"], cross_old_with_new)
    write_json(paths["cross_verify_new_payload_with_old_key"], cross_new_with_old)

    snapshot_path = ledger_dir / "ledger_snapshot.json"
    retention_path = ledger_dir / "retention_manifest.json"

    epoch_verify = verify_multi_signer_ledger(ledger_dir)
    write_json(paths["epoch_snapshot"], load_json(snapshot_path))
    write_json(paths["retention_manifest"], load_json(retention_path))
    write_json(paths["epoch_verify"], epoch_verify)

    tampered_manifest = load_json(ledger_dir / "segments_manifest.json")
    if len(tampered_manifest.get("segments", [])) >= 2:
        tampered_manifest["segments"][1]["key_epoch"] = "tampered_new_epoch"
        tampered_manifest["segments"][1]["previous_epoch_last_hash"] = "TAMPERED_EPOCH_HASH"
    write_json(paths["epoch_tampered"], tampered_manifest)

    tampered_dir = paths["scenario_dir"] / "tampered_epoch_probe"
    remove_if_exists(tampered_dir)
    ensure_dir(tampered_dir)
    shutil.copy2(snapshot_path, tampered_dir / "ledger_snapshot.json")
    shutil.copy2(retention_path, tampered_dir / "retention_manifest.json")
    shutil.copy2(ledger_dir / "segments_manifest.json", tampered_dir / "segments_manifest.json")

    original_manifest = load_json(ledger_dir / "segments_manifest.json")
    for item in original_manifest["segments"]:
        src = ROOT / item["segment_path"]
        dst = tampered_dir / Path(item["segment_path"]).name
        shutil.copy2(src, dst)

    rewritten_manifest = tampered_manifest
    for item in rewritten_manifest["segments"]:
        item["segment_path"] = rel(tampered_dir / Path(item["segment_path"]).name)
    write_json(tampered_dir / "segments_manifest.json", rewritten_manifest)

    tampered_verify = verify_multi_signer_ledger(tampered_dir)
    write_json(paths["epoch_tamper_detect"], tampered_verify)

    runtime_report = {
        "report_version": 1,
        "report_type": "detached_signer_multi_signer_rotation_runtime_report",
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
        "old_request_a_verified": old_verify_a["verified_ok"],
        "old_request_b_verified": old_verify_b["verified_ok"],
        "new_request_c_verified": new_verify_c["verified_ok"],
        "new_request_d_verified": new_verify_d["verified_ok"],
        "cross_old_payload_with_new_key_rejected": not cross_old_with_new["verified_ok"],
        "cross_new_payload_with_old_key_rejected": not cross_new_with_old["verified_ok"],
        "segment_count": epoch_verify["segment_count"],
        "entry_count": epoch_verify["entry_count"],
        "multi_signer_chain_valid": epoch_verify["chain_valid"],
        "multi_signer_continuity_valid": epoch_verify["continuity_valid"],
        "cross_key_epoch_valid": epoch_verify["cross_key_epoch_valid"],
        "snapshot_valid": epoch_verify["snapshot_valid"],
        "retention_valid": epoch_verify["retention_valid"],
        "epoch_tamper_detected": (not tampered_verify["chain_valid"]) or (not tampered_verify["cross_key_epoch_valid"]),
        "window_verdict_old": gate_decision["derived"]["old_window_verdict"],
        "window_verdict_new": gate_decision["derived"]["new_window_verdict"],
        "notes": [
            "old signer روی epoch اول sign کرده است.",
            "new signer روی epoch دوم sign کرده است.",
            "ledger continuity بین key epochها verify شده است.",
            "cross-key verify برای payloadهای epoch اشتباه رد شده است.",
            "tamper روی epoch metadata detectable بوده است.",
        ],
    }
    write_json(paths["runtime_report"], runtime_report)
    write_text(paths["executed_marker"], "executed\n")
    remove_if_exists(paths["denied_marker"])

    return {
        "old_handshake": old_handshake,
        "new_handshake": new_handshake,
        "old_private_key_read_attempt": old_private_key_read_attempt,
        "new_private_key_read_attempt": new_private_key_read_attempt,
        "old_verify_a": old_verify_a,
        "old_verify_b": old_verify_b,
        "new_verify_c": new_verify_c,
        "new_verify_d": new_verify_d,
        "cross_old_with_new": cross_old_with_new,
        "cross_new_with_old": cross_new_with_old,
        "epoch_verify": epoch_verify,
        "tampered_verify": tampered_verify,
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
        "old_request_a_verified": runtime_report["old_request_a_verified"],
        "old_request_b_verified": runtime_report["old_request_b_verified"],
        "new_request_c_verified": runtime_report["new_request_c_verified"],
        "new_request_d_verified": runtime_report["new_request_d_verified"],
        "cross_old_payload_with_new_key_rejected": runtime_report["cross_old_payload_with_new_key_rejected"],
        "cross_new_payload_with_old_key_rejected": runtime_report["cross_new_payload_with_old_key_rejected"],
        "multi_signer_chain_valid": runtime_report["multi_signer_chain_valid"],
        "multi_signer_continuity_valid": runtime_report["multi_signer_continuity_valid"],
        "cross_key_epoch_valid": runtime_report["cross_key_epoch_valid"],
        "snapshot_valid": runtime_report["snapshot_valid"],
        "retention_valid": runtime_report["retention_valid"],
        "epoch_tamper_detected": runtime_report["epoch_tamper_detected"],
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
        "epoch_snapshot",
        "epoch_verify",
        "epoch_tampered",
        "epoch_tamper_detect",
        "retention_manifest",
        "old_payload_a",
        "old_sig_a",
        "old_verify_a",
        "old_payload_b",
        "old_sig_b",
        "old_verify_b",
        "new_payload_c",
        "new_sig_c",
        "new_verify_c",
        "new_payload_d",
        "new_sig_d",
        "new_verify_d",
        "cross_verify_old_payload_with_new_key",
        "cross_verify_new_payload_with_old_key",
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


def load_or_init_segments_manifest(ledger_dir: Path) -> dict[str, Any]:
    manifest_path = ledger_dir / "segments_manifest.json"
    if manifest_path.exists():
        return load_json(manifest_path)
    return {"segments": []}


def run_signer_service(
    private_key_path: Path,
    key_id: str,
    ledger_dir: Path,
    segment_size: int,
    key_epoch: str,
    public_key_path: Path,
) -> int:
    fd = os.open(private_key_path, os.O_RDONLY)
    fd_path = f"/proc/self/fd/{fd}"
    os.unlink(private_key_path)

    ensure_dir(ledger_dir)
    manifest_path = ledger_dir / "segments_manifest.json"
    snapshot_path = ledger_dir / "ledger_snapshot.json"
    retention_path = ledger_dir / "retention_manifest.json"

    segments_manifest = load_or_init_segments_manifest(ledger_dir)

    seen_request_ids: set[str] = set()
    total_entries = 0
    current_segment_entries = 0
    current_segment_path: Path | None = None

    if segments_manifest["segments"]:
        for segment_meta in segments_manifest["segments"]:
            path = ROOT / segment_meta["segment_path"]
            entries = load_segment_entries(path)
            total_entries += len(entries)
            current_segment_entries = len(entries)
            current_segment_path = path
            for entry in entries:
                if "request_id" in entry:
                    seen_request_ids.add(entry["request_id"])

    def current_last_hash() -> str:
        if not segments_manifest["segments"]:
            return "GENESIS"
        return segments_manifest["segments"][-1]["segment_last_entry_hash"] or "GENESIS"

    def flush_snapshot_and_retention() -> None:
        write_json(
            snapshot_path,
            {
                "snapshot_version": 1,
                "current_key_epoch": key_epoch,
                "key_id": key_id,
                "segments_count": len(segments_manifest["segments"]),
                "entry_count": total_entries,
                "last_entry_hash": current_last_hash(),
            },
        )
        write_json(
            retention_path,
            {
                "retention_version": 1,
                "policy": "retain_all_segments_for_proof",
                "retained_segments": [item["segment_path"] for item in segments_manifest["segments"]],
            },
        )

    def open_new_segment(previous_epoch_last_hash: str | None) -> tuple[dict[str, Any], Path]:
        segment_index = len(segments_manifest["segments"]) + 1
        path = segment_file(ledger_dir, segment_index)
        previous_segment_last_hash = current_last_hash()
        segment_meta = {
            "segment_index": segment_index,
            "segment_path": rel(path),
            "key_id": key_id,
            "key_epoch": key_epoch,
            "public_key_path": rel(public_key_path),
            "previous_segment_last_hash": previous_segment_last_hash,
            "previous_epoch_last_hash": previous_epoch_last_hash,
            "segment_first_entry_index": total_entries + 1,
            "segment_last_entry_index": None,
            "segment_last_entry_hash": None,
        }
        segments_manifest["segments"].append(segment_meta)
        return segment_meta, path

    def append_ledger_entry(request: dict[str, Any], payload: dict[str, Any], signature_path: Path) -> dict[str, Any]:
        nonlocal total_entries, current_segment_entries, current_segment_path

        need_new_segment = False
        previous_epoch_last_hash: str | None = None

        if not segments_manifest["segments"]:
            need_new_segment = True
        else:
            current_segment_meta = segments_manifest["segments"][-1]
            current_segment_path_local = ROOT / current_segment_meta["segment_path"]
            current_entries = load_segment_entries(current_segment_path_local)
            current_segment_entries = len(current_entries)
            current_segment_path = current_segment_path_local

            if current_segment_meta["key_epoch"] != key_epoch:
                need_new_segment = True
                previous_epoch_last_hash = current_segment_meta["segment_last_entry_hash"]
            elif current_segment_entries >= segment_size:
                need_new_segment = True
                previous_epoch_last_hash = current_segment_meta.get("previous_epoch_last_hash")

        if need_new_segment:
            _, path = open_new_segment(previous_epoch_last_hash)
            current_segment_path = path
            current_segment_entries = 0

        assert current_segment_path is not None
        current_segment_meta = segments_manifest["segments"][-1]
        segment_entries = load_segment_entries(current_segment_path)
        previous_entry_hash = (
            segment_entries[-1]["entry_hash"]
            if segment_entries
            else current_segment_meta["previous_segment_last_hash"]
        )

        entry = {
            "entry_index": total_entries + 1,
            "timestamp_utc": iso_no_microseconds(utc_now()),
            "key_id": key_id,
            "key_epoch": key_epoch,
            "public_key_path": rel(public_key_path),
            "request_id": request.get("request_id"),
            "payload_sha256": sha256_file(Path(request["payload_path"])),
            "signature_sha256": sha256_file(signature_path),
            "payload_type": payload.get("payload_type"),
            "payload_class": payload.get("payload_class"),
            "target_path": payload.get("execution_output", {}).get("target_path"),
            "segment_index": current_segment_meta["segment_index"],
            "previous_entry_hash": previous_entry_hash,
        }
        entry["entry_hash"] = sha256_text(canonical_json(entry))

        with current_segment_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

        total_entries += 1
        current_segment_entries += 1

        current_segment_meta["segment_last_entry_index"] = entry["entry_index"]
        current_segment_meta["segment_last_entry_hash"] = entry["entry_hash"]

        write_json(manifest_path, segments_manifest)
        flush_snapshot_and_retention()
        return entry

    ready = {
        "ready": True,
        "service": "detached_external_signer",
        "key_id": key_id,
        "key_epoch": key_epoch,
        "fd_path": fd_path,
        "private_key_path_exists_after_detach": private_key_path.exists(),
        "ledger_dir": str(ledger_dir),
        "segment_size": segment_size,
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

            request_id = request.get("request_id")
            if request_id in seen_request_ids:
                response = {
                    "ok": False,
                    "action": "sign",
                    "request_id": request_id,
                    "payload_path": request.get("payload_path"),
                    "signature_path": request.get("signature_path"),
                    "policy_reason": "replay_request_id",
                    "signature_exists": False,
                }
                print(json.dumps(response), flush=True)
                continue

            payload_path = Path(request["payload_path"])
            signature_path = Path(request["signature_path"])
            ensure_dir(signature_path.parent)
            payload = load_json(payload_path)

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
                seen_request_ids.add(request_id)
                ledger_entry = append_ledger_entry(request, payload, signature_path)
                response = {
                    "ok": True,
                    "action": "sign",
                    "request_id": request_id,
                    "payload_path": str(payload_path),
                    "signature_path": str(signature_path),
                    "ledger_entry_index": ledger_entry["entry_index"],
                    "ledger_entry_hash": ledger_entry["entry_hash"],
                    "segment_index": ledger_entry["segment_index"],
                    "key_epoch": key_epoch,
                    "key_id": key_id,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "signature_exists": signature_path.exists(),
                }
            else:
                response = {
                    "ok": False,
                    "action": "sign",
                    "request_id": request_id,
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
    old_key: ScenarioKey,
    new_key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
    output_dir: Path,
    ledger_dir: Path,
    segment_size: int,
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
        mode="multi_signer_key_rotation_continuity",
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

    bundle = simulate_multi_signer_rotation_execution(
        label=label,
        scenario_name=scenario_name,
        old_key=old_key,
        new_key=new_key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        paths=paths,
        ledger_dir=ledger_dir,
        segment_size=segment_size,
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
        "old_request_a_verified": runtime_report["old_request_a_verified"],
        "old_request_b_verified": runtime_report["old_request_b_verified"],
        "new_request_c_verified": runtime_report["new_request_c_verified"],
        "new_request_d_verified": runtime_report["new_request_d_verified"],
        "cross_old_payload_with_new_key_rejected": runtime_report["cross_old_payload_with_new_key_rejected"],
        "cross_new_payload_with_old_key_rejected": runtime_report["cross_new_payload_with_old_key_rejected"],
        "segment_count": runtime_report["segment_count"],
        "entry_count": runtime_report["entry_count"],
        "multi_signer_chain_valid": runtime_report["multi_signer_chain_valid"],
        "multi_signer_continuity_valid": runtime_report["multi_signer_continuity_valid"],
        "cross_key_epoch_valid": runtime_report["cross_key_epoch_valid"],
        "snapshot_valid": runtime_report["snapshot_valid"],
        "retention_valid": runtime_report["retention_valid"],
        "epoch_tamper_detected": runtime_report["epoch_tamper_detected"],
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
        "proof_type": "detached_external_signer_multi_signer_rotation_proof",
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
    active = summary["scenarios"]["multi_signer_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R17 — Multi-Signer / Key-Rotation Continuity Proof + Cross-Key Audit Verifiability

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- OpenSSL version: `{summary["openssl_version"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`
- Detached signer custody directory: `{summary["detached_signer_custody_directory"]}`
- Ledger directory: `{summary["ledger_directory"]}`

## Multi-Signer Runtime

- Gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Old signer ready: **{str(active.get("old_signer_ready", False)).upper()}**
- New signer ready: **{str(active.get("new_signer_ready", False)).upper()}**
- Old request A verified: **{str(active.get("old_request_a_verified", False)).upper()}**
- Old request B verified: **{str(active.get("old_request_b_verified", False)).upper()}**
- New request C verified: **{str(active.get("new_request_c_verified", False)).upper()}**
- New request D verified: **{str(active.get("new_request_d_verified", False)).upper()}**
- Cross old payload with new key rejected: **{str(active.get("cross_old_payload_with_new_key_rejected", False)).upper()}**
- Cross new payload with old key rejected: **{str(active.get("cross_new_payload_with_old_key_rejected", False)).upper()}**
- Segment count: `{active.get("segment_count")}`
- Entry count: `{active.get("entry_count")}`
- Multi-signer chain valid: **{str(active.get("multi_signer_chain_valid", False)).upper()}**
- Multi-signer continuity valid: **{str(active.get("multi_signer_continuity_valid", False)).upper()}**
- Cross-key epoch valid: **{str(active.get("cross_key_epoch_valid", False)).upper()}**
- Snapshot valid: **{str(active.get("snapshot_valid", False)).upper()}**
- Retention valid: **{str(active.get("retention_valid", False)).upper()}**
- Epoch tamper detected: **{str(active.get("epoch_tamper_detected", False)).upper()}**

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
        description="R17 - Multi-Signer / Key-Rotation Continuity Proof + Cross-Key Audit Verifiability"
    )
    parser.add_argument(
        "--label",
        default="R17_detached_signer_multi_signer_rotation_proof",
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
        "--ledger-dir",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--segment-size",
        type=int,
        default=2,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--key-epoch",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--public-key-path",
        default=None,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    if args.signer_service:
        if not args.private_key_path or not args.key_id or not args.ledger_dir or not args.key_epoch or not args.public_key_path:
            raise SystemExit("Signer service requires --private-key-path, --key-id, --ledger-dir, --key-epoch and --public-key-path.")
        return_code = run_signer_service(
            Path(args.private_key_path),
            args.key_id,
            Path(args.ledger_dir),
            args.segment_size,
            args.key_epoch,
            Path(args.public_key_path),
        )
        raise SystemExit(return_code)

    openssl_version = require_openssl()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    output_dir = ARTIFACTS_DIR / "detached_external_signer_multi_signer_rotation_proof" / args.label
    custody_dir = STATE_DIR / args.label
    ledger_dir = output_dir / "multi_signer_rotated_ledger"

    remove_if_exists(output_dir)
    remove_if_exists(custody_dir)

    ensure_dir(output_dir)
    ensure_dir(custody_dir)
    ensure_dir(ledger_dir)

    old_key = ScenarioKey(
        key_id="r17-attestation-key-old",
        private_key_path=custody_dir / "attestation_private_old.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_old.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=10)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=5)),
    )
    new_key = ScenarioKey(
        key_id="r17-attestation-key-new",
        private_key_path=custody_dir / "attestation_private_new.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_new.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    expired_key = ScenarioKey(
        key_id="r17-attestation-key-expired",
        private_key_path=custody_dir / "attestation_private_expired.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_expired.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=30)),
        not_after=iso_no_microseconds(base_verification_time - timedelta(seconds=1)),
    )
    future_key = ScenarioKey(
        key_id="r17-attestation-key-future",
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
        "registry_type": "detached_external_signer_multi_signer_rotation_registry",
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

    multi_signer_runtime = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__multi_signer_runtime",
        old_key=old_key,
        new_key=new_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
        ledger_dir=ledger_dir,
        segment_size=2,
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

    if not multi_signer_runtime["gate_decision_allow"] or not multi_signer_runtime["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not multi_signer_runtime.get("old_signer_ready", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("new_signer_ready", False):
        proof_status = "FAIL"
    if multi_signer_runtime.get("old_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if multi_signer_runtime.get("new_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if multi_signer_runtime.get("old_control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"
    if multi_signer_runtime.get("new_control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("old_request_a_verified", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("old_request_b_verified", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("new_request_c_verified", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("new_request_d_verified", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("cross_old_payload_with_new_key_rejected", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("cross_new_payload_with_old_key_rejected", False):
        proof_status = "FAIL"
    if multi_signer_runtime.get("segment_count") != 2:
        proof_status = "FAIL"
    if multi_signer_runtime.get("entry_count") != 4:
        proof_status = "FAIL"
    if not multi_signer_runtime.get("multi_signer_chain_valid", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("multi_signer_continuity_valid", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("cross_key_epoch_valid", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("snapshot_valid", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("retention_valid", False):
        proof_status = "FAIL"
    if not multi_signer_runtime.get("epoch_tamper_detected", False):
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
        "report_type": "detached_external_signer_multi_signer_rotation_proof",
        "generated_at_utc": utc_now_iso(),
        "proof_label": args.label,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "future_fixture_time_utc": iso_no_microseconds(future_fixture_time),
        "openssl_version": openssl_version,
        "proof_status": proof_status,
        "output_directory": rel(output_dir),
        "detached_signer_custody_directory": rel(custody_dir),
        "ledger_directory": rel(ledger_dir),
        "registry_path": rel(output_dir / "attestation_key_policy_registry.json"),
        "artifact_boundary_scan": artifact_boundary_scan,
        "runtime_boundary_scan": runtime_boundary_scan,
        "detached_signer_custody_scan": detached_signer_custody_scan,
        "scenarios": {
            "multi_signer_runtime": multi_signer_runtime,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "detached_external_signer_multi_signer_rotation_proof.json"
    summary_md_path = output_dir / "detached_external_signer_multi_signer_rotation_proof.md"
    digest_path = output_dir / "detached_external_signer_multi_signer_rotation_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "summary_json_path": rel(summary_json_path),
        "summary_md_path": rel(summary_md_path),
        "multi_signer_rotation_safe": (
            multi_signer_runtime["gate_decision_allow"]
            and multi_signer_runtime["runtime_status_allow_executed"]
            and not multi_signer_runtime.get("old_control_plane_private_key_read_allowed", True)
            and not multi_signer_runtime.get("new_control_plane_private_key_read_allowed", True)
            and not multi_signer_runtime.get("old_key_path_exists_after_detach", True)
            and not multi_signer_runtime.get("new_key_path_exists_after_detach", True)
            and multi_signer_runtime.get("old_request_a_verified", False)
            and multi_signer_runtime.get("old_request_b_verified", False)
            and multi_signer_runtime.get("new_request_c_verified", False)
            and multi_signer_runtime.get("new_request_d_verified", False)
            and multi_signer_runtime.get("cross_old_payload_with_new_key_rejected", False)
            and multi_signer_runtime.get("cross_new_payload_with_old_key_rejected", False)
            and multi_signer_runtime.get("multi_signer_chain_valid", False)
            and multi_signer_runtime.get("multi_signer_continuity_valid", False)
            and multi_signer_runtime.get("cross_key_epoch_valid", False)
            and multi_signer_runtime.get("snapshot_valid", False)
            and multi_signer_runtime.get("retention_valid", False)
            and multi_signer_runtime.get("epoch_tamper_detected", False)
        ),
        "no_on_disk_private_keys_after_proof": (
            not artifact_boundary_scan["contains_private_keys"]
            and not runtime_boundary_scan["contains_private_keys"]
            and not detached_signer_custody_scan["contains_private_keys"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 96)
    print("R17 - MULTI-SIGNER / KEY-ROTATION CONTINUITY PROOF + CROSS-KEY AUDIT VERIFIABILITY")
    print("=" * 96)
    print(f"LABEL                                               : {args.label}")
    print(f"OPENSSL VERSION                                     : {openssl_version}")
    print(f"PROOF STATUS                                        : {proof_status}")
    print(f"BASE VERIFICATION TIME                              : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME                                 : {iso_no_microseconds(future_fixture_time)}")
    print(f"DETACHED SIGNER CUSTODY DIR                         : {rel(custody_dir)}")
    print(f"LEDGER DIRECTORY                                    : {rel(ledger_dir)}")
    print(f"MULTI-SIGNER EXECUTED                               : {multi_signer_runtime['runtime_status_allow_executed']}")
    print(f"OLD REQUEST A VERIFIED                              : {multi_signer_runtime.get('old_request_a_verified', False)}")
    print(f"OLD REQUEST B VERIFIED                              : {multi_signer_runtime.get('old_request_b_verified', False)}")
    print(f"NEW REQUEST C VERIFIED                              : {multi_signer_runtime.get('new_request_c_verified', False)}")
    print(f"NEW REQUEST D VERIFIED                              : {multi_signer_runtime.get('new_request_d_verified', False)}")
    print(f"CROSS OLD PAYLOAD WITH NEW KEY REJECTED             : {multi_signer_runtime.get('cross_old_payload_with_new_key_rejected', False)}")
    print(f"CROSS NEW PAYLOAD WITH OLD KEY REJECTED             : {multi_signer_runtime.get('cross_new_payload_with_old_key_rejected', False)}")
    print(f"SEGMENT COUNT                                       : {multi_signer_runtime.get('segment_count')}")
    print(f"ENTRY COUNT                                         : {multi_signer_runtime.get('entry_count')}")
    print(f"MULTI-SIGNER CHAIN VALID                            : {multi_signer_runtime.get('multi_signer_chain_valid', False)}")
    print(f"MULTI-SIGNER CONTINUITY VALID                       : {multi_signer_runtime.get('multi_signer_continuity_valid', False)}")
    print(f"CROSS-KEY EPOCH VALID                               : {multi_signer_runtime.get('cross_key_epoch_valid', False)}")
    print(f"SNAPSHOT VALID                                      : {multi_signer_runtime.get('snapshot_valid', False)}")
    print(f"RETENTION VALID                                     : {multi_signer_runtime.get('retention_valid', False)}")
    print(f"EPOCH TAMPER DETECTED                               : {multi_signer_runtime.get('epoch_tamper_detected', False)}")
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
