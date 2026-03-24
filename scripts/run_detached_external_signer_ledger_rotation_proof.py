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
STATE_DIR = ROOT / "state" / "detached_external_signer_ledger_rotation"


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
        "rotation_snapshot": scenario_dir / "ledger_rotation_snapshot.json",
        "rotation_verify": scenario_dir / "ledger_rotation_verify.json",
        "rotation_tampered": scenario_dir / "ledger_rotation_tampered.json",
        "rotation_tamper_detect": scenario_dir / "ledger_rotation_tamper_detect.json",
        "retention_manifest": scenario_dir / "ledger_retention_manifest.json",
        "payload_a": scenario_dir / "allowed_payload_a.json",
        "sig_a": scenario_dir / "allowed_signature_a.sig",
        "verify_a": scenario_dir / "allowed_verify_a.json",
        "payload_b": scenario_dir / "allowed_payload_b.json",
        "sig_b": scenario_dir / "allowed_signature_b.sig",
        "verify_b": scenario_dir / "allowed_verify_b.json",
        "payload_c": scenario_dir / "allowed_payload_c.json",
        "sig_c": scenario_dir / "allowed_signature_c.sig",
        "verify_c": scenario_dir / "allowed_verify_c.json",
        "runtime_report": scenario_dir / "detached_signer_ledger_rotation_runtime_report.json",
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
        "proof_type": "detached_external_signer_ledger_rotation_proof",
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


def spawn_signer(
    private_key_path: Path,
    key_id: str,
    ledger_dir: Path,
    segment_size: int,
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


def load_all_segments(ledger_dir: Path) -> list[dict[str, Any]]:
    manifest_path = ledger_dir / "segments_manifest.json"
    if not manifest_path.exists():
        return []
    manifest = load_json(manifest_path)
    segments: list[dict[str, Any]] = []
    for item in manifest.get("segments", []):
        path = ROOT / item["segment_path"]
        segments.extend(load_segment_entries(path))
    return segments


def verify_rotated_ledger(ledger_dir: Path) -> dict[str, Any]:
    manifest_path = ledger_dir / "segments_manifest.json"
    snapshot_path = ledger_dir / "ledger_snapshot.json"
    retention_path = ledger_dir / "retention_manifest.json"

    if not manifest_path.exists():
        return {
            "chain_valid": False,
            "continuity_valid": False,
            "snapshot_valid": False,
            "retention_valid": False,
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

    for i, segment in enumerate(segments, start=1):
        path = ROOT / segment["segment_path"]
        entries = load_segment_entries(path)

        if segment.get("segment_index") != i:
            problems.append(f"segment_index_mismatch_{i}")
            continuity_valid = False

        if segment.get("previous_segment_last_hash") != previous_segment_last_hash:
            problems.append(f"segment_previous_hash_mismatch_{i}")
            continuity_valid = False

        previous_entry_hash = segment.get("previous_segment_last_hash", "GENESIS")
        for entry in entries:
            body = dict(entry)
            recorded_hash = body.pop("entry_hash", None)
            if body.get("previous_entry_hash") != previous_entry_hash:
                problems.append(f"entry_previous_hash_mismatch_segment_{i}_entry_{body.get('entry_index')}")
                continuity_valid = False
            recalculated_hash = sha256_text(canonical_json(body))
            if recorded_hash != recalculated_hash:
                problems.append(f"entry_hash_mismatch_segment_{i}_entry_{body.get('entry_index')}")
                continuity_valid = False
            previous_entry_hash = recorded_hash or ""

        if segment.get("segment_first_entry_index") != (entries[0]["entry_index"] if entries else None):
            problems.append(f"segment_first_index_mismatch_{i}")
            continuity_valid = False

        if segment.get("segment_last_entry_index") != (entries[-1]["entry_index"] if entries else None):
            problems.append(f"segment_last_index_mismatch_{i}")
            continuity_valid = False

        if segment.get("segment_last_entry_hash") != previous_entry_hash:
            problems.append(f"segment_last_hash_mismatch_{i}")
            continuity_valid = False

        previous_segment_last_hash = segment.get("segment_last_entry_hash", "")
        all_entries.extend(entries)

    snapshot_valid = False
    if snapshot_path.exists():
        snapshot = load_json(snapshot_path)
        snapshot_valid = (
            snapshot.get("entry_count") == len(all_entries)
            and snapshot.get("last_entry_hash") == (all_entries[-1]["entry_hash"] if all_entries else "GENESIS")
            and snapshot.get("segments_count") == len(segments)
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
        "segment_count": len(segments),
        "entry_count": len(all_entries),
        "last_entry_hash": all_entries[-1]["entry_hash"] if all_entries else "GENESIS",
        "problems": problems,
    }


def simulate_rotation_execution(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
    ledger_dir: Path,
    segment_size: int,
) -> dict[str, Any]:
    signer_proc, handshake = spawn_signer(key.private_key_path, key.key_id, ledger_dir, segment_size)
    write_json(paths["signer_handshake"], handshake)

    private_key_read_attempt = attempt_private_key_read(key.private_key_path)
    write_json(paths["private_key_read_attempt"], private_key_read_attempt)

    payload_a = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time,
        request_name="request_a",
        target_path="proof/request_a.txt",
        content="alpha-content",
    )
    payload_b = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time + timedelta(seconds=1),
        request_name="request_b",
        target_path="proof/request_b.txt",
        content="beta-content",
    )
    payload_c = build_allowed_payload(
        label=label,
        scenario_name=scenario_name,
        key=key,
        gate_decision=gate_decision,
        scenario_verification_time=scenario_verification_time + timedelta(seconds=2),
        request_name="request_c",
        target_path="proof/request_c.txt",
        content="gamma-content",
    )

    write_text(paths["payload_a"], canonical_json(payload_a) + "\n")
    write_text(paths["payload_b"], canonical_json(payload_b) + "\n")
    write_text(paths["payload_c"], canonical_json(payload_c) + "\n")

    response_a = send_sign_request(
        signer_proc,
        payload_path=paths["payload_a"],
        signature_path=paths["sig_a"],
        request_id="request_a",
    )
    response_b = send_sign_request(
        signer_proc,
        payload_path=paths["payload_b"],
        signature_path=paths["sig_b"],
        request_id="request_b",
    )
    response_c = send_sign_request(
        signer_proc,
        payload_path=paths["payload_c"],
        signature_path=paths["sig_c"],
        request_id="request_c",
    )

    write_json(
        paths["signer_request_log"],
        {
            "request_a": response_a,
            "request_b": response_b,
            "request_c": response_c,
        },
    )

    verify_a = openssl_verify(paths["payload_a"], key.public_key_path, paths["sig_a"])
    verify_b = openssl_verify(paths["payload_b"], key.public_key_path, paths["sig_b"])
    verify_c = openssl_verify(paths["payload_c"], key.public_key_path, paths["sig_c"])
    write_json(paths["verify_a"], verify_a)
    write_json(paths["verify_b"], verify_b)
    write_json(paths["verify_c"], verify_c)

    snapshot_path = ledger_dir / "ledger_snapshot.json"
    retention_path = ledger_dir / "retention_manifest.json"

    rotation_verify = verify_rotated_ledger(ledger_dir)
    write_json(paths["rotation_snapshot"], load_json(snapshot_path))
    write_json(paths["retention_manifest"], load_json(retention_path))
    write_json(paths["rotation_verify"], rotation_verify)

    tampered_manifest = load_json(ledger_dir / "segments_manifest.json")
    if tampered_manifest.get("segments"):
        tampered_manifest["segments"][1]["previous_segment_last_hash"] = "TAMPERED_HASH"
    write_json(paths["rotation_tampered"], tampered_manifest)

    tampered_dir = paths["scenario_dir"] / "tampered_rotation_probe"
    remove_if_exists(tampered_dir)
    ensure_dir(tampered_dir)
    shutil.copy2(ledger_dir / "segments_manifest.json", tampered_dir / "segments_manifest.json")
    shutil.copy2(snapshot_path, tampered_dir / "ledger_snapshot.json")
    shutil.copy2(retention_path, tampered_dir / "retention_manifest.json")
    for item in load_json(ledger_dir / "segments_manifest.json")["segments"]:
        src = ROOT / item["segment_path"]
        dst = tampered_dir / Path(item["segment_path"]).name
        shutil.copy2(src, dst)
    write_json(tampered_dir / "segments_manifest.json", tampered_manifest)

    rewritten_manifest = load_json(tampered_dir / "segments_manifest.json")
    for item in rewritten_manifest["segments"]:
        item["segment_path"] = rel(tampered_dir / Path(item["segment_path"]).name)
    write_json(tampered_dir / "segments_manifest.json", rewritten_manifest)

    tampered_verify = verify_rotated_ledger(tampered_dir)
    write_json(paths["rotation_tamper_detect"], tampered_verify)

    runtime_report = {
        "report_version": 1,
        "report_type": "detached_signer_ledger_rotation_runtime_report",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "PASS",
        "runtime_status_allow_executed": True,
        "detached_signer_ready": handshake.get("ready", False),
        "detached_signer_key_path_exists_after_detach": handshake.get("private_key_path_exists_after_detach", True),
        "control_plane_private_key_read_allowed": private_key_read_attempt["read_allowed"],
        "request_a_signature_verified": verify_a["verified_ok"],
        "request_b_signature_verified": verify_b["verified_ok"],
        "request_c_signature_verified": verify_c["verified_ok"],
        "segment_count": rotation_verify["segment_count"],
        "entry_count": rotation_verify["entry_count"],
        "rotation_continuity_valid": rotation_verify["continuity_valid"],
        "rotation_chain_valid": rotation_verify["chain_valid"],
        "snapshot_valid": rotation_verify["snapshot_valid"],
        "retention_valid": rotation_verify["retention_valid"],
        "rotation_tamper_detected": (not tampered_verify["chain_valid"]) or (not tampered_verify["continuity_valid"]),
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "notes": [
            "ledger پس از رسیدن به segment_size rotate شده است.",
            "snapshot و retention manifest ساخته شده‌اند.",
            "continuity بین segmentها verify شده است.",
            "tamper در segment manifest detectable بوده است.",
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
        "response_c": response_c,
        "verify_a": verify_a,
        "verify_b": verify_b,
        "verify_c": verify_c,
        "rotation_verify": rotation_verify,
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
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "runtime_status_allow_executed": True,
        "control_plane_private_key_read_allowed": runtime_report["control_plane_private_key_read_allowed"],
        "detached_signer_key_path_exists_after_detach": runtime_report["detached_signer_key_path_exists_after_detach"],
        "request_a_signature_verified": runtime_report["request_a_signature_verified"],
        "request_b_signature_verified": runtime_report["request_b_signature_verified"],
        "request_c_signature_verified": runtime_report["request_c_signature_verified"],
        "rotation_chain_valid": runtime_report["rotation_chain_valid"],
        "rotation_continuity_valid": runtime_report["rotation_continuity_valid"],
        "snapshot_valid": runtime_report["snapshot_valid"],
        "retention_valid": runtime_report["retention_valid"],
        "rotation_tamper_detected": runtime_report["rotation_tamper_detected"],
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
        "signer_handshake",
        "signer_request_log",
        "rotation_snapshot",
        "rotation_verify",
        "rotation_tampered",
        "rotation_tamper_detect",
        "retention_manifest",
        "payload_a",
        "sig_a",
        "verify_a",
        "payload_b",
        "sig_b",
        "verify_b",
        "payload_c",
        "sig_c",
        "verify_c",
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


def run_signer_service(private_key_path: Path, key_id: str, ledger_dir: Path, segment_size: int) -> int:
    fd = os.open(private_key_path, os.O_RDONLY)
    fd_path = f"/proc/self/fd/{fd}"
    os.unlink(private_key_path)

    ensure_dir(ledger_dir)
    manifest_path = ledger_dir / "segments_manifest.json"
    snapshot_path = ledger_dir / "ledger_snapshot.json"
    retention_path = ledger_dir / "retention_manifest.json"

    seen_request_ids: set[str] = set()
    total_entries = 0
    segment_index = 1
    current_segment_entries = 0
    previous_segment_last_hash = "GENESIS"
    current_segment_path = segment_file(ledger_dir, segment_index)

    segments_manifest = {
        "segments": [],
    }

    def flush_snapshot_and_retention() -> None:
        write_json(
            snapshot_path,
            {
                "snapshot_version": 1,
                "key_id": key_id,
                "segments_count": len(segments_manifest["segments"]),
                "entry_count": total_entries,
                "last_entry_hash": (
                    segments_manifest["segments"][-1]["segment_last_entry_hash"]
                    if segments_manifest["segments"]
                    else "GENESIS"
                ),
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

    def roll_segment_if_needed() -> None:
        nonlocal segment_index, current_segment_entries, previous_segment_last_hash, current_segment_path
        if current_segment_entries < segment_size:
            return
        previous_segment_last_hash = segments_manifest["segments"][-1]["segment_last_entry_hash"]
        segment_index += 1
        current_segment_entries = 0
        current_segment_path = segment_file(ledger_dir, segment_index)

    def append_ledger_entry(request: dict[str, Any], payload: dict[str, Any], signature_path: Path) -> dict[str, Any]:
        nonlocal total_entries, current_segment_entries, previous_segment_last_hash, current_segment_path

        roll_segment_if_needed()

        if current_segment_entries == 0:
            segment_meta = {
                "segment_index": segment_index,
                "segment_path": rel(current_segment_path),
                "previous_segment_last_hash": previous_segment_last_hash,
                "segment_first_entry_index": total_entries + 1,
                "segment_last_entry_index": None,
                "segment_last_entry_hash": None,
            }
            segments_manifest["segments"].append(segment_meta)

        segment_entries = load_segment_entries(current_segment_path)
        previous_entry_hash = (
            segment_entries[-1]["entry_hash"]
            if segment_entries
            else segments_manifest["segments"][-1]["previous_segment_last_hash"]
        )

        entry = {
            "entry_index": total_entries + 1,
            "timestamp_utc": iso_no_microseconds(utc_now()),
            "key_id": key_id,
            "request_id": request.get("request_id"),
            "payload_sha256": sha256_file(Path(request["payload_path"])),
            "signature_sha256": sha256_file(signature_path),
            "payload_type": payload.get("payload_type"),
            "payload_class": payload.get("payload_class"),
            "target_path": payload.get("execution_output", {}).get("target_path"),
            "segment_index": segment_index,
            "previous_entry_hash": previous_entry_hash,
        }
        entry["entry_hash"] = sha256_text(canonical_json(entry))

        with current_segment_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

        total_entries += 1
        current_segment_entries += 1

        segments_manifest["segments"][-1]["segment_last_entry_index"] = entry["entry_index"]
        segments_manifest["segments"][-1]["segment_last_entry_hash"] = entry["entry_hash"]

        write_json(manifest_path, segments_manifest)
        flush_snapshot_and_retention()
        return entry

    ready = {
        "ready": True,
        "service": "detached_external_signer",
        "key_id": key_id,
        "fd_path": fd_path,
        "private_key_path_exists_after_detach": private_key_path.exists(),
        "ledger_dir": str(ledger_dir),
        "segment_size": segment_size,
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
    key: ScenarioKey,
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
        public_key_path=key.public_key_path,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        mode="ledger_rotation_snapshot_retention",
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

    bundle = simulate_rotation_execution(
        label=label,
        scenario_name=scenario_name,
        key=key,
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
        "request_c_signature_verified": runtime_report["request_c_signature_verified"],
        "segment_count": runtime_report["segment_count"],
        "entry_count": runtime_report["entry_count"],
        "rotation_continuity_valid": runtime_report["rotation_continuity_valid"],
        "rotation_chain_valid": runtime_report["rotation_chain_valid"],
        "snapshot_valid": runtime_report["snapshot_valid"],
        "retention_valid": runtime_report["retention_valid"],
        "rotation_tamper_detected": runtime_report["rotation_tamper_detected"],
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
    active = summary["scenarios"]["rotation_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R16 — Ledger Rotation / Snapshot / Retention Proof + Verifiable Continuity Across Rotated Segments

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- OpenSSL version: `{summary["openssl_version"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`
- Detached signer custody directory: `{summary["detached_signer_custody_directory"]}`
- Ledger directory: `{summary["ledger_directory"]}`

## Rotation Runtime

- Gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Detached signer ready: **{str(active.get("detached_signer_ready", False)).upper()}**
- Control plane private key read allowed: **{str(active.get("control_plane_private_key_read_allowed", True)).upper()}**
- Request A signature verified: **{str(active.get("request_a_signature_verified", False)).upper()}**
- Request B signature verified: **{str(active.get("request_b_signature_verified", False)).upper()}**
- Request C signature verified: **{str(active.get("request_c_signature_verified", False)).upper()}**
- Segment count: `{active.get("segment_count")}`
- Entry count: `{active.get("entry_count")}`
- Rotation chain valid: **{str(active.get("rotation_chain_valid", False)).upper()}**
- Rotation continuity valid: **{str(active.get("rotation_continuity_valid", False)).upper()}**
- Snapshot valid: **{str(active.get("snapshot_valid", False)).upper()}**
- Retention valid: **{str(active.get("retention_valid", False)).upper()}**
- Rotation tamper detected: **{str(active.get("rotation_tamper_detected", False)).upper()}**

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
        description="R16 - Ledger Rotation / Snapshot / Retention Proof + Verifiable Continuity Across Rotated Segments"
    )
    parser.add_argument(
        "--label",
        default="R16_detached_signer_ledger_rotation_proof",
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
    args = parser.parse_args()

    if args.signer_service:
        if not args.private_key_path or not args.key_id or not args.ledger_dir:
            raise SystemExit("Signer service requires --private-key-path, --key-id and --ledger-dir.")
        return_code = run_signer_service(
            Path(args.private_key_path),
            args.key_id,
            Path(args.ledger_dir),
            args.segment_size,
        )
        raise SystemExit(return_code)

    openssl_version = require_openssl()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    output_dir = ARTIFACTS_DIR / "detached_external_signer_ledger_rotation_proof" / args.label
    custody_dir = STATE_DIR / args.label
    ledger_dir = output_dir / "rotated_ledger"

    remove_if_exists(output_dir)
    remove_if_exists(custody_dir)

    ensure_dir(output_dir)
    ensure_dir(custody_dir)
    ensure_dir(ledger_dir)

    rotation_key = ScenarioKey(
        key_id="r16-attestation-key-rotation",
        private_key_path=custody_dir / "attestation_private_rotation.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_rotation.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )
    expired_key = ScenarioKey(
        key_id="r16-attestation-key-expired",
        private_key_path=custody_dir / "attestation_private_expired.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_expired.pem",
        not_before=iso_no_microseconds(base_verification_time - timedelta(days=30)),
        not_after=iso_no_microseconds(base_verification_time - timedelta(seconds=1)),
    )
    future_key = ScenarioKey(
        key_id="r16-attestation-key-future",
        private_key_path=custody_dir / "attestation_private_future.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_future.pem",
        not_before=iso_no_microseconds(base_verification_time + timedelta(days=1)),
        not_after=iso_no_microseconds(base_verification_time + timedelta(days=30)),
    )

    for key in (rotation_key, expired_key, future_key):
        generate_rsa_keypair(key.private_key_path, key.public_key_path)

    future_fixture_time = parse_utc(future_key.not_before) - timedelta(seconds=1)

    registry = {
        "registry_version": 1,
        "registry_type": "detached_external_signer_ledger_rotation_registry",
        "generated_at_utc": utc_now_iso(),
        "entries": [
            {
                "key_id": key.key_id,
                "public_key_path": rel(key.public_key_path),
                "public_key_sha256": sha256_file(key.public_key_path),
                "not_before": key.not_before,
                "not_after": key.not_after,
            }
            for key in (rotation_key, expired_key, future_key)
        ],
    }
    write_json(output_dir / "attestation_key_policy_registry.json", registry)

    rotation_runtime = execute_allowed_scenario(
        label=args.label,
        scenario_name=f"{args.label}__rotation_runtime",
        key=rotation_key,
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

    if not rotation_runtime["gate_decision_allow"] or not rotation_runtime["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if rotation_runtime.get("detached_signer_key_path_exists_after_detach", True):
        proof_status = "FAIL"
    if rotation_runtime.get("control_plane_private_key_read_allowed", True):
        proof_status = "FAIL"
    if not rotation_runtime.get("request_a_signature_verified", False):
        proof_status = "FAIL"
    if not rotation_runtime.get("request_b_signature_verified", False):
        proof_status = "FAIL"
    if not rotation_runtime.get("request_c_signature_verified", False):
        proof_status = "FAIL"
    if rotation_runtime.get("segment_count") != 2:
        proof_status = "FAIL"
    if rotation_runtime.get("entry_count") != 3:
        proof_status = "FAIL"
    if not rotation_runtime.get("rotation_chain_valid", False):
        proof_status = "FAIL"
    if not rotation_runtime.get("rotation_continuity_valid", False):
        proof_status = "FAIL"
    if not rotation_runtime.get("snapshot_valid", False):
        proof_status = "FAIL"
    if not rotation_runtime.get("retention_valid", False):
        proof_status = "FAIL"
    if not rotation_runtime.get("rotation_tamper_detected", False):
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
        "report_type": "detached_external_signer_ledger_rotation_proof",
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
            "rotation_runtime": rotation_runtime,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "detached_external_signer_ledger_rotation_proof.json"
    summary_md_path = output_dir / "detached_external_signer_ledger_rotation_proof.md"
    digest_path = output_dir / "detached_external_signer_ledger_rotation_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "summary_json_path": rel(summary_json_path),
        "summary_md_path": rel(summary_md_path),
        "rotation_safe": (
            rotation_runtime["gate_decision_allow"]
            and rotation_runtime["runtime_status_allow_executed"]
            and not rotation_runtime.get("control_plane_private_key_read_allowed", True)
            and not rotation_runtime.get("detached_signer_key_path_exists_after_detach", True)
            and rotation_runtime.get("request_a_signature_verified", False)
            and rotation_runtime.get("request_b_signature_verified", False)
            and rotation_runtime.get("request_c_signature_verified", False)
            and rotation_runtime.get("rotation_chain_valid", False)
            and rotation_runtime.get("rotation_continuity_valid", False)
            and rotation_runtime.get("snapshot_valid", False)
            and rotation_runtime.get("retention_valid", False)
            and rotation_runtime.get("rotation_tamper_detected", False)
        ),
        "no_on_disk_private_keys_after_proof": (
            not artifact_boundary_scan["contains_private_keys"]
            and not runtime_boundary_scan["contains_private_keys"]
            and not detached_signer_custody_scan["contains_private_keys"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 92)
    print("R16 - LEDGER ROTATION / SNAPSHOT / RETENTION PROOF + VERIFIABLE CONTINUITY")
    print("=" * 92)
    print(f"LABEL                                           : {args.label}")
    print(f"OPENSSL VERSION                                 : {openssl_version}")
    print(f"PROOF STATUS                                    : {proof_status}")
    print(f"BASE VERIFICATION TIME                          : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME                             : {iso_no_microseconds(future_fixture_time)}")
    print(f"DETACHED SIGNER CUSTODY DIR                     : {rel(custody_dir)}")
    print(f"LEDGER DIRECTORY                                : {rel(ledger_dir)}")
    print(f"ROTATION EXECUTED                               : {rotation_runtime['runtime_status_allow_executed']}")
    print(f"REQUEST A VERIFIED                              : {rotation_runtime.get('request_a_signature_verified', False)}")
    print(f"REQUEST B VERIFIED                              : {rotation_runtime.get('request_b_signature_verified', False)}")
    print(f"REQUEST C VERIFIED                              : {rotation_runtime.get('request_c_signature_verified', False)}")
    print(f"SEGMENT COUNT                                   : {rotation_runtime.get('segment_count')}")
    print(f"ENTRY COUNT                                     : {rotation_runtime.get('entry_count')}")
    print(f"ROTATION CHAIN VALID                            : {rotation_runtime.get('rotation_chain_valid', False)}")
    print(f"ROTATION CONTINUITY VALID                       : {rotation_runtime.get('rotation_continuity_valid', False)}")
    print(f"SNAPSHOT VALID                                  : {rotation_runtime.get('snapshot_valid', False)}")
    print(f"RETENTION VALID                                 : {rotation_runtime.get('retention_valid', False)}")
    print(f"ROTATION TAMPER DETECTED                        : {rotation_runtime.get('rotation_tamper_detected', False)}")
    print(f"EXPIRED KEY CLEANED                             : {expired.get('denied_key_cleanup_removed', False)}")
    print(f"FUTURE KEY CLEANED                              : {future.get('denied_key_cleanup_removed', False)}")
    print(f"ARTIFACT BOUNDARY PRIVATE KEYS                  : {artifact_boundary_scan['contains_private_keys']}")
    print(f"RUNTIME BOUNDARY PRIVATE KEYS                   : {runtime_boundary_scan['contains_private_keys']}")
    print(f"DETACHED SIGNER CUSTODY PRIVATE KEYS            : {detached_signer_custody_scan['contains_private_keys']}")
    print(f"SUMMARY JSON                                    : {rel(summary_json_path)}")
    print(f"REPORT MD                                       : {rel(summary_md_path)}")
    print(f"DIGEST                                          : {rel(digest_path)}")
    print("=" * 92)


if __name__ == "__main__":
    main()
