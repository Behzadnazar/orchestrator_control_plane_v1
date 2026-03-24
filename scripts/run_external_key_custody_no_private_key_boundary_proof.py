#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = ROOT / "artifacts" / "operations"
STATE_DIR = ROOT / "state" / "external_signer_custody"


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


def evaluate_window(key: ScenarioKey, verification_time_utc: datetime) -> tuple[bool, str]:
    not_before = parse_utc(key.not_before)
    not_after = parse_utc(key.not_after)

    if verification_time_utc < not_before:
        return False, "not_yet_valid"
    if verification_time_utc > not_after:
        return False, "expired"
    return True, "within_window"


def openssl_sign(data_path: Path, private_key_path: Path, signature_path: Path) -> dict[str, Any]:
    result = run_cmd(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(private_key_path),
            "-out",
            str(signature_path),
            str(data_path),
        ]
    )
    return {
        "command": [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            rel(private_key_path),
            "-out",
            rel(signature_path),
            rel(data_path),
        ],
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "signature_exists": signature_path.exists(),
    }


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


def scan_for_private_keys(base_dir: Path) -> dict[str, Any]:
    suspicious_files: list[str] = []
    pem_private_markers = (
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    )
    suspicious_names = (
        "private",
        ".key",
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

        lower_name = path.name.lower()
        content = ""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            content = ""

        has_private_marker = any(marker in content for marker in pem_private_markers)
        looks_like_private_name = (
            "private" in lower_name
            or lower_name.endswith(".key")
            or lower_name.endswith("_key.pem")
        )

        if has_private_marker:
            suspicious_files.append(rel(path))
        elif looks_like_private_name and "public" not in lower_name:
            if "signature" not in lower_name:
                suspicious_files.append(rel(path))

    return {
        "scanned_root": rel(base_dir),
        "private_key_files_found": suspicious_files,
        "contains_private_keys": len(suspicious_files) > 0,
    }


def scenario_paths(base_dir: Path, scenario_name: str) -> dict[str, Path]:
    scenario_dir = base_dir / scenario_name
    return {
        "scenario_dir": scenario_dir,
        "manifest": scenario_dir / "normalized_request_manifest.json",
        "gate_decision": scenario_dir / "pre_execution_gate_decision.json",
        "gate_report": scenario_dir / "pre_execution_gate_report.json",
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
    }


def build_manifest(
    *,
    label: str,
    scenario_name: str,
    public_key_path: Path,
    scenario_verification_time: datetime,
    verification_mode: str,
    custody_root: Path,
) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "proof_type": "external_key_custody_no_private_key_boundary_proof",
        "proof_label": label,
        "scenario": scenario_name,
        "generated_at_utc": utc_now_iso(),
        "workflow": {
            "name": "external_signed_runtime_gate",
            "mode": "external_key_custody_no_private_key_boundary",
        },
        "verification_context": {
            "verification_time_utc": iso_no_microseconds(scenario_verification_time),
            "verification_mode": verification_mode,
        },
        "key_custody": {
            "custody_mode": "external_signer_directory",
            "private_key_location": rel(custody_root),
            "public_key_visible_to_runtime": rel(public_key_path),
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
            "private_key_exists_in_external_custody": key.private_key_path.exists(),
            "public_key_sha256": sha256_file(key.public_key_path),
            "registry_key_within_window": within_window,
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


def simulate_signed_runtime_execution(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    manifest: dict[str, Any],
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
) -> dict[str, Any]:
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

    receipt_sign = openssl_sign(paths["receipt_payload"], key.private_key_path, paths["receipt_signature"])
    if receipt_sign["returncode"] != 0:
        raise SystemExit(f"Receipt signing failed:\n{json.dumps(receipt_sign, indent=2)}")

    receipt_verify = openssl_verify(paths["receipt_payload"], key.public_key_path, paths["receipt_signature"])
    write_json(paths["receipt_verification"], receipt_verify)

    receipt_tampered = dict(receipt_payload)
    receipt_tampered["status"] = "TAMPERED"
    write_text(paths["receipt_tampered_payload"], canonical_json(receipt_tampered) + "\n")
    receipt_tamper_verify = openssl_verify(
        paths["receipt_tampered_payload"],
        key.public_key_path,
        paths["receipt_signature"],
    )
    write_json(paths["receipt_tamper_verification"], receipt_tamper_verify)

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
        "receipt_signature_sha256": sha256_file(paths["receipt_signature"]),
        "signature_algorithm": "openssl_dgst_sha256_rsa",
    }
    write_text(paths["attestation_payload"], canonical_json(attestation_payload) + "\n")

    attestation_sign = openssl_sign(paths["attestation_payload"], key.private_key_path, paths["attestation_signature"])
    if attestation_sign["returncode"] != 0:
        raise SystemExit(f"Attestation signing failed:\n{json.dumps(attestation_sign, indent=2)}")

    attestation_verify = openssl_verify(paths["attestation_payload"], key.public_key_path, paths["attestation_signature"])
    write_json(paths["attestation_verification"], attestation_verify)

    attestation_tampered = dict(attestation_payload)
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
        "report_type": "external_key_custody_runtime_report",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "PASS",
        "runtime_status_allow_executed": True,
        "executed": True,
        "execution_started_at_utc": execution_started_at,
        "execution_finished_at_utc": execution_finished_at,
        "receipt_signature_verified": receipt_verify["verified_ok"],
        "receipt_tamper_rejected": not receipt_tamper_verify["verified_ok"],
        "attestation_signature_verified": attestation_verify["verified_ok"],
        "attestation_tamper_rejected": not attestation_tamper_verify["verified_ok"],
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "notes": [
            "Signing با private key خارجی انجام شد.",
            "Runtime boundary فقط public key و verification evidence را می‌بیند.",
            "Tampered receipt و attestation رد شدند.",
        ],
    }
    write_json(paths["runtime_report"], runtime_report)
    write_text(paths["executed_marker"], "executed\n")
    remove_if_exists(paths["denied_marker"])

    return {
        "receipt_sign": receipt_sign,
        "receipt_verify": receipt_verify,
        "receipt_tamper_verify": receipt_tamper_verify,
        "attestation_sign": attestation_sign,
        "attestation_verify": attestation_verify,
        "attestation_tamper_verify": attestation_tamper_verify,
    }


def build_denied_report(
    *,
    label: str,
    scenario_name: str,
    scenario_verification_time: datetime,
    verification_mode: str,
    gate_decision: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    for key in (
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
        "runtime_report",
        "executed_marker",
    ):
        remove_if_exists(paths[key])

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
        "receipt_exists": False,
        "receipt_signature_exists": False,
        "attestation_exists": False,
        "attestation_signature_exists": False,
        "runtime_report_exists": False,
    }
    write_json(paths["gate_report"], report)
    return report


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
        "preventive_block_applied": False,
        "receipt_exists": paths["receipt_payload"].exists(),
        "receipt_signature_exists": paths["receipt_signature"].exists(),
        "attestation_exists": paths["attestation_payload"].exists(),
        "attestation_signature_exists": paths["attestation_signature"].exists(),
        "runtime_report_exists": paths["runtime_report"].exists(),
        "receipt_signature_verified": runtime_report["receipt_signature_verified"],
        "receipt_tamper_rejected": runtime_report["receipt_tamper_rejected"],
        "attestation_signature_verified": runtime_report["attestation_signature_verified"],
        "attestation_tamper_rejected": runtime_report["attestation_tamper_rejected"],
    }
    write_json(paths["gate_report"], report)
    return report


def execute_scenario(
    *,
    label: str,
    scenario_name: str,
    key: ScenarioKey,
    scenario_verification_time: datetime,
    verification_mode: str,
    output_dir: Path,
    custody_root: Path,
) -> dict[str, Any]:
    paths = scenario_paths(output_dir, scenario_name)
    ensure_dir(paths["scenario_dir"])

    manifest = build_manifest(
        label=label,
        scenario_name=scenario_name,
        public_key_path=key.public_key_path,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
        custody_root=custody_root,
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

    verification_bundle: dict[str, Any] | None = None

    if gate_decision["gate_decision_allow"]:
        verification_bundle = simulate_signed_runtime_execution(
            label=label,
            scenario_name=scenario_name,
            key=key,
            manifest=manifest,
            gate_decision=gate_decision,
            scenario_verification_time=scenario_verification_time,
            paths=paths,
        )
        gate_report = build_allowed_report(
            label=label,
            scenario_name=scenario_name,
            scenario_verification_time=scenario_verification_time,
            verification_mode=verification_mode,
            gate_decision=gate_decision,
            paths=paths,
        )
    else:
        gate_report = build_denied_report(
            label=label,
            scenario_name=scenario_name,
            scenario_verification_time=scenario_verification_time,
            verification_mode=verification_mode,
            gate_decision=gate_decision,
            paths=paths,
        )

    result = {
        "scenario": scenario_name,
        "public_key_path": rel(key.public_key_path),
        "private_key_path": rel(key.private_key_path),
        "verification_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "gate_decision_allow": gate_decision["gate_decision_allow"],
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "runtime_status_allow_executed": gate_report["runtime_status_allow_executed"],
        "receipt_exists": paths["receipt_payload"].exists(),
        "receipt_signature_exists": paths["receipt_signature"].exists(),
        "attestation_exists": paths["attestation_payload"].exists(),
        "attestation_signature_exists": paths["attestation_signature"].exists(),
        "runtime_report_exists": paths["runtime_report"].exists(),
        "executed_marker_exists": paths["executed_marker"].exists(),
        "denied_marker_exists": paths["denied_marker"].exists(),
        "manifest_path": rel(paths["manifest"]),
        "gate_decision_path": rel(paths["gate_decision"]),
        "gate_report_path": rel(paths["gate_report"]),
    }

    if verification_bundle is not None:
        result.update(
            {
                "receipt_signature_verified": verification_bundle["receipt_verify"]["verified_ok"],
                "receipt_tamper_rejected": not verification_bundle["receipt_tamper_verify"]["verified_ok"],
                "attestation_signature_verified": verification_bundle["attestation_verify"]["verified_ok"],
                "attestation_tamper_rejected": not verification_bundle["attestation_tamper_verify"]["verified_ok"],
                "receipt_payload_path": rel(paths["receipt_payload"]),
                "receipt_signature_path": rel(paths["receipt_signature"]),
                "receipt_verification_path": rel(paths["receipt_verification"]),
                "receipt_tampered_payload_path": rel(paths["receipt_tampered_payload"]),
                "receipt_tamper_verification_path": rel(paths["receipt_tamper_verification"]),
                "attestation_payload_path": rel(paths["attestation_payload"]),
                "attestation_signature_path": rel(paths["attestation_signature"]),
                "attestation_verification_path": rel(paths["attestation_verification"]),
                "attestation_tampered_payload_path": rel(paths["attestation_tampered_payload"]),
                "attestation_tamper_verification_path": rel(paths["attestation_tamper_verification"]),
                "runtime_report_path": rel(paths["runtime_report"]),
            }
        )
    return result


def render_markdown(summary: dict[str, Any]) -> str:
    active = summary["scenarios"]["active_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R10 — External Key Custody + No Private Key in Artifact/Runtime Boundary

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- OpenSSL version: `{summary["openssl_version"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`
- External custody directory: `{summary["external_custody_directory"]}`

## Active Path

- Active gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Active executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Receipt signature verified: **{str(active.get("receipt_signature_verified", False)).upper()}**
- Receipt tamper rejected: **{str(active.get("receipt_tamper_rejected", False)).upper()}**
- Attestation signature verified: **{str(active.get("attestation_signature_verified", False)).upper()}**
- Attestation tamper rejected: **{str(active.get("attestation_tamper_rejected", False)).upper()}**

## Denied Paths

- Expired gate decision: **{"ALLOW" if expired["gate_decision_allow"] else "DENY"}**
- Future gate decision: **{"ALLOW" if future["gate_decision_allow"] else "DENY"}**
- Expired executed: **{str(expired["runtime_status_allow_executed"]).upper()}**
- Future executed: **{str(future["runtime_status_allow_executed"]).upper()}**

## Boundary Scan

- Artifact boundary contains private keys: **{str(summary["artifact_boundary_scan"]["contains_private_keys"]).upper()}**
- Runtime boundary contains private keys: **{str(summary["runtime_boundary_scan"]["contains_private_keys"]).upper()}**
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="R10 - External Key Custody + No Private Key in Artifact/Runtime Boundary"
    )
    parser.add_argument(
        "--label",
        default="R10_external_key_custody_no_private_key_boundary_proof",
        help="Proof label",
    )
    parser.add_argument(
        "--verification-time",
        default=None,
        help="Base UTC timestamp override in ISO-8601 format",
    )
    args = parser.parse_args()

    openssl_version = require_openssl()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    output_dir = ARTIFACTS_DIR / "external_key_custody_no_private_key_boundary_proof" / args.label
    custody_dir = STATE_DIR / args.label

    remove_if_exists(output_dir)
    remove_if_exists(custody_dir)

    ensure_dir(output_dir)
    ensure_dir(custody_dir)

    active_not_before = base_verification_time - timedelta(days=1)
    active_not_after = base_verification_time + timedelta(days=30)

    expired_not_before = base_verification_time - timedelta(days=30)
    expired_not_after = base_verification_time - timedelta(seconds=1)

    future_not_before = base_verification_time + timedelta(days=1)
    future_not_after = base_verification_time + timedelta(days=30)

    active_key = ScenarioKey(
        key_id="r10-attestation-key-active",
        private_key_path=custody_dir / "attestation_private_active.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_active.pem",
        not_before=iso_no_microseconds(active_not_before),
        not_after=iso_no_microseconds(active_not_after),
    )
    expired_key = ScenarioKey(
        key_id="r10-attestation-key-expired",
        private_key_path=custody_dir / "attestation_private_expired.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_expired.pem",
        not_before=iso_no_microseconds(expired_not_before),
        not_after=iso_no_microseconds(expired_not_after),
    )
    future_key = ScenarioKey(
        key_id="r10-attestation-key-future",
        private_key_path=custody_dir / "attestation_private_future.pem",
        public_key_path=output_dir / "public_keys" / "attestation_public_future.pem",
        not_before=iso_no_microseconds(future_not_before),
        not_after=iso_no_microseconds(future_not_after),
    )

    for key in (active_key, expired_key, future_key):
        generate_rsa_keypair(key.private_key_path, key.public_key_path)

    future_fixture_time = parse_utc(future_key.not_before) - timedelta(seconds=1)

    registry = {
        "registry_version": 1,
        "registry_type": "external_key_custody_registry",
        "generated_at_utc": utc_now_iso(),
        "entries": [
            {
                "key_id": key.key_id,
                "public_key_path": rel(key.public_key_path),
                "public_key_sha256": sha256_file(key.public_key_path),
                "not_before": key.not_before,
                "not_after": key.not_after,
            }
            for key in (active_key, expired_key, future_key)
        ],
    }
    write_json(output_dir / "attestation_key_policy_registry.json", registry)

    active = execute_scenario(
        label=args.label,
        scenario_name=f"{args.label}__active_runtime",
        key=active_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
        custody_root=custody_dir,
    )
    expired = execute_scenario(
        label=args.label,
        scenario_name=f"{args.label}__expired_runtime",
        key=expired_key,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
        custody_root=custody_dir,
    )
    future = execute_scenario(
        label=args.label,
        scenario_name=f"{args.label}__future_runtime",
        key=future_key,
        scenario_verification_time=future_fixture_time,
        verification_mode="strict_pre_not_before_fixture",
        output_dir=output_dir,
        custody_root=custody_dir,
    )

    artifact_boundary_scan = scan_for_private_keys(output_dir)
    runtime_boundary_scan = scan_for_private_keys(output_dir)

    custody_scan = scan_for_private_keys(custody_dir)

    proof_status = "PASS"
    if not active["gate_decision_allow"]:
        proof_status = "FAIL"
    if not active["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not active["receipt_exists"] or not active["receipt_signature_exists"]:
        proof_status = "FAIL"
    if not active["attestation_exists"] or not active["attestation_signature_exists"]:
        proof_status = "FAIL"
    if not active["runtime_report_exists"]:
        proof_status = "FAIL"
    if not active.get("receipt_signature_verified", False):
        proof_status = "FAIL"
    if not active.get("receipt_tamper_rejected", False):
        proof_status = "FAIL"
    if not active.get("attestation_signature_verified", False):
        proof_status = "FAIL"
    if not active.get("attestation_tamper_rejected", False):
        proof_status = "FAIL"

    if expired["gate_decision_allow"] or future["gate_decision_allow"]:
        proof_status = "FAIL"
    if expired["runtime_status_allow_executed"] or future["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if expired["receipt_exists"] or expired["attestation_exists"] or expired["runtime_report_exists"]:
        proof_status = "FAIL"
    if future["receipt_exists"] or future["attestation_exists"] or future["runtime_report_exists"]:
        proof_status = "FAIL"

    if artifact_boundary_scan["contains_private_keys"]:
        proof_status = "FAIL"
    if runtime_boundary_scan["contains_private_keys"]:
        proof_status = "FAIL"
    if not custody_scan["contains_private_keys"]:
        proof_status = "FAIL"

    summary = {
        "report_version": 1,
        "report_type": "external_key_custody_no_private_key_boundary_proof",
        "generated_at_utc": utc_now_iso(),
        "proof_label": args.label,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "future_fixture_time_utc": iso_no_microseconds(future_fixture_time),
        "openssl_version": openssl_version,
        "proof_status": proof_status,
        "output_directory": rel(output_dir),
        "external_custody_directory": rel(custody_dir),
        "registry_path": rel(output_dir / "attestation_key_policy_registry.json"),
        "artifact_boundary_scan": artifact_boundary_scan,
        "runtime_boundary_scan": runtime_boundary_scan,
        "external_custody_scan": custody_scan,
        "scenarios": {
            "active_runtime": active,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "external_key_custody_no_private_key_boundary_proof.json"
    summary_md_path = output_dir / "external_key_custody_no_private_key_boundary_proof.md"
    digest_path = output_dir / "external_key_custody_no_private_key_boundary_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "future_fixture_time_utc": iso_no_microseconds(future_fixture_time),
        "summary_json_path": rel(summary_json_path),
        "summary_md_path": rel(summary_md_path),
        "active_path_real_signature_verified": (
            active["gate_decision_allow"]
            and active["runtime_status_allow_executed"]
            and active.get("receipt_signature_verified", False)
            and active.get("receipt_tamper_rejected", False)
            and active.get("attestation_signature_verified", False)
            and active.get("attestation_tamper_rejected", False)
        ),
        "artifact_boundary_private_key_free": not artifact_boundary_scan["contains_private_keys"],
        "runtime_boundary_private_key_free": not runtime_boundary_scan["contains_private_keys"],
        "external_custody_contains_private_keys": custody_scan["contains_private_keys"],
        "denied_paths_blocked": (
            not expired["gate_decision_allow"]
            and not future["gate_decision_allow"]
            and not expired["runtime_status_allow_executed"]
            and not future["runtime_status_allow_executed"]
            and not expired["receipt_exists"]
            and not future["receipt_exists"]
            and not expired["attestation_exists"]
            and not future["attestation_exists"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 80)
    print("R10 - EXTERNAL KEY CUSTODY + NO PRIVATE KEY IN ARTIFACT/RUNTIME BOUNDARY")
    print("=" * 80)
    print(f"LABEL                                : {args.label}")
    print(f"OPENSSL VERSION                      : {openssl_version}")
    print(f"PROOF STATUS                         : {proof_status}")
    print(f"BASE VERIFICATION TIME               : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME                  : {iso_no_microseconds(future_fixture_time)}")
    print(f"EXTERNAL CUSTODY DIR                 : {rel(custody_dir)}")
    print(f"ACTIVE GATE                          : {'ALLOW' if active['gate_decision_allow'] else 'DENY'}")
    print(f"ACTIVE EXECUTED                      : {active['runtime_status_allow_executed']}")
    print(f"RECEIPT VERIFIED                     : {active.get('receipt_signature_verified', False)}")
    print(f"RECEIPT TAMPER REJECTED              : {active.get('receipt_tamper_rejected', False)}")
    print(f"ATTESTATION VERIFIED                 : {active.get('attestation_signature_verified', False)}")
    print(f"ATTESTATION TAMPER REJECTED          : {active.get('attestation_tamper_rejected', False)}")
    print(f"EXPIRED GATE                         : {'ALLOW' if expired['gate_decision_allow'] else 'DENY'}")
    print(f"FUTURE GATE                          : {'ALLOW' if future['gate_decision_allow'] else 'DENY'}")
    print(f"ARTIFACT BOUNDARY PRIVATE KEYS       : {artifact_boundary_scan['contains_private_keys']}")
    print(f"RUNTIME BOUNDARY PRIVATE KEYS        : {runtime_boundary_scan['contains_private_keys']}")
    print(f"EXTERNAL CUSTODY PRIVATE KEYS        : {custody_scan['contains_private_keys']}")
    print(f"SUMMARY JSON                         : {rel(summary_json_path)}")
    print(f"REPORT MD                            : {rel(summary_md_path)}")
    print(f"DIGEST                               : {rel(digest_path)}")
    print("=" * 80)


if __name__ == "__main__":
    main()
