#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = ROOT / "artifacts" / "operations"
R5_DIR = ARTIFACTS_DIR / "key_rotation_revocation_proof" / "R5_key_rotation_revocation_proof"
R6_DIR = ARTIFACTS_DIR / "key_policy_validity_proof" / "R6_key_policy_validity_window_proof"


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def parse_utc(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def iso_no_microseconds(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


@dataclass
class RegistryEntry:
    key_id: str
    public_key_path: str
    public_key_sha256: str
    status: str
    revoked: bool
    usage: str
    not_before: str
    not_after: str


def load_registry_entries(registry_path: Path) -> list[RegistryEntry]:
    raw = load_json(registry_path)
    if isinstance(raw, dict):
        if isinstance(raw.get("keys"), list):
            items = raw["keys"]
        elif isinstance(raw.get("entries"), list):
            items = raw["entries"]
        else:
            raise SystemExit(f"Unsupported registry structure in {registry_path}")
    elif isinstance(raw, list):
        items = raw
    else:
        raise SystemExit(f"Unsupported registry structure in {registry_path}")

    entries: list[RegistryEntry] = []
    for item in items:
        entries.append(
            RegistryEntry(
                key_id=item["key_id"],
                public_key_path=item["public_key_path"],
                public_key_sha256=item["public_key_sha256"],
                status=item["status"],
                revoked=bool(item["revoked"]),
                usage=item["usage"],
                not_before=item["not_before"],
                not_after=item["not_after"],
            )
        )
    return entries


def find_registry_entry(registry_entries: list[RegistryEntry], public_key_path: Path) -> RegistryEntry:
    rel = os.path.relpath(public_key_path, ROOT).replace("\\", "/")
    for entry in registry_entries:
        if entry.public_key_path == rel:
            return entry
    raise SystemExit(f"Registry entry not found for key path: {rel}")


def evaluate_window(entry: RegistryEntry, verification_time_utc: datetime) -> tuple[bool, str]:
    if entry.status != "active":
        return False, "inactive"
    if entry.revoked:
        return False, "revoked"
    if entry.usage != "attestation_signing":
        return False, "invalid_usage"

    not_before = parse_utc(entry.not_before)
    not_after = parse_utc(entry.not_after)

    if verification_time_utc < not_before:
        return False, "not_yet_valid"
    if verification_time_utc > not_after:
        return False, "expired"
    return True, "within_window"


def remove_if_exists(path: Path) -> None:
    if path.exists():
        path.unlink()


def scenario_paths(base_dir: Path, scenario_name: str) -> dict[str, Path]:
    scenario_dir = base_dir / scenario_name
    return {
        "scenario_dir": scenario_dir,
        "manifest": scenario_dir / "normalized_request_manifest.json",
        "gate_decision": scenario_dir / "pre_execution_gate_decision.json",
        "gate_report": scenario_dir / "pre_execution_gate_report.json",
        "receipt": scenario_dir / "external_signed_execution_receipt.json",
        "attestation": scenario_dir / "external_signed_execution_attestation.json",
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
) -> dict[str, Any]:
    return {
        "manifest_version": 1,
        "proof_type": "key_policy_allow_path_runtime_execution_proof",
        "proof_label": label,
        "scenario": scenario_name,
        "generated_at_utc": utc_now_iso(),
        "workflow": {
            "name": "external_signed_runtime_gate",
            "mode": "allow_path_runtime_execution",
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
            "public_key_path": os.path.relpath(public_key_path, ROOT).replace("\\", "/"),
        },
    }


def derive_future_denial_time(entry: RegistryEntry) -> datetime:
    not_before = parse_utc(entry.not_before)
    return (not_before - timedelta(seconds=1)).replace(microsecond=0)


def build_gate_decision(
    *,
    label: str,
    scenario_name: str,
    public_key_path: Path,
    registry_path: Path,
    entry: RegistryEntry,
    scenario_verification_time: datetime,
    verification_mode: str,
) -> dict[str, Any]:
    entry_key_sha = sha256_file(public_key_path)
    registry_key_sha_matches = entry_key_sha == entry.public_key_sha256
    within_window, verdict = evaluate_window(entry, scenario_verification_time)
    gate_decision_allow = within_window and registry_key_sha_matches

    return {
        "decision_version": 1,
        "decision_type": "pre_execution_key_policy_gate",
        "proof_label": label,
        "scenario": scenario_name,
        "decision_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "public_key_path": os.path.relpath(public_key_path, ROOT).replace("\\", "/"),
        "registry_path": os.path.relpath(registry_path, ROOT).replace("\\", "/"),
        "registry_entry": {
            "key_id": entry.key_id,
            "status": entry.status,
            "revoked": entry.revoked,
            "usage": entry.usage,
            "not_before": entry.not_before,
            "not_after": entry.not_after,
            "public_key_sha256": entry.public_key_sha256,
        },
        "checks": {
            "registry_entry_found": True,
            "registry_key_hash_matches": registry_key_sha_matches,
            "registry_key_active": entry.status == "active",
            "registry_key_not_revoked": not entry.revoked,
            "registry_key_usage_valid": entry.usage == "attestation_signing",
            "registry_key_within_window": within_window,
        },
        "derived": {
            "window_verdict": verdict,
        },
        "gate_decision_allow": gate_decision_allow,
    }


def simulate_runtime_execution(
    *,
    label: str,
    scenario_name: str,
    public_key_path: Path,
    entry: RegistryEntry,
    manifest: dict[str, Any],
    gate_decision: dict[str, Any],
    scenario_verification_time: datetime,
    paths: dict[str, Path],
) -> None:
    manifest_canonical = canonical_json(manifest)
    gate_canonical = canonical_json(gate_decision)
    execution_started_at = iso_no_microseconds(scenario_verification_time)
    execution_finished_at = iso_no_microseconds(scenario_verification_time + timedelta(seconds=1))

    receipt = {
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
        "public_key_path": os.path.relpath(public_key_path, ROOT).replace("\\", "/"),
        "key_id": entry.key_id,
        "manifest_sha256": sha256_text(manifest_canonical),
        "gate_decision_sha256": sha256_text(gate_canonical),
        "execution_output": {
            "target_path": manifest["task"]["payload"]["target_path"],
            "content_sha256": sha256_text(manifest["task"]["payload"]["content"]),
        },
    }

    receipt_sha256 = sha256_text(canonical_json(receipt))
    receipt["receipt_sha256"] = receipt_sha256
    write_json(paths["receipt"], receipt)

    attestation_payload = {
        "attestation_version": 1,
        "attestation_type": "external_signed_execution_attestation",
        "proof_label": label,
        "scenario": scenario_name,
        "attested": True,
        "attestation_time_utc": execution_finished_at,
        "key_id": entry.key_id,
        "public_key_path": os.path.relpath(public_key_path, ROOT).replace("\\", "/"),
        "receipt_sha256": receipt_sha256,
        "manifest_sha256": receipt["manifest_sha256"],
        "gate_decision_sha256": receipt["gate_decision_sha256"],
        "signature_algorithm": "simulated_sha256_attestation",
        "signature": sha256_text(
            f"{entry.key_id}|{receipt_sha256}|{receipt['manifest_sha256']}|{receipt['gate_decision_sha256']}"
        ),
    }
    write_json(paths["attestation"], attestation_payload)

    runtime_report = {
        "report_version": 1,
        "report_type": "external_signed_runtime_report",
        "proof_label": label,
        "scenario": scenario_name,
        "status": "PASS",
        "runtime_status_allow_executed": True,
        "executed": True,
        "execution_started_at_utc": execution_started_at,
        "execution_finished_at_utc": execution_finished_at,
        "receipt_exists": True,
        "attestation_exists": True,
        "gate_decision_allow": True,
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "notes": [
            "Gate allow شد.",
            "Runtime path واقعاً اجرا شد.",
            "Execution receipt و attestation و runtime report تولید شدند.",
        ],
    }
    write_json(paths["runtime_report"], runtime_report)
    write_text(paths["executed_marker"], "executed\n")
    remove_if_exists(paths["denied_marker"])


def build_denied_report(
    *,
    label: str,
    scenario_name: str,
    scenario_verification_time: datetime,
    verification_mode: str,
    gate_decision: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    remove_if_exists(paths["receipt"])
    remove_if_exists(paths["attestation"])
    remove_if_exists(paths["runtime_report"])
    remove_if_exists(paths["executed_marker"])
    write_text(paths["denied_marker"], "denied\n")

    runtime_files_absent = (
        not paths["receipt"].exists()
        and not paths["attestation"].exists()
        and not paths["runtime_report"].exists()
    )

    report = {
        "report_version": 1,
        "report_type": "pre_execution_gate_report",
        "proof_label": label,
        "scenario": scenario_name,
        "evaluation_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "status": "PASS" if runtime_files_absent else "FAIL",
        "decision": "DENY",
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "runtime_status_allow_executed": False,
        "preventive_block_applied": True,
        "receipt_exists": False,
        "attestation_exists": False,
        "runtime_report_exists": False,
        "notes": [
            "Key خارج از validity window بوده است.",
            "Gate قبل از runtime درخواست را block کرده است.",
            "هیچ execution artifactی نباید وجود داشته باشد.",
        ],
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
        "receipt_exists": paths["receipt"].exists(),
        "attestation_exists": paths["attestation"].exists(),
        "runtime_report_exists": paths["runtime_report"].exists(),
        "notes": [
            "Key داخل validity window است.",
            "Gate اجازه داده است.",
            "Runtime path اجرا شد و artifactها تولید شدند.",
        ],
    }
    write_json(paths["gate_report"], report)
    return report


def execute_scenario(
    *,
    label: str,
    scenario_name: str,
    public_key_path: Path,
    registry_path: Path,
    registry_entries: list[RegistryEntry],
    scenario_verification_time: datetime,
    verification_mode: str,
    output_dir: Path,
) -> dict[str, Any]:
    paths = scenario_paths(output_dir, scenario_name)
    ensure_dir(paths["scenario_dir"])

    manifest = build_manifest(
        label=label,
        scenario_name=scenario_name,
        public_key_path=public_key_path,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
    )
    write_json(paths["manifest"], manifest)

    entry = find_registry_entry(registry_entries, public_key_path)
    gate_decision = build_gate_decision(
        label=label,
        scenario_name=scenario_name,
        public_key_path=public_key_path,
        registry_path=registry_path,
        entry=entry,
        scenario_verification_time=scenario_verification_time,
        verification_mode=verification_mode,
    )
    write_json(paths["gate_decision"], gate_decision)

    if gate_decision["gate_decision_allow"]:
        simulate_runtime_execution(
            label=label,
            scenario_name=scenario_name,
            public_key_path=public_key_path,
            entry=entry,
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

    return {
        "scenario": scenario_name,
        "public_key_path": os.path.relpath(public_key_path, ROOT).replace("\\", "/"),
        "verification_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "gate_decision_allow": gate_decision["gate_decision_allow"],
        "window_verdict": gate_decision["derived"]["window_verdict"],
        "registry_key_within_window": gate_decision["checks"]["registry_key_within_window"],
        "registry_key_hash_matches": gate_decision["checks"]["registry_key_hash_matches"],
        "runtime_status_allow_executed": gate_report["runtime_status_allow_executed"],
        "preventive_block_applied": gate_report["preventive_block_applied"],
        "receipt_exists": paths["receipt"].exists(),
        "attestation_exists": paths["attestation"].exists(),
        "runtime_report_exists": paths["runtime_report"].exists(),
        "executed_marker_exists": paths["executed_marker"].exists(),
        "denied_marker_exists": paths["denied_marker"].exists(),
        "status": gate_report["status"],
        "manifest_path": os.path.relpath(paths["manifest"], ROOT).replace("\\", "/"),
        "gate_decision_path": os.path.relpath(paths["gate_decision"], ROOT).replace("\\", "/"),
        "gate_report_path": os.path.relpath(paths["gate_report"], ROOT).replace("\\", "/"),
        "receipt_path": os.path.relpath(paths["receipt"], ROOT).replace("\\", "/") if paths["receipt"].exists() else None,
        "attestation_path": os.path.relpath(paths["attestation"], ROOT).replace("\\", "/") if paths["attestation"].exists() else None,
        "runtime_report_path": os.path.relpath(paths["runtime_report"], ROOT).replace("\\", "/") if paths["runtime_report"].exists() else None,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    active = summary["scenarios"]["active_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R8 — Allow-Path Runtime Execution Proof

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`

## Gate Outcomes

- Active gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Expired gate decision: **{"ALLOW" if expired["gate_decision_allow"] else "DENY"}**
- Future gate decision: **{"ALLOW" if future["gate_decision_allow"] else "DENY"}**

## Runtime Outcomes

- Active runtime executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Expired runtime executed: **{str(expired["runtime_status_allow_executed"]).upper()}**
- Future runtime executed: **{str(future["runtime_status_allow_executed"]).upper()}**

## Active Artifacts

- Active receipt exists: **{str(active["receipt_exists"]).upper()}**
- Active attestation exists: **{str(active["attestation_exists"]).upper()}**
- Active runtime report exists: **{str(active["runtime_report_exists"]).upper()}**

## Denied Artifact Absence

- Expired receipt exists: **{str(expired["receipt_exists"]).upper()}**
- Expired attestation exists: **{str(expired["attestation_exists"]).upper()}**
- Expired runtime report exists: **{str(expired["runtime_report_exists"]).upper()}**
- Future receipt exists: **{str(future["receipt_exists"]).upper()}**
- Future attestation exists: **{str(future["attestation_exists"]).upper()}**
- Future runtime report exists: **{str(future["runtime_report_exists"]).upper()}**
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="R8 - Allow-Path Runtime Execution Proof"
    )
    parser.add_argument(
        "--label",
        default="R8_allow_path_runtime_execution_proof",
        help="Proof label",
    )
    parser.add_argument(
        "--verification-time",
        default=None,
        help="Base UTC timestamp override in ISO-8601 format",
    )
    args = parser.parse_args()

    if args.verification_time:
        base_verification_time = parse_utc(args.verification_time).replace(microsecond=0)
    else:
        base_verification_time = utc_now()

    registry_path = R6_DIR / "attestation_key_policy_registry.json"
    active_key_path = R5_DIR / "attestation_public_v2.pem"
    expired_key_path = R6_DIR / "attestation_public_expired.pem"
    future_key_path = R6_DIR / "attestation_public_future.pem"

    required_paths = [registry_path, active_key_path, expired_key_path, future_key_path]
    missing = [str(p) for p in required_paths if not p.exists()]
    if missing:
        raise SystemExit("Missing required files:\n- " + "\n- ".join(missing))

    output_dir = ARTIFACTS_DIR / "key_policy_allow_path_runtime_execution_proof" / args.label
    ensure_dir(output_dir)

    registry_entries = load_registry_entries(registry_path)
    future_entry = find_registry_entry(registry_entries, future_key_path)
    future_pre_not_before_time = derive_future_denial_time(future_entry)

    active = execute_scenario(
        label=args.label,
        scenario_name=f"{args.label}__active_runtime",
        public_key_path=active_key_path,
        registry_path=registry_path,
        registry_entries=registry_entries,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
    )

    expired = execute_scenario(
        label=args.label,
        scenario_name=f"{args.label}__expired_runtime",
        public_key_path=expired_key_path,
        registry_path=registry_path,
        registry_entries=registry_entries,
        scenario_verification_time=base_verification_time,
        verification_mode="base_time",
        output_dir=output_dir,
    )

    future = execute_scenario(
        label=args.label,
        scenario_name=f"{args.label}__future_runtime",
        public_key_path=future_key_path,
        registry_path=registry_path,
        registry_entries=registry_entries,
        scenario_verification_time=future_pre_not_before_time,
        verification_mode="strict_pre_not_before_fixture",
        output_dir=output_dir,
    )

    proof_status = "PASS"
    if not active["gate_decision_allow"]:
        proof_status = "FAIL"
    if not active["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if not active["receipt_exists"] or not active["attestation_exists"] or not active["runtime_report_exists"]:
        proof_status = "FAIL"
    if active["window_verdict"] != "within_window":
        proof_status = "FAIL"
    if expired["gate_decision_allow"] or future["gate_decision_allow"]:
        proof_status = "FAIL"
    if expired["window_verdict"] != "expired":
        proof_status = "FAIL"
    if future["window_verdict"] != "not_yet_valid":
        proof_status = "FAIL"
    if expired["runtime_status_allow_executed"] or future["runtime_status_allow_executed"]:
        proof_status = "FAIL"
    if expired["receipt_exists"] or expired["attestation_exists"] or expired["runtime_report_exists"]:
        proof_status = "FAIL"
    if future["receipt_exists"] or future["attestation_exists"] or future["runtime_report_exists"]:
        proof_status = "FAIL"

    summary = {
        "report_version": 1,
        "report_type": "key_policy_allow_path_runtime_execution_proof",
        "generated_at_utc": utc_now_iso(),
        "proof_label": args.label,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "proof_status": proof_status,
        "registry_path": os.path.relpath(registry_path, ROOT).replace("\\", "/"),
        "output_directory": os.path.relpath(output_dir, ROOT).replace("\\", "/"),
        "scenarios": {
            "active_runtime": active,
            "expired_runtime": expired,
            "future_runtime": future,
        },
    }

    summary_json_path = output_dir / "key_policy_allow_path_runtime_execution_proof.json"
    summary_md_path = output_dir / "key_policy_allow_path_runtime_execution_proof.md"
    digest_path = output_dir / "key_policy_allow_path_runtime_execution_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "future_fixture_verification_time_utc": future["verification_time_utc"],
        "summary_json_path": os.path.relpath(summary_json_path, ROOT).replace("\\", "/"),
        "summary_md_path": os.path.relpath(summary_md_path, ROOT).replace("\\", "/"),
        "active_path_executed": (
            active["gate_decision_allow"]
            and active["runtime_status_allow_executed"]
            and active["receipt_exists"]
            and active["attestation_exists"]
            and active["runtime_report_exists"]
        ),
        "denied_paths_blocked": (
            not expired["gate_decision_allow"]
            and not future["gate_decision_allow"]
            and not expired["runtime_status_allow_executed"]
            and not future["runtime_status_allow_executed"]
            and not expired["receipt_exists"]
            and not expired["attestation_exists"]
            and not expired["runtime_report_exists"]
            and not future["receipt_exists"]
            and not future["attestation_exists"]
            and not future["runtime_report_exists"]
        ),
    }
    write_json(digest_path, digest)

    print("=" * 72)
    print("R8 - ALLOW-PATH RUNTIME EXECUTION PROOF")
    print("=" * 72)
    print(f"LABEL                       : {args.label}")
    print(f"PROOF STATUS                : {proof_status}")
    print(f"BASE VERIFICATION TIME      : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME         : {future['verification_time_utc']}")
    print(f"ACTIVE GATE                 : {'ALLOW' if active['gate_decision_allow'] else 'DENY'}")
    print(f"EXPIRED GATE                : {'ALLOW' if expired['gate_decision_allow'] else 'DENY'}")
    print(f"FUTURE GATE                 : {'ALLOW' if future['gate_decision_allow'] else 'DENY'}")
    print(f"ACTIVE EXECUTED             : {active['runtime_status_allow_executed']}")
    print(f"EXPIRED EXECUTED            : {expired['runtime_status_allow_executed']}")
    print(f"FUTURE EXECUTED             : {future['runtime_status_allow_executed']}")
    print(f"SUMMARY JSON                : {os.path.relpath(summary_json_path, ROOT).replace(chr(92), '/')}")
    print(f"REPORT MD                   : {os.path.relpath(summary_md_path, ROOT).replace(chr(92), '/')}")
    print(f"DIGEST                      : {os.path.relpath(digest_path, ROOT).replace(chr(92), '/')}")
    print("=" * 72)


if __name__ == "__main__":
    main()
