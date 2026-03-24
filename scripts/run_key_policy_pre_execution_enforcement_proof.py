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


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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
        "admitted_marker": scenario_dir / "runtime_admitted.marker",
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
        "proof_type": "key_policy_pre_execution_enforcement_proof",
        "proof_label": label,
        "scenario": scenario_name,
        "generated_at_utc": utc_now_iso(),
        "workflow": {
            "name": "external_signed_runtime_gate",
            "mode": "pre_execution_enforcement",
        },
        "verification_context": {
            "verification_time_utc": iso_no_microseconds(scenario_verification_time),
            "verification_mode": verification_mode,
        },
        "attestation": {
            "public_key_path": os.path.relpath(public_key_path, ROOT).replace("\\", "/"),
        },
    }


def derive_future_denial_time(entry: RegistryEntry) -> datetime:
    not_before = parse_utc(entry.not_before)
    return (not_before - timedelta(seconds=1)).replace(microsecond=0)


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
    within_window, verdict = evaluate_window(entry, scenario_verification_time)

    entry_key_sha = sha256_file(public_key_path)
    registry_key_sha_matches = entry_key_sha == entry.public_key_sha256

    gate_decision_allow = within_window and registry_key_sha_matches

    gate_decision = {
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
    write_json(paths["gate_decision"], gate_decision)

    if gate_decision_allow:
        write_text(paths["admitted_marker"], "admitted\n")
        remove_if_exists(paths["denied_marker"])

        report = {
            "report_version": 1,
            "report_type": "pre_execution_gate_report",
            "proof_label": label,
            "scenario": scenario_name,
            "evaluation_time_utc": iso_no_microseconds(scenario_verification_time),
            "verification_mode": verification_mode,
            "status": "PASS",
            "decision": "ALLOW",
            "window_verdict": verdict,
            "runtime_status_allow_executed": False,
            "preventive_block_applied": False,
            "receipt_exists": paths["receipt"].exists(),
            "attestation_exists": paths["attestation"].exists(),
            "runtime_report_exists": paths["runtime_report"].exists(),
            "notes": [
                "Key داخل validity window است.",
                "Gate اجازه داده است.",
                "این proof هنوز runtime واقعی را اجرا نمی‌کند.",
            ],
        }
        write_json(paths["gate_report"], report)
    else:
        write_text(paths["denied_marker"], "denied\n")
        remove_if_exists(paths["admitted_marker"])
        remove_if_exists(paths["receipt"])
        remove_if_exists(paths["attestation"])
        remove_if_exists(paths["runtime_report"])

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
            "window_verdict": verdict,
            "runtime_status_allow_executed": False,
            "preventive_block_applied": True,
            "receipt_exists": paths["receipt"].exists(),
            "attestation_exists": paths["attestation"].exists(),
            "runtime_report_exists": paths["runtime_report"].exists(),
            "notes": [
                "Key خارج از validity window بوده است.",
                "Gate قبل از runtime درخواست را block کرده است.",
                "هیچ receipt/attestation/runtime report نباید وجود داشته باشد.",
            ],
        }
        write_json(paths["gate_report"], report)

    gate_report = load_json(paths["gate_report"])

    return {
        "scenario": scenario_name,
        "public_key_path": os.path.relpath(public_key_path, ROOT).replace("\\", "/"),
        "verification_time_utc": iso_no_microseconds(scenario_verification_time),
        "verification_mode": verification_mode,
        "gate_decision_allow": gate_decision_allow,
        "window_verdict": verdict,
        "registry_key_within_window": gate_decision["checks"]["registry_key_within_window"],
        "registry_key_hash_matches": gate_decision["checks"]["registry_key_hash_matches"],
        "preventive_block_applied": gate_report["preventive_block_applied"],
        "runtime_status_allow_executed": gate_report["runtime_status_allow_executed"],
        "receipt_exists": gate_report["receipt_exists"],
        "attestation_exists": gate_report["attestation_exists"],
        "runtime_report_exists": gate_report["runtime_report_exists"],
        "status": gate_report["status"],
        "manifest_path": os.path.relpath(paths["manifest"], ROOT).replace("\\", "/"),
        "gate_decision_path": os.path.relpath(paths["gate_decision"], ROOT).replace("\\", "/"),
        "gate_report_path": os.path.relpath(paths["gate_report"], ROOT).replace("\\", "/"),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    active = summary["scenarios"]["active_runtime"]
    expired = summary["scenarios"]["expired_runtime"]
    future = summary["scenarios"]["future_runtime"]

    return f"""# R7.1 — Future-Key Fixture Repair + Strict Pre-Not-Before Denial Proof

- Generated at (UTC): `{summary["generated_at_utc"]}`
- Proof label: `{summary["proof_label"]}`
- Base verification time (UTC): `{summary["base_verification_time_utc"]}`
- Proof status: **{summary["proof_status"]}**
- Output directory: `{summary["output_directory"]}`

## Outcomes

- Active gate decision: **{"ALLOW" if active["gate_decision_allow"] else "DENY"}**
- Expired gate decision: **{"ALLOW" if expired["gate_decision_allow"] else "DENY"}**
- Future gate decision: **{"ALLOW" if future["gate_decision_allow"] else "DENY"}**

## Scenario Verification Times

- Active verification time: `{active["verification_time_utc"]}` (`{active["verification_mode"]}`)
- Expired verification time: `{expired["verification_time_utc"]}` (`{expired["verification_mode"]}`)
- Future verification time: `{future["verification_time_utc"]}` (`{future["verification_mode"]}`)

## Runtime Prevention

- Active runtime executed: **{str(active["runtime_status_allow_executed"]).upper()}**
- Expired runtime executed: **{str(expired["runtime_status_allow_executed"]).upper()}**
- Future runtime executed: **{str(future["runtime_status_allow_executed"]).upper()}**

## Artifact Absence For Denied Paths

- Expired receipt exists: **{str(expired["receipt_exists"]).upper()}**
- Expired attestation exists: **{str(expired["attestation_exists"]).upper()}**
- Expired runtime report exists: **{str(expired["runtime_report_exists"]).upper()}**
- Future receipt exists: **{str(future["receipt_exists"]).upper()}**
- Future attestation exists: **{str(future["attestation_exists"]).upper()}**
- Future runtime report exists: **{str(future["runtime_report_exists"]).upper()}**

## Window Verdicts

- Active verdict: `{active["window_verdict"]}`
- Expired verdict: `{expired["window_verdict"]}`
- Future verdict: `{future["window_verdict"]}`
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="R7.1 - Future-Key Fixture Repair + Strict Pre-Not-Before Denial Proof"
    )
    parser.add_argument(
        "--label",
        default="R7_1_future_key_fixture_repair",
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
        base_verification_time = datetime.now(timezone.utc).replace(microsecond=0)

    registry_path = R6_DIR / "attestation_key_policy_registry.json"
    active_key_path = R5_DIR / "attestation_public_v2.pem"
    expired_key_path = R6_DIR / "attestation_public_expired.pem"
    future_key_path = R6_DIR / "attestation_public_future.pem"

    required_paths = [registry_path, active_key_path, expired_key_path, future_key_path]
    missing = [str(p) for p in required_paths if not p.exists()]
    if missing:
        raise SystemExit("Missing required files:\n- " + "\n- ".join(missing))

    output_dir = ARTIFACTS_DIR / "key_policy_pre_execution_enforcement_proof" / args.label
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
    if active["status"] != "PASS":
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
        "report_type": "key_policy_pre_execution_enforcement_proof",
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

    summary_json_path = output_dir / "key_policy_pre_execution_enforcement_proof.json"
    summary_md_path = output_dir / "key_policy_pre_execution_enforcement_proof.md"
    digest_path = output_dir / "key_policy_pre_execution_enforcement_proof_digest.json"

    write_json(summary_json_path, summary)
    write_text(summary_md_path, render_markdown(summary))

    digest = {
        "proof_label": args.label,
        "proof_status": proof_status,
        "base_verification_time_utc": iso_no_microseconds(base_verification_time),
        "future_fixture_verification_time_utc": future["verification_time_utc"],
        "summary_json_path": os.path.relpath(summary_json_path, ROOT).replace("\\", "/"),
        "summary_md_path": os.path.relpath(summary_md_path, ROOT).replace("\\", "/"),
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
    print("R7.1 - FUTURE-KEY FIXTURE REPAIR + STRICT PRE-NOT-BEFORE DENIAL")
    print("=" * 72)
    print(f"LABEL                       : {args.label}")
    print(f"PROOF STATUS                : {proof_status}")
    print(f"BASE VERIFICATION TIME      : {iso_no_microseconds(base_verification_time)}")
    print(f"FUTURE FIXTURE TIME         : {future['verification_time_utc']}")
    print(f"ACTIVE GATE                 : {'ALLOW' if active['gate_decision_allow'] else 'DENY'}")
    print(f"EXPIRED GATE                : {'ALLOW' if expired['gate_decision_allow'] else 'DENY'}")
    print(f"FUTURE GATE                 : {'ALLOW' if future['gate_decision_allow'] else 'DENY'}")
    print(f"ACTIVE VERDICT              : {active['window_verdict']}")
    print(f"EXPIRED VERDICT             : {expired['window_verdict']}")
    print(f"FUTURE VERDICT              : {future['window_verdict']}")
    print(f"SUMMARY JSON                : {os.path.relpath(summary_json_path, ROOT).replace(chr(92), '/')}")
    print(f"REPORT MD                   : {os.path.relpath(summary_md_path, ROOT).replace(chr(92), '/')}")
    print(f"DIGEST                      : {os.path.relpath(digest_path, ROOT).replace(chr(92), '/')}")
    print("=" * 72)


if __name__ == "__main__":
    main()
