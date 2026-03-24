#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
SIGNED_RUNTIME_ROOT = OPERATIONS_ROOT / "signed_runtime"
VERIFY_ROOT = OPERATIONS_ROOT / "attestation_verification"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path):
    return json.loads(read_text(path))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


def derive_attestation_key(workflow_id: str, operation: str, runtime_label: str) -> tuple[str, str]:
    seed_material = f"{workflow_id}|{operation}|{runtime_label}|control-plane-local-attestation-v1".encode("utf-8")
    seed = sha256_bytes(seed_material)
    key_hex = sha256_bytes(f"{seed}|attestation-key".encode("utf-8"))
    return seed, key_hex


def sign_payload(attestation_key_hex: str, payload: dict) -> str:
    key = bytes.fromhex(attestation_key_hex)
    body = canonical_json(payload).encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def build_markdown_report(result: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Signed Execution Attestation Verification")
    lines.append("")
    lines.append(f"- Runtime label: `{result['runtime_label']}`")
    lines.append(f"- Verification status: **{result['verification_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Core Checks")
    lines.append("")
    lines.append(f"- Receipt exists: **{result['checks']['receipt_exists']}**")
    lines.append(f"- Attestation exists: **{result['checks']['attestation_exists']}**")
    lines.append(f"- Receipt hash matches: **{result['checks']['receipt_hash_matches']}**")
    lines.append(f"- Gate decision hash matches: **{result['checks']['gate_decision_hash_matches']}**")
    lines.append(f"- Attestation key hash matches: **{result['checks']['attestation_key_hash_matches']}**")
    lines.append(f"- Signature matches: **{result['checks']['signature_matches']}**")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify local signed execution attestation."
    )
    parser.add_argument("--runtime-label", required=True)
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    runtime_label = args.runtime_label.strip()
    label = args.label.strip() or f"{runtime_label}__verification"

    if not runtime_label:
        raise SystemExit("runtime-label must not be empty.")

    signed_dir = SIGNED_RUNTIME_ROOT / runtime_label
    if not signed_dir.exists():
        raise SystemExit(f"Signed runtime directory not found: {signed_dir}")

    output_dir = VERIFY_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")

    receipt_path = require_file(signed_dir / "signed_execution_receipt.json")
    attestation_path = require_file(signed_dir / "signed_execution_attestation.json")
    report_path = require_file(signed_dir / "signed_runtime_report.json")
    manifest_path = require_file(signed_dir / "normalized_request_manifest.json")
    gate_decision_path = require_file(
        ROOT / str(read_json(report_path)["gate_phase"]["gate_decision_path"])
    )

    receipt = read_json(receipt_path)
    attestation = read_json(attestation_path)
    report = read_json(report_path)
    manifest = read_json(manifest_path)
    gate_decision = read_json(gate_decision_path)

    workflow_id = str(report.get("workflow_id", ""))
    operation = str(report.get("operation", ""))
    _, attestation_key_hex = derive_attestation_key(
        workflow_id=workflow_id,
        operation=operation,
        runtime_label=runtime_label,
    )

    attestation_payload = {
        "attestation_version": attestation.get("attestation_version"),
        "attestation_type": attestation.get("attestation_type"),
        "generated_at_utc": attestation.get("generated_at_utc"),
        "runtime_label": attestation.get("runtime_label"),
        "workflow_id": attestation.get("workflow_id"),
        "operation": attestation.get("operation"),
        "gate_label": attestation.get("gate_label"),
        "gate_decision": attestation.get("gate_decision"),
        "runtime_status": attestation.get("runtime_status"),
        "receipt_path": attestation.get("receipt_path"),
        "receipt_sha256": attestation.get("receipt_sha256"),
        "payload_stdout_sha256": attestation.get("payload_stdout_sha256"),
        "payload_stderr_sha256": attestation.get("payload_stderr_sha256"),
        "payload_returncode": attestation.get("payload_returncode"),
        "payload_executed": attestation.get("payload_executed"),
        "manifest_sha256": attestation.get("manifest_sha256"),
        "gate_decision_sha256": attestation.get("gate_decision_sha256"),
        "attestation_key_sha256": attestation.get("attestation_key_sha256"),
    }

    expected_signature = sign_payload(attestation_key_hex, attestation_payload)

    checks = {
        "receipt_exists": receipt_path.exists(),
        "attestation_exists": attestation_path.exists(),
        "receipt_hash_matches": sha256_file(receipt_path) == attestation.get("receipt_sha256"),
        "gate_decision_hash_matches": sha256_file(gate_decision_path) == attestation.get("gate_decision_sha256"),
        "attestation_key_hash_matches": sha256_bytes(bytes.fromhex(attestation_key_hex)) == attestation.get("attestation_key_sha256"),
        "signature_matches": expected_signature == attestation.get("signature"),
        "manifest_hash_matches": sha256_file(manifest_path) == attestation.get("manifest_sha256"),
        "receipt_runtime_consistent": receipt.get("runtime_label") == runtime_label,
        "report_runtime_consistent": report.get("runtime_label") == runtime_label,
        "manifest_workflow_consistent": manifest.get("workflow_id") == workflow_id,
        "gate_decision_allow_for_signed_execution": str(gate_decision.get("decision", "")).upper() == "ALLOW",
    }

    verification_status = "PASS" if all(checks.values()) else "FAIL"

    result = {
        "verification_version": 1,
        "verification_type": "signed_execution_attestation_verification",
        "runtime_label": runtime_label,
        "verification_status": verification_status,
        "inputs": {
            "receipt_path": rel(receipt_path),
            "attestation_path": rel(attestation_path),
            "report_path": rel(report_path),
            "manifest_path": rel(manifest_path),
            "gate_decision_path": rel(gate_decision_path),
        },
        "checks": checks,
        "derived_values": {
            "workflow_id": workflow_id,
            "operation": operation,
            "derived_attestation_key_sha256": sha256_bytes(bytes.fromhex(attestation_key_hex)),
            "expected_signature": expected_signature,
            "recorded_signature": attestation.get("signature"),
        },
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    json_path = output_dir / "signed_execution_attestation_verification.json"
    md_path = output_dir / "signed_execution_attestation_verification.md"
    digest_path = output_dir / "signed_execution_attestation_verification_digest.json"

    write_json(json_path, result)
    write_text(md_path, build_markdown_report(result, output_dir))

    digest = {
        "runtime_label": runtime_label,
        "verification_status": verification_status,
        "artifacts": [
            {
                "path": rel(json_path),
                "size_bytes": json_path.stat().st_size,
                "sha256": sha256_file(json_path),
            },
            {
                "path": rel(md_path),
                "size_bytes": md_path.stat().st_size,
                "sha256": sha256_file(md_path),
            },
        ],
    }
    write_json(digest_path, digest)

    print("=" * 72)
    print("SIGNED EXECUTION ATTESTATION VERIFICATION")
    print("=" * 72)
    print(f"RUNTIME LABEL : {runtime_label}")
    print(f"STATUS        : {verification_status}")
    print(f"REPORT JSON   : {rel(json_path)}")
    print(f"REPORT MD     : {rel(md_path)}")
    print(f"DIGEST        : {rel(digest_path)}")
    print("=" * 72)

    return 0 if verification_status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
