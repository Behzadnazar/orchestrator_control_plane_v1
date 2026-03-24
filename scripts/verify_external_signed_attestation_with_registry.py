#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OPERATIONS_ROOT = ROOT / "artifacts" / "operations"
EXTERNAL_SIGNED_ROOT = OPERATIONS_ROOT / "external_signed_runtime"
VERIFY_ROOT = OPERATIONS_ROOT / "external_attestation_registry_verification"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path):
    return json.loads(read_text(path))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def sha256_file(path: Path) -> str:
    import hashlib
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


def openssl_verify(public_key_path: Path, payload: dict, signature_b64: str) -> bool:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        payload_path = td_path / "payload.json"
        sig_path = td_path / "payload.sig"
        payload_path.write_text(canonical_json(payload), encoding="utf-8")
        sig_path.write_bytes(base64.b64decode(signature_b64.encode("ascii")))

        cmd = [
            "openssl",
            "dgst",
            "-sha256",
            "-verify",
            str(public_key_path),
            "-signature",
            str(sig_path),
            str(payload_path),
        ]
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
        return proc.returncode == 0


def load_registry_entry(registry: dict, public_key_path_rel: str, public_key_sha256: str) -> dict | None:
    keys = registry.get("keys", [])
    for item in keys:
        if not isinstance(item, dict):
            continue
        if item.get("public_key_path") == public_key_path_rel and item.get("public_key_sha256") == public_key_sha256:
            return item
    return None


def build_markdown_report(result: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# External Signed Attestation Verification with Key Registry")
    lines.append("")
    lines.append(f"- Runtime label: `{result['runtime_label']}`")
    lines.append(f"- Verification status: **{result['verification_status']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Registry Checks")
    lines.append("")
    lines.append(f"- Registry entry found: **{result['checks']['registry_entry_found']}**")
    lines.append(f"- Key status active: **{result['checks']['registry_key_active']}**")
    lines.append(f"- Key not revoked: **{result['checks']['registry_key_not_revoked']}**")
    lines.append("")
    lines.append("## Signature Checks")
    lines.append("")
    lines.append(f"- Signature valid: **{result['checks']['signature_valid']}**")
    lines.append(f"- Receipt hash matches: **{result['checks']['receipt_hash_matches']}**")
    lines.append(f"- Manifest hash matches: **{result['checks']['manifest_hash_matches']}**")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify external-key signed attestation against key registry and revocation state.")
    parser.add_argument("--runtime-label", required=True)
    parser.add_argument("--registry-path", required=True)
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    runtime_label = args.runtime_label.strip()
    registry_path = Path(args.registry_path).resolve()
    label = args.label.strip() or f"{runtime_label}__registry_verification"

    if not runtime_label:
        raise SystemExit("runtime-label must not be empty.")

    signed_dir = EXTERNAL_SIGNED_ROOT / runtime_label
    if not signed_dir.exists():
        raise SystemExit(f"Signed runtime directory not found: {signed_dir}")

    output_dir = VERIFY_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")

    receipt_path = require_file(signed_dir / "external_signed_execution_receipt.json")
    attestation_path = require_file(signed_dir / "external_signed_execution_attestation.json")
    report_path = require_file(signed_dir / "external_signed_runtime_report.json")
    manifest_path = require_file(signed_dir / "normalized_request_manifest.json")
    registry_path = require_file(registry_path)

    receipt = read_json(receipt_path)
    attestation = read_json(attestation_path)
    report = read_json(report_path)
    manifest = read_json(manifest_path)
    registry = read_json(registry_path)

    public_key_rel = str(attestation.get("public_key_path", "")).strip()
    public_key_path = require_file(ROOT / public_key_rel)
    public_key_sha256 = sha256_file(public_key_path)

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
        "public_key_path": attestation.get("public_key_path"),
        "public_key_sha256": attestation.get("public_key_sha256"),
        "trust_boundary_mode": attestation.get("trust_boundary_mode"),
        "private_key_material_embedded": attestation.get("private_key_material_embedded"),
    }

    signature_valid = openssl_verify(public_key_path, attestation_payload, str(attestation.get("signature_b64", "")))
    registry_entry = load_registry_entry(registry, public_key_rel, public_key_sha256)

    checks = {
        "receipt_exists": receipt_path.exists(),
        "attestation_exists": attestation_path.exists(),
        "report_exists": report_path.exists(),
        "manifest_exists": manifest_path.exists(),
        "registry_exists": registry_path.exists(),
        "receipt_hash_matches": sha256_file(receipt_path) == attestation.get("receipt_sha256"),
        "manifest_hash_matches": sha256_file(manifest_path) == attestation.get("manifest_sha256"),
        "public_key_hash_matches": public_key_sha256 == attestation.get("public_key_sha256"),
        "private_key_material_not_embedded": attestation.get("private_key_material_embedded") is False,
        "signature_valid": signature_valid,
        "registry_entry_found": registry_entry is not None,
        "registry_key_active": bool(registry_entry and registry_entry.get("status") == "active"),
        "registry_key_not_revoked": bool(registry_entry and registry_entry.get("revoked") is False),
        "gate_decision_allow": str(attestation.get("gate_decision", "")).upper() == "ALLOW",
        "runtime_status_allow_executed": str(attestation.get("runtime_status", "")).upper() == "ALLOW_EXECUTED",
        "report_runtime_consistent": report.get("runtime_label") == runtime_label,
        "receipt_runtime_consistent": receipt.get("runtime_label") == runtime_label,
        "manifest_workflow_consistent": manifest.get("workflow_id") == report.get("workflow_id"),
    }

    verification_status = "PASS" if all(checks.values()) else "FAIL"

    result = {
        "verification_version": 1,
        "verification_type": "external_signed_attestation_registry_verification",
        "runtime_label": runtime_label,
        "verification_status": verification_status,
        "inputs": {
            "receipt_path": rel(receipt_path),
            "attestation_path": rel(attestation_path),
            "report_path": rel(report_path),
            "manifest_path": rel(manifest_path),
            "public_key_path": rel(public_key_path),
            "registry_path": rel(registry_path),
        },
        "registry_entry": registry_entry,
        "checks": checks,
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    json_path = output_dir / "external_signed_attestation_registry_verification.json"
    md_path = output_dir / "external_signed_attestation_registry_verification.md"
    digest_path = output_dir / "external_signed_attestation_registry_verification_digest.json"

    write_json(json_path, result)
    write_text(md_path, build_markdown_report(result, output_dir))
    write_json(digest_path, {
        "runtime_label": runtime_label,
        "verification_status": verification_status,
        "artifacts": [
            {"path": rel(json_path), "size_bytes": json_path.stat().st_size, "sha256": sha256_file(json_path)},
            {"path": rel(md_path), "size_bytes": md_path.stat().st_size, "sha256": sha256_file(md_path)},
        ],
    })

    print("=" * 72)
    print("EXTERNAL SIGNED ATTESTATION REGISTRY VERIFICATION")
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
