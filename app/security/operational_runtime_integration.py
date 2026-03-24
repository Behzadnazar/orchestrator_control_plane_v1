from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class OperationalRuntimeIntegrationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OperationalRuntimePaths:
    project_root: str

    @property
    def root(self) -> Path:
        return Path(self.project_root)

    @property
    def handover_dir(self) -> Path:
        return self.root / "artifacts" / "handover"

    @property
    def baseline_manifest_json(self) -> Path:
        return self.handover_dir / "proof_registry_baseline_manifest.json"

    @property
    def baseline_manifest_sha256(self) -> Path:
        return self.handover_dir / "proof_registry_baseline_manifest.sha256"

    @property
    def integration_package_json(self) -> Path:
        return self.handover_dir / "integration_handover_package.json"

    @property
    def runtime_integration_json(self) -> Path:
        return self.handover_dir / "runtime_control_plane_integration.json"

    @property
    def formal_delivery_bundle_json(self) -> Path:
        return self.handover_dir / "formal_delivery_bundle.json"

    @property
    def formal_delivery_bundle_sha256(self) -> Path:
        return self.handover_dir / "formal_delivery_bundle.sha256"

    @property
    def operational_plan_md(self) -> Path:
        return self.handover_dir / "OPERATIONAL_INTEGRATION_PLAN.md"

    @property
    def final_summary_md(self) -> Path:
        return self.handover_dir / "FINAL_SECURITY_HANDOVER_SUMMARY.md"

    @property
    def runtime_operational_json(self) -> Path:
        return self.handover_dir / "runtime_operational_integration.json"

    @property
    def runtime_operational_md(self) -> Path:
        return self.handover_dir / "RUNTIME_OPERATIONAL_INTEGRATION.md"

    @property
    def app_security_dir(self) -> Path:
        return self.root / "app" / "security"

    @property
    def tests_proofs_dir(self) -> Path:
        return self.root / "tests" / "proofs"

    @property
    def scripts_dir(self) -> Path:
        return self.root / "scripts"


def _ensure_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise OperationalRuntimeIntegrationError(f"required {label} not found: {path}")


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _validate_baseline(baseline: dict[str, Any], sidecar_text: str) -> None:
    if baseline.get("manifest_type") != "proof-registry-baseline":
        raise OperationalRuntimeIntegrationError("baseline manifest type is invalid")

    if baseline.get("proof_range") != "R01-R35":
        raise OperationalRuntimeIntegrationError("baseline proof_range is invalid")

    proofs = baseline.get("proofs")
    if not isinstance(proofs, list) or len(proofs) != 35:
        raise OperationalRuntimeIntegrationError("baseline proof count is invalid")

    status_counts = baseline.get("summary", {}).get("status_counts", {})
    if status_counts.get("complete") != 35:
        raise OperationalRuntimeIntegrationError("baseline is not fully complete")

    manifest_sha = str(baseline.get("manifest_sha256", "")).strip()
    if not manifest_sha:
        raise OperationalRuntimeIntegrationError("baseline manifest sha256 is missing")

    if manifest_sha != sidecar_text.strip():
        raise OperationalRuntimeIntegrationError("baseline sha256 does not match sidecar file")


def _validate_integration_package(package: dict[str, Any], expected_sha: str) -> None:
    if package.get("package_type") != "integration-handover-package":
        raise OperationalRuntimeIntegrationError("integration handover package type is invalid")

    baseline = package.get("baseline_manifest", {})
    if baseline.get("sha256") != expected_sha:
        raise OperationalRuntimeIntegrationError("integration handover package sha does not match baseline sha")

    if baseline.get("proof_count") != 35:
        raise OperationalRuntimeIntegrationError("integration handover package proof_count is invalid")


def _validate_runtime_integration(runtime_payload: dict[str, Any], expected_sha: str) -> None:
    if runtime_payload.get("document_type") != "runtime-control-plane-integration":
        raise OperationalRuntimeIntegrationError("runtime control-plane integration type is invalid")

    baseline_binding = runtime_payload.get("baseline_binding", {})
    if baseline_binding.get("manifest_sha256") != expected_sha:
        raise OperationalRuntimeIntegrationError("runtime control-plane integration sha does not match baseline sha")

    if baseline_binding.get("proof_count") != 35:
        raise OperationalRuntimeIntegrationError("runtime control-plane integration proof_count is invalid")


def _validate_formal_bundle(bundle: dict[str, Any], expected_sha: str) -> None:
    if bundle.get("bundle_type") != "formal-delivery-bundle":
        raise OperationalRuntimeIntegrationError("formal delivery bundle type is invalid")

    baseline = bundle.get("baseline", {})
    if baseline.get("manifest_sha256") != expected_sha:
        raise OperationalRuntimeIntegrationError("formal delivery bundle sha does not match baseline sha")

    scope = bundle.get("bundle_scope", {})
    if scope.get("proof_count") != 35:
        raise OperationalRuntimeIntegrationError("formal delivery bundle proof_count is invalid")


def _directory_inventory(path: Path) -> dict[str, Any]:
    entries = sorted(p.name for p in path.iterdir()) if path.exists() else []
    return {
        "path": str(path),
        "exists": path.exists(),
        "entry_count": len(entries),
        "sample_entries": entries[:10],
    }


def _build_payload(
    *,
    project_root: Path,
    baseline_sha: str,
    app_security_inventory: dict[str, Any],
    tests_proofs_inventory: dict[str, Any],
    scripts_inventory: dict[str, Any],
) -> dict[str, Any]:
    return {
        "document_type": "runtime-operational-integration",
        "document_version": 1,
        "project_root": str(project_root),
        "activation_status": "ready-for-operational-runtime-integration",
        "baseline_binding": {
            "proof_range": "R01-R35",
            "proof_count": 35,
            "baseline_sha256": baseline_sha,
        },
        "required_runtime_surfaces": [
            "app/security/",
            "tests/proofs/",
            "scripts/",
            "artifacts/handover/",
        ],
        "runtime_surface_inventory": {
            "app_security": app_security_inventory,
            "tests_proofs": tests_proofs_inventory,
            "scripts": scripts_inventory,
        },
        "operational_runtime_sequence": [
            "verify baseline manifest and sha256 sidecar",
            "verify integration handover package",
            "verify runtime control plane integration package",
            "verify formal delivery bundle",
            "verify app/security and tests/proofs runtime surfaces",
            "treat runtime onboarding as blocked on any mismatch",
            "handoff runtime activation only after all checks pass",
        ],
        "operational_gate_contract": {
            "baseline_match_required": True,
            "integration_package_match_required": True,
            "runtime_package_match_required": True,
            "formal_bundle_match_required": True,
            "project_surfaces_present_required": True,
            "missing_or_mismatched_input_is_fatal": True,
        },
    }


def _build_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Runtime Operational Integration")
    lines.append("")
    lines.append("## Status")
    lines.append("")
    lines.append(f"- Document Type: `{payload['document_type']}`")
    lines.append(f"- Document Version: `{payload['document_version']}`")
    lines.append(f"- Activation Status: `{payload['activation_status']}`")
    lines.append(f"- Proof Range: `{payload['baseline_binding']['proof_range']}`")
    lines.append(f"- Proof Count: `{payload['baseline_binding']['proof_count']}`")
    lines.append(f"- Baseline SHA256: `{payload['baseline_binding']['baseline_sha256']}`")
    lines.append("")
    lines.append("## Runtime Surfaces")
    lines.append("")
    for key, value in payload["runtime_surface_inventory"].items():
        lines.append(f"- **{key}**")
        lines.append(f"  - path: `{value['path']}`")
        lines.append(f"  - exists: `{value['exists']}`")
        lines.append(f"  - entry_count: `{value['entry_count']}`")
        lines.append(f"  - sample_entries: `{value['sample_entries']}`")
    lines.append("")
    lines.append("## Operational Runtime Sequence")
    lines.append("")
    for idx, item in enumerate(payload["operational_runtime_sequence"], start=1):
        lines.append(f"{idx}. {item}")
    lines.append("")
    lines.append("## Gate Contract")
    lines.append("")
    for key, value in payload["operational_gate_contract"].items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_operational_runtime_integration(*, project_root: str | Path) -> dict[str, Any]:
    project_root_path = Path(project_root).resolve()
    paths = OperationalRuntimePaths(project_root=str(project_root_path))

    _ensure_exists(paths.baseline_manifest_json, "baseline manifest json")
    _ensure_exists(paths.baseline_manifest_sha256, "baseline manifest sha256")
    _ensure_exists(paths.integration_package_json, "integration handover package json")
    _ensure_exists(paths.runtime_integration_json, "runtime integration json")
    _ensure_exists(paths.formal_delivery_bundle_json, "formal delivery bundle json")
    _ensure_exists(paths.formal_delivery_bundle_sha256, "formal delivery bundle sha256")
    _ensure_exists(paths.operational_plan_md, "operational integration plan markdown")
    _ensure_exists(paths.final_summary_md, "final security handover summary markdown")
    _ensure_exists(paths.app_security_dir, "app/security directory")
    _ensure_exists(paths.tests_proofs_dir, "tests/proofs directory")
    _ensure_exists(paths.scripts_dir, "scripts directory")

    baseline = _read_json(paths.baseline_manifest_json)
    baseline_sidecar = _read_text(paths.baseline_manifest_sha256)
    _validate_baseline(baseline, baseline_sidecar)

    baseline_sha = str(baseline["manifest_sha256"])

    integration_package = _read_json(paths.integration_package_json)
    _validate_integration_package(integration_package, baseline_sha)

    runtime_package = _read_json(paths.runtime_integration_json)
    _validate_runtime_integration(runtime_package, baseline_sha)

    formal_bundle = _read_json(paths.formal_delivery_bundle_json)
    _validate_formal_bundle(formal_bundle, baseline_sha)

    app_security_inventory = _directory_inventory(paths.app_security_dir)
    tests_proofs_inventory = _directory_inventory(paths.tests_proofs_dir)
    scripts_inventory = _directory_inventory(paths.scripts_dir)

    payload = _build_payload(
        project_root=project_root_path,
        baseline_sha=baseline_sha,
        app_security_inventory=app_security_inventory,
        tests_proofs_inventory=tests_proofs_inventory,
        scripts_inventory=scripts_inventory,
    )

    paths.runtime_operational_json.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    paths.runtime_operational_md.write_text(
        _build_markdown(payload),
        encoding="utf-8",
    )

    return {
        "ok": True,
        "runtime_operational_json": str(paths.runtime_operational_json),
        "runtime_operational_md": str(paths.runtime_operational_md),
        "baseline_sha256": baseline_sha,
    }
