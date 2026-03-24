from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class RuntimeControlPlaneIntegrationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RuntimeIntegrationPaths:
    project_root: str

    @property
    def handover_dir(self) -> Path:
        return Path(self.project_root) / "artifacts" / "handover"

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
    def operational_plan_md(self) -> Path:
        return self.handover_dir / "OPERATIONAL_INTEGRATION_PLAN.md"

    @property
    def final_summary_md(self) -> Path:
        return self.handover_dir / "FINAL_SECURITY_HANDOVER_SUMMARY.md"

    @property
    def runtime_integration_json(self) -> Path:
        return self.handover_dir / "runtime_control_plane_integration.json"

    @property
    def runtime_integration_md(self) -> Path:
        return self.handover_dir / "RUNTIME_CONTROL_PLANE_INTEGRATION.md"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise RuntimeControlPlaneIntegrationError(f"required {label} file not found: {path}")


def _validate_baseline(manifest: dict[str, Any], sidecar_text: str) -> None:
    if manifest.get("manifest_type") != "proof-registry-baseline":
        raise RuntimeControlPlaneIntegrationError("baseline manifest type is invalid")

    if manifest.get("proof_range") != "R01-R35":
        raise RuntimeControlPlaneIntegrationError("baseline manifest proof_range is invalid")

    proofs = manifest.get("proofs")
    if not isinstance(proofs, list) or len(proofs) != 35:
        raise RuntimeControlPlaneIntegrationError("baseline manifest proof count is invalid")

    status_counts = manifest.get("summary", {}).get("status_counts", {})
    if status_counts.get("complete") != 35:
        raise RuntimeControlPlaneIntegrationError("baseline manifest is not fully complete")

    manifest_sha = str(manifest.get("manifest_sha256", "")).strip()
    if not manifest_sha:
        raise RuntimeControlPlaneIntegrationError("baseline manifest sha256 is missing")

    if manifest_sha != sidecar_text.strip():
        raise RuntimeControlPlaneIntegrationError("baseline manifest sha256 does not match sidecar file")


def _validate_integration_package(package: dict[str, Any], expected_manifest_sha: str) -> None:
    if package.get("package_type") != "integration-handover-package":
        raise RuntimeControlPlaneIntegrationError("integration handover package type is invalid")

    baseline = package.get("baseline_manifest", {})
    if baseline.get("proof_count") != 35:
        raise RuntimeControlPlaneIntegrationError("integration handover package proof_count is invalid")

    if baseline.get("proof_range") != "R01-R35":
        raise RuntimeControlPlaneIntegrationError("integration handover package proof_range is invalid")

    if baseline.get("sha256") != expected_manifest_sha:
        raise RuntimeControlPlaneIntegrationError("integration handover package does not reference the current baseline sha256")


def _build_runtime_payload(
    *,
    project_root: Path,
    manifest: dict[str, Any],
    package: dict[str, Any],
) -> dict[str, Any]:
    return {
        "document_type": "runtime-control-plane-integration",
        "document_version": 1,
        "project_root": str(project_root),
        "baseline_binding": {
            "manifest_path": "artifacts/handover/proof_registry_baseline_manifest.json",
            "manifest_sha256": manifest["manifest_sha256"],
            "integration_package_path": "artifacts/handover/integration_handover_package.json",
            "proof_count": package["baseline_manifest"]["proof_count"],
        },
        "runtime_scope": {
            "status": "ready-for-runtime-integration",
            "security_baseline_required": True,
            "proof_registry_required": True,
            "handover_package_required": True,
        },
        "control_plane_runtime_surfaces": [
            "app/security/",
            "scripts/",
            "tests/proofs/",
            "artifacts/handover/",
        ],
        "integration_sequence": [
            {
                "step": 1,
                "name": "baseline-verification",
                "description": "Verify proof registry baseline manifest and sidecar sha256 before runtime integration.",
            },
            {
                "step": 2,
                "name": "handover-package-verification",
                "description": "Verify the integration handover package references the current baseline manifest.",
            },
            {
                "step": 3,
                "name": "runtime-surface-wiring",
                "description": "Wire control-plane runtime against app/security implementation surfaces and scripts.",
            },
            {
                "step": 4,
                "name": "proof-suite-gate",
                "description": "Run proof suite before runtime cutover or release candidate promotion.",
            },
            {
                "step": 5,
                "name": "operational-handover",
                "description": "Use the operational integration plan and final security summary as handover baseline for runtime onboarding.",
            },
        ],
        "runtime_acceptance_contract": {
            "baseline_sha_match_required": True,
            "package_sha_alignment_required": True,
            "proof_count_35_required": True,
            "missing_handover_artifact_is_fatal": True,
            "runtime_without_verified_baseline_is_forbidden": True,
        },
        "runtime_outputs": [
            "runtime_control_plane_integration.json",
            "RUNTIME_CONTROL_PLANE_INTEGRATION.md",
            "OPERATIONAL_INTEGRATION_PLAN.md",
            "FINAL_SECURITY_HANDOVER_SUMMARY.md",
        ],
    }


def _build_runtime_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Runtime Control Plane Integration")
    lines.append("")
    lines.append("## Status")
    lines.append("")
    lines.append(f"- Document Type: `{payload['document_type']}`")
    lines.append(f"- Document Version: `{payload['document_version']}`")
    lines.append(f"- Project Root: `{payload['project_root']}`")
    lines.append(f"- Runtime Status: `{payload['runtime_scope']['status']}`")
    lines.append("")
    lines.append("## Baseline Binding")
    lines.append("")
    lines.append(f"- Baseline Manifest: `{payload['baseline_binding']['manifest_path']}`")
    lines.append(f"- Baseline SHA256: `{payload['baseline_binding']['manifest_sha256']}`")
    lines.append(f"- Integration Package: `{payload['baseline_binding']['integration_package_path']}`")
    lines.append(f"- Proof Count: `{payload['baseline_binding']['proof_count']}`")
    lines.append("")
    lines.append("## Integration Sequence")
    lines.append("")
    for item in payload["integration_sequence"]:
        lines.append(f"{item['step']}. **{item['name']}** — {item['description']}")
    lines.append("")
    lines.append("## Runtime Acceptance Contract")
    lines.append("")
    contract = payload["runtime_acceptance_contract"]
    for key, value in contract.items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")
    lines.append("## Runtime Outputs")
    lines.append("")
    for item in payload["runtime_outputs"]:
        lines.append(f"- `{item}`")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_runtime_control_plane_integration(*, project_root: str | Path) -> dict[str, Any]:
    project_root_path = Path(project_root).resolve()
    paths = RuntimeIntegrationPaths(project_root=str(project_root_path))

    _ensure_exists(paths.baseline_manifest_json, "baseline manifest json")
    _ensure_exists(paths.baseline_manifest_sha256, "baseline manifest sha256")
    _ensure_exists(paths.integration_package_json, "integration handover package json")
    _ensure_exists(paths.operational_plan_md, "operational integration plan")
    _ensure_exists(paths.final_summary_md, "final security handover summary")

    manifest = _read_json(paths.baseline_manifest_json)
    sidecar = paths.baseline_manifest_sha256.read_text(encoding="utf-8")
    _validate_baseline(manifest, sidecar)

    package = _read_json(paths.integration_package_json)
    _validate_integration_package(package, manifest["manifest_sha256"])

    payload = _build_runtime_payload(
        project_root=project_root_path,
        manifest=manifest,
        package=package,
    )

    paths.runtime_integration_json.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    paths.runtime_integration_md.write_text(
        _build_runtime_markdown(payload),
        encoding="utf-8",
    )

    return {
        "ok": True,
        "runtime_integration_json": str(paths.runtime_integration_json),
        "runtime_integration_md": str(paths.runtime_integration_md),
        "baseline_manifest_json": str(paths.baseline_manifest_json),
        "integration_package_json": str(paths.integration_package_json),
    }
