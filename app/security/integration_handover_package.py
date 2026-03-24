from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class IntegrationHandoverPackageError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IntegrationHandoverPaths:
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
    def integration_package_md(self) -> Path:
        return self.handover_dir / "INTEGRATION_HANDOVER_PACKAGE.md"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_file(path: Path, label: str) -> None:
    if not path.exists():
        raise IntegrationHandoverPackageError(f"required {label} file not found: {path}")


def _validate_baseline_manifest(manifest: dict[str, Any], manifest_sha256_text: str) -> None:
    if manifest.get("manifest_type") != "proof-registry-baseline":
        raise IntegrationHandoverPackageError("baseline manifest has unexpected manifest_type")

    if manifest.get("proof_range") != "R01-R35":
        raise IntegrationHandoverPackageError("baseline manifest has unexpected proof_range")

    proofs = manifest.get("proofs")
    if not isinstance(proofs, list) or len(proofs) != 35:
        raise IntegrationHandoverPackageError("baseline manifest does not contain exactly 35 proofs")

    summary = manifest.get("summary", {})
    status_counts = summary.get("status_counts", {})
    if status_counts.get("complete") != 35:
        raise IntegrationHandoverPackageError("baseline manifest is not fully complete")

    manifest_sha256 = str(manifest.get("manifest_sha256", "")).strip()
    if not manifest_sha256 or len(manifest_sha256) != 64:
        raise IntegrationHandoverPackageError("baseline manifest sha256 is missing or invalid")

    sha_file_value = manifest_sha256_text.strip()
    if manifest_sha256 != sha_file_value:
        raise IntegrationHandoverPackageError("baseline manifest sha256 does not match .sha256 sidecar file")


def _build_package_payload(project_root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    proof_ids = [str(item["proof_id"]) for item in manifest["proofs"]]
    titles = {str(item["proof_id"]): str(item["title"]) for item in manifest["proofs"]}

    return {
        "package_type": "integration-handover-package",
        "package_version": 1,
        "project_root": str(project_root),
        "baseline_manifest": {
            "path": "artifacts/handover/proof_registry_baseline_manifest.json",
            "sha256": manifest["manifest_sha256"],
            "proof_range": manifest["proof_range"],
            "proof_count": len(manifest["proofs"]),
        },
        "integration_scope": {
            "status": "ready-for-handover",
            "proof_range": proof_ids,
            "first_proof": proof_ids[0],
            "last_proof": proof_ids[-1],
        },
        "implementation_surfaces": [
            "app/security/",
            "tests/proofs/",
            "scripts/",
            "artifacts/handover/",
        ],
        "primary_outputs": [
            "proof registry baseline manifest",
            "formal proof registry entries R01-R35",
            "handover-ready integration package",
        ],
        "integration_contract": {
            "baseline_required": True,
            "all_proofs_complete_required": True,
            "hash_sidecar_required": True,
            "proof_manifest_mismatch_is_fatal": True,
        },
        "recommended_handover_sequence": [
            "verify baseline manifest and sha256",
            "review proof registry coverage R01-R35",
            "review security implementation surfaces under app/security",
            "run proof test suite under tests/proofs",
            "integrate control-plane components against the proven baseline",
        ],
        "top_level_summary": {
            "complete_proofs": len(proof_ids),
            "sample_titles": [
                titles["R01"],
                titles["R21"],
                titles["R35"],
            ],
        },
    }


def _build_markdown(package: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Integration Handover Package")
    lines.append("")
    lines.append("## Status")
    lines.append("")
    lines.append(f"- Package Type: `{package['package_type']}`")
    lines.append(f"- Package Version: `{package['package_version']}`")
    lines.append(f"- Project Root: `{package['project_root']}`")
    lines.append(f"- Baseline Proof Count: `{package['baseline_manifest']['proof_count']}`")
    lines.append(f"- Baseline Proof Range: `{package['baseline_manifest']['proof_range']}`")
    lines.append(f"- Baseline Manifest SHA256: `{package['baseline_manifest']['sha256']}`")
    lines.append("")
    lines.append("## Required Inputs")
    lines.append("")
    lines.append(f"- Baseline Manifest JSON: `{package['baseline_manifest']['path']}`")
    lines.append("- Baseline Manifest SHA256 sidecar file must match the JSON manifest.")
    lines.append("")
    lines.append("## Integration Contract")
    lines.append("")
    contract = package["integration_contract"]
    lines.append(f"- baseline_required: `{contract['baseline_required']}`")
    lines.append(f"- all_proofs_complete_required: `{contract['all_proofs_complete_required']}`")
    lines.append(f"- hash_sidecar_required: `{contract['hash_sidecar_required']}`")
    lines.append(f"- proof_manifest_mismatch_is_fatal: `{contract['proof_manifest_mismatch_is_fatal']}`")
    lines.append("")
    lines.append("## Implementation Surfaces")
    lines.append("")
    for item in package["implementation_surfaces"]:
        lines.append(f"- `{item}`")
    lines.append("")
    lines.append("## Recommended Handover Sequence")
    lines.append("")
    for idx, step in enumerate(package["recommended_handover_sequence"], start=1):
        lines.append(f"{idx}. {step}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Complete Proofs Registered: `{package['top_level_summary']['complete_proofs']}`")
    lines.append("- Representative Registry Titles:")
    for title in package["top_level_summary"]["sample_titles"]:
        lines.append(f"  - {title}")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_integration_handover_package(*, project_root: str | Path) -> dict[str, Any]:
    project_root_path = Path(project_root).resolve()
    paths = IntegrationHandoverPaths(project_root=str(project_root_path))

    _ensure_file(paths.baseline_manifest_json, "baseline manifest json")
    _ensure_file(paths.baseline_manifest_sha256, "baseline manifest sha256")

    manifest = _read_json(paths.baseline_manifest_json)
    manifest_sha256_text = paths.baseline_manifest_sha256.read_text(encoding="utf-8")
    _validate_baseline_manifest(manifest, manifest_sha256_text)

    package = _build_package_payload(project_root_path, manifest)

    paths.handover_dir.mkdir(parents=True, exist_ok=True)
    paths.integration_package_json.write_text(
        json.dumps(package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    paths.integration_package_md.write_text(
        _build_markdown(package),
        encoding="utf-8",
    )

    return {
        "ok": True,
        "integration_package_json": str(paths.integration_package_json),
        "integration_package_md": str(paths.integration_package_md),
        "baseline_manifest_json": str(paths.baseline_manifest_json),
        "baseline_manifest_sha256": str(paths.baseline_manifest_sha256),
        "proof_count": package["baseline_manifest"]["proof_count"],
    }

