from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class FormalDeliveryBundleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FormalDeliveryPaths:
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

    @property
    def runtime_integration_json(self) -> Path:
        return self.handover_dir / "runtime_control_plane_integration.json"

    @property
    def runtime_integration_md(self) -> Path:
        return self.handover_dir / "RUNTIME_CONTROL_PLANE_INTEGRATION.md"

    @property
    def operational_plan_md(self) -> Path:
        return self.handover_dir / "OPERATIONAL_INTEGRATION_PLAN.md"

    @property
    def final_summary_md(self) -> Path:
        return self.handover_dir / "FINAL_SECURITY_HANDOVER_SUMMARY.md"

    @property
    def delivery_bundle_json(self) -> Path:
        return self.handover_dir / "formal_delivery_bundle.json"

    @property
    def delivery_bundle_md(self) -> Path:
        return self.handover_dir / "FORMAL_DELIVERY_BUNDLE.md"

    @property
    def delivery_bundle_sha256(self) -> Path:
        return self.handover_dir / "formal_delivery_bundle.sha256"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _ensure_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise FormalDeliveryBundleError(f"required {label} file not found: {path}")


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_descriptor(path: Path, relative_root: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": str(path.relative_to(relative_root)),
        "sha256": _sha256_hex(data),
        "size_bytes": len(data),
    }


def _validate_baseline(manifest: dict[str, Any], sidecar_text: str) -> None:
    if manifest.get("manifest_type") != "proof-registry-baseline":
        raise FormalDeliveryBundleError("baseline manifest type is invalid")

    if manifest.get("proof_range") != "R01-R35":
        raise FormalDeliveryBundleError("baseline manifest proof_range is invalid")

    proofs = manifest.get("proofs")
    if not isinstance(proofs, list) or len(proofs) != 35:
        raise FormalDeliveryBundleError("baseline manifest proof count is invalid")

    status_counts = manifest.get("summary", {}).get("status_counts", {})
    if status_counts.get("complete") != 35:
        raise FormalDeliveryBundleError("baseline manifest is not fully complete")

    manifest_sha = str(manifest.get("manifest_sha256", "")).strip()
    if not manifest_sha:
        raise FormalDeliveryBundleError("baseline manifest sha256 is missing")

    if manifest_sha != sidecar_text.strip():
        raise FormalDeliveryBundleError("baseline manifest sha256 does not match sidecar file")


def _validate_integration_package(package: dict[str, Any], baseline_sha: str) -> None:
    if package.get("package_type") != "integration-handover-package":
        raise FormalDeliveryBundleError("integration handover package type is invalid")

    baseline = package.get("baseline_manifest", {})
    if baseline.get("proof_count") != 35:
        raise FormalDeliveryBundleError("integration handover package proof_count is invalid")

    if baseline.get("proof_range") != "R01-R35":
        raise FormalDeliveryBundleError("integration handover package proof_range is invalid")

    if baseline.get("sha256") != baseline_sha:
        raise FormalDeliveryBundleError("integration handover package sha does not match baseline sha")


def _validate_runtime_package(runtime_package: dict[str, Any], baseline_sha: str) -> None:
    if runtime_package.get("document_type") != "runtime-control-plane-integration":
        raise FormalDeliveryBundleError("runtime integration document type is invalid")

    baseline_binding = runtime_package.get("baseline_binding", {})
    if baseline_binding.get("proof_count") != 35:
        raise FormalDeliveryBundleError("runtime integration proof_count is invalid")

    if baseline_binding.get("manifest_sha256") != baseline_sha:
        raise FormalDeliveryBundleError("runtime integration baseline sha does not match baseline manifest sha")


def _build_bundle_payload(
    *,
    project_root: Path,
    paths: FormalDeliveryPaths,
    baseline_manifest: dict[str, Any],
    integration_package: dict[str, Any],
    runtime_package: dict[str, Any],
) -> dict[str, Any]:
    files = [
        _file_descriptor(paths.baseline_manifest_json, project_root),
        _file_descriptor(paths.baseline_manifest_sha256, project_root),
        _file_descriptor(paths.integration_package_json, project_root),
        _file_descriptor(paths.integration_package_md, project_root),
        _file_descriptor(paths.runtime_integration_json, project_root),
        _file_descriptor(paths.runtime_integration_md, project_root),
        _file_descriptor(paths.operational_plan_md, project_root),
        _file_descriptor(paths.final_summary_md, project_root),
    ]

    return {
        "bundle_type": "formal-delivery-bundle",
        "bundle_version": 1,
        "project_root": str(project_root),
        "bundle_scope": {
            "status": "ready-for-formal-delivery",
            "proof_range": "R01-R35",
            "proof_count": 35,
        },
        "baseline": {
            "manifest_path": str(paths.baseline_manifest_json.relative_to(project_root)),
            "manifest_sha256_path": str(paths.baseline_manifest_sha256.relative_to(project_root)),
            "manifest_sha256": baseline_manifest["manifest_sha256"],
        },
        "handover": {
            "integration_package_json": str(paths.integration_package_json.relative_to(project_root)),
            "integration_package_md": str(paths.integration_package_md.relative_to(project_root)),
        },
        "runtime": {
            "runtime_integration_json": str(paths.runtime_integration_json.relative_to(project_root)),
            "runtime_integration_md": str(paths.runtime_integration_md.relative_to(project_root)),
        },
        "operational_docs": {
            "operational_plan_md": str(paths.operational_plan_md.relative_to(project_root)),
            "final_summary_md": str(paths.final_summary_md.relative_to(project_root)),
        },
        "consistency_contract": {
            "baseline_complete_required": True,
            "baseline_sha_alignment_required": True,
            "handover_package_required": True,
            "runtime_package_required": True,
            "operational_docs_required": True,
            "missing_or_mismatched_artifact_is_fatal": True,
        },
        "verified_bindings": {
            "integration_package_references_baseline_sha": True,
            "runtime_package_references_baseline_sha": True,
            "proof_count_verified": True,
        },
        "included_files": files,
        "top_level_summary": {
            "baseline_manifest_type": baseline_manifest["manifest_type"],
            "integration_package_type": integration_package["package_type"],
            "runtime_document_type": runtime_package["document_type"],
        },
    }


def _build_bundle_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Formal Delivery Bundle")
    lines.append("")
    lines.append("## Status")
    lines.append("")
    lines.append(f"- Bundle Type: `{payload['bundle_type']}`")
    lines.append(f"- Bundle Version: `{payload['bundle_version']}`")
    lines.append(f"- Proof Range: `{payload['bundle_scope']['proof_range']}`")
    lines.append(f"- Proof Count: `{payload['bundle_scope']['proof_count']}`")
    lines.append(f"- Delivery Status: `{payload['bundle_scope']['status']}`")
    lines.append("")
    lines.append("## Baseline")
    lines.append("")
    lines.append(f"- Manifest: `{payload['baseline']['manifest_path']}`")
    lines.append(f"- Manifest SHA256 File: `{payload['baseline']['manifest_sha256_path']}`")
    lines.append(f"- Manifest SHA256: `{payload['baseline']['manifest_sha256']}`")
    lines.append("")
    lines.append("## Handover and Runtime Artifacts")
    lines.append("")
    lines.append(f"- Handover JSON: `{payload['handover']['integration_package_json']}`")
    lines.append(f"- Handover Markdown: `{payload['handover']['integration_package_md']}`")
    lines.append(f"- Runtime JSON: `{payload['runtime']['runtime_integration_json']}`")
    lines.append(f"- Runtime Markdown: `{payload['runtime']['runtime_integration_md']}`")
    lines.append(f"- Operational Plan: `{payload['operational_docs']['operational_plan_md']}`")
    lines.append(f"- Final Summary: `{payload['operational_docs']['final_summary_md']}`")
    lines.append("")
    lines.append("## Consistency Contract")
    lines.append("")
    for key, value in payload["consistency_contract"].items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")
    lines.append("## Included Files")
    lines.append("")
    for item in payload["included_files"]:
        lines.append(
            f"- `{item['path']}` | sha256=`{item['sha256']}` | size=`{item['size_bytes']}`"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def build_formal_delivery_bundle(*, project_root: str | Path) -> dict[str, Any]:
    project_root_path = Path(project_root).resolve()
    paths = FormalDeliveryPaths(project_root=str(project_root_path))

    _ensure_exists(paths.baseline_manifest_json, "baseline manifest json")
    _ensure_exists(paths.baseline_manifest_sha256, "baseline manifest sha256")
    _ensure_exists(paths.integration_package_json, "integration handover package json")
    _ensure_exists(paths.integration_package_md, "integration handover package markdown")
    _ensure_exists(paths.runtime_integration_json, "runtime integration json")
    _ensure_exists(paths.runtime_integration_md, "runtime integration markdown")
    _ensure_exists(paths.operational_plan_md, "operational integration plan markdown")
    _ensure_exists(paths.final_summary_md, "final security summary markdown")

    baseline_manifest = _read_json(paths.baseline_manifest_json)
    baseline_sha_sidecar = _read_text(paths.baseline_manifest_sha256)
    _validate_baseline(baseline_manifest, baseline_sha_sidecar)

    integration_package = _read_json(paths.integration_package_json)
    _validate_integration_package(integration_package, baseline_manifest["manifest_sha256"])

    runtime_package = _read_json(paths.runtime_integration_json)
    _validate_runtime_package(runtime_package, baseline_manifest["manifest_sha256"])

    bundle_payload = _build_bundle_payload(
        project_root=project_root_path,
        paths=paths,
        baseline_manifest=baseline_manifest,
        integration_package=integration_package,
        runtime_package=runtime_package,
    )

    bundle_sha = _sha256_hex(_canonical_json_bytes(bundle_payload))
    bundle_payload["bundle_sha256"] = bundle_sha

    paths.delivery_bundle_json.write_text(
        json.dumps(bundle_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    paths.delivery_bundle_md.write_text(
        _build_bundle_markdown(bundle_payload),
        encoding="utf-8",
    )
    paths.delivery_bundle_sha256.write_text(
        bundle_sha + "\n",
        encoding="utf-8",
    )

    return {
        "ok": True,
        "delivery_bundle_json": str(paths.delivery_bundle_json),
        "delivery_bundle_md": str(paths.delivery_bundle_md),
        "delivery_bundle_sha256": str(paths.delivery_bundle_sha256),
        "bundle_sha256": bundle_sha,
    }
