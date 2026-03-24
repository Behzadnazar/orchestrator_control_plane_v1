from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ReleaseCandidateRolloutError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseCandidatePaths:
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
    def runtime_operational_json(self) -> Path:
        return self.handover_dir / "runtime_operational_integration.json"

    @property
    def runtime_operational_md(self) -> Path:
        return self.handover_dir / "RUNTIME_OPERATIONAL_INTEGRATION.md"

    @property
    def operational_plan_md(self) -> Path:
        return self.handover_dir / "OPERATIONAL_INTEGRATION_PLAN.md"

    @property
    def final_summary_md(self) -> Path:
        return self.handover_dir / "FINAL_SECURITY_HANDOVER_SUMMARY.md"

    @property
    def rollout_plan_md(self) -> Path:
        return self.handover_dir / "RC_ROLLOUT_PLAN.md"

    @property
    def onboarding_handoff_md(self) -> Path:
        return self.handover_dir / "RUNTIME_ONBOARDING_HANDOFF.md"

    @property
    def rollout_json(self) -> Path:
        return self.handover_dir / "release_candidate_rollout.json"

    @property
    def rollout_md(self) -> Path:
        return self.handover_dir / "RELEASE_CANDIDATE_ROLLOUT.md"


def _ensure_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise ReleaseCandidateRolloutError(f"required {label} not found: {path}")


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _validate_baseline(baseline: dict[str, Any], sidecar_text: str) -> str:
    if baseline.get("manifest_type") != "proof-registry-baseline":
        raise ReleaseCandidateRolloutError("baseline manifest type is invalid")

    if baseline.get("proof_range") != "R01-R35":
        raise ReleaseCandidateRolloutError("baseline proof_range is invalid")

    proofs = baseline.get("proofs")
    if not isinstance(proofs, list) or len(proofs) != 35:
        raise ReleaseCandidateRolloutError("baseline proof count is invalid")

    status_counts = baseline.get("summary", {}).get("status_counts", {})
    if status_counts.get("complete") != 35:
        raise ReleaseCandidateRolloutError("baseline is not fully complete")

    manifest_sha = str(baseline.get("manifest_sha256", "")).strip()
    if not manifest_sha:
        raise ReleaseCandidateRolloutError("baseline manifest sha256 is missing")

    if manifest_sha != sidecar_text.strip():
        raise ReleaseCandidateRolloutError("baseline sha256 does not match sidecar file")

    return manifest_sha


def _validate_integration_package(package: dict[str, Any], expected_sha: str) -> None:
    if package.get("package_type") != "integration-handover-package":
        raise ReleaseCandidateRolloutError("integration handover package type is invalid")

    baseline = package.get("baseline_manifest", {})
    if baseline.get("sha256") != expected_sha:
        raise ReleaseCandidateRolloutError("integration handover package sha does not match baseline sha")

    if baseline.get("proof_count") != 35:
        raise ReleaseCandidateRolloutError("integration handover package proof_count is invalid")


def _validate_runtime_integration(runtime_payload: dict[str, Any], expected_sha: str) -> None:
    if runtime_payload.get("document_type") != "runtime-control-plane-integration":
        raise ReleaseCandidateRolloutError("runtime control-plane integration type is invalid")

    baseline_binding = runtime_payload.get("baseline_binding", {})
    if baseline_binding.get("manifest_sha256") != expected_sha:
        raise ReleaseCandidateRolloutError("runtime control-plane integration sha does not match baseline sha")

    if baseline_binding.get("proof_count") != 35:
        raise ReleaseCandidateRolloutError("runtime control-plane integration proof_count is invalid")


def _validate_formal_bundle(bundle: dict[str, Any], expected_sha: str, sidecar_text: str) -> None:
    if bundle.get("bundle_type") != "formal-delivery-bundle":
        raise ReleaseCandidateRolloutError("formal delivery bundle type is invalid")

    baseline = bundle.get("baseline", {})
    if baseline.get("manifest_sha256") != expected_sha:
        raise ReleaseCandidateRolloutError("formal delivery bundle sha does not match baseline sha")

    bundle_sha = str(bundle.get("bundle_sha256", "")).strip()
    if not bundle_sha:
        raise ReleaseCandidateRolloutError("formal delivery bundle sha256 is missing")

    if bundle_sha != sidecar_text.strip():
        raise ReleaseCandidateRolloutError("formal delivery bundle sha256 does not match sidecar file")


def _validate_operational_runtime(runtime_payload: dict[str, Any], expected_sha: str) -> None:
    if runtime_payload.get("document_type") != "runtime-operational-integration":
        raise ReleaseCandidateRolloutError("runtime operational integration type is invalid")

    baseline_binding = runtime_payload.get("baseline_binding", {})
    if baseline_binding.get("baseline_sha256") != expected_sha:
        raise ReleaseCandidateRolloutError("runtime operational integration sha does not match baseline sha")

    if baseline_binding.get("proof_count") != 35:
        raise ReleaseCandidateRolloutError("runtime operational integration proof_count is invalid")


def _build_rollout_payload(
    *,
    project_root: Path,
    baseline_sha: str,
) -> dict[str, Any]:
    return {
        "document_type": "release-candidate-rollout",
        "document_version": 1,
        "project_root": str(project_root),
        "rollout_status": "ready-for-release-candidate-rollout",
        "baseline_binding": {
            "proof_range": "R01-R35",
            "proof_count": 35,
            "baseline_sha256": baseline_sha,
        },
        "required_inputs": [
            "proof_registry_baseline_manifest.json",
            "proof_registry_baseline_manifest.sha256",
            "integration_handover_package.json",
            "runtime_control_plane_integration.json",
            "formal_delivery_bundle.json",
            "formal_delivery_bundle.sha256",
            "runtime_operational_integration.json",
            "OPERATIONAL_INTEGRATION_PLAN.md",
            "FINAL_SECURITY_HANDOVER_SUMMARY.md",
            "RC_ROLLOUT_PLAN.md",
            "RUNTIME_ONBOARDING_HANDOFF.md",
        ],
        "rollout_sequence": [
            "verify baseline manifest and sidecar sha256",
            "verify integration handover package binding",
            "verify runtime control-plane integration binding",
            "verify formal delivery bundle and sidecar sha256",
            "verify runtime operational integration binding",
            "review RC rollout plan",
            "review runtime onboarding handoff",
            "authorize runtime onboarding only after all checks pass",
        ],
        "release_gate_contract": {
            "baseline_complete_required": True,
            "baseline_sha_alignment_required": True,
            "handover_package_required": True,
            "runtime_package_required": True,
            "formal_delivery_bundle_required": True,
            "runtime_operational_package_required": True,
            "rollout_and_onboarding_docs_required": True,
            "mismatch_or_missing_artifact_is_fatal": True,
        },
    }


def _build_rollout_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Release Candidate Rollout")
    lines.append("")
    lines.append("## Status")
    lines.append("")
    lines.append(f"- Document Type: `{payload['document_type']}`")
    lines.append(f"- Document Version: `{payload['document_version']}`")
    lines.append(f"- Rollout Status: `{payload['rollout_status']}`")
    lines.append(f"- Proof Range: `{payload['baseline_binding']['proof_range']}`")
    lines.append(f"- Proof Count: `{payload['baseline_binding']['proof_count']}`")
    lines.append(f"- Baseline SHA256: `{payload['baseline_binding']['baseline_sha256']}`")
    lines.append("")
    lines.append("## Required Inputs")
    lines.append("")
    for item in payload["required_inputs"]:
        lines.append(f"- `{item}`")
    lines.append("")
    lines.append("## Rollout Sequence")
    lines.append("")
    for idx, item in enumerate(payload["rollout_sequence"], start=1):
        lines.append(f"{idx}. {item}")
    lines.append("")
    lines.append("## Release Gate Contract")
    lines.append("")
    for key, value in payload["release_gate_contract"].items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")
    return "\n".join(lines) + "\n"


def build_release_candidate_rollout(*, project_root: str | Path) -> dict[str, Any]:
    project_root_path = Path(project_root).resolve()
    paths = ReleaseCandidatePaths(project_root=str(project_root_path))

    _ensure_exists(paths.baseline_manifest_json, "baseline manifest json")
    _ensure_exists(paths.baseline_manifest_sha256, "baseline manifest sha256")
    _ensure_exists(paths.integration_package_json, "integration handover package json")
    _ensure_exists(paths.runtime_integration_json, "runtime control-plane integration json")
    _ensure_exists(paths.formal_delivery_bundle_json, "formal delivery bundle json")
    _ensure_exists(paths.formal_delivery_bundle_sha256, "formal delivery bundle sha256")
    _ensure_exists(paths.runtime_operational_json, "runtime operational integration json")
    _ensure_exists(paths.runtime_operational_md, "runtime operational integration markdown")
    _ensure_exists(paths.operational_plan_md, "operational integration plan markdown")
    _ensure_exists(paths.final_summary_md, "final security handover summary markdown")
    _ensure_exists(paths.rollout_plan_md, "rc rollout plan markdown")
    _ensure_exists(paths.onboarding_handoff_md, "runtime onboarding handoff markdown")

    baseline = _read_json(paths.baseline_manifest_json)
    baseline_sidecar = _read_text(paths.baseline_manifest_sha256)
    baseline_sha = _validate_baseline(baseline, baseline_sidecar)

    integration_package = _read_json(paths.integration_package_json)
    _validate_integration_package(integration_package, baseline_sha)

    runtime_integration = _read_json(paths.runtime_integration_json)
    _validate_runtime_integration(runtime_integration, baseline_sha)

    formal_bundle = _read_json(paths.formal_delivery_bundle_json)
    formal_bundle_sidecar = _read_text(paths.formal_delivery_bundle_sha256)
    _validate_formal_bundle(formal_bundle, baseline_sha, formal_bundle_sidecar)

    runtime_operational = _read_json(paths.runtime_operational_json)
    _validate_operational_runtime(runtime_operational, baseline_sha)

    payload = _build_rollout_payload(
        project_root=project_root_path,
        baseline_sha=baseline_sha,
    )

    paths.rollout_json.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    paths.rollout_md.write_text(
        _build_rollout_markdown(payload),
        encoding="utf-8",
    )

    return {
        "ok": True,
        "rollout_json": str(paths.rollout_json),
        "rollout_md": str(paths.rollout_md),
        "baseline_sha256": baseline_sha,
    }
