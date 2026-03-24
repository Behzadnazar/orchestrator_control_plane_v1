from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.security.release_candidate_rollout import (
    ReleaseCandidateRolloutError,
    build_release_candidate_rollout,
)


def _write_valid_inputs(tmp_path: Path) -> None:
    handover_dir = tmp_path / "artifacts" / "handover"
    handover_dir.mkdir(parents=True, exist_ok=True)

    baseline = {
        "manifest_type": "proof-registry-baseline",
        "manifest_version": 1,
        "proof_range": "R01-R35",
        "project_root": str(tmp_path),
        "summary": {
            "expected_total": 35,
            "actual_total": 35,
            "status_counts": {
                "complete": 35,
                "gap": 0,
                "missing": 0,
                "pending": 0,
            },
        },
        "proofs": [{"proof_id": f"R{i:02d}"} for i in range(1, 36)],
        "manifest_sha256": "7" * 64,
    }

    integration_package = {
        "package_type": "integration-handover-package",
        "baseline_manifest": {
            "sha256": "7" * 64,
            "proof_range": "R01-R35",
            "proof_count": 35,
        },
    }

    runtime_integration = {
        "document_type": "runtime-control-plane-integration",
        "baseline_binding": {
            "manifest_sha256": "7" * 64,
            "proof_count": 35,
        },
    }

    formal_bundle = {
        "bundle_type": "formal-delivery-bundle",
        "bundle_scope": {
            "proof_count": 35,
        },
        "baseline": {
            "manifest_sha256": "7" * 64,
        },
        "bundle_sha256": "8" * 64,
    }

    runtime_operational = {
        "document_type": "runtime-operational-integration",
        "baseline_binding": {
            "baseline_sha256": "7" * 64,
            "proof_count": 35,
        },
    }

    (handover_dir / "proof_registry_baseline_manifest.json").write_text(
        json.dumps(baseline, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "proof_registry_baseline_manifest.sha256").write_text(
        "7" * 64 + "\n",
        encoding="utf-8",
    )
    (handover_dir / "integration_handover_package.json").write_text(
        json.dumps(integration_package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "runtime_control_plane_integration.json").write_text(
        json.dumps(runtime_integration, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "formal_delivery_bundle.json").write_text(
        json.dumps(formal_bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "formal_delivery_bundle.sha256").write_text(
        "8" * 64 + "\n",
        encoding="utf-8",
    )
    (handover_dir / "runtime_operational_integration.json").write_text(
        json.dumps(runtime_operational, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "RUNTIME_OPERATIONAL_INTEGRATION.md").write_text("# runtime operational\n", encoding="utf-8")
    (handover_dir / "OPERATIONAL_INTEGRATION_PLAN.md").write_text("# plan\n", encoding="utf-8")
    (handover_dir / "FINAL_SECURITY_HANDOVER_SUMMARY.md").write_text("# summary\n", encoding="utf-8")
    (handover_dir / "RC_ROLLOUT_PLAN.md").write_text("# rollout\n", encoding="utf-8")
    (handover_dir / "RUNTIME_ONBOARDING_HANDOFF.md").write_text("# onboarding\n", encoding="utf-8")


def test_release_candidate_rollout_builds_from_valid_inputs(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    result = build_release_candidate_rollout(project_root=tmp_path)

    assert result["ok"] is True
    assert Path(result["rollout_json"]).exists() is True
    assert Path(result["rollout_md"]).exists() is True
    assert result["baseline_sha256"] == "7" * 64


def test_release_candidate_rollout_fails_when_runtime_operational_sha_mismatches(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    path = tmp_path / "artifacts" / "handover" / "runtime_operational_integration.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["baseline_binding"]["baseline_sha256"] = "0" * 64
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    with pytest.raises(
        ReleaseCandidateRolloutError,
        match="runtime operational integration sha does not match baseline sha",
    ):
        build_release_candidate_rollout(project_root=tmp_path)


def test_release_candidate_rollout_fails_when_rollout_plan_missing(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    path = tmp_path / "artifacts" / "handover" / "RC_ROLLOUT_PLAN.md"
    path.unlink()

    with pytest.raises(
        ReleaseCandidateRolloutError,
        match="required rc rollout plan markdown not found",
    ):
        build_release_candidate_rollout(project_root=tmp_path)
