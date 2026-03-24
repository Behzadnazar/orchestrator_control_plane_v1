from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.security.runtime_control_plane_integration import (
    RuntimeControlPlaneIntegrationError,
    build_runtime_control_plane_integration,
)


def _write_valid_inputs(tmp_path: Path) -> None:
    handover_dir = tmp_path / "artifacts" / "handover"
    handover_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
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
        "proofs": [
            {
                "proof_id": f"R{i:02d}",
                "title": f"Proof R{i:02d}",
                "status": "complete",
                "summary": f"Summary R{i:02d}",
                "notes": "",
                "evidence": [],
            }
            for i in range(1, 36)
        ],
        "manifest_sha256": "c" * 64,
    }

    package = {
        "package_type": "integration-handover-package",
        "package_version": 1,
        "baseline_manifest": {
            "path": "artifacts/handover/proof_registry_baseline_manifest.json",
            "sha256": "c" * 64,
            "proof_range": "R01-R35",
            "proof_count": 35,
        },
    }

    (handover_dir / "proof_registry_baseline_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "proof_registry_baseline_manifest.sha256").write_text(
        "c" * 64 + "\n",
        encoding="utf-8",
    )
    (handover_dir / "integration_handover_package.json").write_text(
        json.dumps(package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "OPERATIONAL_INTEGRATION_PLAN.md").write_text(
        "# plan\n",
        encoding="utf-8",
    )
    (handover_dir / "FINAL_SECURITY_HANDOVER_SUMMARY.md").write_text(
        "# summary\n",
        encoding="utf-8",
    )


def test_runtime_control_plane_integration_builds_from_valid_inputs(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    result = build_runtime_control_plane_integration(project_root=tmp_path)

    assert result["ok"] is True
    assert Path(result["runtime_integration_json"]).exists() is True
    assert Path(result["runtime_integration_md"]).exists() is True


def test_runtime_control_plane_integration_fails_when_package_sha_mismatches(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    package_path = tmp_path / "artifacts" / "handover" / "integration_handover_package.json"
    package = json.loads(package_path.read_text(encoding="utf-8"))
    package["baseline_manifest"]["sha256"] = "d" * 64
    package_path.write_text(json.dumps(package, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    with pytest.raises(
        RuntimeControlPlaneIntegrationError,
        match="integration handover package does not reference the current baseline sha256",
    ):
        build_runtime_control_plane_integration(project_root=tmp_path)


def test_runtime_control_plane_integration_fails_when_operational_plan_missing(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    plan_path = tmp_path / "artifacts" / "handover" / "OPERATIONAL_INTEGRATION_PLAN.md"
    plan_path.unlink()

    with pytest.raises(
        RuntimeControlPlaneIntegrationError,
        match="required operational integration plan file not found",
    ):
        build_runtime_control_plane_integration(project_root=tmp_path)

