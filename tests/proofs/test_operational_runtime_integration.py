from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.security.operational_runtime_integration import (
    OperationalRuntimeIntegrationError,
    build_operational_runtime_integration,
)


def _write_valid_inputs(tmp_path: Path) -> None:
    handover_dir = tmp_path / "artifacts" / "handover"
    handover_dir.mkdir(parents=True, exist_ok=True)

    (tmp_path / "app" / "security").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tests" / "proofs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scripts").mkdir(parents=True, exist_ok=True)

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
        "manifest_sha256": "1" * 64,
    }

    integration_package = {
        "package_type": "integration-handover-package",
        "package_version": 1,
        "baseline_manifest": {
            "path": "artifacts/handover/proof_registry_baseline_manifest.json",
            "sha256": "1" * 64,
            "proof_range": "R01-R35",
            "proof_count": 35,
        },
    }

    runtime_package = {
        "document_type": "runtime-control-plane-integration",
        "document_version": 1,
        "baseline_binding": {
            "manifest_path": "artifacts/handover/proof_registry_baseline_manifest.json",
            "manifest_sha256": "1" * 64,
            "integration_package_path": "artifacts/handover/integration_handover_package.json",
            "proof_count": 35,
        },
    }

    formal_bundle = {
        "bundle_type": "formal-delivery-bundle",
        "bundle_version": 1,
        "bundle_scope": {
            "status": "ready-for-formal-delivery",
            "proof_range": "R01-R35",
            "proof_count": 35,
        },
        "baseline": {
            "manifest_path": "artifacts/handover/proof_registry_baseline_manifest.json",
            "manifest_sha256_path": "artifacts/handover/proof_registry_baseline_manifest.sha256",
            "manifest_sha256": "1" * 64,
        },
    }

    (handover_dir / "proof_registry_baseline_manifest.json").write_text(
        json.dumps(baseline, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "proof_registry_baseline_manifest.sha256").write_text(
        "1" * 64 + "\n",
        encoding="utf-8",
    )
    (handover_dir / "integration_handover_package.json").write_text(
        json.dumps(integration_package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "runtime_control_plane_integration.json").write_text(
        json.dumps(runtime_package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "formal_delivery_bundle.json").write_text(
        json.dumps(formal_bundle, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "formal_delivery_bundle.sha256").write_text(
        "2" * 64 + "\n",
        encoding="utf-8",
    )
    (handover_dir / "OPERATIONAL_INTEGRATION_PLAN.md").write_text("# plan\n", encoding="utf-8")
    (handover_dir / "FINAL_SECURITY_HANDOVER_SUMMARY.md").write_text("# summary\n", encoding="utf-8")


def test_operational_runtime_integration_builds_from_valid_inputs(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    result = build_operational_runtime_integration(project_root=tmp_path)

    assert result["ok"] is True
    assert Path(result["runtime_operational_json"]).exists() is True
    assert Path(result["runtime_operational_md"]).exists() is True
    assert result["baseline_sha256"] == "1" * 64


def test_operational_runtime_integration_fails_when_formal_bundle_sha_mismatches(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    bundle_path = tmp_path / "artifacts" / "handover" / "formal_delivery_bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["baseline"]["manifest_sha256"] = "9" * 64
    bundle_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    with pytest.raises(
        OperationalRuntimeIntegrationError,
        match="formal delivery bundle sha does not match baseline sha",
    ):
        build_operational_runtime_integration(project_root=tmp_path)


def test_operational_runtime_integration_fails_when_app_security_missing(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    app_security_dir = tmp_path / "app" / "security"
    app_security_dir.rmdir()
    (tmp_path / "app").rmdir()

    with pytest.raises(
        OperationalRuntimeIntegrationError,
        match="required app/security directory not found",
    ):
        build_operational_runtime_integration(project_root=tmp_path)
