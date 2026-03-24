from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.security.formal_delivery_bundle import (
    FormalDeliveryBundleError,
    build_formal_delivery_bundle,
)


def _write_valid_inputs(tmp_path: Path) -> None:
    handover_dir = tmp_path / "artifacts" / "handover"
    handover_dir.mkdir(parents=True, exist_ok=True)

    baseline_manifest = {
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
        "manifest_sha256": "e" * 64,
    }

    integration_package = {
        "package_type": "integration-handover-package",
        "package_version": 1,
        "baseline_manifest": {
            "path": "artifacts/handover/proof_registry_baseline_manifest.json",
            "sha256": "e" * 64,
            "proof_range": "R01-R35",
            "proof_count": 35,
        },
    }

    runtime_package = {
        "document_type": "runtime-control-plane-integration",
        "document_version": 1,
        "baseline_binding": {
            "manifest_path": "artifacts/handover/proof_registry_baseline_manifest.json",
            "manifest_sha256": "e" * 64,
            "integration_package_path": "artifacts/handover/integration_handover_package.json",
            "proof_count": 35,
        },
    }

    (handover_dir / "proof_registry_baseline_manifest.json").write_text(
        json.dumps(baseline_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "proof_registry_baseline_manifest.sha256").write_text(
        "e" * 64 + "\n",
        encoding="utf-8",
    )
    (handover_dir / "integration_handover_package.json").write_text(
        json.dumps(integration_package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "INTEGRATION_HANDOVER_PACKAGE.md").write_text(
        "# integration handover package\n",
        encoding="utf-8",
    )
    (handover_dir / "runtime_control_plane_integration.json").write_text(
        json.dumps(runtime_package, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "RUNTIME_CONTROL_PLANE_INTEGRATION.md").write_text(
        "# runtime integration\n",
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


def test_formal_delivery_bundle_builds_from_valid_inputs(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    result = build_formal_delivery_bundle(project_root=tmp_path)

    assert result["ok"] is True
    assert Path(result["delivery_bundle_json"]).exists() is True
    assert Path(result["delivery_bundle_md"]).exists() is True
    assert Path(result["delivery_bundle_sha256"]).exists() is True
    assert len(result["bundle_sha256"]) == 64


def test_formal_delivery_bundle_fails_when_runtime_sha_mismatches_baseline(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    runtime_path = tmp_path / "artifacts" / "handover" / "runtime_control_plane_integration.json"
    runtime_payload = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime_payload["baseline_binding"]["manifest_sha256"] = "f" * 64
    runtime_path.write_text(
        json.dumps(runtime_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        FormalDeliveryBundleError,
        match="runtime integration baseline sha does not match baseline manifest sha",
    ):
        build_formal_delivery_bundle(project_root=tmp_path)


def test_formal_delivery_bundle_fails_when_final_summary_missing(tmp_path: Path) -> None:
    _write_valid_inputs(tmp_path)

    summary_path = tmp_path / "artifacts" / "handover" / "FINAL_SECURITY_HANDOVER_SUMMARY.md"
    summary_path.unlink()

    with pytest.raises(
        FormalDeliveryBundleError,
        match="required final security summary markdown file not found",
    ):
        build_formal_delivery_bundle(project_root=tmp_path)
