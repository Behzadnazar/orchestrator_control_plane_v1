from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.security.integration_handover_package import (
    IntegrationHandoverPackageError,
    build_integration_handover_package,
)


def _write_valid_baseline(tmp_path: Path) -> None:
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
        "manifest_sha256": "a" * 64,
    }

    (handover_dir / "proof_registry_baseline_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (handover_dir / "proof_registry_baseline_manifest.sha256").write_text(
        "a" * 64 + "\n",
        encoding="utf-8",
    )


def test_integration_handover_package_builds_from_valid_baseline(tmp_path: Path) -> None:
    _write_valid_baseline(tmp_path)

    result = build_integration_handover_package(project_root=tmp_path)

    assert result["ok"] is True
    assert Path(result["integration_package_json"]).exists() is True
    assert Path(result["integration_package_md"]).exists() is True
    assert result["proof_count"] == 35


def test_integration_handover_package_fails_when_sha_sidecar_mismatches(tmp_path: Path) -> None:
    _write_valid_baseline(tmp_path)
    sha_path = tmp_path / "artifacts" / "handover" / "proof_registry_baseline_manifest.sha256"
    sha_path.write_text("b" * 64 + "\n", encoding="utf-8")

    with pytest.raises(
        IntegrationHandoverPackageError,
        match="baseline manifest sha256 does not match .sha256 sidecar file",
    ):
        build_integration_handover_package(project_root=tmp_path)


def test_integration_handover_package_fails_when_baseline_manifest_missing(tmp_path: Path) -> None:
    with pytest.raises(
        IntegrationHandoverPackageError,
        match="required baseline manifest json file not found",
    ):
        build_integration_handover_package(project_root=tmp_path)
