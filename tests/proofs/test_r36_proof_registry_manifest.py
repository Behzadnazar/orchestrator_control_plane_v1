from __future__ import annotations

from pathlib import Path

import pytest

from app.security.proof_registry_manifest import (
    OFFICIAL_PROOF_REGISTRY,
    ProofRegistryEntry,
    ProofRegistryManifestError,
    build_manifest_payload,
    validate_registry,
    write_manifest_files,
)


def _make_complete_registry(tmp_path: Path) -> list[ProofRegistryEntry]:
    registry: list[ProofRegistryEntry] = []
    for i in range(1, 36):
        proof_id = f"R{i:02d}"
        relative_path = f"evidence/{proof_id}.txt"
        absolute_path = tmp_path / relative_path
        absolute_path.parent.mkdir(parents=True, exist_ok=True)
        absolute_path.write_text(f"official evidence for {proof_id}\n", encoding="utf-8")

        registry.append(
            ProofRegistryEntry(
                proof_id=proof_id,
                title=f"{proof_id} synthetic complete proof",
                status="complete",
                summary=f"{proof_id} synthetic complete proof summary",
                evidence_paths=(relative_path,),
                notes="synthetic registry for passing manifest generation test",
            )
        )
    return registry


def _make_incomplete_registry(tmp_path: Path) -> list[ProofRegistryEntry]:
    registry = _make_complete_registry(tmp_path)
    broken = list(registry)
    broken[0] = ProofRegistryEntry(
        proof_id="R01",
        title="R01 pending synthetic proof",
        status="pending",
        summary="pending synthetic proof should block manifest generation",
        evidence_paths=(),
        notes="intentional pending failure case",
    )
    return broken


def test_r36_official_registry_now_passes_after_r01_r20_backfill() -> None:
    project_root = Path(__file__).resolve().parents[2]

    validation = validate_registry(
        project_root=project_root,
        registry=OFFICIAL_PROOF_REGISTRY,
    )

    assert validation["ok"] is True
    assert validation["summary"]["expected_total"] == 35
    assert validation["summary"]["actual_total"] == 35
    assert validation["summary"]["status_counts"]["complete"] == 35

    manifest = build_manifest_payload(
        project_root=project_root,
        registry=OFFICIAL_PROOF_REGISTRY,
    )

    assert manifest["manifest_type"] == "proof-registry-baseline"
    assert manifest["proof_range"] == "R01-R35"
    assert manifest["summary"]["status_counts"]["complete"] == 35
    assert len(manifest["proofs"]) == 35
    assert len(manifest["manifest_sha256"]) == 64


def test_r36_manifest_passes_and_writes_hash_when_registry_is_complete(
    tmp_path: Path,
) -> None:
    registry = _make_complete_registry(tmp_path)
    output_json = tmp_path / "handover" / "proof_registry_baseline_manifest.json"
    output_sha256 = tmp_path / "handover" / "proof_registry_baseline_manifest.sha256"

    result = write_manifest_files(
        project_root=tmp_path,
        output_json_path=output_json,
        output_sha256_path=output_sha256,
        registry=registry,
    )

    assert result["ok"] is True
    assert output_json.exists() is True
    assert output_sha256.exists() is True

    manifest = output_json.read_text(encoding="utf-8")
    digest = output_sha256.read_text(encoding="utf-8").strip()

    assert '"manifest_type": "proof-registry-baseline"' in manifest
    assert '"proof_range": "R01-R35"' in manifest
    assert len(digest) == 64


def test_r36_manifest_fails_if_complete_entry_points_to_missing_evidence(
    tmp_path: Path,
) -> None:
    registry = _make_complete_registry(tmp_path)
    broken = list(registry)
    broken[0] = ProofRegistryEntry(
        proof_id="R01",
        title="R01 broken evidence entry",
        status="complete",
        summary="broken complete entry should fail because evidence file is missing",
        evidence_paths=("evidence/DOES_NOT_EXIST.txt",),
        notes="intentional failure case",
    )

    with pytest.raises(ProofRegistryManifestError):
        build_manifest_payload(
            project_root=tmp_path,
            registry=broken,
        )


def test_r36_manifest_fails_if_registry_has_pending_or_missing_slot(
    tmp_path: Path,
) -> None:
    pending_registry = _make_incomplete_registry(tmp_path)

    with pytest.raises(ProofRegistryManifestError):
        build_manifest_payload(
            project_root=tmp_path,
            registry=pending_registry,
        )

    complete_registry = _make_complete_registry(tmp_path)
    truncated = complete_registry[:-1]

    with pytest.raises(ProofRegistryManifestError):
        build_manifest_payload(
            project_root=tmp_path,
            registry=truncated,
        )
