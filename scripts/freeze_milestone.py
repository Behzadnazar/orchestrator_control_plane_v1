from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.artifact_paths import BASE_DIR, TEST_ARTIFACTS_DIR, ensure_dir


RELEASES_DIR = BASE_DIR / "artifacts" / "releases"
MILESTONES_DIR = RELEASES_DIR / "milestones"
MILESTONE_TAG = "control-plane-v1-phase-l2-freeze"

LATEST_RELEASE = RELEASES_DIR / "latest_release.json"
LATEST_VERIFICATION = RELEASES_DIR / "latest_verification.json"
INDEX_PATH = TEST_ARTIFACTS_DIR / "index.json"

REQUIRED_SUITES = ["all", "smoke", "e2e", "regression", "ci_check"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def require_file(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing {label}: {path}")


def validate_release(release: dict[str, Any]) -> None:
    if release.get("baseline_status") != "green":
        raise RuntimeError("cannot freeze milestone while baseline_status is not green")


def validate_verification(verification: dict[str, Any]) -> None:
    if verification.get("drift_detected") is not False:
        raise RuntimeError("cannot freeze milestone while drift_detected is not false")
    if verification.get("drift_count") != 0:
        raise RuntimeError("cannot freeze milestone while drift_count is not zero")


def validate_index(index: dict[str, Any]) -> None:
    status_summary = index.get("status_summary", {})
    suite_summary = index.get("suite_summary", {})
    latest_pointers = index.get("latest_pointers", {})

    if status_summary.get("failed_runs") != 0:
        raise RuntimeError("cannot freeze milestone while failed_runs is not zero")

    if status_summary.get("preflight_failed_runs") != 0:
        raise RuntimeError("cannot freeze milestone while preflight_failed_runs is not zero")

    missing_pointers = [suite for suite in REQUIRED_SUITES if suite not in latest_pointers]
    if missing_pointers:
        raise RuntimeError(
            "cannot freeze milestone while required latest pointers are missing: "
            + ", ".join(missing_pointers)
        )

    for suite in REQUIRED_SUITES:
        bucket = suite_summary.get(suite)
        if not bucket:
            raise RuntimeError(f"cannot freeze milestone while suite_summary missing: {suite}")
        if bucket.get("latest_status") != "passed":
            raise RuntimeError(
                f"cannot freeze milestone while latest_status for suite {suite} is not passed"
            )
        if bucket.get("latest_exit_code") != 0:
            raise RuntimeError(
                f"cannot freeze milestone while latest_exit_code for suite {suite} is not zero"
            )


def build_payload() -> dict[str, Any]:
    require_file(LATEST_RELEASE, "latest release snapshot")
    require_file(LATEST_VERIFICATION, "latest verification snapshot")
    require_file(INDEX_PATH, "latest artifact index")

    release = load_json(LATEST_RELEASE)
    verification = load_json(LATEST_VERIFICATION)
    index = load_json(INDEX_PATH)

    validate_release(release)
    validate_verification(verification)
    validate_index(index)

    return {
        "milestone_tag": MILESTONE_TAG,
        "milestone_stage": "Phase L.2",
        "frozen_at_utc": utc_now_iso(),
        "project_root": str(BASE_DIR),
        "freeze_status": "frozen",
        "freeze_gate": {
            "release_snapshot_path": str(LATEST_RELEASE),
            "verification_snapshot_path": str(LATEST_VERIFICATION),
            "artifact_index_path": str(INDEX_PATH),
            "required_suites": REQUIRED_SUITES,
            "baseline_status": release.get("baseline_status"),
            "verification_drift_detected": verification.get("drift_detected"),
            "verification_drift_count": verification.get("drift_count"),
            "failed_runs": index.get("status_summary", {}).get("failed_runs"),
            "preflight_failed_runs": index.get("status_summary", {}).get("preflight_failed_runs"),
        },
        "baseline_release_version": release.get("release_version"),
        "baseline_release_stage": release.get("release_stage"),
        "baseline_status": release.get("baseline_status"),
        "verification_status": "passed",
        "entry_points": release.get("entry_points", {}),
        "make_targets": release.get("make_targets", []),
        "artifact_contract": release.get("artifact_contract", {}),
        "suite_summary": index.get("suite_summary", {}),
        "status_summary": index.get("status_summary", {}),
        "latest_pointers": index.get("latest_pointers", {}),
        "key_file_count": len(release.get("key_files", [])),
    }


def main() -> int:
    ensure_dir(MILESTONES_DIR)

    payload = build_payload()

    milestone_dir = ensure_dir(MILESTONES_DIR / MILESTONE_TAG)
    manifest_path = milestone_dir / "milestone_manifest.json"
    latest_manifest_path = MILESTONES_DIR / "latest_milestone.json"
    latest_pointer_path = MILESTONES_DIR / "latest_milestone.txt"

    write_json(manifest_path, payload)
    write_json(latest_manifest_path, payload)
    write_text(latest_pointer_path, str(manifest_path) + "\n")

    print(f"[freeze_milestone] milestone_tag={MILESTONE_TAG}")
    print(f"[freeze_milestone] manifest_path={manifest_path}")
    print(f"[freeze_milestone] latest_manifest={latest_manifest_path}")
    print(f"[freeze_milestone] latest_pointer={latest_pointer_path}")
    print("[freeze_milestone] FINAL_STATUS=PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
