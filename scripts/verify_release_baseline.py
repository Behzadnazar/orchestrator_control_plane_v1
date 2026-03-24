from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.artifact_paths import BASE_DIR, ensure_dir


RELEASES_DIR = BASE_DIR / "artifacts" / "releases"
DEFAULT_BASELINE = RELEASES_DIR / "control-plane-v1-baseline" / "release_snapshot.json"
LATEST_VERIFICATION = RELEASES_DIR / "latest_verification.json"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def verify_key_files(project_root: Path, baseline_key_files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    drift_items: list[dict[str, Any]] = []

    for item in baseline_key_files:
        rel_path = item["path"]
        expected_exists = item["exists"]
        expected_size = item["size_bytes"]
        expected_sha = item["sha256"]

        path = project_root / rel_path
        actual_exists = path.exists()

        actual_size = path.stat().st_size if actual_exists else None
        actual_sha = sha256_file(path) if actual_exists else None

        status = "match"
        reasons: list[str] = []

        if actual_exists != expected_exists:
            status = "drift"
            reasons.append("exists_mismatch")

        if actual_exists and expected_exists:
            if actual_size != expected_size:
                status = "drift"
                reasons.append("size_mismatch")
            if actual_sha != expected_sha:
                status = "drift"
                reasons.append("sha256_mismatch")

        if status == "drift":
            drift_items.append(
                {
                    "path": rel_path,
                    "expected_exists": expected_exists,
                    "actual_exists": actual_exists,
                    "expected_size_bytes": expected_size,
                    "actual_size_bytes": actual_size,
                    "expected_sha256": expected_sha,
                    "actual_sha256": actual_sha,
                    "reasons": reasons,
                }
            )

    return drift_items


def build_reason_summary(drift_items: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "exists_mismatch": 0,
        "size_mismatch": 0,
        "sha256_mismatch": 0,
        "other": 0,
    }

    for item in drift_items:
        reasons = item.get("reasons", [])
        matched = False
        for reason in reasons:
            if reason in summary:
                summary[reason] += 1
                matched = True
        if not matched:
            summary["other"] += 1

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify current project files against a release baseline snapshot."
    )
    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE),
        help="Path to baseline release_snapshot.json",
    )
    args = parser.parse_args()

    baseline_path = Path(args.baseline).resolve()

    if not baseline_path.exists():
        print(f"[verify_release_baseline] FAIL missing baseline: {baseline_path}")
        return 2

    ensure_dir(RELEASES_DIR)

    baseline = load_json(baseline_path)
    project_root = Path(baseline["project_root"])
    baseline_key_files = baseline.get("key_files", [])

    drift_items = verify_key_files(project_root, baseline_key_files)
    reason_summary = build_reason_summary(drift_items)

    payload = {
        "verification_stage": "Phase K.2",
        "verified_at_utc": utc_now_iso(),
        "baseline_path": str(baseline_path),
        "release_version": baseline.get("release_version"),
        "release_stage": baseline.get("release_stage"),
        "project_root": str(project_root),
        "drift_detected": len(drift_items) > 0,
        "drift_count": len(drift_items),
        "reason_summary": reason_summary,
        "drift_items": drift_items,
    }

    version = baseline.get("release_version", "unknown-baseline")
    version_dir = ensure_dir(RELEASES_DIR / version)
    verification_path = version_dir / "baseline_verification.json"

    write_json(verification_path, payload)
    write_json(LATEST_VERIFICATION, payload)

    print(f"[verify_release_baseline] baseline={baseline_path}")
    print(f"[verify_release_baseline] verification_path={verification_path}")
    print(f"[verify_release_baseline] latest_verification={LATEST_VERIFICATION}")
    print(
        "[verify_release_baseline] reason_summary="
        f"exists={reason_summary['exists_mismatch']},"
        f"size={reason_summary['size_mismatch']},"
        f"sha256={reason_summary['sha256_mismatch']},"
        f"other={reason_summary['other']}"
    )

    if drift_items:
        print(f"[verify_release_baseline] FINAL_STATUS=DRIFT drift_count={len(drift_items)}")
        return 1

    print("[verify_release_baseline] FINAL_STATUS=PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
