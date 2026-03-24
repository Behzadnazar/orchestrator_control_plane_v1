from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from scripts.artifact_paths import BASE_DIR


RELEASES_DIR = BASE_DIR / "artifacts" / "releases"
DEFAULT_VERIFICATION = RELEASES_DIR / "latest_verification.json"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def print_header(title: str) -> None:
    print(f"\n== {title} ==")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a human-readable baseline drift report."
    )
    parser.add_argument(
        "--verification",
        default=str(DEFAULT_VERIFICATION),
        help="Path to baseline_verification.json or latest_verification.json",
    )
    args = parser.parse_args()

    verification_path = Path(args.verification).resolve()

    if not verification_path.exists():
        print(f"[show_baseline_diff] FAIL missing verification: {verification_path}")
        return 2

    payload = load_json(verification_path)

    print(f"verification_path={verification_path}")
    print(f"verification_stage={payload.get('verification_stage')}")
    print(f"verified_at_utc={payload.get('verified_at_utc')}")
    print(f"baseline_path={payload.get('baseline_path')}")
    print(f"release_version={payload.get('release_version')}")
    print(f"release_stage={payload.get('release_stage')}")
    print(f"project_root={payload.get('project_root')}")
    print(f"drift_detected={payload.get('drift_detected')}")
    print(f"drift_count={payload.get('drift_count')}")

    drift_items = payload.get("drift_items", [])

    if not drift_items:
        print_header("drift_summary")
        print("No drift detected. Current tree matches the saved baseline manifest.")
        print("[show_baseline_diff] FINAL_STATUS=PASSED")
        return 0

    grouped: dict[str, list[dict[str, Any]]] = {
        "exists_mismatch": [],
        "size_mismatch": [],
        "sha256_mismatch": [],
        "other": [],
    }

    for item in drift_items:
        reasons = item.get("reasons", [])
        matched = False
        for reason in reasons:
            if reason in grouped:
                grouped[reason].append(item)
                matched = True
        if not matched:
            grouped["other"].append(item)

    print_header("drift_summary")
    print("Drift detected. One or more key files differ from baseline.")

    for bucket_name in ["exists_mismatch", "size_mismatch", "sha256_mismatch", "other"]:
        items = grouped[bucket_name]
        if not items:
            continue

        print_header(bucket_name)
        for item in items:
            print(f"path={item.get('path')}")
            print(f"  reasons={','.join(item.get('reasons', []))}")
            print(f"  expected_exists={item.get('expected_exists')}")
            print(f"  actual_exists={item.get('actual_exists')}")
            print(f"  expected_size_bytes={item.get('expected_size_bytes')}")
            print(f"  actual_size_bytes={item.get('actual_size_bytes')}")
            print(f"  expected_sha256={item.get('expected_sha256')}")
            print(f"  actual_sha256={item.get('actual_sha256')}")

    print("[show_baseline_diff] FINAL_STATUS=DRIFT")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
