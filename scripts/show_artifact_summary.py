from __future__ import annotations

import json

from scripts.artifact_paths import TEST_ARTIFACTS_DIR


def main() -> int:
    index_path = TEST_ARTIFACTS_DIR / "index.json"

    if not index_path.exists():
        print(f"[show_artifact_summary] missing index: {index_path}")
        return 2

    payload = json.loads(index_path.read_text(encoding="utf-8"))

    print(f"artifact_root={payload.get('artifact_root')}")
    print(f"generated_at_utc={payload.get('generated_at_utc')}")
    print(f"retained_timestamp_count={payload.get('retained_timestamp_count')}")
    print(f"run_count={payload.get('run_count')}")

    status_summary = payload.get("status_summary", {})
    print("\n== status_summary ==")
    for key in ["total_runs", "passed_runs", "failed_runs", "preflight_failed_runs"]:
        print(f"{key}={status_summary.get(key)}")

    print("\n== suite_summary ==")
    suite_summary = payload.get("suite_summary", {})
    for suite in sorted(suite_summary.keys()):
        bucket = suite_summary[suite]
        print(f"\n[{suite}]")
        print(f"run_count={bucket.get('run_count')}")
        print(f"passed_count={bucket.get('passed_count')}")
        print(f"failed_count={bucket.get('failed_count')}")
        print(f"preflight_failed_count={bucket.get('preflight_failed_count')}")
        print(f"latest_timestamp={bucket.get('latest_timestamp')}")
        print(f"latest_status={bucket.get('latest_status')}")
        print(f"latest_tests={bucket.get('latest_tests')}")
        print(f"latest_failures={bucket.get('latest_failures')}")
        print(f"latest_errors={bucket.get('latest_errors')}")
        print(f"latest_skipped={bucket.get('latest_skipped')}")
        print(f"total_artifact_files={bucket.get('total_artifact_files')}")
        print(f"total_artifact_size_bytes={bucket.get('total_artifact_size_bytes')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
