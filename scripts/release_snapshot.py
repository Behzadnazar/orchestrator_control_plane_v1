from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.artifact_paths import BASE_DIR, TEST_ARTIFACTS_DIR, ensure_dir


RELEASES_DIR = BASE_DIR / "artifacts" / "releases"
CURRENT_VERSION = "control-plane-v1-baseline"
CURRENT_STAGE = "Phase K.1"


KEY_FILES = [
    "pytest.ini",
    "Makefile",
    "README_TESTS.md",
    "worker_loop_final.py",
    "app/db.py",
    "app/services/control_plane_service.py",
    "scripts/__init__.py",
    "scripts/preflight_check.py",
    "scripts/run_tests.py",
    "scripts/ci_check.py",
    "scripts/artifact_paths.py",
    "scripts/artifact_index.py",
    "scripts/show_artifact_summary.py",
    "tests/test_smoke.py",
    "tests/test_workflow_e2e.py",
    "tests/test_regression_matrix.py",
]


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


def load_index() -> dict[str, Any]:
    index_path = TEST_ARTIFACTS_DIR / "index.json"
    if not index_path.exists():
        raise FileNotFoundError(f"missing artifact index: {index_path}")
    return json.loads(index_path.read_text(encoding="utf-8"))


def collect_key_file_manifest() -> list[dict[str, Any]]:
    manifest: list[dict[str, Any]] = []

    for rel in KEY_FILES:
        path = BASE_DIR / rel
        if not path.exists():
            manifest.append(
                {
                    "path": rel,
                    "exists": False,
                    "size_bytes": None,
                    "sha256": None,
                }
            )
            continue

        manifest.append(
            {
                "path": rel,
                "exists": True,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    return manifest


def build_release_payload() -> dict[str, Any]:
    index = load_index()
    latest = index.get("latest_pointers", {})
    status_summary = index.get("status_summary", {})
    suite_summary = index.get("suite_summary", {})

    return {
        "release_version": CURRENT_VERSION,
        "release_stage": CURRENT_STAGE,
        "generated_at_utc": utc_now_iso(),
        "project_root": str(BASE_DIR),
        "artifact_root": str(TEST_ARTIFACTS_DIR),
        "baseline_status": "green",
        "entry_points": {
            "preflight": "python3 -m scripts.preflight_check",
            "run_all": "python3 -m scripts.run_tests --suite all",
            "run_smoke": "python3 -m scripts.run_tests --suite smoke",
            "run_e2e": "python3 -m scripts.run_tests --suite e2e",
            "run_regression": "python3 -m scripts.run_tests --suite regression",
            "ci_check": "python3 -m scripts.ci_check",
            "show_summary": "python3 -m scripts.show_artifact_summary",
        },
        "make_targets": [
            "make preflight",
            "make test",
            "make test-smoke",
            "make test-e2e",
            "make test-regression",
            "make ci-check",
            "make show-summary",
        ],
        "suite_summary": suite_summary,
        "status_summary": status_summary,
        "latest_pointers": latest,
        "artifact_contract": {
            "per_run_files": [
                "command.txt",
                "preflight.stdout.log",
                "preflight.stderr.log",
                "pytest.stdout.log",
                "pytest.stderr.log",
                "summary.json",
                "junit.xml",
            ],
            "index_file": "artifacts/test_runs/index.json",
            "latest_pointer_dir": "artifacts/test_runs/latest",
            "retention_policy": "retain latest 8 timestamp directories",
        },
        "key_files": collect_key_file_manifest(),
    }


def main() -> int:
    ensure_dir(RELEASES_DIR)

    payload = build_release_payload()

    version_dir = ensure_dir(RELEASES_DIR / CURRENT_VERSION)
    snapshot_path = version_dir / "release_snapshot.json"
    latest_path = RELEASES_DIR / "latest_release.json"

    write_json(snapshot_path, payload)
    write_json(latest_path, payload)

    print(f"[release_snapshot] version={CURRENT_VERSION}")
    print(f"[release_snapshot] snapshot_path={snapshot_path}")
    print(f"[release_snapshot] latest_path={latest_path}")
    print("[release_snapshot] FINAL_STATUS=PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
