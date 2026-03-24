from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
TEST_ARTIFACTS_DIR = BASE_DIR / "artifacts" / "test_runs"
LATEST_POINTERS_DIR = TEST_ARTIFACTS_DIR / "latest"


def utc_run_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_run_dir(suite: str) -> Path:
    return ensure_dir(TEST_ARTIFACTS_DIR / utc_run_stamp() / suite)
