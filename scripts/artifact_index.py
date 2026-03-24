from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from scripts.artifact_paths import LATEST_POINTERS_DIR, TEST_ARTIFACTS_DIR, ensure_dir


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def load_summary(summary_path: Path) -> dict[str, Any] | None:
    return load_json(summary_path)


def safe_file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def count_files_and_bytes(root: Path) -> tuple[int, int]:
    file_count = 0
    total_size_bytes = 0

    if not root.exists():
        return file_count, total_size_bytes

    for path in root.rglob("*"):
        if path.is_file():
            file_count += 1
            total_size_bytes += safe_file_size(path)

    return file_count, total_size_bytes


def parse_junit_xml(junit_path: Path) -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "junit_present": False,
        "tests": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }

    if not junit_path.exists():
        return metrics

    try:
        tree = ET.parse(junit_path)
        root = tree.getroot()
    except ET.ParseError:
        metrics["junit_present"] = False
        return metrics

    metrics["junit_present"] = True

    if root.tag == "testsuite":
        suites = [root]
    else:
        suites = root.findall(".//testsuite")

    for suite in suites:
        metrics["tests"] += int(suite.attrib.get("tests", "0"))
        metrics["failures"] += int(suite.attrib.get("failures", "0"))
        metrics["errors"] += int(suite.attrib.get("errors", "0"))
        metrics["skipped"] += int(suite.attrib.get("skipped", "0"))

    return metrics


def load_latest_pointers() -> dict[str, str]:
    pointers: dict[str, str] = {}

    if not LATEST_POINTERS_DIR.exists():
        return pointers

    for path in sorted(LATEST_POINTERS_DIR.glob("*.txt")):
        try:
            pointers[path.stem] = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue

    return pointers


def list_timestamp_dirs() -> list[Path]:
    if not TEST_ARTIFACTS_DIR.exists():
        return []

    dirs: list[Path] = []
    for child in TEST_ARTIFACTS_DIR.iterdir():
        if not child.is_dir():
            continue
        if child.name == "latest":
            continue
        dirs.append(child)

    return sorted(dirs, key=lambda p: p.name)


def build_run_entry(
    ts_dir: Path,
    suite_dir: Path,
    latest_pointers: dict[str, str],
) -> dict[str, Any]:
    summary_path = suite_dir / "summary.json"
    junit_path = suite_dir / "junit.xml"
    command_path = suite_dir / "command.txt"

    summary = load_summary(summary_path) or {}
    junit_metrics = parse_junit_xml(junit_path)
    file_count, total_size_bytes = count_files_and_bytes(suite_dir)

    suite_name = suite_dir.name
    run_dir_str = str(suite_dir)

    return {
        "timestamp": ts_dir.name,
        "suite": suite_name,
        "run_dir": run_dir_str,
        "summary_path": str(summary_path),
        "status": summary.get("status"),
        "exit_code": summary.get("exit_code"),
        "started_at_utc": summary.get("started_at_utc"),
        "finished_at_utc": summary.get("finished_at_utc"),
        "duration_seconds": summary.get("duration_seconds"),
        "command": summary.get("command"),
        "command_path": str(command_path) if command_path.exists() else None,
        "file_count": file_count,
        "total_size_bytes": total_size_bytes,
        "is_latest": latest_pointers.get(suite_name) == run_dir_str,
        "junit": junit_metrics,
    }


def build_suite_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    suite_summary: dict[str, Any] = {}

    for run in runs:
        suite = run["suite"]

        bucket = suite_summary.setdefault(
            suite,
            {
                "run_count": 0,
                "passed_count": 0,
                "failed_count": 0,
                "preflight_failed_count": 0,
                "latest_timestamp": None,
                "latest_run_dir": None,
                "latest_status": None,
                "latest_exit_code": None,
                "latest_duration_seconds": None,
                "latest_tests": 0,
                "latest_failures": 0,
                "latest_errors": 0,
                "latest_skipped": 0,
                "total_artifact_files": 0,
                "total_artifact_size_bytes": 0,
            },
        )

        bucket["run_count"] += 1
        bucket["total_artifact_files"] += int(run.get("file_count") or 0)
        bucket["total_artifact_size_bytes"] += int(run.get("total_size_bytes") or 0)

        status = run.get("status")
        if status == "passed":
            bucket["passed_count"] += 1
        elif status == "preflight_failed":
            bucket["preflight_failed_count"] += 1
        else:
            bucket["failed_count"] += 1

        latest_timestamp = bucket["latest_timestamp"]
        if latest_timestamp is None or run["timestamp"] >= latest_timestamp:
            bucket["latest_timestamp"] = run["timestamp"]
            bucket["latest_run_dir"] = run["run_dir"]
            bucket["latest_status"] = run.get("status")
            bucket["latest_exit_code"] = run.get("exit_code")
            bucket["latest_duration_seconds"] = run.get("duration_seconds")
            junit = run.get("junit") or {}
            bucket["latest_tests"] = junit.get("tests", 0)
            bucket["latest_failures"] = junit.get("failures", 0)
            bucket["latest_errors"] = junit.get("errors", 0)
            bucket["latest_skipped"] = junit.get("skipped", 0)

    return suite_summary


def build_status_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    summary = {
        "total_runs": len(runs),
        "passed_runs": 0,
        "failed_runs": 0,
        "preflight_failed_runs": 0,
    }

    for run in runs:
        status = run.get("status")
        if status == "passed":
            summary["passed_runs"] += 1
        elif status == "preflight_failed":
            summary["preflight_failed_runs"] += 1
        else:
            summary["failed_runs"] += 1

    return summary


def build_index_payload() -> dict[str, Any]:
    latest_pointers = load_latest_pointers()
    timestamp_dirs = list_timestamp_dirs()

    runs: list[dict[str, Any]] = []
    for ts_dir in timestamp_dirs:
        suite_dirs = sorted([p for p in ts_dir.iterdir() if p.is_dir()], key=lambda p: p.name)
        for suite_dir in suite_dirs:
            runs.append(build_run_entry(ts_dir, suite_dir, latest_pointers))

    return {
        "artifact_root": str(TEST_ARTIFACTS_DIR),
        "generated_at_utc": utc_now_iso(),
        "retained_timestamp_count": len(timestamp_dirs),
        "retained_timestamps": [p.name for p in timestamp_dirs],
        "latest_pointers": latest_pointers,
        "status_summary": build_status_summary(runs),
        "suite_summary": build_suite_summary(runs),
        "run_count": len(runs),
        "runs": runs,
    }


def write_index() -> Path:
    ensure_dir(TEST_ARTIFACTS_DIR)
    payload = build_index_payload()
    index_path = TEST_ARTIFACTS_DIR / "index.json"
    write_json(index_path, payload)
    return index_path


def write_latest_pointer(suite: str, run_dir: Path) -> Path:
    ensure_dir(LATEST_POINTERS_DIR)
    pointer_path = LATEST_POINTERS_DIR / f"{suite}.txt"
    write_text(pointer_path, str(run_dir) + "\n")
    return pointer_path


def prune_old_timestamp_dirs(keep: int) -> list[str]:
    if keep < 1:
        raise ValueError("keep must be >= 1")

    timestamp_dirs = list_timestamp_dirs()
    if len(timestamp_dirs) <= keep:
        return []

    to_delete = timestamp_dirs[:-keep]
    deleted: list[str] = []

    for path in to_delete:
        shutil.rmtree(path)
        deleted.append(path.name)

    return deleted


def register_run_and_refresh(
    *,
    suite: str,
    run_dir: Path,
    retention_count: int,
) -> dict[str, Any]:
    pointer_path = write_latest_pointer(suite, run_dir)
    deleted = prune_old_timestamp_dirs(retention_count)
    index_path = write_index()

    return {
        "suite": suite,
        "run_dir": str(run_dir),
        "latest_pointer": str(pointer_path),
        "deleted_timestamps": deleted,
        "index_path": str(index_path),
    }
