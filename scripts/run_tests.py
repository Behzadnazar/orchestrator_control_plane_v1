from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from scripts.artifact_index import parse_junit_xml, register_run_and_refresh
from scripts.artifact_paths import BASE_DIR, build_run_dir, ensure_dir


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run_preflight(run_dir: Path) -> int:
    cmd = [sys.executable, "-m", "scripts.preflight_check"]
    result = subprocess.run(
        cmd,
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        check=False,
    )

    write_text(run_dir / "preflight.stdout.log", result.stdout or "")
    write_text(run_dir / "preflight.stderr.log", result.stderr or "")

    if result.stdout:
        print("===== PREFLIGHT STDOUT =====")
        print(result.stdout.rstrip())

    if result.stderr:
        print("===== PREFLIGHT STDERR =====")
        print(result.stderr.rstrip())

    if result.returncode != 0:
        print(f"[run_tests] PREFLIGHT_FAILED exit_code={result.returncode}")
        return result.returncode

    print("[run_tests] PREFLIGHT_PASSED")
    return 0


def build_pytest_command(suite: str, junit_xml: Path) -> list[str]:
    cmd = [sys.executable, "-m", "pytest", "--junit-xml", str(junit_xml)]

    if suite == "all":
        cmd.extend(["-q"])
    elif suite == "smoke":
        cmd.extend(["-q", "-m", "smoke"])
    elif suite == "e2e":
        cmd.extend(["-q", "-m", "e2e"])
    elif suite == "regression":
        cmd.extend(["-q", "-m", "regression"])
    else:
        raise ValueError(f"unsupported suite: {suite}")

    return cmd


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run control-plane test suites with stable entry points."
    )
    parser.add_argument(
        "--suite",
        choices=["all", "smoke", "e2e", "regression"],
        default="all",
        help="Select which test suite to run.",
    )
    parser.add_argument(
        "--retention-count",
        type=int,
        default=8,
        help="How many timestamp run directories to retain under artifacts/test_runs.",
    )
    args = parser.parse_args()

    started_at_utc = utc_now_iso()
    monotonic_start = time.monotonic()

    run_dir = ensure_dir(build_run_dir(args.suite))
    junit_xml = run_dir / "junit.xml"

    preflight_exit = run_preflight(run_dir)
    if preflight_exit != 0:
        finished_at_utc = utc_now_iso()
        duration_seconds = round(time.monotonic() - monotonic_start, 3)

        write_json(
            run_dir / "summary.json",
            {
                "suite": args.suite,
                "status": "preflight_failed",
                "exit_code": preflight_exit,
                "started_at_utc": started_at_utc,
                "finished_at_utc": finished_at_utc,
                "duration_seconds": duration_seconds,
                "run_dir": str(run_dir),
                "command": None,
                "junit_xml": None,
                "tests": 0,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "stdout_log": str(run_dir / "pytest.stdout.log"),
                "stderr_log": str(run_dir / "pytest.stderr.log"),
                "preflight_stdout_log": str(run_dir / "preflight.stdout.log"),
                "preflight_stderr_log": str(run_dir / "preflight.stderr.log"),
            },
        )
        refresh = register_run_and_refresh(
            suite=args.suite,
            run_dir=run_dir,
            retention_count=args.retention_count,
        )
        print(f"[run_tests] latest_pointer={refresh['latest_pointer']}")
        print(f"[run_tests] index_path={refresh['index_path']}")
        if refresh["deleted_timestamps"]:
            print(f"[run_tests] pruned={','.join(refresh['deleted_timestamps'])}")
        return preflight_exit

    cmd = build_pytest_command(args.suite, junit_xml)

    write_text(run_dir / "command.txt", " ".join(cmd) + "\n")

    print(f"[run_tests] suite={args.suite}")
    print(f"[run_tests] cwd={BASE_DIR}")
    print(f"[run_tests] run_dir={run_dir}")
    print(f"[run_tests] command={' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        check=False,
    )

    write_text(run_dir / "pytest.stdout.log", result.stdout or "")
    write_text(run_dir / "pytest.stderr.log", result.stderr or "")

    if result.stdout:
        print("===== PYTEST STDOUT =====")
        print(result.stdout.rstrip())

    if result.stderr:
        print("===== PYTEST STDERR =====")
        print(result.stderr.rstrip())

    status = "passed" if result.returncode == 0 else "failed"
    finished_at_utc = utc_now_iso()
    duration_seconds = round(time.monotonic() - monotonic_start, 3)
    junit_metrics = parse_junit_xml(junit_xml)

    write_json(
        run_dir / "summary.json",
        {
            "suite": args.suite,
            "status": status,
            "exit_code": result.returncode,
            "started_at_utc": started_at_utc,
            "finished_at_utc": finished_at_utc,
            "duration_seconds": duration_seconds,
            "run_dir": str(run_dir),
            "command": " ".join(cmd),
            "junit_xml": str(junit_xml),
            "tests": junit_metrics["tests"],
            "failures": junit_metrics["failures"],
            "errors": junit_metrics["errors"],
            "skipped": junit_metrics["skipped"],
            "stdout_log": str(run_dir / "pytest.stdout.log"),
            "stderr_log": str(run_dir / "pytest.stderr.log"),
            "preflight_stdout_log": str(run_dir / "preflight.stdout.log"),
            "preflight_stderr_log": str(run_dir / "preflight.stderr.log"),
        },
    )

    refresh = register_run_and_refresh(
        suite=args.suite,
        run_dir=run_dir,
        retention_count=args.retention_count,
    )

    print(f"[run_tests] latest_pointer={refresh['latest_pointer']}")
    print(f"[run_tests] index_path={refresh['index_path']}")
    if refresh["deleted_timestamps"]:
        print(f"[run_tests] pruned={','.join(refresh['deleted_timestamps'])}")

    if result.returncode != 0:
        print(f"[run_tests] FAILED suite={args.suite} exit_code={result.returncode}")
    else:
        print(f"[run_tests] PASSED suite={args.suite}")

    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
