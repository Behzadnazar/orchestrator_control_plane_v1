from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from scripts.artifact_index import register_run_and_refresh
from scripts.artifact_paths import BASE_DIR, build_run_dir, ensure_dir


PYTHON = BASE_DIR / ".venv" / "bin" / "python3"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run_step(name: str, cmd: list[str], run_dir: Path) -> tuple[int, dict]:
    step_started_at = utc_now_iso()
    step_monotonic_start = time.monotonic()

    print(f"[ci_check] START step={name}")
    print(f"[ci_check] CMD {' '.join(cmd)}")

    result = subprocess.run(
        cmd,
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        check=False,
    )

    stdout_log = run_dir / f"{name}.stdout.log"
    stderr_log = run_dir / f"{name}.stderr.log"

    write_text(stdout_log, result.stdout or "")
    write_text(stderr_log, result.stderr or "")

    if result.stdout:
        print(f"===== {name} STDOUT =====")
        print(result.stdout.rstrip())

    if result.stderr:
        print(f"===== {name} STDERR =====")
        print(result.stderr.rstrip())

    step_finished_at = utc_now_iso()
    step_duration_seconds = round(time.monotonic() - step_monotonic_start, 3)

    metadata = {
        "name": name,
        "command": " ".join(cmd),
        "exit_code": result.returncode,
        "status": "passed" if result.returncode == 0 else "failed",
        "started_at_utc": step_started_at,
        "finished_at_utc": step_finished_at,
        "duration_seconds": step_duration_seconds,
        "stdout_log": str(stdout_log),
        "stderr_log": str(stderr_log),
    }

    if result.returncode != 0:
        print(f"[ci_check] FAIL step={name} exit_code={result.returncode}")
    else:
        print(f"[ci_check] PASS step={name}")

    return result.returncode, metadata


def main() -> int:
    retention_count = 8
    started_at_utc = utc_now_iso()
    monotonic_start = time.monotonic()

    run_dir = ensure_dir(build_run_dir("ci_check"))
    steps_metadata: list[dict] = []

    if not PYTHON.exists():
        finished_at_utc = utc_now_iso()
        duration_seconds = round(time.monotonic() - monotonic_start, 3)

        write_json(
            run_dir / "summary.json",
            {
                "suite": "ci_check",
                "status": "failed",
                "failed_step": "bootstrap",
                "exit_code": 2,
                "started_at_utc": started_at_utc,
                "finished_at_utc": finished_at_utc,
                "duration_seconds": duration_seconds,
                "reason": f"missing interpreter: {PYTHON}",
                "run_dir": str(run_dir),
                "step_count": 0,
                "steps": [],
            },
        )
        refresh = register_run_and_refresh(
            suite="ci_check",
            run_dir=run_dir,
            retention_count=retention_count,
        )
        print(f"[ci_check] latest_pointer={refresh['latest_pointer']}")
        print(f"[ci_check] index_path={refresh['index_path']}")
        print(f"[ci_check] FAIL missing interpreter: {PYTHON}")
        return 2

    steps: list[tuple[str, list[str]]] = [
        ("preflight", [str(PYTHON), "-m", "scripts.preflight_check"]),
        ("suite_all", [str(PYTHON), "-m", "scripts.run_tests", "--suite", "all"]),
        ("suite_smoke", [str(PYTHON), "-m", "scripts.run_tests", "--suite", "smoke"]),
        ("suite_e2e", [str(PYTHON), "-m", "scripts.run_tests", "--suite", "e2e"]),
        ("suite_regression", [str(PYTHON), "-m", "scripts.run_tests", "--suite", "regression"]),
    ]

    for step_name, cmd in steps:
        exit_code, metadata = run_step(step_name, cmd, run_dir)
        steps_metadata.append(metadata)

        if exit_code != 0:
            finished_at_utc = utc_now_iso()
            duration_seconds = round(time.monotonic() - monotonic_start, 3)

            write_json(
                run_dir / "summary.json",
                {
                    "suite": "ci_check",
                    "status": "failed",
                    "failed_step": step_name,
                    "exit_code": exit_code,
                    "started_at_utc": started_at_utc,
                    "finished_at_utc": finished_at_utc,
                    "duration_seconds": duration_seconds,
                    "run_dir": str(run_dir),
                    "step_count": len(steps_metadata),
                    "steps": steps_metadata,
                },
            )
            refresh = register_run_and_refresh(
                suite="ci_check",
                run_dir=run_dir,
                retention_count=retention_count,
            )
            print(f"[ci_check] latest_pointer={refresh['latest_pointer']}")
            print(f"[ci_check] index_path={refresh['index_path']}")
            if refresh["deleted_timestamps"]:
                print(f"[ci_check] pruned={','.join(refresh['deleted_timestamps'])}")
            print(f"[ci_check] FINAL_STATUS=FAILED failed_step={step_name}")
            return exit_code

    finished_at_utc = utc_now_iso()
    duration_seconds = round(time.monotonic() - monotonic_start, 3)

    write_json(
        run_dir / "summary.json",
        {
            "suite": "ci_check",
            "status": "passed",
            "failed_step": None,
            "exit_code": 0,
            "started_at_utc": started_at_utc,
            "finished_at_utc": finished_at_utc,
            "duration_seconds": duration_seconds,
            "run_dir": str(run_dir),
            "step_count": len(steps_metadata),
            "steps": steps_metadata,
        },
    )

    refresh = register_run_and_refresh(
        suite="ci_check",
        run_dir=run_dir,
        retention_count=retention_count,
    )
    print(f"[ci_check] latest_pointer={refresh['latest_pointer']}")
    print(f"[ci_check] index_path={refresh['index_path']}")
    if refresh["deleted_timestamps"]:
        print(f"[ci_check] pruned={','.join(refresh['deleted_timestamps'])}")
    print("[ci_check] FINAL_STATUS=PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
