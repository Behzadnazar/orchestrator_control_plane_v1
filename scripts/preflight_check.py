from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
VENV_PYTHON = BASE_DIR / ".venv" / "bin" / "python3"

REQUIRED_FILES = [
    BASE_DIR / "pytest.ini",
    BASE_DIR / "worker_loop_final.py",
    BASE_DIR / "app" / "db.py",
    BASE_DIR / "app" / "services" / "control_plane_service.py",
    BASE_DIR / "scripts" / "__init__.py",
    BASE_DIR / "scripts" / "run_tests.py",
    BASE_DIR / "scripts" / "ci_check.py",
    BASE_DIR / "tests" / "test_smoke.py",
    BASE_DIR / "tests" / "test_workflow_e2e.py",
    BASE_DIR / "tests" / "test_regression_matrix.py",
]


def fail(message: str, exit_code: int = 2) -> int:
    print(f"[preflight] FAIL {message}")
    return exit_code


def pass_check(message: str) -> None:
    print(f"[preflight] PASS {message}")


def check_base_dir() -> int:
    if not BASE_DIR.exists():
        return fail(f"base dir missing: {BASE_DIR}")
    pass_check(f"base dir present: {BASE_DIR}")
    return 0


def check_venv_python() -> int:
    if not VENV_PYTHON.exists():
        return fail(f"missing venv interpreter: {VENV_PYTHON}")
    pass_check(f"venv interpreter present: {VENV_PYTHON}")
    return 0


def check_required_files() -> int:
    missing: list[Path] = [path for path in REQUIRED_FILES if not path.exists()]
    if missing:
        for path in missing:
            print(f"[preflight] MISSING_FILE {path}")
        return fail("required project files are missing")
    pass_check(f"required files present: {len(REQUIRED_FILES)}")
    return 0


def check_python_executable() -> int:
    current = Path(sys.executable).resolve()
    expected = VENV_PYTHON.resolve()

    if current != expected:
        return fail(
            f"unexpected interpreter: current={current} expected={expected}",
            exit_code=3,
        )

    pass_check(f"active interpreter matches venv: {current}")
    return 0


def check_pytest_available() -> int:
    spec = importlib.util.find_spec("pytest")
    if spec is None:
        return fail("pytest is not importable inside active interpreter")
    pass_check("pytest import available")
    return 0


def main() -> int:
    checks = [
        check_base_dir,
        check_venv_python,
        check_required_files,
        check_python_executable,
        check_pytest_available,
    ]

    for check in checks:
        exit_code = check()
        if exit_code != 0:
            print("[preflight] FINAL_STATUS=FAILED")
            return exit_code

    print("[preflight] FINAL_STATUS=PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
