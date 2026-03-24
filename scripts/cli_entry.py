#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def ensure_project_root_on_syspath() -> None:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


ensure_project_root_on_syspath()

from app.module_contracts import lock_module_contracts, validate_cli_entry_name  # noqa: E402
from scripts.run_regression_suite import main as run_regression_main  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Official CLI entry for orchestrator control plane.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lock_cmd = subparsers.add_parser("lock-contracts", help="Validate frozen module contracts.")
    lock_cmd.set_defaults(command="lock-contracts")

    test_cmd = subparsers.add_parser("run-suite", help="Run the official regression suite entry.")
    test_cmd.add_argument("--suite", required=False, default="all")
    test_cmd.set_defaults(command="run-suite")

    return parser.parse_args()


def main() -> int:
    os.chdir(PROJECT_ROOT)
    args = parse_args()

    entry_report = validate_cli_entry_name("scripts/cli_entry.py")
    if not entry_report.ok:
        print(json.dumps(entry_report.to_dict(), indent=2, ensure_ascii=False))
        return 1

    if args.command == "lock-contracts":
        report = lock_module_contracts()
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return 0 if report.ok else 1

    if args.command == "run-suite":
        sys.argv = ["run_regression_suite.py", "--suite", args.suite]
        return run_regression_main()

    print(json.dumps({"ok": False, "code": "CLI_ENTRY_INVALID", "message": "Unsupported command."}, indent=2, ensure_ascii=False))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
