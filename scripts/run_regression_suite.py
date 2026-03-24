#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = PROJECT_ROOT / "tests"
REPORT_DIR = PROJECT_ROOT / "artifacts" / "test_reports"
MANIFEST_PATH = TESTS_DIR / "suite_manifest.json"


def ensure_project_root_on_syspath() -> None:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


ensure_project_root_on_syspath()

from app.test_diagnostics import categorize_failure  # noqa: E402


def load_manifest() -> dict[str, Any]:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Missing suite manifest: {MANIFEST_PATH}")

    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    if "version" not in data or not isinstance(data["version"], int):
        raise ValueError("suite_manifest.json is missing a valid integer 'version'")

    if "suite_execution_order" not in data or not isinstance(data["suite_execution_order"], list):
        raise ValueError("suite_manifest.json is missing a valid 'suite_execution_order' list")

    if "suites" not in data or not isinstance(data["suites"], dict):
        raise ValueError("suite_manifest.json is missing a valid 'suites' object")

    if "official_discovery_command" not in data or not isinstance(data["official_discovery_command"], str):
        raise ValueError("suite_manifest.json is missing 'official_discovery_command'")

    if "stable_failure_categories" not in data or not isinstance(data["stable_failure_categories"], list):
        raise ValueError("suite_manifest.json is missing 'stable_failure_categories'")

    return data


class DetailedTextResult(unittest.TextTestResult):
    def build_failure_diagnostics(self) -> list[dict[str, str]]:
        diagnostics: list[dict[str, str]] = []

        for test_case, traceback_text in self.failures:
            item = categorize_failure(str(test_case), traceback_text, "failure")
            diagnostics.append(
                {
                    "test": item.test,
                    "kind": item.kind,
                    "category": item.category,
                    "summary": item.summary,
                    "traceback": item.traceback,
                }
            )

        for test_case, traceback_text in self.errors:
            item = categorize_failure(str(test_case), traceback_text, "error")
            diagnostics.append(
                {
                    "test": item.test,
                    "kind": item.kind,
                    "category": item.category,
                    "summary": item.summary,
                    "traceback": item.traceback,
                }
            )

        skipped = getattr(self, "skipped", [])
        for test_case, reason in skipped:
            diagnostics.append(
                {
                    "test": str(test_case),
                    "kind": "skipped",
                    "category": "SKIPPED",
                    "summary": str(reason),
                    "traceback": str(reason),
                }
            )

        return diagnostics


class DetailedTextRunner(unittest.TextTestRunner):
    resultclass = DetailedTextResult


def parse_args(manifest: dict[str, Any]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run orchestrator control plane regression suites.")
    parser.add_argument(
        "--suite",
        choices=manifest["suite_execution_order"],
        default="all",
        help="Which regression suite to run.",
    )
    return parser.parse_args()


def discover_suite(loader: unittest.TestLoader, suite_name: str, manifest: dict[str, Any]) -> unittest.TestSuite:
    suite = unittest.TestSuite()
    suite_config = manifest["suites"][suite_name]

    for pattern in suite_config["patterns"]:
        discovered = loader.discover(
            start_dir=str(TESTS_DIR),
            pattern=pattern,
            top_level_dir=str(PROJECT_ROOT),
        )
        suite.addTests(discovered)

    return suite


def build_summary(suite_name: str, result: DetailedTextResult, manifest: dict[str, Any]) -> dict[str, Any]:
    failure_diagnostics = result.build_failure_diagnostics()

    return {
        "suite": suite_name,
        "manifest_version": manifest["version"],
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project_root": str(PROJECT_ROOT),
        "official_discovery_command": manifest["official_discovery_command"],
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(getattr(result, "skipped", [])),
        "successful": result.wasSuccessful(),
        "failure_diagnostics": failure_diagnostics,
    }


def write_reports(summary: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    json_path = REPORT_DIR / "latest_summary.json"
    txt_path = REPORT_DIR / "latest_summary.txt"

    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        f"suite={summary['suite']}",
        f"manifest_version={summary['manifest_version']}",
        f"tests_run={summary['tests_run']}",
        f"failures={summary['failures']}",
        f"errors={summary['errors']}",
        f"skipped={summary['skipped']}",
        f"successful={summary['successful']}",
        f"official_discovery_command={summary['official_discovery_command']}",
    ]

    if summary["failure_diagnostics"]:
        lines.append("failure_categories=" + ",".join(item["category"] for item in summary["failure_diagnostics"]))
    else:
        lines.append("failure_categories=")

    txt_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    os.chdir(PROJECT_ROOT)

    manifest = load_manifest()
    args = parse_args(manifest)

    loader = unittest.TestLoader()
    suite = discover_suite(loader, args.suite, manifest)

    runner = DetailedTextRunner(verbosity=2)
    result: DetailedTextResult = runner.run(suite)

    summary = build_summary(args.suite, result, manifest)
    write_reports(summary)

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
