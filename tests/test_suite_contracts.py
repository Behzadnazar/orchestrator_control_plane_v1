from __future__ import annotations

import json
import unittest
from pathlib import Path

from app.test_diagnostics import FailureCategory, categorize_failure


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = PROJECT_ROOT / "tests" / "suite_manifest.json"


class ControlPlaneSuiteContractsTests(unittest.TestCase):
    def test_suite_manifest_is_present_and_well_formed(self) -> None:
        self.assertTrue(MANIFEST_PATH.exists(), "suite_manifest.json must exist")

        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

        self.assertEqual(manifest["version"], 1)
        self.assertIn("official_discovery_command", manifest)
        self.assertIn("-t .", manifest["official_discovery_command"])
        self.assertIn("suites", manifest)
        self.assertIn("all", manifest["suites"])

        for suite_name in manifest["suite_execution_order"]:
            self.assertIn(suite_name, manifest["suites"])
            self.assertTrue(manifest["suites"][suite_name]["patterns"])
            self.assertTrue(manifest["suites"][suite_name]["expected_modules"])

    def test_manifest_failure_categories_match_python_enum(self) -> None:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        expected = [item.value for item in FailureCategory]
        self.assertEqual(manifest["stable_failure_categories"], expected)

    def test_import_error_is_categorized_stably(self) -> None:
        diagnostic = categorize_failure(
            "tests.test_smoke.ControlPlaneSmokeTests.test_health_and_worker_registration",
            "ModuleNotFoundError: No module named 'tests'",
            "error",
        )
        self.assertEqual(diagnostic.category, FailureCategory.IMPORT_ERROR.value)

    def test_assertion_failure_is_categorized_stably(self) -> None:
        diagnostic = categorize_failure(
            "tests.test_workflow_e2e.ControlPlaneWorkflowE2ETests.test_phase_h_demo_end_to_end_regression",
            "AssertionError: expected status=done, got failed",
            "failure",
        )
        self.assertEqual(diagnostic.category, FailureCategory.ASSERTION_FAILURE.value)


if __name__ == "__main__":
    unittest.main()
