from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from app.contract_audit import (
    audit_registry_handler_contracts,
    audit_registry_handler_contracts_from_mappings,
    format_contract_issues,
    validate_handler_result_contract,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _ok_handler(_payload: object) -> dict[str, object]:
    return {"status": "completed", "details": {"ok": True}, "artifacts": []}


class ControlPlaneContractAuditTests(unittest.TestCase):
    def test_real_registry_handler_audit_passes(self) -> None:
        report = audit_registry_handler_contracts()
        self.assertEqual(
            report.error_count,
            0,
            msg=format_contract_issues(report.issues),
        )

    def test_missing_handler_reference_is_rejected(self) -> None:
        report = audit_registry_handler_contracts_from_mappings(
            registry={
                "backend.test": {"handler": "missing_handler"},
            },
            handlers={
                "handle_backend_test": _ok_handler,
            },
        )
        codes = [item.code for item in report.issues]
        self.assertIn("HANDLER_NOT_FOUND", codes)

    def test_invalid_registry_entry_shape_is_rejected(self) -> None:
        report = audit_registry_handler_contracts_from_mappings(
            registry={
                "backend.test": 123,
            },
            handlers={
                "handle_backend_test": _ok_handler,
            },
        )
        codes = [item.code for item in report.issues]
        self.assertIn("INVALID_REGISTRY_ENTRY", codes)

    def test_invalid_handler_result_missing_status_is_rejected(self) -> None:
        issues = validate_handler_result_contract(
            {
                "details": {"ok": True},
                "artifacts": [],
            }
        )
        codes = [item.code for item in issues]
        self.assertIn("MISSING_STATUS", codes)

    def test_invalid_handler_result_non_mapping_is_rejected(self) -> None:
        issues = validate_handler_result_contract(["not", "a", "mapping"])
        codes = [item.code for item in issues]
        self.assertIn("NON_MAPPING_RESULT", codes)

    def test_audit_script_regression(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/audit_contracts.py"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            completed.returncode,
            0,
            msg=f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}",
        )

        payload = json.loads(completed.stdout)
        self.assertEqual(payload["error_count"], 0)
        self.assertIn("registry_entries", payload)
        self.assertIn("handler_entries", payload)

        report_path = PROJECT_ROOT / "artifacts" / "test_reports" / "latest_contract_audit.json"
        self.assertTrue(report_path.exists(), "latest_contract_audit.json must exist after script execution")


if __name__ == "__main__":
    unittest.main()
