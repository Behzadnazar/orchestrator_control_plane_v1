from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.module_contracts import (
    ModuleContractCode,
    lock_module_contracts,
    validate_cli_entry_name,
    validate_worker_entry_name,
)
from app.persistent_queue_runtime import ensure_persistent_queue_schema, get_persistent_queue_item, insert_persistent_queue_item
from app.queue_contracts import QueueStatus


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class ControlPlaneModuleContractsTests(unittest.TestCase):
    def test_frozen_registry_shape_preserved(self) -> None:
        report = lock_module_contracts()
        self.assertTrue(report.ok, msg=report.to_dict())

    def test_registry_shape_drift_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            registry_module = tmp / "broken_registry.py"
            handlers_module = tmp / "broken_handlers.py"

            registry_module.write_text(
                "TASK_REGISTRY = {'backend.test': 'handle_backend_test'}\n",
                encoding="utf-8",
            )
            handlers_module.write_text(
                "TASK_HANDLERS = {'handle_backend_test': lambda payload: {'status': 'completed', 'details': {}, 'artifacts': []}}\n",
                encoding="utf-8",
            )

            sys.path.insert(0, str(tmp))
            try:
                report = lock_module_contracts("broken_registry", "broken_handlers")
            finally:
                sys.path.pop(0)

        self.assertFalse(report.ok)
        self.assertEqual(report.code, ModuleContractCode.REGISTRY_SHAPE_DRIFT.value)

    def test_module_contract_export_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            registry_module = tmp / "missing_registry.py"
            handlers_module = tmp / "ok_handlers.py"

            registry_module.write_text("X = 1\n", encoding="utf-8")
            handlers_module.write_text(
                "TASK_HANDLERS = {'handle_backend_test': lambda payload: {'status': 'completed', 'details': {}, 'artifacts': []}}\n",
                encoding="utf-8",
            )

            sys.path.insert(0, str(tmp))
            try:
                report = lock_module_contracts("missing_registry", "ok_handlers")
            finally:
                sys.path.pop(0)

        self.assertFalse(report.ok)
        self.assertEqual(report.code, ModuleContractCode.REGISTRY_EXPORT_MISSING.value)

    def test_module_contract_export_invalid_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            registry_module = tmp / "ok_registry.py"
            handlers_module = tmp / "bad_handlers.py"

            registry_module.write_text(
                "TASK_REGISTRY = {'backend.test': {'handler': 'handle_backend_test'}}\n",
                encoding="utf-8",
            )
            handlers_module.write_text(
                "TASK_HANDLERS = {'handle_backend_test': 'not-callable'}\n",
                encoding="utf-8",
            )

            sys.path.insert(0, str(tmp))
            try:
                report = lock_module_contracts("ok_registry", "bad_handlers")
            finally:
                sys.path.pop(0)

        self.assertFalse(report.ok)
        self.assertEqual(report.code, ModuleContractCode.HANDLER_ENTRY_NOT_CALLABLE.value)

    def test_cli_entry_invokes_official_path(self) -> None:
        report = validate_cli_entry_name("scripts/cli_entry.py")
        self.assertTrue(report.ok)

    def test_worker_entry_invokes_official_dispatch(self) -> None:
        report = validate_worker_entry_name("scripts/worker_entry.py")
        self.assertTrue(report.ok)

    def test_cli_entry_lock_contracts_command(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/cli_entry.py", "lock-contracts"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, msg=f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])

    def test_worker_entry_dispatches_official_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "entry.sqlite3"
            ensure_persistent_queue_schema(db_path)

            insert_persistent_queue_item(
                db_path,
                {
                    "queue_item_id": "entry-1",
                    "task_id": "task-1",
                    "task_type": "backend.test",
                    "status": QueueStatus.QUEUED.value,
                },
            )

            completed = subprocess.run(
                [sys.executable, "scripts/worker_entry.py", "--db-path", str(db_path), "--worker-id", "worker-entry"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, msg=f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}")
            payload = json.loads(completed.stdout)
            self.assertTrue(payload["ok"])

            item = get_persistent_queue_item(db_path, "entry-1")
            self.assertIsNotNone(item)
            self.assertEqual(item["status"], QueueStatus.COMPLETED.value)


if __name__ == "__main__":
    unittest.main()
