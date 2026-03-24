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

from app.module_contracts import lock_module_contracts, validate_worker_entry_name  # noqa: E402
from app.registry_dispatch_runtime import dispatch_queue_item_via_registry  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Official worker entry for orchestrator control plane.")
    parser.add_argument("--db-path", required=True)
    parser.add_argument("--worker-id", required=True)
    return parser.parse_args()


def main() -> int:
    os.chdir(PROJECT_ROOT)
    args = parse_args()

    entry_report = validate_worker_entry_name("scripts/worker_entry.py")
    if not entry_report.ok:
        print(json.dumps(entry_report.to_dict(), indent=2, ensure_ascii=False))
        return 1

    lock_report = lock_module_contracts()
    if not lock_report.ok:
        print(json.dumps(lock_report.to_dict(), indent=2, ensure_ascii=False))
        return 1

    result = dispatch_queue_item_via_registry(
        args.db_path,
        args.worker_id,
    )
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
