#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_ROOT / "artifacts" / "test_reports"


def ensure_project_root_on_syspath() -> None:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


ensure_project_root_on_syspath()

from app.contract_audit import audit_registry_handler_contracts, format_contract_issues  # noqa: E402


def main() -> int:
    os.chdir(PROJECT_ROOT)

    report = audit_registry_handler_contracts()
    payload = report.to_dict()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REPORT_DIR / "latest_contract_audit.json"
    txt_path = REPORT_DIR / "latest_contract_audit.txt"

    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    txt_lines = [
        f"registry_module={payload['registry_module']}",
        f"handlers_module={payload['handlers_module']}",
        f"registry_entries={payload['registry_entries']}",
        f"handler_entries={payload['handler_entries']}",
        f"error_count={payload['error_count']}",
        f"warning_count={payload['warning_count']}",
        "issues=",
        format_contract_issues(report.issues),
    ]
    txt_path.write_text("\n".join(txt_lines), encoding="utf-8")

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["error_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
