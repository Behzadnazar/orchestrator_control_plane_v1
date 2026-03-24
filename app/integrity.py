from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .config import DB_PATH, BASE_DIR
from .validator import validate_config
from .migrations import apply_migrations, current_versions


REQUIRED_TABLES = {
    "schema_migrations",
    "agents",
    "tasks",
    "events",
    "approvals",
    "file_locks",
    "heartbeats",
}


def run_integrity_checks() -> dict:
    result = {
        "db_exists": Path(DB_PATH).exists(),
        "config_ok": False,
        "config_errors": [],
        "migrations_applied_now": [],
        "schema_versions": [],
        "required_tables_ok": False,
        "missing_tables": [],
        "status": "unhealthy",
    }

    ok, errors = validate_config(Path(BASE_DIR))
    result["config_ok"] = ok
    result["config_errors"] = errors

    applied = apply_migrations()
    result["migrations_applied_now"] = applied
    result["schema_versions"] = current_versions()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type='table'
    """).fetchall()
    existing = {r["name"] for r in rows}
    missing = sorted(REQUIRED_TABLES - existing)

    result["required_tables_ok"] = len(missing) == 0
    result["missing_tables"] = missing

    conn.close()

    if result["config_ok"] and result["required_tables_ok"]:
        result["status"] = "healthy"

    return result


def main() -> None:
    print(json.dumps(run_integrity_checks(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
