from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .config import DB_PATH


MIGRATIONS_DIR = Path("migrations")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def ensure_migration_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)


def get_applied_versions(conn: sqlite3.Connection) -> set[str]:
    ensure_migration_table(conn)
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {r["version"] for r in rows}


def discover_migrations() -> list[Path]:
    if not MIGRATIONS_DIR.exists():
        return []
    return sorted(p for p in MIGRATIONS_DIR.glob("*.sql") if p.is_file())


def apply_migrations() -> list[str]:
    applied_now: list[str] = []
    with _connect() as conn:
        ensure_migration_table(conn)
        applied = get_applied_versions(conn)

        for path in discover_migrations():
            version = path.stem
            if version in applied:
                continue

            sql = path.read_text(encoding="utf-8")
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (version, utc_now()),
            )
            applied_now.append(version)

    return applied_now


def current_versions() -> list[dict]:
    with _connect() as conn:
        ensure_migration_table(conn)
        rows = conn.execute("""
            SELECT version, applied_at
            FROM schema_migrations
            ORDER BY version ASC
        """).fetchall()
        return [{"version": r["version"], "applied_at": r["applied_at"]} for r in rows]
