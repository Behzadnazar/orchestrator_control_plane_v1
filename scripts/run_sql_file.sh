#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: ./scripts/run_sql_file.sh <db_path> <sql_file>"
  exit 1
fi

DB_PATH="$1"
SQL_FILE="$2"

if [ ! -f "$SQL_FILE" ]; then
  echo "[ERROR] SQL file not found: $SQL_FILE"
  exit 1
fi

sqlite3 "$DB_PATH" < "$SQL_FILE"
echo "[SQL_APPLIED] $SQL_FILE -> $DB_PATH"
