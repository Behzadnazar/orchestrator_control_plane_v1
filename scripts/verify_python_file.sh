#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: ./scripts/verify_python_file.sh <file.py>"
  exit 1
fi

FILE="$1"

python3 -m py_compile "$FILE"
echo "[PY_COMPILE_OK] $FILE"
echo "----- HEAD -----"
sed -n '1,80p' "$FILE"
echo "----- SHA256 -----"
sha256sum "$FILE"
