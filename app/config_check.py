from __future__ import annotations

import json
from pathlib import Path

from .config import BASE_DIR
from .validator import validate_config


def main() -> None:
    ok, errors = validate_config(Path(BASE_DIR))
    print(json.dumps({"ok": ok, "errors": errors}, ensure_ascii=False, indent=2))
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
