from __future__ import annotations

import json
from pathlib import Path

from .config import BASE_DIR
from .typed_config import ConfigError, TypedProjectConfig


def main() -> None:
    try:
        cfg = TypedProjectConfig.load(Path(BASE_DIR))
        print(json.dumps({
            "ok": True,
            "summary": {
                "agents": len(cfg.agents),
                "routing_rules": len(cfg.routing_rules),
                "file_ownership_rules": len(cfg.file_ownership),
                "runtime_env": cfg.runtime_env.__dict__,
            }
        }, ensure_ascii=False, indent=2))
    except ConfigError as e:
        print(json.dumps({
            "ok": False,
            "error": str(e),
        }, ensure_ascii=False, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
