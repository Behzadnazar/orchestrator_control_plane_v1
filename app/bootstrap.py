from __future__ import annotations

import json
from pathlib import Path

from .config import BASE_DIR
from .integrity import run_integrity_checks
from .typed_config import ConfigError, TypedProjectConfig
from .boot import safe_recover_before_boot


def main() -> None:
    try:
        typed_cfg = TypedProjectConfig.load(Path(BASE_DIR))
    except ConfigError as e:
        print(json.dumps({
            "bootstrap_ok": False,
            "phase": "typed_config",
            "error": str(e),
        }, ensure_ascii=False, indent=2))
        raise SystemExit(1)

    integrity = run_integrity_checks()
    if integrity["status"] != "healthy":
        print(json.dumps({
            "bootstrap_ok": False,
            "phase": "integrity",
            "integrity": integrity,
        }, ensure_ascii=False, indent=2))
        raise SystemExit(1)

    recovery = safe_recover_before_boot()

    print(json.dumps({
        "bootstrap_ok": True,
        "phase": "bootstrap_complete",
        "typed_config_summary": {
            "agents": len(typed_cfg.agents),
            "routing_rules": len(typed_cfg.routing_rules),
            "file_ownership_rules": len(typed_cfg.file_ownership),
            "runtime_env": typed_cfg.runtime_env.__dict__,
        },
        "integrity": integrity,
        "recovery": recovery,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
