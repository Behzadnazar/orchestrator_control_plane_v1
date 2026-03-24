from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.security.operational_runtime_integration import (
    OperationalRuntimeIntegrationError,
    build_operational_runtime_integration,
)


def main() -> int:
    try:
        result = build_operational_runtime_integration(project_root=PROJECT_ROOT)
    except OperationalRuntimeIntegrationError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"runtime_operational_json={result['runtime_operational_json']}")
    print(f"runtime_operational_md={result['runtime_operational_md']}")
    print(f"baseline_sha256={result['baseline_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
