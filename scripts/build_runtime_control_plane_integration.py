from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.security.runtime_control_plane_integration import (
    RuntimeControlPlaneIntegrationError,
    build_runtime_control_plane_integration,
)


def main() -> int:
    try:
        result = build_runtime_control_plane_integration(project_root=PROJECT_ROOT)
    except RuntimeControlPlaneIntegrationError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"runtime_integration_json={result['runtime_integration_json']}")
    print(f"runtime_integration_md={result['runtime_integration_md']}")
    print(f"baseline_manifest_json={result['baseline_manifest_json']}")
    print(f"integration_package_json={result['integration_package_json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
