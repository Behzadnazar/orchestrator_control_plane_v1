from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.security.integration_handover_package import (
    IntegrationHandoverPackageError,
    build_integration_handover_package,
)


def main() -> int:
    try:
        result = build_integration_handover_package(project_root=PROJECT_ROOT)
    except IntegrationHandoverPackageError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"integration_package_json={result['integration_package_json']}")
    print(f"integration_package_md={result['integration_package_md']}")
    print(f"baseline_manifest_json={result['baseline_manifest_json']}")
    print(f"baseline_manifest_sha256={result['baseline_manifest_sha256']}")
    print(f"proof_count={result['proof_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
