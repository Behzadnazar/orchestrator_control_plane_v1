from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.security.formal_delivery_bundle import (
    FormalDeliveryBundleError,
    build_formal_delivery_bundle,
)


def main() -> int:
    try:
        result = build_formal_delivery_bundle(project_root=PROJECT_ROOT)
    except FormalDeliveryBundleError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"delivery_bundle_json={result['delivery_bundle_json']}")
    print(f"delivery_bundle_md={result['delivery_bundle_md']}")
    print(f"delivery_bundle_sha256_file={result['delivery_bundle_sha256']}")
    print(f"bundle_sha256={result['bundle_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
