from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.security.proof_registry_manifest import (
    ProofRegistryManifestError,
    write_manifest_files,
)


def main() -> int:
    output_dir = PROJECT_ROOT / "artifacts" / "handover"
    output_json = output_dir / "proof_registry_baseline_manifest.json"
    output_sha256 = output_dir / "proof_registry_baseline_manifest.sha256"

    try:
        result = write_manifest_files(
            project_root=PROJECT_ROOT,
            output_json_path=output_json,
            output_sha256_path=output_sha256,
        )
    except ProofRegistryManifestError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"manifest_json={result['output_json_path']}")
    print(f"manifest_sha256_file={result['output_sha256_path']}")
    print(f"manifest_sha256={result['manifest_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
