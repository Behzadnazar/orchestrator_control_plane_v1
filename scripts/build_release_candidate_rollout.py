from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.security.release_candidate_rollout import (
    ReleaseCandidateRolloutError,
    build_release_candidate_rollout,
)


def main() -> int:
    try:
        result = build_release_candidate_rollout(project_root=PROJECT_ROOT)
    except ReleaseCandidateRolloutError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"rollout_json={result['rollout_json']}")
    print(f"rollout_md={result['rollout_md']}")
    print(f"baseline_sha256={result['baseline_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
