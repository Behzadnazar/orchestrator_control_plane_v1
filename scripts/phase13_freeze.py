from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


UTC = timezone.utc


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def collect_files(project_root: Path) -> List[Path]:
    wanted = [
        project_root / "artifacts" / "runs" / "phase13_external_v1" / "boundary" / "integration_boundary.md",
        project_root / "artifacts" / "runs" / "phase13_external_v1" / "repo" / "repo_ci_binding.json",
        project_root / "artifacts" / "runs" / "phase13_external_v1" / "environments" / "environment_governance.json",
        project_root / "artifacts" / "runs" / "phase13_external_v1" / "security" / "secrets_config.json",
        project_root / "artifacts" / "runs" / "phase13_external_v1" / "security" / "supply_chain_bundle.json",
        project_root / "artifacts" / "runs" / "phase13_external_v1" / "rollout" / "rollout_strategy.json",
        project_root / "artifacts" / "runs" / "phase13_external_v1" / "ops" / "observability_change_integration.json",
        project_root / "artifacts" / "runs" / "phase13_external_v1" / "delivery" / "first_external_delivery_plan.json",
        project_root / "artifacts" / "phase13_handover" / "phase13_proof_summary.json",
        project_root / "artifacts" / "phase13_handover" / "phase13_proof_summary.md"
    ]
    return [p for p in wanted if p.exists()]


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    freeze_dir = project_root / "artifacts" / "phase13_freeze"
    freeze_dir.mkdir(parents=True, exist_ok=True)

    files = collect_files(project_root)
    manifest: Dict[str, object] = {
        "generated_at": utc_now_iso(),
        "phase": "13",
        "baseline_name": "phase13_external_delivery_freeze_v1",
        "files": [
            {
                "path": str(path.relative_to(project_root).as_posix()),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size
            }
            for path in files
        ]
    }

    manifest_path = freeze_dir / "phase13_baseline_manifest.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)

    md = [
        "# Phase13 Baseline Freeze",
        "",
        f"- generated_at: {manifest['generated_at']}",
        f"- baseline_name: {manifest['baseline_name']}",
        f"- files_count: {len(files)}",
        "",
        "## Files",
        ""
    ]
    for item in manifest["files"]:
        md.append(f"- {item['path']} | sha256={item['sha256']} | bytes={item['bytes']}")
    md.append("")
    (freeze_dir / "phase13_baseline_manifest.md").write_text("\n".join(md), encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "manifest_json": str(manifest_path),
        "manifest_md": str(freeze_dir / "phase13_baseline_manifest.md"),
        "files_count": len(files)
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
