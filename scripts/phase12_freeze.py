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
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "intake" / "project_intake.md",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "environments" / "promotion_model.json",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "cicd" / "pipeline_spec.yaml",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "ops" / "observability_spec.json",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "ops" / "change_control.md",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "supply" / "sbom.json",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "supply" / "provenance.json",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "supply" / "signing.json",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "architect" / "change_review.json",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "release" / "deployment_report.json",
        project_root / "artifacts" / "runs" / "phase12_prod_v1" / "postmortem" / "postmortem.md",
        project_root / "artifacts" / "phase12_handover" / "phase12_proof_summary.json",
        project_root / "artifacts" / "phase12_handover" / "phase12_proof_summary.md"
    ]
    return [p for p in wanted if p.exists()]


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    freeze_dir = project_root / "artifacts" / "phase12_freeze"
    freeze_dir.mkdir(parents=True, exist_ok=True)

    files = collect_files(project_root)
    manifest: Dict[str, object] = {
        "generated_at": utc_now_iso(),
        "phase": "12",
        "baseline_name": "phase12_production_workflow_freeze_v1",
        "files": [
            {
                "path": str(path.relative_to(project_root).as_posix()),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size
            }
            for path in files
        ]
    }

    manifest_path = freeze_dir / "phase12_baseline_manifest.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)

    md = [
        "# Phase12 Baseline Freeze",
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
    (freeze_dir / "phase12_baseline_manifest.md").write_text("\n".join(md), encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "manifest_json": str(manifest_path),
        "manifest_md": str(freeze_dir / "phase12_baseline_manifest.md"),
        "files_count": len(files)
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
