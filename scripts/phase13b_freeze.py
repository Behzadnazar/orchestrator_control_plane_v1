#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FREEZE_DIR = ROOT / "artifacts/phase13b_real/freeze"
FREEZE_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_files() -> list[Path]:
    rels = [
        "config/phase13b_github_real.json",
        "scripts/phase13b_bootstrap_github.py",
        "scripts/phase13b_prepare_release_bundle.py",
        "scripts/phase13b_verify_github_state.py",
        "scripts/phase13b_freeze.py",
        ".github/workflows/phase13b_governed_delivery.yml",
        ".github/CODEOWNERS",
        "artifacts/phase13b_real/bootstrap/bootstrap_summary.json",
        "artifacts/phase13b_real/bootstrap/bootstrap_summary.md",
        "artifacts/phase13b_real/build/bundle_manifest.json",
        "artifacts/phase13b_real/build/build_summary.json",
        "artifacts/phase13b_real/proof/github_state_summary.json",
        "artifacts/phase13b_real/proof/github_state_summary.md"
    ]
    files = []
    for rel in rels:
        p = ROOT / rel
        if p.exists():
            files.append(p)
    return files


def main() -> None:
    files = collect_files()
    manifest = {
        "generated_at": utc_now(),
        "baseline_name": "phase13b_real_external_freeze_v1",
        "files_count": len(files),
        "files": []
    }

    for path in files:
        manifest["files"].append({
            "path": str(path.relative_to(ROOT)),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size
        })

    json_path = FREEZE_DIR / "phase13b_baseline_manifest.json"
    md_path = FREEZE_DIR / "phase13b_baseline_manifest.md"

    json_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Phase13B Baseline Freeze",
        "",
        f"- generated_at: {manifest['generated_at']}",
        f"- baseline_name: {manifest['baseline_name']}",
        f"- files_count: {manifest['files_count']}",
        "",
        "## Files",
        ""
    ]
    for item in manifest["files"]:
        lines.append(
            f"- {item['path']} | sha256={item['sha256']} | bytes={item['bytes']}"
        )
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "manifest_json": str(json_path.relative_to(ROOT)),
        "manifest_md": str(md_path.relative_to(ROOT)),
        "files_count": manifest["files_count"]
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
