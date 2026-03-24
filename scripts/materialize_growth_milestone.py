#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FREEZE_GATE_ROOT = ROOT / "artifacts" / "freeze_gate"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_json(path: Path):
    return json.loads(read_text(path))


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


def require_dir(path: Path) -> Path:
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Required directory missing: {path}")
    return path


def replace_all(text: str, old: str, new: str) -> str:
    return text.replace(old, new)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize a new freeze-gate milestone from an existing PASS milestone for audit chain growth tests."
    )
    parser.add_argument("--source-milestone", required=True)
    parser.add_argument("--target-milestone", required=True)
    args = parser.parse_args()

    source_milestone = args.source_milestone.strip()
    target_milestone = args.target_milestone.strip()

    if not source_milestone:
        raise SystemExit("source milestone must not be empty.")
    if not target_milestone:
        raise SystemExit("target milestone must not be empty.")
    if source_milestone == target_milestone:
        raise SystemExit("source milestone and target milestone must be different.")

    src_dir = require_dir(FREEZE_GATE_ROOT / source_milestone)
    dst_dir = FREEZE_GATE_ROOT / target_milestone

    if dst_dir.exists():
        raise SystemExit(f"Target milestone already exists: {dst_dir}")

    shutil.copytree(src_dir, dst_dir)

    src_zip = dst_dir / f"{source_milestone}_evidence_bundle.zip"
    dst_zip = dst_dir / f"{target_milestone}_evidence_bundle.zip"
    require_file(src_zip)
    src_zip.rename(dst_zip)

    summary_path = require_file(dst_dir / "freeze_gate_summary.json")
    summary = read_json(summary_path)
    summary["milestone"] = target_milestone
    outputs = summary.get("outputs", {})
    if isinstance(outputs, dict):
        for key, value in list(outputs.items()):
            if isinstance(value, str):
                outputs[key] = value.replace(source_milestone, target_milestone)
    summary["outputs"] = outputs
    evidence_sources = summary.get("evidence_sources", {})
    if isinstance(evidence_sources, dict):
        for key, value in list(evidence_sources.items()):
            if isinstance(value, str):
                evidence_sources[key] = value.replace(source_milestone, target_milestone)
    summary["evidence_sources"] = evidence_sources
    write_json(summary_path, summary)

    manifest_path = require_file(dst_dir / "evidence_bundle_manifest.json")
    manifest = read_json(manifest_path)
    manifest["milestone"] = target_milestone
    items = manifest.get("items", [])
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                for key in ("source_path", "bundle_path"):
                    value = item.get(key)
                    if isinstance(value, str):
                        item[key] = value.replace(source_milestone, target_milestone)
    manifest["items"] = items
    write_json(manifest_path, manifest)

    report_path = require_file(dst_dir / "freeze_gate_audit_report.md")
    report_text = read_text(report_path)
    report_text = replace_all(report_text, f"# Freeze Gate Audit Report — {source_milestone}", f"# Freeze Gate Audit Report — {target_milestone}")
    report_text = replace_all(report_text, f"/{source_milestone}`", f"/{target_milestone}`")
    report_text = replace_all(report_text, f"{source_milestone}_evidence_bundle.zip", f"{target_milestone}_evidence_bundle.zip")
    report_text = replace_all(report_text, source_milestone, target_milestone)
    write_text(report_path, report_text)

    print("=" * 72)
    print("GROWTH MILESTONE MATERIALIZED")
    print("=" * 72)
    print(f"SOURCE MILESTONE : {source_milestone}")
    print(f"TARGET MILESTONE : {target_milestone}")
    print(f"TARGET DIRECTORY : {dst_dir.relative_to(ROOT)}")
    print(f"TARGET ZIP       : {dst_zip.relative_to(ROOT)}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
