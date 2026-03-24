#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FREEZE_GATE_ROOT = ROOT / "artifacts" / "freeze_gate"


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path):
    return json.loads(read_text(path))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


def normalize_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", name)


def copy_with_label(src: Path, dst_dir: Path, label: str) -> Path:
    dst = dst_dir / f"{normalize_name(label)}__{normalize_name(src.name)}"
    shutil.copy2(src, dst)
    return dst


def evaluate_baseline(data: dict) -> str:
    baseline_status = str(data.get("baseline_status", "")).strip().lower()
    if baseline_status in {"green", "pass", "passed", "ok", "success"}:
        return "PASS"
    if baseline_status in {"red", "fail", "failed", "error"}:
        return "FAIL"

    suite_summary = data.get("suite_summary")
    if isinstance(suite_summary, dict):
        any_failed = False
        for suite_data in suite_summary.values():
            if isinstance(suite_data, dict):
                latest_status = str(suite_data.get("latest_status", "")).strip().lower()
                latest_exit_code = suite_data.get("latest_exit_code")
                if latest_status in {"failed", "error"}:
                    any_failed = True
                if isinstance(latest_exit_code, int) and latest_exit_code != 0:
                    any_failed = True
        return "FAIL" if any_failed else "PASS"

    return "UNKNOWN"


def evaluate_verification(data: dict) -> str:
    drift_detected = data.get("drift_detected")
    drift_count = data.get("drift_count")
    if drift_detected is False and drift_count in (0, "0", None):
        return "PASS"
    if drift_detected is True:
        return "FAIL"
    return "UNKNOWN"


def evaluate_drift_proof(data: dict) -> str:
    flags = [
        data.get("proof_passed"),
        data.get("expected_failure_observed"),
        data.get("negative_proof_ok"),
    ]
    if any(v is False for v in flags):
        return "FAIL"
    if any(v is True for v in flags):
        return "PASS"
    return "UNKNOWN"


def evaluate_freeze_proof(data: dict) -> str:
    freeze_status = str(data.get("freeze_status", "")).strip().lower()
    if freeze_status == "frozen":
        return "PASS"
    if freeze_status in {"failed", "error"}:
        return "FAIL"

    freeze_gate = data.get("freeze_gate")
    if isinstance(freeze_gate, dict):
        if (
            str(freeze_gate.get("baseline_status", "")).strip().lower() == "green"
            and freeze_gate.get("verification_drift_detected") is False
            and freeze_gate.get("verification_drift_count") == 0
            and freeze_gate.get("failed_runs") == 0
            and freeze_gate.get("preflight_failed_runs") == 0
        ):
            return "PASS"

    return "UNKNOWN"


def zip_directory(directory: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in directory.rglob("*"):
            if path.is_file():
                arcname = path.relative_to(directory.parent)
                zf.write(path, arcname=str(arcname))


def build_report(
    milestone: str,
    generated_at: str,
    output_dir: Path,
    statuses: dict[str, str],
    copied: dict[str, Path],
    snippets: dict[str, str],
    overall_status: str,
) -> str:
    titles = {
        "baseline_manifest": "Baseline Manifest",
        "verification": "Verification",
        "drift_proof": "Drift Proof",
        "freeze_proof": "Freeze Proof",
    }

    lines: list[str] = []
    lines.append(f"# Freeze Gate Audit Report — {milestone}")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{generated_at}`")
    lines.append(f"- Project root: `{ROOT}`")
    lines.append(f"- Output directory: `{output_dir}`")
    lines.append(f"- Overall status: **{overall_status}**")
    lines.append("")
    lines.append("## Gate Summary")
    lines.append("")
    lines.append("| Gate | Status | Evidence |")
    lines.append("|---|---|---|")
    for key in ("baseline_manifest", "verification", "drift_proof", "freeze_proof"):
        lines.append(f"| {titles[key]} | {statuses[key]} | `{rel(copied[key])}` |")
    lines.append("| Drift Report | PASS | `Derived from verification evidence` |")
    lines.append("")
    lines.append("## Evidence Extracts")
    lines.append("")
    for key in ("baseline_manifest", "verification", "drift_proof", "freeze_proof"):
        lines.append(f"### {titles[key]}")
        lines.append("")
        lines.append(f"- Status: **{statuses[key]}**")
        lines.append(f"- Evidence path: `{rel(copied[key])}`")
        lines.append("")
        lines.append("```text")
        lines.append(snippets[key])
        lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an independent freeze gate milestone from underlying evidence, without cloning previous freeze-gate artifacts."
    )
    parser.add_argument("--milestone", required=True)
    parser.add_argument(
        "--baseline-path",
        default=str(ROOT / "artifacts" / "releases" / "control-plane-v1-baseline" / "release_snapshot.json"),
    )
    parser.add_argument(
        "--verification-path",
        default=str(ROOT / "artifacts" / "releases" / "latest_verification.json"),
    )
    parser.add_argument(
        "--drift-proof-path",
        default=str(ROOT / "artifacts" / "releases" / "negative_proof" / "latest_negative_proof.json"),
    )
    parser.add_argument(
        "--freeze-proof-path",
        default=str(ROOT / "artifacts" / "releases" / "milestones" / "control-plane-v1-phase-l2-freeze" / "milestone_manifest.json"),
    )
    args = parser.parse_args()

    milestone = args.milestone.strip()
    if not milestone:
        raise SystemExit("Milestone must not be empty.")

    output_dir = FREEZE_GATE_ROOT / milestone
    if output_dir.exists():
        raise SystemExit(f"Target milestone already exists: {output_dir}")

    baseline_path = require_file(Path(args.baseline_path))
    verification_path = require_file(Path(args.verification_path))
    drift_proof_path = require_file(Path(args.drift_proof_path))
    freeze_proof_path = require_file(Path(args.freeze_proof_path))

    baseline_data = read_json(baseline_path)
    verification_data = read_json(verification_path)
    drift_proof_data = read_json(drift_proof_path)
    freeze_proof_data = read_json(freeze_proof_path)

    statuses = {
        "baseline_manifest": evaluate_baseline(baseline_data),
        "verification": evaluate_verification(verification_data),
        "drift_proof": evaluate_drift_proof(drift_proof_data),
        "freeze_proof": evaluate_freeze_proof(freeze_proof_data),
    }

    if any(v != "PASS" for v in statuses.values()):
        raise SystemExit(f"Independent freeze gate cannot be built because not all source gates are PASS: {statuses}")

    generated_at = now_utc()
    output_dir.mkdir(parents=True, exist_ok=False)
    bundle_dir = output_dir / "evidence_bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    copied = {
        "baseline_manifest": copy_with_label(baseline_path, bundle_dir, "baseline_manifest"),
        "verification": copy_with_label(verification_path, bundle_dir, "verification"),
        "drift_proof": copy_with_label(drift_proof_path, bundle_dir, "drift_proof"),
        "freeze_proof": copy_with_label(freeze_proof_path, bundle_dir, "freeze_proof"),
    }

    snippets = {
        key: json.dumps(read_json(path), ensure_ascii=False, indent=2)[:1600]
        for key, path in copied.items()
    }

    bundle_items = []
    for key in ("baseline_manifest", "verification", "drift_proof", "freeze_proof"):
        path = copied[key]
        bundle_items.append(
            {
                "label": key,
                "status": "COPIED",
                "source_path": rel({
                    "baseline_manifest": baseline_path,
                    "verification": verification_path,
                    "drift_proof": drift_proof_path,
                    "freeze_proof": freeze_proof_path,
                }[key]),
                "bundle_path": rel(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )

    overall_status = "PASS"
    manifest = {
        "generated_at_utc": generated_at,
        "milestone": milestone,
        "project_root": str(ROOT),
        "overall_status": overall_status,
        "gate_statuses": {
            "baseline_manifest": "PASS",
            "verification": "PASS",
            "drift_report": "PASS",
            "drift_proof": "PASS",
            "freeze_proof": "PASS",
        },
        "items": bundle_items,
        "generation_mode": "independent_from_underlying_evidence",
        "notes": [
            "This milestone was generated from underlying baseline/verification/negative-proof/freeze-proof evidence.",
            "It was not cloned from a previous freeze_gate milestone directory."
        ],
    }
    write_json(output_dir / "evidence_bundle_manifest.json", manifest)

    summary = {
        "generated_at_utc": generated_at,
        "milestone": milestone,
        "overall_status": overall_status,
        "gate_statuses": {
            "baseline_manifest": "PASS",
            "verification": "PASS",
            "drift_report": "PASS",
            "drift_proof": "PASS",
            "freeze_proof": "PASS",
        },
        "evidence_sources": {
            "baseline_manifest": rel(baseline_path),
            "verification": rel(verification_path),
            "drift_report": rel(verification_path),
            "drift_proof": rel(drift_proof_path),
            "freeze_proof": rel(freeze_proof_path),
        },
        "outputs": {
            "report_markdown": rel(output_dir / "freeze_gate_audit_report.md"),
            "summary_json": rel(output_dir / "freeze_gate_summary.json"),
            "bundle_manifest_json": rel(output_dir / "evidence_bundle_manifest.json"),
            "bundle_archive_zip": rel(output_dir / f"{milestone}_evidence_bundle.zip"),
        },
        "generation_mode": "independent_from_underlying_evidence",
    }
    write_json(output_dir / "freeze_gate_summary.json", summary)

    report = build_report(
        milestone=milestone,
        generated_at=generated_at,
        output_dir=output_dir,
        statuses=statuses,
        copied=copied,
        snippets=snippets,
        overall_status=overall_status,
    )
    write_text(output_dir / "freeze_gate_audit_report.md", report)

    zip_directory(bundle_dir, output_dir / f"{milestone}_evidence_bundle.zip")

    print("=" * 72)
    print("INDEPENDENT FREEZE GATE MILESTONE BUILT")
    print("=" * 72)
    print(f"MILESTONE       : {milestone}")
    print(f"OUTPUT DIR      : {rel(output_dir)}")
    print(f"BUNDLE ZIP      : {rel(output_dir / f'{milestone}_evidence_bundle.zip')}")
    print(f"GENERATION MODE : independent_from_underlying_evidence")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
