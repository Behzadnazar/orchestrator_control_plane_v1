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
from typing import Iterable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_ROOT = ROOT / "artifacts" / "freeze_gate"

SEARCH_DIR_NAMES = (
    "artifacts",
    "reports",
    "evidence",
    "baseline",
    "milestones",
    "snapshots",
)


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_json(path: Path):
    return json.loads(load_text(path))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def safe_rel(path: Path | None, base: Path) -> str:
    if path is None:
        return "NOT FOUND"
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except Exception:
        return str(path)


def iter_search_roots(root: Path) -> list[Path]:
    roots: list[Path] = []
    for name in SEARCH_DIR_NAMES:
        p = root / name
        if p.exists() and p.is_dir():
            roots.append(p)
    if not roots:
        roots.append(root)
    return roots


def iter_candidate_files(root: Path) -> Iterable[Path]:
    for search_root in iter_search_roots(root):
        for path in search_root.rglob("*"):
            if path.is_file():
                yield path


def norm(s: str) -> str:
    return s.lower().replace("-", "_").replace(" ", "_")


def classify_candidate(path: Path) -> set[str]:
    text = norm(str(path))
    name = norm(path.name)
    tags: set[str] = set()

    if (
        ("baseline" in text and "manifest" in text)
        or "release_snapshot" in name
        or ("baseline" in text and "snapshot" in text)
    ):
        tags.add("baseline_manifest")

    if (
        "verification" in text
        or "verify" in text
        or "latest_verification" in name
        or "baseline_verification" in name
        or ("baseline" in text and "check" in text)
    ):
        tags.add("verification")

    if (
        ("drift" in text and "report" in text)
        or ("drift" in text and "diff" in text)
        or "latest_drift_report" in name
        or "drift_report" in name
        or "baseline_verification" in name
    ):
        tags.add("drift_report")

    if (
        ("drift" in text and "proof" in text)
        or ("negative" in text and "proof" in text)
        or ("controlled" in text and "drift" in text)
        or ("simulation" in text and "drift" in text)
        or "latest_negative_proof" in name
        or "negative_proof" in name
        or "drift_proof" in name
        or "controlled_drift" in name
    ):
        tags.add("drift_proof")

    if (
        ("freeze" in text and "proof" in text)
        or ("freeze" in text and "gate" in text)
        or ("milestone" in text and "tag" in text)
        or ("workflow" in text and "freeze" in text)
        or "latest_freeze" in name
        or "freeze_proof" in name
        or "freeze_gate" in name
        or ("milestones" in text and name == "milestone_manifest.json")
        or ("phase_l1_freeze" in text and name == "milestone_manifest.json")
        or ("phase_l2_freeze" in text and name == "milestone_manifest.json")
    ):
        tags.add("freeze_proof")

    return tags


def candidate_score(label: str, path: Path) -> tuple[int, float]:
    text = norm(str(path))
    name = norm(path.name)
    score = 0

    if path.suffix.lower() in {".json", ".md", ".txt", ".log"}:
        score += 5

    if label == "baseline_manifest":
        if "release_snapshot" in name:
            score += 150
        if "baseline" in text:
            score += 50
        if "snapshot" in text:
            score += 40
        if "manifest" in text:
            score += 30

    elif label == "verification":
        if "latest_verification" in name:
            score += 150
        if "baseline_verification" in name:
            score += 120
        if "verification" in text:
            score += 50
        if "verify" in text:
            score += 30

    elif label == "drift_report":
        if "latest_drift_report" in name or "drift_report" in name:
            score += 150
        if "baseline_verification" in name:
            score += 120
        if "drift" in text:
            score += 40
        if "report" in text or "diff" in text:
            score += 30

    elif label == "drift_proof":
        if "latest_negative_proof" in name or "negative_proof" in name or "drift_proof" in name:
            score += 150
        if "controlled_drift" in name:
            score += 130
        if "negative" in text:
            score += 40
        if "proof" in text:
            score += 30
        if "simulation" in text:
            score += 20

    elif label == "freeze_proof":
        if "freeze_proof" in name or "freeze_gate" in name or "latest_freeze" in name:
            score += 150
        if name == "milestone_manifest.json" and "milestones" in text:
            score += 140
        if "phase_l2_freeze" in text:
            score += 60
        if "phase_l1_freeze" in text:
            score += 40
        if "freeze" in text:
            score += 50
        if "gate" in text:
            score += 20
        if "tag" in text or "milestone" in text:
            score += 20

    try:
        mtime = path.stat().st_mtime
    except Exception:
        mtime = 0.0

    return score, mtime


def find_best_candidate(root: Path, label: str) -> Path | None:
    candidates: list[Path] = []
    for path in iter_candidate_files(root):
        if label in classify_candidate(path):
            candidates.append(path)

    if not candidates:
        return None

    candidates.sort(key=lambda p: candidate_score(label, p), reverse=True)
    return candidates[0]


def discover_evidence(root: Path) -> dict[str, Path | None]:
    labels = (
        "baseline_manifest",
        "verification",
        "drift_report",
        "drift_proof",
        "freeze_proof",
    )
    return {label: find_best_candidate(root, label) for label in labels}


def parse_boolish(value) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "yes", "1", "pass", "passed", "ok", "success", "green", "frozen"}:
            return True
        if v in {"false", "no", "0", "fail", "failed", "error", "red"}:
            return False
    return None


def parse_status_from_text(text: str) -> str:
    t = text.lower()

    fail_markers = [
        "failed",
        "failure",
        "error",
        "mismatch",
        "drift detected",
        "violation",
        "not frozen",
        "freeze failed",
        '"freeze_status": "failed"',
    ]
    pass_markers = [
        "passed",
        "pass",
        "ok",
        "verified",
        "success",
        "clean",
        "no drift",
        "frozen",
        "freeze passed",
        "green",
        '"freeze_status": "frozen"',
    ]

    fail_hits = sum(1 for x in fail_markers if x in t)
    pass_hits = sum(1 for x in pass_markers if x in t)

    if fail_hits > 0 and fail_hits >= pass_hits:
        return "FAIL"
    if pass_hits > 0 and fail_hits == 0:
        return "PASS"
    return "UNKNOWN"


def parse_status_from_json(data, label: str) -> str:
    if not isinstance(data, dict):
        payload = json.dumps(data, ensure_ascii=False).lower()
        return parse_status_from_text(payload)

    if label == "baseline_manifest":
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

    for key in ("status", "result", "outcome"):
        if key in data:
            value = str(data[key]).strip().lower()
            if value in {"pass", "passed", "ok", "success", "verified", "green"}:
                return "PASS"
            if value in {"fail", "failed", "error", "red"}:
                return "FAIL"

    if label == "verification":
        drift_detected = parse_boolish(data.get("drift_detected"))
        drift_count = data.get("drift_count")
        if drift_detected is False and drift_count in (0, "0", None):
            return "PASS"
        if drift_detected is True:
            return "FAIL"

    if label == "drift_report":
        drift_detected = parse_boolish(data.get("drift_detected"))
        drift_count = data.get("drift_count")
        if drift_detected is False and drift_count in (0, "0", None):
            return "PASS"
        if drift_detected is True:
            return "FAIL"

    if label == "drift_proof":
        proof_passed = parse_boolish(data.get("proof_passed"))
        expected_failure_observed = parse_boolish(data.get("expected_failure_observed"))
        negative_proof_ok = parse_boolish(data.get("negative_proof_ok"))

        if True in {proof_passed, expected_failure_observed, negative_proof_ok}:
            return "PASS"
        if False in {proof_passed, expected_failure_observed, negative_proof_ok}:
            return "FAIL"

    if label == "freeze_proof":
        freeze_status = str(data.get("freeze_status", "")).strip().lower()
        if freeze_status == "frozen":
            return "PASS"
        if freeze_status in {"failed", "error"}:
            return "FAIL"

        frozen = parse_boolish(data.get("frozen"))
        freeze_ok = parse_boolish(data.get("freeze_ok"))
        if frozen is True or freeze_ok is True:
            return "PASS"
        if frozen is False or freeze_ok is False:
            return "FAIL"

        milestone_stage = str(data.get("milestone_stage", "")).strip().lower()
        release_stage = str(data.get("release_stage", "")).strip().lower()
        if "freeze" in milestone_stage or "freeze" in release_stage:
            return "PASS"

        freeze_gate = data.get("freeze_gate")
        if isinstance(freeze_gate, dict):
            baseline_status = str(freeze_gate.get("baseline_status", "")).strip().lower()
            verification_drift_detected = freeze_gate.get("verification_drift_detected")
            verification_drift_count = freeze_gate.get("verification_drift_count")
            failed_runs = freeze_gate.get("failed_runs")
            preflight_failed_runs = freeze_gate.get("preflight_failed_runs")

            if (
                baseline_status == "green"
                and verification_drift_detected is False
                and verification_drift_count == 0
                and failed_runs == 0
                and preflight_failed_runs == 0
            ):
                return "PASS"

    payload = json.dumps(data, ensure_ascii=False).lower()
    return parse_status_from_text(payload)


def parse_status(path: Path | None, label: str) -> str:
    if path is None or not path.exists():
        return "MISSING"
    try:
        if path.suffix.lower() == ".json":
            return parse_status_from_json(load_json(path), label)
        return parse_status_from_text(load_text(path))
    except Exception:
        return "UNKNOWN"


def extract_summary(path: Path | None, max_len: int = 1600) -> str:
    if path is None:
        return "NOT FOUND"
    try:
        if path.suffix.lower() == ".json":
            return json.dumps(load_json(path), ensure_ascii=False, indent=2)[:max_len].strip() or "EMPTY"
        txt = load_text(path).strip()
        return txt[:max_len] if txt else "EMPTY"
    except Exception as exc:
        return f"UNREADABLE: {exc}"


def normalize_label_filename(label: str, path: Path) -> str:
    safe_label = re.sub(r"[^a-zA-Z0-9_.-]+", "_", label)
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", path.name)
    return f"{safe_label}__{safe_name}"


def copy_evidence_bundle(evidence: dict[str, Path | None], bundle_dir: Path) -> list[dict]:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    items: list[dict] = []

    for label, src in evidence.items():
        if src is None or not src.exists():
            items.append(
                {
                    "label": label,
                    "status": "MISSING",
                    "source_path": None,
                    "bundle_path": None,
                    "sha256": None,
                    "size_bytes": None,
                }
            )
            continue

        dst = bundle_dir / normalize_label_filename(label, src)
        shutil.copy2(src, dst)

        items.append(
            {
                "label": label,
                "status": "COPIED",
                "source_path": safe_rel(src, ROOT),
                "bundle_path": safe_rel(dst, ROOT),
                "sha256": sha256_file(dst),
                "size_bytes": dst.stat().st_size,
            }
        )

    return items


def build_overall_status(statuses: dict[str, str]) -> str:
    values = set(statuses.values())
    if "FAIL" in values:
        return "FAIL"
    if "MISSING" in values:
        return "INCOMPLETE"
    if "UNKNOWN" in values:
        return "REVIEW_REQUIRED"
    if values == {"PASS"}:
        return "PASS"
    return "REVIEW_REQUIRED"


def zip_directory(directory: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in directory.rglob("*"):
            if path.is_file():
                arcname = path.relative_to(directory.parent)
                zf.write(path, arcname=str(arcname))


def build_markdown_report(
    milestone: str,
    generated_at: str,
    output_dir: Path,
    evidence: dict[str, Path | None],
    statuses: dict[str, str],
    snippets: dict[str, str],
    overall_status: str,
) -> str:
    titles = {
        "baseline_manifest": "Baseline Manifest",
        "verification": "Verification",
        "drift_report": "Drift Report",
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
    for key in ("baseline_manifest", "verification", "drift_report", "drift_proof", "freeze_proof"):
        lines.append(f"| {titles[key]} | {statuses[key]} | `{safe_rel(evidence[key], ROOT)}` |")
    lines.append("")
    lines.append("## Evidence Extracts")
    lines.append("")
    for key in ("baseline_manifest", "verification", "drift_report", "drift_proof", "freeze_proof"):
        lines.append(f"### {titles[key]}")
        lines.append("")
        lines.append(f"- Status: **{statuses[key]}**")
        lines.append(f"- Source: `{safe_rel(evidence[key], ROOT)}`")
        lines.append("")
        lines.append("```text")
        lines.append(snippets[key])
        lines.append("```")
        lines.append("")
    lines.append("## Bundle Contents")
    lines.append("")
    lines.append(f"- Bundle manifest: `{output_dir / 'evidence_bundle_manifest.json'}`")
    lines.append(f"- Bundle archive: `{output_dir / f'{milestone}_evidence_bundle.zip'}`")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def latest_auto_milestone_name() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("milestone_%Y%m%dT%H%M%SZ")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build freeze gate audit report + evidence bundle.")
    parser.add_argument("--milestone", default=latest_auto_milestone_name())
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    args = parser.parse_args()

    milestone = args.milestone.strip()
    output_root = Path(args.output_root).resolve()
    output_dir = output_root / milestone
    bundle_dir = output_dir / "evidence_bundle"

    generated_at = utc_now_iso()
    evidence = discover_evidence(ROOT)
    statuses = {label: parse_status(path, label) for label, path in evidence.items()}
    snippets = {label: extract_summary(path) for label, path in evidence.items()}
    overall_status = build_overall_status(statuses)

    output_dir.mkdir(parents=True, exist_ok=True)

    bundle_items = copy_evidence_bundle(evidence, bundle_dir)

    bundle_manifest = {
        "generated_at_utc": generated_at,
        "milestone": milestone,
        "project_root": str(ROOT),
        "overall_status": overall_status,
        "gate_statuses": statuses,
        "items": bundle_items,
    }
    write_json(output_dir / "evidence_bundle_manifest.json", bundle_manifest)

    summary = {
        "generated_at_utc": generated_at,
        "milestone": milestone,
        "overall_status": overall_status,
        "gate_statuses": statuses,
        "evidence_sources": {label: safe_rel(path, ROOT) if path else None for label, path in evidence.items()},
        "outputs": {
            "report_markdown": safe_rel(output_dir / "freeze_gate_audit_report.md", ROOT),
            "summary_json": safe_rel(output_dir / "freeze_gate_summary.json", ROOT),
            "bundle_manifest_json": safe_rel(output_dir / "evidence_bundle_manifest.json", ROOT),
            "bundle_archive_zip": safe_rel(output_dir / f"{milestone}_evidence_bundle.zip", ROOT),
        },
    }
    write_json(output_dir / "freeze_gate_summary.json", summary)

    report = build_markdown_report(
        milestone=milestone,
        generated_at=generated_at,
        output_dir=output_dir,
        evidence=evidence,
        statuses=statuses,
        snippets=snippets,
        overall_status=overall_status,
    )
    write_text(output_dir / "freeze_gate_audit_report.md", report)

    zip_directory(bundle_dir, output_dir / f"{milestone}_evidence_bundle.zip")

    print("=" * 72)
    print("FREEZE GATE AUDIT REPORT + EVIDENCE BUNDLE")
    print("=" * 72)
    print(f"MILESTONE     : {milestone}")
    print(f"GENERATED UTC : {generated_at}")
    print(f"OVERALL       : {overall_status}")
    print("-" * 72)
    for key in ("baseline_manifest", "verification", "drift_report", "drift_proof", "freeze_proof"):
        print(f"{key:18} {statuses[key]:15} {safe_rel(evidence[key], ROOT)}")
    print("-" * 72)
    print(f"REPORT        : {safe_rel(output_dir / 'freeze_gate_audit_report.md', ROOT)}")
    print(f"SUMMARY JSON  : {safe_rel(output_dir / 'freeze_gate_summary.json', ROOT)}")
    print(f"BUNDLE MANIFEST: {safe_rel(output_dir / 'evidence_bundle_manifest.json', ROOT)}")
    print(f"BUNDLE ZIP    : {safe_rel(output_dir / f'{milestone}_evidence_bundle.zip', ROOT)}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
