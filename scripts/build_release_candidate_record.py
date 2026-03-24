#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUDIT_ROOT = ROOT / "artifacts" / "audit"
FREEZE_GATE_ROOT = ROOT / "artifacts" / "freeze_gate"
RC_ROOT = ROOT / "artifacts" / "release_candidates"
RC_RECORDS_ROOT = AUDIT_ROOT / "release_candidate_records"
AUDIT_INDEX_PATH = AUDIT_ROOT / "immutable_audit_index.jsonl"

REQUIRED_FREEZE_FILES = (
    "freeze_gate_audit_report.md",
    "freeze_gate_summary.json",
    "evidence_bundle_manifest.json",
)

REQUIRED_AUDIT_FILES = (
    "signed_milestone_record.json",
    "signed_milestone_digest_report.json",
    "signed_milestone_record.md",
)


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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


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


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def latest_index_entry_sha256(index_path: Path) -> str | None:
    if not index_path.exists() or not index_path.is_file():
        return None

    last_nonempty = None
    with index_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last_nonempty = line

    if last_nonempty is None:
        return None

    obj = json.loads(last_nonempty)
    entry_sha256 = obj.get("entry_sha256")
    if not isinstance(entry_sha256, str) or not entry_sha256:
        raise ValueError("Latest audit index entry does not contain a valid entry_sha256.")
    return entry_sha256


def append_jsonl(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


def require_dir(path: Path) -> Path:
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Required directory missing: {path}")
    return path


def load_freeze_gate_bundle(milestone: str) -> dict:
    freeze_dir = require_dir(FREEZE_GATE_ROOT / milestone)

    files = {}
    for name in REQUIRED_FREEZE_FILES:
        files[name] = require_file(freeze_dir / name)

    bundle_zip = require_file(freeze_dir / f"{milestone}_evidence_bundle.zip")
    files[f"{milestone}_evidence_bundle.zip"] = bundle_zip

    summary = read_json(files["freeze_gate_summary.json"])
    report = files["freeze_gate_audit_report.md"]
    manifest = read_json(files["evidence_bundle_manifest.json"])

    return {
        "freeze_dir": freeze_dir,
        "files": files,
        "summary": summary,
        "report_path": report,
        "manifest": manifest,
    }


def load_milestone_audit_bundle(milestone: str) -> dict:
    record_dir = require_dir(AUDIT_ROOT / "milestone_records" / milestone)

    files = {}
    for name in REQUIRED_AUDIT_FILES:
        files[name] = require_file(record_dir / name)

    signed_record = read_json(files["signed_milestone_record.json"])
    digest_report = read_json(files["signed_milestone_digest_report.json"])

    return {
        "record_dir": record_dir,
        "files": files,
        "signed_record": signed_record,
        "digest_report": digest_report,
    }


def load_chain_verification(label: str) -> dict:
    verification_dir = require_dir(AUDIT_ROOT / "verification" / label)
    summary_path = require_file(verification_dir / "audit_chain_verification_summary.json")
    report_path = require_file(verification_dir / "audit_chain_verification_report.md")

    summary = read_json(summary_path)

    return {
        "verification_dir": verification_dir,
        "summary_path": summary_path,
        "report_path": report_path,
        "summary": summary,
    }


def evaluate_promotion_gate(
    milestone: str,
    rc_name: str,
    freeze_bundle: dict,
    audit_bundle: dict,
    chain_bundle: dict,
) -> dict:
    freeze_summary = freeze_bundle["summary"]
    freeze_manifest = freeze_bundle["manifest"]
    signed_record = audit_bundle["signed_record"]
    digest_report = audit_bundle["digest_report"]
    chain_summary = chain_bundle["summary"]

    checks = {
        "freeze_gate_pass": str(freeze_summary.get("overall_status", "")).upper() == "PASS",
        "all_freeze_gate_statuses_pass": all(
            str(v).upper() == "PASS"
            for v in dict(freeze_summary.get("gate_statuses", {})).values()
        ),
        "bundle_manifest_pass": str(freeze_manifest.get("overall_status", "")).upper() == "PASS",
        "signed_milestone_record_pass": str(signed_record.get("freeze_gate_overall_status", "")).upper() == "PASS",
        "digest_report_has_record_sha256": bool(digest_report.get("record_sha256")),
        "audit_chain_verification_pass": str(chain_summary.get("overall_status", "")).upper() == "PASS",
        "audit_chain_has_no_failed_entries": int(chain_summary.get("failed_entries", 0)) == 0,
    }

    promotion_allowed = all(checks.values())

    decision = {
        "decision_type": "release_candidate_promotion_gate",
        "generated_at_utc": now_utc(),
        "milestone": milestone,
        "release_candidate": rc_name,
        "promotion_allowed": promotion_allowed,
        "promotion_status": "PASS" if promotion_allowed else "FAIL",
        "checks": checks,
        "evidence": {
            "freeze_gate_summary_path": rel(freeze_bundle["files"]["freeze_gate_summary.json"]),
            "freeze_gate_report_path": rel(freeze_bundle["report_path"]),
            "freeze_bundle_manifest_path": rel(freeze_bundle["files"]["evidence_bundle_manifest.json"]),
            "freeze_bundle_zip_path": rel(freeze_bundle["files"][f"{milestone}_evidence_bundle.zip"]),
            "signed_milestone_record_path": rel(audit_bundle["files"]["signed_milestone_record.json"]),
            "signed_milestone_digest_report_path": rel(audit_bundle["files"]["signed_milestone_digest_report.json"]),
            "audit_chain_summary_path": rel(chain_bundle["summary_path"]),
            "audit_chain_report_path": rel(chain_bundle["report_path"]),
        },
        "audit_chain_contract": {
            "link_field": "previous_entry_sha256",
            "link_target": "previous.entry_sha256",
            "contract_version": 2,
        },
    }

    return decision


def build_rc_artifact_digests(paths: list[Path]) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(paths, key=lambda p: str(p)):
        rows.append(
            {
                "path": rel(path),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return rows


def build_rc_record(
    milestone: str,
    rc_name: str,
    promotion_gate: dict,
    freeze_bundle: dict,
    audit_bundle: dict,
    chain_bundle: dict,
) -> dict:
    return {
        "record_version": 2,
        "record_type": "release_candidate_record",
        "signature_type": "sha256_canonical_record",
        "generated_at_utc": now_utc(),
        "milestone": milestone,
        "release_candidate": rc_name,
        "promotion_status": promotion_gate["promotion_status"],
        "promotion_allowed": promotion_gate["promotion_allowed"],
        "promotion_gate_checks": promotion_gate["checks"],
        "evidence_paths": promotion_gate["evidence"],
        "source_summaries": {
            "freeze_gate_overall_status": freeze_bundle["summary"].get("overall_status"),
            "freeze_gate_statuses": freeze_bundle["summary"].get("gate_statuses"),
            "signed_milestone_overall_status": audit_bundle["signed_record"].get("freeze_gate_overall_status"),
            "audit_chain_overall_status": chain_bundle["summary"].get("overall_status"),
            "audit_chain_total_entries": chain_bundle["summary"].get("total_entries"),
            "audit_chain_failed_entries": chain_bundle["summary"].get("failed_entries"),
        },
        "audit_chain_contract": {
            "link_field": "previous_entry_sha256",
            "link_target": "previous.entry_sha256",
            "contract_version": 2,
        },
    }


def build_markdown_report(
    milestone: str,
    rc_name: str,
    promotion_gate: dict,
    rc_record_path: Path,
    digest_report_path: Path,
    index_path: Path,
) -> str:
    lines: list[str] = []
    lines.append(f"# Release Candidate Promotion Gate — {rc_name}")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{promotion_gate['generated_at_utc']}`")
    lines.append(f"- Milestone: `{milestone}`")
    lines.append(f"- Release Candidate: `{rc_name}`")
    lines.append(f"- Promotion status: **{promotion_gate['promotion_status']}**")
    lines.append(f"- Promotion allowed: **{promotion_gate['promotion_allowed']}**")
    lines.append(f"- RC record path: `{rel(rc_record_path)}`")
    lines.append(f"- Digest report path: `{rel(digest_report_path)}`")
    lines.append(f"- Audit index path: `{rel(index_path)}`")
    lines.append("")
    lines.append("## Gate Checks")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|---|---|")
    for key, value in promotion_gate["checks"].items():
        lines.append(f"| {key} | {'PASS' if value else 'FAIL'} |")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    lines.append("| Name | Path |")
    lines.append("|---|---|")
    for key, value in promotion_gate["evidence"].items():
        lines.append(f"| {key} | `{value}` |")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build release candidate record and append immutable audit index entry."
    )
    parser.add_argument("--milestone", required=True, help="Milestone name under artifacts/freeze_gate/")
    parser.add_argument("--rc-name", required=True, help="Release candidate identifier, for example RC1")
    parser.add_argument(
        "--chain-label",
        required=True,
        help="Audit chain verification label under artifacts/audit/verification/",
    )
    args = parser.parse_args()

    milestone = args.milestone.strip()
    rc_name = args.rc_name.strip()
    chain_label = args.chain_label.strip()

    if not milestone:
        raise SystemExit("Milestone must not be empty.")
    if not rc_name:
        raise SystemExit("RC name must not be empty.")
    if not chain_label:
        raise SystemExit("Chain label must not be empty.")

    freeze_bundle = load_freeze_gate_bundle(milestone)
    audit_bundle = load_milestone_audit_bundle(milestone)
    chain_bundle = load_chain_verification(chain_label)

    promotion_gate = evaluate_promotion_gate(
        milestone=milestone,
        rc_name=rc_name,
        freeze_bundle=freeze_bundle,
        audit_bundle=audit_bundle,
        chain_bundle=chain_bundle,
    )

    if not promotion_gate["promotion_allowed"]:
        raise SystemExit(
            f"Promotion gate failed for milestone={milestone}, rc={rc_name}. Refusing to create RC record."
        )

    rc_dir = RC_ROOT / rc_name
    rc_dir.mkdir(parents=True, exist_ok=True)

    promotion_gate_path = rc_dir / "promotion_gate_decision.json"
    write_json(promotion_gate_path, promotion_gate)

    rc_record_core = build_rc_record(
        milestone=milestone,
        rc_name=rc_name,
        promotion_gate=promotion_gate,
        freeze_bundle=freeze_bundle,
        audit_bundle=audit_bundle,
        chain_bundle=chain_bundle,
    )
    rc_record_canonical = canonical_json(rc_record_core)
    rc_record = {
        **rc_record_core,
        "canonical_payload_sha256": sha256_bytes(rc_record_canonical.encode("utf-8")),
        "canonical_payload_preview": rc_record_canonical[:4000],
    }

    rc_record_path = rc_dir / "release_candidate_record.json"
    write_json(rc_record_path, rc_record)

    rc_digest_paths = [
        promotion_gate_path,
        rc_record_path,
        freeze_bundle["files"]["freeze_gate_summary.json"],
        freeze_bundle["files"]["freeze_gate_audit_report.md"],
        freeze_bundle["files"]["evidence_bundle_manifest.json"],
        freeze_bundle["files"][f"{milestone}_evidence_bundle.zip"],
        audit_bundle["files"]["signed_milestone_record.json"],
        audit_bundle["files"]["signed_milestone_digest_report.json"],
        chain_bundle["summary_path"],
        chain_bundle["report_path"],
    ]
    rc_digests = build_rc_artifact_digests(rc_digest_paths)

    digest_report = {
        "generated_at_utc": now_utc(),
        "milestone": milestone,
        "release_candidate": rc_name,
        "promotion_status": promotion_gate["promotion_status"],
        "promotion_allowed": promotion_gate["promotion_allowed"],
        "artifacts": rc_digests,
        "audit_chain_contract": {
            "link_field": "previous_entry_sha256",
            "link_target": "previous.entry_sha256",
            "contract_version": 2,
        },
    }
    digest_report_path = rc_dir / "release_candidate_digest_report.json"
    write_json(digest_report_path, digest_report)

    rc_md_path = rc_dir / "release_candidate_record.md"
    write_text(
        rc_md_path,
        build_markdown_report(
            milestone=milestone,
            rc_name=rc_name,
            promotion_gate=promotion_gate,
            rc_record_path=rc_record_path,
            digest_report_path=digest_report_path,
            index_path=AUDIT_INDEX_PATH,
        ),
    )

    audit_record_dir = RC_RECORDS_ROOT / rc_name
    audit_record_dir.mkdir(parents=True, exist_ok=True)

    mirrored_record_path = audit_record_dir / "release_candidate_record.json"
    mirrored_digest_path = audit_record_dir / "release_candidate_digest_report.json"
    mirrored_md_path = audit_record_dir / "release_candidate_record.md"

    write_json(mirrored_record_path, rc_record)
    write_json(mirrored_digest_path, digest_report)
    write_text(mirrored_md_path, read_text(rc_md_path))

    previous_entry_sha256 = latest_index_entry_sha256(AUDIT_INDEX_PATH)
    index_entry_core = {
        "index_version": 2,
        "entry_type": "release_candidate_record",
        "link_mode": "entry_sha256",
        "appended_at_utc": now_utc(),
        "milestone": milestone,
        "release_candidate": rc_name,
        "record_path": rel(mirrored_record_path),
        "record_sha256": sha256_file(mirrored_record_path),
        "promotion_gate_path": rel(promotion_gate_path),
        "digest_report_path": rel(mirrored_digest_path),
        "overall_status": promotion_gate["promotion_status"],
        "previous_entry_sha256": previous_entry_sha256,
    }
    index_entry_canonical = canonical_json(index_entry_core)
    index_entry = {
        **index_entry_core,
        "entry_sha256": sha256_bytes(index_entry_canonical.encode("utf-8")),
    }
    append_jsonl(AUDIT_INDEX_PATH, index_entry)

    print("=" * 72)
    print("RELEASE CANDIDATE PROMOTION GATE + RC RECORD")
    print("=" * 72)
    print(f"MILESTONE        : {milestone}")
    print(f"RELEASE CANDIDATE: {rc_name}")
    print(f"PROMOTION STATUS : {promotion_gate['promotion_status']}")
    print(f"PROMOTION GATE   : {rel(promotion_gate_path)}")
    print(f"RC RECORD JSON   : {rel(mirrored_record_path)}")
    print(f"RC RECORD MD     : {rel(mirrored_md_path)}")
    print(f"DIGEST REPORT    : {rel(mirrored_digest_path)}")
    print(f"AUDIT INDEX      : {rel(AUDIT_INDEX_PATH)}")
    print(f"INDEX ENTRY HASH : {index_entry['entry_sha256']}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
