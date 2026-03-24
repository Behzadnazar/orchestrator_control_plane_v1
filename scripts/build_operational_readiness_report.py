#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUDIT_ROOT = ROOT / "artifacts" / "audit"
OUTPUT_ROOT = ROOT / "artifacts" / "operations"


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


def require_dir(path: Path) -> Path:
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Required directory missing: {path}")
    return path


def load_index_entries(index_path: Path) -> list[dict]:
    entries: list[dict] = []
    with require_file(index_path).open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            obj["_line_number"] = lineno
            entries.append(obj)
    return entries


def build_checks(
    closure_report: dict,
    latest_chain_summary: dict,
    latest_matrix_summary: dict,
    index_entries: list[dict],
    milestone_dir: Path,
    rc_dir: Path,
) -> dict:
    checks = {
        "closure_report_pass": str(closure_report.get("closure_status", "")).upper() == "PASS",
        "closure_readiness_declared": str(closure_report.get("governance_readiness", "")).upper() == "LOCAL_PRODUCTION_GOVERNANCE_READY",
        "latest_chain_pass": str(latest_chain_summary.get("overall_status", "")).upper() == "PASS",
        "latest_chain_failed_entries_zero": int(latest_chain_summary.get("failed_entries", -1)) == 0,
        "latest_matrix_pass": str(latest_matrix_summary.get("proof_status", "")).upper() == "PASS",
        "latest_matrix_failed_scenarios_zero": int(latest_matrix_summary.get("coverage", {}).get("failed_scenarios", -1)) == 0,
        "audit_index_has_entries": len(index_entries) >= 1,
        "audit_index_link_mode_v2_only": all(str(x.get("link_mode", "")) == "entry_sha256" for x in index_entries),
        "milestone_records_exist": any(milestone_dir.rglob("signed_milestone_record.json")),
        "release_candidate_records_exist": any(rc_dir.rglob("release_candidate_record.json")),
    }
    return checks


def build_scope(index_entries: list[dict], milestone_dir: Path, rc_dir: Path) -> dict:
    milestone_records = sorted(str(p.parent.name) for p in milestone_dir.rglob("signed_milestone_record.json"))
    rc_records = sorted(str(p.parent.name) for p in rc_dir.rglob("release_candidate_record.json"))

    return {
        "total_audit_index_entries": len(index_entries),
        "milestone_record_count": len(milestone_records),
        "release_candidate_record_count": len(rc_records),
        "milestone_records": milestone_records,
        "release_candidate_records": rc_records,
        "audit_entry_types": sorted({str(x.get("entry_type")) for x in index_entries}),
        "latest_index_entry_type": str(index_entries[-1].get("entry_type")) if index_entries else None,
        "latest_index_entry_line": index_entries[-1].get("_line_number") if index_entries else None,
    }


def build_limitations() -> list[str]:
    return [
        "No asymmetric cryptographic signatures are implemented.",
        "No WORM or OS-enforced immutability layer is implemented.",
        "Operational readiness is local-scope only, not external compliance certification.",
        "Tamper coverage is limited to defined matrix scenarios.",
        "Evidence-family diversity is still limited and partially shared across milestones.",
        "This report proves governance readiness for controlled local operation, not adversarial internet-scale trust.",
    ]


def build_markdown_report(
    generated_at: str,
    label: str,
    status: str,
    readiness: str,
    checks: dict,
    scope: dict,
    sources: dict,
    limitations: list[str],
    output_dir: Path,
) -> str:
    lines: list[str] = []
    lines.append("# Operational Readiness Report")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{generated_at}`")
    lines.append(f"- Label: `{label}`")
    lines.append(f"- Status: **{status}**")
    lines.append(f"- Readiness: **{readiness}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Preflight Checks")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|---|---|")
    for key, value in checks.items():
        lines.append(f"| {key} | {'PASS' if value else 'FAIL'} |")
    lines.append("")
    lines.append("## Scope Snapshot")
    lines.append("")
    lines.append(f"- Total audit index entries: **{scope['total_audit_index_entries']}**")
    lines.append(f"- Milestone record count: **{scope['milestone_record_count']}**")
    lines.append(f"- Release candidate record count: **{scope['release_candidate_record_count']}**")
    lines.append(f"- Audit entry types: `{', '.join(scope['audit_entry_types'])}`")
    lines.append(f"- Latest index entry type: `{scope['latest_index_entry_type']}`")
    lines.append(f"- Latest index entry line: `{scope['latest_index_entry_line']}`")
    lines.append("")
    lines.append("## Source Artifacts")
    lines.append("")
    lines.append("| Name | Path |")
    lines.append("|---|---|")
    for key, value in sources.items():
        lines.append(f"| {key} | `{value}` |")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for item in limitations:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Final Operational Declaration")
    lines.append("")
    if status == "PASS":
        lines.append(
            "The governance layer is operationally ready for controlled local use. Preflight governance checks, chain verification, milestone/RC record presence, and tamper-matrix evidence are all in a passing state."
        )
    else:
        lines.append(
            "The governance layer is not yet operationally ready. One or more mandatory readiness checks failed and must be corrected before controlled operation."
        )
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build operational readiness report from governance closure and latest verification artifacts."
    )
    parser.add_argument("--label", default="Q1_operational_readiness")
    parser.add_argument(
        "--closure-label",
        default="P1_governance_closure",
        help="Closure label under artifacts/audit/closure/",
    )
    parser.add_argument(
        "--chain-label",
        default="O3_post_matrix_restore_check",
        help="Latest chain verification label under artifacts/audit/verification/",
    )
    parser.add_argument(
        "--matrix-label",
        default="O3_independent_tamper_matrix",
        help="Latest tamper matrix label under artifacts/audit/tamper_matrix/",
    )
    args = parser.parse_args()

    label = args.label.strip()
    closure_label = args.closure_label.strip()
    chain_label = args.chain_label.strip()
    matrix_label = args.matrix_label.strip()

    if not label:
        raise SystemExit("Label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output already exists: {output_dir}")

    closure_json_path = require_file(AUDIT_ROOT / "closure" / closure_label / "governance_closure_report.json")
    closure_md_path = require_file(AUDIT_ROOT / "closure" / closure_label / "governance_closure_report.md")
    chain_summary_path = require_file(AUDIT_ROOT / "verification" / chain_label / "audit_chain_verification_summary.json")
    matrix_summary_path = require_file(AUDIT_ROOT / "tamper_matrix" / matrix_label / "tamper_matrix_summary.json")
    index_path = require_file(AUDIT_ROOT / "immutable_audit_index.jsonl")
    milestone_dir = require_dir(AUDIT_ROOT / "milestone_records")
    rc_dir = require_dir(AUDIT_ROOT / "release_candidate_records")

    closure_report = read_json(closure_json_path)
    latest_chain_summary = read_json(chain_summary_path)
    latest_matrix_summary = read_json(matrix_summary_path)
    index_entries = load_index_entries(index_path)

    checks = build_checks(
        closure_report=closure_report,
        latest_chain_summary=latest_chain_summary,
        latest_matrix_summary=latest_matrix_summary,
        index_entries=index_entries,
        milestone_dir=milestone_dir,
        rc_dir=rc_dir,
    )
    scope = build_scope(index_entries=index_entries, milestone_dir=milestone_dir, rc_dir=rc_dir)
    limitations = build_limitations()

    status = "PASS" if all(checks.values()) else "FAIL"
    readiness = "CONTROLLED_LOCAL_OPERATION_READY" if status == "PASS" else "NOT_READY"

    generated_at = now_utc()
    sources = {
        "closure_report_json": rel(closure_json_path),
        "closure_report_md": rel(closure_md_path),
        "latest_chain_summary": rel(chain_summary_path),
        "latest_matrix_summary": rel(matrix_summary_path),
        "immutable_audit_index": rel(index_path),
        "milestone_records_dir": rel(milestone_dir),
        "release_candidate_records_dir": rel(rc_dir),
    }

    report = {
        "report_version": 1,
        "report_type": "operational_readiness_report",
        "generated_at_utc": generated_at,
        "label": label,
        "status": status,
        "readiness": readiness,
        "checks": checks,
        "scope": scope,
        "sources": sources,
        "limitations": limitations,
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    json_path = output_dir / "operational_readiness_report.json"
    md_path = output_dir / "operational_readiness_report.md"
    digest_path = output_dir / "operational_readiness_digest_report.json"

    write_json(json_path, report)
    write_text(
        md_path,
        build_markdown_report(
            generated_at=generated_at,
            label=label,
            status=status,
            readiness=readiness,
            checks=checks,
            scope=scope,
            sources=sources,
            limitations=limitations,
            output_dir=output_dir,
        ),
    )

    digest_report = {
        "generated_at_utc": generated_at,
        "label": label,
        "status": status,
        "artifacts": [
            {
                "path": rel(json_path),
                "size_bytes": json_path.stat().st_size,
                "sha256": sha256_file(json_path),
            },
            {
                "path": rel(md_path),
                "size_bytes": md_path.stat().st_size,
                "sha256": sha256_file(md_path),
            },
        ],
    }
    write_json(digest_path, digest_report)

    print("=" * 72)
    print("OPERATIONAL READINESS REPORT")
    print("=" * 72)
    print(f"LABEL         : {label}")
    print(f"STATUS        : {status}")
    print(f"READINESS     : {readiness}")
    print(f"REPORT JSON   : {rel(json_path)}")
    print(f"REPORT MD     : {rel(md_path)}")
    print(f"DIGEST REPORT : {rel(digest_path)}")
    print("=" * 72)

    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
