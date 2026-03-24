#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUDIT_ROOT = ROOT / "artifacts" / "audit"
AUDIT_INDEX_PATH = AUDIT_ROOT / "immutable_audit_index.jsonl"
OUTPUT_ROOT = AUDIT_ROOT / "verification"


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


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


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def load_index_entries(index_path: Path) -> list[dict]:
    if not index_path.exists() or not index_path.is_file():
        raise FileNotFoundError(f"Audit index not found: {index_path}")

    entries: list[dict] = []
    with index_path.open("r", encoding="utf-8") as f:
        for lineno, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at line {lineno}: {exc}") from exc

            if not isinstance(obj, dict):
                raise ValueError(f"Invalid index entry type at line {lineno}: expected object")

            obj["_line_number"] = lineno
            entries.append(obj)

    return entries


def verify_entry_hash(entry: dict) -> tuple[bool, str | None, str | None]:
    recorded = entry.get("entry_sha256")
    if not isinstance(recorded, str) or not recorded:
        return False, recorded, None

    core = {k: v for k, v in entry.items() if not k.startswith("_") and k != "entry_sha256"}
    computed = sha256_bytes(canonical_json(core).encode("utf-8"))
    return computed == recorded, recorded, computed


def verify_chain(entries: list[dict], allow_legacy_raw_line_links: bool) -> tuple[list[dict], str]:
    results: list[dict] = []
    any_fail = False

    previous_entry_sha256 = None
    previous_raw_line_sha256 = None

    for entry in entries:
        line_number = entry["_line_number"]
        milestone = entry.get("milestone")
        link_mode = entry.get("link_mode", "legacy_unknown")

        hash_ok, recorded_entry_sha256, computed_entry_sha256 = verify_entry_hash(entry)

        recorded_previous = entry.get("previous_entry_sha256")

        expected_previous_entry_sha256 = previous_entry_sha256
        expected_previous_raw_line_sha256 = previous_raw_line_sha256

        previous_link_contract_ok = recorded_previous == expected_previous_entry_sha256

        previous_link_legacy_ok = False
        previous_link_mode_resolved = "entry_sha256"
        if not previous_link_contract_ok and allow_legacy_raw_line_links:
            previous_link_legacy_ok = recorded_previous == expected_previous_raw_line_sha256
            if previous_link_legacy_ok:
                previous_link_mode_resolved = "legacy_raw_line_sha256"

        previous_link_ok = previous_link_contract_ok or previous_link_legacy_ok

        record_path_value = entry.get("record_path")
        record_path = ROOT / record_path_value if isinstance(record_path_value, str) else None
        record_exists = bool(record_path and record_path.exists() and record_path.is_file())

        record_file_sha256 = None
        record_sha256_matches = None
        recorded_record_sha256 = entry.get("record_sha256")

        if record_exists:
            record_file_sha256 = sha256_file(record_path)
            record_sha256_matches = record_file_sha256 == recorded_record_sha256

        entry_ok = bool(
            hash_ok
            and previous_link_ok
            and record_exists
            and record_sha256_matches is True
        )

        if not entry_ok:
            any_fail = True

        canonical_line_without_entry_hash = {
            k: v for k, v in entry.items() if not k.startswith("_") and k != "entry_sha256"
        }
        raw_line_sha256_for_compat = sha256_bytes(
            json.dumps(entry, ensure_ascii=False, sort_keys=True).encode("utf-8")
        )

        results.append(
            {
                "line_number": line_number,
                "milestone": milestone,
                "release_candidate": entry.get("release_candidate"),
                "entry_type": entry.get("entry_type"),
                "link_mode_declared": link_mode,
                "link_mode_resolved": previous_link_mode_resolved,
                "record_path": record_path_value,
                "record_exists": record_exists,
                "recorded_record_sha256": recorded_record_sha256,
                "computed_record_sha256": record_file_sha256,
                "record_sha256_matches": record_sha256_matches,
                "recorded_previous_entry_sha256": recorded_previous,
                "expected_previous_entry_sha256": expected_previous_entry_sha256,
                "expected_previous_raw_line_sha256": expected_previous_raw_line_sha256,
                "previous_link_contract_ok": previous_link_contract_ok,
                "previous_link_legacy_ok": previous_link_legacy_ok,
                "previous_link_ok": previous_link_ok,
                "recorded_entry_sha256": recorded_entry_sha256,
                "computed_entry_sha256": computed_entry_sha256,
                "entry_hash_ok": hash_ok,
                "entry_ok": entry_ok,
                "entry_core_preview": canonical_json(canonical_line_without_entry_hash)[:1200],
                "raw_line_sha256_for_compat": raw_line_sha256_for_compat,
            }
        )

        previous_entry_sha256 = recorded_entry_sha256
        previous_raw_line_sha256 = raw_line_sha256_for_compat

    overall_status = "PASS" if not any_fail else "FAIL"
    return results, overall_status


def build_summary(entries: list[dict], results: list[dict], overall_status: str, allow_legacy_raw_line_links: bool) -> dict:
    total_entries = len(entries)
    ok_entries = sum(1 for r in results if r["entry_ok"])
    failed_entries = total_entries - ok_entries

    return {
        "generated_at_utc": now_utc(),
        "verification_type": "immutable_audit_chain_verification",
        "index_path": rel(AUDIT_INDEX_PATH),
        "overall_status": overall_status,
        "allow_legacy_raw_line_links": allow_legacy_raw_line_links,
        "contract_rule": "previous_entry_sha256 must equal previous entry's entry_sha256",
        "total_entries": total_entries,
        "ok_entries": ok_entries,
        "failed_entries": failed_entries,
        "results": results,
    }


def build_markdown_report(summary: dict, output_dir: Path) -> str:
    lines: list[str] = []
    lines.append("# Immutable Audit Chain Verification Report")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Index path: `{summary['index_path']}`")
    lines.append(f"- Overall status: **{summary['overall_status']}**")
    lines.append(f"- Legacy raw-line links allowed: **{summary['allow_legacy_raw_line_links']}**")
    lines.append(f"- Contract rule: `{summary['contract_rule']}`")
    lines.append(f"- Total entries: **{summary['total_entries']}**")
    lines.append(f"- OK entries: **{summary['ok_entries']}**")
    lines.append(f"- Failed entries: **{summary['failed_entries']}**")
    lines.append(f"- Output directory: `{rel(output_dir)}`")
    lines.append("")
    lines.append("## Entry Matrix")
    lines.append("")
    lines.append("| Line | Type | Milestone | RC | Entry Hash | Previous Link | Link Mode | Record Exists | Record SHA256 | Entry OK |")
    lines.append("|---:|---|---|---|---|---|---|---|---|---|")

    for r in summary["results"]:
        lines.append(
            f"| {r['line_number']} | {r['entry_type']} | {r['milestone']} | {r['release_candidate']} | "
            f"{'OK' if r['entry_hash_ok'] else 'FAIL'} | "
            f"{'OK' if r['previous_link_ok'] else 'FAIL'} | "
            f"{r['link_mode_resolved']} | "
            f"{'OK' if r['record_exists'] else 'FAIL'} | "
            f"{'OK' if r['record_sha256_matches'] else 'FAIL'} | "
            f"{'OK' if r['entry_ok'] else 'FAIL'} |"
        )

    lines.append("")
    lines.append("## Detailed Results")
    lines.append("")

    for r in summary["results"]:
        lines.append(f"### Line {r['line_number']} — {r['entry_type']}")
        lines.append("")
        lines.append(f"- Milestone: `{r['milestone']}`")
        lines.append(f"- Release candidate: `{r['release_candidate']}`")
        lines.append(f"- Entry OK: **{'YES' if r['entry_ok'] else 'NO'}**")
        lines.append(f"- Declared link mode: `{r['link_mode_declared']}`")
        lines.append(f"- Resolved link mode: `{r['link_mode_resolved']}`")
        lines.append(f"- Record path: `{r['record_path']}`")
        lines.append(f"- Recorded entry SHA256: `{r['recorded_entry_sha256']}`")
        lines.append(f"- Computed entry SHA256: `{r['computed_entry_sha256']}`")
        lines.append(f"- Recorded previous entry SHA256: `{r['recorded_previous_entry_sha256']}`")
        lines.append(f"- Expected previous entry SHA256: `{r['expected_previous_entry_sha256']}`")
        lines.append(f"- Expected previous raw-line SHA256: `{r['expected_previous_raw_line_sha256']}`")
        lines.append(f"- Recorded record SHA256: `{r['recorded_record_sha256']}`")
        lines.append(f"- Computed record SHA256: `{r['computed_record_sha256']}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify immutable audit index chain and detect tampering/truncation mismatches."
    )
    parser.add_argument(
        "--label",
        default=dt.datetime.now(dt.timezone.utc).strftime("audit_chain_check_%Y%m%dT%H%M%SZ"),
        help="Verification output label.",
    )
    parser.add_argument(
        "--allow-legacy-raw-line-links",
        action="store_true",
        help="Allow old entries whose previous_entry_sha256 points to the previous raw JSONL line SHA256.",
    )
    args = parser.parse_args()

    label = args.label.strip()
    if not label:
        raise SystemExit("Label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    output_dir.mkdir(parents=True, exist_ok=True)

    entries = load_index_entries(AUDIT_INDEX_PATH)
    results, overall_status = verify_chain(entries, allow_legacy_raw_line_links=args.allow_legacy_raw_line_links)
    summary = build_summary(entries, results, overall_status, args.allow_legacy_raw_line_links)

    summary_path = output_dir / "audit_chain_verification_summary.json"
    report_path = output_dir / "audit_chain_verification_report.md"

    write_json(summary_path, summary)
    write_text(report_path, build_markdown_report(summary, output_dir))

    print("=" * 72)
    print("IMMUTABLE AUDIT CHAIN VERIFICATION")
    print("=" * 72)
    print(f"LABEL          : {label}")
    print(f"INDEX PATH     : {rel(AUDIT_INDEX_PATH)}")
    print(f"OVERALL STATUS : {overall_status}")
    print(f"TOTAL ENTRIES  : {summary['total_entries']}")
    print(f"OK ENTRIES     : {summary['ok_entries']}")
    print(f"FAILED ENTRIES : {summary['failed_entries']}")
    print(f"LEGACY MODE    : {args.allow_legacy_raw_line_links}")
    print("-" * 72)
    print(f"SUMMARY JSON   : {rel(summary_path)}")
    print(f"REPORT MD      : {rel(report_path)}")
    print("=" * 72)

    return 0 if overall_status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
