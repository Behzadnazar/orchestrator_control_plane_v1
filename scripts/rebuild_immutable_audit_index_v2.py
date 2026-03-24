#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUDIT_ROOT = ROOT / "artifacts" / "audit"
INDEX_PATH = AUDIT_ROOT / "immutable_audit_index.jsonl"
BACKUP_ROOT = AUDIT_ROOT / "index_backups"
MILESTONE_RECORDS_ROOT = AUDIT_ROOT / "milestone_records"
RC_RECORDS_ROOT = AUDIT_ROOT / "release_candidate_records"


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path):
    return json.loads(read_text(path))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


def discover_milestone_entries() -> list[dict]:
    items: list[dict] = []
    if not MILESTONE_RECORDS_ROOT.exists():
        return items

    for record_path in sorted(MILESTONE_RECORDS_ROOT.rglob("signed_milestone_record.json")):
        record = read_json(record_path)
        milestone = record.get("milestone")
        if not isinstance(milestone, str) or not milestone:
            raise ValueError(f"Invalid milestone in {record_path}")

        freeze_dir = ROOT / str(record.get("freeze_gate_directory"))
        freeze_summary_path = freeze_dir / "freeze_gate_summary.json"
        freeze_report_path = freeze_dir / "freeze_gate_audit_report.md"
        bundle_manifest_path = freeze_dir / "evidence_bundle_manifest.json"
        bundle_zip_path = freeze_dir / f"{milestone}_evidence_bundle.zip"

        require_file(freeze_summary_path)
        require_file(freeze_report_path)
        require_file(bundle_manifest_path)
        require_file(bundle_zip_path)

        items.append(
            {
                "sort_time": record.get("generated_at_utc"),
                "entry_core": {
                    "index_version": 2,
                    "entry_type": "milestone_record",
                    "link_mode": "entry_sha256",
                    "appended_at_utc": record.get("generated_at_utc"),
                    "milestone": milestone,
                    "record_path": rel(record_path),
                    "record_sha256": sha256_file(record_path),
                    "freeze_gate_directory": rel(freeze_dir),
                    "freeze_gate_summary_path": rel(freeze_summary_path),
                    "freeze_gate_report_path": rel(freeze_report_path),
                    "bundle_manifest_path": rel(bundle_manifest_path),
                    "bundle_zip_path": rel(bundle_zip_path),
                    "overall_status": record.get("freeze_gate_overall_status"),
                },
            }
        )

    return items


def discover_release_candidate_entries() -> list[dict]:
    items: list[dict] = []
    if not RC_RECORDS_ROOT.exists():
        return items

    for record_path in sorted(RC_RECORDS_ROOT.rglob("release_candidate_record.json")):
        record = read_json(record_path)
        milestone = record.get("milestone")
        rc_name = record.get("release_candidate")
        if not isinstance(milestone, str) or not milestone:
            raise ValueError(f"Invalid milestone in {record_path}")
        if not isinstance(rc_name, str) or not rc_name:
            raise ValueError(f"Invalid release_candidate in {record_path}")

        digest_report_path = record_path.parent / "release_candidate_digest_report.json"
        require_file(digest_report_path)

        rc_root_record_path = ROOT / "artifacts" / "release_candidates" / rc_name / "promotion_gate_decision.json"
        require_file(rc_root_record_path)
        promotion_gate = read_json(rc_root_record_path)

        items.append(
            {
                "sort_time": record.get("generated_at_utc"),
                "entry_core": {
                    "index_version": 2,
                    "entry_type": "release_candidate_record",
                    "link_mode": "entry_sha256",
                    "appended_at_utc": record.get("generated_at_utc"),
                    "milestone": milestone,
                    "release_candidate": rc_name,
                    "record_path": rel(record_path),
                    "record_sha256": sha256_file(record_path),
                    "promotion_gate_path": rel(rc_root_record_path),
                    "digest_report_path": rel(digest_report_path),
                    "overall_status": promotion_gate.get("promotion_status"),
                },
            }
        )

    return items


def build_entries() -> list[dict]:
    discovered = discover_milestone_entries() + discover_release_candidate_entries()
    discovered.sort(key=lambda x: (str(x["sort_time"]), json.dumps(x["entry_core"], ensure_ascii=False, sort_keys=True)))

    built: list[dict] = []
    previous_entry_sha256 = None

    for item in discovered:
        core = dict(item["entry_core"])
        core["previous_entry_sha256"] = previous_entry_sha256
        entry_sha256 = sha256_bytes(canonical_json(core).encode("utf-8"))
        entry = {**core, "entry_sha256": entry_sha256}
        built.append(entry)
        previous_entry_sha256 = entry_sha256

    return built


def main() -> int:
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)

    backup_path = BACKUP_ROOT / f"immutable_audit_index.pre_v2_{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
    if INDEX_PATH.exists():
        shutil.copy2(INDEX_PATH, backup_path)

    entries = build_entries()
    text = ""
    for entry in entries:
        text += json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"

    write_text(INDEX_PATH, text)

    print("=" * 72)
    print("IMMUTABLE AUDIT INDEX REBUILT")
    print("=" * 72)
    print(f"INDEX PATH      : {rel(INDEX_PATH)}")
    print(f"BACKUP PATH     : {rel(backup_path) if backup_path.exists() else None}")
    print(f"ENTRY COUNT     : {len(entries)}")
    if entries:
        print(f"LAST ENTRY HASH : {entries[-1]['entry_sha256']}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
