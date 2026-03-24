#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FREEZE_GATE_ROOT = ROOT / "artifacts" / "freeze_gate"
AUDIT_ROOT = ROOT / "artifacts" / "audit"
AUDIT_INDEX_PATH = AUDIT_ROOT / "immutable_audit_index.jsonl"
MILESTONE_RECORDS_ROOT = AUDIT_ROOT / "milestone_records"

REQUIRED_OUTPUTS = (
    "freeze_gate_audit_report.md",
    "freeze_gate_summary.json",
    "evidence_bundle_manifest.json",
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


def rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except Exception:
        return str(path)


def locate_freeze_gate_dir(milestone: str) -> Path:
    path = FREEZE_GATE_ROOT / milestone
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"Freeze gate directory not found: {path}")
    return path


def locate_required_files(freeze_dir: Path, milestone: str) -> dict[str, Path]:
    files: dict[str, Path] = {}

    for name in REQUIRED_OUTPUTS:
        p = freeze_dir / name
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"Required file missing: {p}")
        files[name] = p

    zip_path = freeze_dir / f"{milestone}_evidence_bundle.zip"
    if not zip_path.exists() or not zip_path.is_file():
        raise FileNotFoundError(f"Required bundle zip missing: {zip_path}")
    files[f"{milestone}_evidence_bundle.zip"] = zip_path

    return files


def build_artifact_digest_table(files: dict[str, Path]) -> list[dict]:
    rows: list[dict] = []
    for logical_name, path in sorted(files.items(), key=lambda x: x[0]):
        rows.append(
            {
                "logical_name": logical_name,
                "path": rel(path),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return rows


def build_canonical_signature_payload(record_core: dict) -> str:
    return json.dumps(record_core, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build signed milestone record and append immutable audit index entry."
    )
    parser.add_argument("--milestone", required=True, help="Milestone directory name under artifacts/freeze_gate/")
    args = parser.parse_args()

    milestone = args.milestone.strip()
    if not milestone:
        raise SystemExit("Milestone must not be empty.")

    freeze_dir = locate_freeze_gate_dir(milestone)
    files = locate_required_files(freeze_dir, milestone)

    summary = read_json(files["freeze_gate_summary.json"])
    bundle_manifest = read_json(files["evidence_bundle_manifest.json"])

    overall_status = str(summary.get("overall_status", "")).strip().upper()
    if overall_status != "PASS":
        raise SystemExit(
            f"Milestone {milestone} is not PASS in freeze gate summary. Refusing to write signed record."
        )

    gate_statuses = summary.get("gate_statuses", {})
    if not isinstance(gate_statuses, dict):
        raise SystemExit("freeze_gate_summary.json -> gate_statuses is invalid.")

    artifact_digests = build_artifact_digest_table(files)

    record_core = {
        "record_version": 2,
        "record_type": "signed_milestone_record",
        "signature_type": "sha256_canonical_record",
        "generated_at_utc": now_utc(),
        "milestone": milestone,
        "project_root": str(ROOT),
        "freeze_gate_directory": rel(freeze_dir),
        "freeze_gate_overall_status": overall_status,
        "gate_statuses": gate_statuses,
        "artifact_digests": artifact_digests,
        "bundle_manifest_overall_status": bundle_manifest.get("overall_status"),
        "bundle_manifest_gate_statuses": bundle_manifest.get("gate_statuses"),
        "audit_chain_contract": {
            "link_field": "previous_entry_sha256",
            "link_target": "previous.entry_sha256",
            "contract_version": 2,
        },
    }

    canonical_payload = build_canonical_signature_payload(record_core)
    record_signature_sha256 = sha256_bytes(canonical_payload.encode("utf-8"))

    signed_record = {
        **record_core,
        "canonical_payload_sha256": record_signature_sha256,
        "canonical_payload_preview": canonical_payload[:4000],
    }

    record_dir = MILESTONE_RECORDS_ROOT / milestone
    record_path = record_dir / "signed_milestone_record.json"
    write_json(record_path, signed_record)

    previous_entry_sha256 = latest_index_entry_sha256(AUDIT_INDEX_PATH)
    index_entry_core = {
        "index_version": 2,
        "entry_type": "milestone_record",
        "link_mode": "entry_sha256",
        "appended_at_utc": now_utc(),
        "milestone": milestone,
        "record_path": rel(record_path),
        "record_sha256": sha256_file(record_path),
        "freeze_gate_directory": rel(freeze_dir),
        "freeze_gate_summary_path": rel(files["freeze_gate_summary.json"]),
        "freeze_gate_report_path": rel(files["freeze_gate_audit_report.md"]),
        "bundle_manifest_path": rel(files["evidence_bundle_manifest.json"]),
        "bundle_zip_path": rel(files[f"{milestone}_evidence_bundle.zip"]),
        "overall_status": overall_status,
        "previous_entry_sha256": previous_entry_sha256,
    }

    index_entry_canonical = json.dumps(
        index_entry_core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    index_entry = {
        **index_entry_core,
        "entry_sha256": sha256_bytes(index_entry_canonical.encode("utf-8")),
    }

    append_jsonl(AUDIT_INDEX_PATH, index_entry)

    digest_report = {
        "generated_at_utc": now_utc(),
        "milestone": milestone,
        "record_path": rel(record_path),
        "record_sha256": sha256_file(record_path),
        "audit_index_path": rel(AUDIT_INDEX_PATH),
        "latest_index_entry_sha256": index_entry["entry_sha256"],
        "artifacts": artifact_digests,
        "audit_chain_contract": {
            "link_field": "previous_entry_sha256",
            "link_target": "previous.entry_sha256",
            "contract_version": 2,
        },
    }
    digest_report_path = record_dir / "signed_milestone_digest_report.json"
    write_json(digest_report_path, digest_report)

    human_report_lines = [
        f"# Signed Milestone Record — {milestone}",
        "",
        f"- Generated at (UTC): `{digest_report['generated_at_utc']}`",
        f"- Record path: `{rel(record_path)}`",
        f"- Record SHA256: `{digest_report['record_sha256']}`",
        f"- Audit index path: `{rel(AUDIT_INDEX_PATH)}`",
        f"- Latest audit entry SHA256: `{digest_report['latest_index_entry_sha256']}`",
        "",
        "## Artifact Digests",
        "",
        "| Logical Name | Path | Size (bytes) | SHA256 |",
        "|---|---|---:|---|",
    ]

    for row in artifact_digests:
        human_report_lines.append(
            f"| {row['logical_name']} | `{row['path']}` | {row['size_bytes']} | `{row['sha256']}` |"
        )

    human_report_lines.append("")
    human_report_path = record_dir / "signed_milestone_record.md"
    write_text(human_report_path, "\n".join(human_report_lines))

    print("=" * 72)
    print("SIGNED MILESTONE RECORD + IMMUTABLE AUDIT INDEX")
    print("=" * 72)
    print(f"MILESTONE        : {milestone}")
    print(f"FREEZE STATUS    : {overall_status}")
    print(f"RECORD JSON      : {rel(record_path)}")
    print(f"RECORD MD        : {rel(human_report_path)}")
    print(f"DIGEST REPORT    : {rel(digest_report_path)}")
    print(f"AUDIT INDEX      : {rel(AUDIT_INDEX_PATH)}")
    print(f"INDEX ENTRY HASH : {index_entry['entry_sha256']}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
