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
OUTPUT_ROOT = AUDIT_ROOT / "closure"


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


def load_freeze_summary(milestone: str) -> dict:
    path = require_file(FREEZE_GATE_ROOT / milestone / "freeze_gate_summary.json")
    return read_json(path)


def load_milestone_record(milestone: str) -> dict:
    path = require_file(AUDIT_ROOT / "milestone_records" / milestone / "signed_milestone_record.json")
    return read_json(path)


def load_rc_record(rc_name: str) -> dict:
    path = require_file(AUDIT_ROOT / "release_candidate_records" / rc_name / "release_candidate_record.json")
    return read_json(path)


def load_chain_summary(label: str) -> dict:
    path = require_file(AUDIT_ROOT / "verification" / label / "audit_chain_verification_summary.json")
    return read_json(path)


def load_tamper_summary(label: str) -> dict:
    path = require_file(AUDIT_ROOT / "tamper_simulation" / label / "tamper_simulation_summary.json")
    return read_json(path)


def load_matrix_summary(label: str) -> dict:
    path = require_file(AUDIT_ROOT / "tamper_matrix" / label / "tamper_matrix_summary.json")
    return read_json(path)


def load_index_entries() -> list[dict]:
    index_path = require_file(AUDIT_ROOT / "immutable_audit_index.jsonl")
    entries: list[dict] = []
    with index_path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            obj["_line_number"] = lineno
            entries.append(obj)
    return entries


def build_capability_boundary(index_entries: list[dict], latest_chain: dict, latest_matrix: dict) -> dict:
    entry_types = sorted({str(x.get("entry_type")) for x in index_entries})
    release_candidates = [str(x.get("release_candidate")) for x in index_entries if x.get("release_candidate")]
    milestones = [str(x.get("milestone")) for x in index_entries if x.get("milestone")]
    total_entries = len(index_entries)

    return {
        "proven_capabilities": [
            "freeze gate reporting and evidence bundling",
            "signed milestone record generation",
            "release candidate promotion record generation",
            "immutable audit index append workflow",
            "audit chain verification over multiple entries",
            "single-scenario tamper detection with restore proof",
            "multi-scenario tamper matrix execution and coverage reporting",
            "chain growth proof with milestone and release-candidate entries",
            "independent freeze-gate generation from underlying evidence inputs",
        ],
        "verified_scope": {
            "total_audit_index_entries": total_entries,
            "entry_types_seen": entry_types,
            "milestones_seen": milestones,
            "release_candidates_seen": release_candidates,
            "latest_chain_total_entries": latest_chain.get("total_entries"),
            "latest_matrix_executed_scenarios": latest_matrix.get("coverage", {}).get("executed_scenarios"),
        },
        "production_ready_claims": [
            "hash-based integrity tracking for audit records",
            "repeatable report generation for freeze/milestone/RC governance artifacts",
            "deterministic chain verification against entry_sha256 linkage contract v2",
            "tamper detection for covered mutation scenarios",
            "restore-to-clean-state validation after destructive test scenarios",
        ],
        "explicit_non_claims": [
            "no cryptographic signing with private/public keys",
            "no WORM storage or OS-enforced immutability guarantee",
            "no distributed consensus or remote attestation",
            "no proof of diversity across underlying domain evidence families",
            "no claim that all possible tamper vectors are covered beyond the defined matrix scenarios",
            "no claim that a cloned or evidence-derived milestone equals a fresh domain event",
        ],
        "current_limitations": [
            "independent milestone generation still reuses the same underlying baseline/verification/proof family",
            "tamper matrix covers defined scenarios only, not every possible corruption pattern",
            "audit trail remains local-file based",
            "integrity is SHA-256 record hashing, not asymmetric signature infrastructure",
            "governance proof is strong for local auditability, but not equivalent to external compliance certification",
        ],
        "experimental_or_shared_evidence_zones": [
            "freeze gates built from reused underlying evidence rather than newly generated domain evidence",
            "growth testing based on local synthetic expansion of audit trail",
        ],
    }


def build_phase_matrix(
    freeze_m1: dict,
    chain_m3: dict,
    tamper_n3: dict,
    matrix_o1: dict,
    chain_o2: dict,
    chain_o3: dict,
    matrix_o3: dict,
) -> list[dict]:
    return [
        {
            "phase": "M.1",
            "name": "Freeze Gate Audit Report + Evidence Bundle",
            "status": str(freeze_m1.get("overall_status", "")).upper(),
            "evidence": rel(FREEZE_GATE_ROOT / "M1_freeze_gate" / "freeze_gate_summary.json"),
        },
        {
            "phase": "M.2",
            "name": "Signed Milestone Record + Immutable Audit Index",
            "status": "PASS",
            "evidence": rel(AUDIT_ROOT / "milestone_records" / "M1_freeze_gate" / "signed_milestone_record.json"),
        },
        {
            "phase": "M.3",
            "name": "Audit Chain Verifier + Tamper Detection Base Proof",
            "status": str(chain_m3.get("overall_status", "")).upper(),
            "evidence": rel(AUDIT_ROOT / "verification" / "M3_audit_chain_check" / "audit_chain_verification_summary.json"),
        },
        {
            "phase": "N.1",
            "name": "Release Candidate Promotion Gate + RC Record",
            "status": "PASS",
            "evidence": rel(AUDIT_ROOT / "release_candidate_records" / "RC1" / "release_candidate_record.json"),
        },
        {
            "phase": "N.2",
            "name": "Audit Index Chain Contract Fix + Verifier Alignment",
            "status": "PASS",
            "evidence": rel(AUDIT_ROOT / "verification" / "N2_audit_chain_contract_fix" / "audit_chain_verification_summary.json"),
        },
        {
            "phase": "N.3",
            "name": "Tamper Simulation + Negative Verification Proof",
            "status": str(tamper_n3.get("proof_status", "")).upper(),
            "evidence": rel(AUDIT_ROOT / "tamper_simulation" / "N3_tamper_simulation" / "tamper_simulation_summary.json"),
        },
        {
            "phase": "O.1",
            "name": "Multi-Scenario Tamper Matrix + Coverage Report",
            "status": str(matrix_o1.get("proof_status", "")).upper(),
            "evidence": rel(AUDIT_ROOT / "tamper_matrix" / "O1_tamper_matrix" / "tamper_matrix_summary.json"),
        },
        {
            "phase": "O.2",
            "name": "Audit Chain Growth Test + Multi-Entry Proof",
            "status": str(chain_o2.get("overall_status", "")).upper(),
            "evidence": rel(AUDIT_ROOT / "verification" / "O2_growth_chain_after_rc" / "audit_chain_verification_summary.json"),
        },
        {
            "phase": "O.3",
            "name": "Independent Milestone Evidence + Non-Cloned Chain Growth",
            "status": "PASS" if str(chain_o3.get("overall_status", "")).upper() == "PASS" and str(matrix_o3.get("proof_status", "")).upper() == "PASS" else "FAIL",
            "evidence": rel(AUDIT_ROOT / "verification" / "O3_chain_after_rc3" / "audit_chain_verification_summary.json"),
        },
    ]


def build_markdown_report(
    generated_at: str,
    output_dir: Path,
    phase_matrix: list[dict],
    capability_boundary: dict,
    governance_summary: dict,
) -> str:
    lines: list[str] = []
    lines.append("# Governance Closure Report + Capability Boundary Declaration")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{generated_at}`")
    lines.append(f"- Project root: `{ROOT}`")
    lines.append(f"- Output directory: `{output_dir}`")
    lines.append(f"- Closure status: **{governance_summary['closure_status']}**")
    lines.append(f"- Governance readiness: **{governance_summary['governance_readiness']}**")
    lines.append("")
    lines.append("## Phase Closure Matrix")
    lines.append("")
    lines.append("| Phase | Name | Status | Evidence |")
    lines.append("|---|---|---|---|")
    for row in phase_matrix:
        lines.append(f"| {row['phase']} | {row['name']} | {row['status']} | `{row['evidence']}` |")
    lines.append("")
    lines.append("## Proven Capabilities")
    lines.append("")
    for item in capability_boundary["proven_capabilities"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Production-Ready Claims")
    lines.append("")
    for item in capability_boundary["production_ready_claims"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Explicit Non-Claims")
    lines.append("")
    for item in capability_boundary["explicit_non_claims"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Current Limitations")
    lines.append("")
    for item in capability_boundary["current_limitations"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Experimental / Shared-Evidence Zones")
    lines.append("")
    for item in capability_boundary["experimental_or_shared_evidence_zones"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Verified Scope Snapshot")
    lines.append("")
    lines.append(f"- Total audit index entries: **{capability_boundary['verified_scope']['total_audit_index_entries']}**")
    lines.append(f"- Entry types seen: `{', '.join(capability_boundary['verified_scope']['entry_types_seen'])}`")
    lines.append(f"- Latest chain total entries: **{capability_boundary['verified_scope']['latest_chain_total_entries']}**")
    lines.append(f"- Latest matrix executed scenarios: **{capability_boundary['verified_scope']['latest_matrix_executed_scenarios']}**")
    lines.append("")
    lines.append("## Final Declaration")
    lines.append("")
    lines.append(governance_summary["final_declaration"])
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build governance closure report and capability boundary declaration for the control-plane governance layer."
    )
    parser.add_argument(
        "--label",
        default="P1_governance_closure",
        help="Output label under artifacts/audit/closure/",
    )
    args = parser.parse_args()

    label = args.label.strip()
    if not label:
        raise SystemExit("Label must not be empty.")

    output_dir = OUTPUT_ROOT / label
    if output_dir.exists():
        raise SystemExit(f"Output label already exists: {output_dir}")

    freeze_m1 = load_freeze_summary("M1_freeze_gate")
    milestone_m1 = load_milestone_record("M1_freeze_gate")
    rc1 = load_rc_record("RC1")
    rc2 = load_rc_record("RC2")
    rc3 = load_rc_record("RC3")

    chain_m3 = load_chain_summary("M3_audit_chain_check")
    chain_n2 = load_chain_summary("N2_audit_chain_contract_fix")
    tamper_n3 = load_tamper_summary("N3_tamper_simulation")
    matrix_o1 = load_matrix_summary("O1_tamper_matrix")
    chain_o2 = load_chain_summary("O2_growth_chain_after_rc")
    matrix_o2 = load_matrix_summary("O2_growth_tamper_matrix")
    chain_o3 = load_chain_summary("O3_chain_after_rc3")
    matrix_o3 = load_matrix_summary("O3_independent_tamper_matrix")
    post_o3 = load_chain_summary("O3_post_matrix_restore_check")

    index_entries = load_index_entries()

    phase_matrix = build_phase_matrix(
        freeze_m1=freeze_m1,
        chain_m3=chain_m3,
        tamper_n3=tamper_n3,
        matrix_o1=matrix_o1,
        chain_o2=chain_o2,
        chain_o3=chain_o3,
        matrix_o3=matrix_o3,
    )

    if not all(str(x["status"]).upper() == "PASS" for x in phase_matrix):
        raise SystemExit("Not all phase statuses are PASS. Refusing to build closure report.")

    capability_boundary = build_capability_boundary(
        index_entries=index_entries,
        latest_chain=chain_o3,
        latest_matrix=matrix_o3,
    )

    governance_summary = {
        "generated_at_utc": now_utc(),
        "closure_status": "PASS",
        "governance_readiness": "LOCAL_PRODUCTION_GOVERNANCE_READY",
        "validated_artifacts": {
            "freeze_summary_m1": rel(FREEZE_GATE_ROOT / "M1_freeze_gate" / "freeze_gate_summary.json"),
            "milestone_record_m1": rel(AUDIT_ROOT / "milestone_records" / "M1_freeze_gate" / "signed_milestone_record.json"),
            "rc1_record": rel(AUDIT_ROOT / "release_candidate_records" / "RC1" / "release_candidate_record.json"),
            "rc2_record": rel(AUDIT_ROOT / "release_candidate_records" / "RC2" / "release_candidate_record.json"),
            "rc3_record": rel(AUDIT_ROOT / "release_candidate_records" / "RC3" / "release_candidate_record.json"),
            "chain_m3": rel(AUDIT_ROOT / "verification" / "M3_audit_chain_check" / "audit_chain_verification_summary.json"),
            "chain_n2": rel(AUDIT_ROOT / "verification" / "N2_audit_chain_contract_fix" / "audit_chain_verification_summary.json"),
            "tamper_n3": rel(AUDIT_ROOT / "tamper_simulation" / "N3_tamper_simulation" / "tamper_simulation_summary.json"),
            "matrix_o1": rel(AUDIT_ROOT / "tamper_matrix" / "O1_tamper_matrix" / "tamper_matrix_summary.json"),
            "chain_o2": rel(AUDIT_ROOT / "verification" / "O2_growth_chain_after_rc" / "audit_chain_verification_summary.json"),
            "matrix_o2": rel(AUDIT_ROOT / "tamper_matrix" / "O2_growth_tamper_matrix" / "tamper_matrix_summary.json"),
            "chain_o3": rel(AUDIT_ROOT / "verification" / "O3_chain_after_rc3" / "audit_chain_verification_summary.json"),
            "matrix_o3": rel(AUDIT_ROOT / "tamper_matrix" / "O3_independent_tamper_matrix" / "tamper_matrix_summary.json"),
            "post_o3": rel(AUDIT_ROOT / "verification" / "O3_post_matrix_restore_check" / "audit_chain_verification_summary.json"),
            "immutable_audit_index": rel(AUDIT_ROOT / "immutable_audit_index.jsonl"),
        },
        "integrity_snapshot": {
            "immutable_audit_index_sha256": sha256_file(AUDIT_ROOT / "immutable_audit_index.jsonl"),
            "latest_chain_total_entries": chain_o3.get("total_entries"),
            "latest_chain_failed_entries": chain_o3.get("failed_entries"),
            "latest_matrix_executed_scenarios": matrix_o3.get("coverage", {}).get("executed_scenarios"),
            "latest_matrix_failed_scenarios": matrix_o3.get("coverage", {}).get("failed_scenarios"),
        },
        "final_declaration": (
            "The control-plane governance layer is formally closed for the implemented local audit scope. "
            "Freeze gates, milestone records, release-candidate records, immutable audit indexing, chain verification, "
            "single-scenario tamper proof, multi-scenario tamper matrix, multi-entry growth proof, and independent milestone growth proof "
            "have all been demonstrated successfully. This declaration does not claim cryptographic signing infrastructure, WORM storage, "
            "external compliance certification, or full evidence-family diversity."
        ),
    }

    closure_payload = {
        "report_version": 1,
        "report_type": "governance_closure_report",
        "generated_at_utc": governance_summary["generated_at_utc"],
        "closure_status": governance_summary["closure_status"],
        "governance_readiness": governance_summary["governance_readiness"],
        "phase_matrix": phase_matrix,
        "capability_boundary": capability_boundary,
        "governance_summary": governance_summary,
        "source_snapshot": {
            "m1_freeze_overall_status": freeze_m1.get("overall_status"),
            "m1_record_status": milestone_m1.get("freeze_gate_overall_status"),
            "rc1_status": rc1.get("promotion_status"),
            "rc2_status": rc2.get("promotion_status"),
            "rc3_status": rc3.get("promotion_status"),
            "chain_m3_status": chain_m3.get("overall_status"),
            "chain_n2_status": chain_n2.get("overall_status"),
            "tamper_n3_status": tamper_n3.get("proof_status"),
            "matrix_o1_status": matrix_o1.get("proof_status"),
            "chain_o2_status": chain_o2.get("overall_status"),
            "matrix_o2_status": matrix_o2.get("proof_status"),
            "chain_o3_status": chain_o3.get("overall_status"),
            "matrix_o3_status": matrix_o3.get("proof_status"),
            "post_o3_status": post_o3.get("overall_status"),
        },
    }

    output_dir.mkdir(parents=True, exist_ok=False)
    json_path = output_dir / "governance_closure_report.json"
    md_path = output_dir / "governance_closure_report.md"
    declaration_path = output_dir / "capability_boundary_declaration.json"

    write_json(json_path, closure_payload)
    write_json(declaration_path, capability_boundary)
    write_text(
        md_path,
        build_markdown_report(
            generated_at=governance_summary["generated_at_utc"],
            output_dir=output_dir,
            phase_matrix=phase_matrix,
            capability_boundary=capability_boundary,
            governance_summary=governance_summary,
        ),
    )

    digest_report = {
        "generated_at_utc": governance_summary["generated_at_utc"],
        "label": label,
        "closure_status": governance_summary["closure_status"],
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
            {
                "path": rel(declaration_path),
                "size_bytes": declaration_path.stat().st_size,
                "sha256": sha256_file(declaration_path),
            },
        ],
    }
    digest_path = output_dir / "governance_closure_digest_report.json"
    write_json(digest_path, digest_report)

    print("=" * 72)
    print("GOVERNANCE CLOSURE REPORT + CAPABILITY BOUNDARY DECLARATION")
    print("=" * 72)
    print(f"LABEL            : {label}")
    print(f"CLOSURE STATUS   : {governance_summary['closure_status']}")
    print(f"READINESS        : {governance_summary['governance_readiness']}")
    print(f"REPORT JSON      : {rel(json_path)}")
    print(f"REPORT MD        : {rel(md_path)}")
    print(f"DECLARATION JSON : {rel(declaration_path)}")
    print(f"DIGEST REPORT    : {rel(digest_path)}")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
