#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AUDIT_ROOT = ROOT / "artifacts" / "audit"
INDEX_PATH = AUDIT_ROOT / "immutable_audit_index.jsonl"
OUTPUT_ROOT = AUDIT_ROOT / "tamper_matrix"


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


def read_json(path: Path):
    return json.loads(read_text(path))


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


def require_file(path: Path) -> Path:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Required file missing: {path}")
    return path


def load_index_lines() -> list[str]:
    require_file(INDEX_PATH)
    return INDEX_PATH.read_text(encoding="utf-8").splitlines()


def save_index_lines(lines: list[str]) -> None:
    text = "\n".join(lines)
    if lines:
        text += "\n"
    INDEX_PATH.write_text(text, encoding="utf-8")


def restore_index(src: Path) -> None:
    shutil.copy2(src, INDEX_PATH)


def mutate_hex_string(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("Expected non-empty string value to mutate.")
    first = value[0].lower()
    replacement = "0" if first != "0" else "1"
    return replacement + value[1:]


def run_verifier(label: str) -> dict:
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "verify_immutable_audit_chain.py"),
        "--label",
        label,
    ]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)

    summary_path = ROOT / "artifacts" / "audit" / "verification" / label / "audit_chain_verification_summary.json"
    summary = read_json(summary_path) if summary_path.exists() else None
    overall_status = None
    if isinstance(summary, dict):
        overall_status = str(summary.get("overall_status", "")).upper()

    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "summary_path": rel(summary_path) if summary_path.exists() else None,
        "overall_status": overall_status,
        "stdout_sha256": sha256_bytes((proc.stdout or "").encode("utf-8")),
        "stderr_sha256": sha256_bytes((proc.stderr or "").encode("utf-8")),
    }


def tamper_record_sha256_last(lines: list[str]) -> tuple[list[str], dict]:
    if not lines:
        raise ValueError("Audit index is empty.")
    obj = json.loads(lines[-1])
    original = obj.get("record_sha256")
    if not isinstance(original, str) or not original:
        raise ValueError("Last entry does not contain valid record_sha256.")
    obj["record_sha256"] = mutate_hex_string(original)
    mutated = list(lines)
    mutated[-1] = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return mutated, {
        "tamper_type": "record_sha256_mismatch",
        "target_line_number": len(lines),
        "field": "record_sha256",
        "original_value": original,
        "tampered_value": obj["record_sha256"],
    }


def tamper_previous_entry_sha256_last(lines: list[str]) -> tuple[list[str], dict]:
    if len(lines) < 2:
        raise ValueError("Need at least 2 lines for previous_entry_sha256 tamper.")
    obj = json.loads(lines[-1])
    original = obj.get("previous_entry_sha256")
    if not isinstance(original, str) or not original:
        raise ValueError("Last entry does not contain valid previous_entry_sha256.")
    obj["previous_entry_sha256"] = mutate_hex_string(original)
    mutated = list(lines)
    mutated[-1] = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return mutated, {
        "tamper_type": "previous_entry_sha256_mismatch",
        "target_line_number": len(lines),
        "field": "previous_entry_sha256",
        "original_value": original,
        "tampered_value": obj["previous_entry_sha256"],
    }


def tamper_entry_sha256_last(lines: list[str]) -> tuple[list[str], dict]:
    if not lines:
        raise ValueError("Audit index is empty.")
    obj = json.loads(lines[-1])
    original = obj.get("entry_sha256")
    if not isinstance(original, str) or not original:
        raise ValueError("Last entry does not contain valid entry_sha256.")
    obj["entry_sha256"] = mutate_hex_string(original)
    mutated = list(lines)
    mutated[-1] = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return mutated, {
        "tamper_type": "entry_sha256_mismatch",
        "target_line_number": len(lines),
        "field": "entry_sha256",
        "original_value": original,
        "tampered_value": obj["entry_sha256"],
    }


def tamper_record_path_last(lines: list[str]) -> tuple[list[str], dict]:
    if not lines:
        raise ValueError("Audit index is empty.")
    obj = json.loads(lines[-1])
    original = obj.get("record_path")
    if not isinstance(original, str) or not original:
        raise ValueError("Last entry does not contain valid record_path.")
    obj["record_path"] = original + ".tampered_missing"
    mutated = list(lines)
    mutated[-1] = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return mutated, {
        "tamper_type": "record_path_missing_target",
        "target_line_number": len(lines),
        "field": "record_path",
        "original_value": original,
        "tampered_value": obj["record_path"],
    }


def tamper_remove_first_line(lines: list[str]) -> tuple[list[str], dict]:
    if len(lines) < 2:
        raise ValueError("Need at least 2 lines to remove the first line.")
    removed = lines[0]
    mutated = lines[1:]
    return mutated, {
        "tamper_type": "remove_first_line_truncation",
        "target_line_number": 1,
        "field": "line_removal",
        "original_value": sha256_bytes(removed.encode("utf-8")),
        "tampered_value": "REMOVED",
    }


def tamper_swap_first_two_lines(lines: list[str]) -> tuple[list[str], dict]:
    if len(lines) < 2:
        raise ValueError("Need at least 2 lines to swap order.")
    mutated = list(lines)
    mutated[0], mutated[1] = mutated[1], mutated[0]
    return mutated, {
        "tamper_type": "swap_first_two_lines_order_break",
        "target_line_number": 1,
        "field": "line_order",
        "original_value": "1<->2",
        "tampered_value": "2<->1",
    }


SCENARIOS = (
    {
        "name": "record_sha256_mismatch",
        "expected_status": "FAIL",
        "handler": tamper_record_sha256_last,
        "description": "Mutate the last entry record_sha256 so record digest no longer matches file content.",
    },
    {
        "name": "previous_entry_sha256_mismatch",
        "expected_status": "FAIL",
        "handler": tamper_previous_entry_sha256_last,
        "description": "Mutate the last entry previous_entry_sha256 so chain link breaks.",
    },
    {
        "name": "entry_sha256_mismatch",
        "expected_status": "FAIL",
        "handler": tamper_entry_sha256_last,
        "description": "Mutate the last entry entry_sha256 so entry hash verification fails.",
    },
    {
        "name": "record_path_missing_target",
        "expected_status": "FAIL",
        "handler": tamper_record_path_last,
        "description": "Mutate the last entry record_path so the referenced record no longer exists.",
    },
    {
        "name": "remove_first_line_truncation",
        "expected_status": "FAIL",
        "handler": tamper_remove_first_line,
        "description": "Remove the first line so the remaining chain starts with a non-null previous link.",
    },
    {
        "name": "swap_first_two_lines_order_break",
        "expected_status": "FAIL",
        "handler": tamper_swap_first_two_lines,
        "description": "Swap the first two entries so ordering and chain semantics break.",
    },
)


def run_scenario(label: str, backup_path: Path, original_lines: list[str], scenario: dict) -> dict:
    restore_index(backup_path)

    try:
        tampered_lines, tamper_meta = scenario["handler"](original_lines)
    except Exception as exc:
        return {
            "scenario": scenario["name"],
            "description": scenario["description"],
            "expected_status": scenario["expected_status"],
            "execution_status": "SKIPPED",
            "skip_reason": str(exc),
            "tamper_operation": None,
            "verification": None,
            "observed_status": None,
            "expected_failure_observed": None,
            "scenario_passed": None,
        }

    save_index_lines(tampered_lines)

    run = run_verifier(f"{label}_{scenario['name']}")
    observed = run["overall_status"]
    scenario_passed = observed == scenario["expected_status"]

    restore_index(backup_path)

    return {
        "scenario": scenario["name"],
        "description": scenario["description"],
        "expected_status": scenario["expected_status"],
        "execution_status": "EXECUTED",
        "skip_reason": None,
        "tamper_operation": tamper_meta,
        "verification": {
            "label": f"{label}_{scenario['name']}",
            "returncode": run["returncode"],
            "overall_status": observed,
            "summary_path": run["summary_path"],
            "stdout_sha256": run["stdout_sha256"],
            "stderr_sha256": run["stderr_sha256"],
        },
        "observed_status": observed,
        "expected_failure_observed": observed == "FAIL",
        "scenario_passed": scenario_passed,
    }


def build_coverage(summary: dict) -> dict:
    scenarios = summary["scenario_results"]
    total_defined = len(scenarios)
    executed = sum(1 for s in scenarios if s["execution_status"] == "EXECUTED")
    skipped = total_defined - executed
    passed = sum(1 for s in scenarios if s["scenario_passed"] is True)
    failed = sum(1 for s in scenarios if s["execution_status"] == "EXECUTED" and s["scenario_passed"] is False)

    return {
        "total_defined_scenarios": total_defined,
        "executed_scenarios": executed,
        "skipped_scenarios": skipped,
        "passed_scenarios": passed,
        "failed_scenarios": failed,
        "scenario_names": [s["scenario"] for s in scenarios],
        "executed_scenario_names": [s["scenario"] for s in scenarios if s["execution_status"] == "EXECUTED"],
        "skipped_scenario_names": [s["scenario"] for s in scenarios if s["execution_status"] == "SKIPPED"],
        "failed_scenario_names": [s["scenario"] for s in scenarios if s["execution_status"] == "EXECUTED" and s["scenario_passed"] is False],
    }


def build_markdown_report(summary: dict) -> str:
    lines: list[str] = []
    lines.append("# Multi-Scenario Tamper Matrix + Coverage Report")
    lines.append("")
    lines.append(f"- Generated at (UTC): `{summary['generated_at_utc']}`")
    lines.append(f"- Scenario label: `{summary['scenario_label']}`")
    lines.append(f"- Index path: `{summary['index_path']}`")
    lines.append(f"- Backup path: `{summary['backup_path']}`")
    lines.append(f"- Baseline status: **{summary['baseline_phase']['overall_status']}**")
    lines.append(f"- Restore check status: **{summary['restore_phase']['overall_status']}**")
    lines.append(f"- Overall proof status: **{summary['proof_status']}**")
    lines.append("")
    lines.append("## Coverage Summary")
    lines.append("")
    lines.append(f"- Total defined scenarios: **{summary['coverage']['total_defined_scenarios']}**")
    lines.append(f"- Executed scenarios: **{summary['coverage']['executed_scenarios']}**")
    lines.append(f"- Skipped scenarios: **{summary['coverage']['skipped_scenarios']}**")
    lines.append(f"- Passed scenarios: **{summary['coverage']['passed_scenarios']}**")
    lines.append(f"- Failed scenarios: **{summary['coverage']['failed_scenarios']}**")
    lines.append("")
    lines.append("## Tamper Matrix")
    lines.append("")
    lines.append("| Scenario | Expected | Observed | Execution | Result | Summary Path |")
    lines.append("|---|---|---|---|---|---|")
    for item in summary["scenario_results"]:
        observed = item["observed_status"] if item["observed_status"] is not None else "SKIPPED"
        result = (
            "PASS" if item["scenario_passed"] is True
            else "FAIL" if item["scenario_passed"] is False
            else "SKIPPED"
        )
        summary_path = item["verification"]["summary_path"] if item["verification"] else None
        lines.append(
            f"| {item['scenario']} | {item['expected_status']} | {observed} | {item['execution_status']} | {result} | `{summary_path}` |"
        )

    lines.append("")
    lines.append("## Scenario Details")
    lines.append("")
    for item in summary["scenario_results"]:
        lines.append(f"### {item['scenario']}")
        lines.append("")
        lines.append(f"- Description: {item['description']}")
        lines.append(f"- Execution status: **{item['execution_status']}**")
        lines.append(f"- Expected status: **{item['expected_status']}**")
        lines.append(f"- Observed status: **{item['observed_status']}**")
        if item["skip_reason"]:
            lines.append(f"- Skip reason: `{item['skip_reason']}`")
        if item["tamper_operation"]:
            lines.append(f"- Tamper type: `{item['tamper_operation']['tamper_type']}`")
            lines.append(f"- Target line: `{item['tamper_operation']['target_line_number']}`")
            lines.append(f"- Field: `{item['tamper_operation']['field']}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run multi-scenario tamper matrix against immutable audit index and build coverage report."
    )
    parser.add_argument(
        "--label",
        default=dt.datetime.now(dt.timezone.utc).strftime("O1_tamper_matrix_%Y%m%dT%H%M%SZ"),
        help="Scenario output label.",
    )
    args = parser.parse_args()

    label = args.label.strip()
    if not label:
        raise SystemExit("Label must not be empty.")

    require_file(INDEX_PATH)
    require_file(ROOT / "scripts" / "verify_immutable_audit_chain.py")

    output_dir = OUTPUT_ROOT / label
    output_dir.mkdir(parents=True, exist_ok=True)

    backup_path = output_dir / "immutable_audit_index.backup.jsonl"
    shutil.copy2(INDEX_PATH, backup_path)

    original_lines = load_index_lines()

    baseline_run = run_verifier(f"{label}_baseline")
    restore_index(backup_path)
    baseline_status = baseline_run["overall_status"]

    scenario_results = []
    for scenario in SCENARIOS:
        scenario_results.append(run_scenario(label, backup_path, original_lines, scenario))

    restore_index(backup_path)

    restore_run = run_verifier(f"{label}_post_restore")
    restore_status = restore_run["overall_status"]

    summary = {
        "generated_at_utc": now_utc(),
        "scenario_label": label,
        "index_path": rel(INDEX_PATH),
        "backup_path": rel(backup_path),
        "baseline_phase": {
            "label": f"{label}_baseline",
            "returncode": baseline_run["returncode"],
            "overall_status": baseline_status,
            "summary_path": baseline_run["summary_path"],
            "stdout_sha256": baseline_run["stdout_sha256"],
            "stderr_sha256": baseline_run["stderr_sha256"],
        },
        "scenario_results": scenario_results,
        "restore_phase": {
            "label": f"{label}_post_restore",
            "returncode": restore_run["returncode"],
            "overall_status": restore_status,
            "summary_path": restore_run["summary_path"],
            "stdout_sha256": restore_run["stdout_sha256"],
            "stderr_sha256": restore_run["stderr_sha256"],
        },
        "contract_rule": "previous_entry_sha256 must equal previous entry's entry_sha256",
    }

    summary["coverage"] = build_coverage(summary)

    proof_passed = (
        baseline_status == "PASS"
        and restore_status == "PASS"
        and summary["coverage"]["failed_scenarios"] == 0
        and summary["coverage"]["executed_scenarios"] >= 1
    )
    summary["proof_passed"] = proof_passed
    summary["proof_status"] = "PASS" if proof_passed else "FAIL"

    summary_path = output_dir / "tamper_matrix_summary.json"
    report_path = output_dir / "tamper_matrix_coverage_report.md"
    negative_proof_path = output_dir / "tamper_matrix_negative_proof.json"

    write_json(summary_path, summary)
    write_text(report_path, build_markdown_report(summary))

    negative_proof = {
        "proof_stage": "Phase O.1",
        "generated_at_utc": now_utc(),
        "proof_passed": proof_passed,
        "negative_proof_ok": proof_passed,
        "baseline_pass_observed": baseline_status == "PASS",
        "restore_pass_observed": restore_status == "PASS",
        "executed_scenarios": summary["coverage"]["executed_scenarios"],
        "passed_scenarios": summary["coverage"]["passed_scenarios"],
        "failed_scenarios": summary["coverage"]["failed_scenarios"],
        "skipped_scenarios": summary["coverage"]["skipped_scenarios"],
        "scenario_label": label,
        "summary_path": rel(summary_path),
        "report_path": rel(report_path),
        "backup_sha256": sha256_file(backup_path),
        "restored_index_sha256": sha256_file(INDEX_PATH),
        "contract_rule": "previous_entry_sha256 must equal previous entry's entry_sha256",
    }
    write_json(negative_proof_path, negative_proof)

    print("=" * 72)
    print("MULTI-SCENARIO TAMPER MATRIX + COVERAGE REPORT")
    print("=" * 72)
    print(f"LABEL             : {label}")
    print(f"INDEX PATH        : {rel(INDEX_PATH)}")
    print(f"BACKUP PATH       : {rel(backup_path)}")
    print(f"BASELINE STATUS   : {baseline_status}")
    print(f"RESTORE STATUS    : {restore_status}")
    print(f"EXECUTED SCENARIOS: {summary['coverage']['executed_scenarios']}")
    print(f"PASSED SCENARIOS  : {summary['coverage']['passed_scenarios']}")
    print(f"FAILED SCENARIOS  : {summary['coverage']['failed_scenarios']}")
    print(f"SKIPPED SCENARIOS : {summary['coverage']['skipped_scenarios']}")
    print(f"PROOF STATUS      : {summary['proof_status']}")
    print("-" * 72)
    print(f"SUMMARY JSON      : {rel(summary_path)}")
    print(f"REPORT MD         : {rel(report_path)}")
    print(f"NEGATIVE PROOF    : {rel(negative_proof_path)}")
    print("=" * 72)

    return 0 if proof_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
