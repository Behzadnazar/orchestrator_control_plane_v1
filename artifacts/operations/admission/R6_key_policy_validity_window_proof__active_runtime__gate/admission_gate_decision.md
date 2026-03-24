# Control Plane Admission Gate Decision

- Generated at (UTC): `2026-03-20T11:33:34+00:00`
- Decision: **ALLOW**
- Operation: `release`
- Workflow ID: `R6_key_policy_validity_window_proof__active_workflow`
- Output directory: `artifacts/operations/admission/R6_key_policy_validity_window_proof__active_runtime__gate`

## Inputs

- Readiness report: `artifacts/operations/Q1_operational_readiness/operational_readiness_report.json`
- Chain summary: `artifacts/audit/verification/Q1_post_readiness_chain_check/audit_chain_verification_summary.json`
- Audit index: `artifacts/audit/immutable_audit_index.jsonl`
- Milestone record: `artifacts/audit/milestone_records/O3_independent_freeze/signed_milestone_record.json`
- RC record: `artifacts/audit/release_candidate_records/RC3/release_candidate_record.json`

## Gate Checks

| Check | Result |
|---|---|
| operational_readiness_pass | PASS |
| operational_mode_controlled_local_ready | PASS |
| readiness_checks_all_true | PASS |
| latest_chain_pass | PASS |
| latest_chain_failed_entries_zero | PASS |
| audit_index_nonempty | PASS |
| latest_audit_entry_present | PASS |
| milestone_record_pass | PASS |
| release_candidate_required_present | PASS |
| release_candidate_pass | PASS |
| release_candidate_allowed | PASS |
| operation_policy_milestone_required_present | PASS |
| operation_policy_rc_required_present | PASS |

## Fail-Closed Rule

Any failed mandatory check results in DENY.
