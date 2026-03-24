# Multi-Scenario Tamper Matrix + Coverage Report

- Generated at (UTC): `2026-03-20T10:30:29+00:00`
- Scenario label: `O3_independent_tamper_matrix`
- Index path: `artifacts/audit/immutable_audit_index.jsonl`
- Backup path: `artifacts/audit/tamper_matrix/O3_independent_tamper_matrix/immutable_audit_index.backup.jsonl`
- Baseline status: **PASS**
- Restore check status: **PASS**
- Overall proof status: **PASS**

## Coverage Summary

- Total defined scenarios: **6**
- Executed scenarios: **6**
- Skipped scenarios: **0**
- Passed scenarios: **6**
- Failed scenarios: **0**

## Tamper Matrix

| Scenario | Expected | Observed | Execution | Result | Summary Path |
|---|---|---|---|---|---|
| record_sha256_mismatch | FAIL | FAIL | EXECUTED | PASS | `artifacts/audit/verification/O3_independent_tamper_matrix_record_sha256_mismatch/audit_chain_verification_summary.json` |
| previous_entry_sha256_mismatch | FAIL | FAIL | EXECUTED | PASS | `artifacts/audit/verification/O3_independent_tamper_matrix_previous_entry_sha256_mismatch/audit_chain_verification_summary.json` |
| entry_sha256_mismatch | FAIL | FAIL | EXECUTED | PASS | `artifacts/audit/verification/O3_independent_tamper_matrix_entry_sha256_mismatch/audit_chain_verification_summary.json` |
| record_path_missing_target | FAIL | FAIL | EXECUTED | PASS | `artifacts/audit/verification/O3_independent_tamper_matrix_record_path_missing_target/audit_chain_verification_summary.json` |
| remove_first_line_truncation | FAIL | FAIL | EXECUTED | PASS | `artifacts/audit/verification/O3_independent_tamper_matrix_remove_first_line_truncation/audit_chain_verification_summary.json` |
| swap_first_two_lines_order_break | FAIL | FAIL | EXECUTED | PASS | `artifacts/audit/verification/O3_independent_tamper_matrix_swap_first_two_lines_order_break/audit_chain_verification_summary.json` |

## Scenario Details

### record_sha256_mismatch

- Description: Mutate the last entry record_sha256 so record digest no longer matches file content.
- Execution status: **EXECUTED**
- Expected status: **FAIL**
- Observed status: **FAIL**
- Tamper type: `record_sha256_mismatch`
- Target line: `6`
- Field: `record_sha256`

### previous_entry_sha256_mismatch

- Description: Mutate the last entry previous_entry_sha256 so chain link breaks.
- Execution status: **EXECUTED**
- Expected status: **FAIL**
- Observed status: **FAIL**
- Tamper type: `previous_entry_sha256_mismatch`
- Target line: `6`
- Field: `previous_entry_sha256`

### entry_sha256_mismatch

- Description: Mutate the last entry entry_sha256 so entry hash verification fails.
- Execution status: **EXECUTED**
- Expected status: **FAIL**
- Observed status: **FAIL**
- Tamper type: `entry_sha256_mismatch`
- Target line: `6`
- Field: `entry_sha256`

### record_path_missing_target

- Description: Mutate the last entry record_path so the referenced record no longer exists.
- Execution status: **EXECUTED**
- Expected status: **FAIL**
- Observed status: **FAIL**
- Tamper type: `record_path_missing_target`
- Target line: `6`
- Field: `record_path`

### remove_first_line_truncation

- Description: Remove the first line so the remaining chain starts with a non-null previous link.
- Execution status: **EXECUTED**
- Expected status: **FAIL**
- Observed status: **FAIL**
- Tamper type: `remove_first_line_truncation`
- Target line: `1`
- Field: `line_removal`

### swap_first_two_lines_order_break

- Description: Swap the first two entries so ordering and chain semantics break.
- Execution status: **EXECUTED**
- Expected status: **FAIL**
- Observed status: **FAIL**
- Tamper type: `swap_first_two_lines_order_break`
- Target line: `1`
- Field: `line_order`
