# Tamper Simulation + Negative Verification Proof

- Generated at (UTC): `2026-03-20T09:54:20+00:00`
- Scenario label: `N3_tamper_simulation`
- Index path: `artifacts/audit/immutable_audit_index.jsonl`
- Backup path: `artifacts/audit/tamper_simulation/N3_tamper_simulation/immutable_audit_index.backup.jsonl`
- Tamper status: **FAIL**
- Restore status: **PASS**
- Proof status: **PASS**

## Tamper Operation

- Tamper type: `record_sha256_mismatch`
- Target line number: `2`
- Field: `record_sha256`

## Verification Results

| Phase | Return Code | Overall Status | Summary Path |
|---|---:|---|---|
| Baseline | 0 | PASS | `artifacts/audit/verification/N3_tamper_simulation_baseline/audit_chain_verification_summary.json` |
| Tamper | 1 | FAIL | `artifacts/audit/verification/N3_tamper_simulation_tampered/audit_chain_verification_summary.json` |
| Restore | 0 | PASS | `artifacts/audit/verification/N3_tamper_simulation_restored/audit_chain_verification_summary.json` |

## Expected Outcome

- Baseline must be `PASS`.
- Tampered verification must be `FAIL`.
- Restored verification must return to `PASS`.
