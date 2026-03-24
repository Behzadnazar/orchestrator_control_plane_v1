# R15 — Audit Chain / Append-Only Signing Ledger Proof + Replay Detection

- Generated at (UTC): `2026-03-20T13:41:13+00:00`
- Proof label: `R15_detached_signer_audit_ledger_proof`
- Base verification time (UTC): `2026-03-20T13:41:12+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_audit_ledger_proof/R15_detached_signer_audit_ledger_proof`
- Detached signer custody directory: `state/detached_external_signer_audit_ledger/R15_detached_signer_audit_ledger_proof`

## Ledger Runtime

- Gate decision: **ALLOW**
- Executed: **TRUE**
- Detached signer ready: **TRUE**
- Control plane private key read allowed: **FALSE**
- Request A signature verified: **TRUE**
- Request B signature verified: **TRUE**
- Replay request rejected: **TRUE**
- Replay reject reason: `replay_request_id`
- Ledger entry count: `2`
- Ledger chain valid: **TRUE**
- Ledger replay detected in verification: **FALSE**
- Ledger tamper detected: **TRUE**

## Denied Paths Cleanup

- Expired cleaned: **TRUE**
- Future cleaned: **TRUE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys after proof: **FALSE**
