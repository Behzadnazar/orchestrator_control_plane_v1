# R19 — Threshold / Dual-Authorization Signing Proof + Split Trust Approval Boundary

- Generated at (UTC): `2026-03-21T08:04:21+00:00`
- Proof label: `R19_detached_signer_dual_authorization_proof`
- Base verification time (UTC): `2026-03-21T08:04:17+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_dual_authorization_proof/R19_detached_signer_dual_authorization_proof`
- Detached signer custody directory: `state/detached_external_signer_dual_authorization/R19_detached_signer_dual_authorization_proof`

## Dual Authorization Runtime

- Gate decision: **ALLOW**
- Executed: **TRUE**
- Signer ready: **TRUE**
- Approver A ready: **TRUE**
- Approver B ready: **TRUE**
- Single approval rejected: **TRUE**
- Single approval reason: `insufficient_distinct_approvals`
- Duplicate approval rejected: **TRUE**
- Duplicate approval reason: `duplicate_approver_ids`
- Tampered approval rejected: **TRUE**
- Tampered approval reason: `invalid_signature_approver_a`
- Dual approval accepted: **TRUE**
- Dual payload signature verified: **TRUE**
- Dual payload tamper rejected: **TRUE**

## Denied Paths Cleanup

- Expired cleaned: **TRUE**
- Future cleaned: **TRUE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys after proof: **FALSE**
