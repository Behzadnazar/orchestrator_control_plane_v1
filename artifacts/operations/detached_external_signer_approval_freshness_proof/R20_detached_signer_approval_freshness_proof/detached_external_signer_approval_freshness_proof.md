# R20 — Approval Freshness / Expiry / Nonce-Binding Proof + Anti-Replay Across Authorization Tokens

- Generated at (UTC): `2026-03-21T08:23:19+00:00`
- Proof label: `R20_detached_signer_approval_freshness_proof`
- Base verification time (UTC): `2026-03-21T08:23:14+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_approval_freshness_proof/R20_detached_signer_approval_freshness_proof`
- Detached signer custody directory: `state/detached_external_signer_approval_freshness/R20_detached_signer_approval_freshness_proof`

## Approval Freshness Runtime

- Gate decision: **ALLOW**
- Executed: **TRUE**
- Fresh dual approval accepted: **TRUE**
- Token replay rejected: **TRUE**
- Token replay reason: `approval_token_replay_approver_a`
- Expired token rejected: **TRUE**
- Expired token reason: `approval_expired_approver_a`
- Nonce mismatch rejected: **TRUE**
- Nonce mismatch reason: `nonce_mismatch_approver_a`
- Request mismatch rejected: **TRUE**
- Request mismatch reason: `request_id_mismatch_approver_a`
- Fresh payload signature verified: **TRUE**
- Fresh payload tamper rejected: **TRUE**
- Used token count after first accept: `2`

## Denied Paths Cleanup

- Expired cleaned: **TRUE**
- Future cleaned: **TRUE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys after proof: **FALSE**
