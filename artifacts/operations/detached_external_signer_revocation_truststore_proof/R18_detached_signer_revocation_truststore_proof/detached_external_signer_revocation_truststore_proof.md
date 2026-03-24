# R18 — Revocation / Trust-Store Update Proof + Historical Verification Boundaries

- Generated at (UTC): `2026-03-21T06:55:08+00:00`
- Proof label: `R18_detached_signer_revocation_truststore_proof`
- Base verification time (UTC): `2026-03-21T06:55:03+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_revocation_truststore_proof/R18_detached_signer_revocation_truststore_proof`
- Detached signer custody directory: `state/detached_external_signer_revocation_truststore/R18_detached_signer_revocation_truststore_proof`

## Revocation Runtime

- Gate decision: **ALLOW**
- Executed: **TRUE**
- Old signer ready: **TRUE**
- New signer ready: **TRUE**
- Historical old verify before revocation: **TRUE**
- Historical old verify after revocation: **TRUE**
- Current new verify after revocation: **TRUE**
- Revoked old new sign rejected: **TRUE**
- Revoked old new sign reject reason: `key_revoked_for_new_signing`
- Trust-store tamper detected: **TRUE**

## Denied Paths Cleanup

- Expired cleaned: **TRUE**
- Future cleaned: **TRUE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys after proof: **FALSE**
