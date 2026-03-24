# R17 — Multi-Signer / Key-Rotation Continuity Proof + Cross-Key Audit Verifiability

- Generated at (UTC): `2026-03-20T14:02:36+00:00`
- Proof label: `R17_detached_signer_multi_signer_rotation_proof`
- Base verification time (UTC): `2026-03-20T14:02:33+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_multi_signer_rotation_proof/R17_detached_signer_multi_signer_rotation_proof`
- Detached signer custody directory: `state/detached_external_signer_multi_signer_rotation/R17_detached_signer_multi_signer_rotation_proof`
- Ledger directory: `artifacts/operations/detached_external_signer_multi_signer_rotation_proof/R17_detached_signer_multi_signer_rotation_proof/multi_signer_rotated_ledger`

## Multi-Signer Runtime

- Gate decision: **ALLOW**
- Executed: **TRUE**
- Old signer ready: **TRUE**
- New signer ready: **TRUE**
- Old request A verified: **TRUE**
- Old request B verified: **TRUE**
- New request C verified: **TRUE**
- New request D verified: **TRUE**
- Cross old payload with new key rejected: **TRUE**
- Cross new payload with old key rejected: **TRUE**
- Segment count: `2`
- Entry count: `4`
- Multi-signer chain valid: **TRUE**
- Multi-signer continuity valid: **TRUE**
- Cross-key epoch valid: **TRUE**
- Snapshot valid: **TRUE**
- Retention valid: **TRUE**
- Epoch tamper detected: **TRUE**

## Denied Paths Cleanup

- Expired cleaned: **TRUE**
- Future cleaned: **TRUE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys after proof: **FALSE**
