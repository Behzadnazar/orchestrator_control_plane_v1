# R11.2 — Denied-Key Custody Cleanup + Proof-Scoped No-On-Disk Private Keys

- Generated at (UTC): `2026-03-20T13:11:59+00:00`
- Proof label: `R11_2_denied_key_custody_cleanup_proof`
- Base verification time (UTC): `2026-03-20T13:11:55+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_interface_proof/R11_2_denied_key_custody_cleanup_proof`
- Detached signer custody directory: `state/detached_external_signer/R11_2_denied_key_custody_cleanup_proof`

## Active Path

- Active gate decision: **ALLOW**
- Active executed: **TRUE**
- Detached signer ready: **TRUE**
- Signer key path exists after detach: **FALSE**
- Control plane private key read allowed: **FALSE**
- Receipt signature verified: **TRUE**
- Receipt tamper rejected: **TRUE**
- Attestation signature verified: **TRUE**
- Attestation tamper rejected: **TRUE**

## Denied Paths Cleanup

- Expired gate decision: **DENY**
- Future gate decision: **DENY**
- Expired cleanup removed key: **TRUE**
- Future cleanup removed key: **TRUE**
- Expired key exists after cleanup: **FALSE**
- Future key exists after cleanup: **FALSE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys on disk after proof: **FALSE**
