# R11 — Detached External Signer Interface + Control Plane Cannot Read Private Key

- Generated at (UTC): `2026-03-20T12:44:48+00:00`
- Proof label: `R11_detached_external_signer_interface_proof`
- Base verification time (UTC): `2026-03-20T12:44:46+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **FAIL**
- Output directory: `artifacts/operations/detached_external_signer_interface_proof/R11_detached_external_signer_interface_proof`
- Detached signer custody directory: `state/detached_external_signer/R11_detached_external_signer_interface_proof`

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

## Denied Paths

- Expired gate decision: **DENY**
- Future gate decision: **DENY**
- Expired executed: **FALSE**
- Future executed: **FALSE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys on disk after detach: **TRUE**
