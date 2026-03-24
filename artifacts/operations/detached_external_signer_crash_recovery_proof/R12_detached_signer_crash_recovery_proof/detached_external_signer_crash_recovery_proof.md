# R12 — Restart/Crash Recovery Proof for Detached Signer + No Key Leakage After Abnormal Termination

- Generated at (UTC): `2026-03-20T13:19:04+00:00`
- Proof label: `R12_detached_signer_crash_recovery_proof`
- Base verification time (UTC): `2026-03-20T13:18:58+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_crash_recovery_proof/R12_detached_signer_crash_recovery_proof`
- Detached signer custody directory: `state/detached_external_signer_crash_recovery/R12_detached_signer_crash_recovery_proof`

## Normal Active Path

- Active gate decision: **ALLOW**
- Active executed: **TRUE**
- Active receipt verified: **TRUE**
- Active attestation verified: **TRUE**

## Crash Path

- Crash gate decision: **ALLOW**
- Crash observed: **TRUE**
- Crash signer returncode: `91`
- Crash key path exists after detach: **FALSE**
- Crash control plane private key read allowed: **FALSE**
- Crash receipt signature exists: **FALSE**
- Crash runtime report exists: **FALSE**

## Recovery Path

- Recovery gate decision: **ALLOW**
- Recovery executed: **TRUE**
- Recovery receipt verified: **TRUE**
- Recovery attestation verified: **TRUE**

## Denied Paths Cleanup

- Expired cleaned: **TRUE**
- Future cleaned: **TRUE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys after proof: **FALSE**
