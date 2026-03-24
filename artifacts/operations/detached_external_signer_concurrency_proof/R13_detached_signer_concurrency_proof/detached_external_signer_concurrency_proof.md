# R13 — Multi-Request Concurrency / Reentrancy Proof for Detached Signer + No Cross-Signature Mix-Up

- Generated at (UTC): `2026-03-20T13:24:37+00:00`
- Proof label: `R13_detached_signer_concurrency_proof`
- Base verification time (UTC): `2026-03-20T13:24:34+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_concurrency_proof/R13_detached_signer_concurrency_proof`
- Detached signer custody directory: `state/detached_external_signer_concurrency/R13_detached_signer_concurrency_proof`

## Concurrency Runtime

- Gate decision: **ALLOW**
- Executed: **TRUE**
- Detached signer ready: **TRUE**
- Control plane private key read allowed: **FALSE**
- Request A signature verified: **TRUE**
- Request B signature verified: **TRUE**
- Request A tamper rejected: **TRUE**
- Request B tamper rejected: **TRUE**
- Cross-verify A with signature B rejected: **TRUE**
- Cross-verify B with signature A rejected: **TRUE**
- Signatures are distinct: **TRUE**

## Denied Paths Cleanup

- Expired cleaned: **TRUE**
- Future cleaned: **TRUE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys after proof: **FALSE**
