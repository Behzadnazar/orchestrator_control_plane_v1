# R14 — Signer Policy Enforcement Proof + Request-Type / Payload-Class Restrictions

- Generated at (UTC): `2026-03-20T13:32:26+00:00`
- Proof label: `R14_detached_signer_policy_enforcement_proof`
- Base verification time (UTC): `2026-03-20T13:32:24+00:00`
- OpenSSL version: `OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)`
- Proof status: **PASS**
- Output directory: `artifacts/operations/detached_external_signer_policy_proof/R14_detached_signer_policy_enforcement_proof`
- Detached signer custody directory: `state/detached_external_signer_policy/R14_detached_signer_policy_enforcement_proof`

## Policy Runtime

- Gate decision: **ALLOW**
- Executed: **TRUE**
- Detached signer ready: **TRUE**
- Control plane private key read allowed: **FALSE**
- Allowed signature verified: **TRUE**
- Allowed tamper rejected: **TRUE**
- Disallowed type rejected: **TRUE**
- Disallowed class rejected: **TRUE**
- Disallowed target rejected: **TRUE**
- Disallowed type reason: `disallowed_payload_type`
- Disallowed class reason: `disallowed_payload_class`
- Disallowed target reason: `disallowed_target_path`

## Denied Paths Cleanup

- Expired cleaned: **TRUE**
- Future cleaned: **TRUE**

## Boundary Scan

- Artifact boundary contains private keys: **FALSE**
- Runtime boundary contains private keys: **FALSE**
- Detached signer custody contains private keys after proof: **FALSE**
