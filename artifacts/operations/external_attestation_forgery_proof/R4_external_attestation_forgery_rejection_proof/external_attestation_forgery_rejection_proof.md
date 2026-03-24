# Forgery Rejection Proof for External-Key Attestation

- Generated at (UTC): `2026-03-20T11:22:02+00:00`
- Proof label: `R4_external_attestation_forgery_rejection_proof`
- Runtime label: `R3_trust_separation_external_key_proof__runtime`
- Proof status: **PASS**
- Output directory: `artifacts/operations/external_attestation_forgery_proof/R4_external_attestation_forgery_rejection_proof`

## Baseline Verification

- Status: **PASS**
- Return code: `0`
- Verification path: `artifacts/operations/external_attestation_verification/R4_external_attestation_forgery_rejection_proof__baseline/external_signed_attestation_verification.json`

## Forgery Tamper

- Tamper type: `signature_b64_forgery`
- Target file: `artifacts/operations/external_signed_runtime/R3_trust_separation_external_key_proof__runtime/external_signed_execution_attestation.json`
- Field: `signature_b64`
- Verification status: **FAIL**

## Wrong Public Key Check

- Status: **FAIL**
- Return code: `1`

## Restore Verification

- Status: **PASS**
- Return code: `0`

## Final Declaration

Baseline external attestation verification passed, forged/tampered attestation was rejected, wrong-public-key verification was rejected, and restored verification returned to PASS.
