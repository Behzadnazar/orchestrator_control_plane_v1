# External-Key Signed Execution Entry

- Generated at (UTC): `2026-03-20T11:19:24+00:00`
- Runtime label: `R3_trust_separation_external_key_proof__runtime`
- Workflow ID: `R3_trust_separation_external_key_proof__workflow`
- Operation: `release`
- Gate decision: **ALLOW**
- Runtime status: **ALLOW_EXECUTED**
- Output directory: `artifacts/operations/external_signed_runtime/R3_trust_separation_external_key_proof__runtime`

## Trust Separation

- Signing uses an external private key file.
- Verification is expected to use only the public key.
- The attestation artifact contains the public-key path, not private-key material.

## Artifacts

- Receipt path: `artifacts/operations/external_signed_runtime/R3_trust_separation_external_key_proof__runtime/external_signed_execution_receipt.json`
- Attestation path: `artifacts/operations/external_signed_runtime/R3_trust_separation_external_key_proof__runtime/external_signed_execution_attestation.json`
- Public key path: `artifacts/keys/attestation/attestation_public.pem`
