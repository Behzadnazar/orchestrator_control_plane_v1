# Release Candidate Rollout

## Status

- Document Type: `release-candidate-rollout`
- Document Version: `1`
- Rollout Status: `ready-for-release-candidate-rollout`
- Proof Range: `R01-R35`
- Proof Count: `35`
- Baseline SHA256: `7a6c585ea82d4db3a9b8160b9d474788563582cd40a04fe9e45c7d3240431890`

## Required Inputs

- `proof_registry_baseline_manifest.json`
- `proof_registry_baseline_manifest.sha256`
- `integration_handover_package.json`
- `runtime_control_plane_integration.json`
- `formal_delivery_bundle.json`
- `formal_delivery_bundle.sha256`
- `runtime_operational_integration.json`
- `OPERATIONAL_INTEGRATION_PLAN.md`
- `FINAL_SECURITY_HANDOVER_SUMMARY.md`
- `RC_ROLLOUT_PLAN.md`
- `RUNTIME_ONBOARDING_HANDOFF.md`

## Rollout Sequence

1. verify baseline manifest and sidecar sha256
2. verify integration handover package binding
3. verify runtime control-plane integration binding
4. verify formal delivery bundle and sidecar sha256
5. verify runtime operational integration binding
6. review RC rollout plan
7. review runtime onboarding handoff
8. authorize runtime onboarding only after all checks pass

## Release Gate Contract

- baseline_complete_required: `True`
- baseline_sha_alignment_required: `True`
- handover_package_required: `True`
- runtime_package_required: `True`
- formal_delivery_bundle_required: `True`
- runtime_operational_package_required: `True`
- rollout_and_onboarding_docs_required: `True`
- mismatch_or_missing_artifact_is_fatal: `True`

