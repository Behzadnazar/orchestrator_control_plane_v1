# Phase13 Proof Summary

- generated_at: 2026-03-24T10:15:35+00:00
- passed: 17/17

## Proofs

### boundary_exists
- expected: True
- actual: True
- ok: True

### repo_binding_exists
- expected: True
- actual: True
- ok: True

### environment_governance_exists
- expected: True
- actual: True
- ok: True

### secrets_config_exists
- expected: True
- actual: True
- ok: True

### supply_chain_exists
- expected: True
- actual: True
- ok: True

### rollout_exists
- expected: True
- actual: True
- ok: True

### observability_change_exists
- expected: True
- actual: True
- ok: True

### first_delivery_exists
- expected: True
- actual: True
- ok: True

### prod_required_reviewers
- expected: 2
- actual: 2
- ok: True

### prod_prevent_self_review
- expected: True
- actual: True
- ok: True

### secretless_auth_preferred
- expected: oidc_or_workload_identity_federation
- actual: oidc_or_workload_identity_federation
- ok: True

### attestation_required
- expected: True
- actual: True
- ok: True

### signed_sbom_required
- expected: True
- actual: True
- ok: True

### rollout_mode_ring_canary
- expected: ring_canary
- actual: ring_canary
- ok: True

### delivery_attestation_ready
- expected: True
- actual: True
- ok: True

### delivery_rollback_ready
- expected: True
- actual: True
- ok: True

### path_escape_denied
- expected: 1
- actual: 1
- ok: True
- detail: {"ok": false, "task_type": "external.configure_secrets_access", "error": "ValueError: path escapes project root: /tmp/phase13-evil.json", "ts": "2026-03-24T10:15:35+00:00"}
