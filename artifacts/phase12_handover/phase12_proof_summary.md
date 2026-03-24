# Phase12 Proof Summary

- generated_at: 2026-03-24T09:51:26+00:00
- workflow_run_id: wfr-phase12-2455937c
- passed: 24/24

## Proofs

### P_status_intake.define_project
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_env.define_promotion_model
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_cicd.write_pipeline_spec
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_ops.write_observability_spec
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_ops.write_change_control_spec
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_devops.generate_supply_chain_bundle
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_architect.review_production_change
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_release.promote_environment
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_debugger.write_postmortem
- expected: succeeded
- actual: succeeded
- ok: True

### intake_exists
- expected: True
- actual: True
- ok: True

### env_model_exists
- expected: True
- actual: True
- ok: True

### pipeline_exists
- expected: True
- actual: True
- ok: True

### observability_exists
- expected: True
- actual: True
- ok: True

### change_control_exists
- expected: True
- actual: True
- ok: True

### sbom_exists
- expected: True
- actual: True
- ok: True

### provenance_exists
- expected: True
- actual: True
- ok: True

### signing_exists
- expected: True
- actual: True
- ok: True

### change_review_exists
- expected: True
- actual: True
- ok: True

### deployment_report_exists
- expected: True
- actual: True
- ok: True

### postmortem_exists
- expected: True
- actual: True
- ok: True

### P_unauthorized_approval_denied
- expected: True
- actual: True
- ok: True
- detail: {
  "ok": false,
  "error_type": "ApprovalGateError",
  "error": "actor not authorized for approval: actor=ci-bot, roles=['automation'], required=['devops_reviewer', 'human_approver', 'operations_reviewer', 'platform_admin', 'release_manager']",
  "ts": "2026-03-24T09:51:26+00:00"
}

### P_path_escape_denied
- expected: 3
- actual: 3
- ok: True
- detail: {"ok": false, "task_type": "env.define_promotion_model", "error": "governance denied execution", "reasons": ["path escapes project root: /tmp/phase12-evil.json"], "ts": "2026-03-24T09:51:26+00:00"}

### P_prod_target_environment
- expected: prod
- actual: prod
- ok: True

### P_safe_deployment_mode
- expected: ring_canary
- actual: ring_canary
- ok: True

## Phase12 Status

- intake.define_project | succeeded | attempts=1
- env.define_promotion_model | succeeded | attempts=1
- cicd.write_pipeline_spec | succeeded | attempts=1
- ops.write_observability_spec | succeeded | attempts=1
- ops.write_change_control_spec | succeeded | attempts=1
- devops.generate_supply_chain_bundle | succeeded | attempts=1
- architect.review_production_change | succeeded | attempts=1
- release.promote_environment | succeeded | attempts=1
- debugger.write_postmortem | succeeded | attempts=1
