# Phase11 Proof Summary

- generated_at: 2026-03-24T09:30:38+00:00
- workflow_run_id: wfr-phase11-09ec36bb
- passed: 17/17

## Proofs

### P_status_research.collect_notes
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_frontend.write_component
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_backend.write_file
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_memory.write_json
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_debugger.analyze_failure
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_devops.build_release_bundle
- expected: succeeded
- actual: succeeded
- ok: True

### P_status_architect.review_constraints
- expected: succeeded
- actual: succeeded
- ok: True

### research_notes_exists
- expected: True
- actual: True
- ok: True

### frontend_component_exists
- expected: True
- actual: True
- ok: True

### backend_bundle_exists
- expected: True
- actual: True
- ok: True

### memory_state_exists
- expected: True
- actual: True
- ok: True

### debugger_rca_exists
- expected: True
- actual: True
- ok: True

### devops_manifest_exists
- expected: True
- actual: True
- ok: True

### architect_review_exists
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
  "error": "workflow_run_key not allowed: phase_h_demo_v2; actor not authorized for approval: actor=ci-bot, roles=['automation'], required=['frontend_reviewer', 'human_approver', 'platform_admin']",
  "ts": "2026-03-24T09:30:38+00:00"
}

### P_memory_read_positive
- expected: 0
- actual: 0
- ok: True

### P_path_escape_denied
- expected: 3
- actual: 3
- ok: True
- detail: {"ok": false, "task_type": "memory.write_json", "error": "governance denied execution", "reasons": ["path escapes project root: /tmp/phase11-evil.json"], "ts": "2026-03-24T09:30:38+00:00"}

## Phase11 Status

- research.collect_notes | succeeded | attempts=1
- frontend.write_component | succeeded | attempts=1
- backend.write_file | succeeded | attempts=1
- memory.write_json | succeeded | attempts=1
- debugger.analyze_failure | succeeded | attempts=1
- devops.build_release_bundle | succeeded | attempts=1
- architect.review_constraints | succeeded | attempts=1
