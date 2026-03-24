# Governance Handover Summary

- generated_at: 2026-03-24T08:08:37+00:00
- passed: 6/6

## Proof Results

### G1_positive_approval_frontend
- expected: True
- actual: True
- reasons: (none)

### G2_negative_unauthorized_actor
- expected: False
- actual: False
- reasons: actor not authorized for approval: actor=ci-bot, roles=['automation'], required=['frontend_reviewer', 'human_approver', 'platform_admin']

### G3_negative_path_escape
- expected: False
- actual: False
- reasons: path escapes project root: /tmp/evil.txt

### G4_negative_missing_dependency
- expected: False
- actual: False
- reasons: required upstream artifact missing: /home/behzad/Schreibtisch/ai-dev-system/orchestrator_control_plane_v1/artifacts/runs/phase_h_demo_v2/research/missing.md; required input path does not exist: artifacts/runs/phase_h_demo_v2/research/missing.md

### G5_positive_memory_write
- expected: True
- actual: True
- reasons: (none)

### G6_negative_memory_namespace_violation
- expected: False
- actual: False
- reasons: write path not allowed by policy: artifacts/runs/phase_h_demo_v2/frontend/bad.json; path خارج از namespace عامل است: artifacts/runs/phase_h_demo_v2/frontend/bad.json

## Runtime Status Summary

- backend.fail_test | dead_letter | 2
- backend.write_file | succeeded | 3
- frontend.write_component | succeeded | 1
- research.collect_notes | succeeded | 4
- unknown.ghost_task | dead_letter | 1
