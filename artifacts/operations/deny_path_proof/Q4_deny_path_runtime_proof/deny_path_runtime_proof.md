# Deny-Path Runtime Proof + Blocked Payload Evidence

- Generated at (UTC): `2026-03-20T10:58:28+00:00`
- Proof label: `Q4_deny_path_runtime_proof`
- Runtime label: `Q4_deny_path_runtime_proof__runtime`
- Workflow ID: `Q4_deny_path_runtime_proof__workflow`
- Expected gate decision: **DENY**
- Observed gate decision: **DENY**
- Runtime status: **DENY_BLOCKED**
- Proof status: **PASS**
- Output directory: `artifacts/operations/deny_path_proof/Q4_deny_path_runtime_proof`

## Runtime Wrapper Result

- Wrapper return code: `3`
- Wrapped command: `python3 -c "print('Q4_BLOCK_MARKER_SHOULD_NOT_APPEAR')"`

## Gate Evidence

- Gate decision path: `artifacts/operations/admission/Q4_deny_path_runtime_proof__runtime__gate/admission_gate_decision.json`
- Runtime report path: `artifacts/operations/runtime/Q4_deny_path_runtime_proof__runtime/runtime_gate_report.json`
- Payload stdout path: `artifacts/operations/runtime/Q4_deny_path_runtime_proof__runtime/payload.stdout.txt`
- Payload stderr path: `artifacts/operations/runtime/Q4_deny_path_runtime_proof__runtime/payload.stderr.txt`

## Blocked Payload Assertions

- Payload executed: **False**
- Payload stdout empty: **True**
- Payload stderr empty: **True**
- Block marker absent: **True**

## Final Declaration

The deny-path runtime proof passed. The gate returned DENY, the wrapper blocked execution, and no payload marker was emitted.
