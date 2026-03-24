# Gate-Enforced Runtime Entry

- Generated at (UTC): `2026-03-20T10:58:28+00:00`
- Runtime label: `Q4_deny_path_runtime_proof__runtime`
- Operation: `release`
- Workflow ID: `Q4_deny_path_runtime_proof__workflow`
- Gate decision: **DENY**
- Runtime status: **DENY_BLOCKED**
- Output directory: `artifacts/operations/runtime/Q4_deny_path_runtime_proof__runtime`

## Gate Phase

- Gate label: `Q4_deny_path_runtime_proof__runtime__gate`
- Gate return code: `2`
- Gate decision path: `artifacts/operations/admission/Q4_deny_path_runtime_proof__runtime__gate/admission_gate_decision.json`

## Runtime Enforcement

Gate returned `DENY`, so runtime wrapper stopped before executing the requested command.

## Command Result

- Wrapped command: `python3 -c "print('Q4_BLOCK_MARKER_SHOULD_NOT_APPEAR')"`
- Command executed: **False**
- Command return code: `None`

## Fail-Closed Rule

If the admission gate does not return `ALLOW`, the wrapper exits non-zero and does not run the payload command.
