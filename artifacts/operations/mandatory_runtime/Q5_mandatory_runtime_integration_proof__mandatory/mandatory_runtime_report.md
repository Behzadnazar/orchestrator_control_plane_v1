# Mandatory Runtime Entry Report

- Generated at (UTC): `2026-03-20T11:03:45+00:00`
- Runtime label: `Q5_mandatory_runtime_integration_proof__mandatory`
- Operation: `release`
- Workflow ID: `Q5_mandatory_runtime_integration_proof__workflow`
- Gate decision: **ALLOW**
- Runtime status: **ALLOW_EXECUTED**
- Output directory: `artifacts/operations/mandatory_runtime/Q5_mandatory_runtime_integration_proof__mandatory`

## Gate Phase

- Gate label: `Q5_mandatory_runtime_integration_proof__mandatory__gate`
- Gate decision path: `artifacts/operations/admission/Q5_mandatory_runtime_integration_proof__mandatory__gate/admission_gate_decision.json`
- Gate return code: `0`

## Mandatory Execution Contract

- Payload is executed only when gate returns `ALLOW`.
- Payload receives mandatory environment variables from the wrapper.
- A receipt is written for the workflow execution attempt.

## Payload Phase

- Command executed: **True**
- Command return code: `0`
- Receipt path: `artifacts/operations/mandatory_runtime/Q5_mandatory_runtime_integration_proof__mandatory/mandatory_execution_receipt.json`
