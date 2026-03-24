# Operational Integration Plan

## Purpose

This document defines the operational integration baseline for the proven control-plane security and consistency track.

The purpose of this plan is to ensure that runtime onboarding, integration, release preparation, and handover all happen against the same formally verified baseline.

## Required Inputs

The following artifacts are mandatory before runtime integration starts:

- `artifacts/handover/proof_registry_baseline_manifest.json`
- `artifacts/handover/proof_registry_baseline_manifest.sha256`
- `artifacts/handover/integration_handover_package.json`
- `artifacts/handover/INTEGRATION_HANDOVER_PACKAGE.md`

## Operational Preconditions

Runtime integration must not begin unless all of the following are true:

1. The proof registry baseline manifest exists.
2. The baseline SHA256 sidecar matches the manifest.
3. The integration handover package exists and references the same baseline SHA256.
4. Proof count is exactly `35`.
5. Runtime integration uses the same `app/security/` surfaces covered by the proof suite.
6. No missing, pending, or gap proof slot exists in the formal registry.

## Operational Integration Sequence

1. Verify the baseline manifest and sidecar SHA256.
2. Verify the integration handover package.
3. Verify that `app/security/` and `tests/proofs/` are present in the integration target.
4. Run the proof suite before integration cutover.
5. Bind runtime integration only after the proof suite passes.
6. Use the final security summary as the handover reference during integration onboarding.
7. Treat any mismatch between baseline, package, and runtime artifacts as a release blocker.

## Runtime Guardrails

The following runtime guardrails are mandatory:

- No runtime cutover without verified baseline.
- No runtime package acceptance with mismatched baseline SHA.
- No operational handover with incomplete proof registry coverage.
- No security sign-off without final handover summary.
- No integration shortcut that bypasses the proof-based baseline.

## Expected Outputs

The runtime integration stage must produce or preserve the following:

- a verified runtime-control-plane integration document
- a preserved baseline manifest and sidecar hash
- a preserved integration handover package
- a preserved final security / handover summary

## Operational Decision Rule

If the baseline is complete and hash-aligned, integration may proceed.

If the baseline is missing, hash-mismatched, incomplete, or inconsistent, integration must stop.
