# Runtime Onboarding Handoff

## Purpose

This document defines the runtime onboarding handoff boundary for the orchestrator control-plane baseline.

It exists to ensure that operational onboarding uses the formally verified baseline rather than ad-hoc runtime assumptions.

## Required Artifacts

Runtime onboarding must receive the following artifacts:

- proof registry baseline manifest
- proof registry baseline SHA256 sidecar
- integration handover package
- runtime control-plane integration package
- formal delivery bundle
- runtime operational integration output
- operational integration plan
- final security / handover summary
- release-candidate rollout plan

## Runtime Onboarding Rule

Runtime onboarding is allowed only when all required artifacts are present and aligned to the same baseline SHA256.

## Runtime Handoff Rule

The handoff is not valid if any of the following occurs:

- baseline SHA mismatch
- missing handover artifact
- missing runtime package
- missing operational documentation
- missing rollout plan
- incomplete proof range

## Final Runtime Position

Runtime onboarding must treat the baseline manifest as the formal source of truth.
