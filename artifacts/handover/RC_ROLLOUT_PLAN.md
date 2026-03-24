# RC Rollout Plan

## Objective

This document defines the release-candidate rollout path for the orchestrator control-plane baseline.

The rollout must happen only after the formal baseline, handover package, runtime package, formal delivery bundle, and operational runtime integration are all verified.

## Preconditions

The following must already exist and be valid:

- proof registry baseline manifest
- proof registry baseline SHA256 sidecar
- integration handover package
- runtime control-plane integration package
- formal delivery bundle
- runtime operational integration package

## Rollout Sequence

1. Verify the baseline manifest and sidecar SHA256.
2. Verify the integration handover package.
3. Verify the runtime control-plane integration package.
4. Verify the formal delivery bundle and its sidecar SHA256.
5. Verify the runtime operational integration output.
6. Confirm operational integration plan and final handover summary are present.
7. Approve runtime onboarding only after all verification steps succeed.
8. Treat any missing, mismatched, or partial input as a rollout blocker.

## Rollout Gate

Release-candidate rollout is allowed only if all artifacts point to the same baseline SHA256 and the proof range remains complete for `R01-R35`.

## Failure Rule

If baseline alignment breaks, rollout must stop immediately.
