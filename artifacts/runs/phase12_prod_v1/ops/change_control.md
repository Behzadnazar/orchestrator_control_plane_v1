# Secrets / Config / Artifact Governance + Change Control

- generated_at: 2026-03-24T09:51:25+00:00
- change_window: Sun 01:00-03:00 UTC

## Rules

- Secrets are injected only at deploy time and never baked into artifacts.
- Config is versioned per environment and promoted through the same governed pipeline.
- Artifacts are immutable after signing and provenance generation.
- Production changes require dual approval and rollback readiness.

## Change Control

- CAB review required before prod promotion.
- Emergency change path requires post-incident review within 24h.
