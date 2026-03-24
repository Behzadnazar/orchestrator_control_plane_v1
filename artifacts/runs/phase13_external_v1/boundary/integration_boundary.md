# External Delivery Platform Selection + Integration Boundary

- generated_at: 2026-03-24T10:15:35+00:00
- primary_platform: github_actions
- secondary_platform: azure_devops

## Boundary

- Local orchestrator remains source of governance truth.
- External platform receives reviewed deployment specifications only.
- External approvals, protected environments, and deployment checks gate production execution.
- Artifact provenance and attestation must be verifiable outside the local control plane.

## Repository / CI Scope

- GitHub repository is the primary external source repository.
- GitHub Actions environments govern deployment targets.
- Azure DevOps remains compatible as a secondary enterprise delivery substrate.

## Non-Goals

- No direct credential baking into workflows.
- No unrestricted production deployment path.
- No mutable post-signing artifact rewrite.
