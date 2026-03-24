# Control Plane Test Operations

## Preconditions
- Project root: `orchestrator_control_plane_v1`
- Virtual environment exists at `.venv`
- Test runner is executed from project root

## Package-Safe Entry Points
Operational scripts are executed in module mode:

- `python3 -m scripts.preflight_check`
- `python3 -m scripts.run_tests --suite all`
- `python3 -m scripts.ci_check`
- `python3 -m scripts.show_artifact_summary`
- `python3 -m scripts.release_snapshot`
- `python3 -m scripts.verify_release_baseline`
- `python3 -m scripts.show_baseline_diff`
- `python3 -m scripts.freeze_milestone`

## Artifact Root
All normalized test artifacts are stored under:

```bash
artifacts/test_runs
