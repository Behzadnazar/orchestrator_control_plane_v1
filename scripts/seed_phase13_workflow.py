from __future__ import annotations

import json
from pathlib import Path


PHASE13_KEY = "phase13_external_v1"


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    run_root = project_root / "artifacts" / "runs" / PHASE13_KEY
    for part in ["boundary", "repo", "environments", "security", "rollout", "ops", "delivery"]:
        (run_root / part).mkdir(parents=True, exist_ok=True)

    state = {
        "workflow_run_key": PHASE13_KEY,
        "tasks": [
            {
                "task_type": "external.select_platform",
                "payload": {
                    "boundary_output_path": str(run_root / "boundary" / "integration_boundary.md")
                }
            },
            {
                "task_type": "external.bind_repository_ci",
                "payload": {
                    "repo_name": "governed-external-delivery-repo",
                    "repo_binding_output_path": str(run_root / "repo" / "repo_ci_binding.json")
                }
            },
            {
                "task_type": "external.configure_environments",
                "payload": {
                    "environment_governance_output_path": str(run_root / "environments" / "environment_governance.json")
                }
            },
            {
                "task_type": "external.configure_secrets_access",
                "payload": {
                    "secrets_config_output_path": str(run_root / "security" / "secrets_config.json")
                }
            },
            {
                "task_type": "external.configure_supply_chain",
                "payload": {
                    "supply_chain_output_path": str(run_root / "security" / "supply_chain_bundle.json")
                }
            },
            {
                "task_type": "external.configure_rollout",
                "payload": {
                    "rollout_output_path": str(run_root / "rollout" / "rollout_strategy.json")
                }
            },
            {
                "task_type": "external.configure_observability_change",
                "payload": {
                    "observability_change_output_path": str(run_root / "ops" / "observability_change_integration.json")
                }
            },
            {
                "task_type": "external.execute_first_delivery",
                "payload": {
                    "delivery_plan_output_path": str(run_root / "delivery" / "first_external_delivery_plan.json")
                }
            }
        ]
    }

    state_path = project_root / "artifacts" / "state" / "phase13" / "current_workflow_run.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

    print(json.dumps({"ok": True, "state_path": str(state_path), "tasks_count": len(state["tasks"])}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
