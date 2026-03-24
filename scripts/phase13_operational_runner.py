from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


UTC = timezone.utc
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def load_payload() -> Dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("stdin payload must be a JSON object")
    return data


def safe_project_path(raw: str) -> Path:
    if not raw or not isinstance(raw, str):
        raise ValueError("path is required and must be a string")
    candidate = Path(raw)
    resolved = candidate.resolve() if candidate.is_absolute() else (PROJECT_ROOT / candidate).resolve()
    try:
        resolved.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError(f"path escapes project root: {raw}") from exc
    return resolved


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, content: str) -> Dict[str, Any]:
    ensure_parent(path)
    path.write_text(content, encoding="utf-8")
    return {"ok": True, "action": "write_text_file", "path": str(path), "ts": utc_now_iso()}


def write_json(path: Path, value: Any) -> Dict[str, Any]:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2, sort_keys=True)
    return {"ok": True, "action": "write_json_file", "path": str(path), "ts": utc_now_iso()}


def load_platform_config() -> Dict[str, Any]:
    path = PROJECT_ROOT / "config" / "phase13_external_platform.json"
    return json.loads(path.read_text(encoding="utf-8"))


def handle_platform_selection(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("boundary_output_path", "")))
    cfg = load_platform_config()
    lines = [
        "# External Delivery Platform Selection + Integration Boundary",
        "",
        f"- generated_at: {utc_now_iso()}",
        f"- primary_platform: {cfg['external_delivery_model']['primary_platform']}",
        f"- secondary_platform: {cfg['external_delivery_model']['secondary_platform']}",
        "",
        "## Boundary",
        "",
        "- Local orchestrator remains source of governance truth.",
        "- External platform receives reviewed deployment specifications only.",
        "- External approvals, protected environments, and deployment checks gate production execution.",
        "- Artifact provenance and attestation must be verifiable outside the local control plane.",
        "",
        "## Repository / CI Scope",
        "",
        "- GitHub repository is the primary external source repository.",
        "- GitHub Actions environments govern deployment targets.",
        "- Azure DevOps remains compatible as a secondary enterprise delivery substrate.",
        "",
        "## Non-Goals",
        "",
        "- No direct credential baking into workflows.",
        "- No unrestricted production deployment path.",
        "- No mutable post-signing artifact rewrite.",
        ""
    ]
    return write_text(output_path, "\n".join(lines))


def handle_repo_ci_binding(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("repo_binding_output_path", "")))
    repo_name = str(payload.get("repo_name", "")).strip()
    if not repo_name:
        raise ValueError("repo_name is required")
    value = {
        "generated_at": utc_now_iso(),
        "repo_name": repo_name,
        "ci_platform": "github_actions",
        "identity_model": {
            "default_token_permissions": "least_privilege",
            "human_approval_roles": ["release_manager", "security_reviewer", "operations_reviewer"],
            "automation_identity": "oidc_or_workload_identity_federation",
            "fallback_identity": "environment_scoped_secret_only"
        },
        "repository_binding": {
            "default_branch": "main",
            "protected_release_patterns": ["releases/*"],
            "environment_binding": ["dev", "test", "staging", "prod"]
        }
    }
    return write_json(output_path, value)


def handle_environment_governance(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("environment_governance_output_path", "")))
    cfg = load_platform_config()
    value = {
        "generated_at": utc_now_iso(),
        "platform": "github_environments",
        "environments": {
            "dev": {
                "required_reviewers": 0,
                "branch_policy": ["main", "feature/*"],
                "checks": ["lint", "unit", "static-analysis"]
            },
            "test": {
                "required_reviewers": 1,
                "branch_policy": ["main", "releases/*"],
                "checks": ["integration", "contract", "security-scan"]
            },
            "staging": {
                "required_reviewers": 1,
                "branch_policy": ["main", "releases/*"],
                "checks": ["smoke", "observability-baseline", "change-ticket-linked"]
            },
            "prod": {
                "required_reviewers": cfg["production_rules"]["required_reviewers"],
                "prevent_self_review": cfg["production_rules"]["prevent_self_review"],
                "branch_policy": cfg["production_rules"]["branch_policy"],
                "checks": [
                    "manual-approval",
                    "attestation-verification",
                    "signed-sbom-verification",
                    "provenance-verification",
                    "safe-rollout-ready",
                    "rollback-ready"
                ]
            }
        }
    }
    return write_json(output_path, value)


def handle_secrets_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("secrets_config_output_path", "")))
    value = {
        "generated_at": utc_now_iso(),
        "secret_model": {
            "preferred_auth": "oidc_or_workload_identity_federation",
            "fallback_auth": "environment_scoped_secrets_only",
            "rules": [
                "No static production credential in repository workflow files.",
                "Environment secrets unlock only inside approved environment jobs.",
                "Prod secrets isolated from dev/test/staging secrets.",
                "Secret rotation governed through change control."
            ]
        },
        "config_scope": {
            "repository": ["non-sensitive defaults only"],
            "environment": ["deployment endpoints", "scoped runtime secrets", "feature flags"],
            "artifact": ["never store secrets in artifacts"]
        }
    }
    return write_json(output_path, value)


def handle_supply_chain(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("supply_chain_output_path", "")))
    value = {
        "generated_at": utc_now_iso(),
        "attestation": {
            "provider": "github_artifact_attestations",
            "required": True,
            "verification_stage": "pre-prod-and-prod"
        },
        "sbom": {
            "required": True,
            "format": "json",
            "signed": True
        },
        "provenance": {
            "required": True,
            "claims": [
                "repository",
                "workflow",
                "environment",
                "commit_sha",
                "builder_identity"
            ]
        },
        "artifact_policy": {
            "immutable_after_signing": True,
            "registry_push_only_after_attestation": True
        }
    }
    return write_json(output_path, value)


def handle_rollout_controls(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("rollout_output_path", "")))
    value = {
        "generated_at": utc_now_iso(),
        "deployment_strategy": {
            "mode": "ring_canary",
            "rings": ["internal", "limited", "broad", "global"],
            "promotion_rule": "advance only on healthy observability checks"
        },
        "rollback": {
            "required": True,
            "trigger_conditions": ["error_rate_regression", "latency_budget_breach", "manual_stop"],
            "rollback_target": "previous_attested_release"
        }
    }
    return write_json(output_path, value)


def handle_observability_change(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("observability_change_output_path", "")))
    value = {
        "generated_at": utc_now_iso(),
        "observability_signals": {
            "metrics": ["latency_p95", "error_rate", "availability", "deployment_success_rate"],
            "alerts": ["sev1_error_budget_burn", "sev2_canary_failure", "sev2_release_regression"]
        },
        "change_management": {
            "required_for_prod": True,
            "link_change_ticket": True,
            "post_incident_review_required": True
        }
    }
    return write_json(output_path, value)


def handle_first_external_delivery(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("delivery_plan_output_path", "")))
    value = {
        "generated_at": utc_now_iso(),
        "delivery_target": "external_production_platform",
        "sequence": [
            "approve_governed_local_release_spec",
            "push_repository_changes",
            "trigger_external_ci",
            "wait_for_environment_checks",
            "verify_attestation_and_sbom",
            "start_ring_canary_rollout",
            "observe_health_signals",
            "promote_or_rollback"
        ],
        "release_readiness": {
            "environment_gates_ready": True,
            "secrets_model_ready": True,
            "attestation_ready": True,
            "rollback_ready": True
        }
    }
    return write_json(output_path, value)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 scripts/phase13_operational_runner.py <task_type>", file=sys.stderr)
        return 2

    task_type = sys.argv[1]
    payload = load_payload()

    handlers = {
        "external.select_platform": handle_platform_selection,
        "external.bind_repository_ci": handle_repo_ci_binding,
        "external.configure_environments": handle_environment_governance,
        "external.configure_secrets_access": handle_secrets_config,
        "external.configure_supply_chain": handle_supply_chain,
        "external.configure_rollout": handle_rollout_controls,
        "external.configure_observability_change": handle_observability_change,
        "external.execute_first_delivery": handle_first_external_delivery,
    }

    if task_type not in handlers:
        print(json.dumps({"ok": False, "task_type": task_type, "error": f"unknown task_type: {task_type}", "ts": utc_now_iso()}, ensure_ascii=False))
        return 2

    try:
        result = handlers[task_type](payload)
        print(json.dumps({"ok": True, "task_type": task_type, "result": result, "ts": utc_now_iso()}, ensure_ascii=False))
        return 0
    except ValueError as exc:
        print(json.dumps({"ok": False, "task_type": task_type, "error": f"ValueError: {exc}", "ts": utc_now_iso()}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
