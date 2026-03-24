from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.governance import Governance, GovernanceError  # noqa: E402
from app.governance_audit import GovernanceAudit  # noqa: E402


UTC = timezone.utc


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


def governance() -> Governance:
    return Governance(PROJECT_ROOT)


def audit() -> GovernanceAudit:
    return GovernanceAudit(PROJECT_ROOT)


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


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_text(read_text(path))


def handle_intake_define_project(payload: Dict[str, Any]) -> Dict[str, Any]:
    project_name = str(payload.get("project_name", "")).strip()
    business_goal = str(payload.get("business_goal", "")).strip()
    scope = str(payload.get("scope", "")).strip()
    constraints = payload.get("constraints", [])
    output_path = safe_project_path(str(payload.get("intake_output_path", "")))
    if not project_name or not business_goal:
        raise ValueError("project_name and business_goal are required")
    if not isinstance(constraints, list):
        constraints = []
    md = [
        "# Real Project Intake",
        "",
        f"- project_name: {project_name}",
        f"- generated_at: {utc_now_iso()}",
        f"- business_goal: {business_goal}",
        "",
        "## Scope",
        "",
        scope or "Production-grade governed multi-agent delivery workflow.",
        "",
        "## Constraints",
        "",
    ]
    if constraints:
        md.extend([f"- {str(x)}" for x in constraints])
    else:
        md.append("- No additional constraints provided.")
    md.append("")
    return write_text(output_path, "\n".join(md))


def handle_env_define_promotion_model(payload: Dict[str, Any]) -> Dict[str, Any]:
    output_path = safe_project_path(str(payload.get("path", "")))
    model_name = str(payload.get("model_name", "")).strip()
    if not model_name:
        raise ValueError("model_name is required")
    value = {
        "model_name": model_name,
        "generated_at": utc_now_iso(),
        "environments": {
            "dev": {"approvals": 0, "checks": ["lint", "unit", "static-analysis"]},
            "test": {"approvals": 1, "checks": ["integration", "contract", "security-scan"]},
            "staging": {"approvals": 1, "checks": ["smoke", "observability-baseline", "release-gates"]},
            "prod": {"approvals": 2, "checks": ["manual-approval", "signed-sbom", "provenance", "safe-deployment", "rollback-ready"]}
        },
        "promotion_flow": ["dev", "test", "staging", "prod"]
    }
    return write_json(output_path, value)


def handle_cicd_write_pipeline_spec(payload: Dict[str, Any]) -> Dict[str, Any]:
    pipeline_name = str(payload.get("pipeline_name", "")).strip()
    intake_path = safe_project_path(str(payload.get("intake_path", "")))
    environment_model_path = safe_project_path(str(payload.get("environment_model_path", "")))
    output_path = safe_project_path(str(payload.get("pipeline_output_path", "")))
    if not pipeline_name:
        raise ValueError("pipeline_name is required")
    if not intake_path.exists() or not environment_model_path.exists():
        raise ValueError("intake_path and environment_model_path must exist")
    env_model = read_json(environment_model_path)
    yaml_text = "\n".join([
        f"name: {pipeline_name}",
        "trigger:",
        "  - main",
        "stages:",
        "  - dev",
        "  - test",
        "  - staging",
        "  - prod",
        "release_gates:",
        "  pre_prod_checks:",
        "    - integration",
        "    - security_scan",
        "  prod_checks:",
        "    - manual_approval",
        "    - signed_sbom",
        "    - provenance_attestation",
        "    - observability_validation",
        "promotion_flow: " + " -> ".join(env_model["promotion_flow"]),
        ""
    ])
    return write_text(output_path, yaml_text)


def handle_ops_write_observability_spec(payload: Dict[str, Any]) -> Dict[str, Any]:
    service_name = str(payload.get("service_name", "")).strip()
    pipeline_path = safe_project_path(str(payload.get("pipeline_path", "")))
    output_path = safe_project_path(str(payload.get("observability_output_path", "")))
    if not service_name:
        raise ValueError("service_name is required")
    if not pipeline_path.exists():
        raise ValueError("pipeline_path must exist")
    spec = {
        "service_name": service_name,
        "generated_at": utc_now_iso(),
        "metrics": ["latency_p95", "error_rate", "availability", "deployment_success_rate"],
        "alerts": ["sev1_error_budget_burn", "sev2_release_regression", "sev2_canary_failure"],
        "validation_gates": {
            "pre_deploy": ["baseline_available", "no_open_sev0"],
            "post_deploy": ["smoke_green", "alerts_clear", "rollback_signal_ready"]
        },
        "safe_deployment_strategy": {
            "mode": "ring_canary",
            "rings": ["internal", "limited", "broad", "global"]
        }
    }
    return write_json(output_path, spec)


def handle_ops_write_change_control_spec(payload: Dict[str, Any]) -> Dict[str, Any]:
    change_window = str(payload.get("change_window", "")).strip()
    pipeline_path = safe_project_path(str(payload.get("pipeline_path", "")))
    environment_model_path = safe_project_path(str(payload.get("environment_model_path", "")))
    output_path = safe_project_path(str(payload.get("change_control_output_path", "")))
    if not change_window:
        raise ValueError("change_window is required")
    if not pipeline_path.exists() or not environment_model_path.exists():
        raise ValueError("pipeline_path and environment_model_path must exist")
    md = [
        "# Secrets / Config / Artifact Governance + Change Control",
        "",
        f"- generated_at: {utc_now_iso()}",
        f"- change_window: {change_window}",
        "",
        "## Rules",
        "",
        "- Secrets are injected only at deploy time and never baked into artifacts.",
        "- Config is versioned per environment and promoted through the same governed pipeline.",
        "- Artifacts are immutable after signing and provenance generation.",
        "- Production changes require dual approval and rollback readiness.",
        "",
        "## Change Control",
        "",
        "- CAB review required before prod promotion.",
        "- Emergency change path requires post-incident review within 24h.",
        ""
    ]
    return write_text(output_path, "\n".join(md))


def handle_devops_generate_supply_chain_bundle(payload: Dict[str, Any]) -> Dict[str, Any]:
    release_name = str(payload.get("release_name", "")).strip()
    intake_path = safe_project_path(str(payload.get("intake_path", "")))
    pipeline_path = safe_project_path(str(payload.get("pipeline_path", "")))
    observability_path = safe_project_path(str(payload.get("observability_path", "")))
    change_control_path = safe_project_path(str(payload.get("change_control_path", "")))
    sbom_output_path = safe_project_path(str(payload.get("sbom_output_path", "")))
    provenance_output_path = safe_project_path(str(payload.get("provenance_output_path", "")))
    signing_output_path = safe_project_path(str(payload.get("signing_output_path", "")))
    if not release_name:
        raise ValueError("release_name is required")
    inputs = [intake_path, pipeline_path, observability_path, change_control_path]
    for p in inputs:
        if not p.exists():
            raise ValueError(f"required input missing: {p}")
    sbom = {
        "release_name": release_name,
        "generated_at": utc_now_iso(),
        "components": [
            {"path": str(p.relative_to(PROJECT_ROOT).as_posix()), "sha256": sha256_file(p)}
            for p in inputs
        ]
    }
    provenance = {
        "release_name": release_name,
        "generated_at": utc_now_iso(),
        "builder": "governed-phase12-runner",
        "source_artifacts": [str(p.relative_to(PROJECT_ROOT).as_posix()) for p in inputs]
    }
    signing = {
        "release_name": release_name,
        "generated_at": utc_now_iso(),
        "signature_policy": "signed-sbom-and-provenance-required",
        "signing_status": "attested"
    }
    write_json(sbom_output_path, sbom)
    write_json(provenance_output_path, provenance)
    write_json(signing_output_path, signing)
    return {
        "ok": True,
        "action": "generate_supply_chain_bundle",
        "sbom_output_path": str(sbom_output_path),
        "provenance_output_path": str(provenance_output_path),
        "signing_output_path": str(signing_output_path),
        "ts": utc_now_iso()
    }


def handle_architect_review_production_change(payload: Dict[str, Any]) -> Dict[str, Any]:
    review_title = str(payload.get("review_title", "")).strip()
    intake_path = safe_project_path(str(payload.get("intake_path", "")))
    environment_model_path = safe_project_path(str(payload.get("environment_model_path", "")))
    pipeline_path = safe_project_path(str(payload.get("pipeline_path", "")))
    observability_path = safe_project_path(str(payload.get("observability_path", "")))
    change_control_path = safe_project_path(str(payload.get("change_control_path", "")))
    sbom_path = safe_project_path(str(payload.get("sbom_path", "")))
    provenance_path = safe_project_path(str(payload.get("provenance_path", "")))
    signing_path = safe_project_path(str(payload.get("signing_path", "")))
    output_path = safe_project_path(str(payload.get("review_output_path", "")))
    if not review_title:
        raise ValueError("review_title is required")
    for p in [intake_path, environment_model_path, pipeline_path, observability_path, change_control_path, sbom_path, provenance_path, signing_path]:
        if not p.exists():
            raise ValueError(f"required input missing: {p}")
    review = {
        "review_title": review_title,
        "generated_at": utc_now_iso(),
        "decision": "approved-with-production-constraints",
        "constraints": [
            "Promote only through gated environments.",
            "Require signed SBOM and provenance before prod.",
            "Hold rollback package ready before broad exposure.",
            "Stop rollout on alert regression."
        ],
        "evidence": {
            "intake_path": str(intake_path),
            "environment_model_path": str(environment_model_path),
            "pipeline_path": str(pipeline_path),
            "observability_path": str(observability_path),
            "change_control_path": str(change_control_path),
            "sbom_path": str(sbom_path),
            "provenance_path": str(provenance_path),
            "signing_path": str(signing_path)
        }
    }
    return write_json(output_path, review)


def handle_release_promote_environment(payload: Dict[str, Any]) -> Dict[str, Any]:
    target_environment = str(payload.get("target_environment", "")).strip()
    strategy = str(payload.get("strategy", "")).strip()
    environment_model_path = safe_project_path(str(payload.get("environment_model_path", "")))
    pipeline_path = safe_project_path(str(payload.get("pipeline_path", "")))
    observability_path = safe_project_path(str(payload.get("observability_path", "")))
    change_control_path = safe_project_path(str(payload.get("change_control_path", "")))
    sbom_path = safe_project_path(str(payload.get("sbom_path", "")))
    provenance_path = safe_project_path(str(payload.get("provenance_path", "")))
    signing_path = safe_project_path(str(payload.get("signing_path", "")))
    change_review_path = safe_project_path(str(payload.get("change_review_path", "")))
    output_path = safe_project_path(str(payload.get("deployment_report_path", "")))
    if target_environment not in {"dev", "test", "staging", "prod"}:
        raise ValueError("target_environment must be one of dev/test/staging/prod")
    if not strategy:
        raise ValueError("strategy is required")
    for p in [environment_model_path, pipeline_path, observability_path, change_control_path, sbom_path, provenance_path, signing_path, change_review_path]:
        if not p.exists():
            raise ValueError(f"required input missing: {p}")
    env_model = read_json(environment_model_path)
    obs = read_json(observability_path)
    report = {
        "generated_at": utc_now_iso(),
        "target_environment": target_environment,
        "strategy": strategy,
        "promotion_flow": env_model["promotion_flow"],
        "prod_checks": env_model["environments"]["prod"]["checks"],
        "observability_validation_gates": obs["validation_gates"],
        "deployment_decision": "promoted",
        "safe_deployment": {
            "mode": "ring_canary",
            "current_ring": "internal",
            "next_rings": ["limited", "broad", "global"]
        },
        "rollback_ready": True
    }
    return write_json(output_path, report)


def handle_debugger_write_postmortem(payload: Dict[str, Any]) -> Dict[str, Any]:
    incident_title = str(payload.get("incident_title", "")).strip()
    deployment_report_path = safe_project_path(str(payload.get("deployment_report_path", "")))
    change_review_path = safe_project_path(str(payload.get("change_review_path", "")))
    output_path = safe_project_path(str(payload.get("postmortem_output_path", "")))
    if not incident_title:
        raise ValueError("incident_title is required")
    if not deployment_report_path.exists() or not change_review_path.exists():
        raise ValueError("deployment_report_path and change_review_path must exist")
    report = read_json(deployment_report_path)
    review = read_json(change_review_path)
    md = [
        "# Production Postmortem Workflow",
        "",
        f"- incident_title: {incident_title}",
        f"- generated_at: {utc_now_iso()}",
        "",
        "## Deployment Context",
        "",
        f"- target_environment: {report.get('target_environment')}",
        f"- strategy: {report.get('strategy')}",
        f"- rollback_ready: {report.get('rollback_ready')}",
        "",
        "## Architectural Decision",
        "",
        f"- decision: {review.get('decision')}",
        "",
        "## Recovery / Rollback",
        "",
        "- Validate current ring health.",
        "- Stop further promotion on alert regression.",
        "- Roll back to previous signed release if SLO breach persists.",
        "",
        "## Follow-up",
        "",
        "- Update change control if emergency path was used.",
        "- Review release gates and alert thresholds.",
        ""
    ]
    return write_text(output_path, "\n".join(md))


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 scripts/phase12_operational_runner.py <task_type>", file=sys.stderr)
        return 2

    task_type = sys.argv[1]
    payload = load_payload()
    gov = governance()
    gov_audit = audit()

    decision = gov.decide(task_type=task_type, payload=payload, service_path=task_type, mode="execution")
    if not decision.ok:
        gov_audit.log(
            "execution_denied_by_policy_runner",
            {
                "task_type": task_type,
                "owner_agent": decision.owner_agent,
                "reasons": decision.reasons,
                "payload_preview_keys": sorted(payload.keys())
            }
        )
        print(json.dumps({"ok": False, "task_type": task_type, "error": "governance denied execution", "reasons": decision.reasons, "ts": utc_now_iso()}, ensure_ascii=False))
        return 3

    gov_audit.log(
        "execution_allowed_by_policy_runner",
        {
            "task_type": task_type,
            "owner_agent": decision.owner_agent,
            "matched_paths": decision.matched_paths,
            "payload_preview_keys": sorted(payload.keys())
        }
    )

    handlers = {
        "intake.define_project": handle_intake_define_project,
        "env.define_promotion_model": handle_env_define_promotion_model,
        "cicd.write_pipeline_spec": handle_cicd_write_pipeline_spec,
        "ops.write_observability_spec": handle_ops_write_observability_spec,
        "ops.write_change_control_spec": handle_ops_write_change_control_spec,
        "devops.generate_supply_chain_bundle": handle_devops_generate_supply_chain_bundle,
        "architect.review_production_change": handle_architect_review_production_change,
        "release.promote_environment": handle_release_promote_environment,
        "debugger.write_postmortem": handle_debugger_write_postmortem
    }

    if task_type not in handlers:
        gov_audit.log("execution_denied_unknown_task_type", {"task_type": task_type})
        print(json.dumps({"ok": False, "task_type": task_type, "error": f"unknown task_type: {task_type}", "ts": utc_now_iso()}, ensure_ascii=False))
        return 2

    try:
        result = handlers[task_type](payload)
        gov_audit.log(
            "execution_handler_succeeded",
            {
                "task_type": task_type,
                "result_action": result.get("action"),
                "result_path": result.get("path") or result.get("deployment_report_path") or result.get("sbom_output_path")
            }
        )
        print(json.dumps({"ok": True, "task_type": task_type, "result": result, "ts": utc_now_iso()}, ensure_ascii=False))
        return 0
    except (GovernanceError, ValueError, RuntimeError) as exc:
        gov_audit.log("execution_handler_failed", {"task_type": task_type, "error": f"{type(exc).__name__}: {exc}"})
        print(json.dumps({"ok": False, "task_type": task_type, "error": f"{type(exc).__name__}: {exc}", "ts": utc_now_iso()}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
