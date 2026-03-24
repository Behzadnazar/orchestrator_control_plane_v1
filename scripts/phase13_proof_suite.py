from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


UTC = timezone.utc
PHASE13_KEY = "phase13_external_v1"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def run(project_root: Path, cmd: List[str], stdin_text: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(project_root), input=stdin_text, capture_output=True, text=True, check=False)


def path_exists(project_root: Path, rel: str) -> bool:
    return (project_root / rel).exists()


def read_json_file(project_root: Path, rel: str) -> Any:
    with (project_root / rel).open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    handover_dir = project_root / "artifacts" / "phase13_handover"
    handover_dir.mkdir(parents=True, exist_ok=True)

    proofs: List[Dict[str, Any]] = []

    artifact_checks = [
        ("boundary_exists", "artifacts/runs/phase13_external_v1/boundary/integration_boundary.md"),
        ("repo_binding_exists", "artifacts/runs/phase13_external_v1/repo/repo_ci_binding.json"),
        ("environment_governance_exists", "artifacts/runs/phase13_external_v1/environments/environment_governance.json"),
        ("secrets_config_exists", "artifacts/runs/phase13_external_v1/security/secrets_config.json"),
        ("supply_chain_exists", "artifacts/runs/phase13_external_v1/security/supply_chain_bundle.json"),
        ("rollout_exists", "artifacts/runs/phase13_external_v1/rollout/rollout_strategy.json"),
        ("observability_change_exists", "artifacts/runs/phase13_external_v1/ops/observability_change_integration.json"),
        ("first_delivery_exists", "artifacts/runs/phase13_external_v1/delivery/first_external_delivery_plan.json")
    ]
    for proof_id, rel in artifact_checks:
        ok = path_exists(project_root, rel)
        proofs.append({"proof_id": proof_id, "expected": True, "actual": ok, "ok": ok})

    env_cfg = read_json_file(project_root, "artifacts/runs/phase13_external_v1/environments/environment_governance.json")
    prod_cfg = env_cfg["environments"]["prod"]
    proofs.append({"proof_id": "prod_required_reviewers", "expected": 2, "actual": prod_cfg.get("required_reviewers"), "ok": prod_cfg.get("required_reviewers") == 2})
    proofs.append({"proof_id": "prod_prevent_self_review", "expected": True, "actual": prod_cfg.get("prevent_self_review"), "ok": prod_cfg.get("prevent_self_review") is True})

    secrets_cfg = read_json_file(project_root, "artifacts/runs/phase13_external_v1/security/secrets_config.json")
    proofs.append({"proof_id": "secretless_auth_preferred", "expected": "oidc_or_workload_identity_federation", "actual": secrets_cfg["secret_model"]["preferred_auth"], "ok": secrets_cfg["secret_model"]["preferred_auth"] == "oidc_or_workload_identity_federation"})

    supply = read_json_file(project_root, "artifacts/runs/phase13_external_v1/security/supply_chain_bundle.json")
    proofs.append({"proof_id": "attestation_required", "expected": True, "actual": supply["attestation"]["required"], "ok": supply["attestation"]["required"] is True})
    proofs.append({"proof_id": "signed_sbom_required", "expected": True, "actual": supply["sbom"]["signed"], "ok": supply["sbom"]["signed"] is True})

    rollout = read_json_file(project_root, "artifacts/runs/phase13_external_v1/rollout/rollout_strategy.json")
    proofs.append({"proof_id": "rollout_mode_ring_canary", "expected": "ring_canary", "actual": rollout["deployment_strategy"]["mode"], "ok": rollout["deployment_strategy"]["mode"] == "ring_canary"})

    delivery = read_json_file(project_root, "artifacts/runs/phase13_external_v1/delivery/first_external_delivery_plan.json")
    proofs.append({"proof_id": "delivery_attestation_ready", "expected": True, "actual": delivery["release_readiness"]["attestation_ready"], "ok": delivery["release_readiness"]["attestation_ready"] is True})
    proofs.append({"proof_id": "delivery_rollback_ready", "expected": True, "actual": delivery["release_readiness"]["rollback_ready"], "ok": delivery["release_readiness"]["rollback_ready"] is True})

    path_escape = run(
        project_root,
        ["python3", "scripts/phase13_operational_runner.py", "external.configure_secrets_access"],
        stdin_text=json.dumps({"secrets_config_output_path": "/tmp/phase13-evil.json"})
    )
    proofs.append({
        "proof_id": "path_escape_denied",
        "expected": 1,
        "actual": path_escape.returncode,
        "ok": path_escape.returncode == 1,
        "detail": (path_escape.stdout or "").strip()
    })

    passed = sum(1 for p in proofs if p["ok"])
    summary = {
        "generated_at": utc_now_iso(),
        "workflow_run_key": PHASE13_KEY,
        "passed": passed,
        "total": len(proofs),
        "proofs": proofs
    }

    with (handover_dir / "phase13_proof_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, sort_keys=True)

    md = [
        "# Phase13 Proof Summary",
        "",
        f"- generated_at: {summary['generated_at']}",
        f"- passed: {passed}/{len(proofs)}",
        "",
        "## Proofs",
        ""
    ]
    for item in proofs:
        md.append(f"### {item['proof_id']}")
        md.append(f"- expected: {item['expected']}")
        md.append(f"- actual: {item['actual']}")
        md.append(f"- ok: {item['ok']}")
        if item.get("detail"):
            md.append(f"- detail: {item['detail']}")
        md.append("")
    (handover_dir / "phase13_proof_summary.md").write_text("\n".join(md), encoding="utf-8")

    print(json.dumps({
        "ok": True,
        "passed": passed,
        "total": len(proofs),
        "handover_json": str(handover_dir / "phase13_proof_summary.json"),
        "handover_md": str(handover_dir / "phase13_proof_summary.md")
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
