#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config/phase13b_github_real.json"
PROOF_DIR = ROOT / "artifacts/phase13b_real/proof"
PROOF_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def gh_api(path: str, jq: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    cmd = [
        "gh", "api",
        path,
        "-H", "Accept: application/vnd.github+json",
        "-H", "X-GitHub-Api-Version: 2022-11-28",
    ]
    if jq:
        cmd.extend(["--jq", jq])
    return run(cmd, check=check)


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def current_login() -> str:
    return gh_api("user", jq=".login").stdout.strip()


def write_json(name: str, data: object) -> None:
    (PROOF_DIR / name).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def safe_json_request(path: str) -> tuple[bool, object]:
    result = gh_api(path, check=False)
    if result.returncode != 0:
        return False, {"error": result.stderr.strip(), "path": path}
    return True, json.loads(result.stdout)


def main() -> None:
    cfg = load_config()
    gh_cfg = cfg["github"]

    owner = gh_cfg["owner"] or current_login()
    repo = gh_cfg["repo"]
    branch = gh_cfg["default_branch"]
    release_prefix = gh_cfg["release_prefix"]

    ok_repo, repo_data = safe_json_request(f"repos/{owner}/{repo}")
    ok_branch, branch_protection = safe_json_request(f"repos/{owner}/{repo}/branches/{branch}/protection")
    ok_signed, signed_commits = safe_json_request(f"repos/{owner}/{repo}/branches/{branch}/protection/required_signatures")
    ok_prod, prod_env = safe_json_request(f"repos/{owner}/{repo}/environments/production")
    ok_runs, runs = safe_json_request(f"repos/{owner}/{repo}/actions/workflows/phase13b_governed_delivery.yml/runs?per_page=5")
    ok_releases, releases = safe_json_request(f"repos/{owner}/{repo}/releases?per_page=10")
    ok_deployments, deployments = safe_json_request(f"repos/{owner}/{repo}/deployments?environment=production&per_page=10")

    write_json("repo.json", repo_data)
    write_json("branch_protection.json", branch_protection)
    write_json("required_signatures.json", signed_commits)
    write_json("production_environment.json", prod_env)
    write_json("workflow_runs.json", runs)
    write_json("releases.json", releases)
    write_json("deployments.json", deployments)

    latest_release = None
    if ok_releases and isinstance(releases, list):
        for item in releases:
            tag = item.get("tag_name", "")
            if tag.startswith(release_prefix):
                latest_release = item
                break

    summary = {
        "generated_at": utc_now(),
        "repo": f"{owner}/{repo}",
        "checks": {
            "repo_exists": ok_repo,
            "branch_protection_present": ok_branch,
            "signed_commits_required": ok_signed,
            "production_environment_present": ok_prod,
            "workflow_runs_visible": ok_runs,
            "releases_visible": ok_releases,
            "deployments_visible": ok_deployments,
            "latest_phase13b_release_present": latest_release is not None
        },
        "latest_release": {
            "tag_name": latest_release.get("tag_name") if latest_release else None,
            "html_url": latest_release.get("html_url") if latest_release else None,
            "asset_names": [asset.get("name") for asset in latest_release.get("assets", [])] if latest_release else []
        },
        "production_environment": {
            "prevent_self_review": None,
            "reviewers_count": 0
        },
        "recent_workflow_runs": [],
        "recent_deployments_count": len(deployments) if isinstance(deployments, list) else None
    }

    if ok_prod and isinstance(prod_env, dict):
        rules = prod_env.get("protection_rules", [])
        for rule in rules:
            if rule.get("type") == "required_reviewers":
                summary["production_environment"]["prevent_self_review"] = rule.get("prevent_self_review")
                summary["production_environment"]["reviewers_count"] = len(rule.get("reviewers", []))

    if ok_runs and isinstance(runs, dict):
        for item in runs.get("workflow_runs", [])[:5]:
            summary["recent_workflow_runs"].append({
                "id": item.get("id"),
                "status": item.get("status"),
                "conclusion": item.get("conclusion"),
                "html_url": item.get("html_url"),
                "head_branch": item.get("head_branch")
            })

    write_json("github_state_summary.json", summary)

    lines = [
        "# Phase13B GitHub State Summary",
        "",
        f"- generated_at: {summary['generated_at']}",
        f"- repo: {summary['repo']}",
        "",
        "## Checks",
        "",
    ]
    for key, value in summary["checks"].items():
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("## Production Environment")
    lines.append("")
    lines.append(f"- prevent_self_review: {summary['production_environment']['prevent_self_review']}")
    lines.append(f"- reviewers_count: {summary['production_environment']['reviewers_count']}")
    lines.append("")
    lines.append("## Latest Release")
    lines.append("")
    lines.append(f"- tag_name: {summary['latest_release']['tag_name']}")
    lines.append(f"- html_url: {summary['latest_release']['html_url']}")
    for asset in summary["latest_release"]["asset_names"]:
        lines.append(f"- asset: {asset}")
    lines.append("")
    lines.append("## Recent Workflow Runs")
    lines.append("")
    for item in summary["recent_workflow_runs"]:
        lines.append(
            f"- id={item['id']} status={item['status']} conclusion={item['conclusion']} branch={item['head_branch']}"
        )
    lines.append("")

    (PROOF_DIR / "github_state_summary.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
