#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config/phase13b_github_real.json"
BOOTSTRAP_DIR = ROOT / "artifacts/phase13b_real/bootstrap"
BOOTSTRAP_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fail(message: str, extra: dict | None = None) -> None:
    payload = {
        "ok": False,
        "error": message,
        "ts": utc_now(),
    }
    if extra:
        payload["detail"] = extra
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    sys.exit(1)


def run(
    cmd: list[str],
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        input=input_text,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def gh_api(
    method: str,
    path: str,
    body: dict | None = None,
    jq: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        "gh",
        "api",
        "-X",
        method,
        path,
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        "X-GitHub-Api-Version: 2022-11-28",
    ]
    if jq:
        cmd.extend(["--jq", jq])

    if body is not None:
        cmd.extend(["--input", "-"])
        return run(cmd, check=check, input_text=json.dumps(body))

    return run(cmd, check=check)


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        fail(f"missing config: {CONFIG_PATH}")
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {CONFIG_PATH}: {exc}")
    raise RuntimeError("unreachable")


def current_github_login() -> str:
    return gh_api("GET", "user", jq=".login").stdout.strip()


def repo_exists(owner: str, repo: str) -> bool:
    result = run(
        ["gh", "repo", "view", f"{owner}/{repo}", "--json", "nameWithOwner"],
        check=False,
    )
    return result.returncode == 0


def ensure_repo(owner: str, repo: str, visibility: str, create_if_missing: bool) -> None:
    if repo_exists(owner, repo):
        return

    if not create_if_missing:
        fail(
            "target GitHub repository does not exist and create_repo_if_missing=false",
            {"repo": f"{owner}/{repo}"},
        )

    visibility_flag = "--private" if visibility == "private" else "--public"
    run(
        [
            "gh",
            "repo",
            "create",
            f"{owner}/{repo}",
            visibility_flag,
            "--source",
            ".",
            "--remote",
            "origin",
            "--push",
        ]
    )


def ensure_default_branch(local_branch: str, default_branch: str) -> None:
    if local_branch != default_branch:
        fail(
            "current local branch does not match configured default branch",
            {
                "current_branch": local_branch,
                "default_branch": default_branch,
            },
        )


def git_current_branch() -> str:
    return run(["git", "branch", "--show-current"]).stdout.strip()


def ensure_origin_remote(owner: str, repo: str) -> None:
    remote = run(["git", "remote", "get-url", "origin"], check=False)
    expected_ssh = f"git@github.com:{owner}/{repo}.git"
    expected_https = f"https://github.com/{owner}/{repo}.git"

    if remote.returncode != 0:
        run(["git", "remote", "add", "origin", expected_ssh])
        return

    value = remote.stdout.strip()
    if value not in {expected_ssh, expected_https}:
        fail(
            "origin remote points to a different repository",
            {
                "origin": value,
                "expected_ssh": expected_ssh,
                "expected_https": expected_https,
            },
        )


def write_codeowners(codeowners: list[str], current_login: str) -> str:
    owners = [entry.strip() for entry in codeowners if entry.strip()]
    if not owners:
        owners = [f"@{current_login}"]

    content = "\n".join(
        [
            f"* {' '.join(owners)}",
            f"/scripts/ {' '.join(owners)}",
            f"/config/ {' '.join(owners)}",
            f"/.github/ {' '.join(owners)}",
            "",
        ]
    )

    path = ROOT / ".github" / "CODEOWNERS"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path.relative_to(ROOT))


def resolve_reviewer(owner: str, raw: str) -> dict:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty reviewer entry")

    if raw.startswith("team:"):
        slug = raw.split(":", 1)[1].strip()
        if not slug:
            raise ValueError(f"invalid team reviewer entry: {raw}")
        team = json.loads(gh_api("GET", f"orgs/{owner}/teams/{slug}").stdout)
        return {
            "type": "Team",
            "id": team["id"],
            "slug": slug,
        }

    login = raw.removeprefix("@")
    user = json.loads(gh_api("GET", f"users/{login}").stdout)
    return {
        "type": "User",
        "id": user["id"],
        "login": login,
    }


def normalize_reviewers(owner: str, reviewers: list[str]) -> tuple[list[dict], list[dict]]:
    resolved: list[dict] = []
    display: list[dict] = []

    for entry in reviewers:
        item = resolve_reviewer(owner, entry)
        resolved.append({"type": item["type"], "id": item["id"]})
        display.append(item)

    return resolved, display


def protect_branch(owner: str, repo: str, branch: str, cfg: dict) -> None:
    payload = {
        "required_status_checks": {
            "strict": True,
            "contexts": cfg["required_status_checks"],
        },
        "enforce_admins": cfg["enforce_admins"],
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": cfg["dismiss_stale_reviews"],
            "require_code_owner_reviews": cfg["require_code_owner_reviews"],
            "required_approving_review_count": cfg["required_approving_review_count"],
            "require_last_push_approval": cfg["require_last_push_approval"],
        },
        "restrictions": None,
        "required_linear_history": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "block_creations": True,
        "required_conversation_resolution": True,
        "lock_branch": False,
        "allow_fork_syncing": False,
    }

    gh_api(
        "PUT",
        f"repos/{owner}/{repo}/branches/{branch}/protection",
        body=payload,
    )

    if cfg["enforce_admins"]:
        gh_api(
            "POST",
            f"repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins",
        )

    if cfg["require_signed_commits"]:
        gh_api(
            "POST",
            f"repos/{owner}/{repo}/branches/{branch}/protection/required_signatures",
        )


def configure_environment(
    owner: str,
    repo: str,
    env_name: str,
    wait_timer: int,
    reviewer_specs: list[str],
    prevent_self_review: bool,
) -> dict:
    encoded_env = urllib.parse.quote(env_name, safe="")
    reviewers_api, reviewers_display = normalize_reviewers(owner, reviewer_specs)

    payload = {
        "wait_timer": wait_timer,
        "prevent_self_review": prevent_self_review,
        "reviewers": reviewers_api if reviewers_api else None,
        "deployment_branch_policy": {
            "protected_branches": True,
            "custom_branch_policies": False,
        },
    }

    response = gh_api(
        "PUT",
        f"repos/{owner}/{repo}/environments/{encoded_env}",
        body=payload,
    )
    data = json.loads(response.stdout)

    return {
        "name": env_name,
        "wait_timer": wait_timer,
        "prevent_self_review": prevent_self_review,
        "reviewers": reviewers_display,
        "html_url": data.get("html_url"),
        "deployment_branch_policy": data.get("deployment_branch_policy"),
    }


def write_summary(summary: dict) -> None:
    json_path = BOOTSTRAP_DIR / "bootstrap_summary.json"
    md_path = BOOTSTRAP_DIR / "bootstrap_summary.md"

    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    lines = [
        "# Phase13B GitHub Bootstrap Summary",
        "",
        f"- generated_at: {summary['generated_at']}",
        f"- repo: {summary['repo']}",
        f"- default_branch: {summary['default_branch']}",
        f"- codeowners_path: {summary['codeowners_path']}",
        "",
        "## Environments",
        "",
    ]

    for env in summary["environments"]:
        lines.append(f"### {env['name']}")
        lines.append(f"- wait_timer: {env['wait_timer']}")
        lines.append(f"- prevent_self_review: {env['prevent_self_review']}")
        lines.append(f"- reviewers_count: {len(env['reviewers'])}")
        if env["html_url"]:
            lines.append(f"- html_url: {env['html_url']}")
        lines.append("")

    warnings = summary.get("warnings", [])
    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for item in warnings:
            lines.append(f"- {item}")
        lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    try:
        run(["gh", "auth", "status"])
    except RuntimeError:
        fail("GitHub CLI is not authenticated. Run: gh auth login --web --git-protocol ssh")

    cfg = load_config()
    gh_cfg = cfg["github"]

    current_login = current_github_login()
    owner = gh_cfg["owner"] or current_login
    repo = gh_cfg["repo"]
    visibility = gh_cfg["visibility"]
    default_branch = gh_cfg["default_branch"]

    local_branch = git_current_branch()
    ensure_default_branch(local_branch, default_branch)

    ensure_repo(owner, repo, visibility, gh_cfg["create_repo_if_missing"])
    ensure_origin_remote(owner, repo)

    codeowners_path = write_codeowners(gh_cfg.get("codeowners", []), current_login)
    protect_branch(owner, repo, default_branch, gh_cfg)

    wait_timers = gh_cfg["environment_wait_timers"]

    dev_env = configure_environment(
        owner=owner,
        repo=repo,
        env_name="dev",
        wait_timer=wait_timers["dev"],
        reviewer_specs=gh_cfg.get("dev_reviewers", []),
        prevent_self_review=False,
    )

    staging_env = configure_environment(
        owner=owner,
        repo=repo,
        env_name="staging",
        wait_timer=wait_timers["staging"],
        reviewer_specs=gh_cfg.get("staging_reviewers", []),
        prevent_self_review=False,
    )

    production_reviewers = gh_cfg.get("production_reviewers", [])
    prod_env = configure_environment(
        owner=owner,
        repo=repo,
        env_name="production",
        wait_timer=wait_timers["production"],
        reviewer_specs=production_reviewers,
        prevent_self_review=True if production_reviewers else False,
    )

    warnings: list[str] = []

    if not production_reviewers:
        warnings.append(
            "production_reviewers is empty; production environment was created without reviewer gate. "
            "This is operationally weaker than the target governance model."
        )

    if (
        gh_cfg["required_approving_review_count"] > 1
        and len(production_reviewers) < gh_cfg["required_approving_review_count"]
    ):
        warnings.append(
            "required_approving_review_count is greater than the number of production reviewers configured. "
            "GitHub environment approval and PR review count are not identical controls."
        )

    summary = {
        "ok": True,
        "generated_at": utc_now(),
        "repo": f"{owner}/{repo}",
        "default_branch": default_branch,
        "codeowners_path": codeowners_path,
        "branch_protection": {
            "required_status_checks": gh_cfg["required_status_checks"],
            "required_approving_review_count": gh_cfg["required_approving_review_count"],
            "require_code_owner_reviews": gh_cfg["require_code_owner_reviews"],
            "dismiss_stale_reviews": gh_cfg["dismiss_stale_reviews"],
            "require_last_push_approval": gh_cfg["require_last_push_approval"],
            "enforce_admins": gh_cfg["enforce_admins"],
            "require_signed_commits": gh_cfg["require_signed_commits"],
        },
        "environments": [dev_env, staging_env, prod_env],
        "warnings": warnings,
    }

    write_summary(summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        fail(str(exc))
