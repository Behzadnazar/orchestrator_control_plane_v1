from __future__ import annotations
import json
from pathlib import Path
from .config import CONFIG_DIR
from .models import CRITICAL_PATH_HINTS

FILE_OWNERSHIP = json.loads((CONFIG_DIR / "file_ownership.json").read_text(encoding="utf-8"))
MEMORY_POLICY = json.loads((CONFIG_DIR / "memory_policy.json").read_text(encoding="utf-8"))

HUMAN_REQUIRED_TASK_TYPES = {"deployment", "security_audit", "production_change"}

def path_matches_prefix(path: str, prefixes: list[str]) -> bool:
    for prefix in prefixes:
        if prefix == "*" or path.startswith(prefix):
            return True
    return False

def check_file_write_permission(agent_type: str, target_files: list[str]) -> tuple[bool, str]:
    allowed_prefixes = FILE_OWNERSHIP.get(agent_type, [])
    for path in target_files:
        if not path_matches_prefix(path, allowed_prefixes):
            return False, f"agent_type={agent_type} cannot modify file={path}; allowed_prefixes={allowed_prefixes}"
    return True, "ok"

def requires_human(task: dict) -> tuple[bool, str]:
    if task["task_type"] in HUMAN_REQUIRED_TASK_TYPES:
        return True, f"task_type={task['task_type']} requires human approval"
    for path in task["payload"].get("target_files", []):
        lowered = path.lower()
        for hint in CRITICAL_PATH_HINTS:
            if hint.lower() in lowered:
                return True, f"critical target file requires human approval: {path}"
    return False, "no human approval required"

def check_tool_permission(agent: dict, tool_name: str) -> tuple[bool, str]:
    if tool_name not in agent["allowed_tools"]:
        return False, f"tool={tool_name} not allowed for agent={agent['agent_id']}"
    return True, "ok"

def check_memory_access(agent_type: str, plane: str, mode: str, path: str | None = None) -> tuple[bool, str]:
    plane_policy = MEMORY_POLICY.get(plane, {})
    role_policy = plane_policy.get(agent_type) or plane_policy.get("all")
    if not role_policy:
        return False, f"no memory policy for plane={plane} agent_type={agent_type}"
    rule = role_policy.get(mode)
    if isinstance(rule, bool):
        return (rule, "ok" if rule else "denied")
    if isinstance(rule, list):
        if path is None:
            return False, f"path required for plane={plane} mode={mode}"
        for prefix in rule:
            if prefix == "*" or path.startswith(prefix):
                return True, "ok"
        return False, f"path={path} denied by memory policy"
    return False, "invalid policy rule"
