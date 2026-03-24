from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from scripts.task_registry import (
    AGENT_REGISTRY,
    find_candidate_workers,
    get_task_spec,
    get_worker_capabilities,
    get_worker_tools,
    is_known_task_type,
)


BASE_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = BASE_DIR / "config" / "policies" / "orchestrator_policy.json"


@lru_cache(maxsize=1)
def _load_policy_cached() -> dict[str, Any]:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def load_policy(force_reload: bool = False) -> dict[str, Any]:
    if force_reload:
        _load_policy_cached.cache_clear()
    return _load_policy_cached()


def get_policy_snapshot(force_reload: bool = False) -> dict[str, Any]:
    return load_policy(force_reload=force_reload)


def get_policy_source() -> str:
    return str(POLICY_PATH)


def get_global_worker_loop_settings(force_reload: bool = False) -> dict[str, int]:
    policy = load_policy(force_reload=force_reload)
    return dict(policy["global"]["worker_loop"])


def get_global_limits(force_reload: bool = False) -> dict[str, int]:
    policy = load_policy(force_reload=force_reload)
    return dict(policy["global"]["limits"])


def _global_limits(policy: dict[str, Any]) -> dict[str, int]:
    return dict(policy["global"]["limits"])


def _global_recovery_policy(policy: dict[str, Any]) -> dict[str, str]:
    return dict(policy["global"]["recovery_policy"])


def get_task_limits(task_type: str, force_reload: bool = False) -> dict[str, int]:
    policy = load_policy(force_reload=force_reload)
    merged = _global_limits(policy)
    merged.update(policy.get("tasks", {}).get(task_type, {}).get("limits", {}))
    return merged


def get_recovery_policy(task_type: str, force_reload: bool = False) -> dict[str, str]:
    policy = load_policy(force_reload=force_reload)
    merged = _global_recovery_policy(policy)
    merged.update(policy.get("tasks", {}).get(task_type, {}).get("recovery_policy", {}))
    return merged


def build_policy_input(worker_id: str, task_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    worker = AGENT_REGISTRY.get(worker_id, {})
    task_spec = get_task_spec(task_type)

    return {
        "worker_id": worker_id,
        "task_type": task_type,
        "payload": payload,
        "worker": {
            "exists": worker_id in AGENT_REGISTRY,
            "agent_role": worker.get("agent_role"),
            "capabilities": list(worker.get("capabilities", [])),
            "tools": list(worker.get("tools", [])),
        },
        "task": {
            "exists": is_known_task_type(task_type),
            "spec": task_spec,
            "candidate_workers": find_candidate_workers(task_type),
        },
        "policy": {
            "source": get_policy_source(),
            "limits": get_task_limits(task_type) if is_known_task_type(task_type) else {},
            "recovery_policy": get_recovery_policy(task_type) if is_known_task_type(task_type) else {},
            "worker_loop": get_global_worker_loop_settings(),
            "global_limits": get_global_limits(),
        },
    }


def classify_task_routability(task_type: str) -> tuple[bool, dict[str, Any]]:
    if not is_known_task_type(task_type):
        return False, {
            "reason": "unknown_task_type",
            "candidate_workers": [],
            "policy_source": get_policy_source(),
        }

    candidates = find_candidate_workers(task_type)
    if not candidates:
        return False, {
            "reason": "no_capable_worker",
            "candidate_workers": [],
            "policy_source": get_policy_source(),
        }

    spec = get_task_spec(task_type)
    if spec is None:
        return False, {
            "reason": "missing_task_spec",
            "candidate_workers": candidates,
            "policy_source": get_policy_source(),
        }

    return True, {
        "reason": "routable",
        "candidate_workers": candidates,
        "owner_role": spec["owner_role"],
        "allowed_tools": spec["allowed_tools"],
        "limits": get_task_limits(task_type),
        "recovery_policy": get_recovery_policy(task_type),
        "policy_source": get_policy_source(),
    }


def evaluate_admission(worker_id: str, task_type: str, payload: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    policy_input = build_policy_input(worker_id, task_type, payload)
    policy_cfg = load_policy().get("admission", {})

    if worker_id not in AGENT_REGISTRY:
        return False, {
            "reason": f"unknown worker '{worker_id}'",
            "decision": "deny",
            "policy_source": get_policy_source(),
            "policy_input": policy_input,
            "limits": {},
            "recovery_policy": {},
        }

    if not is_known_task_type(task_type):
        return False, {
            "reason": f"unknown task type '{task_type}'",
            "decision": "deny",
            "policy_source": get_policy_source(),
            "policy_input": policy_input,
            "limits": {},
            "recovery_policy": {},
        }

    spec = get_task_spec(task_type)
    worker = AGENT_REGISTRY[worker_id]

    if spec is None:
        return False, {
            "reason": f"missing task spec for '{task_type}'",
            "decision": "deny",
            "policy_source": get_policy_source(),
            "policy_input": policy_input,
            "limits": {},
            "recovery_policy": {},
        }

    required_capabilities = set(spec["required_capabilities"])
    worker_capabilities = set(get_worker_capabilities(worker_id))
    if not required_capabilities.issubset(worker_capabilities):
        return False, {
            "reason": (
                f"Worker '{worker_id}' lacks capabilities for '{task_type}'. "
                f"Required={sorted(required_capabilities)} Worker={sorted(worker_capabilities)}"
            ),
            "decision": "deny",
            "policy_source": get_policy_source(),
            "policy_input": policy_input,
            "limits": get_task_limits(task_type),
            "recovery_policy": get_recovery_policy(task_type),
        }

    if policy_cfg.get("require_owner_role_match", True):
        if worker.get("agent_role") != spec["owner_role"]:
            return False, {
                "reason": (
                    f"Worker '{worker_id}' role '{worker.get('agent_role')}' "
                    f"does not match task owner role '{spec['owner_role']}'"
                ),
                "decision": "deny",
                "policy_source": get_policy_source(),
                "policy_input": policy_input,
                "limits": get_task_limits(task_type),
                "recovery_policy": get_recovery_policy(task_type),
            }

    if policy_cfg.get("require_worker_tools_cover_task_tools", True):
        worker_tools = set(get_worker_tools(worker_id))
        task_tools = set(spec["allowed_tools"])
        if not task_tools.issubset(worker_tools):
            return False, {
                "reason": (
                    f"Worker '{worker_id}' lacks required tools for '{task_type}'. "
                    f"Required={sorted(task_tools)} Worker={sorted(worker_tools)}"
                ),
                "decision": "deny",
                "policy_source": get_policy_source(),
                "policy_input": policy_input,
                "limits": get_task_limits(task_type),
                "recovery_policy": get_recovery_policy(task_type),
            }

    return True, {
        "reason": "allowed",
        "decision": "allow",
        "owner_role": spec["owner_role"],
        "allowed_tools": spec["allowed_tools"],
        "limits": get_task_limits(task_type),
        "recovery_policy": get_recovery_policy(task_type),
        "policy_source": get_policy_source(),
        "policy_input": policy_input,
    }


def decide_recovery_action(task: dict[str, Any], failure_reason: str) -> dict[str, Any]:
    task_type = str(task["task_type"])
    attempt_count = int(task["attempt_count"])
    max_attempts = int(task["max_attempts"])

    if attempt_count >= max_attempts:
        return {
            "next_status": "dead_letter",
            "policy_action": "dead_letter",
            "policy_source": "max_attempts_guard",
            "reason_text": f"{failure_reason}: max_attempts reached ({attempt_count}/{max_attempts})",
        }

    if not is_known_task_type(task_type):
        return {
            "next_status": "dead_letter",
            "policy_action": "dead_letter",
            "policy_source": get_policy_source(),
            "reason_text": f"{failure_reason}: unknown task type '{task_type}'",
        }

    task_policy = get_recovery_policy(task_type)
    action = task_policy.get(failure_reason, "dead_letter")
    next_status = "queued" if action == "requeue" else "dead_letter"

    return {
        "next_status": next_status,
        "policy_action": action,
        "policy_source": get_policy_source(),
        "reason_text": f"{failure_reason}: recovery policy decided '{action}' for '{task_type}'",
    }
