from __future__ import annotations

import json
from pathlib import Path


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_config(base_dir: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []

    config_dir = base_dir / "config"
    required_files = [
        config_dir / "agents.json",
        config_dir / "routing_rules.json",
        config_dir / "file_ownership.json",
        config_dir / "memory_policy.json",
    ]

    for path in required_files:
        if not path.exists():
            errors.append(f"missing config file: {path}")

    if errors:
        return False, errors

    try:
        agents = _load_json(config_dir / "agents.json")
        routing = _load_json(config_dir / "routing_rules.json")
        ownership = _load_json(config_dir / "file_ownership.json")
        memory_policy = _load_json(config_dir / "memory_policy.json")
    except Exception as e:
        return False, [f"json parse error: {e}"]

    if not isinstance(agents, list) or not agents:
        errors.append("agents.json must contain a non-empty list")

    agent_types = set()
    capabilities = set()

    for idx, agent in enumerate(agents):
        for field in ("agent_id", "agent_type", "capabilities", "allowed_tools", "status"):
            if field not in agent:
                errors.append(f"agents[{idx}] missing field: {field}")

        if "agent_type" in agent:
            agent_types.add(agent["agent_type"])

        if "capabilities" in agent and isinstance(agent["capabilities"], list):
            capabilities.update(agent["capabilities"])

    if not isinstance(routing, dict) or not routing:
        errors.append("routing_rules.json must contain a non-empty object")
    else:
        for task_type, agent_type in routing.items():
            if agent_type not in agent_types:
                errors.append(f"routing rule points to unknown agent_type: {task_type} -> {agent_type}")

    if not isinstance(ownership, dict) or not ownership:
        errors.append("file_ownership.json must contain a non-empty object")
    else:
        for agent_type in agent_types:
            if agent_type not in ownership:
                errors.append(f"missing file ownership for agent_type: {agent_type}")

    if not isinstance(memory_policy, dict) or "filesystem" not in memory_policy:
        errors.append("memory_policy.json must contain 'filesystem' section")

    return len(errors) == 0, errors
