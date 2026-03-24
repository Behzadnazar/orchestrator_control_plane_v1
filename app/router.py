from __future__ import annotations
import json
from pathlib import Path
from .config import CONFIG_DIR
from . import db

ROUTING_RULES = json.loads((CONFIG_DIR / "routing_rules.json").read_text(encoding="utf-8"))

def route_task(task: dict) -> dict:
    task_type = task["task_type"]
    target_agent_type = ROUTING_RULES.get(task_type)
    if not target_agent_type:
        raise ValueError(f"no routing rule for task_type={task_type}")

    agents = db.list_agents()
    candidates = [
        a for a in agents
        if a["agent_type"] == target_agent_type
        and a["status"] == "Idle"
        and (task_type in a["capabilities"] or target_agent_type in a["capabilities"])
    ]
    if not candidates:
        raise RuntimeError(f"no available agent for task_type={task_type}, target_agent_type={target_agent_type}")
    return candidates[0]
