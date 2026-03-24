from __future__ import annotations

from typing import Any


TASK_CATALOG: dict[str, dict[str, Any]] = {
    "backend.test": {
        "handler": "handle_backend_test",
        "owner_role": "backend",
        "allowed_tools": ["python", "filesystem", "tests"],
        "required_capabilities": ["backend.test"],
        "required_payload_keys": [],
    },
    "backend.fail_test": {
        "handler": "handle_backend_fail_test",
        "owner_role": "backend",
        "allowed_tools": ["python", "filesystem", "tests"],
        "required_capabilities": ["backend.fail_test"],
        "required_payload_keys": [],
    },
    "backend.write_file": {
        "handler": "handle_backend_write_file",
        "owner_role": "backend",
        "allowed_tools": ["python", "filesystem", "tests"],
        "required_capabilities": ["backend.write_file"],
        "required_payload_keys": ["path", "content", "workflow_run_key"],
    },
    "frontend.write_component": {
        "handler": "handle_frontend_write_component",
        "owner_role": "frontend",
        "allowed_tools": ["filesystem", "ui"],
        "required_capabilities": ["frontend.write_component"],
        "required_payload_keys": ["component_name", "source_notes_path", "target_path", "workflow_run_key"],
    },
    "research.collect_notes": {
        "handler": "handle_research_collect_notes",
        "owner_role": "research",
        "allowed_tools": ["filesystem", "notes"],
        "required_capabilities": ["research.collect_notes"],
        "required_payload_keys": ["topic", "notes_path", "workflow_run_key"],
    },
}


def _build_frozen_task_registry() -> dict[str, dict[str, str]]:
    frozen: dict[str, dict[str, str]] = {}
    for task_type, spec in TASK_CATALOG.items():
        entry: dict[str, str] = {"handler": str(spec["handler"])}
        executor = spec.get("executor")
        if isinstance(executor, str) and executor.strip():
            entry["executor"] = executor
        frozen[task_type] = entry
    return frozen


TASK_REGISTRY: dict[str, dict[str, str]] = _build_frozen_task_registry()


AGENT_REGISTRY: dict[str, dict[str, Any]] = {
    "backend-worker-v2": {
        "agent_role": "backend",
        "capabilities": ["backend.test", "backend.fail_test", "backend.write_file"],
        "tools": ["python", "filesystem", "tests"],
    },
    "frontend-worker-v1": {
        "agent_role": "frontend",
        "capabilities": ["frontend.write_component"],
        "tools": ["filesystem", "ui"],
    },
    "research-worker-v1": {
        "agent_role": "research",
        "capabilities": ["research.collect_notes"],
        "tools": ["filesystem", "notes"],
    },
}


def get_task_catalog() -> dict[str, dict[str, Any]]:
    return {task_type: dict(spec) for task_type, spec in TASK_CATALOG.items()}


def load_task_catalog() -> dict[str, dict[str, Any]]:
    return get_task_catalog()


def build_task_catalog() -> dict[str, dict[str, Any]]:
    return get_task_catalog()


def get_task_registry() -> dict[str, dict[str, str]]:
    return {task_type: dict(spec) for task_type, spec in TASK_REGISTRY.items()}


def load_task_registry() -> dict[str, dict[str, str]]:
    return get_task_registry()


def build_task_registry() -> dict[str, dict[str, str]]:
    return get_task_registry()


def get_agent_registry() -> dict[str, dict[str, Any]]:
    return {worker_id: dict(spec) for worker_id, spec in AGENT_REGISTRY.items()}


def load_agent_registry() -> dict[str, dict[str, Any]]:
    return get_agent_registry()


def build_agent_registry() -> dict[str, dict[str, Any]]:
    return get_agent_registry()


def is_known_task_type(task_type: str) -> bool:
    return task_type in TASK_CATALOG


def get_registry_entry(task_type: str) -> dict[str, str] | None:
    spec = TASK_REGISTRY.get(task_type)
    return dict(spec) if isinstance(spec, dict) else None


def get_task_spec(task_type: str) -> dict[str, Any] | None:
    spec = TASK_CATALOG.get(task_type)
    return dict(spec) if isinstance(spec, dict) else None


def get_handler_name(task_type: str) -> str | None:
    spec = TASK_CATALOG.get(task_type)
    if not isinstance(spec, dict):
        return None
    handler = spec.get("handler")
    return handler if isinstance(handler, str) and handler.strip() else None


def get_task_types_for_agent(worker_id: str) -> list[str]:
    worker = AGENT_REGISTRY.get(worker_id, {})
    capabilities = worker.get("capabilities", [])
    return list(capabilities) if isinstance(capabilities, list) else []


def get_worker_names_for_agent(agent_role: str) -> list[str]:
    names: list[str] = []
    for worker_id, spec in AGENT_REGISTRY.items():
        if spec.get("agent_role") == agent_role:
            names.append(worker_id)
    return names


def get_worker_capabilities(worker_id: str) -> list[str]:
    worker = AGENT_REGISTRY.get(worker_id, {})
    capabilities = worker.get("capabilities", [])
    return list(capabilities) if isinstance(capabilities, list) else []


def get_worker_tools(worker_id: str) -> list[str]:
    worker = AGENT_REGISTRY.get(worker_id, {})
    tools = worker.get("tools", [])
    return list(tools) if isinstance(tools, list) else []


def resolve_agent_for_task_type(task_type: str) -> str | None:
    spec = TASK_CATALOG.get(task_type)
    if not isinstance(spec, dict):
        return None
    owner_role = spec.get("owner_role")
    return owner_role if isinstance(owner_role, str) and owner_role.strip() else None


def find_candidate_workers(task_type: str) -> list[str]:
    spec = TASK_CATALOG.get(task_type)
    if not isinstance(spec, dict):
        return []

    owner_role = spec.get("owner_role")
    required_capabilities = spec.get("required_capabilities", [])

    if not isinstance(owner_role, str) or not owner_role.strip():
        return []

    required = set(required_capabilities) if isinstance(required_capabilities, list) else set()
    candidates: list[str] = []

    for worker_id, worker_spec in AGENT_REGISTRY.items():
        if worker_spec.get("agent_role") != owner_role:
            continue
        capabilities = worker_spec.get("capabilities", [])
        capability_set = set(capabilities) if isinstance(capabilities, list) else set()
        if required.issubset(capability_set):
            candidates.append(worker_id)

    return candidates
