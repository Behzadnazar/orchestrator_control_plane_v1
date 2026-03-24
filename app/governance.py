from __future__ import annotations

import json
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional


class GovernanceError(Exception):
    pass


@dataclass
class Decision:
    ok: bool
    task_type: str
    service_path: str
    owner_agent: Optional[str]
    actor: Optional[str]
    reasons: List[str]
    matched_paths: List[Dict[str, str]]

    def require_ok(self) -> None:
        if not self.ok:
            joined = "; ".join(self.reasons) if self.reasons else "governance denied"
            raise GovernanceError(joined)


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _ensure_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


class Governance:
    def __init__(
        self,
        project_root: Path,
        registry_path: Optional[Path] = None,
        policy_path: Optional[Path] = None,
    ) -> None:
        self.project_root = project_root.resolve()
        self.registry_path = (registry_path or (self.project_root / "config" / "agent_registry.json")).resolve()
        self.policy_path = (policy_path or (self.project_root / "config" / "governance_policy.json")).resolve()

        self.registry = _read_json(self.registry_path)
        self.policy = _read_json(self.policy_path)

    def actor_roles(self, actor: str) -> List[str]:
        actors = _ensure_dict(self.registry.get("actors"))
        item = _ensure_dict(actors.get(actor))
        roles = item.get("roles", [])
        return [str(x) for x in roles if isinstance(x, str)]

    def task_policy(self, task_type: str) -> Dict[str, Any]:
        policies = _ensure_dict(self.policy.get("task_policies"))
        item = policies.get(task_type)
        if not isinstance(item, dict):
            raise GovernanceError(f"task_type not registered in governance policy: {task_type}")
        return item

    def owner_agent(self, task_type: str) -> str:
        policy = self.task_policy(task_type)
        owner = str(policy.get("owner_agent", "")).strip()
        if not owner:
            raise GovernanceError(f"owner_agent missing for task_type={task_type}")
        agents = _ensure_dict(self.registry.get("agents"))
        if owner not in agents:
            raise GovernanceError(f"owner_agent not registered: {owner}")
        return owner

    def _service_allowed(self, owner_agent: str, task_type: str, service_path: str) -> bool:
        policy = self.task_policy(task_type)
        allowed_service_paths = policy.get("allowed_service_paths", [])
        if service_path not in allowed_service_paths:
            return False

        agents = _ensure_dict(self.registry.get("agents"))
        owner = _ensure_dict(agents.get(owner_agent))
        capabilities = _ensure_dict(owner.get("capabilities"))
        registry_service_paths = capabilities.get("service_paths", [])
        registry_task_types = capabilities.get("task_types", [])
        return service_path in registry_service_paths and task_type in registry_task_types

    def _canonicalize_under_project(self, raw: str) -> Path:
        candidate = Path(raw)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (self.project_root / candidate).resolve()

        try:
            resolved.relative_to(self.project_root)
        except ValueError as exc:
            raise GovernanceError(f"path escapes project root: {raw}") from exc

        return resolved

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.project_root).as_posix()

    def _matches_any(self, rel_path: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            if fnmatch(rel_path, pattern):
                return True
        return False

    def _collect_paths(self, task_type: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        policy = self.task_policy(task_type)
        collected: List[Dict[str, Any]] = []

        def collect(keys: List[str], mode: str, required: bool) -> None:
            for key in keys:
                value = payload.get(key)
                if value is None or value == "":
                    if required:
                        raise GovernanceError(f"required path field missing: {key}")
                    continue
                if not isinstance(value, str):
                    raise GovernanceError(f"path field must be string: {key}")
                canonical = self._canonicalize_under_project(value)
                collected.append(
                    {
                        "field": key,
                        "mode": mode,
                        "canonical": str(canonical),
                        "rel": self._rel(canonical),
                    }
                )

        collect([str(x) for x in policy.get("required_input_paths", [])], "read", True)
        collect([str(x) for x in policy.get("optional_input_paths", [])], "read", False)
        collect([str(x) for x in policy.get("required_output_paths", [])], "write", True)
        collect([str(x) for x in policy.get("optional_output_paths", [])], "write", False)
        return collected

    def _check_required_fields(self, task_type: str, payload: Dict[str, Any]) -> List[str]:
        policy = self.task_policy(task_type)
        reasons: List[str] = []
        for field in policy.get("required_fields", []):
            if field not in payload or payload.get(field) in (None, ""):
                reasons.append(f"required field missing: {field}")
        return reasons

    def _check_workflow_contract(self, task_type: str, payload: Dict[str, Any]) -> List[str]:
        policy = self.task_policy(task_type)
        contract = _ensure_dict(policy.get("workflow_contract"))
        reasons: List[str] = []

        allowed_keys = contract.get("allowed_workflow_run_keys", [])
        workflow_key = str(payload.get("workflow_run_key", "")).strip()
        if allowed_keys and workflow_key and workflow_key not in allowed_keys:
            reasons.append(f"workflow_run_key not allowed: {workflow_key}")

        if task_type == "frontend.write_component":
            src = payload.get("source_notes_path")
            if not src:
                reasons.append("frontend.write_component requires source_notes_path")
            else:
                src_path = self._canonicalize_under_project(str(src))
                if not src_path.exists():
                    reasons.append(f"required upstream artifact missing: {src_path}")

        if task_type == "backend.write_file":
            component_path = payload.get("component_path")
            if component_path:
                comp = self._canonicalize_under_project(str(component_path))
                if not comp.exists():
                    reasons.append(f"declared component_path does not exist: {comp}")

        return reasons

    def _check_tools_and_namespaces(self, task_type: str, payload: Dict[str, Any], matched_paths: List[Dict[str, Any]]) -> List[str]:
        policy = self.task_policy(task_type)
        owner_agent = self.owner_agent(task_type)

        agents = _ensure_dict(self.registry.get("agents"))
        owner = _ensure_dict(agents.get(owner_agent))
        capabilities = _ensure_dict(owner.get("capabilities"))
        registry_tools = [str(x) for x in capabilities.get("tools", [])]
        policy_tools = [str(x) for x in policy.get("allowed_tools", [])]

        reasons: List[str] = []
        for tool in policy_tools:
            if tool not in registry_tools:
                reasons.append(f"tool not granted in agent registry: {tool}")

        namespace_patterns = [str(x) for x in capabilities.get("memory_namespaces", [])]
        for item in matched_paths:
            rel_path = item["rel"]
            if item["mode"] == "write" and not self._matches_any(rel_path, namespace_patterns):
                reasons.append(f"path خارج از namespace عامل است: {rel_path}")

        return reasons

    def _check_path_permissions(self, task_type: str, matched_paths: List[Dict[str, Any]]) -> List[str]:
        policy = self.task_policy(task_type)
        read_globs = [str(x) for x in policy.get("allowed_read_globs", [])]
        write_globs = [str(x) for x in policy.get("allowed_write_globs", [])]
        reasons: List[str] = []

        for item in matched_paths:
            rel_path = item["rel"]
            if item["mode"] == "read":
                if not self._matches_any(rel_path, read_globs):
                    reasons.append(f"read path not allowed by policy: {rel_path}")
                path_obj = self.project_root / rel_path
                if not path_obj.exists():
                    reasons.append(f"required input path does not exist: {rel_path}")
            elif item["mode"] == "write":
                if not self._matches_any(rel_path, write_globs):
                    reasons.append(f"write path not allowed by policy: {rel_path}")

        return reasons

    def decide(
        self,
        task_type: str,
        payload: Dict[str, Any],
        service_path: Optional[str] = None,
        actor: Optional[str] = None,
        mode: str = "execution",
    ) -> Decision:
        reasons: List[str] = []
        matched_paths: List[Dict[str, Any]] = []

        try:
            owner_agent = self.owner_agent(task_type)
        except GovernanceError as exc:
            return Decision(
                ok=False,
                task_type=task_type,
                service_path=service_path or task_type,
                owner_agent=None,
                actor=actor,
                reasons=[str(exc)],
                matched_paths=[],
            )

        service_path = (service_path or task_type).strip() or task_type
        if not self._service_allowed(owner_agent, task_type, service_path):
            reasons.append(f"service path not allowed for task_type={task_type}: {service_path}")

        reasons.extend(self._check_required_fields(task_type, payload))

        try:
            matched_paths = self._collect_paths(task_type, payload)
        except GovernanceError as exc:
            reasons.append(str(exc))

        reasons.extend(self._check_workflow_contract(task_type, payload))

        if matched_paths:
            reasons.extend(self._check_path_permissions(task_type, matched_paths))
            reasons.extend(self._check_tools_and_namespaces(task_type, payload, matched_paths))

        if mode == "approval":
            if not actor:
                reasons.append("approval actor missing")
            else:
                actor_roles = set(self.actor_roles(actor))
                approver_roles = set(str(x) for x in self.task_policy(task_type).get("approver_roles", []))
                if not actor_roles.intersection(approver_roles):
                    reasons.append(
                        f"actor not authorized for approval: actor={actor}, roles={sorted(actor_roles)}, required={sorted(approver_roles)}"
                    )

        return Decision(
            ok=len(reasons) == 0,
            task_type=task_type,
            service_path=service_path,
            owner_agent=owner_agent,
            actor=actor,
            reasons=reasons,
            matched_paths=[
                {"field": str(x["field"]), "mode": str(x["mode"]), "path": str(x["rel"])}
                for x in matched_paths
            ],
        )
