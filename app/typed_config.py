from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(Exception):
    pass


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"missing file: {path}")
    except json.JSONDecodeError as e:
        raise ConfigError(f"invalid json in {path}: {e}")


def _expect_type(name: str, value, expected_type):
    if not isinstance(value, expected_type):
        raise ConfigError(f"{name} must be {expected_type.__name__}")


def _expect_non_empty_str(name: str, value):
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{name} must be a non-empty string")
    return value.strip()


def _expect_list_of_str(name: str, value):
    if not isinstance(value, list) or not value or not all(isinstance(x, str) and x.strip() for x in value):
        raise ConfigError(f"{name} must be a non-empty list of strings")
    return [x.strip() for x in value]


@dataclass
class AgentConfig:
    agent_id: str
    agent_type: str
    capabilities: list[str]
    allowed_tools: list[str]
    status: str


@dataclass
class RuntimeEnvConfig:
    grpc_host: str = "127.0.0.1"
    grpc_port: int = 50051
    http_health_host: str = "127.0.0.1"
    http_health_port: int = 8080
    log_level: str = "INFO"
    daemon_poll_interval: float = 2.0

    @classmethod
    def from_env(cls) -> "RuntimeEnvConfig":
        def _int_env(name: str, default: int) -> int:
            raw = os.getenv(name, str(default))
            try:
                value = int(raw)
            except ValueError:
                raise ConfigError(f"env {name} must be int")
            if value <= 0:
                raise ConfigError(f"env {name} must be > 0")
            return value

        def _float_env(name: str, default: float) -> float:
            raw = os.getenv(name, str(default))
            try:
                value = float(raw)
            except ValueError:
                raise ConfigError(f"env {name} must be float")
            if value <= 0:
                raise ConfigError(f"env {name} must be > 0")
            return value

        grpc_host = os.getenv("OCP_GRPC_HOST", "127.0.0.1").strip()
        http_health_host = os.getenv("OCP_HTTP_HEALTH_HOST", "127.0.0.1").strip()
        log_level = os.getenv("OCP_LOG_LEVEL", "INFO").strip().upper()

        if not grpc_host:
            raise ConfigError("env OCP_GRPC_HOST must be non-empty")
        if not http_health_host:
            raise ConfigError("env OCP_HTTP_HEALTH_HOST must be non-empty")
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigError("env OCP_LOG_LEVEL invalid")

        return cls(
            grpc_host=grpc_host,
            grpc_port=_int_env("OCP_GRPC_PORT", 50051),
            http_health_host=http_health_host,
            http_health_port=_int_env("OCP_HTTP_HEALTH_PORT", 8080),
            log_level=log_level,
            daemon_poll_interval=_float_env("OCP_DAEMON_POLL_INTERVAL", 2.0),
        )


@dataclass
class TypedProjectConfig:
    agents: list[AgentConfig] = field(default_factory=list)
    routing_rules: dict[str, str] = field(default_factory=dict)
    file_ownership: dict[str, list[str]] = field(default_factory=dict)
    memory_policy: dict = field(default_factory=dict)
    runtime_env: RuntimeEnvConfig = field(default_factory=RuntimeEnvConfig)

    @classmethod
    def load(cls, base_dir: Path) -> "TypedProjectConfig":
        config_dir = base_dir / "config"

        raw_agents = _load_json(config_dir / "agents.json")
        raw_routing = _load_json(config_dir / "routing_rules.json")
        raw_ownership = _load_json(config_dir / "file_ownership.json")
        raw_memory = _load_json(config_dir / "memory_policy.json")

        _expect_type("agents.json", raw_agents, list)
        _expect_type("routing_rules.json", raw_routing, dict)
        _expect_type("file_ownership.json", raw_ownership, dict)
        _expect_type("memory_policy.json", raw_memory, dict)

        agents: list[AgentConfig] = []
        seen_agent_ids: set[str] = set()
        seen_agent_types: set[str] = set()

        for i, item in enumerate(raw_agents):
            _expect_type(f"agents[{i}]", item, dict)
            agent = AgentConfig(
                agent_id=_expect_non_empty_str(f"agents[{i}].agent_id", item.get("agent_id")),
                agent_type=_expect_non_empty_str(f"agents[{i}].agent_type", item.get("agent_type")),
                capabilities=_expect_list_of_str(f"agents[{i}].capabilities", item.get("capabilities")),
                allowed_tools=_expect_list_of_str(f"agents[{i}].allowed_tools", item.get("allowed_tools")),
                status=_expect_non_empty_str(f"agents[{i}].status", item.get("status")),
            )
            if agent.agent_id in seen_agent_ids:
                raise ConfigError(f"duplicate agent_id: {agent.agent_id}")
            seen_agent_ids.add(agent.agent_id)
            seen_agent_types.add(agent.agent_type)
            agents.append(agent)

        routing_rules: dict[str, str] = {}
        for task_type, agent_type in raw_routing.items():
            task_type = _expect_non_empty_str(f"routing_rules[{task_type}].task_type", task_type)
            agent_type = _expect_non_empty_str(f"routing_rules[{task_type}].agent_type", agent_type)
            if agent_type not in seen_agent_types:
                raise ConfigError(f"routing_rules references unknown agent_type: {task_type} -> {agent_type}")
            routing_rules[task_type] = agent_type

        file_ownership: dict[str, list[str]] = {}
        for agent_type, prefixes in raw_ownership.items():
            agent_type = _expect_non_empty_str(f"file_ownership key", agent_type)
            if agent_type not in seen_agent_types:
                raise ConfigError(f"file_ownership references unknown agent_type: {agent_type}")
            file_ownership[agent_type] = _expect_list_of_str(f"file_ownership[{agent_type}]", prefixes)

        if "filesystem" not in raw_memory:
            raise ConfigError("memory_policy.json must contain 'filesystem'")
        if not isinstance(raw_memory["filesystem"], dict):
            raise ConfigError("memory_policy.filesystem must be object")

        runtime_env = RuntimeEnvConfig.from_env()

        return cls(
            agents=agents,
            routing_rules=routing_rules,
            file_ownership=file_ownership,
            memory_policy=raw_memory,
            runtime_env=runtime_env,
        )

    def as_dict(self) -> dict:
        return {
            "agents": [a.__dict__ for a in self.agents],
            "routing_rules": self.routing_rules,
            "file_ownership": self.file_ownership,
            "memory_policy": self.memory_policy,
            "runtime_env": self.runtime_env.__dict__,
        }
