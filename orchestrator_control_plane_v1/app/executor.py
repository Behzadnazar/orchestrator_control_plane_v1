from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .config import (
    ARTIFACTS_DIR,
    DEFAULT_CPU_LIMIT,
    DEFAULT_MEMORY_LIMIT,
    DEFAULT_NETWORK_MODE,
    DEFAULT_SANDBOX_IMAGE,
    DEFAULT_SANDBOX_MODE,
    DEFAULT_TIMEOUT_SECONDS,
    WORKSPACES_DIR,
)

def command_exists(name: str) -> bool:
    return shutil.which(name) is not None

def ensure_workspace(task_id: str) -> Path:
    path = WORKSPACES_DIR / task_id
    path.mkdir(parents=True, exist_ok=True)
    return path

def write_artifact(task_id: str, name: str, content: str) -> str:
    task_dir = ARTIFACTS_DIR / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    file_path = task_dir / name
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)

def run_command(payload: dict[str, Any]) -> dict[str, Any]:
    command = payload.get("command")
    if not command:
        raise ValueError("payload.command is required")

    task_id = payload["task_id"]
    timeout = int(payload.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    workspace = ensure_workspace(task_id)

    shell_cmd = command if isinstance(command, str) else " ".join(command)
    mode = payload.get("sandbox_mode", DEFAULT_SANDBOX_MODE)

    if mode == "docker" and command_exists("docker"):
        return _run_in_docker(task_id, shell_cmd, workspace, timeout)
    return _run_local(task_id, shell_cmd, workspace, timeout)

def _run_local(task_id: str, shell_cmd: str, workspace: Path, timeout: int) -> dict[str, Any]:
    proc = subprocess.run(
        ["bash", "-lc", shell_cmd],
        cwd=str(workspace),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    stdout_path = write_artifact(task_id, "stdout.log", proc.stdout)
    stderr_path = write_artifact(task_id, "stderr.log", proc.stderr)
    return {
        "executor_mode": "local",
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_artifact": stdout_path,
        "stderr_artifact": stderr_path,
    }

def _run_in_docker(task_id: str, shell_cmd: str, workspace: Path, timeout: int) -> dict[str, Any]:
    docker_cmd = [
        "docker", "run", "--rm",
        "--network", DEFAULT_NETWORK_MODE,
        "--cpus", DEFAULT_CPU_LIMIT,
        "--memory", DEFAULT_MEMORY_LIMIT,
        "-v", f"{workspace}:/workspace",
        "-w", "/workspace",
        DEFAULT_SANDBOX_IMAGE,
        "bash", "-lc", shell_cmd
    ]
    proc = subprocess.run(
        docker_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    stdout_path = write_artifact(task_id, "stdout.log", proc.stdout)
    stderr_path = write_artifact(task_id, "stderr.log", proc.stderr)
    write_artifact(task_id, "docker_cmd.json", json.dumps(docker_cmd, ensure_ascii=False, indent=2))
    return {
        "executor_mode": "docker",
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stdout_artifact": stdout_path,
        "stderr_artifact": stderr_path,
    }
