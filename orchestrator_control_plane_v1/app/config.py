from __future__ import annotations
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
WORKSPACES_DIR = BASE_DIR / "workspaces"
CONFIG_DIR = BASE_DIR / "config"
PROTOS_DIR = BASE_DIR / "protos"
DB_PATH = DATA_DIR / "orchestrator.db"

DEFAULT_TIMEOUT_SECONDS = int(os.getenv("ORCH_TIMEOUT_SECONDS", "300"))
DEFAULT_MAX_RETRIES = int(os.getenv("ORCH_MAX_RETRIES", "2"))
DEFAULT_CPU_LIMIT = os.getenv("ORCH_CPU_LIMIT", "1.0")
DEFAULT_MEMORY_LIMIT = os.getenv("ORCH_MEMORY_LIMIT", "512m")
DEFAULT_SANDBOX_IMAGE = os.getenv("ORCH_SANDBOX_IMAGE", "python:3.11-slim")
DEFAULT_SANDBOX_MODE = os.getenv("ORCH_SANDBOX_MODE", "docker")
DEFAULT_NETWORK_MODE = os.getenv("ORCH_NETWORK_MODE", "none")

for path in [DATA_DIR, ARTIFACTS_DIR, WORKSPACES_DIR]:
    path.mkdir(parents=True, exist_ok=True)
