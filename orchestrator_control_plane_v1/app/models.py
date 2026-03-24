from __future__ import annotations
from enum import Enum

class LifecycleState(str, Enum):
    IDLE = "Idle"
    ASSIGNED = "Assigned"
    EXECUTING = "Executing"
    REVIEW = "Review"
    COMPLETED = "Completed"
    FAILED = "Failed"

class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"

PRIORITY_SCORE = {
    Priority.CRITICAL.value: 400,
    Priority.HIGH.value: 300,
    Priority.NORMAL.value: 200,
    Priority.LOW.value: 100,
}

CRITICAL_PATH_HINTS = [
    ".env",
    "secrets",
    "infra/prod/",
    "docker-compose.prod",
    "policies/"
]
