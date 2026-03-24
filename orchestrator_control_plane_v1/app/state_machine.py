from __future__ import annotations
from .models import LifecycleState

ALLOWED_TRANSITIONS = {
    LifecycleState.IDLE.value: [LifecycleState.ASSIGNED.value],
    LifecycleState.ASSIGNED.value: [LifecycleState.EXECUTING.value],
    LifecycleState.EXECUTING.value: [LifecycleState.REVIEW.value],
    LifecycleState.REVIEW.value: [LifecycleState.COMPLETED.value, LifecycleState.FAILED.value],
    LifecycleState.COMPLETED.value: [],
    LifecycleState.FAILED.value: [],
}

def validate_transition(current: str, new: str) -> None:
    allowed = ALLOWED_TRANSITIONS.get(current, [])
    if new not in allowed:
        raise ValueError(f"invalid transition: {current} -> {new}; allowed={allowed}")
