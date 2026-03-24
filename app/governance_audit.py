from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


UTC = timezone.utc


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class GovernanceAudit:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self.audit_dir = self.project_root / "artifacts" / "governance_audit"
        self.audit_file = self.audit_dir / "governance_events.jsonl"
        self.audit_dir.mkdir(parents=True, exist_ok=True)

    def path(self) -> Path:
        return self.audit_file

    def log(
        self,
        event_type: str,
        payload: Dict[str, Any],
        actor: Optional[str] = None,
        worker: Optional[str] = None,
    ) -> None:
        record: Dict[str, Any] = {
            "ts": utc_now_iso(),
            "event_type": event_type,
            **payload,
        }
        if actor:
            record["actor"] = actor
        if worker:
            record["worker"] = worker

        self.audit_dir.mkdir(parents=True, exist_ok=True)
        with self.audit_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
