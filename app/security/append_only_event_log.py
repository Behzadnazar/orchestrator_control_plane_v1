from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.security.atomic_multi_ledger_commit import AtomicLedgerPaths


def _json_canonical(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True, slots=True)
class LoggedEvent:
    seq: int
    event_type: str
    prev_hash: str | None
    payload: dict[str, Any]
    event_hash: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "event_type": self.event_type,
            "prev_hash": self.prev_hash,
            "payload": self.payload,
            "event_hash": self.event_hash,
        }


class AppendOnlyEventLogError(ValueError):
    pass


class AppendOnlyEventLogManager:
    REQUIRED_ORDER = [
        "delegation.consumed",
        "execution.bound",
        "execution.finalized",
    ]

    def __init__(self, *, ledger_paths: AtomicLedgerPaths, log_path: str) -> None:
        self._ledger_paths = ledger_paths
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._ledger_paths.coordinator_db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("ATTACH DATABASE ? AS consumed", (self._ledger_paths.consumption_db_path,))
        conn.execute("ATTACH DATABASE ? AS binding", (self._ledger_paths.binding_db_path,))
        conn.execute("ATTACH DATABASE ? AS outcome", (self._ledger_paths.outcome_db_path,))
        return conn

    def create_log_from_committed_state(self, *, chain_digest: str) -> dict[str, Any]:
        conn = self._connect()
        try:
            consumed_row = conn.execute(
                "SELECT * FROM consumed.delegation_consumptions WHERE chain_digest = ?",
                (chain_digest,),
            ).fetchone()
            binding_row = conn.execute(
                "SELECT * FROM binding.execution_audit_bindings WHERE chain_digest = ?",
                (chain_digest,),
            ).fetchone()
            outcome_row = conn.execute(
                "SELECT * FROM outcome.execution_outcome_seals WHERE chain_digest = ?",
                (chain_digest,),
            ).fetchone()
        finally:
            conn.close()

        if consumed_row is None or binding_row is None or outcome_row is None:
            raise AppendOnlyEventLogError("cannot create event log from incomplete committed state")

        payloads = [
            dict(consumed_row),
            dict(binding_row),
            dict(outcome_row),
        ]

        prev_hash: str | None = None
        events: list[LoggedEvent] = []

        for idx, event_type in enumerate(self.REQUIRED_ORDER, start=1):
            payload = payloads[idx - 1]
            event_hash = self._compute_event_hash(
                seq=idx,
                event_type=event_type,
                prev_hash=prev_hash,
                payload=payload,
            )
            events.append(
                LoggedEvent(
                    seq=idx,
                    event_type=event_type,
                    prev_hash=prev_hash,
                    payload=payload,
                    event_hash=event_hash,
                )
            )
            prev_hash = event_hash

        with self._log_path.open("w", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event.to_payload(), ensure_ascii=False) + "\n")

        return {
            "ok": True,
            "log_path": str(self._log_path),
            "event_count": len(events),
            "tail_hash": prev_hash,
        }

    def replay_and_verify(self) -> dict[str, Any]:
        if not self._log_path.exists():
            raise AppendOnlyEventLogError("append-only event log file not found")

        lines = self._log_path.read_text(encoding="utf-8").splitlines()
        if not lines:
            raise AppendOnlyEventLogError("append-only event log is empty")

        events: list[LoggedEvent] = []
        prev_hash: str | None = None

        for index, line in enumerate(lines, start=1):
            raw = json.loads(line)
            event = LoggedEvent(
                seq=int(raw["seq"]),
                event_type=str(raw["event_type"]),
                prev_hash=raw["prev_hash"],
                payload=dict(raw["payload"]),
                event_hash=str(raw["event_hash"]),
            )

            if event.seq != index:
                raise AppendOnlyEventLogError("event log sequence is not contiguous")

            if index > len(self.REQUIRED_ORDER):
                raise AppendOnlyEventLogError("event log contains unexpected extra events")

            if event.event_type != self.REQUIRED_ORDER[index - 1]:
                raise AppendOnlyEventLogError("event log event_type order is invalid")

            if event.prev_hash != prev_hash:
                raise AppendOnlyEventLogError("event log prev_hash chain is invalid")

            recomputed = self._compute_event_hash(
                seq=event.seq,
                event_type=event.event_type,
                prev_hash=event.prev_hash,
                payload=event.payload,
            )
            if recomputed != event.event_hash:
                raise AppendOnlyEventLogError("event log event_hash verification failed")

            events.append(event)
            prev_hash = event.event_hash

        if len(events) != len(self.REQUIRED_ORDER):
            raise AppendOnlyEventLogError("event log is truncated and missing required terminal events")

        consumed = events[0].payload
        binding = events[1].payload
        outcome = events[2].payload

        chain_digest = str(consumed["chain_digest"])
        if str(binding["chain_digest"]) != chain_digest:
            raise AppendOnlyEventLogError("replayed event log has chain_digest mismatch in binding event")
        if str(outcome["chain_digest"]) != chain_digest:
            raise AppendOnlyEventLogError("replayed event log has chain_digest mismatch in outcome event")

        if str(binding["execution_id"]) != str(outcome["execution_id"]):
            raise AppendOnlyEventLogError("replayed event log has mismatched execution_id across events")

        if str(binding["audit_event_id"]) != str(outcome["binding_audit_event_id"]):
            raise AppendOnlyEventLogError("replayed event log has mismatched binding audit id across events")

        return {
            "ok": True,
            "state": "fully_present",
            "chain_digest": chain_digest,
            "event_count": len(events),
            "tail_hash": prev_hash,
            "execution_id": str(outcome["execution_id"]),
            "binding_audit_event_id": str(outcome["binding_audit_event_id"]),
            "final_audit_event_id": str(outcome["final_audit_event_id"]),
            "status": str(outcome["status"]),
            "result_digest": str(outcome["result_digest"]),
        }

    def _compute_event_hash(
        self,
        *,
        seq: int,
        event_type: str,
        prev_hash: str | None,
        payload: dict[str, Any],
    ) -> str:
        material = {
            "seq": seq,
            "event_type": event_type,
            "prev_hash": prev_hash,
            "payload": payload,
        }
        return _sha256_hex(_json_canonical(material))
