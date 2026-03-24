from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.security.atomic_multi_ledger_commit import AtomicLedgerPaths
from app.security.external_observer_consistency import (
    ObserverSnapshot,
    ReadOnlyReplicaObserver,
)


@dataclass(frozen=True, slots=True)
class OperationalDecision:
    chain_digest: str
    state: str
    allow_action: bool
    reason: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "chain_digest": self.chain_digest,
            "state": self.state,
            "allow_action": self.allow_action,
            "reason": self.reason,
        }


class MonotonicObserverOrderingError(ValueError):
    pass


class MonotonicObserverOrderingManager:
    _STATE_RANK = {
        "absent": 0,
        "fully_present": 1,
    }

    def __init__(self, *, ledger_paths: AtomicLedgerPaths) -> None:
        self._observer = ReadOnlyReplicaObserver(ledger_paths)
        self._last_snapshot_by_chain: dict[str, ObserverSnapshot] = {}

    def observe_and_record(self, *, chain_digest: str) -> dict[str, Any]:
        snapshot = self._observer.observe(chain_digest=chain_digest)
        self.record_presented_snapshot(snapshot=snapshot)
        return snapshot.to_payload()

    def record_presented_snapshot(self, *, snapshot: ObserverSnapshot) -> dict[str, Any]:
        chain_digest = snapshot.chain_digest
        last = self._last_snapshot_by_chain.get(chain_digest)

        if last is not None:
            self._assert_monotonic(last=last, current=snapshot)

        self._last_snapshot_by_chain[chain_digest] = snapshot
        return snapshot.to_payload()

    def evaluate_operational_decision(self, *, chain_digest: str) -> dict[str, Any]:
        snapshot = self._last_snapshot_by_chain.get(chain_digest)
        if snapshot is None:
            snapshot = self._observer.observe(chain_digest=chain_digest)
            self.record_presented_snapshot(snapshot=snapshot)

        if snapshot.state == "fully_present":
            return OperationalDecision(
                chain_digest=chain_digest,
                state=snapshot.state,
                allow_action=True,
                reason="observer state is fully_present and monotonic ordering is intact",
            ).to_payload()

        return OperationalDecision(
            chain_digest=chain_digest,
            state=snapshot.state,
            allow_action=False,
            reason="observer state is not yet fully_present",
        ).to_payload()

    def get_last_snapshot(self, *, chain_digest: str) -> dict[str, Any] | None:
        snapshot = self._last_snapshot_by_chain.get(chain_digest)
        if snapshot is None:
            return None
        return snapshot.to_payload()

    def _assert_monotonic(self, *, last: ObserverSnapshot, current: ObserverSnapshot) -> None:
        last_rank = self._rank(last.state)
        current_rank = self._rank(current.state)

        if current_rank < last_rank:
            raise MonotonicObserverOrderingError(
                "observer state regressed to an older snapshot"
            )

        if current_rank > last_rank:
            return

        if current.state == "fully_present":
            if current.execution_id != last.execution_id:
                raise MonotonicObserverOrderingError(
                    "observer fully_present snapshot changed execution_id non-monotonically"
                )
            if current.binding_audit_event_id != last.binding_audit_event_id:
                raise MonotonicObserverOrderingError(
                    "observer fully_present snapshot changed binding_audit_event_id non-monotonically"
                )
            if current.final_audit_event_id != last.final_audit_event_id:
                raise MonotonicObserverOrderingError(
                    "observer fully_present snapshot changed final_audit_event_id non-monotonically"
                )
            if current.status != last.status:
                raise MonotonicObserverOrderingError(
                    "observer fully_present snapshot changed status non-monotonically"
                )
            if current.result_digest != last.result_digest:
                raise MonotonicObserverOrderingError(
                    "observer fully_present snapshot changed result_digest non-monotonically"
                )

    def _rank(self, state: str) -> int:
        if state not in self._STATE_RANK:
            raise MonotonicObserverOrderingError(
                f"unknown observer state: {state}"
            )
        return self._STATE_RANK[state]
