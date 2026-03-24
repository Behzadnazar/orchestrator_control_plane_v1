from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from typing import Any

from app.security.atomic_multi_ledger_commit import (
    AtomicCommitError,
    AtomicCommitResult,
    AtomicLedgerPaths,
    AtomicMultiLedgerCommitCoordinator,
)
from app.security.delegation_consumption import DelegationConsumptionEnvelope
from app.security.execution_binding import AuditEventRecord, ExecutionRecord
from app.security.outcome_sealing import (
    ExecutionOutcomeRecord,
    OutcomeFinalizationAuditRecord,
)


@dataclass(frozen=True, slots=True)
class ConcurrentCommitAttempt:
    label: str
    execution: ExecutionRecord
    binding_audit_event: AuditEventRecord
    outcome: ExecutionOutcomeRecord
    final_audit_event: OutcomeFinalizationAuditRecord


@dataclass(frozen=True, slots=True)
class ConcurrentCommitAttemptResult:
    label: str
    ok: bool
    error_type: str | None
    error_message: str | None
    chain_digest: str | None
    execution_id: str
    binding_audit_event_id: str
    final_audit_event_id: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "ok": self.ok,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "chain_digest": self.chain_digest,
            "execution_id": self.execution_id,
            "binding_audit_event_id": self.binding_audit_event_id,
            "final_audit_event_id": self.final_audit_event_id,
        }


@dataclass(frozen=True, slots=True)
class ConcurrentRaceSummary:
    ok: bool
    winning_label: str
    losing_label: str
    winner_chain_digest: str
    state: str
    counts: dict[str, int]
    results: tuple[ConcurrentCommitAttemptResult, ConcurrentCommitAttemptResult]

    def to_payload(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "winning_label": self.winning_label,
            "losing_label": self.losing_label,
            "winner_chain_digest": self.winner_chain_digest,
            "state": self.state,
            "counts": self.counts,
            "results": [r.to_payload() for r in self.results],
        }


class ConcurrentAtomicCommitError(ValueError):
    pass


class RaceAwareAtomicMultiLedgerCommitCoordinator(AtomicMultiLedgerCommitCoordinator):
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._ledger_paths.coordinator_db_path,
            timeout=10.0,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("ATTACH DATABASE ? AS consumed", (self._ledger_paths.consumption_db_path,))
        conn.execute("ATTACH DATABASE ? AS binding", (self._ledger_paths.binding_db_path,))
        conn.execute("ATTACH DATABASE ? AS outcome", (self._ledger_paths.outcome_db_path,))
        return conn


class ConcurrentAtomicCommitRaceHarness:
    def __init__(
        self,
        trust_store: dict[str, bytes],
        *,
        ledger_paths: AtomicLedgerPaths,
        max_chain_depth: int = 8,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._trust_store = trust_store
        self._ledger_paths = ledger_paths
        self._max_chain_depth = max_chain_depth
        self._clock_skew_seconds = clock_skew_seconds

    def _new_coordinator(self) -> RaceAwareAtomicMultiLedgerCommitCoordinator:
        return RaceAwareAtomicMultiLedgerCommitCoordinator(
            self._trust_store,
            ledger_paths=self._ledger_paths,
            max_chain_depth=self._max_chain_depth,
            clock_skew_seconds=self._clock_skew_seconds,
        )

    def run_same_chain_race(
        self,
        envelope: DelegationConsumptionEnvelope,
        *,
        expected_leaf_subject: str,
        required_scopes: list[str],
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_issued_for: str,
        attempt_a: ConcurrentCommitAttempt,
        attempt_b: ConcurrentCommitAttempt,
        now: int,
    ) -> ConcurrentRaceSummary:
        barrier = threading.Barrier(3)
        results: list[ConcurrentCommitAttemptResult] = []
        lock = threading.Lock()

        def worker(attempt: ConcurrentCommitAttempt) -> None:
            barrier.wait()
            coordinator = self._new_coordinator()
            try:
                result = coordinator.verify_and_atomic_commit(
                    envelope,
                    expected_leaf_subject=expected_leaf_subject,
                    required_scopes=required_scopes,
                    expected_request_id=expected_request_id,
                    expected_task_id=expected_task_id,
                    expected_operation_id=expected_operation_id,
                    expected_payload_digest=expected_payload_digest,
                    expected_issued_for=expected_issued_for,
                    execution=attempt.execution,
                    binding_audit_event=attempt.binding_audit_event,
                    outcome=attempt.outcome,
                    final_audit_event=attempt.final_audit_event,
                    now=now,
                )
                item = ConcurrentCommitAttemptResult(
                    label=attempt.label,
                    ok=True,
                    error_type=None,
                    error_message=None,
                    chain_digest=result.chain_digest,
                    execution_id=attempt.execution.execution_id,
                    binding_audit_event_id=attempt.binding_audit_event.audit_event_id,
                    final_audit_event_id=attempt.final_audit_event.audit_event_id,
                )
            except AtomicCommitError as exc:
                item = ConcurrentCommitAttemptResult(
                    label=attempt.label,
                    ok=False,
                    error_type="AtomicCommitError",
                    error_message=str(exc),
                    chain_digest=None,
                    execution_id=attempt.execution.execution_id,
                    binding_audit_event_id=attempt.binding_audit_event.audit_event_id,
                    final_audit_event_id=attempt.final_audit_event.audit_event_id,
                )
            except sqlite3.OperationalError as exc:
                item = ConcurrentCommitAttemptResult(
                    label=attempt.label,
                    ok=False,
                    error_type="OperationalError",
                    error_message=str(exc),
                    chain_digest=None,
                    execution_id=attempt.execution.execution_id,
                    binding_audit_event_id=attempt.binding_audit_event.audit_event_id,
                    final_audit_event_id=attempt.final_audit_event.audit_event_id,
                )
            except Exception as exc:
                item = ConcurrentCommitAttemptResult(
                    label=attempt.label,
                    ok=False,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                    chain_digest=None,
                    execution_id=attempt.execution.execution_id,
                    binding_audit_event_id=attempt.binding_audit_event.audit_event_id,
                    final_audit_event_id=attempt.final_audit_event.audit_event_id,
                )

            with lock:
                results.append(item)

        t1 = threading.Thread(target=worker, args=(attempt_a,), name=f"race-{attempt_a.label}")
        t2 = threading.Thread(target=worker, args=(attempt_b,), name=f"race-{attempt_b.label}")

        t1.start()
        t2.start()
        barrier.wait()
        t1.join()
        t2.join()

        if len(results) != 2:
            raise ConcurrentAtomicCommitError("race did not produce exactly two attempt results")

        ordered = tuple(sorted(results, key=lambda x: x.label))
        successes = [r for r in ordered if r.ok]
        failures = [r for r in ordered if not r.ok]

        if len(successes) != 1:
            raise ConcurrentAtomicCommitError(
                f"expected exactly one winner in race, got {len(successes)}"
            )

        if len(failures) != 1:
            raise ConcurrentAtomicCommitError(
                f"expected exactly one loser in race, got {len(failures)}"
            )

        loser = failures[0]
        if loser.error_type != "AtomicCommitError":
            raise ConcurrentAtomicCommitError(
                f"losing contender failed for unexpected reason: {loser.error_type}: {loser.error_message}"
            )

        if loser.error_message != "atomic multi-ledger commit rejected due to replay or identifier re-use":
            raise ConcurrentAtomicCommitError(
                "losing contender did not fail with deterministic replay/identifier denial"
            )

        winner = successes[0]
        coordinator = self._new_coordinator()
        consistency = coordinator.assert_atomic_state_consistency(winner.chain_digest or "")

        if consistency["state"] != "fully_present":
            raise ConcurrentAtomicCommitError("final state after race is not fully_present")

        if consistency["counts"] != {"consumed": 1, "binding": 1, "outcome": 1}:
            raise ConcurrentAtomicCommitError("final state counts after race are not exactly 1/1/1")

        return ConcurrentRaceSummary(
            ok=True,
            winning_label=winner.label,
            losing_label=loser.label,
            winner_chain_digest=winner.chain_digest or "",
            state=consistency["state"],
            counts=consistency["counts"],
            results=ordered,
        )

    def verify_winner_material_after_restart(
        self,
        *,
        chain_digest: str,
        execution: ExecutionRecord,
        binding_audit_event_id: str,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        leaf_subject: str,
    ) -> dict[str, Any]:
        coordinator = self._new_coordinator()
        return coordinator.verify_persisted_seal_after_restart(
            chain_digest=chain_digest,
            execution=execution,
            binding_audit_event_id=binding_audit_event_id,
            outcome=outcome,
            final_audit_event=final_audit_event,
            leaf_subject=leaf_subject,
        )

    def deny_followup_replay_after_race(
        self,
        envelope: DelegationConsumptionEnvelope,
        *,
        expected_leaf_subject: str,
        required_scopes: list[str],
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_issued_for: str,
        attempt: ConcurrentCommitAttempt,
        now: int,
    ) -> None:
        coordinator = self._new_coordinator()
        try:
            coordinator.verify_and_atomic_commit(
                envelope,
                expected_leaf_subject=expected_leaf_subject,
                required_scopes=required_scopes,
                expected_request_id=expected_request_id,
                expected_task_id=expected_task_id,
                expected_operation_id=expected_operation_id,
                expected_payload_digest=expected_payload_digest,
                expected_issued_for=expected_issued_for,
                execution=attempt.execution,
                binding_audit_event=attempt.binding_audit_event,
                outcome=attempt.outcome,
                final_audit_event=attempt.final_audit_event,
                now=now,
            )
        except AtomicCommitError:
            return

        raise ConcurrentAtomicCommitError("follow-up replay unexpectedly succeeded after race")
