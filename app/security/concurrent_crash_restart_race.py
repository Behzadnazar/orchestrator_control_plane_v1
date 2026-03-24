from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.security.atomic_multi_ledger_commit import (
    AtomicCommitError,
    AtomicLedgerPaths,
    AtomicMultiLedgerCommitCoordinator,
)
from app.security.concurrent_atomic_commit import (
    ConcurrentAtomicCommitRaceHarness,
    ConcurrentCommitAttempt,
    ConcurrentRaceSummary,
)
from app.security.delegation_consumption import DelegationConsumptionEnvelope
from app.security.execution_binding import AuditEventRecord, ExecutionRecord
from app.security.outcome_sealing import (
    ExecutionOutcomeRecord,
    OutcomeFinalizationAuditRecord,
)


@dataclass(frozen=True, slots=True)
class WinnerVisibilityRecord:
    chain_digest: str
    execution_id: str
    binding_audit_event_id: str
    final_audit_event_id: str
    status: str
    result_digest: str
    visible_state: str
    counts: dict[str, int]

    def to_payload(self) -> dict[str, Any]:
        return {
            "chain_digest": self.chain_digest,
            "execution_id": self.execution_id,
            "binding_audit_event_id": self.binding_audit_event_id,
            "final_audit_event_id": self.final_audit_event_id,
            "status": self.status,
            "result_digest": self.result_digest,
            "visible_state": self.visible_state,
            "counts": self.counts,
        }


class ConcurrentCrashRestartRaceError(ValueError):
    pass


class ConcurrentCrashRestartRaceHarness:
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

    def _new_race_harness(self) -> ConcurrentAtomicCommitRaceHarness:
        return ConcurrentAtomicCommitRaceHarness(
            self._trust_store,
            ledger_paths=self._ledger_paths,
            max_chain_depth=self._max_chain_depth,
            clock_skew_seconds=self._clock_skew_seconds,
        )

    def _new_coordinator(self) -> AtomicMultiLedgerCommitCoordinator:
        return AtomicMultiLedgerCommitCoordinator(
            self._trust_store,
            ledger_paths=self._ledger_paths,
            max_chain_depth=self._max_chain_depth,
            clock_skew_seconds=self._clock_skew_seconds,
        )

    def run_race_then_restart_visibility_check(
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
    ) -> dict[str, Any]:
        race_harness = self._new_race_harness()
        race_summary = race_harness.run_same_chain_race(
            envelope,
            expected_leaf_subject=expected_leaf_subject,
            required_scopes=required_scopes,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_issued_for=expected_issued_for,
            attempt_a=attempt_a,
            attempt_b=attempt_b,
            now=now,
        )

        attempts = {
            attempt_a.label: attempt_a,
            attempt_b.label: attempt_b,
        }
        winner_attempt = attempts[race_summary.winning_label]

        visible = self.observe_winner_visibility_after_restart(
            chain_digest=race_summary.winner_chain_digest
        )

        verified = race_harness.verify_winner_material_after_restart(
            chain_digest=race_summary.winner_chain_digest,
            execution=winner_attempt.execution,
            binding_audit_event_id=winner_attempt.binding_audit_event.audit_event_id,
            outcome=winner_attempt.outcome,
            final_audit_event=winner_attempt.final_audit_event,
            leaf_subject=expected_leaf_subject,
        )

        self._assert_observer_and_verifier_agree(
            visible=visible,
            verified=verified,
            winner_attempt=winner_attempt,
        )

        return {
            "ok": True,
            "race_summary": race_summary.to_payload(),
            "visible": visible.to_payload(),
            "verified": verified,
        }

    def observe_winner_visibility_after_restart(
        self,
        *,
        chain_digest: str,
    ) -> WinnerVisibilityRecord:
        coordinator = self._new_coordinator()
        consistency = coordinator.assert_atomic_state_consistency(chain_digest)

        if consistency["state"] != "fully_present":
            raise ConcurrentCrashRestartRaceError(
                "winner is not fully visible after restart"
            )

        counts = consistency["counts"]
        if counts != {"consumed": 1, "binding": 1, "outcome": 1}:
            raise ConcurrentCrashRestartRaceError(
                "winner visibility counts are not deterministic 1/1/1"
            )

        conn = coordinator._connect()
        try:
            binding_row = conn.execute(
                """
                SELECT
                    chain_digest,
                    execution_id,
                    audit_event_id,
                    event_type
                FROM binding.execution_audit_bindings
                WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()

            outcome_row = conn.execute(
                """
                SELECT
                    chain_digest,
                    execution_id,
                    binding_audit_event_id,
                    final_audit_event_id,
                    status,
                    result_digest
                FROM outcome.execution_outcome_seals
                WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()
        finally:
            conn.close()

        if binding_row is None:
            raise ConcurrentCrashRestartRaceError(
                "binding row not visible after restart"
            )

        if outcome_row is None:
            raise ConcurrentCrashRestartRaceError(
                "outcome row not visible after restart"
            )

        if binding_row["execution_id"] != outcome_row["execution_id"]:
            raise ConcurrentCrashRestartRaceError(
                "observer detected mismatched execution_id across visible ledgers"
            )

        if binding_row["audit_event_id"] != outcome_row["binding_audit_event_id"]:
            raise ConcurrentCrashRestartRaceError(
                "observer detected mismatched binding audit id across visible ledgers"
            )

        return WinnerVisibilityRecord(
            chain_digest=chain_digest,
            execution_id=str(outcome_row["execution_id"]),
            binding_audit_event_id=str(outcome_row["binding_audit_event_id"]),
            final_audit_event_id=str(outcome_row["final_audit_event_id"]),
            status=str(outcome_row["status"]),
            result_digest=str(outcome_row["result_digest"]),
            visible_state=str(consistency["state"]),
            counts=counts,
        )

    def deny_stale_loser_replay_after_restart(
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
        loser_attempt: ConcurrentCommitAttempt,
        now: int,
    ) -> None:
        race_harness = self._new_race_harness()
        race_harness.deny_followup_replay_after_race(
            envelope,
            expected_leaf_subject=expected_leaf_subject,
            required_scopes=required_scopes,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_issued_for=expected_issued_for,
            attempt=loser_attempt,
            now=now,
        )

    def detect_tampered_winner_material_after_restart(
        self,
        *,
        chain_digest: str,
        execution: ExecutionRecord,
        binding_audit_event_id: str,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        leaf_subject: str,
    ) -> None:
        race_harness = self._new_race_harness()
        race_harness.verify_winner_material_after_restart(
            chain_digest=chain_digest,
            execution=execution,
            binding_audit_event_id=binding_audit_event_id,
            outcome=outcome,
            final_audit_event=final_audit_event,
            leaf_subject=leaf_subject,
        )

    def assert_post_commit_visibility_is_deterministic(
        self,
        *,
        chain_digest: str,
    ) -> dict[str, Any]:
        first = self.observe_winner_visibility_after_restart(chain_digest=chain_digest)
        second = self.observe_winner_visibility_after_restart(chain_digest=chain_digest)

        if first.to_payload() != second.to_payload():
            raise ConcurrentCrashRestartRaceError(
                "post-commit visibility is not deterministic across repeated observations"
            )

        return {
            "ok": True,
            "visible": first.to_payload(),
        }

    def _assert_observer_and_verifier_agree(
        self,
        *,
        visible: WinnerVisibilityRecord,
        verified: dict[str, Any],
        winner_attempt: ConcurrentCommitAttempt,
    ) -> None:
        if visible.execution_id != verified["execution_id"]:
            raise ConcurrentCrashRestartRaceError(
                "observer/verifier execution_id disagreement after restart"
            )

        if visible.binding_audit_event_id != verified["binding_audit_event_id"]:
            raise ConcurrentCrashRestartRaceError(
                "observer/verifier binding_audit_event_id disagreement after restart"
            )

        if visible.final_audit_event_id != verified["final_audit_event_id"]:
            raise ConcurrentCrashRestartRaceError(
                "observer/verifier final_audit_event_id disagreement after restart"
            )

        if visible.status != verified["status"]:
            raise ConcurrentCrashRestartRaceError(
                "observer/verifier status disagreement after restart"
            )

        if visible.result_digest != verified["result_digest"]:
            raise ConcurrentCrashRestartRaceError(
                "observer/verifier result_digest disagreement after restart"
            )

        if visible.execution_id != winner_attempt.execution.execution_id:
            raise ConcurrentCrashRestartRaceError(
                "persisted visible winner does not match winning execution material"
            )
