from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

from app.security.atomic_multi_ledger_commit import (
    AtomicCommitError,
    AtomicCommitResult,
    AtomicLedgerPaths,
    AtomicMultiLedgerCommitCoordinator,
)
from app.security.delegation_consumption import (
    DelegationConsumptionEnvelope,
    canonical_chain_digest,
)
from app.security.execution_binding import (
    AuditEventRecord,
    ExecutionRecord,
)
from app.security.outcome_sealing import (
    ExecutionOutcomeRecord,
    OutcomeFinalizationAuditRecord,
    compute_outcome_seal_digest,
)


@dataclass(frozen=True, slots=True)
class ObserverSnapshot:
    chain_digest: str
    state: str
    counts: dict[str, int]
    execution_id: str | None
    binding_audit_event_id: str | None
    final_audit_event_id: str | None
    status: str | None
    result_digest: str | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "chain_digest": self.chain_digest,
            "state": self.state,
            "counts": self.counts,
            "execution_id": self.execution_id,
            "binding_audit_event_id": self.binding_audit_event_id,
            "final_audit_event_id": self.final_audit_event_id,
            "status": self.status,
            "result_digest": self.result_digest,
        }


class ExternalObserverConsistencyError(ValueError):
    pass


class ReadOnlyReplicaObserver:
    def __init__(self, ledger_paths: AtomicLedgerPaths) -> None:
        self._ledger_paths = ledger_paths

    @staticmethod
    def _ro_uri(path: str) -> str:
        return f"file:{path}?mode=ro"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._ro_uri(self._ledger_paths.coordinator_db_path),
            uri=True,
            timeout=10.0,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        conn.execute(
            "ATTACH DATABASE ? AS consumed",
            (self._ro_uri(self._ledger_paths.consumption_db_path),),
        )
        conn.execute(
            "ATTACH DATABASE ? AS binding",
            (self._ro_uri(self._ledger_paths.binding_db_path),),
        )
        conn.execute(
            "ATTACH DATABASE ? AS outcome",
            (self._ro_uri(self._ledger_paths.outcome_db_path),),
        )
        return conn

    def observe(self, *, chain_digest: str) -> ObserverSnapshot:
        conn = self._connect()
        try:
            consumed_count = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM consumed.delegation_consumptions WHERE chain_digest = ?",
                    (chain_digest,),
                ).fetchone()["c"]
            )
            binding_count = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM binding.execution_audit_bindings WHERE chain_digest = ?",
                    (chain_digest,),
                ).fetchone()["c"]
            )
            outcome_count = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM outcome.execution_outcome_seals WHERE chain_digest = ?",
                    (chain_digest,),
                ).fetchone()["c"]
            )

            counts = {
                "consumed": consumed_count,
                "binding": binding_count,
                "outcome": outcome_count,
            }

            distinct = {consumed_count, binding_count, outcome_count}
            if distinct == {0}:
                return ObserverSnapshot(
                    chain_digest=chain_digest,
                    state="absent",
                    counts=counts,
                    execution_id=None,
                    binding_audit_event_id=None,
                    final_audit_event_id=None,
                    status=None,
                    result_digest=None,
                )

            if distinct != {1}:
                raise ExternalObserverConsistencyError(
                    "observer detected partial visible state across ledgers"
                )

            binding_row = conn.execute(
                """
                SELECT
                    execution_id,
                    audit_event_id
                FROM binding.execution_audit_bindings
                WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()

            outcome_row = conn.execute(
                """
                SELECT
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

            if binding_row is None or outcome_row is None:
                raise ExternalObserverConsistencyError(
                    "observer could not load fully visible binding/outcome rows"
                )

            if str(binding_row["execution_id"]) != str(outcome_row["execution_id"]):
                raise ExternalObserverConsistencyError(
                    "observer detected mismatched execution_id across visible ledgers"
                )

            if str(binding_row["audit_event_id"]) != str(outcome_row["binding_audit_event_id"]):
                raise ExternalObserverConsistencyError(
                    "observer detected mismatched binding audit id across visible ledgers"
                )

            return ObserverSnapshot(
                chain_digest=chain_digest,
                state="fully_present",
                counts=counts,
                execution_id=str(outcome_row["execution_id"]),
                binding_audit_event_id=str(outcome_row["binding_audit_event_id"]),
                final_audit_event_id=str(outcome_row["final_audit_event_id"]),
                status=str(outcome_row["status"]),
                result_digest=str(outcome_row["result_digest"]),
            )
        finally:
            conn.close()


class VisibilityControlledAtomicCoordinator(AtomicMultiLedgerCommitCoordinator):
    def verify_and_atomic_commit_with_precommit_pause(
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
        execution: ExecutionRecord,
        binding_audit_event: AuditEventRecord,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        observer_can_read_event: threading.Event,
        continue_commit_event: threading.Event,
        now: int | None = None,
    ) -> AtomicCommitResult:
        current_time = int(time.time()) if now is None else int(now)

        self._verify_all_semantics(
            envelope=envelope,
            expected_leaf_subject=expected_leaf_subject,
            required_scopes=required_scopes,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_issued_for=expected_issued_for,
            execution=execution,
            binding_audit_event=binding_audit_event,
            outcome=outcome,
            final_audit_event=final_audit_event,
            now=current_time,
        )

        chain_digest = canonical_chain_digest(envelope.signed_chain)
        seal_digest = compute_outcome_seal_digest(
            chain_digest=chain_digest,
            execution=execution,
            binding_audit_event_id=binding_audit_event.audit_event_id,
            final_audit_event=final_audit_event,
            outcome=outcome,
            leaf_subject=expected_leaf_subject,
        )

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO consumed.delegation_consumptions (
                    chain_digest,
                    request_id,
                    task_id,
                    operation_id,
                    payload_digest,
                    nonce,
                    issued_for,
                    leaf_subject,
                    consumed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_digest,
                    envelope.request_id,
                    envelope.task_id,
                    envelope.operation_id,
                    envelope.payload_digest,
                    envelope.nonce,
                    envelope.issued_for,
                    expected_leaf_subject,
                    current_time,
                ),
            )

            conn.execute(
                """
                INSERT INTO binding.execution_audit_bindings (
                    chain_digest,
                    execution_id,
                    audit_event_id,
                    run_id,
                    request_id,
                    task_id,
                    operation_id,
                    payload_digest,
                    leaf_subject,
                    event_type,
                    bound_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_digest,
                    execution.execution_id,
                    binding_audit_event.audit_event_id,
                    execution.run_id,
                    execution.request_id,
                    execution.task_id,
                    execution.operation_id,
                    execution.payload_digest,
                    expected_leaf_subject,
                    binding_audit_event.event_type,
                    current_time,
                ),
            )

            conn.execute(
                """
                INSERT INTO outcome.execution_outcome_seals (
                    chain_digest,
                    execution_id,
                    binding_audit_event_id,
                    final_audit_event_id,
                    run_id,
                    request_id,
                    task_id,
                    operation_id,
                    payload_digest,
                    leaf_subject,
                    status,
                    result_digest,
                    finished_at,
                    sealed_at,
                    seal_digest
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_digest,
                    execution.execution_id,
                    binding_audit_event.audit_event_id,
                    final_audit_event.audit_event_id,
                    execution.run_id,
                    execution.request_id,
                    execution.task_id,
                    execution.operation_id,
                    execution.payload_digest,
                    expected_leaf_subject,
                    outcome.status,
                    outcome.result_digest,
                    outcome.finished_at,
                    current_time,
                    seal_digest,
                ),
            )

            observer_can_read_event.set()

            released = continue_commit_event.wait(timeout=10.0)
            if not released:
                conn.rollback()
                raise ExternalObserverConsistencyError(
                    "writer timed out while waiting for observer before commit"
                )

            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise AtomicCommitError(
                "atomic multi-ledger commit rejected due to replay or identifier re-use"
            ) from exc
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        return AtomicCommitResult(
            ok=True,
            chain_digest=chain_digest,
            execution_id=execution.execution_id,
            binding_audit_event_id=binding_audit_event.audit_event_id,
            final_audit_event_id=final_audit_event.audit_event_id,
            request_id=execution.request_id,
            task_id=execution.task_id,
            operation_id=execution.operation_id,
            payload_digest=execution.payload_digest,
            leaf_subject=expected_leaf_subject,
            status=outcome.status,
            result_digest=outcome.result_digest,
            seal_digest=seal_digest,
            committed_at=current_time,
        )


class ExternalObserverConsistencyHarness:
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

    def _new_writer(self) -> VisibilityControlledAtomicCoordinator:
        return VisibilityControlledAtomicCoordinator(
            self._trust_store,
            ledger_paths=self._ledger_paths,
            max_chain_depth=self._max_chain_depth,
            clock_skew_seconds=self._clock_skew_seconds,
        )

    def _new_reader(self) -> ReadOnlyReplicaObserver:
        return ReadOnlyReplicaObserver(self._ledger_paths)

    def run_precommit_visibility_probe(
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
        execution: ExecutionRecord,
        binding_audit_event: AuditEventRecord,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        now: int,
    ) -> dict[str, Any]:
        writer = self._new_writer()
        reader = self._new_reader()
        observer_can_read_event = threading.Event()
        continue_commit_event = threading.Event()

        result_holder: dict[str, Any] = {}
        error_holder: dict[str, BaseException] = {}

        def writer_job() -> None:
            try:
                result_holder["result"] = writer.verify_and_atomic_commit_with_precommit_pause(
                    envelope,
                    expected_leaf_subject=expected_leaf_subject,
                    required_scopes=required_scopes,
                    expected_request_id=expected_request_id,
                    expected_task_id=expected_task_id,
                    expected_operation_id=expected_operation_id,
                    expected_payload_digest=expected_payload_digest,
                    expected_issued_for=expected_issued_for,
                    execution=execution,
                    binding_audit_event=binding_audit_event,
                    outcome=outcome,
                    final_audit_event=final_audit_event,
                    observer_can_read_event=observer_can_read_event,
                    continue_commit_event=continue_commit_event,
                    now=now,
                )
            except BaseException as exc:
                error_holder["writer"] = exc

        t = threading.Thread(target=writer_job, name="r29-writer")
        t.start()

        signaled = observer_can_read_event.wait(timeout=10.0)
        if not signaled:
            raise ExternalObserverConsistencyError(
                "observer was not released before pre-commit visibility probe"
            )

        chain_digest = canonical_chain_digest(envelope.signed_chain)
        precommit_snapshot = reader.observe(chain_digest=chain_digest)

        continue_commit_event.set()
        t.join(timeout=10.0)

        if t.is_alive():
            raise ExternalObserverConsistencyError("writer thread did not finish")

        if "writer" in error_holder:
            raise error_holder["writer"]

        commit_result = result_holder["result"]
        postcommit_snapshot = reader.observe(chain_digest=chain_digest)

        return {
            "ok": True,
            "chain_digest": chain_digest,
            "precommit_snapshot": precommit_snapshot.to_payload(),
            "postcommit_snapshot": postcommit_snapshot.to_payload(),
            "commit_result": commit_result.to_payload(),
        }

    def verify_observer_and_commit_agree(
        self,
        *,
        chain_digest: str,
        expected_execution_id: str,
        expected_binding_audit_event_id: str,
        expected_final_audit_event_id: str,
        expected_status: str,
        expected_result_digest: str,
    ) -> dict[str, Any]:
        reader = self._new_reader()
        visible = reader.observe(chain_digest=chain_digest)

        if visible.state != "fully_present":
            raise ExternalObserverConsistencyError(
                "observer does not see fully_present state after commit"
            )

        if visible.execution_id != expected_execution_id:
            raise ExternalObserverConsistencyError(
                "observer execution_id does not match committed winner"
            )

        if visible.binding_audit_event_id != expected_binding_audit_event_id:
            raise ExternalObserverConsistencyError(
                "observer binding_audit_event_id does not match committed winner"
            )

        if visible.final_audit_event_id != expected_final_audit_event_id:
            raise ExternalObserverConsistencyError(
                "observer final_audit_event_id does not match committed winner"
            )

        if visible.status != expected_status:
            raise ExternalObserverConsistencyError(
                "observer status does not match committed winner"
            )

        if visible.result_digest != expected_result_digest:
            raise ExternalObserverConsistencyError(
                "observer result_digest does not match committed winner"
            )

        return {
            "ok": True,
            "visible": visible.to_payload(),
        }

    def assert_repeated_readonly_observation_is_deterministic(
        self,
        *,
        chain_digest: str,
    ) -> dict[str, Any]:
        reader = self._new_reader()
        first = reader.observe(chain_digest=chain_digest)
        second = reader.observe(chain_digest=chain_digest)

        if first.to_payload() != second.to_payload():
            raise ExternalObserverConsistencyError(
                "read-only observer produced non-deterministic snapshots"
            )

        return {
            "ok": True,
            "snapshot": first.to_payload(),
        }
