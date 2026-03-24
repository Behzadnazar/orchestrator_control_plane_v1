from __future__ import annotations

import hmac
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from app.security.delegation_chain import DelegationChainVerifier, DelegationError
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


FailureStage = Literal[
    "none",
    "after_consumption_insert",
    "after_binding_insert",
    "before_commit",
]


@dataclass(frozen=True, slots=True)
class AtomicLedgerPaths:
    base_dir: str

    @property
    def coordinator_db_path(self) -> str:
        return str(Path(self.base_dir) / "r26_atomic_coordinator.db")

    @property
    def consumption_db_path(self) -> str:
        return str(Path(self.base_dir) / "r26_consumption.db")

    @property
    def binding_db_path(self) -> str:
        return str(Path(self.base_dir) / "r26_binding.db")

    @property
    def outcome_db_path(self) -> str:
        return str(Path(self.base_dir) / "r26_outcome.db")


@dataclass(frozen=True, slots=True)
class AtomicCommitResult:
    ok: bool
    chain_digest: str
    execution_id: str
    binding_audit_event_id: str
    final_audit_event_id: str
    request_id: str
    task_id: str
    operation_id: str
    payload_digest: str
    leaf_subject: str
    status: str
    result_digest: str
    seal_digest: str
    committed_at: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "chain_digest": self.chain_digest,
            "execution_id": self.execution_id,
            "binding_audit_event_id": self.binding_audit_event_id,
            "final_audit_event_id": self.final_audit_event_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "payload_digest": self.payload_digest,
            "leaf_subject": self.leaf_subject,
            "status": self.status,
            "result_digest": self.result_digest,
            "seal_digest": self.seal_digest,
            "committed_at": self.committed_at,
        }


class AtomicCommitError(ValueError):
    pass


class PartialWriteInjectedError(RuntimeError):
    pass


class AtomicMultiLedgerCommitCoordinator:
    REQUIRED_BINDING_EVENT_TYPE = "delegation.execution.bound"
    REQUIRED_FINAL_EVENT_TYPE = "delegation.execution.finalized"
    ALLOWED_OUTCOME_STATUSES = {"succeeded", "failed"}

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
        self._chain_verifier = DelegationChainVerifier(
            trust_store,
            max_chain_depth=max_chain_depth,
            clock_skew_seconds=clock_skew_seconds,
        )
        Path(self._ledger_paths.base_dir).mkdir(parents=True, exist_ok=True)
        self._initialize_databases()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._ledger_paths.coordinator_db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("ATTACH DATABASE ? AS consumed", (self._ledger_paths.consumption_db_path,))
        conn.execute("ATTACH DATABASE ? AS binding", (self._ledger_paths.binding_db_path,))
        conn.execute("ATTACH DATABASE ? AS outcome", (self._ledger_paths.outcome_db_path,))
        return conn

    def _initialize_databases(self) -> None:
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS consumed.delegation_consumptions (
                        chain_digest TEXT PRIMARY KEY,
                        request_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        payload_digest TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        issued_for TEXT NOT NULL,
                        leaf_subject TEXT NOT NULL,
                        consumed_at INTEGER NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS consumed.idx_request_nonce
                    ON delegation_consumptions (request_id, nonce)
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS binding.execution_audit_bindings (
                        chain_digest TEXT PRIMARY KEY,
                        execution_id TEXT NOT NULL UNIQUE,
                        audit_event_id TEXT NOT NULL UNIQUE,
                        run_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        payload_digest TEXT NOT NULL,
                        leaf_subject TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        bound_at INTEGER NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS outcome.execution_outcome_seals (
                        chain_digest TEXT PRIMARY KEY,
                        execution_id TEXT NOT NULL UNIQUE,
                        binding_audit_event_id TEXT NOT NULL UNIQUE,
                        final_audit_event_id TEXT NOT NULL UNIQUE,
                        run_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        payload_digest TEXT NOT NULL,
                        leaf_subject TEXT NOT NULL,
                        status TEXT NOT NULL,
                        result_digest TEXT NOT NULL,
                        finished_at INTEGER NOT NULL,
                        sealed_at INTEGER NOT NULL,
                        seal_digest TEXT NOT NULL
                    )
                    """
                )
        finally:
            conn.close()

    def verify_and_atomic_commit(
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
        now: int | None = None,
        fail_stage: FailureStage = "none",
    ) -> AtomicCommitResult:
        current_time = int(time.time()) if now is None else int(now)

        chain_result = self._verify_all_semantics(
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
            with conn:
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

                if fail_stage == "after_consumption_insert":
                    raise PartialWriteInjectedError(
                        "injected failure after consumption insert"
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

                if fail_stage == "after_binding_insert":
                    raise PartialWriteInjectedError(
                        "injected failure after binding insert"
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

                if fail_stage == "before_commit":
                    raise PartialWriteInjectedError(
                        "injected failure before commit"
                    )

        except sqlite3.IntegrityError as exc:
            raise AtomicCommitError(
                "atomic multi-ledger commit rejected due to replay or identifier re-use"
            ) from exc
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

    def verify_persisted_seal_after_restart(
        self,
        *,
        chain_digest: str,
        execution: ExecutionRecord,
        binding_audit_event_id: str,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        leaf_subject: str,
    ) -> dict[str, Any]:
        conn = self._connect()
        try:
            stored = conn.execute(
                """
                SELECT
                    chain_digest,
                    execution_id,
                    binding_audit_event_id,
                    final_audit_event_id,
                    status,
                    result_digest,
                    seal_digest
                FROM outcome.execution_outcome_seals
                WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()
        finally:
            conn.close()

        if stored is None:
            raise AtomicCommitError("persisted outcome seal not found")

        recomputed = compute_outcome_seal_digest(
            chain_digest=chain_digest,
            execution=execution,
            binding_audit_event_id=binding_audit_event_id,
            final_audit_event=final_audit_event,
            outcome=outcome,
            leaf_subject=leaf_subject,
        )

        if not hmac.compare_digest(stored["seal_digest"], recomputed):
            raise AtomicCommitError("persisted outcome seal does not match presented material")

        return {
            "ok": True,
            "chain_digest": stored["chain_digest"],
            "execution_id": stored["execution_id"],
            "binding_audit_event_id": stored["binding_audit_event_id"],
            "final_audit_event_id": stored["final_audit_event_id"],
            "status": stored["status"],
            "result_digest": stored["result_digest"],
            "seal_digest": stored["seal_digest"],
        }

    def get_atomic_state_counts(self, chain_digest: str) -> dict[str, int]:
        conn = self._connect()
        try:
            consumed_count = conn.execute(
                "SELECT COUNT(*) AS c FROM consumed.delegation_consumptions WHERE chain_digest = ?",
                (chain_digest,),
            ).fetchone()["c"]
            binding_count = conn.execute(
                "SELECT COUNT(*) AS c FROM binding.execution_audit_bindings WHERE chain_digest = ?",
                (chain_digest,),
            ).fetchone()["c"]
            outcome_count = conn.execute(
                "SELECT COUNT(*) AS c FROM outcome.execution_outcome_seals WHERE chain_digest = ?",
                (chain_digest,),
            ).fetchone()["c"]
        finally:
            conn.close()

        return {
            "consumed": int(consumed_count),
            "binding": int(binding_count),
            "outcome": int(outcome_count),
        }

    def assert_atomic_state_consistency(self, chain_digest: str) -> dict[str, Any]:
        counts = self.get_atomic_state_counts(chain_digest)
        values = {counts["consumed"], counts["binding"], counts["outcome"]}

        if values == {0}:
            return {"ok": True, "state": "absent", "counts": counts}

        if values == {1}:
            return {"ok": True, "state": "fully_present", "counts": counts}

        raise AtomicCommitError(
            "partial multi-ledger state detected across consumed/binding/outcome ledgers"
        )

    def _verify_all_semantics(
        self,
        *,
        envelope: DelegationConsumptionEnvelope,
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
        if envelope.request_id != expected_request_id:
            raise AtomicCommitError("request_id binding mismatch")

        if envelope.task_id != expected_task_id:
            raise AtomicCommitError("task_id binding mismatch")

        if envelope.operation_id != expected_operation_id:
            raise AtomicCommitError("operation_id binding mismatch")

        if envelope.payload_digest != expected_payload_digest:
            raise AtomicCommitError("payload_digest binding mismatch")

        if envelope.issued_for != expected_issued_for:
            raise AtomicCommitError("issued_for binding mismatch")

        if not envelope.nonce.strip():
            raise AtomicCommitError("nonce must be non-empty")

        try:
            chain_result = self._chain_verifier.verify_chain(
                envelope.signed_chain,
                expected_leaf_subject=expected_leaf_subject,
                required_scopes=required_scopes,
                now=now,
            )
        except DelegationError as exc:
            raise AtomicCommitError(str(exc)) from exc

        self._verify_execution(
            execution=execution,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_leaf_subject=expected_leaf_subject,
        )

        self._verify_binding_audit(
            binding_audit_event=binding_audit_event,
            execution=execution,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_chain_digest=canonical_chain_digest(envelope.signed_chain),
            expected_leaf_subject=expected_leaf_subject,
        )

        self._verify_outcome(
            outcome=outcome,
            execution=execution,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_leaf_subject=expected_leaf_subject,
        )

        self._verify_final_audit(
            final_audit_event=final_audit_event,
            binding_audit_event=binding_audit_event,
            execution=execution,
            outcome=outcome,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_chain_digest=canonical_chain_digest(envelope.signed_chain),
            expected_leaf_subject=expected_leaf_subject,
        )

        return chain_result

    def _verify_execution(
        self,
        *,
        execution: ExecutionRecord,
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_leaf_subject: str,
    ) -> None:
        if not execution.execution_id.strip():
            raise AtomicCommitError("execution_id must be non-empty")

        if not execution.run_id.strip():
            raise AtomicCommitError("run_id must be non-empty")

        if execution.request_id != expected_request_id:
            raise AtomicCommitError("execution request_id mismatch")

        if execution.task_id != expected_task_id:
            raise AtomicCommitError("execution task_id mismatch")

        if execution.operation_id != expected_operation_id:
            raise AtomicCommitError("execution operation_id mismatch")

        if execution.payload_digest != expected_payload_digest:
            raise AtomicCommitError("execution payload_digest mismatch")

        if execution.executor_subject != expected_leaf_subject:
            raise AtomicCommitError("execution executor_subject mismatch")

    def _verify_binding_audit(
        self,
        *,
        binding_audit_event: AuditEventRecord,
        execution: ExecutionRecord,
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_chain_digest: str,
        expected_leaf_subject: str,
    ) -> None:
        if not binding_audit_event.audit_event_id.strip():
            raise AtomicCommitError("binding audit_event_id must be non-empty")

        if binding_audit_event.event_type != self.REQUIRED_BINDING_EVENT_TYPE:
            raise AtomicCommitError("binding audit event_type mismatch")

        if binding_audit_event.execution_id != execution.execution_id:
            raise AtomicCommitError("binding audit execution_id mismatch")

        if binding_audit_event.run_id != execution.run_id:
            raise AtomicCommitError("binding audit run_id mismatch")

        if binding_audit_event.request_id != expected_request_id:
            raise AtomicCommitError("binding audit request_id mismatch")

        if binding_audit_event.task_id != expected_task_id:
            raise AtomicCommitError("binding audit task_id mismatch")

        if binding_audit_event.operation_id != expected_operation_id:
            raise AtomicCommitError("binding audit operation_id mismatch")

        if binding_audit_event.payload_digest != expected_payload_digest:
            raise AtomicCommitError("binding audit payload_digest mismatch")

        if binding_audit_event.chain_digest != expected_chain_digest:
            raise AtomicCommitError("binding audit chain_digest mismatch")

        if binding_audit_event.leaf_subject != expected_leaf_subject:
            raise AtomicCommitError("binding audit leaf_subject mismatch")

    def _verify_outcome(
        self,
        *,
        outcome: ExecutionOutcomeRecord,
        execution: ExecutionRecord,
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_leaf_subject: str,
    ) -> None:
        if not outcome.execution_id.strip():
            raise AtomicCommitError("outcome execution_id must be non-empty")

        if outcome.execution_id != execution.execution_id:
            raise AtomicCommitError("outcome execution_id mismatch")

        if outcome.run_id != execution.run_id:
            raise AtomicCommitError("outcome run_id mismatch")

        if outcome.request_id != expected_request_id:
            raise AtomicCommitError("outcome request_id mismatch")

        if outcome.task_id != expected_task_id:
            raise AtomicCommitError("outcome task_id mismatch")

        if outcome.operation_id != expected_operation_id:
            raise AtomicCommitError("outcome operation_id mismatch")

        if outcome.payload_digest != expected_payload_digest:
            raise AtomicCommitError("outcome payload_digest mismatch")

        if outcome.executor_subject != expected_leaf_subject:
            raise AtomicCommitError("outcome executor_subject mismatch")

        if outcome.status not in self.ALLOWED_OUTCOME_STATUSES:
            raise AtomicCommitError("outcome status is not allowed")

        if not outcome.result_digest.strip():
            raise AtomicCommitError("outcome result_digest must be non-empty")

        if outcome.finished_at < execution.started_at:
            raise AtomicCommitError("outcome finished_at precedes execution started_at")

    def _verify_final_audit(
        self,
        *,
        final_audit_event: OutcomeFinalizationAuditRecord,
        binding_audit_event: AuditEventRecord,
        execution: ExecutionRecord,
        outcome: ExecutionOutcomeRecord,
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_chain_digest: str,
        expected_leaf_subject: str,
    ) -> None:
        if not final_audit_event.audit_event_id.strip():
            raise AtomicCommitError("final audit_event_id must be non-empty")

        if final_audit_event.event_type != self.REQUIRED_FINAL_EVENT_TYPE:
            raise AtomicCommitError("final audit event_type mismatch")

        if final_audit_event.parent_audit_event_id != binding_audit_event.audit_event_id:
            raise AtomicCommitError("final audit parent_audit_event_id mismatch")

        if final_audit_event.execution_id != execution.execution_id:
            raise AtomicCommitError("final audit execution_id mismatch")

        if final_audit_event.run_id != execution.run_id:
            raise AtomicCommitError("final audit run_id mismatch")

        if final_audit_event.request_id != expected_request_id:
            raise AtomicCommitError("final audit request_id mismatch")

        if final_audit_event.task_id != expected_task_id:
            raise AtomicCommitError("final audit task_id mismatch")

        if final_audit_event.operation_id != expected_operation_id:
            raise AtomicCommitError("final audit operation_id mismatch")

        if final_audit_event.payload_digest != expected_payload_digest:
            raise AtomicCommitError("final audit payload_digest mismatch")

        if final_audit_event.chain_digest != expected_chain_digest:
            raise AtomicCommitError("final audit chain_digest mismatch")

        if final_audit_event.leaf_subject != expected_leaf_subject:
            raise AtomicCommitError("final audit leaf_subject mismatch")

        if final_audit_event.status != outcome.status:
            raise AtomicCommitError("final audit status mismatch")

        if final_audit_event.result_digest != outcome.result_digest:
            raise AtomicCommitError("final audit result_digest mismatch")

        if final_audit_event.created_at < outcome.finished_at:
            raise AtomicCommitError("final audit created_at precedes outcome finished_at")
