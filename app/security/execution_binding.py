from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any

from app.security.delegation_consumption import (
    ConsumedDelegationLedger,
    DelegationConsumptionEnvelope,
    DelegationConsumptionError,
    DelegationConsumptionVerifier,
    canonical_chain_digest,
)


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    execution_id: str
    run_id: str
    request_id: str
    task_id: str
    operation_id: str
    payload_digest: str
    executor_subject: str
    started_at: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "run_id": self.run_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "payload_digest": self.payload_digest,
            "executor_subject": self.executor_subject,
            "started_at": self.started_at,
        }


@dataclass(frozen=True, slots=True)
class AuditEventRecord:
    audit_event_id: str
    event_type: str
    execution_id: str
    run_id: str
    request_id: str
    task_id: str
    operation_id: str
    payload_digest: str
    chain_digest: str
    leaf_subject: str
    created_at: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "audit_event_id": self.audit_event_id,
            "event_type": self.event_type,
            "execution_id": self.execution_id,
            "run_id": self.run_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "payload_digest": self.payload_digest,
            "chain_digest": self.chain_digest,
            "leaf_subject": self.leaf_subject,
            "created_at": self.created_at,
        }


class ExecutionBindingError(ValueError):
    pass


class ExecutionAuditBindingLedger:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_audit_bindings (
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

    def bind_once(
        self,
        *,
        chain_digest: str,
        execution: ExecutionRecord,
        audit_event: AuditEventRecord,
        leaf_subject: str,
        bound_at: int | None = None,
    ) -> None:
        ts = int(time.time()) if bound_at is None else int(bound_at)

        try:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO execution_audit_bindings (
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
                        audit_event.audit_event_id,
                        execution.run_id,
                        execution.request_id,
                        execution.task_id,
                        execution.operation_id,
                        execution.payload_digest,
                        leaf_subject,
                        audit_event.event_type,
                        ts,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ExecutionBindingError(
                "execution/audit binding already exists or identifiers were re-used"
            ) from exc

    def fetch_by_chain_digest(self, chain_digest: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT
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
            FROM execution_audit_bindings
            WHERE chain_digest = ?
            """,
            (chain_digest,),
        ).fetchone()

        if row is None:
            return None

        return {
            "chain_digest": row["chain_digest"],
            "execution_id": row["execution_id"],
            "audit_event_id": row["audit_event_id"],
            "run_id": row["run_id"],
            "request_id": row["request_id"],
            "task_id": row["task_id"],
            "operation_id": row["operation_id"],
            "payload_digest": row["payload_digest"],
            "leaf_subject": row["leaf_subject"],
            "event_type": row["event_type"],
            "bound_at": row["bound_at"],
        }


class ConsumptionExecutionBindingVerifier:
    REQUIRED_AUDIT_EVENT_TYPE = "delegation.execution.bound"

    def __init__(
        self,
        trust_store: dict[str, bytes],
        *,
        consumption_ledger: ConsumedDelegationLedger | None = None,
        binding_ledger: ExecutionAuditBindingLedger | None = None,
        max_chain_depth: int = 8,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._consumption_ledger = consumption_ledger or ConsumedDelegationLedger()
        self._binding_ledger = binding_ledger or ExecutionAuditBindingLedger()
        self._consumption_verifier = DelegationConsumptionVerifier(
            trust_store,
            ledger=self._consumption_ledger,
            max_chain_depth=max_chain_depth,
            clock_skew_seconds=clock_skew_seconds,
        )

    def verify_consume_and_bind(
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
        audit_event: AuditEventRecord,
        now: int | None = None,
    ) -> dict[str, Any]:
        current_time = int(time.time()) if now is None else int(now)

        consumed = self._consumption_verifier.verify_and_consume(
            envelope,
            expected_leaf_subject=expected_leaf_subject,
            required_scopes=required_scopes,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_issued_for=expected_issued_for,
            now=current_time,
        )

        chain_digest = consumed["chain_digest"]

        self._verify_execution_binding(
            execution=execution,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_leaf_subject=expected_leaf_subject,
        )

        self._verify_audit_event_binding(
            audit_event=audit_event,
            execution=execution,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_chain_digest=chain_digest,
            expected_leaf_subject=expected_leaf_subject,
        )

        self._binding_ledger.bind_once(
            chain_digest=chain_digest,
            execution=execution,
            audit_event=audit_event,
            leaf_subject=expected_leaf_subject,
            bound_at=current_time,
        )

        return {
            "ok": True,
            "chain_digest": chain_digest,
            "execution_id": execution.execution_id,
            "audit_event_id": audit_event.audit_event_id,
            "run_id": execution.run_id,
            "request_id": execution.request_id,
            "task_id": execution.task_id,
            "operation_id": execution.operation_id,
            "payload_digest": execution.payload_digest,
            "leaf_subject": expected_leaf_subject,
            "event_type": audit_event.event_type,
            "bound_at": current_time,
        }

    def _verify_execution_binding(
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
            raise ExecutionBindingError("execution_id must be non-empty")

        if not execution.run_id.strip():
            raise ExecutionBindingError("run_id must be non-empty")

        if execution.request_id != expected_request_id:
            raise ExecutionBindingError("execution request_id mismatch")

        if execution.task_id != expected_task_id:
            raise ExecutionBindingError("execution task_id mismatch")

        if execution.operation_id != expected_operation_id:
            raise ExecutionBindingError("execution operation_id mismatch")

        if execution.payload_digest != expected_payload_digest:
            raise ExecutionBindingError("execution payload_digest mismatch")

        if execution.executor_subject != expected_leaf_subject:
            raise ExecutionBindingError("execution executor_subject mismatch")

    def _verify_audit_event_binding(
        self,
        *,
        audit_event: AuditEventRecord,
        execution: ExecutionRecord,
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_chain_digest: str,
        expected_leaf_subject: str,
    ) -> None:
        if not audit_event.audit_event_id.strip():
            raise ExecutionBindingError("audit_event_id must be non-empty")

        if audit_event.event_type != self.REQUIRED_AUDIT_EVENT_TYPE:
            raise ExecutionBindingError("audit event_type mismatch")

        if audit_event.execution_id != execution.execution_id:
            raise ExecutionBindingError("audit execution_id mismatch")

        if audit_event.run_id != execution.run_id:
            raise ExecutionBindingError("audit run_id mismatch")

        if audit_event.request_id != expected_request_id:
            raise ExecutionBindingError("audit request_id mismatch")

        if audit_event.task_id != expected_task_id:
            raise ExecutionBindingError("audit task_id mismatch")

        if audit_event.operation_id != expected_operation_id:
            raise ExecutionBindingError("audit operation_id mismatch")

        if audit_event.payload_digest != expected_payload_digest:
            raise ExecutionBindingError("audit payload_digest mismatch")

        if audit_event.chain_digest != expected_chain_digest:
            raise ExecutionBindingError("audit chain_digest mismatch")

        if audit_event.leaf_subject != expected_leaf_subject:
            raise ExecutionBindingError("audit leaf_subject mismatch")


def new_execution_record(
    *,
    run_id: str,
    request_id: str,
    task_id: str,
    operation_id: str,
    payload_digest: str,
    executor_subject: str,
    started_at: int,
) -> ExecutionRecord:
    return ExecutionRecord(
        execution_id=str(uuid.uuid4()),
        run_id=run_id,
        request_id=request_id,
        task_id=task_id,
        operation_id=operation_id,
        payload_digest=payload_digest,
        executor_subject=executor_subject,
        started_at=started_at,
    )


def new_audit_event_record(
    *,
    execution_id: str,
    run_id: str,
    request_id: str,
    task_id: str,
    operation_id: str,
    payload_digest: str,
    chain_digest: str,
    leaf_subject: str,
    created_at: int,
    event_type: str = ConsumptionExecutionBindingVerifier.REQUIRED_AUDIT_EVENT_TYPE,
) -> AuditEventRecord:
    return AuditEventRecord(
        audit_event_id=str(uuid.uuid4()),
        event_type=event_type,
        execution_id=execution_id,
        run_id=run_id,
        request_id=request_id,
        task_id=task_id,
        operation_id=operation_id,
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject=leaf_subject,
        created_at=created_at,
    )


def expected_chain_digest_for_envelope(envelope: DelegationConsumptionEnvelope) -> str:
    return canonical_chain_digest(envelope.signed_chain)
