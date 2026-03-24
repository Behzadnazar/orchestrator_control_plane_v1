from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any

from app.security.delegation_consumption import (
    ConsumedDelegationLedger,
    DelegationConsumptionEnvelope,
)
from app.security.execution_binding import (
    AuditEventRecord,
    ConsumptionExecutionBindingVerifier,
    ExecutionAuditBindingLedger,
    ExecutionBindingError,
    ExecutionRecord,
)


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
class ExecutionOutcomeRecord:
    execution_id: str
    run_id: str
    request_id: str
    task_id: str
    operation_id: str
    payload_digest: str
    executor_subject: str
    status: str
    result_digest: str
    finished_at: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "run_id": self.run_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "payload_digest": self.payload_digest,
            "executor_subject": self.executor_subject,
            "status": self.status,
            "result_digest": self.result_digest,
            "finished_at": self.finished_at,
        }


@dataclass(frozen=True, slots=True)
class OutcomeFinalizationAuditRecord:
    audit_event_id: str
    event_type: str
    parent_audit_event_id: str
    execution_id: str
    run_id: str
    request_id: str
    task_id: str
    operation_id: str
    payload_digest: str
    chain_digest: str
    leaf_subject: str
    status: str
    result_digest: str
    created_at: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "audit_event_id": self.audit_event_id,
            "event_type": self.event_type,
            "parent_audit_event_id": self.parent_audit_event_id,
            "execution_id": self.execution_id,
            "run_id": self.run_id,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "payload_digest": self.payload_digest,
            "chain_digest": self.chain_digest,
            "leaf_subject": self.leaf_subject,
            "status": self.status,
            "result_digest": self.result_digest,
            "created_at": self.created_at,
        }


class OutcomeSealingError(ValueError):
    pass


class OutcomeSealingLedger:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_outcome_seals (
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

    def seal_once(
        self,
        *,
        chain_digest: str,
        execution: ExecutionRecord,
        binding_audit_event_id: str,
        final_audit_event: OutcomeFinalizationAuditRecord,
        outcome: ExecutionOutcomeRecord,
        leaf_subject: str,
        sealed_at: int | None = None,
    ) -> str:
        ts = int(time.time()) if sealed_at is None else int(sealed_at)
        seal_digest = compute_outcome_seal_digest(
            chain_digest=chain_digest,
            execution=execution,
            binding_audit_event_id=binding_audit_event_id,
            final_audit_event=final_audit_event,
            outcome=outcome,
            leaf_subject=leaf_subject,
        )

        try:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO execution_outcome_seals (
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
                        binding_audit_event_id,
                        final_audit_event.audit_event_id,
                        execution.run_id,
                        execution.request_id,
                        execution.task_id,
                        execution.operation_id,
                        execution.payload_digest,
                        leaf_subject,
                        outcome.status,
                        outcome.result_digest,
                        outcome.finished_at,
                        ts,
                        seal_digest,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise OutcomeSealingError(
                "execution outcome already sealed or audit identifiers were re-used"
            ) from exc

        return seal_digest

    def fetch_by_chain_digest(self, chain_digest: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT
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
            FROM execution_outcome_seals
            WHERE chain_digest = ?
            """,
            (chain_digest,),
        ).fetchone()

        if row is None:
            return None

        return {
            "chain_digest": row["chain_digest"],
            "execution_id": row["execution_id"],
            "binding_audit_event_id": row["binding_audit_event_id"],
            "final_audit_event_id": row["final_audit_event_id"],
            "run_id": row["run_id"],
            "request_id": row["request_id"],
            "task_id": row["task_id"],
            "operation_id": row["operation_id"],
            "payload_digest": row["payload_digest"],
            "leaf_subject": row["leaf_subject"],
            "status": row["status"],
            "result_digest": row["result_digest"],
            "finished_at": row["finished_at"],
            "sealed_at": row["sealed_at"],
            "seal_digest": row["seal_digest"],
        }


def compute_result_digest(result_payload: dict[str, Any]) -> str:
    return _sha256_hex(_json_canonical(result_payload))


def compute_outcome_seal_digest(
    *,
    chain_digest: str,
    execution: ExecutionRecord,
    binding_audit_event_id: str,
    final_audit_event: OutcomeFinalizationAuditRecord,
    outcome: ExecutionOutcomeRecord,
    leaf_subject: str,
) -> str:
    material = {
        "chain_digest": chain_digest,
        "execution": execution.to_payload(),
        "binding_audit_event_id": binding_audit_event_id,
        "final_audit_event": final_audit_event.to_payload(),
        "outcome": outcome.to_payload(),
        "leaf_subject": leaf_subject,
    }
    return _sha256_hex(_json_canonical(material))


class ExecutionOutcomeSealingVerifier:
    REQUIRED_FINAL_AUDIT_EVENT_TYPE = "delegation.execution.finalized"
    ALLOWED_STATUSES = {"succeeded", "failed"}

    def __init__(
        self,
        trust_store: dict[str, bytes],
        *,
        consumption_ledger: ConsumedDelegationLedger | None = None,
        binding_ledger: ExecutionAuditBindingLedger | None = None,
        outcome_ledger: OutcomeSealingLedger | None = None,
        max_chain_depth: int = 8,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._binding_verifier = ConsumptionExecutionBindingVerifier(
            trust_store,
            consumption_ledger=consumption_ledger,
            binding_ledger=binding_ledger,
            max_chain_depth=max_chain_depth,
            clock_skew_seconds=clock_skew_seconds,
        )
        self._outcome_ledger = outcome_ledger or OutcomeSealingLedger()

    def verify_bind_and_seal(
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
    ) -> dict[str, Any]:
        current_time = int(time.time()) if now is None else int(now)

        bound = self._binding_verifier.verify_consume_and_bind(
            envelope,
            expected_leaf_subject=expected_leaf_subject,
            required_scopes=required_scopes,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_issued_for=expected_issued_for,
            execution=execution,
            audit_event=binding_audit_event,
            now=current_time,
        )

        chain_digest = bound["chain_digest"]

        self._verify_outcome(
            outcome=outcome,
            execution=execution,
            expected_leaf_subject=expected_leaf_subject,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
        )

        self._verify_final_audit(
            final_audit_event=final_audit_event,
            binding_audit_event=binding_audit_event,
            execution=execution,
            outcome=outcome,
            expected_chain_digest=chain_digest,
            expected_leaf_subject=expected_leaf_subject,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
        )

        seal_digest = self._outcome_ledger.seal_once(
            chain_digest=chain_digest,
            execution=execution,
            binding_audit_event_id=binding_audit_event.audit_event_id,
            final_audit_event=final_audit_event,
            outcome=outcome,
            leaf_subject=expected_leaf_subject,
            sealed_at=current_time,
        )

        return {
            "ok": True,
            "chain_digest": chain_digest,
            "execution_id": execution.execution_id,
            "binding_audit_event_id": binding_audit_event.audit_event_id,
            "final_audit_event_id": final_audit_event.audit_event_id,
            "request_id": execution.request_id,
            "task_id": execution.task_id,
            "operation_id": execution.operation_id,
            "payload_digest": execution.payload_digest,
            "leaf_subject": expected_leaf_subject,
            "status": outcome.status,
            "result_digest": outcome.result_digest,
            "seal_digest": seal_digest,
            "sealed_at": current_time,
        }

    def verify_presented_seal(
        self,
        *,
        chain_digest: str,
        execution: ExecutionRecord,
        binding_audit_event_id: str,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        leaf_subject: str,
    ) -> dict[str, Any]:
        stored = self._outcome_ledger.fetch_by_chain_digest(chain_digest)
        if stored is None:
            raise OutcomeSealingError("sealed outcome not found for chain_digest")

        recomputed = compute_outcome_seal_digest(
            chain_digest=chain_digest,
            execution=execution,
            binding_audit_event_id=binding_audit_event_id,
            final_audit_event=final_audit_event,
            outcome=outcome,
            leaf_subject=leaf_subject,
        )

        if not hmac.compare_digest(stored["seal_digest"], recomputed):
            raise OutcomeSealingError("presented execution outcome seal does not match stored seal")

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

    def _verify_outcome(
        self,
        *,
        outcome: ExecutionOutcomeRecord,
        execution: ExecutionRecord,
        expected_leaf_subject: str,
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
    ) -> None:
        if not outcome.execution_id.strip():
            raise OutcomeSealingError("outcome execution_id must be non-empty")

        if outcome.execution_id != execution.execution_id:
            raise OutcomeSealingError("outcome execution_id mismatch")

        if outcome.run_id != execution.run_id:
            raise OutcomeSealingError("outcome run_id mismatch")

        if outcome.request_id != expected_request_id:
            raise OutcomeSealingError("outcome request_id mismatch")

        if outcome.task_id != expected_task_id:
            raise OutcomeSealingError("outcome task_id mismatch")

        if outcome.operation_id != expected_operation_id:
            raise OutcomeSealingError("outcome operation_id mismatch")

        if outcome.payload_digest != expected_payload_digest:
            raise OutcomeSealingError("outcome payload_digest mismatch")

        if outcome.executor_subject != expected_leaf_subject:
            raise OutcomeSealingError("outcome executor_subject mismatch")

        if outcome.status not in self.ALLOWED_STATUSES:
            raise OutcomeSealingError("outcome status is not allowed")

        if not outcome.result_digest.strip():
            raise OutcomeSealingError("outcome result_digest must be non-empty")

        if outcome.finished_at < execution.started_at:
            raise OutcomeSealingError("outcome finished_at precedes execution started_at")

    def _verify_final_audit(
        self,
        *,
        final_audit_event: OutcomeFinalizationAuditRecord,
        binding_audit_event: AuditEventRecord,
        execution: ExecutionRecord,
        outcome: ExecutionOutcomeRecord,
        expected_chain_digest: str,
        expected_leaf_subject: str,
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
    ) -> None:
        if not final_audit_event.audit_event_id.strip():
            raise OutcomeSealingError("final audit_event_id must be non-empty")

        if final_audit_event.event_type != self.REQUIRED_FINAL_AUDIT_EVENT_TYPE:
            raise OutcomeSealingError("final audit event_type mismatch")

        if final_audit_event.parent_audit_event_id != binding_audit_event.audit_event_id:
            raise OutcomeSealingError("final audit parent_audit_event_id mismatch")

        if final_audit_event.execution_id != execution.execution_id:
            raise OutcomeSealingError("final audit execution_id mismatch")

        if final_audit_event.run_id != execution.run_id:
            raise OutcomeSealingError("final audit run_id mismatch")

        if final_audit_event.request_id != expected_request_id:
            raise OutcomeSealingError("final audit request_id mismatch")

        if final_audit_event.task_id != expected_task_id:
            raise OutcomeSealingError("final audit task_id mismatch")

        if final_audit_event.operation_id != expected_operation_id:
            raise OutcomeSealingError("final audit operation_id mismatch")

        if final_audit_event.payload_digest != expected_payload_digest:
            raise OutcomeSealingError("final audit payload_digest mismatch")

        if final_audit_event.chain_digest != expected_chain_digest:
            raise OutcomeSealingError("final audit chain_digest mismatch")

        if final_audit_event.leaf_subject != expected_leaf_subject:
            raise OutcomeSealingError("final audit leaf_subject mismatch")

        if final_audit_event.status != outcome.status:
            raise OutcomeSealingError("final audit status mismatch")

        if final_audit_event.result_digest != outcome.result_digest:
            raise OutcomeSealingError("final audit result_digest mismatch")

        if final_audit_event.created_at < outcome.finished_at:
            raise OutcomeSealingError("final audit created_at precedes outcome finished_at")


def new_execution_outcome_record(
    *,
    execution_id: str,
    run_id: str,
    request_id: str,
    task_id: str,
    operation_id: str,
    payload_digest: str,
    executor_subject: str,
    status: str,
    result_digest: str,
    finished_at: int,
) -> ExecutionOutcomeRecord:
    return ExecutionOutcomeRecord(
        execution_id=execution_id,
        run_id=run_id,
        request_id=request_id,
        task_id=task_id,
        operation_id=operation_id,
        payload_digest=payload_digest,
        executor_subject=executor_subject,
        status=status,
        result_digest=result_digest,
        finished_at=finished_at,
    )


def new_outcome_finalization_audit_record(
    *,
    parent_audit_event_id: str,
    execution_id: str,
    run_id: str,
    request_id: str,
    task_id: str,
    operation_id: str,
    payload_digest: str,
    chain_digest: str,
    leaf_subject: str,
    status: str,
    result_digest: str,
    created_at: int,
    event_type: str = ExecutionOutcomeSealingVerifier.REQUIRED_FINAL_AUDIT_EVENT_TYPE,
) -> OutcomeFinalizationAuditRecord:
    return OutcomeFinalizationAuditRecord(
        audit_event_id=str(uuid.uuid4()),
        event_type=event_type,
        parent_audit_event_id=parent_audit_event_id,
        execution_id=execution_id,
        run_id=run_id,
        request_id=request_id,
        task_id=task_id,
        operation_id=operation_id,
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject=leaf_subject,
        status=status,
        result_digest=result_digest,
        created_at=created_at,
    )
