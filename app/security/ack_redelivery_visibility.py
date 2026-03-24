from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.security.atomic_multi_ledger_commit import (
    AtomicCommitError,
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
class QueuePaths:
    base_dir: str

    @property
    def queue_db_path(self) -> str:
        return str(Path(self.base_dir) / "r32_queue.db")


class AckRedeliveryError(ValueError):
    pass


class AckRedeliveryCoordinator:
    def __init__(
        self,
        trust_store: dict[str, bytes],
        *,
        ledger_paths: AtomicLedgerPaths,
        queue_paths: QueuePaths,
        max_chain_depth: int = 8,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._trust_store = trust_store
        self._ledger_paths = ledger_paths
        self._queue_paths = queue_paths
        Path(self._queue_paths.base_dir).mkdir(parents=True, exist_ok=True)
        self._atomic = AtomicMultiLedgerCommitCoordinator(
            trust_store,
            ledger_paths=ledger_paths,
            max_chain_depth=max_chain_depth,
            clock_skew_seconds=clock_skew_seconds,
        )
        self._initialize_queue()

    def _queue_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._queue_paths.queue_db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize_queue(self) -> None:
        conn = self._queue_conn()
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS delivery_queue (
                        message_id TEXT PRIMARY KEY,
                        chain_digest TEXT NOT NULL,
                        status TEXT NOT NULL,
                        delivery_count INTEGER NOT NULL,
                        last_error TEXT,
                        last_delivery_at INTEGER,
                        acked_at INTEGER
                    )
                    """
                )
            conn.close()
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def enqueue(self, *, message_id: str, chain_digest: str) -> None:
        conn = self._queue_conn()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO delivery_queue (
                        message_id,
                        chain_digest,
                        status,
                        delivery_count,
                        last_error,
                        last_delivery_at,
                        acked_at
                    )
                    VALUES (?, ?, 'queued', 0, NULL, NULL, NULL)
                    """,
                    (message_id, chain_digest),
                )
        except sqlite3.IntegrityError as exc:
            raise AckRedeliveryError("queue message already exists") from exc
        finally:
            conn.close()

    def process_delivery(
        self,
        *,
        message_id: str,
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
        ack_after_commit: bool,
        now: int,
    ) -> dict[str, Any]:
        self._claim_message(message_id=message_id, now=now)

        committed_now = False
        replayed_existing = False
        commit_result: dict[str, Any] | None = None

        try:
            result = self._atomic.verify_and_atomic_commit(
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
                now=now,
            )
            commit_result = result.to_payload()
            committed_now = True
        except AtomicCommitError:
            state = self._atomic.assert_atomic_state_consistency(
                envelope.signed_chain and commit_result["chain_digest"] if commit_result else self._chain_digest_from_envelope(envelope)
            )
            if state["state"] != "fully_present":
                self._release_for_redelivery(
                    message_id=message_id,
                    last_error="atomic commit failed before visible side effect existed",
                )
                raise
            replayed_existing = True

        if ack_after_commit:
            self._ack_message(message_id=message_id, now=now + 1)
        else:
            # simulate crash after commit but before ack
            pass

        visible = self._atomic.assert_atomic_state_consistency(
            self._chain_digest_from_envelope(envelope)
        )

        return {
            "ok": True,
            "message_id": message_id,
            "committed_now": committed_now,
            "replayed_existing": replayed_existing,
            "visible_state": visible["state"],
            "counts": visible["counts"],
        }

    def requeue_inflight_for_redelivery(self, *, message_id: str) -> None:
        conn = self._queue_conn()
        try:
            with conn:
                row = conn.execute(
                    "SELECT status FROM delivery_queue WHERE message_id = ?",
                    (message_id,),
                ).fetchone()
                if row is None:
                    raise AckRedeliveryError("queue message not found")
                if str(row["status"]) != "inflight":
                    raise AckRedeliveryError("only inflight message can be requeued")
                conn.execute(
                    """
                    UPDATE delivery_queue
                    SET status = 'queued'
                    WHERE message_id = ?
                    """,
                    (message_id,),
                )
        finally:
            conn.close()

    def get_message_state(self, *, message_id: str) -> dict[str, Any]:
        conn = self._queue_conn()
        try:
            row = conn.execute(
                """
                SELECT
                    message_id,
                    chain_digest,
                    status,
                    delivery_count,
                    last_error,
                    last_delivery_at,
                    acked_at
                FROM delivery_queue
                WHERE message_id = ?
                """,
                (message_id,),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            raise AckRedeliveryError("queue message not found")

        return dict(row)

    def assert_exactly_once_visibility(self, *, chain_digest: str) -> dict[str, Any]:
        state = self._atomic.assert_atomic_state_consistency(chain_digest)
        if state["state"] != "fully_present":
            raise AckRedeliveryError("visible side effect is not fully_present")
        if state["counts"] != {"consumed": 1, "binding": 1, "outcome": 1}:
            raise AckRedeliveryError("visible side effect is not exactly-once 1/1/1")
        return {"ok": True, "state": state["state"], "counts": state["counts"]}

    def _claim_message(self, *, message_id: str, now: int) -> None:
        conn = self._queue_conn()
        try:
            with conn:
                row = conn.execute(
                    """
                    SELECT status, delivery_count
                    FROM delivery_queue
                    WHERE message_id = ?
                    """,
                    (message_id,),
                ).fetchone()
                if row is None:
                    raise AckRedeliveryError("queue message not found")

                if str(row["status"]) == "acked":
                    raise AckRedeliveryError("acked message cannot be delivered again")

                if str(row["status"]) != "queued":
                    raise AckRedeliveryError("only queued message can be claimed")

                conn.execute(
                    """
                    UPDATE delivery_queue
                    SET status = 'inflight',
                        delivery_count = delivery_count + 1,
                        last_delivery_at = ?
                    WHERE message_id = ?
                    """,
                    (now, message_id),
                )
        finally:
            conn.close()

    def _ack_message(self, *, message_id: str, now: int) -> None:
        conn = self._queue_conn()
        try:
            with conn:
                row = conn.execute(
                    "SELECT status FROM delivery_queue WHERE message_id = ?",
                    (message_id,),
                ).fetchone()
                if row is None:
                    raise AckRedeliveryError("queue message not found")
                if str(row["status"]) != "inflight":
                    raise AckRedeliveryError("only inflight message can be acked")
                conn.execute(
                    """
                    UPDATE delivery_queue
                    SET status = 'acked',
                        acked_at = ?
                    WHERE message_id = ?
                    """,
                    (now, message_id),
                )
        finally:
            conn.close()

    def _release_for_redelivery(self, *, message_id: str, last_error: str) -> None:
        conn = self._queue_conn()
        try:
            with conn:
                conn.execute(
                    """
                    UPDATE delivery_queue
                    SET status = 'queued',
                        last_error = ?
                    WHERE message_id = ?
                    """,
                    (last_error, message_id),
                )
        finally:
            conn.close()

    @staticmethod
    def _chain_digest_from_envelope(envelope: DelegationConsumptionEnvelope) -> str:
        from app.security.delegation_consumption import canonical_chain_digest

        return canonical_chain_digest(envelope.signed_chain)
