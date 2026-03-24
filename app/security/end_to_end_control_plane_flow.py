from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.security.ack_redelivery_visibility import (
    AckRedeliveryCoordinator,
    QueuePaths,
)
from app.security.append_only_event_log import AppendOnlyEventLogManager
from app.security.atomic_multi_ledger_commit import AtomicLedgerPaths
from app.security.checkpoint_snapshot import CheckpointSnapshotManager
from app.security.delegation_consumption import (
    DelegationConsumptionEnvelope,
    canonical_chain_digest,
)
from app.security.execution_binding import AuditEventRecord, ExecutionRecord
from app.security.external_observer_consistency import ReadOnlyReplicaObserver
from app.security.outcome_sealing import (
    ExecutionOutcomeRecord,
    OutcomeFinalizationAuditRecord,
)


@dataclass(frozen=True, slots=True)
class EndToEndFlowResult:
    chain_digest: str
    message_id: str
    first_delivery: dict[str, Any]
    second_delivery: dict[str, Any] | None
    queue_state: dict[str, Any]
    live_visible: dict[str, Any]
    replayed_log: dict[str, Any]
    restored_state: dict[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return {
            "chain_digest": self.chain_digest,
            "message_id": self.message_id,
            "first_delivery": self.first_delivery,
            "second_delivery": self.second_delivery,
            "queue_state": self.queue_state,
            "live_visible": self.live_visible,
            "replayed_log": self.replayed_log,
            "restored_state": self.restored_state,
        }


class EndToEndControlPlaneFlowError(ValueError):
    pass


class EndToEndControlPlaneFlowHarness:
    def __init__(
        self,
        trust_store: dict[str, bytes],
        *,
        live_ledger_paths: AtomicLedgerPaths,
        queue_paths: QueuePaths,
        restore_ledger_paths: AtomicLedgerPaths,
        event_log_path: str,
        snapshot_path: str,
        max_chain_depth: int = 8,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._trust_store = trust_store
        self._live_ledger_paths = live_ledger_paths
        self._queue_paths = queue_paths
        self._restore_ledger_paths = restore_ledger_paths
        self._event_log_path = event_log_path
        self._snapshot_path = snapshot_path
        self._max_chain_depth = max_chain_depth
        self._clock_skew_seconds = clock_skew_seconds

    def run_flow(
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
        crash_before_ack_first_attempt: bool,
        now: int,
    ) -> dict[str, Any]:
        chain_digest = canonical_chain_digest(envelope.signed_chain)

        redelivery = AckRedeliveryCoordinator(
            self._trust_store,
            ledger_paths=self._live_ledger_paths,
            queue_paths=self._queue_paths,
            max_chain_depth=self._max_chain_depth,
            clock_skew_seconds=self._clock_skew_seconds,
        )
        observer = ReadOnlyReplicaObserver(self._live_ledger_paths)
        checkpoint = CheckpointSnapshotManager(source_paths=self._live_ledger_paths)
        event_log = AppendOnlyEventLogManager(
            ledger_paths=self._live_ledger_paths,
            log_path=self._event_log_path,
        )

        redelivery.enqueue(message_id=message_id, chain_digest=chain_digest)

        first = redelivery.process_delivery(
            message_id=message_id,
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
            ack_after_commit=not crash_before_ack_first_attempt,
            now=now,
        )

        second: dict[str, Any] | None = None
        if crash_before_ack_first_attempt:
            redelivery.requeue_inflight_for_redelivery(message_id=message_id)
            second = redelivery.process_delivery(
                message_id=message_id,
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
                ack_after_commit=True,
                now=now + 10,
            )

        queue_state = redelivery.get_message_state(message_id=message_id)
        live_visible = observer.observe(chain_digest=chain_digest).to_payload()

        event_log.create_log_from_committed_state(chain_digest=chain_digest)
        replayed_log = event_log.replay_and_verify()

        checkpoint.create_snapshot(
            chain_digest=chain_digest,
            snapshot_path=self._snapshot_path,
        )
        restored_state = checkpoint.restore_snapshot(
            snapshot_path=self._snapshot_path,
            restore_paths=self._restore_ledger_paths,
        )

        result = EndToEndFlowResult(
            chain_digest=chain_digest,
            message_id=message_id,
            first_delivery=first,
            second_delivery=second,
            queue_state=queue_state,
            live_visible=live_visible,
            replayed_log=replayed_log,
            restored_state=restored_state,
        )

        self.verify_consistency(
            chain_digest=chain_digest,
            expected_execution_id=execution.execution_id,
            expected_binding_audit_event_id=binding_audit_event.audit_event_id,
            expected_final_audit_event_id=final_audit_event.audit_event_id,
            expected_status=outcome.status,
            expected_result_digest=outcome.result_digest,
        )

        return result.to_payload()

    def verify_consistency(
        self,
        *,
        chain_digest: str,
        expected_execution_id: str,
        expected_binding_audit_event_id: str,
        expected_final_audit_event_id: str,
        expected_status: str,
        expected_result_digest: str,
    ) -> dict[str, Any]:
        live = ReadOnlyReplicaObserver(self._live_ledger_paths).observe(chain_digest=chain_digest).to_payload()

        replayed = AppendOnlyEventLogManager(
            ledger_paths=self._live_ledger_paths,
            log_path=self._event_log_path,
        ).replay_and_verify()

        restored = CheckpointSnapshotManager(
            source_paths=self._live_ledger_paths
        ).observe_restored_state(
            restore_paths=self._restore_ledger_paths,
            chain_digest=chain_digest,
        )

        for view_name, view in {
            "live": live,
            "replayed": replayed,
            "restored": restored,
        }.items():
            if view["execution_id"] != expected_execution_id:
                raise EndToEndControlPlaneFlowError(
                    f"{view_name} execution_id does not match end-to-end flow"
                )
            if view["final_audit_event_id"] != expected_final_audit_event_id:
                raise EndToEndControlPlaneFlowError(
                    f"{view_name} final_audit_event_id does not match end-to-end flow"
                )
            if view["status"] != expected_status:
                raise EndToEndControlPlaneFlowError(
                    f"{view_name} status does not match end-to-end flow"
                )
            if view["result_digest"] != expected_result_digest:
                raise EndToEndControlPlaneFlowError(
                    f"{view_name} result_digest does not match end-to-end flow"
                )

        if live["binding_audit_event_id"] != expected_binding_audit_event_id:
            raise EndToEndControlPlaneFlowError(
                "live binding_audit_event_id does not match end-to-end flow"
            )
        if replayed["binding_audit_event_id"] != expected_binding_audit_event_id:
            raise EndToEndControlPlaneFlowError(
                "replayed binding_audit_event_id does not match end-to-end flow"
            )
        if restored["binding_audit_event_id"] != expected_binding_audit_event_id:
            raise EndToEndControlPlaneFlowError(
                "restored binding_audit_event_id does not match end-to-end flow"
            )

        return {
            "ok": True,
            "chain_digest": chain_digest,
            "execution_id": expected_execution_id,
            "binding_audit_event_id": expected_binding_audit_event_id,
            "final_audit_event_id": expected_final_audit_event_id,
            "status": expected_status,
            "result_digest": expected_result_digest,
        }
