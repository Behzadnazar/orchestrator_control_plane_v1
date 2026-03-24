from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.security.ack_redelivery_visibility import QueuePaths
from app.security.atomic_multi_ledger_commit import AtomicLedgerPaths
from app.security.end_to_end_control_plane_flow import (
    EndToEndControlPlaneFlowError,
    EndToEndControlPlaneFlowHarness,
)
from app.security.monotonic_observer_ordering import (
    MonotonicObserverOrderingError,
    MonotonicObserverOrderingManager,
)
from app.security.delegation_consumption import DelegationConsumptionEnvelope
from app.security.execution_binding import AuditEventRecord, ExecutionRecord
from app.security.outcome_sealing import (
    ExecutionOutcomeRecord,
    OutcomeFinalizationAuditRecord,
)
from app.security.external_observer_consistency import ObserverSnapshot


@dataclass(frozen=True, slots=True)
class ReleaseGateResult:
    chain_digest: str
    gate_passed: bool
    monotonic_decision: dict[str, Any]
    live_visible: dict[str, Any]
    replayed_log: dict[str, Any]
    restored_state: dict[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return {
            "chain_digest": self.chain_digest,
            "gate_passed": self.gate_passed,
            "monotonic_decision": self.monotonic_decision,
            "live_visible": self.live_visible,
            "replayed_log": self.replayed_log,
            "restored_state": self.restored_state,
        }


class ReleaseGateError(ValueError):
    pass


class ReleaseGateHarness:
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
        self._flow = EndToEndControlPlaneFlowHarness(
            trust_store,
            live_ledger_paths=live_ledger_paths,
            queue_paths=queue_paths,
            restore_ledger_paths=restore_ledger_paths,
            event_log_path=event_log_path,
            snapshot_path=snapshot_path,
            max_chain_depth=max_chain_depth,
            clock_skew_seconds=clock_skew_seconds,
        )
        self._monotonic = MonotonicObserverOrderingManager(
            ledger_paths=live_ledger_paths
        )

    def run_release_gate(
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
        result = self._flow.run_flow(
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
            crash_before_ack_first_attempt=crash_before_ack_first_attempt,
            now=now,
        )

        chain_digest = result["chain_digest"]
        first_observation = self._monotonic.observe_and_record(chain_digest=chain_digest)
        second_observation = self._monotonic.observe_and_record(chain_digest=chain_digest)
        decision = self._monotonic.evaluate_operational_decision(chain_digest=chain_digest)

        if first_observation != second_observation:
            raise ReleaseGateError(
                "release gate failed because repeated observer snapshots were not identical"
            )

        if decision["allow_action"] is not True:
            raise ReleaseGateError(
                "release gate failed because operational decision is not allow"
            )

        self._assert_views_agree(
            live_visible=result["live_visible"],
            replayed_log=result["replayed_log"],
            restored_state=result["restored_state"],
        )

        gate = ReleaseGateResult(
            chain_digest=chain_digest,
            gate_passed=True,
            monotonic_decision=decision,
            live_visible=result["live_visible"],
            replayed_log=result["replayed_log"],
            restored_state=result["restored_state"],
        )
        return gate.to_payload()

    def submit_stale_snapshot(
        self,
        *,
        snapshot: ObserverSnapshot,
    ) -> None:
        self._monotonic.record_presented_snapshot(snapshot=snapshot)

    def verify_release_state(
        self,
        *,
        chain_digest: str,
        expected_execution_id: str,
        expected_binding_audit_event_id: str,
        expected_final_audit_event_id: str,
        expected_status: str,
        expected_result_digest: str,
    ) -> dict[str, Any]:
        self._flow.verify_consistency(
            chain_digest=chain_digest,
            expected_execution_id=expected_execution_id,
            expected_binding_audit_event_id=expected_binding_audit_event_id,
            expected_final_audit_event_id=expected_final_audit_event_id,
            expected_status=expected_status,
            expected_result_digest=expected_result_digest,
        )
        decision = self._monotonic.evaluate_operational_decision(chain_digest=chain_digest)
        if decision["allow_action"] is not True:
            raise ReleaseGateError(
                "release verification failed because monotonic decision denied action"
            )
        return {
            "ok": True,
            "chain_digest": chain_digest,
            "decision": decision,
        }

    def _assert_views_agree(
        self,
        *,
        live_visible: dict[str, Any],
        replayed_log: dict[str, Any],
        restored_state: dict[str, Any],
    ) -> None:
        for field in [
            "execution_id",
            "binding_audit_event_id",
            "final_audit_event_id",
            "status",
            "result_digest",
        ]:
            values = {
                live_visible[field],
                replayed_log[field],
                restored_state[field],
            }
            if len(values) != 1:
                raise ReleaseGateError(
                    f"release gate found disagreement across views for field={field}"
                )
