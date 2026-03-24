from __future__ import annotations

from pathlib import Path

import pytest

from app.security.ack_redelivery_visibility import (
    AckRedeliveryCoordinator,
    AckRedeliveryError,
    QueuePaths,
)
from app.security.atomic_multi_ledger_commit import AtomicLedgerPaths
from app.security.delegation_chain import build_signed_delegation
from app.security.delegation_consumption import (
    DelegationConsumptionEnvelope,
    canonical_chain_digest,
    canonical_payload_digest,
)
from app.security.execution_binding import (
    new_audit_event_record,
    new_execution_record,
)
from app.security.outcome_sealing import (
    compute_result_digest,
    new_execution_outcome_record,
    new_outcome_finalization_audit_record,
)


@pytest.fixture()
def trust_store() -> dict[str, bytes]:
    return {
        "root-approver": b"root-approver-secret",
        "team-lead": b"team-lead-secret",
        "worker-a": b"worker-a-secret",
    }


def _build_bundle(trust_store: dict[str, bytes], now: int) -> dict[str, object]:
    root = build_signed_delegation(
        trust_store,
        delegation_id="d-r32-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r32",
        parent_delegation_id=None,
    )
    leaf = build_signed_delegation(
        trust_store,
        delegation_id="d-r32-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1800,
        nonce="n-leaf-r32",
        parent_delegation_id="d-r32-001",
    )
    signed_chain = [root, leaf]
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest({"path": "src/r32.py", "mode": "write"})

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r32-001",
        task_id="task-r32-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r32-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r32-001",
        request_id="req-r32-001",
        task_id="task-r32-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r32-001",
        task_id="task-r32-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest({"status": "ok", "bytes_written": 1200})
    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r32-001",
        task_id="task-r32-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        status="succeeded",
        result_digest=result_digest,
        finished_at=now + 30,
    )

    final = new_outcome_finalization_audit_record(
        parent_audit_event_id=binding.audit_event_id,
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r32-001",
        task_id="task-r32-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        status="succeeded",
        result_digest=result_digest,
        created_at=now + 31,
    )

    return {
        "chain_digest": chain_digest,
        "payload_digest": payload_digest,
        "envelope": envelope,
        "execution": execution,
        "binding": binding,
        "outcome": outcome,
        "final": final,
    }


def test_r32_successful_delivery_acks_once_and_produces_single_visible_effect(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_010_000
    data = _build_bundle(trust_store, now)
    ledger_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r32_case_01_ledgers"))
    queue_paths = QueuePaths(base_dir=str(tmp_path / "r32_case_01_queue"))

    coordinator = AckRedeliveryCoordinator(
        trust_store,
        ledger_paths=ledger_paths,
        queue_paths=queue_paths,
    )
    coordinator.enqueue(message_id="msg-r32-001", chain_digest=data["chain_digest"])

    result = coordinator.process_delivery(
        message_id="msg-r32-001",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r32-001",
        expected_task_id="task-r32-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        ack_after_commit=True,
        now=now + 32,
    )

    state = coordinator.get_message_state(message_id="msg-r32-001")
    visible = coordinator.assert_exactly_once_visibility(chain_digest=data["chain_digest"])

    assert result["ok"] is True
    assert result["committed_now"] is True
    assert state["status"] == "acked"
    assert visible["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}


def test_r32_redelivery_after_crash_before_ack_does_not_duplicate_visible_effect(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_010_100
    data = _build_bundle(trust_store, now)
    ledger_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r32_case_02_ledgers"))
    queue_paths = QueuePaths(base_dir=str(tmp_path / "r32_case_02_queue"))

    coordinator = AckRedeliveryCoordinator(
        trust_store,
        ledger_paths=ledger_paths,
        queue_paths=queue_paths,
    )
    coordinator.enqueue(message_id="msg-r32-002", chain_digest=data["chain_digest"])

    first = coordinator.process_delivery(
        message_id="msg-r32-002",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r32-001",
        expected_task_id="task-r32-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        ack_after_commit=False,
        now=now + 32,
    )

    state_after_crash = coordinator.get_message_state(message_id="msg-r32-002")
    assert first["committed_now"] is True
    assert state_after_crash["status"] == "inflight"

    coordinator.requeue_inflight_for_redelivery(message_id="msg-r32-002")

    second = coordinator.process_delivery(
        message_id="msg-r32-002",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r32-001",
        expected_task_id="task-r32-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        ack_after_commit=True,
        now=now + 40,
    )

    final_state = coordinator.get_message_state(message_id="msg-r32-002")
    visible = coordinator.assert_exactly_once_visibility(chain_digest=data["chain_digest"])

    assert second["replayed_existing"] is True
    assert final_state["status"] == "acked"
    assert visible["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}


def test_r32_multiple_redeliveries_keep_exactly_once_visibility(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_010_200
    data = _build_bundle(trust_store, now)
    ledger_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r32_case_03_ledgers"))
    queue_paths = QueuePaths(base_dir=str(tmp_path / "r32_case_03_queue"))

    coordinator = AckRedeliveryCoordinator(
        trust_store,
        ledger_paths=ledger_paths,
        queue_paths=queue_paths,
    )
    coordinator.enqueue(message_id="msg-r32-003", chain_digest=data["chain_digest"])

    coordinator.process_delivery(
        message_id="msg-r32-003",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r32-001",
        expected_task_id="task-r32-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        ack_after_commit=False,
        now=now + 32,
    )

    coordinator.requeue_inflight_for_redelivery(message_id="msg-r32-003")
    coordinator.process_delivery(
        message_id="msg-r32-003",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r32-001",
        expected_task_id="task-r32-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        ack_after_commit=False,
        now=now + 40,
    )

    coordinator.requeue_inflight_for_redelivery(message_id="msg-r32-003")
    third = coordinator.process_delivery(
        message_id="msg-r32-003",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r32-001",
        expected_task_id="task-r32-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        ack_after_commit=True,
        now=now + 50,
    )

    state = coordinator.get_message_state(message_id="msg-r32-003")
    visible = coordinator.assert_exactly_once_visibility(chain_digest=data["chain_digest"])

    assert third["replayed_existing"] is True
    assert state["status"] == "acked"
    assert state["delivery_count"] == 3
    assert visible["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}


def test_r32_acked_message_cannot_be_delivered_again(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_010_300
    data = _build_bundle(trust_store, now)
    ledger_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r32_case_04_ledgers"))
    queue_paths = QueuePaths(base_dir=str(tmp_path / "r32_case_04_queue"))

    coordinator = AckRedeliveryCoordinator(
        trust_store,
        ledger_paths=ledger_paths,
        queue_paths=queue_paths,
    )
    coordinator.enqueue(message_id="msg-r32-004", chain_digest=data["chain_digest"])

    coordinator.process_delivery(
        message_id="msg-r32-004",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r32-001",
        expected_task_id="task-r32-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        ack_after_commit=True,
        now=now + 32,
    )

    with pytest.raises(
        AckRedeliveryError,
        match="acked message cannot be delivered again",
    ):
        coordinator.process_delivery(
            message_id="msg-r32-004",
            envelope=data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r32-001",
            expected_task_id="task-r32-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding"],
            outcome=data["outcome"],
            final_audit_event=data["final"],
            ack_after_commit=True,
            now=now + 40,
        )
