from __future__ import annotations

import pytest

from app.security.delegation_chain import build_signed_delegation
from app.security.delegation_consumption import (
    ConsumedDelegationLedger,
    DelegationConsumptionEnvelope,
    DelegationConsumptionError,
    canonical_payload_digest,
)
from app.security.execution_binding import (
    ConsumptionExecutionBindingVerifier,
    ExecutionAuditBindingLedger,
    ExecutionBindingError,
    expected_chain_digest_for_envelope,
    new_audit_event_record,
    new_execution_record,
)


@pytest.fixture()
def trust_store() -> dict[str, bytes]:
    return {
        "root-approver": b"root-approver-secret",
        "team-lead": b"team-lead-secret",
        "worker-a": b"worker-a-secret",
    }


def _build_valid_signed_chain(trust_store: dict[str, bytes], now: int) -> list[dict]:
    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-200",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r23",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-201",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-leaf-r23",
        parent_delegation_id="d-200",
    )

    return [root_to_lead, lead_to_worker]


def _build_valid_envelope(trust_store: dict[str, bytes], now: int) -> tuple[DelegationConsumptionEnvelope, str]:
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload_digest = canonical_payload_digest(
        {
            "path": "src/app.py",
            "content_digest": "xyz789",
        }
    )
    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r23-001",
        issued_for="orchestrator-control-plane",
    )
    return envelope, payload_digest


def test_r23_allows_valid_consumption_execution_audit_binding(trust_store: dict[str, bytes]) -> None:
    now = 1_800_001_000
    envelope, payload_digest = _build_valid_envelope(trust_store, now)

    verifier = ConsumptionExecutionBindingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
    )

    execution = new_execution_record(
        run_id="run-r23-001",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=expected_chain_digest_for_envelope(envelope),
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result = verifier.verify_consume_and_bind(
        envelope,
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r23-001",
        expected_task_id="task-r23-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=payload_digest,
        expected_issued_for="orchestrator-control-plane",
        execution=execution,
        audit_event=audit_event,
        now=now + 22,
    )

    assert result["ok"] is True
    assert result["request_id"] == "req-r23-001"
    assert result["task_id"] == "task-r23-001"
    assert result["operation_id"] == "backend.write_file"
    assert result["payload_digest"] == payload_digest
    assert result["leaf_subject"] == "worker-a"
    assert result["execution_id"] == execution.execution_id
    assert result["audit_event_id"] == audit_event.audit_event_id


def test_r23_denies_execution_payload_digest_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_001_100
    envelope, payload_digest = _build_valid_envelope(trust_store, now)

    verifier = ConsumptionExecutionBindingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
    )

    execution = new_execution_record(
        run_id="run-r23-002",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=canonical_payload_digest({"tampered": True}),
        executor_subject="worker-a",
        started_at=now + 20,
    )

    audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=expected_chain_digest_for_envelope(envelope),
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    with pytest.raises(ExecutionBindingError, match="execution payload_digest mismatch"):
        verifier.verify_consume_and_bind(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r23-001",
            expected_task_id="task-r23-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            execution=execution,
            audit_event=audit_event,
            now=now + 22,
        )


def test_r23_denies_execution_executor_subject_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_001_200
    envelope, payload_digest = _build_valid_envelope(trust_store, now)

    verifier = ConsumptionExecutionBindingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
    )

    execution = new_execution_record(
        run_id="run-r23-003",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-b",
        started_at=now + 20,
    )

    audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=expected_chain_digest_for_envelope(envelope),
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    with pytest.raises(ExecutionBindingError, match="execution executor_subject mismatch"):
        verifier.verify_consume_and_bind(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r23-001",
            expected_task_id="task-r23-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            execution=execution,
            audit_event=audit_event,
            now=now + 22,
        )


def test_r23_denies_audit_chain_digest_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_001_300
    envelope, payload_digest = _build_valid_envelope(trust_store, now)

    verifier = ConsumptionExecutionBindingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
    )

    execution = new_execution_record(
        run_id="run-r23-004",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest="wrong-chain-digest",
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    with pytest.raises(ExecutionBindingError, match="audit chain_digest mismatch"):
        verifier.verify_consume_and_bind(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r23-001",
            expected_task_id="task-r23-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            execution=execution,
            audit_event=audit_event,
            now=now + 22,
        )


def test_r23_denies_audit_execution_id_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_001_400
    envelope, payload_digest = _build_valid_envelope(trust_store, now)

    verifier = ConsumptionExecutionBindingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
    )

    execution = new_execution_record(
        run_id="run-r23-005",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    audit_event = new_audit_event_record(
        execution_id="different-execution-id",
        run_id=execution.run_id,
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=expected_chain_digest_for_envelope(envelope),
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    with pytest.raises(ExecutionBindingError, match="audit execution_id mismatch"):
        verifier.verify_consume_and_bind(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r23-001",
            expected_task_id="task-r23-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            execution=execution,
            audit_event=audit_event,
            now=now + 22,
        )


def test_r23_denies_audit_event_type_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_001_500
    envelope, payload_digest = _build_valid_envelope(trust_store, now)

    verifier = ConsumptionExecutionBindingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
    )

    execution = new_execution_record(
        run_id="run-r23-006",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=expected_chain_digest_for_envelope(envelope),
        leaf_subject="worker-a",
        created_at=now + 21,
        event_type="delegation.execution.started",
    )

    with pytest.raises(ExecutionBindingError, match="audit event_type mismatch"):
        verifier.verify_consume_and_bind(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r23-001",
            expected_task_id="task-r23-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            execution=execution,
            audit_event=audit_event,
            now=now + 22,
        )


def test_r23_denies_binding_reuse_after_first_success(trust_store: dict[str, bytes]) -> None:
    now = 1_800_001_600
    envelope, payload_digest = _build_valid_envelope(trust_store, now)

    verifier = ConsumptionExecutionBindingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
    )

    execution = new_execution_record(
        run_id="run-r23-007",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=expected_chain_digest_for_envelope(envelope),
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    verifier.verify_consume_and_bind(
        envelope,
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r23-001",
        expected_task_id="task-r23-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=payload_digest,
        expected_issued_for="orchestrator-control-plane",
        execution=execution,
        audit_event=audit_event,
        now=now + 22,
    )

    with pytest.raises(
        DelegationConsumptionError,
        match="delegation chain already consumed or request/nonce already used",
    ):
        verifier.verify_consume_and_bind(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r23-001",
            expected_task_id="task-r23-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            execution=execution,
            audit_event=audit_event,
            now=now + 23,
        )


def test_r23_denies_non_empty_execution_identifiers_missing(trust_store: dict[str, bytes]) -> None:
    now = 1_800_001_700
    envelope, payload_digest = _build_valid_envelope(trust_store, now)

    verifier = ConsumptionExecutionBindingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
    )

    from app.security.execution_binding import ExecutionRecord

    execution = ExecutionRecord(
        execution_id="   ",
        run_id="run-r23-008",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    audit_event = new_audit_event_record(
        execution_id="irrelevant-for-this-test",
        run_id="run-r23-008",
        request_id="req-r23-001",
        task_id="task-r23-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=expected_chain_digest_for_envelope(envelope),
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    with pytest.raises(ExecutionBindingError, match="execution_id must be non-empty"):
        verifier.verify_consume_and_bind(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r23-001",
            expected_task_id="task-r23-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            execution=execution,
            audit_event=audit_event,
            now=now + 22,
        )
