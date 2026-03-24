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
    ExecutionAuditBindingLedger,
    new_audit_event_record,
    new_execution_record,
)
from app.security.outcome_sealing import (
    ExecutionOutcomeSealingVerifier,
    OutcomeSealingError,
    OutcomeSealingLedger,
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


def _build_valid_signed_chain(trust_store: dict[str, bytes], now: int) -> list[dict]:
    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-r24-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r24",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-r24-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-leaf-r24",
        parent_delegation_id="d-r24-001",
    )

    return [root_to_lead, lead_to_worker]


def _build_valid_bundle(
    trust_store: dict[str, bytes],
    now: int,
) -> dict[str, object]:
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload_digest = canonical_payload_digest(
        {
            "path": "src/app.py",
            "content_digest": "final-r24",
        }
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r24-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r24-001",
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding_audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest="will-be-replaced-by-verifier-check",
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    # chain_digest را از خود chain می‌سازیم
    from app.security.delegation_consumption import canonical_chain_digest

    binding_audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=canonical_chain_digest(signed_chain),
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest(
        {
            "status": "ok",
            "bytes_written": 128,
        }
    )

    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        status="succeeded",
        result_digest=result_digest,
        finished_at=now + 30,
    )

    final_audit_event = new_outcome_finalization_audit_record(
        parent_audit_event_id=binding_audit_event.audit_event_id,
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=canonical_chain_digest(signed_chain),
        leaf_subject="worker-a",
        status="succeeded",
        result_digest=result_digest,
        created_at=now + 31,
    )

    return {
        "signed_chain": signed_chain,
        "payload_digest": payload_digest,
        "envelope": envelope,
        "execution": execution,
        "binding_audit_event": binding_audit_event,
        "outcome": outcome,
        "final_audit_event": final_audit_event,
    }


def test_r24_allows_valid_outcome_sealing_and_presented_verification(
    trust_store: dict[str, bytes],
) -> None:
    now = 1_800_002_000
    data = _build_valid_bundle(trust_store, now)

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    result = verifier.verify_bind_and_seal(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r24-001",
        expected_task_id="task-r24-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    assert result["ok"] is True
    assert result["status"] == "succeeded"
    assert result["operation_id"] == "backend.write_file"
    assert result["leaf_subject"] == "worker-a"
    assert result["result_digest"] == data["outcome"].result_digest

    verified = verifier.verify_presented_seal(
        chain_digest=result["chain_digest"],
        execution=data["execution"],
        binding_audit_event_id=data["binding_audit_event"].audit_event_id,
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        leaf_subject="worker-a",
    )

    assert verified["ok"] is True
    assert verified["status"] == "succeeded"
    assert verified["result_digest"] == data["outcome"].result_digest


def test_r24_denies_outcome_execution_id_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_002_100
    data = _build_valid_bundle(trust_store, now)

    bad_outcome = new_execution_outcome_record(
        execution_id="different-execution-id",
        run_id=data["execution"].run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=data["payload_digest"],
        executor_subject="worker-a",
        status="succeeded",
        result_digest=data["outcome"].result_digest,
        finished_at=now + 30,
    )

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    with pytest.raises(OutcomeSealingError, match="outcome execution_id mismatch"):
        verifier.verify_bind_and_seal(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r24-001",
            expected_task_id="task-r24-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=bad_outcome,
            final_audit_event=data["final_audit_event"],
            now=now + 32,
        )


def test_r24_denies_outcome_executor_subject_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_002_200
    data = _build_valid_bundle(trust_store, now)

    bad_outcome = new_execution_outcome_record(
        execution_id=data["execution"].execution_id,
        run_id=data["execution"].run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=data["payload_digest"],
        executor_subject="worker-b",
        status="succeeded",
        result_digest=data["outcome"].result_digest,
        finished_at=now + 30,
    )

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    with pytest.raises(OutcomeSealingError, match="outcome executor_subject mismatch"):
        verifier.verify_bind_and_seal(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r24-001",
            expected_task_id="task-r24-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=bad_outcome,
            final_audit_event=data["final_audit_event"],
            now=now + 32,
        )


def test_r24_denies_final_audit_parent_binding_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_002_300
    data = _build_valid_bundle(trust_store, now)

    bad_final_audit = new_outcome_finalization_audit_record(
        parent_audit_event_id="wrong-parent-audit-id",
        execution_id=data["execution"].execution_id,
        run_id=data["execution"].run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=data["payload_digest"],
        chain_digest=data["final_audit_event"].chain_digest,
        leaf_subject="worker-a",
        status="succeeded",
        result_digest=data["outcome"].result_digest,
        created_at=now + 31,
    )

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    with pytest.raises(OutcomeSealingError, match="final audit parent_audit_event_id mismatch"):
        verifier.verify_bind_and_seal(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r24-001",
            expected_task_id="task-r24-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=bad_final_audit,
            now=now + 32,
        )


def test_r24_denies_final_audit_chain_digest_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_002_400
    data = _build_valid_bundle(trust_store, now)

    bad_final_audit = new_outcome_finalization_audit_record(
        parent_audit_event_id=data["binding_audit_event"].audit_event_id,
        execution_id=data["execution"].execution_id,
        run_id=data["execution"].run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=data["payload_digest"],
        chain_digest="wrong-chain-digest",
        leaf_subject="worker-a",
        status="succeeded",
        result_digest=data["outcome"].result_digest,
        created_at=now + 31,
    )

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    with pytest.raises(OutcomeSealingError, match="final audit chain_digest mismatch"):
        verifier.verify_bind_and_seal(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r24-001",
            expected_task_id="task-r24-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=bad_final_audit,
            now=now + 32,
        )


def test_r24_denies_final_audit_status_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_002_500
    data = _build_valid_bundle(trust_store, now)

    bad_final_audit = new_outcome_finalization_audit_record(
        parent_audit_event_id=data["binding_audit_event"].audit_event_id,
        execution_id=data["execution"].execution_id,
        run_id=data["execution"].run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=data["payload_digest"],
        chain_digest=data["final_audit_event"].chain_digest,
        leaf_subject="worker-a",
        status="failed",
        result_digest=data["outcome"].result_digest,
        created_at=now + 31,
    )

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    with pytest.raises(OutcomeSealingError, match="final audit status mismatch"):
        verifier.verify_bind_and_seal(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r24-001",
            expected_task_id="task-r24-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=bad_final_audit,
            now=now + 32,
        )


def test_r24_detects_tampered_presented_result_after_success(trust_store: dict[str, bytes]) -> None:
    now = 1_800_002_600
    data = _build_valid_bundle(trust_store, now)

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    result = verifier.verify_bind_and_seal(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r24-001",
        expected_task_id="task-r24-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    tampered_outcome = new_execution_outcome_record(
        execution_id=data["execution"].execution_id,
        run_id=data["execution"].run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=data["payload_digest"],
        executor_subject="worker-a",
        status="succeeded",
        result_digest=compute_result_digest({"status": "ok", "bytes_written": 999999}),
        finished_at=data["outcome"].finished_at,
    )

    with pytest.raises(
        OutcomeSealingError,
        match="presented execution outcome seal does not match stored seal",
    ):
        verifier.verify_presented_seal(
            chain_digest=result["chain_digest"],
            execution=data["execution"],
            binding_audit_event_id=data["binding_audit_event"].audit_event_id,
            outcome=tampered_outcome,
            final_audit_event=data["final_audit_event"],
            leaf_subject="worker-a",
        )


def test_r24_denies_final_audit_event_type_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_002_700
    data = _build_valid_bundle(trust_store, now)

    bad_final_audit = new_outcome_finalization_audit_record(
        parent_audit_event_id=data["binding_audit_event"].audit_event_id,
        execution_id=data["execution"].execution_id,
        run_id=data["execution"].run_id,
        request_id="req-r24-001",
        task_id="task-r24-001",
        operation_id="backend.write_file",
        payload_digest=data["payload_digest"],
        chain_digest=data["final_audit_event"].chain_digest,
        leaf_subject="worker-a",
        status="succeeded",
        result_digest=data["outcome"].result_digest,
        created_at=now + 31,
        event_type="delegation.execution.result",
    )

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    with pytest.raises(OutcomeSealingError, match="final audit event_type mismatch"):
        verifier.verify_bind_and_seal(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r24-001",
            expected_task_id="task-r24-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=bad_final_audit,
            now=now + 32,
        )


def test_r24_denies_reseal_after_first_success(trust_store: dict[str, bytes]) -> None:
    now = 1_800_002_800
    data = _build_valid_bundle(trust_store, now)

    verifier = ExecutionOutcomeSealingVerifier(
        trust_store,
        consumption_ledger=ConsumedDelegationLedger(),
        binding_ledger=ExecutionAuditBindingLedger(),
        outcome_ledger=OutcomeSealingLedger(),
    )

    verifier.verify_bind_and_seal(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r24-001",
        expected_task_id="task-r24-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    with pytest.raises(
        DelegationConsumptionError,
        match="delegation chain already consumed or request/nonce already used",
    ):
        verifier.verify_bind_and_seal(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r24-001",
            expected_task_id="task-r24-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=data["final_audit_event"],
            now=now + 33,
        )
