from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.security.atomic_multi_ledger_commit import (
    AtomicCommitError,
    AtomicLedgerPaths,
    AtomicMultiLedgerCommitCoordinator,
    PartialWriteInjectedError,
)
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


def _build_valid_signed_chain(trust_store: dict[str, bytes], now: int) -> list[dict]:
    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-r26-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r26",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-r26-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-leaf-r26",
        parent_delegation_id="d-r26-001",
    )

    return [root_to_lead, lead_to_worker]


def _build_valid_bundle(trust_store: dict[str, bytes], now: int) -> dict[str, object]:
    signed_chain = _build_valid_signed_chain(trust_store, now)
    chain_digest = canonical_chain_digest(signed_chain)

    payload_digest = canonical_payload_digest(
        {
            "path": "src/app.py",
            "content_digest": "atomic-r26",
        }
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r26-001",
        task_id="task-r26-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r26-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r26-001",
        request_id="req-r26-001",
        task_id="task-r26-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding_audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r26-001",
        task_id="task-r26-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest(
        {
            "status": "ok",
            "bytes_written": 512,
        }
    )

    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r26-001",
        task_id="task-r26-001",
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
        request_id="req-r26-001",
        task_id="task-r26-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        status="succeeded",
        result_digest=result_digest,
        created_at=now + 31,
    )

    return {
        "signed_chain": signed_chain,
        "chain_digest": chain_digest,
        "payload_digest": payload_digest,
        "envelope": envelope,
        "execution": execution,
        "binding_audit_event": binding_audit_event,
        "outcome": outcome,
        "final_audit_event": final_audit_event,
    }


def test_r26_allows_atomic_multi_ledger_commit_and_restart_verification(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_004_000
    data = _build_valid_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r26_case_01"))

    before_restart = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    result = before_restart.verify_and_atomic_commit(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r26-001",
        expected_task_id="task-r26-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    counts = before_restart.assert_atomic_state_consistency(result.chain_digest)
    assert counts["ok"] is True
    assert counts["state"] == "fully_present"
    assert counts["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}

    after_restart = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    verified = after_restart.verify_persisted_seal_after_restart(
        chain_digest=result.chain_digest,
        execution=data["execution"],
        binding_audit_event_id=data["binding_audit_event"].audit_event_id,
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        leaf_subject="worker-a",
    )

    assert verified["ok"] is True
    assert verified["status"] == "succeeded"
    assert verified["final_audit_event_id"] == data["final_audit_event"].audit_event_id


def test_r26_rolls_back_everything_on_injected_failure_after_consumption_insert(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_004_100
    data = _build_valid_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r26_case_02"))

    coordinator = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    with pytest.raises(
        PartialWriteInjectedError,
        match="injected failure after consumption insert",
    ):
        coordinator.verify_and_atomic_commit(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r26-001",
            expected_task_id="task-r26-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=data["final_audit_event"],
            now=now + 32,
            fail_stage="after_consumption_insert",
        )

    counts = coordinator.assert_atomic_state_consistency(data["chain_digest"])
    assert counts["ok"] is True
    assert counts["state"] == "absent"
    assert counts["counts"] == {"consumed": 0, "binding": 0, "outcome": 0}


def test_r26_rolls_back_everything_on_injected_failure_after_binding_insert(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_004_200
    data = _build_valid_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r26_case_03"))

    coordinator = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    with pytest.raises(
        PartialWriteInjectedError,
        match="injected failure after binding insert",
    ):
        coordinator.verify_and_atomic_commit(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r26-001",
            expected_task_id="task-r26-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=data["final_audit_event"],
            now=now + 32,
            fail_stage="after_binding_insert",
        )

    counts = coordinator.assert_atomic_state_consistency(data["chain_digest"])
    assert counts["ok"] is True
    assert counts["state"] == "absent"
    assert counts["counts"] == {"consumed": 0, "binding": 0, "outcome": 0}


def test_r26_rolls_back_everything_on_injected_failure_before_commit(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_004_300
    data = _build_valid_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r26_case_04"))

    coordinator = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    with pytest.raises(
        PartialWriteInjectedError,
        match="injected failure before commit",
    ):
        coordinator.verify_and_atomic_commit(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r26-001",
            expected_task_id="task-r26-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=data["final_audit_event"],
            now=now + 32,
            fail_stage="before_commit",
        )

    counts = coordinator.assert_atomic_state_consistency(data["chain_digest"])
    assert counts["ok"] is True
    assert counts["state"] == "absent"
    assert counts["counts"] == {"consumed": 0, "binding": 0, "outcome": 0}


def test_r26_denies_replay_after_successful_atomic_commit_even_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_004_400
    data = _build_valid_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r26_case_05"))

    first = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    first.verify_and_atomic_commit(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r26-001",
        expected_task_id="task-r26-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    second = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    with pytest.raises(
        AtomicCommitError,
        match="atomic multi-ledger commit rejected due to replay or identifier re-use",
    ):
        second.verify_and_atomic_commit(
            data["envelope"],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-r26-001",
            expected_task_id="task-r26-001",
            expected_operation_id="backend.write_file",
            expected_payload_digest=data["payload_digest"],
            expected_issued_for="orchestrator-control-plane",
            execution=data["execution"],
            binding_audit_event=data["binding_audit_event"],
            outcome=data["outcome"],
            final_audit_event=data["final_audit_event"],
            now=now + 33,
        )


def test_r26_detects_tampered_presented_result_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_004_500
    data = _build_valid_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r26_case_06"))

    coordinator = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    result = coordinator.verify_and_atomic_commit(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r26-001",
        expected_task_id="task-r26-001",
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
        request_id="req-r26-001",
        task_id="task-r26-001",
        operation_id="backend.write_file",
        payload_digest=data["payload_digest"],
        executor_subject="worker-a",
        status="succeeded",
        result_digest=compute_result_digest(
            {
                "status": "ok",
                "bytes_written": 999999,
            }
        ),
        finished_at=data["outcome"].finished_at,
    )

    restarted = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    with pytest.raises(
        AtomicCommitError,
        match="persisted outcome seal does not match presented material",
    ):
        restarted.verify_persisted_seal_after_restart(
            chain_digest=result.chain_digest,
            execution=data["execution"],
            binding_audit_event_id=data["binding_audit_event"].audit_event_id,
            outcome=tampered_outcome,
            final_audit_event=data["final_audit_event"],
            leaf_subject="worker-a",
        )


def test_r26_detects_manually_corrupted_partial_state(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_004_600
    data = _build_valid_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r26_case_07"))

    coordinator = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    result = coordinator.verify_and_atomic_commit(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r26-001",
        expected_task_id="task-r26-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    conn = sqlite3.connect(paths.binding_db_path)
    try:
        conn.execute(
            "DELETE FROM execution_audit_bindings WHERE chain_digest = ?",
            (result.chain_digest,),
        )
        conn.commit()
    finally:
        conn.close()

    restarted = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    with pytest.raises(
        AtomicCommitError,
        match="partial multi-ledger state detected across consumed/binding/outcome ledgers",
    ):
        restarted.assert_atomic_state_consistency(result.chain_digest)
