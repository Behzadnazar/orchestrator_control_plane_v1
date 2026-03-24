from __future__ import annotations

from pathlib import Path

import pytest

from app.security.crash_recovery import (
    CrashRecoveryError,
    CrashRecoveryVerifier,
    PersistentLedgerPaths,
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
    OutcomeSealingError,
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
        delegation_id="d-r25-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r25",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-r25-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-leaf-r25",
        parent_delegation_id="d-r25-001",
    )

    return [root_to_lead, lead_to_worker]


def _build_valid_bundle(trust_store: dict[str, bytes], now: int) -> dict[str, object]:
    signed_chain = _build_valid_signed_chain(trust_store, now)
    chain_digest = canonical_chain_digest(signed_chain)

    payload_digest = canonical_payload_digest(
        {
            "path": "src/app.py",
            "content_digest": "persistent-r25",
        }
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r25-001",
        task_id="task-r25-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r25-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r25-001",
        request_id="req-r25-001",
        task_id="task-r25-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding_audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r25-001",
        task_id="task-r25-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest(
        {
            "status": "ok",
            "bytes_written": 256,
        }
    )

    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r25-001",
        task_id="task-r25-001",
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
        request_id="req-r25-001",
        task_id="task-r25-001",
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


def test_r25_recovers_and_verifies_persistent_seal_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_003_000
    data = _build_valid_bundle(trust_store, now)
    ledger_paths = PersistentLedgerPaths(base_dir=str(tmp_path / "r25_case_01"))

    before_crash = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    seal_result = before_crash.seal_before_crash(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r25-001",
        expected_task_id="task-r25-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    after_restart = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    verified = after_restart.verify_persistent_seal_after_restart(
        chain_digest=seal_result["chain_digest"],
        execution=data["execution"],
        binding_audit_event_id=data["binding_audit_event"].audit_event_id,
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        leaf_subject="worker-a",
    )

    assert verified.ok is True
    assert verified.chain_digest == seal_result["chain_digest"]
    assert verified.execution_id == data["execution"].execution_id
    assert verified.final_audit_event_id == data["final_audit_event"].audit_event_id


def test_r25_denies_replay_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_003_100
    data = _build_valid_bundle(trust_store, now)
    ledger_paths = PersistentLedgerPaths(base_dir=str(tmp_path / "r25_case_02"))

    before_crash = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    before_crash.seal_before_crash(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r25-001",
        expected_task_id="task-r25-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    after_restart = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    after_restart.deny_replay_after_restart(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r25-001",
        expected_task_id="task-r25-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 33,
    )


def test_r25_asserts_persistent_records_exist_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_003_200
    data = _build_valid_bundle(trust_store, now)
    ledger_paths = PersistentLedgerPaths(base_dir=str(tmp_path / "r25_case_03"))

    before_crash = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    seal_result = before_crash.seal_before_crash(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r25-001",
        expected_task_id="task-r25-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    after_restart = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    records = after_restart.assert_persistent_records_exist(
        chain_digest=seal_result["chain_digest"],
        execution_id=data["execution"].execution_id,
        binding_audit_event_id=data["binding_audit_event"].audit_event_id,
        final_audit_event_id=data["final_audit_event"].audit_event_id,
    )

    assert records["ok"] is True
    assert records["bound_execution_id"] == data["execution"].execution_id
    assert records["sealed_final_audit_event_id"] == data["final_audit_event"].audit_event_id
    assert records["sealed_status"] == "succeeded"


def test_r25_detects_tampered_presented_result_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_003_300
    data = _build_valid_bundle(trust_store, now)
    ledger_paths = PersistentLedgerPaths(base_dir=str(tmp_path / "r25_case_04"))

    before_crash = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    seal_result = before_crash.seal_before_crash(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r25-001",
        expected_task_id="task-r25-001",
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
        request_id="req-r25-001",
        task_id="task-r25-001",
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

    after_restart = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    with pytest.raises(
        OutcomeSealingError,
        match="presented execution outcome seal does not match stored seal",
    ):
        after_restart.verify_persistent_seal_after_restart(
            chain_digest=seal_result["chain_digest"],
            execution=data["execution"],
            binding_audit_event_id=data["binding_audit_event"].audit_event_id,
            outcome=tampered_outcome,
            final_audit_event=data["final_audit_event"],
            leaf_subject="worker-a",
        )


def test_r25_detects_missing_persistent_outcome_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_003_400
    data = _build_valid_bundle(trust_store, now)
    ledger_paths = PersistentLedgerPaths(base_dir=str(tmp_path / "r25_case_05"))

    before_crash = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    seal_result = before_crash.seal_before_crash(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r25-001",
        expected_task_id="task-r25-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    outcome_db = Path(ledger_paths.outcome_db_path)
    if outcome_db.exists():
        outcome_db.unlink()

    after_restart = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    with pytest.raises(
        OutcomeSealingError,
        match="sealed outcome not found for chain_digest",
    ):
        after_restart.verify_persistent_seal_after_restart(
            chain_digest=seal_result["chain_digest"],
            execution=data["execution"],
            binding_audit_event_id=data["binding_audit_event"].audit_event_id,
            outcome=data["outcome"],
            final_audit_event=data["final_audit_event"],
            leaf_subject="worker-a",
        )


def test_r25_detects_persistent_binding_execution_id_mismatch(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_003_500
    data = _build_valid_bundle(trust_store, now)
    ledger_paths = PersistentLedgerPaths(base_dir=str(tmp_path / "r25_case_06"))

    before_crash = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    seal_result = before_crash.seal_before_crash(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r25-001",
        expected_task_id="task-r25-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    after_restart = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    with pytest.raises(
        CrashRecoveryError,
        match="persistent binding execution_id mismatch",
    ):
        after_restart.assert_persistent_records_exist(
            chain_digest=seal_result["chain_digest"],
            execution_id="different-execution-id",
            binding_audit_event_id=data["binding_audit_event"].audit_event_id,
            final_audit_event_id=data["final_audit_event"].audit_event_id,
        )


def test_r25_persistent_sqlite_files_are_created(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_003_600
    data = _build_valid_bundle(trust_store, now)
    ledger_paths = PersistentLedgerPaths(base_dir=str(tmp_path / "r25_case_07"))

    verifier = CrashRecoveryVerifier(
        trust_store,
        ledger_paths=ledger_paths,
    )

    verifier.seal_before_crash(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r25-001",
        expected_task_id="task-r25-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    assert Path(ledger_paths.consumption_db_path).exists() is True
    assert Path(ledger_paths.binding_db_path).exists() is True
    assert Path(ledger_paths.outcome_db_path).exists() is True
