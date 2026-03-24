from __future__ import annotations

from pathlib import Path

import pytest

from app.security.atomic_multi_ledger_commit import (
    AtomicLedgerPaths,
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
from app.security.external_observer_consistency import (
    ExternalObserverConsistencyError,
    ExternalObserverConsistencyHarness,
    ReadOnlyReplicaObserver,
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
        delegation_id="d-r29-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r29",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-r29-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-leaf-r29",
        parent_delegation_id="d-r29-001",
    )

    return [root_to_lead, lead_to_worker]


def _build_bundle(trust_store: dict[str, bytes], now: int) -> dict[str, object]:
    signed_chain = _build_valid_signed_chain(trust_store, now)
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest(
        {
            "path": "src/app.py",
            "content_digest": "observer-r29",
        }
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r29-001",
        task_id="task-r29-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r29-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r29-001",
        request_id="req-r29-001",
        task_id="task-r29-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding_audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r29-001",
        task_id="task-r29-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest(
        {
            "status": "ok",
            "bytes_written": 900,
        }
    )

    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r29-001",
        task_id="task-r29-001",
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
        request_id="req-r29-001",
        task_id="task-r29-001",
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


def test_r29_precommit_observer_sees_no_visibility_leak(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_007_000
    data = _build_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r29_case_01"))

    harness = ExternalObserverConsistencyHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_precommit_visibility_probe(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r29-001",
        expected_task_id="task-r29-001",
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
    assert result["precommit_snapshot"]["state"] == "absent"
    assert result["precommit_snapshot"]["counts"] == {"consumed": 0, "binding": 0, "outcome": 0}
    assert result["precommit_snapshot"]["execution_id"] is None


def test_r29_postcommit_observer_sees_only_fully_committed_state(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_007_100
    data = _build_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r29_case_02"))

    harness = ExternalObserverConsistencyHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_precommit_visibility_probe(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r29-001",
        expected_task_id="task-r29-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    assert result["postcommit_snapshot"]["state"] == "fully_present"
    assert result["postcommit_snapshot"]["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}
    assert result["postcommit_snapshot"]["execution_id"] == data["execution"].execution_id
    assert result["postcommit_snapshot"]["final_audit_event_id"] == data["final_audit_event"].audit_event_id


def test_r29_observer_matches_committed_winner_after_commit(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_007_200
    data = _build_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r29_case_03"))

    harness = ExternalObserverConsistencyHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_precommit_visibility_probe(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r29-001",
        expected_task_id="task-r29-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    checked = harness.verify_observer_and_commit_agree(
        chain_digest=result["chain_digest"],
        expected_execution_id=data["execution"].execution_id,
        expected_binding_audit_event_id=data["binding_audit_event"].audit_event_id,
        expected_final_audit_event_id=data["final_audit_event"].audit_event_id,
        expected_status="succeeded",
        expected_result_digest=data["outcome"].result_digest,
    )

    assert checked["ok"] is True
    assert checked["visible"]["execution_id"] == data["execution"].execution_id


def test_r29_readonly_observer_is_deterministic_after_commit(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_007_300
    data = _build_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r29_case_04"))

    harness = ExternalObserverConsistencyHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_precommit_visibility_probe(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r29-001",
        expected_task_id="task-r29-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    deterministic = harness.assert_repeated_readonly_observation_is_deterministic(
        chain_digest=result["chain_digest"]
    )

    assert deterministic["ok"] is True
    assert deterministic["snapshot"]["state"] == "fully_present"
    assert deterministic["snapshot"]["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}


def test_r29_observer_rejects_partially_visible_state_if_storage_is_corrupted(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_007_400
    data = _build_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r29_case_05"))

    harness = ExternalObserverConsistencyHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_precommit_visibility_probe(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r29-001",
        expected_task_id="task-r29-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    import sqlite3

    conn = sqlite3.connect(paths.binding_db_path)
    try:
        conn.execute(
            "DELETE FROM execution_audit_bindings WHERE chain_digest = ?",
            (result["chain_digest"],),
        )
        conn.commit()
    finally:
        conn.close()

    observer = ReadOnlyReplicaObserver(paths)

    with pytest.raises(
        ExternalObserverConsistencyError,
        match="observer detected partial visible state across ledgers",
    ):
        observer.observe(chain_digest=result["chain_digest"])


def test_r29_observer_rejects_cross_ledger_identifier_disagreement(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_007_500
    data = _build_bundle(trust_store, now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r29_case_06"))

    harness = ExternalObserverConsistencyHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_precommit_visibility_probe(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r29-001",
        expected_task_id="task-r29-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )

    import sqlite3

    conn = sqlite3.connect(paths.outcome_db_path)
    try:
        conn.execute(
            """
            UPDATE execution_outcome_seals
            SET execution_id = ?
            WHERE chain_digest = ?
            """,
            ("corrupted-execution-id", result["chain_digest"]),
        )
        conn.commit()
    finally:
        conn.close()

    observer = ReadOnlyReplicaObserver(paths)

    with pytest.raises(
        ExternalObserverConsistencyError,
        match="observer detected mismatched execution_id across visible ledgers",
    ):
        observer.observe(chain_digest=result["chain_digest"])

