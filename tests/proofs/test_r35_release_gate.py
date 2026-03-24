from __future__ import annotations

from pathlib import Path

import pytest

from app.security.ack_redelivery_visibility import QueuePaths
from app.security.atomic_multi_ledger_commit import AtomicLedgerPaths
from app.security.delegation_chain import build_signed_delegation
from app.security.delegation_consumption import (
    DelegationConsumptionEnvelope,
    canonical_chain_digest,
    canonical_payload_digest,
)
from app.security.end_to_end_control_plane_flow import (
    EndToEndControlPlaneFlowError,
)
from app.security.execution_binding import (
    new_audit_event_record,
    new_execution_record,
)
from app.security.external_observer_consistency import ObserverSnapshot
from app.security.monotonic_observer_ordering import (
    MonotonicObserverOrderingError,
)
from app.security.outcome_sealing import (
    compute_result_digest,
    new_execution_outcome_record,
    new_outcome_finalization_audit_record,
)
from app.security.release_gate import (
    ReleaseGateHarness,
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
        delegation_id="d-r35-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r35",
        parent_delegation_id=None,
    )
    leaf = build_signed_delegation(
        trust_store,
        delegation_id="d-r35-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1800,
        nonce="n-leaf-r35",
        parent_delegation_id="d-r35-001",
    )
    signed_chain = [root, leaf]
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest({"path": "src/r35.py", "mode": "write"})

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r35-001",
        task_id="task-r35-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r35-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r35-001",
        request_id="req-r35-001",
        task_id="task-r35-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r35-001",
        task_id="task-r35-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest({"status": "ok", "bytes_written": 1500})
    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r35-001",
        task_id="task-r35-001",
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
        request_id="req-r35-001",
        task_id="task-r35-001",
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


def test_r35_release_gate_passes_on_clean_end_to_end_flow(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_013_000
    data = _build_bundle(trust_store, now)

    gate = ReleaseGateHarness(
        trust_store,
        live_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r35_case_01_live")),
        queue_paths=QueuePaths(base_dir=str(tmp_path / "r35_case_01_queue")),
        restore_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r35_case_01_restore")),
        event_log_path=str(tmp_path / "r35_case_01_artifacts" / "events.jsonl"),
        snapshot_path=str(tmp_path / "r35_case_01_artifacts" / "checkpoint.json"),
    )

    result = gate.run_release_gate(
        message_id="msg-r35-001",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r35-001",
        expected_task_id="task-r35-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        crash_before_ack_first_attempt=False,
        now=now + 32,
    )

    assert result["gate_passed"] is True
    assert result["monotonic_decision"]["allow_action"] is True
    assert result["live_visible"]["execution_id"] == data["execution"].execution_id


def test_r35_release_gate_passes_even_after_redelivery_recovery_flow(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_013_100
    data = _build_bundle(trust_store, now)

    gate = ReleaseGateHarness(
        trust_store,
        live_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r35_case_02_live")),
        queue_paths=QueuePaths(base_dir=str(tmp_path / "r35_case_02_queue")),
        restore_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r35_case_02_restore")),
        event_log_path=str(tmp_path / "r35_case_02_artifacts" / "events.jsonl"),
        snapshot_path=str(tmp_path / "r35_case_02_artifacts" / "checkpoint.json"),
    )

    result = gate.run_release_gate(
        message_id="msg-r35-002",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r35-001",
        expected_task_id="task-r35-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        crash_before_ack_first_attempt=True,
        now=now + 32,
    )

    assert result["gate_passed"] is True
    assert result["monotonic_decision"]["allow_action"] is True
    assert result["replayed_log"]["execution_id"] == data["execution"].execution_id


def test_r35_rejects_stale_regression_snapshot_after_gate_has_passed(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_013_200
    data = _build_bundle(trust_store, now)

    gate = ReleaseGateHarness(
        trust_store,
        live_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r35_case_03_live")),
        queue_paths=QueuePaths(base_dir=str(tmp_path / "r35_case_03_queue")),
        restore_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r35_case_03_restore")),
        event_log_path=str(tmp_path / "r35_case_03_artifacts" / "events.jsonl"),
        snapshot_path=str(tmp_path / "r35_case_03_artifacts" / "checkpoint.json"),
    )

    result = gate.run_release_gate(
        message_id="msg-r35-003",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r35-001",
        expected_task_id="task-r35-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        crash_before_ack_first_attempt=False,
        now=now + 32,
    )

    stale_absent = ObserverSnapshot(
        chain_digest=result["chain_digest"],
        state="absent",
        counts={"consumed": 0, "binding": 0, "outcome": 0},
        execution_id=None,
        binding_audit_event_id=None,
        final_audit_event_id=None,
        status=None,
        result_digest=None,
    )

    with pytest.raises(MonotonicObserverOrderingError):
        gate.submit_stale_snapshot(snapshot=stale_absent)


def test_r35_detects_restore_side_corruption_during_release_verification(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_013_300
    data = _build_bundle(trust_store, now)

    live_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r35_case_04_live"))
    restore_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r35_case_04_restore"))

    gate = ReleaseGateHarness(
        trust_store,
        live_ledger_paths=live_paths,
        queue_paths=QueuePaths(base_dir=str(tmp_path / "r35_case_04_queue")),
        restore_ledger_paths=restore_paths,
        event_log_path=str(tmp_path / "r35_case_04_artifacts" / "events.jsonl"),
        snapshot_path=str(tmp_path / "r35_case_04_artifacts" / "checkpoint.json"),
    )

    result = gate.run_release_gate(
        message_id="msg-r35-004",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r35-001",
        expected_task_id="task-r35-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        crash_before_ack_first_attempt=False,
        now=now + 32,
    )

    import sqlite3

    conn = sqlite3.connect(restore_paths.outcome_db_path)
    try:
        conn.execute(
            """
            UPDATE execution_outcome_seals
            SET result_digest = ?
            WHERE chain_digest = ?
            """,
            ("restore-corrupted-result", result["chain_digest"]),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(
        EndToEndControlPlaneFlowError,
        match="restored result_digest does not match end-to-end flow",
    ):
        gate.verify_release_state(
            chain_digest=result["chain_digest"],
            expected_execution_id=data["execution"].execution_id,
            expected_binding_audit_event_id=data["binding"].audit_event_id,
            expected_final_audit_event_id=data["final"].audit_event_id,
            expected_status="succeeded",
            expected_result_digest=data["outcome"].result_digest,
        )
