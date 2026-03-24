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
    EndToEndControlPlaneFlowHarness,
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
        delegation_id="d-r34-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r34",
        parent_delegation_id=None,
    )
    leaf = build_signed_delegation(
        trust_store,
        delegation_id="d-r34-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1800,
        nonce="n-leaf-r34",
        parent_delegation_id="d-r34-001",
    )
    signed_chain = [root, leaf]
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest({"path": "src/r34.py", "mode": "write"})

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r34-001",
        task_id="task-r34-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r34-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r34-001",
        request_id="req-r34-001",
        task_id="task-r34-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r34-001",
        task_id="task-r34-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest({"status": "ok", "bytes_written": 1400})
    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r34-001",
        task_id="task-r34-001",
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
        request_id="req-r34-001",
        task_id="task-r34-001",
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


def test_r34_runs_full_successful_control_plane_flow(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_012_000
    data = _build_bundle(trust_store, now)

    harness = EndToEndControlPlaneFlowHarness(
        trust_store,
        live_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r34_case_01_live")),
        queue_paths=QueuePaths(base_dir=str(tmp_path / "r34_case_01_queue")),
        restore_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r34_case_01_restore")),
        event_log_path=str(tmp_path / "r34_case_01_artifacts" / "events.jsonl"),
        snapshot_path=str(tmp_path / "r34_case_01_artifacts" / "checkpoint.json"),
    )

    result = harness.run_flow(
        message_id="msg-r34-001",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r34-001",
        expected_task_id="task-r34-001",
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

    assert result["queue_state"]["status"] == "acked"
    assert result["live_visible"]["state"] == "fully_present"
    assert result["replayed_log"]["execution_id"] == data["execution"].execution_id
    assert result["restored_state"]["execution_id"] == data["execution"].execution_id


def test_r34_crash_before_ack_then_redelivery_keeps_exactly_once_flow(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_012_100
    data = _build_bundle(trust_store, now)

    harness = EndToEndControlPlaneFlowHarness(
        trust_store,
        live_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r34_case_02_live")),
        queue_paths=QueuePaths(base_dir=str(tmp_path / "r34_case_02_queue")),
        restore_ledger_paths=AtomicLedgerPaths(base_dir=str(tmp_path / "r34_case_02_restore")),
        event_log_path=str(tmp_path / "r34_case_02_artifacts" / "events.jsonl"),
        snapshot_path=str(tmp_path / "r34_case_02_artifacts" / "checkpoint.json"),
    )

    result = harness.run_flow(
        message_id="msg-r34-002",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r34-001",
        expected_task_id="task-r34-001",
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

    assert result["first_delivery"]["committed_now"] is True
    assert result["second_delivery"]["replayed_existing"] is True
    assert result["queue_state"]["status"] == "acked"
    assert result["live_visible"]["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}


def test_r34_detects_if_live_view_is_corrupted_after_end_to_end_flow(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_012_200
    data = _build_bundle(trust_store, now)

    live_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r34_case_03_live"))
    restore_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r34_case_03_restore"))
    harness = EndToEndControlPlaneFlowHarness(
        trust_store,
        live_ledger_paths=live_paths,
        queue_paths=QueuePaths(base_dir=str(tmp_path / "r34_case_03_queue")),
        restore_ledger_paths=restore_paths,
        event_log_path=str(tmp_path / "r34_case_03_artifacts" / "events.jsonl"),
        snapshot_path=str(tmp_path / "r34_case_03_artifacts" / "checkpoint.json"),
    )

    result = harness.run_flow(
        message_id="msg-r34-003",
        envelope=data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r34-001",
        expected_task_id="task-r34-001",
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

    conn = sqlite3.connect(live_paths.outcome_db_path)
    try:
        conn.execute(
            """
            UPDATE execution_outcome_seals
            SET result_digest = ?
            WHERE chain_digest = ?
            """,
            ("corrupted-result-digest", result["chain_digest"]),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(
        EndToEndControlPlaneFlowError,
        match="live result_digest does not match end-to-end flow",
    ):
        harness.verify_consistency(
            chain_digest=result["chain_digest"],
            expected_execution_id=data["execution"].execution_id,
            expected_binding_audit_event_id=data["binding"].audit_event_id,
            expected_final_audit_event_id=data["final"].audit_event_id,
            expected_status="succeeded",
            expected_result_digest=data["outcome"].result_digest,
        )
