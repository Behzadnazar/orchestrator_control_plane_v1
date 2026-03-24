from __future__ import annotations

from pathlib import Path

import pytest

from app.security.atomic_multi_ledger_commit import (
    AtomicLedgerPaths,
    AtomicMultiLedgerCommitCoordinator,
)
from app.security.checkpoint_snapshot import (
    CheckpointSnapshotError,
    CheckpointSnapshotManager,
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


def _build_bundle(trust_store: dict[str, bytes], now: int) -> dict[str, object]:
    root = build_signed_delegation(
        trust_store,
        delegation_id="d-r30-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r30",
        parent_delegation_id=None,
    )
    leaf = build_signed_delegation(
        trust_store,
        delegation_id="d-r30-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1800,
        nonce="n-leaf-r30",
        parent_delegation_id="d-r30-001",
    )
    signed_chain = [root, leaf]
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest({"path": "src/r30.py", "mode": "write"})

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r30-001",
        task_id="task-r30-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r30-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r30-001",
        request_id="req-r30-001",
        task_id="task-r30-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding_audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r30-001",
        task_id="task-r30-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest({"status": "ok", "bytes_written": 1001})

    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r30-001",
        task_id="task-r30-001",
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
        request_id="req-r30-001",
        task_id="task-r30-001",
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
        "binding_audit_event": binding_audit_event,
        "outcome": outcome,
        "final_audit_event": final_audit_event,
    }


def _commit_source_state(trust_store: dict[str, bytes], source_paths: AtomicLedgerPaths, now: int) -> dict[str, object]:
    data = _build_bundle(trust_store, now)
    coordinator = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=source_paths,
    )
    coordinator.verify_and_atomic_commit(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r30-001",
        expected_task_id="task-r30-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding_audit_event"],
        outcome=data["outcome"],
        final_audit_event=data["final_audit_event"],
        now=now + 32,
    )
    return data


def test_r30_creates_consistent_checkpoint_snapshot_and_restores_it(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_008_000
    source_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r30_source_01"))
    restore_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r30_restore_01"))
    data = _commit_source_state(trust_store, source_paths, now)

    manager = CheckpointSnapshotManager(source_paths=source_paths)
    snapshot_path = str(tmp_path / "r30_case_01" / "checkpoint.json")

    snapshot = manager.create_snapshot(
        chain_digest=data["chain_digest"],
        snapshot_path=snapshot_path,
    )
    restored = manager.restore_snapshot(
        snapshot_path=snapshot_path,
        restore_paths=restore_paths,
    )

    assert snapshot.chain_digest == data["chain_digest"]
    assert restored["ok"] is True
    assert restored["state"] == "fully_present"
    assert restored["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}
    assert restored["execution_id"] == data["execution"].execution_id


def test_r30_restore_is_deterministic_across_repeated_restores(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_008_100
    source_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r30_source_02"))
    restore_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r30_restore_02"))
    data = _commit_source_state(trust_store, source_paths, now)

    manager = CheckpointSnapshotManager(source_paths=source_paths)
    snapshot_path = str(tmp_path / "r30_case_02" / "checkpoint.json")

    manager.create_snapshot(
        chain_digest=data["chain_digest"],
        snapshot_path=snapshot_path,
    )
    deterministic = manager.verify_restore_determinism(
        snapshot_path=snapshot_path,
        restore_paths=restore_paths,
    )

    assert deterministic["ok"] is True
    assert deterministic["state"] == "fully_present"
    assert deterministic["execution_id"] == data["execution"].execution_id


def test_r30_rejects_tampered_snapshot_with_cross_ledger_mismatch(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_008_200
    source_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r30_source_03"))
    restore_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r30_restore_03"))
    data = _commit_source_state(trust_store, source_paths, now)

    manager = CheckpointSnapshotManager(source_paths=source_paths)
    snapshot_path = Path(tmp_path / "r30_case_03" / "checkpoint.json")
    manager.create_snapshot(
        chain_digest=data["chain_digest"],
        snapshot_path=str(snapshot_path),
    )

    import json

    payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    payload["outcome_row"]["execution_id"] = "tampered-execution-id"
    snapshot_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(
        CheckpointSnapshotError,
        match="snapshot has mismatched execution_id across ledgers",
    ):
        manager.restore_snapshot(
            snapshot_path=str(snapshot_path),
            restore_paths=restore_paths,
        )


def test_r30_rejects_restore_target_conflict(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_008_300
    source_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r30_source_04"))
    restore_paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r30_restore_04"))
    data = _commit_source_state(trust_store, source_paths, now)

    manager = CheckpointSnapshotManager(source_paths=source_paths)
    snapshot_path = str(tmp_path / "r30_case_04" / "checkpoint.json")
    manager.create_snapshot(
        chain_digest=data["chain_digest"],
        snapshot_path=snapshot_path,
    )
    manager.restore_snapshot(
        snapshot_path=snapshot_path,
        restore_paths=restore_paths,
    )

    import sqlite3

    conn = sqlite3.connect(restore_paths.outcome_db_path)
    try:
        conn.execute(
            """
            UPDATE execution_outcome_seals
            SET status = ?
            WHERE chain_digest = ?
            """,
            ("failed", data["chain_digest"]),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(
        CheckpointSnapshotError,
        match="restore target already contains conflicting row in outcome.execution_outcome_seals",
    ):
        manager.restore_snapshot(
            snapshot_path=snapshot_path,
            restore_paths=restore_paths,
        )
