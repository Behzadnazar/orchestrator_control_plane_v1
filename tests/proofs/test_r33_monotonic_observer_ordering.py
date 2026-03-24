from __future__ import annotations

from pathlib import Path

import pytest

from app.security.atomic_multi_ledger_commit import (
    AtomicLedgerPaths,
    AtomicMultiLedgerCommitCoordinator,
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
from app.security.external_observer_consistency import ObserverSnapshot
from app.security.monotonic_observer_ordering import (
    MonotonicObserverOrderingError,
    MonotonicObserverOrderingManager,
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
        delegation_id="d-r33-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r33",
        parent_delegation_id=None,
    )
    leaf = build_signed_delegation(
        trust_store,
        delegation_id="d-r33-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1800,
        nonce="n-leaf-r33",
        parent_delegation_id="d-r33-001",
    )
    signed_chain = [root, leaf]
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest({"path": "src/r33.py", "mode": "write"})

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r33-001",
        task_id="task-r33-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r33-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r33-001",
        request_id="req-r33-001",
        task_id="task-r33-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r33-001",
        task_id="task-r33-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest({"status": "ok", "bytes_written": 1300})
    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r33-001",
        task_id="task-r33-001",
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
        request_id="req-r33-001",
        task_id="task-r33-001",
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


def _commit(trust_store: dict[str, bytes], paths: AtomicLedgerPaths, data: dict[str, object], now: int) -> None:
    coordinator = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )
    coordinator.verify_and_atomic_commit(
        data["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r33-001",
        expected_task_id="task-r33-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=data["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        execution=data["execution"],
        binding_audit_event=data["binding"],
        outcome=data["outcome"],
        final_audit_event=data["final"],
        now=now + 32,
    )


def test_r33_observer_moves_monotonically_from_absent_to_fully_present(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_011_000
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r33_case_01"))
    data = _build_bundle(trust_store, now)

    # ایجاد دیتابیس‌ها و جدول‌ها بدون commit
    AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    manager = MonotonicObserverOrderingManager(ledger_paths=paths)

    first = manager.observe_and_record(chain_digest=data["chain_digest"])
    assert first["state"] == "absent"

    _commit(trust_store, paths, data, now)

    second = manager.observe_and_record(chain_digest=data["chain_digest"])
    assert second["state"] == "fully_present"
    assert second["execution_id"] == data["execution"].execution_id

    decision = manager.evaluate_operational_decision(chain_digest=data["chain_digest"])
    assert decision["allow_action"] is True


def test_r33_rejects_regression_to_stale_absent_snapshot(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_011_100
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r33_case_02"))
    data = _build_bundle(trust_store, now)

    AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    manager = MonotonicObserverOrderingManager(ledger_paths=paths)
    manager.observe_and_record(chain_digest=data["chain_digest"])
    _commit(trust_store, paths, data, now)
    manager.observe_and_record(chain_digest=data["chain_digest"])

    stale_absent = ObserverSnapshot(
        chain_digest=data["chain_digest"],
        state="absent",
        counts={"consumed": 0, "binding": 0, "outcome": 0},
        execution_id=None,
        binding_audit_event_id=None,
        final_audit_event_id=None,
        status=None,
        result_digest=None,
    )

    with pytest.raises(
        MonotonicObserverOrderingError,
        match="observer state regressed to an older snapshot",
    ):
        manager.record_presented_snapshot(snapshot=stale_absent)


def test_r33_rejects_conflicting_fully_present_snapshot_with_new_identifiers(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_011_200
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r33_case_03"))
    data = _build_bundle(trust_store, now)

    AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    manager = MonotonicObserverOrderingManager(ledger_paths=paths)
    _commit(trust_store, paths, data, now)
    good = manager.observe_and_record(chain_digest=data["chain_digest"])
    assert good["state"] == "fully_present"

    conflicting = ObserverSnapshot(
        chain_digest=data["chain_digest"],
        state="fully_present",
        counts={"consumed": 1, "binding": 1, "outcome": 1},
        execution_id="different-execution-id",
        binding_audit_event_id=good["binding_audit_event_id"],
        final_audit_event_id=good["final_audit_event_id"],
        status=good["status"],
        result_digest=good["result_digest"],
    )

    with pytest.raises(
        MonotonicObserverOrderingError,
        match="observer fully_present snapshot changed execution_id non-monotonically",
    ):
        manager.record_presented_snapshot(snapshot=conflicting)


def test_r33_stale_snapshot_does_not_flip_operational_decision_back_to_deny(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_011_300
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r33_case_04"))
    data = _build_bundle(trust_store, now)

    AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )

    manager = MonotonicObserverOrderingManager(ledger_paths=paths)
    manager.observe_and_record(chain_digest=data["chain_digest"])
    _commit(trust_store, paths, data, now)
    manager.observe_and_record(chain_digest=data["chain_digest"])

    stale_absent = ObserverSnapshot(
        chain_digest=data["chain_digest"],
        state="absent",
        counts={"consumed": 0, "binding": 0, "outcome": 0},
        execution_id=None,
        binding_audit_event_id=None,
        final_audit_event_id=None,
        status=None,
        result_digest=None,
    )

    with pytest.raises(MonotonicObserverOrderingError):
        manager.record_presented_snapshot(snapshot=stale_absent)

    decision = manager.evaluate_operational_decision(chain_digest=data["chain_digest"])
    assert decision["allow_action"] is True
    assert decision["state"] == "fully_present"
