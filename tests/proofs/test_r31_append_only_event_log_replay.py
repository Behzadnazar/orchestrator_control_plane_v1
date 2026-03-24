from __future__ import annotations

from pathlib import Path

import pytest

from app.security.append_only_event_log import (
    AppendOnlyEventLogError,
    AppendOnlyEventLogManager,
)
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


def _commit_bundle(trust_store: dict[str, bytes], paths: AtomicLedgerPaths, now: int) -> dict[str, object]:
    root = build_signed_delegation(
        trust_store,
        delegation_id="d-r31-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r31",
        parent_delegation_id=None,
    )
    leaf = build_signed_delegation(
        trust_store,
        delegation_id="d-r31-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1800,
        nonce="n-leaf-r31",
        parent_delegation_id="d-r31-001",
    )
    signed_chain = [root, leaf]
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest({"path": "src/r31.py", "mode": "write"})

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r31-001",
        task_id="task-r31-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r31-001",
        issued_for="orchestrator-control-plane",
    )

    execution = new_execution_record(
        run_id="run-r31-001",
        request_id="req-r31-001",
        task_id="task-r31-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r31-001",
        task_id="task-r31-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest({"status": "ok", "bytes_written": 1100})
    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r31-001",
        task_id="task-r31-001",
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
        request_id="req-r31-001",
        task_id="task-r31-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        status="succeeded",
        result_digest=result_digest,
        created_at=now + 31,
    )

    coordinator = AtomicMultiLedgerCommitCoordinator(
        trust_store,
        ledger_paths=paths,
    )
    coordinator.verify_and_atomic_commit(
        envelope,
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r31-001",
        expected_task_id="task-r31-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=payload_digest,
        expected_issued_for="orchestrator-control-plane",
        execution=execution,
        binding_audit_event=binding,
        outcome=outcome,
        final_audit_event=final,
        now=now + 32,
    )

    return {
        "chain_digest": chain_digest,
        "execution": execution,
        "binding": binding,
        "outcome": outcome,
        "final": final,
    }


def test_r31_replays_valid_append_only_event_log_correctly(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_009_000
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r31_case_01"))
    data = _commit_bundle(trust_store, paths, now)
    log_path = str(tmp_path / "r31_case_01" / "events.jsonl")

    manager = AppendOnlyEventLogManager(
        ledger_paths=paths,
        log_path=log_path,
    )
    created = manager.create_log_from_committed_state(chain_digest=data["chain_digest"])
    replayed = manager.replay_and_verify()

    assert created["ok"] is True
    assert replayed["ok"] is True
    assert replayed["state"] == "fully_present"
    assert replayed["execution_id"] == data["execution"].execution_id
    assert replayed["final_audit_event_id"] == data["final"].audit_event_id


def test_r31_rejects_tampered_event_payload_hash_mismatch(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_009_100
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r31_case_02"))
    data = _commit_bundle(trust_store, paths, now)
    log_path = Path(tmp_path / "r31_case_02" / "events.jsonl")

    manager = AppendOnlyEventLogManager(
        ledger_paths=paths,
        log_path=str(log_path),
    )
    manager.create_log_from_committed_state(chain_digest=data["chain_digest"])

    import json

    lines = log_path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["payload"]["execution_id"] = "tampered-execution-id"
    lines[1] = json.dumps(second, ensure_ascii=False)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(
        AppendOnlyEventLogError,
        match="event log event_hash verification failed",
    ):
        manager.replay_and_verify()


def test_r31_rejects_reordered_event_sequence(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_009_200
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r31_case_03"))
    data = _commit_bundle(trust_store, paths, now)
    log_path = Path(tmp_path / "r31_case_03" / "events.jsonl")

    manager = AppendOnlyEventLogManager(
        ledger_paths=paths,
        log_path=str(log_path),
    )
    manager.create_log_from_committed_state(chain_digest=data["chain_digest"])

    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(
        AppendOnlyEventLogError,
        match="event log sequence is not contiguous|event log event_type order is invalid|event log prev_hash chain is invalid|event log event_hash verification failed",
    ):
        manager.replay_and_verify()


def test_r31_rejects_truncated_log_missing_terminal_event(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_009_300
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r31_case_04"))
    data = _commit_bundle(trust_store, paths, now)
    log_path = Path(tmp_path / "r31_case_04" / "events.jsonl")

    manager = AppendOnlyEventLogManager(
        ledger_paths=paths,
        log_path=str(log_path),
    )
    manager.create_log_from_committed_state(chain_digest=data["chain_digest"])

    lines = log_path.read_text(encoding="utf-8").splitlines()
    log_path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

    with pytest.raises(
        AppendOnlyEventLogError,
        match="event log is truncated and missing required terminal events",
    ):
        manager.replay_and_verify()
