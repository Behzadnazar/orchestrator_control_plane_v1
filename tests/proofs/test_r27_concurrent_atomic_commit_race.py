from __future__ import annotations

from pathlib import Path

import pytest

from app.security.atomic_multi_ledger_commit import (
    AtomicCommitError,
    AtomicLedgerPaths,
)
from app.security.concurrent_atomic_commit import (
    ConcurrentAtomicCommitRaceHarness,
    ConcurrentCommitAttempt,
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
        delegation_id="d-r27-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r27",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-r27-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-leaf-r27",
        parent_delegation_id="d-r27-001",
    )

    return [root_to_lead, lead_to_worker]


def _build_shared_context(trust_store: dict[str, bytes], now: int) -> dict[str, object]:
    signed_chain = _build_valid_signed_chain(trust_store, now)
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest(
        {
            "path": "src/app.py",
            "content_digest": "race-r27",
        }
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r27-001",
        task_id="task-r27-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r27-001",
        issued_for="orchestrator-control-plane",
    )

    return {
        "signed_chain": signed_chain,
        "chain_digest": chain_digest,
        "payload_digest": payload_digest,
        "envelope": envelope,
    }


def _build_attempt(label: str, payload_digest: str, chain_digest: str, now: int) -> ConcurrentCommitAttempt:
    execution = new_execution_record(
        run_id=f"run-r27-{label}",
        request_id="req-r27-001",
        task_id="task-r27-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding_audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r27-001",
        task_id="task-r27-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest(
        {
            "status": "ok",
            "bytes_written": 700 if label == "A" else 701,
        }
    )

    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r27-001",
        task_id="task-r27-001",
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
        request_id="req-r27-001",
        task_id="task-r27-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        status="succeeded",
        result_digest=result_digest,
        created_at=now + 31,
    )

    return ConcurrentCommitAttempt(
        label=label,
        execution=execution,
        binding_audit_event=binding_audit_event,
        outcome=outcome,
        final_audit_event=final_audit_event,
    )


def test_r27_allows_exactly_one_winner_in_same_chain_race(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_005_000
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r27_case_01"))

    harness = ConcurrentAtomicCommitRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    summary = harness.run_same_chain_race(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r27-001",
        expected_task_id="task-r27-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    assert summary.ok is True
    assert summary.state == "fully_present"
    assert summary.counts == {"consumed": 1, "binding": 1, "outcome": 1}
    assert {summary.winning_label, summary.losing_label} == {"A", "B"}


def test_r27_loser_fails_with_deterministic_atomic_commit_denial(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_005_100
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r27_case_02"))

    harness = ConcurrentAtomicCommitRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    summary = harness.run_same_chain_race(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r27-001",
        expected_task_id="task-r27-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    loser = next(r for r in summary.results if r.label == summary.losing_label)
    assert loser.ok is False
    assert loser.error_type == "AtomicCommitError"
    assert loser.error_message == "atomic multi-ledger commit rejected due to replay or identifier re-use"


def test_r27_winner_material_verifies_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_005_200
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    attempts = {"A": attempt_a, "B": attempt_b}
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r27_case_03"))

    harness = ConcurrentAtomicCommitRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    summary = harness.run_same_chain_race(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r27-001",
        expected_task_id="task-r27-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    winner = attempts[summary.winning_label]
    verified = harness.verify_winner_material_after_restart(
        chain_digest=summary.winner_chain_digest,
        execution=winner.execution,
        binding_audit_event_id=winner.binding_audit_event.audit_event_id,
        outcome=winner.outcome,
        final_audit_event=winner.final_audit_event,
        leaf_subject="worker-a",
    )

    assert verified["ok"] is True
    assert verified["execution_id"] == winner.execution.execution_id
    assert verified["final_audit_event_id"] == winner.final_audit_event.audit_event_id


def test_r27_denies_followup_replay_after_race_has_finished(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_005_300
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r27_case_04"))

    harness = ConcurrentAtomicCommitRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    summary = harness.run_same_chain_race(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r27-001",
        expected_task_id="task-r27-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    loser_attempt = attempt_a if summary.losing_label == "A" else attempt_b

    harness.deny_followup_replay_after_race(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r27-001",
        expected_task_id="task-r27-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt=loser_attempt,
        now=now + 40,
    )


def test_r27_detects_tampered_winner_material_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_005_400
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    attempts = {"A": attempt_a, "B": attempt_b}
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r27_case_05"))

    harness = ConcurrentAtomicCommitRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    summary = harness.run_same_chain_race(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r27-001",
        expected_task_id="task-r27-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    winner = attempts[summary.winning_label]
    tampered_outcome = new_execution_outcome_record(
        execution_id=winner.execution.execution_id,
        run_id=winner.execution.run_id,
        request_id="req-r27-001",
        task_id="task-r27-001",
        operation_id="backend.write_file",
        payload_digest=shared["payload_digest"],
        executor_subject="worker-a",
        status="succeeded",
        result_digest=compute_result_digest(
            {
                "status": "ok",
                "bytes_written": 999999,
            }
        ),
        finished_at=winner.outcome.finished_at,
    )

    with pytest.raises(
        AtomicCommitError,
        match="persisted outcome seal does not match presented material",
    ):
        harness.verify_winner_material_after_restart(
            chain_digest=summary.winner_chain_digest,
            execution=winner.execution,
            binding_audit_event_id=winner.binding_audit_event.audit_event_id,
            outcome=tampered_outcome,
            final_audit_event=winner.final_audit_event,
            leaf_subject="worker-a",
        )


def test_r27_fails_if_race_does_not_end_in_one_success_one_failure(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_005_500
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r27_case_06"))

    harness = ConcurrentAtomicCommitRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    summary = harness.run_same_chain_race(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r27-001",
        expected_task_id="task-r27-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    winner_count = sum(1 for r in summary.results if r.ok)
    loser_count = sum(1 for r in summary.results if not r.ok)

    assert winner_count == 1
    assert loser_count == 1
