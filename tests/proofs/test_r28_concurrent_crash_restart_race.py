from __future__ import annotations

from pathlib import Path

import pytest

from app.security.atomic_multi_ledger_commit import (
    AtomicCommitError,
    AtomicLedgerPaths,
)
from app.security.concurrent_crash_restart_race import (
    ConcurrentCrashRestartRaceError,
    ConcurrentCrashRestartRaceHarness,
)
from app.security.concurrent_atomic_commit import ConcurrentCommitAttempt
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
        delegation_id="d-r28-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root-r28",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-r28-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-leaf-r28",
        parent_delegation_id="d-r28-001",
    )

    return [root_to_lead, lead_to_worker]


def _build_shared_context(trust_store: dict[str, bytes], now: int) -> dict[str, object]:
    signed_chain = _build_valid_signed_chain(trust_store, now)
    chain_digest = canonical_chain_digest(signed_chain)
    payload_digest = canonical_payload_digest(
        {
            "path": "src/app.py",
            "content_digest": "race-r28",
        }
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-r28-001",
        task_id="task-r28-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-r28-001",
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
        run_id=f"run-r28-{label}",
        request_id="req-r28-001",
        task_id="task-r28-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        executor_subject="worker-a",
        started_at=now + 20,
    )

    binding_audit_event = new_audit_event_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r28-001",
        task_id="task-r28-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        chain_digest=chain_digest,
        leaf_subject="worker-a",
        created_at=now + 21,
    )

    result_digest = compute_result_digest(
        {
            "status": "ok",
            "bytes_written": 800 if label == "A" else 801,
        }
    )

    outcome = new_execution_outcome_record(
        execution_id=execution.execution_id,
        run_id=execution.run_id,
        request_id="req-r28-001",
        task_id="task-r28-001",
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
        request_id="req-r28-001",
        task_id="task-r28-001",
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


def test_r28_preserves_single_visible_winner_after_race_and_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_006_000
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r28_case_01"))

    harness = ConcurrentCrashRestartRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_race_then_restart_visibility_check(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r28-001",
        expected_task_id="task-r28-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    assert result["ok"] is True
    assert result["visible"]["visible_state"] == "fully_present"
    assert result["visible"]["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}
    assert result["race_summary"]["winning_label"] in {"A", "B"}
    assert result["race_summary"]["losing_label"] in {"A", "B"}


def test_r28_denies_stale_loser_replay_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_006_100
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r28_case_02"))

    harness = ConcurrentCrashRestartRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_race_then_restart_visibility_check(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r28-001",
        expected_task_id="task-r28-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    loser_label = result["race_summary"]["losing_label"]
    loser_attempt = attempt_a if loser_label == "A" else attempt_b

    harness.deny_stale_loser_replay_after_restart(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r28-001",
        expected_task_id="task-r28-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        loser_attempt=loser_attempt,
        now=now + 40,
    )


def test_r28_observer_and_verifier_see_same_winner_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_006_200
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    attempts = {"A": attempt_a, "B": attempt_b}
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r28_case_03"))

    harness = ConcurrentCrashRestartRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_race_then_restart_visibility_check(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r28-001",
        expected_task_id="task-r28-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    winner = attempts[result["race_summary"]["winning_label"]]
    assert result["visible"]["execution_id"] == winner.execution.execution_id
    assert result["verified"]["execution_id"] == winner.execution.execution_id
    assert result["visible"]["final_audit_event_id"] == winner.final_audit_event.audit_event_id
    assert result["verified"]["final_audit_event_id"] == winner.final_audit_event.audit_event_id


def test_r28_detects_tampered_winner_material_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_006_300
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    attempts = {"A": attempt_a, "B": attempt_b}
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r28_case_04"))

    harness = ConcurrentCrashRestartRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_race_then_restart_visibility_check(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r28-001",
        expected_task_id="task-r28-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    winner = attempts[result["race_summary"]["winning_label"]]
    tampered_outcome = new_execution_outcome_record(
        execution_id=winner.execution.execution_id,
        run_id=winner.execution.run_id,
        request_id="req-r28-001",
        task_id="task-r28-001",
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
        harness.detect_tampered_winner_material_after_restart(
            chain_digest=result["race_summary"]["winner_chain_digest"],
            execution=winner.execution,
            binding_audit_event_id=winner.binding_audit_event.audit_event_id,
            outcome=tampered_outcome,
            final_audit_event=winner.final_audit_event,
            leaf_subject="worker-a",
        )


def test_r28_post_commit_visibility_is_deterministic_across_repeated_observations(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_006_400
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r28_case_05"))

    harness = ConcurrentCrashRestartRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_race_then_restart_visibility_check(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r28-001",
        expected_task_id="task-r28-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    deterministic = harness.assert_post_commit_visibility_is_deterministic(
        chain_digest=result["race_summary"]["winner_chain_digest"]
    )

    assert deterministic["ok"] is True
    assert deterministic["visible"]["visible_state"] == "fully_present"
    assert deterministic["visible"]["counts"] == {"consumed": 1, "binding": 1, "outcome": 1}


def test_r28_fails_if_visible_ledgers_disagree_after_restart(
    trust_store: dict[str, bytes],
    tmp_path: Path,
) -> None:
    now = 1_800_006_500
    shared = _build_shared_context(trust_store, now)
    attempt_a = _build_attempt("A", shared["payload_digest"], shared["chain_digest"], now)
    attempt_b = _build_attempt("B", shared["payload_digest"], shared["chain_digest"], now)
    paths = AtomicLedgerPaths(base_dir=str(tmp_path / "r28_case_06"))

    harness = ConcurrentCrashRestartRaceHarness(
        trust_store,
        ledger_paths=paths,
    )

    result = harness.run_race_then_restart_visibility_check(
        shared["envelope"],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-r28-001",
        expected_task_id="task-r28-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=shared["payload_digest"],
        expected_issued_for="orchestrator-control-plane",
        attempt_a=attempt_a,
        attempt_b=attempt_b,
        now=now + 32,
    )

    from sqlite3 import connect

    conn = connect(paths.outcome_db_path)
    try:
        conn.execute(
            """
            UPDATE execution_outcome_seals
            SET execution_id = ?
            WHERE chain_digest = ?
            """,
            ("corrupted-execution-id", result["race_summary"]["winner_chain_digest"]),
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(
        ConcurrentCrashRestartRaceError,
        match="observer detected mismatched execution_id across visible ledgers",
    ):
        harness.observe_winner_visibility_after_restart(
            chain_digest=result["race_summary"]["winner_chain_digest"]
        )
