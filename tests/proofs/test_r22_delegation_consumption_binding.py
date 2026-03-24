from __future__ import annotations

import pytest

from app.security.delegation_chain import build_signed_delegation
from app.security.delegation_consumption import (
    ConsumedDelegationLedger,
    DelegationConsumptionEnvelope,
    DelegationConsumptionError,
    DelegationConsumptionVerifier,
    canonical_payload_digest,
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
        delegation_id="d-100",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-root",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-101",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-leaf",
        parent_delegation_id="d-100",
    )

    return [root_to_lead, lead_to_worker]


def test_r22_allows_first_valid_consumption(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_100
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload = {
        "path": "src/app.py",
        "content_digest": "abc123",
    }
    payload_digest = canonical_payload_digest(payload)

    verifier = DelegationConsumptionVerifier(
        trust_store,
        ledger=ConsumedDelegationLedger(),
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-001",
        task_id="task-001",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-001",
        issued_for="orchestrator-control-plane",
    )

    result = verifier.verify_and_consume(
        envelope,
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-001",
        expected_task_id="task-001",
        expected_operation_id="backend.write_file",
        expected_payload_digest=payload_digest,
        expected_issued_for="orchestrator-control-plane",
        now=now + 20,
    )

    assert result["ok"] is True
    assert result["request_id"] == "req-001"
    assert result["task_id"] == "task-001"
    assert result["operation_id"] == "backend.write_file"
    assert result["payload_digest"] == payload_digest
    assert result["issued_for"] == "orchestrator-control-plane"
    assert result["leaf_subject"] == "worker-a"
    assert result["chain_depth"] == 2


def test_r22_denies_reuse_of_same_chain_same_envelope(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_200
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload_digest = canonical_payload_digest({"file": "main.py", "mode": "write"})
    ledger = ConsumedDelegationLedger()

    verifier = DelegationConsumptionVerifier(
        trust_store,
        ledger=ledger,
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-010",
        task_id="task-010",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-010",
        issued_for="orchestrator-control-plane",
    )

    verifier.verify_and_consume(
        envelope,
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-010",
        expected_task_id="task-010",
        expected_operation_id="backend.write_file",
        expected_payload_digest=payload_digest,
        expected_issued_for="orchestrator-control-plane",
        now=now + 20,
    )

    with pytest.raises(
        DelegationConsumptionError,
        match="delegation chain already consumed or request/nonce already used",
    ):
        verifier.verify_and_consume(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-010",
            expected_task_id="task-010",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            now=now + 21,
        )


def test_r22_denies_reuse_of_same_chain_for_different_request(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_300
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload_digest = canonical_payload_digest({"target": "a.txt"})
    ledger = ConsumedDelegationLedger()

    verifier = DelegationConsumptionVerifier(
        trust_store,
        ledger=ledger,
    )

    envelope_a = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-020",
        task_id="task-020",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-020",
        issued_for="orchestrator-control-plane",
    )

    verifier.verify_and_consume(
        envelope_a,
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        expected_request_id="req-020",
        expected_task_id="task-020",
        expected_operation_id="backend.write_file",
        expected_payload_digest=payload_digest,
        expected_issued_for="orchestrator-control-plane",
        now=now + 20,
    )

    envelope_b = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-021",
        task_id="task-021",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-021",
        issued_for="orchestrator-control-plane",
    )

    with pytest.raises(
        DelegationConsumptionError,
        match="delegation chain already consumed or request/nonce already used",
    ):
        verifier.verify_and_consume(
            envelope_b,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-021",
            expected_task_id="task-021",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            now=now + 21,
        )


def test_r22_denies_payload_digest_binding_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_400
    signed_chain = _build_valid_signed_chain(trust_store, now)
    real_payload_digest = canonical_payload_digest({"safe": True})
    wrong_payload_digest = canonical_payload_digest({"safe": False})

    verifier = DelegationConsumptionVerifier(
        trust_store,
        ledger=ConsumedDelegationLedger(),
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-030",
        task_id="task-030",
        operation_id="backend.write_file",
        payload_digest=real_payload_digest,
        nonce="consume-030",
        issued_for="orchestrator-control-plane",
    )

    with pytest.raises(DelegationConsumptionError, match="payload_digest binding mismatch"):
        verifier.verify_and_consume(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-030",
            expected_task_id="task-030",
            expected_operation_id="backend.write_file",
            expected_payload_digest=wrong_payload_digest,
            expected_issued_for="orchestrator-control-plane",
            now=now + 20,
        )


def test_r22_denies_operation_binding_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_500
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload_digest = canonical_payload_digest({"mode": "append"})

    verifier = DelegationConsumptionVerifier(
        trust_store,
        ledger=ConsumedDelegationLedger(),
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-040",
        task_id="task-040",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-040",
        issued_for="orchestrator-control-plane",
    )

    with pytest.raises(DelegationConsumptionError, match="operation_id binding mismatch"):
        verifier.verify_and_consume(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-040",
            expected_task_id="task-040",
            expected_operation_id="backend.delete_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            now=now + 20,
        )


def test_r22_denies_request_id_binding_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_600
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload_digest = canonical_payload_digest({"kind": "unit-test"})

    verifier = DelegationConsumptionVerifier(
        trust_store,
        ledger=ConsumedDelegationLedger(),
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-050",
        task_id="task-050",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-050",
        issued_for="orchestrator-control-plane",
    )

    with pytest.raises(DelegationConsumptionError, match="request_id binding mismatch"):
        verifier.verify_and_consume(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-050-other",
            expected_task_id="task-050",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            now=now + 20,
        )


def test_r22_denies_issued_for_binding_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_700
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload_digest = canonical_payload_digest({"actor": "system"})

    verifier = DelegationConsumptionVerifier(
        trust_store,
        ledger=ConsumedDelegationLedger(),
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-060",
        task_id="task-060",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="consume-060",
        issued_for="orchestrator-control-plane",
    )

    with pytest.raises(DelegationConsumptionError, match="issued_for binding mismatch"):
        verifier.verify_and_consume(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-060",
            expected_task_id="task-060",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="another-control-plane",
            now=now + 20,
        )


def test_r22_denies_empty_nonce(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_800
    signed_chain = _build_valid_signed_chain(trust_store, now)
    payload_digest = canonical_payload_digest({"nonce": "required"})

    verifier = DelegationConsumptionVerifier(
        trust_store,
        ledger=ConsumedDelegationLedger(),
    )

    envelope = DelegationConsumptionEnvelope(
        signed_chain=signed_chain,
        request_id="req-070",
        task_id="task-070",
        operation_id="backend.write_file",
        payload_digest=payload_digest,
        nonce="   ",
        issued_for="orchestrator-control-plane",
    )

    with pytest.raises(DelegationConsumptionError, match="nonce must be non-empty"):
        verifier.verify_and_consume(
            envelope,
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            expected_request_id="req-070",
            expected_task_id="task-070",
            expected_operation_id="backend.write_file",
            expected_payload_digest=payload_digest,
            expected_issued_for="orchestrator-control-plane",
            now=now + 20,
        )
