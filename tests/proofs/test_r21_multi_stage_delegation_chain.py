from __future__ import annotations

import pytest

from app.security.delegation_chain import (
    DelegationChainVerifier,
    DelegationError,
    build_signed_delegation,
)


@pytest.fixture()
def trust_store() -> dict[str, bytes]:
    return {
        "root-approver": b"root-approver-secret",
        "team-lead": b"team-lead-secret",
        "worker-a": b"worker-a-secret",
        "worker-b": b"worker-b-secret",
    }


def test_r21_allows_valid_multi_stage_delegation_chain(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_000

    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-001",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-001",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-002",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 1200,
        nonce="n-002",
        parent_delegation_id="d-001",
    )

    verifier = DelegationChainVerifier(trust_store)
    result = verifier.verify_chain(
        [root_to_lead, lead_to_worker],
        expected_leaf_subject="worker-a",
        required_scopes=["task.execute"],
        now=now + 30,
    )

    assert result["ok"] is True
    assert result["chain_depth"] == 2
    assert result["leaf_subject"] == "worker-a"
    assert result["leaf_scopes"] == ["task.execute"]


def test_r21_denies_scope_escalation_in_child_delegation(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_000

    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-010",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-010",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-011",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=False,
        issued_at=now + 5,
        expires_at=now + 1800,
        nonce="n-011",
        parent_delegation_id="d-010",
    )

    verifier = DelegationChainVerifier(trust_store)

    with pytest.raises(DelegationError, match="child delegation scopes exceed parent delegation scope"):
        verifier.verify_chain(
            [root_to_lead, lead_to_worker],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            now=now + 30,
        )


def test_r21_denies_redelegation_when_parent_disallows_it(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_000

    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-020",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-020",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-021",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 5,
        expires_at=now + 1800,
        nonce="n-021",
        parent_delegation_id="d-020",
    )

    verifier = DelegationChainVerifier(trust_store)

    with pytest.raises(DelegationError, match="scoped re-delegation denied by parent delegation"):
        verifier.verify_chain(
            [root_to_lead, lead_to_worker],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            now=now + 30,
        )


def test_r21_denies_third_stage_after_redelegation_was_cut_off(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_000

    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-030",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-030",
        parent_delegation_id=None,
    )

    lead_to_worker_a = build_signed_delegation(
        trust_store,
        delegation_id="d-031",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 5,
        expires_at=now + 1800,
        nonce="n-031",
        parent_delegation_id="d-030",
    )

    worker_a_to_worker_b = build_signed_delegation(
        trust_store,
        delegation_id="d-032",
        issuer="worker-a",
        subject="worker-b",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 10,
        expires_at=now + 900,
        nonce="n-032",
        parent_delegation_id="d-031",
    )

    verifier = DelegationChainVerifier(trust_store)

    with pytest.raises(DelegationError, match="scoped re-delegation denied by parent delegation"):
        verifier.verify_chain(
            [root_to_lead, lead_to_worker_a, worker_a_to_worker_b],
            expected_leaf_subject="worker-b",
            required_scopes=["task.execute"],
            now=now + 20,
        )


def test_r21_denies_leaf_subject_mismatch(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_000

    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-040",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-040",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-041",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 5,
        expires_at=now + 1200,
        nonce="n-041",
        parent_delegation_id="d-040",
    )

    verifier = DelegationChainVerifier(trust_store)

    with pytest.raises(DelegationError, match="leaf subject mismatch"):
        verifier.verify_chain(
            [root_to_lead, lead_to_worker],
            expected_leaf_subject="worker-b",
            required_scopes=["task.execute"],
            now=now + 20,
        )


def test_r21_denies_required_scope_not_covered_by_leaf(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_000

    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-050",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute", "artifact.write"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-050",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-051",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 5,
        expires_at=now + 1800,
        nonce="n-051",
        parent_delegation_id="d-050",
    )

    verifier = DelegationChainVerifier(trust_store)

    with pytest.raises(DelegationError, match="required scopes not covered by leaf delegation"):
        verifier.verify_chain(
            [root_to_lead, lead_to_worker],
            expected_leaf_subject="worker-a",
            required_scopes=["artifact.write"],
            now=now + 20,
        )


def test_r21_denies_tampered_signed_record(trust_store: dict[str, bytes]) -> None:
    now = 1_800_000_000

    root_to_lead = build_signed_delegation(
        trust_store,
        delegation_id="d-060",
        issuer="root-approver",
        subject="team-lead",
        scopes=["task.execute"],
        allow_redelegate=True,
        issued_at=now,
        expires_at=now + 3600,
        nonce="n-060",
        parent_delegation_id=None,
    )

    lead_to_worker = build_signed_delegation(
        trust_store,
        delegation_id="d-061",
        issuer="team-lead",
        subject="worker-a",
        scopes=["task.execute"],
        allow_redelegate=False,
        issued_at=now + 5,
        expires_at=now + 1800,
        nonce="n-061",
        parent_delegation_id="d-060",
    )

    lead_to_worker["payload"]["scopes"] = ["artifact.write"]

    verifier = DelegationChainVerifier(trust_store)

    with pytest.raises(DelegationError, match="delegation signature verification failed"):
        verifier.verify_chain(
            [root_to_lead, lead_to_worker],
            expected_leaf_subject="worker-a",
            required_scopes=["task.execute"],
            now=now + 20,
        )
