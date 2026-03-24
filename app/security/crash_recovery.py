from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.security.delegation_consumption import (
    ConsumedDelegationLedger,
    DelegationConsumptionEnvelope,
    DelegationConsumptionError,
)
from app.security.execution_binding import (
    AuditEventRecord,
    ExecutionAuditBindingLedger,
    ExecutionRecord,
)
from app.security.outcome_sealing import (
    ExecutionOutcomeRecord,
    ExecutionOutcomeSealingVerifier,
    OutcomeFinalizationAuditRecord,
    OutcomeSealingLedger,
)


@dataclass(frozen=True, slots=True)
class PersistentLedgerPaths:
    base_dir: str

    @property
    def consumption_db_path(self) -> str:
        return str(Path(self.base_dir) / "consumed_delegations.db")

    @property
    def binding_db_path(self) -> str:
        return str(Path(self.base_dir) / "execution_audit_bindings.db")

    @property
    def outcome_db_path(self) -> str:
        return str(Path(self.base_dir) / "execution_outcome_seals.db")


@dataclass(frozen=True, slots=True)
class RecoveryVerificationResult:
    ok: bool
    chain_digest: str
    execution_id: str
    binding_audit_event_id: str
    final_audit_event_id: str
    status: str
    result_digest: str
    seal_digest: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "chain_digest": self.chain_digest,
            "execution_id": self.execution_id,
            "binding_audit_event_id": self.binding_audit_event_id,
            "final_audit_event_id": self.final_audit_event_id,
            "status": self.status,
            "result_digest": self.result_digest,
            "seal_digest": self.seal_digest,
        }


class CrashRecoveryError(ValueError):
    pass


class CrashRecoveryVerifier:
    def __init__(
        self,
        trust_store: dict[str, bytes],
        *,
        ledger_paths: PersistentLedgerPaths,
        max_chain_depth: int = 8,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._trust_store = trust_store
        self._ledger_paths = ledger_paths
        self._max_chain_depth = max_chain_depth
        self._clock_skew_seconds = clock_skew_seconds
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        Path(self._ledger_paths.base_dir).mkdir(parents=True, exist_ok=True)

    def _build_verifier(self) -> ExecutionOutcomeSealingVerifier:
        consumption_ledger = ConsumedDelegationLedger(
            db_path=self._ledger_paths.consumption_db_path
        )
        binding_ledger = ExecutionAuditBindingLedger(
            db_path=self._ledger_paths.binding_db_path
        )
        outcome_ledger = OutcomeSealingLedger(
            db_path=self._ledger_paths.outcome_db_path
        )
        return ExecutionOutcomeSealingVerifier(
            self._trust_store,
            consumption_ledger=consumption_ledger,
            binding_ledger=binding_ledger,
            outcome_ledger=outcome_ledger,
            max_chain_depth=self._max_chain_depth,
            clock_skew_seconds=self._clock_skew_seconds,
        )

    def seal_before_crash(
        self,
        envelope: DelegationConsumptionEnvelope,
        *,
        expected_leaf_subject: str,
        required_scopes: list[str],
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_issued_for: str,
        execution: ExecutionRecord,
        binding_audit_event: AuditEventRecord,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        now: int | None = None,
    ) -> dict[str, Any]:
        verifier = self._build_verifier()
        return verifier.verify_bind_and_seal(
            envelope,
            expected_leaf_subject=expected_leaf_subject,
            required_scopes=required_scopes,
            expected_request_id=expected_request_id,
            expected_task_id=expected_task_id,
            expected_operation_id=expected_operation_id,
            expected_payload_digest=expected_payload_digest,
            expected_issued_for=expected_issued_for,
            execution=execution,
            binding_audit_event=binding_audit_event,
            outcome=outcome,
            final_audit_event=final_audit_event,
            now=now,
        )

    def verify_persistent_seal_after_restart(
        self,
        *,
        chain_digest: str,
        execution: ExecutionRecord,
        binding_audit_event_id: str,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        leaf_subject: str,
    ) -> RecoveryVerificationResult:
        verifier = self._build_verifier()
        result = verifier.verify_presented_seal(
            chain_digest=chain_digest,
            execution=execution,
            binding_audit_event_id=binding_audit_event_id,
            outcome=outcome,
            final_audit_event=final_audit_event,
            leaf_subject=leaf_subject,
        )
        return RecoveryVerificationResult(
            ok=True,
            chain_digest=result["chain_digest"],
            execution_id=result["execution_id"],
            binding_audit_event_id=result["binding_audit_event_id"],
            final_audit_event_id=result["final_audit_event_id"],
            status=result["status"],
            result_digest=result["result_digest"],
            seal_digest=result["seal_digest"],
        )

    def deny_replay_after_restart(
        self,
        envelope: DelegationConsumptionEnvelope,
        *,
        expected_leaf_subject: str,
        required_scopes: list[str],
        expected_request_id: str,
        expected_task_id: str,
        expected_operation_id: str,
        expected_payload_digest: str,
        expected_issued_for: str,
        execution: ExecutionRecord,
        binding_audit_event: AuditEventRecord,
        outcome: ExecutionOutcomeRecord,
        final_audit_event: OutcomeFinalizationAuditRecord,
        now: int | None = None,
    ) -> None:
        verifier = self._build_verifier()
        try:
            verifier.verify_bind_and_seal(
                envelope,
                expected_leaf_subject=expected_leaf_subject,
                required_scopes=required_scopes,
                expected_request_id=expected_request_id,
                expected_task_id=expected_task_id,
                expected_operation_id=expected_operation_id,
                expected_payload_digest=expected_payload_digest,
                expected_issued_for=expected_issued_for,
                execution=execution,
                binding_audit_event=binding_audit_event,
                outcome=outcome,
                final_audit_event=final_audit_event,
                now=now,
            )
        except DelegationConsumptionError:
            return
        raise CrashRecoveryError(
            "replay unexpectedly succeeded after restart"
        )

    def assert_persistent_records_exist(
        self,
        *,
        chain_digest: str,
        execution_id: str,
        binding_audit_event_id: str,
        final_audit_event_id: str,
    ) -> dict[str, Any]:
        consumption_ledger = ConsumedDelegationLedger(
            db_path=self._ledger_paths.consumption_db_path
        )
        binding_ledger = ExecutionAuditBindingLedger(
            db_path=self._ledger_paths.binding_db_path
        )
        outcome_ledger = OutcomeSealingLedger(
            db_path=self._ledger_paths.outcome_db_path
        )

        consumed = consumption_ledger.fetch_by_chain_digest(chain_digest)
        if consumed is None:
            raise CrashRecoveryError(
                "persistent consumed delegation record not found after restart"
            )

        bound = binding_ledger.fetch_by_chain_digest(chain_digest)
        if bound is None:
            raise CrashRecoveryError(
                "persistent execution/audit binding record not found after restart"
            )

        sealed = outcome_ledger.fetch_by_chain_digest(chain_digest)
        if sealed is None:
            raise CrashRecoveryError(
                "persistent outcome seal record not found after restart"
            )

        if bound["execution_id"] != execution_id:
            raise CrashRecoveryError("persistent binding execution_id mismatch")

        if bound["audit_event_id"] != binding_audit_event_id:
            raise CrashRecoveryError("persistent binding audit_event_id mismatch")

        if sealed["final_audit_event_id"] != final_audit_event_id:
            raise CrashRecoveryError("persistent final_audit_event_id mismatch")

        return {
            "ok": True,
            "consumed_request_id": consumed["request_id"],
            "bound_execution_id": bound["execution_id"],
            "bound_audit_event_id": bound["audit_event_id"],
            "sealed_final_audit_event_id": sealed["final_audit_event_id"],
            "sealed_status": sealed["status"],
            "sealed_result_digest": sealed["result_digest"],
            "sealed_seal_digest": sealed["seal_digest"],
        }

