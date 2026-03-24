from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any

from app.security.delegation_chain import DelegationChainVerifier, DelegationError


def _json_canonical(data: Any) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_payload_digest(payload: dict[str, Any]) -> str:
    return _sha256_hex(_json_canonical(payload))


def canonical_chain_digest(signed_chain: list[dict[str, Any]]) -> str:
    return _sha256_hex(_json_canonical({"signed_chain": signed_chain}))


@dataclass(frozen=True, slots=True)
class DelegationConsumptionEnvelope:
    signed_chain: list[dict[str, Any]]
    request_id: str
    task_id: str
    operation_id: str
    payload_digest: str
    nonce: str
    issued_for: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "signed_chain": self.signed_chain,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "operation_id": self.operation_id,
            "payload_digest": self.payload_digest,
            "nonce": self.nonce,
            "issued_for": self.issued_for,
        }


class DelegationConsumptionError(ValueError):
    pass


class ConsumedDelegationLedger:
    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_delegation_chains (
                    chain_digest TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    issued_for TEXT NOT NULL,
                    leaf_subject TEXT NOT NULL,
                    consumed_at INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_consumed_request_nonce
                ON consumed_delegation_chains (request_id, nonce)
                """
            )

    def claim_once(
        self,
        *,
        chain_digest: str,
        request_id: str,
        task_id: str,
        operation_id: str,
        payload_digest: str,
        nonce: str,
        issued_for: str,
        leaf_subject: str,
        consumed_at: int | None = None,
    ) -> None:
        ts = int(time.time()) if consumed_at is None else int(consumed_at)

        try:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO consumed_delegation_chains (
                        chain_digest,
                        request_id,
                        task_id,
                        operation_id,
                        payload_digest,
                        nonce,
                        issued_for,
                        leaf_subject,
                        consumed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        chain_digest,
                        request_id,
                        task_id,
                        operation_id,
                        payload_digest,
                        nonce,
                        issued_for,
                        leaf_subject,
                        ts,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise DelegationConsumptionError(
                "delegation chain already consumed or request/nonce already used"
            ) from exc

    def fetch_by_chain_digest(self, chain_digest: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT
                chain_digest,
                request_id,
                task_id,
                operation_id,
                payload_digest,
                nonce,
                issued_for,
                leaf_subject,
                consumed_at
            FROM consumed_delegation_chains
            WHERE chain_digest = ?
            """,
            (chain_digest,),
        ).fetchone()

        if row is None:
            return None

        return {
            "chain_digest": row["chain_digest"],
            "request_id": row["request_id"],
            "task_id": row["task_id"],
            "operation_id": row["operation_id"],
            "payload_digest": row["payload_digest"],
            "nonce": row["nonce"],
            "issued_for": row["issued_for"],
            "leaf_subject": row["leaf_subject"],
            "consumed_at": row["consumed_at"],
        }


class DelegationConsumptionVerifier:
    def __init__(
        self,
        trust_store: dict[str, bytes],
        *,
        ledger: ConsumedDelegationLedger | None = None,
        max_chain_depth: int = 8,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._chain_verifier = DelegationChainVerifier(
            trust_store,
            max_chain_depth=max_chain_depth,
            clock_skew_seconds=clock_skew_seconds,
        )
        self._ledger = ledger or ConsumedDelegationLedger()

    def verify_and_consume(
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
        now: int | None = None,
    ) -> dict[str, Any]:
        current_time = int(time.time()) if now is None else int(now)

        if envelope.request_id != expected_request_id:
            raise DelegationConsumptionError("request_id binding mismatch")

        if envelope.task_id != expected_task_id:
            raise DelegationConsumptionError("task_id binding mismatch")

        if envelope.operation_id != expected_operation_id:
            raise DelegationConsumptionError("operation_id binding mismatch")

        if envelope.payload_digest != expected_payload_digest:
            raise DelegationConsumptionError("payload_digest binding mismatch")

        if envelope.issued_for != expected_issued_for:
            raise DelegationConsumptionError("issued_for binding mismatch")

        if not envelope.nonce.strip():
            raise DelegationConsumptionError("nonce must be non-empty")

        chain_result = self._chain_verifier.verify_chain(
            envelope.signed_chain,
            expected_leaf_subject=expected_leaf_subject,
            required_scopes=required_scopes,
            now=current_time,
        )

        chain_digest = canonical_chain_digest(envelope.signed_chain)

        self._ledger.claim_once(
            chain_digest=chain_digest,
            request_id=envelope.request_id,
            task_id=envelope.task_id,
            operation_id=envelope.operation_id,
            payload_digest=envelope.payload_digest,
            nonce=envelope.nonce,
            issued_for=envelope.issued_for,
            leaf_subject=expected_leaf_subject,
            consumed_at=current_time,
        )

        return {
            "ok": True,
            "chain_digest": chain_digest,
            "request_id": envelope.request_id,
            "task_id": envelope.task_id,
            "operation_id": envelope.operation_id,
            "payload_digest": envelope.payload_digest,
            "nonce": envelope.nonce,
            "issued_for": envelope.issued_for,
            "leaf_subject": expected_leaf_subject,
            "leaf_scopes": chain_result["leaf_scopes"],
            "chain_depth": chain_result["chain_depth"],
            "consumed_at": current_time,
        }
