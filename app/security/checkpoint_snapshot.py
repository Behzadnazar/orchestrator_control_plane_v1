from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.security.atomic_multi_ledger_commit import AtomicLedgerPaths


def _json_canonical(data: Any) -> str:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


@dataclass(frozen=True, slots=True)
class CheckpointSnapshot:
    chain_digest: str
    consumed_row: dict[str, Any]
    binding_row: dict[str, Any]
    outcome_row: dict[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return {
            "chain_digest": self.chain_digest,
            "consumed_row": self.consumed_row,
            "binding_row": self.binding_row,
            "outcome_row": self.outcome_row,
        }


class CheckpointSnapshotError(ValueError):
    pass


class CheckpointSnapshotManager:
    def __init__(self, *, source_paths: AtomicLedgerPaths) -> None:
        self._source_paths = source_paths
        Path(self._source_paths.base_dir).mkdir(parents=True, exist_ok=True)

    def _connect(self, paths: AtomicLedgerPaths) -> sqlite3.Connection:
        conn = sqlite3.connect(paths.coordinator_db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("ATTACH DATABASE ? AS consumed", (paths.consumption_db_path,))
        conn.execute("ATTACH DATABASE ? AS binding", (paths.binding_db_path,))
        conn.execute("ATTACH DATABASE ? AS outcome", (paths.outcome_db_path,))
        return conn

    def create_snapshot(self, *, chain_digest: str, snapshot_path: str) -> CheckpointSnapshot:
        conn = self._connect(self._source_paths)
        try:
            consumed_row = conn.execute(
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
                FROM consumed.delegation_consumptions
                WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()

            binding_row = conn.execute(
                """
                SELECT
                    chain_digest,
                    execution_id,
                    audit_event_id,
                    run_id,
                    request_id,
                    task_id,
                    operation_id,
                    payload_digest,
                    leaf_subject,
                    event_type,
                    bound_at
                FROM binding.execution_audit_bindings
                WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()

            outcome_row = conn.execute(
                """
                SELECT
                    chain_digest,
                    execution_id,
                    binding_audit_event_id,
                    final_audit_event_id,
                    run_id,
                    request_id,
                    task_id,
                    operation_id,
                    payload_digest,
                    leaf_subject,
                    status,
                    result_digest,
                    finished_at,
                    sealed_at,
                    seal_digest
                FROM outcome.execution_outcome_seals
                WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()
        finally:
            conn.close()

        if consumed_row is None or binding_row is None or outcome_row is None:
            raise CheckpointSnapshotError("cannot create checkpoint snapshot from incomplete committed state")

        snapshot = CheckpointSnapshot(
            chain_digest=chain_digest,
            consumed_row=dict(consumed_row),
            binding_row=dict(binding_row),
            outcome_row=dict(outcome_row),
        )
        self._validate_snapshot(snapshot)

        path = Path(snapshot_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_json_canonical(snapshot.to_payload()), encoding="utf-8")
        return snapshot

    def load_snapshot(self, *, snapshot_path: str) -> CheckpointSnapshot:
        payload = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
        snapshot = CheckpointSnapshot(
            chain_digest=str(payload["chain_digest"]),
            consumed_row=dict(payload["consumed_row"]),
            binding_row=dict(payload["binding_row"]),
            outcome_row=dict(payload["outcome_row"]),
        )
        self._validate_snapshot(snapshot)
        return snapshot

    def restore_snapshot(self, *, snapshot_path: str, restore_paths: AtomicLedgerPaths) -> dict[str, Any]:
        snapshot = self.load_snapshot(snapshot_path=snapshot_path)
        Path(restore_paths.base_dir).mkdir(parents=True, exist_ok=True)

        conn = self._connect(restore_paths)
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS consumed.delegation_consumptions (
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
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS binding.execution_audit_bindings (
                        chain_digest TEXT PRIMARY KEY,
                        execution_id TEXT NOT NULL UNIQUE,
                        audit_event_id TEXT NOT NULL UNIQUE,
                        run_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        payload_digest TEXT NOT NULL,
                        leaf_subject TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        bound_at INTEGER NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS outcome.execution_outcome_seals (
                        chain_digest TEXT PRIMARY KEY,
                        execution_id TEXT NOT NULL UNIQUE,
                        binding_audit_event_id TEXT NOT NULL UNIQUE,
                        final_audit_event_id TEXT NOT NULL UNIQUE,
                        run_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        payload_digest TEXT NOT NULL,
                        leaf_subject TEXT NOT NULL,
                        status TEXT NOT NULL,
                        result_digest TEXT NOT NULL,
                        finished_at INTEGER NOT NULL,
                        sealed_at INTEGER NOT NULL,
                        seal_digest TEXT NOT NULL
                    )
                    """
                )

                self._restore_row(
                    conn=conn,
                    schema="consumed",
                    table="delegation_consumptions",
                    primary_key_name="chain_digest",
                    row=snapshot.consumed_row,
                )
                self._restore_row(
                    conn=conn,
                    schema="binding",
                    table="execution_audit_bindings",
                    primary_key_name="chain_digest",
                    row=snapshot.binding_row,
                )
                self._restore_row(
                    conn=conn,
                    schema="outcome",
                    table="execution_outcome_seals",
                    primary_key_name="chain_digest",
                    row=snapshot.outcome_row,
                )
        finally:
            conn.close()

        return self.observe_restored_state(
            restore_paths=restore_paths,
            chain_digest=snapshot.chain_digest,
        )

    def observe_restored_state(self, *, restore_paths: AtomicLedgerPaths, chain_digest: str) -> dict[str, Any]:
        conn = self._connect(restore_paths)
        try:
            consumed_row = conn.execute(
                """
                SELECT * FROM consumed.delegation_consumptions WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()
            binding_row = conn.execute(
                """
                SELECT * FROM binding.execution_audit_bindings WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()
            outcome_row = conn.execute(
                """
                SELECT * FROM outcome.execution_outcome_seals WHERE chain_digest = ?
                """,
                (chain_digest,),
            ).fetchone()
        finally:
            conn.close()

        counts = {
            "consumed": 1 if consumed_row is not None else 0,
            "binding": 1 if binding_row is not None else 0,
            "outcome": 1 if outcome_row is not None else 0,
        }

        if counts == {"consumed": 0, "binding": 0, "outcome": 0}:
            return {
                "ok": True,
                "state": "absent",
                "counts": counts,
            }

        if counts != {"consumed": 1, "binding": 1, "outcome": 1}:
            raise CheckpointSnapshotError("restored checkpoint produced partial state")

        if str(binding_row["execution_id"]) != str(outcome_row["execution_id"]):
            raise CheckpointSnapshotError("restored checkpoint has mismatched execution_id across ledgers")

        if str(binding_row["audit_event_id"]) != str(outcome_row["binding_audit_event_id"]):
            raise CheckpointSnapshotError("restored checkpoint has mismatched binding audit id across ledgers")

        return {
            "ok": True,
            "state": "fully_present",
            "counts": counts,
            "execution_id": str(outcome_row["execution_id"]),
            "binding_audit_event_id": str(outcome_row["binding_audit_event_id"]),
            "final_audit_event_id": str(outcome_row["final_audit_event_id"]),
            "status": str(outcome_row["status"]),
            "result_digest": str(outcome_row["result_digest"]),
            "seal_digest": str(outcome_row["seal_digest"]),
        }

    def verify_restore_determinism(
        self,
        *,
        snapshot_path: str,
        restore_paths: AtomicLedgerPaths,
    ) -> dict[str, Any]:
        first = self.restore_snapshot(
            snapshot_path=snapshot_path,
            restore_paths=restore_paths,
        )
        second = self.restore_snapshot(
            snapshot_path=snapshot_path,
            restore_paths=restore_paths,
        )

        if first != second:
            raise CheckpointSnapshotError("checkpoint restore is not deterministic across repeated restores")

        return {
            "ok": True,
            "state": first["state"],
            "counts": first["counts"],
            "execution_id": first.get("execution_id"),
            "final_audit_event_id": first.get("final_audit_event_id"),
            "result_digest": first.get("result_digest"),
        }

    def _restore_row(
        self,
        *,
        conn: sqlite3.Connection,
        schema: str,
        table: str,
        primary_key_name: str,
        row: dict[str, Any],
    ) -> None:
        existing = conn.execute(
            f"SELECT * FROM {schema}.{table} WHERE {primary_key_name} = ?",
            (row[primary_key_name],),
        ).fetchone()

        if existing is None:
            columns = list(row.keys())
            placeholders = ", ".join("?" for _ in columns)
            column_list = ", ".join(columns)
            conn.execute(
                f"INSERT INTO {schema}.{table} ({column_list}) VALUES ({placeholders})",
                tuple(row[c] for c in columns),
            )
            return

        existing_row = dict(existing)
        if existing_row != row:
            raise CheckpointSnapshotError(
                f"restore target already contains conflicting row in {schema}.{table}"
            )

    def _validate_snapshot(self, snapshot: CheckpointSnapshot) -> None:
        if snapshot.consumed_row["chain_digest"] != snapshot.chain_digest:
            raise CheckpointSnapshotError("snapshot consumed row chain_digest mismatch")

        if snapshot.binding_row["chain_digest"] != snapshot.chain_digest:
            raise CheckpointSnapshotError("snapshot binding row chain_digest mismatch")

        if snapshot.outcome_row["chain_digest"] != snapshot.chain_digest:
            raise CheckpointSnapshotError("snapshot outcome row chain_digest mismatch")

        if str(snapshot.binding_row["execution_id"]) != str(snapshot.outcome_row["execution_id"]):
            raise CheckpointSnapshotError("snapshot has mismatched execution_id across ledgers")

        if str(snapshot.binding_row["audit_event_id"]) != str(snapshot.outcome_row["binding_audit_event_id"]):
            raise CheckpointSnapshotError("snapshot has mismatched binding audit id across ledgers")
