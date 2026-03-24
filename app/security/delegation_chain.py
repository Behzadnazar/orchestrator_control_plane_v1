from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _json_canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _scope_is_subset(child_scopes: list[str], parent_scopes: list[str]) -> bool:
    parent = set(parent_scopes)
    child = set(child_scopes)
    return child.issubset(parent)


def _normalize_chain(chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in chain:
        normalized.append(
            {
                "delegation_id": str(item["delegation_id"]),
                "issuer": str(item["issuer"]),
                "subject": str(item["subject"]),
                "scopes": sorted(str(x) for x in item["scopes"]),
                "allow_redelegate": bool(item["allow_redelegate"]),
                "issued_at": int(item["issued_at"]),
                "expires_at": int(item["expires_at"]),
                "nonce": str(item["nonce"]),
                "parent_delegation_id": item.get("parent_delegation_id"),
            }
        )
    return normalized


@dataclass(frozen=True, slots=True)
class DelegationRecord:
    delegation_id: str
    issuer: str
    subject: str
    scopes: list[str]
    allow_redelegate: bool
    issued_at: int
    expires_at: int
    nonce: str
    parent_delegation_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "delegation_id": self.delegation_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "scopes": sorted(self.scopes),
            "allow_redelegate": self.allow_redelegate,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "parent_delegation_id": self.parent_delegation_id,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "DelegationRecord":
        return cls(
            delegation_id=str(payload["delegation_id"]),
            issuer=str(payload["issuer"]),
            subject=str(payload["subject"]),
            scopes=[str(x) for x in payload["scopes"]],
            allow_redelegate=bool(payload["allow_redelegate"]),
            issued_at=int(payload["issued_at"]),
            expires_at=int(payload["expires_at"]),
            nonce=str(payload["nonce"]),
            parent_delegation_id=payload.get("parent_delegation_id"),
        )


class DelegationError(ValueError):
    pass


class DelegationSigner:
    def __init__(self, trust_store: dict[str, bytes]) -> None:
        self._trust_store = trust_store

    def sign_record(self, record: DelegationRecord) -> dict[str, Any]:
        key = self._trust_store.get(record.issuer)
        if not key:
            raise DelegationError(f"missing signing key for issuer={record.issuer}")

        payload = record.to_payload()
        payload_bytes = _json_canonical(payload)
        sig = hmac.new(key, payload_bytes, hashlib.sha256).digest()

        return {
            "payload": payload,
            "signature": _b64e(sig),
            "alg": "HS256",
            "kid": record.issuer,
        }

    def verify_signed_record(self, signed_record: dict[str, Any]) -> DelegationRecord:
        kid = str(signed_record["kid"])
        if str(signed_record["alg"]) != "HS256":
            raise DelegationError("unsupported delegation signature algorithm")

        key = self._trust_store.get(kid)
        if not key:
            raise DelegationError(f"missing verification key for kid={kid}")

        payload = signed_record["payload"]
        payload_bytes = _json_canonical(payload)
        expected_sig = hmac.new(key, payload_bytes, hashlib.sha256).digest()
        supplied_sig = _b64d(str(signed_record["signature"]))

        if not hmac.compare_digest(expected_sig, supplied_sig):
            raise DelegationError("delegation signature verification failed")

        record = DelegationRecord.from_payload(payload)
        if record.issuer != kid:
            raise DelegationError("delegation kid/issuer mismatch")

        return record


class DelegationChainVerifier:
    def __init__(
        self,
        trust_store: dict[str, bytes],
        *,
        max_chain_depth: int = 8,
        clock_skew_seconds: int = 30,
    ) -> None:
        self._signer = DelegationSigner(trust_store)
        self._max_chain_depth = max_chain_depth
        self._clock_skew_seconds = clock_skew_seconds

    def verify_chain(
        self,
        signed_chain: list[dict[str, Any]],
        *,
        expected_leaf_subject: str,
        required_scopes: list[str],
        now: int | None = None,
    ) -> dict[str, Any]:
        if not signed_chain:
            raise DelegationError("delegation chain is empty")

        if len(signed_chain) > self._max_chain_depth:
            raise DelegationError("delegation chain exceeds maximum depth")

        current_time = int(time.time()) if now is None else int(now)

        verified_records: list[DelegationRecord] = []
        seen_ids: set[str] = set()

        for idx, signed_record in enumerate(signed_chain):
            record = self._signer.verify_signed_record(signed_record)

            if record.delegation_id in seen_ids:
                raise DelegationError("duplicate delegation_id in chain")
            seen_ids.add(record.delegation_id)

            if record.issued_at - self._clock_skew_seconds > current_time:
                raise DelegationError("delegation issued_at is in the future")

            if record.expires_at + self._clock_skew_seconds < current_time:
                raise DelegationError("delegation is expired")

            if record.expires_at < record.issued_at:
                raise DelegationError("delegation expires before issued_at")

            if idx == 0:
                if record.parent_delegation_id is not None:
                    raise DelegationError("root delegation must not reference a parent")
            else:
                parent = verified_records[idx - 1]

                if record.parent_delegation_id != parent.delegation_id:
                    raise DelegationError("delegation parent linkage mismatch")

                if parent.subject != record.issuer:
                    raise DelegationError(
                        "delegation issuer must equal previous subject in chain"
                    )

                if not parent.allow_redelegate:
                    raise DelegationError(
                        "scoped re-delegation denied by parent delegation"
                    )

                if not _scope_is_subset(record.scopes, parent.scopes):
                    raise DelegationError(
                        "child delegation scopes exceed parent delegation scope"
                    )

                if record.expires_at > parent.expires_at:
                    raise DelegationError(
                        "child delegation lifetime exceeds parent delegation lifetime"
                    )

            verified_records.append(record)

        leaf = verified_records[-1]

        if leaf.subject != expected_leaf_subject:
            raise DelegationError("leaf subject mismatch")

        if not _scope_is_subset(required_scopes, leaf.scopes):
            raise DelegationError("required scopes not covered by leaf delegation")

        return {
            "ok": True,
            "chain_depth": len(verified_records),
            "leaf_subject": leaf.subject,
            "leaf_scopes": sorted(leaf.scopes),
            "verified_chain": _normalize_chain([r.to_payload() for r in verified_records]),
        }


def build_signed_delegation(
    trust_store: dict[str, bytes],
    *,
    delegation_id: str,
    issuer: str,
    subject: str,
    scopes: list[str],
    allow_redelegate: bool,
    issued_at: int,
    expires_at: int,
    nonce: str,
    parent_delegation_id: str | None = None,
) -> dict[str, Any]:
    signer = DelegationSigner(trust_store)
    record = DelegationRecord(
        delegation_id=delegation_id,
        issuer=issuer,
        subject=subject,
        scopes=sorted(scopes),
        allow_redelegate=allow_redelegate,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        parent_delegation_id=parent_delegation_id,
    )
    return signer.sign_record(record)
