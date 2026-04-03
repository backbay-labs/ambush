"""Spine object schemas (transport-level).

These are intentionally lightweight: the transport carries JSON objects that are
validated at the receiver by hashing/signature checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal


def _now_iso_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class SignedEnvelope:
    schema: Literal["aegis.spine.envelope.v1"]
    issuer: str
    seq: int
    prev_envelope_hash: str | None
    envelope_hash: str
    issued_at: str
    capability_token: dict[str, Any] | None
    fact: dict[str, Any]
    signature: str

    @classmethod
    def new_unsigned(
        cls,
        *,
        issuer: str,
        seq: int,
        prev_envelope_hash: str | None,
        fact: dict[str, Any],
        issued_at: str | None = None,
        capability_token: dict[str, Any] | None = None,
    ) -> "SignedEnvelope":
        return cls(
            schema="aegis.spine.envelope.v1",
            issuer=issuer,
            seq=seq,
            prev_envelope_hash=prev_envelope_hash,
            envelope_hash="",
            issued_at=issued_at or _now_iso_z(),
            capability_token=capability_token,
            fact=fact,
            signature="",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "issuer": self.issuer,
            "seq": self.seq,
            "prev_envelope_hash": self.prev_envelope_hash,
            "envelope_hash": self.envelope_hash,
            "issued_at": self.issued_at,
            "capability_token": self.capability_token,
            "fact": self.fact,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SignedEnvelope":
        return cls(
            schema=d["schema"],
            issuer=d["issuer"],
            seq=int(d["seq"]),
            prev_envelope_hash=d.get("prev_envelope_hash"),
            envelope_hash=d["envelope_hash"],
            issued_at=d["issued_at"],
            capability_token=d.get("capability_token"),
            fact=d["fact"],
            signature=d["signature"],
        )


@dataclass
class HeadAnnouncement:
    schema: Literal["aegis.spine.head_announcement.v1"]
    issuer: str
    seq: int
    head_hash: str
    sent_at: str
    signature: str

    @classmethod
    def new_unsigned(
        cls,
        *,
        issuer: str,
        seq: int,
        head_hash: str,
        sent_at: str | None = None,
    ) -> "HeadAnnouncement":
        return cls(
            schema="aegis.spine.head_announcement.v1",
            issuer=issuer,
            seq=seq,
            head_hash=head_hash,
            sent_at=sent_at or _now_iso_z(),
            signature="",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "issuer": self.issuer,
            "seq": self.seq,
            "head_hash": self.head_hash,
            "sent_at": self.sent_at,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HeadAnnouncement":
        return cls(
            schema=d["schema"],
            issuer=d["issuer"],
            seq=int(d["seq"]),
            head_hash=d["head_hash"],
            sent_at=d["sent_at"],
            signature=d["signature"],
        )


@dataclass
class SyncRequest:
    schema: Literal["aegis.spine.sync_request.v1"]
    issuer: str
    from_seq: int
    to_seq: int
    max_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "issuer": self.issuer,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "max_bytes": self.max_bytes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SyncRequest":
        return cls(
            schema=d["schema"],
            issuer=d["issuer"],
            from_seq=int(d["from_seq"]),
            to_seq=int(d["to_seq"]),
            max_bytes=int(d.get("max_bytes", 1048576)),
        )


@dataclass
class SyncResponse:
    schema: Literal["aegis.spine.sync_response.v1"]
    issuer: str
    from_seq: int
    envelopes: list[dict[str, Any]]
    done: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "issuer": self.issuer,
            "from_seq": self.from_seq,
            "envelopes": self.envelopes,
            "done": self.done,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SyncResponse":
        return cls(
            schema=d["schema"],
            issuer=d["issuer"],
            from_seq=int(d["from_seq"]),
            envelopes=list(d.get("envelopes", [])),
            done=bool(d.get("done", True)),
        )


SpineObject = SignedEnvelope | HeadAnnouncement | SyncRequest | SyncResponse


def parse_spine_object(obj: dict[str, Any]) -> SpineObject | None:
    schema = obj.get("schema")
    if schema == "aegis.spine.envelope.v1":
        return SignedEnvelope.from_dict(obj)
    if schema == "aegis.spine.head_announcement.v1":
        return HeadAnnouncement.from_dict(obj)
    if schema == "aegis.spine.sync_request.v1":
        return SyncRequest.from_dict(obj)
    if schema == "aegis.spine.sync_response.v1":
        return SyncResponse.from_dict(obj)
    return None

