from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyntra.trust.ledger.events import EventType, LedgerEvent
from cyntra.trust.ledger.writer import JSONLSink, LedgerWriter
from cyntra.trust.spine.audit import AuditLog
from cyntra.trust.spine.capabilities import (
    CapabilityPolicy,
    fact_kind_from_schema,
    required_scopes_for_fact_schema,
    verify_capability_token,
)
from cyntra.trust.spine.crypto import (
    compute_envelope_hash,
    verify_envelope_signature,
    verify_signature_by_issuer,
)
from cyntra.trust.spine.dedupe import DedupeCache
from cyntra.trust.spine.framing import decode_maybe_zlib_framed
from cyntra.trust.spine.gateway.nats_plane import NATSPlaneHost
from cyntra.trust.spine.gateway.transport import SpinePlaneHost, gather_best_effort
from cyntra.trust.spine.ratelimit import TokenBucket
from cyntra.trust.spine.schemas import HeadAnnouncement, SignedEnvelope, parse_spine_object

logger = logging.getLogger(__name__)


def _nats_subject_matches(pattern: str, subject: str) -> bool:
    """Match NATS-style wildcard subject patterns (`*` and `>`)."""
    p = str(pattern or "")
    s = str(subject or "")
    if not p:
        return False
    if p == s:
        return True

    p_parts = p.split(".")
    s_parts = s.split(".")

    i = 0
    for i, tok in enumerate(p_parts):
        if tok == ">":
            return True
        if i >= len(s_parts):
            return False
        if tok == "*":
            continue
        if tok != s_parts[i]:
            return False

    return i + 1 == len(s_parts)


def _subject_for_spine_object(obj: dict[str, Any]) -> str | None:
    schema = str(obj.get("schema") or "")
    if schema == "aegis.spine.head_announcement.v1":
        return "aegis.spine.heads.v1"

    if schema == "aegis.spine.envelope.v1":
        fact_schema = str((obj.get("fact") or {}).get("schema") or "")
        kind = fact_kind_from_schema(fact_schema)
        if not kind:
            return None
        return f"aegis.spine.envelope.{kind}.v1"

    return None


def _priority_for_spine_object(obj: dict[str, Any]) -> int:
    schema = str(obj.get("schema") or "")
    if schema == "aegis.spine.envelope.v1":
        fact_schema = str((obj.get("fact") or {}).get("schema") or "")
        if fact_schema.endswith("revocation.v1"):
            return 0
        if fact_schema.endswith("log_checkpoint.v1"):
            return 1
        if fact_schema.endswith("incident.v1"):
            return 2
        if fact_schema.endswith("policy_delta.v1"):
            return 3
        if fact_schema.endswith("run.v1"):
            return 4
        if fact_schema.endswith("node_attestation.v1"):
            return 5
        if fact_schema.endswith("heartbeat.v1"):
            return 9
        return 6

    if schema == "aegis.spine.head_announcement.v1":
        return 8

    # Unknown objects are low priority.
    return 9


@dataclass
class SpinePlaneBridgeConfig:
    data_dir: Path = field(default_factory=lambda: Path(".cyntra/spine-gateway"))
    forward_head_announcements: bool = True

    # Transport-level framing (compatible with the Reticulum adapter).
    accept_zlib_framing: bool = True
    max_decompressed_bytes: int = 2_000_000
    max_payload_bytes: int = 256 * 1024

    # Capability enforcement (Spine v1 §7.7 step 4).
    require_capability_token_for_fact_schemas: list[str] = field(
        default_factory=lambda: [
            "aegis.spine.fact.policy_delta.v1",
            "aegis.spine.fact.revocation.v1",
            "aegis.spine.fact.log_checkpoint.v1",
        ]
    )
    trusted_token_issuers: list[str] = field(default_factory=list)
    allow_self_issued_tokens: bool = True

    # Disclosure policy and membership
    trusted_issuers: list[str] = field(default_factory=list)
    # Default-deny: only allow known bridgeable Spine facts unless explicitly widened.
    fact_schema_allowlist: list[str] = field(
        default_factory=lambda: [
            "aegis.spine.fact.incident.v1",
            "aegis.spine.fact.run.v1",
            "aegis.spine.fact.node_attestation.v1",
            "aegis.spine.fact.policy_delta.v1",
            "aegis.spine.fact.artifact_pointer.v1",
            "aegis.spine.fact.revocation.v1",
            "aegis.spine.fact.log_checkpoint.v1",
            "aegis.spine.fact.heartbeat.v1",
        ]
    )
    fact_schema_denylist: list[str] = field(default_factory=list)
    forward_heartbeats: bool = False

    # Bridge filtering (subject taxonomy, default-deny).
    subject_allowlist: list[str] = field(
        default_factory=lambda: [
            "aegis.spine.envelope.incident.v1",
            "aegis.spine.envelope.run.v1",
            "aegis.spine.envelope.node_attestation.v1",
            "aegis.spine.envelope.policy_delta.v1",
            "aegis.spine.envelope.artifact_pointer.v1",
            "aegis.spine.envelope.revocation.v1",
            "aegis.spine.envelope.log_checkpoint.v1",
            "aegis.spine.envelope.heartbeat.v1",
            "aegis.spine.heads.v1",
        ]
    )

    # Rate limits (per sender)
    inbound_bytes_per_sec: int = 100_000
    inbound_bytes_burst: int = 200_000
    inbound_messages_per_sec: float = 50.0
    inbound_messages_burst: float = 100.0

    # Rate limits (per issuer)
    issuer_bytes_per_sec: int = 100_000
    issuer_bytes_burst: int = 200_000
    issuer_messages_per_sec: float = 50.0
    issuer_messages_burst: float = 100.0

    # Rate limits (per subject)
    subject_bytes_per_sec: int = 100_000
    subject_bytes_burst: int = 200_000
    subject_messages_per_sec: float = 50.0
    subject_messages_burst: float = 100.0

    # Dedupe cache
    dedupe_max_items: int = 50_000
    dedupe_ttl_secs: float = 3600.0

    # Rate limiter cache bounds (avoid unbounded growth from many distinct senders/issuers).
    bucket_ttl_secs: float = 3600.0
    bucket_gc_interval_secs: float = 60.0
    sender_bucket_max_entries: int = 10_000
    issuer_bucket_max_entries: int = 10_000
    subject_bucket_max_entries: int = 1_000

    # Outbound scheduling
    outbound_queue_maxsize: int = 100_000

    # Audit log
    audit_log_enabled: bool = True
    audit_log_path: Path | None = None

    # Ledger event log (observability; not critical path)
    ledger_log_enabled: bool = True
    ledger_log_path: Path | None = None
    ledger_log_buffer_size: int = 10


class SpinePlaneBridge:
    """Verify + forward Spine objects across multiple pub/sub planes.

    This is intentionally minimal scaffolding:
    - verifies envelope hashes and signatures before forwarding
    - never mutates signed envelopes
    - enforces disclosure policy and capability tokens (if required)
    - dedupes by `envelope_hash` in-memory
    - prioritizes revocations over low-value messages
    """

    def __init__(self, hosts: list[SpinePlaneHost], config: SpinePlaneBridgeConfig | None = None):
        self.config = config or SpinePlaneBridgeConfig()
        self.config.data_dir.mkdir(parents=True, exist_ok=True)

        self._hosts = list(hosts)
        self._running = False
        self._send_task: asyncio.Task | None = None

        self._seen = DedupeCache(max_items=self.config.dedupe_max_items, ttl_secs=self.config.dedupe_ttl_secs)

        self._audit: AuditLog | None = None
        if self.config.audit_log_enabled:
            self._audit = AuditLog.open(
                self.config.audit_log_path or (self.config.data_dir / "spine_gateway_audit.jsonl")
            )

        self._ledger: LedgerWriter | None = None
        if self.config.ledger_log_enabled:
            path = self.config.ledger_log_path or (self.config.data_dir / "spine_gateway_ledger.jsonl")
            self._ledger = LedgerWriter([JSONLSink(path, buffer_size=max(1, int(self.config.ledger_log_buffer_size)))])

        # Inbound rate limiters
        self._inbound_bytes: OrderedDict[str, TokenBucket] = OrderedDict()
        self._inbound_msgs: OrderedDict[str, TokenBucket] = OrderedDict()
        self._issuer_bytes: OrderedDict[str, TokenBucket] = OrderedDict()
        self._issuer_msgs: OrderedDict[str, TokenBucket] = OrderedDict()
        self._subject_bytes: OrderedDict[str, TokenBucket] = OrderedDict()
        self._subject_msgs: OrderedDict[str, TokenBucket] = OrderedDict()
        self._last_bucket_gc = time.monotonic()

        # Outbound prioritization queue (lower number = higher priority).
        self._outbound_counter = 0
        self._outbound: asyncio.PriorityQueue[tuple[int, int, SpinePlaneHost, bytes, str | None]] = asyncio.PriorityQueue(
            maxsize=self.config.outbound_queue_maxsize
        )

    async def start(self) -> None:
        if self._running:
            return
        self._running = True

        for host in self._hosts:
            host.on_message(lambda payload, sender, channel, h=host: self._on_message(h, payload, sender, channel))

        for host in self._hosts:
            await host.start()

        self._send_task = asyncio.create_task(self._send_loop())

    async def stop(self) -> None:
        self._running = False
        if self._send_task is not None:
            self._send_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._send_task
            self._send_task = None

        for host in self._hosts:
            await host.stop()

        if self._ledger is not None:
            with suppress(Exception):
                await self._ledger.close()

    async def _send_loop(self) -> None:
        while self._running:
            try:
                priority, _counter, host, payload, channel = await self._outbound.get()
            except asyncio.CancelledError:
                break

            try:
                await host.publish(payload, channel=channel)
            except Exception as e:
                logger.debug("Host publish failed (priority=%s): %s", priority, e)
                await self._audit_event("send_error", error=str(e), priority=priority)
            finally:
                self._outbound.task_done()

    async def _on_message(self, src: SpinePlaneHost, payload: bytes, sender: str, channel: str | None) -> None:
        if len(payload) > self.config.max_payload_bytes:
            await self._audit_event(
                "drop",
                reason="payload_too_large",
                sender=sender,
                channel=channel,
                size_bytes=len(payload),
            )
            return

        if channel and channel.startswith("aegis.spine.") and not self._subject_allowed(channel):
            await self._audit_event("drop", reason="subject_not_allowed", sender=sender, channel=channel)
            return

        sender_rate_limited = not self._rate_limit_sender(sender, size_bytes=len(payload))

        obj = self._decode(payload)
        if obj is None:
            await self._audit_event(
                "drop",
                reason="rate_limited" if sender_rate_limited else "invalid_payload",
                sender=sender,
                channel=channel,
                size_bytes=len(payload),
            )
            return

        parsed = parse_spine_object(obj)
        if parsed is None:
            await self._audit_event("drop", reason="unknown_schema", sender=sender, channel=channel)
            return

        possible_revocation = (
            isinstance(parsed, SignedEnvelope) and str((parsed.fact or {}).get("schema") or "").endswith("revocation.v1")
        )

        if sender_rate_limited and not possible_revocation:
            await self._audit_event("drop", reason="rate_limited", sender=sender, channel=channel, size_bytes=len(payload))
            return

        if isinstance(parsed, SignedEnvelope):
            env_dict = parsed.to_dict()
            if compute_envelope_hash(env_dict) != parsed.envelope_hash:
                await self._audit_event(
                    "drop",
                    reason="invalid_envelope_hash",
                    sender=sender,
                    channel=channel,
                    issuer=parsed.issuer,
                    seq=parsed.seq,
                )
                return
            if not verify_envelope_signature(env_dict):
                await self._audit_event(
                    "drop",
                    reason="invalid_envelope_signature",
                    sender=sender,
                    channel=channel,
                    issuer=parsed.issuer,
                    seq=parsed.seq,
                )
                return

            ok, reason = self._enforce_capability(env_dict)
            if not ok:
                await self._audit_event(
                    "drop",
                    reason=reason,
                    sender=sender,
                    channel=channel,
                    issuer=parsed.issuer,
                    seq=parsed.seq,
                )
                return

            if not self._disclosure_allows(env_dict):
                await self._audit_event("drop", reason="disclosure_policy", sender=sender, channel=channel, issuer=parsed.issuer)
                return

            subject = _subject_for_spine_object(env_dict)
            if subject is not None and not self._subject_allowed(subject):
                await self._audit_event(
                    "drop",
                    reason="subject_not_allowed",
                    sender=sender,
                    channel=channel,
                    subject=subject,
                    issuer=parsed.issuer,
                    seq=parsed.seq,
                )
                return
            if isinstance(src, NATSPlaneHost) and channel and subject and channel != subject:
                await self._audit_event(
                    "drop",
                    reason="subject_mismatch",
                    sender=sender,
                    channel=channel,
                    expected_subject=subject,
                    issuer=parsed.issuer,
                    seq=parsed.seq,
                )
                return

            is_revocation = subject == "aegis.spine.envelope.revocation.v1"

            issuer_rate_limited = False
            subject_rate_limited = False
            if not is_revocation:
                issuer_rate_limited = not self._rate_limit_issuer(parsed.issuer, size_bytes=len(payload))
                subject_rate_limited = subject is not None and not self._rate_limit_subject(subject, size_bytes=len(payload))

                if issuer_rate_limited:
                    await self._audit_event("drop", reason="rate_limited_issuer", sender=sender, channel=channel, issuer=parsed.issuer)
                    return
                if subject_rate_limited:
                    await self._audit_event("drop", reason="rate_limited_subject", sender=sender, channel=channel, subject=subject)
                    return

            if is_revocation and sender_rate_limited:
                await self._audit_event(
                    "bypass_rate_limit",
                    reason="revocation_always_allowed",
                    sender=sender,
                    channel=channel,
                    issuer=parsed.issuer,
                    seq=parsed.seq,
                )

            if self._seen.seen(parsed.envelope_hash):
                return

            out_payload = self._encode(env_dict)

            await self._audit_event(
                "forward",
                sender=sender,
                channel=channel,
                schema=str(env_dict.get("schema") or ""),
                envelope_hash=str(env_dict.get("envelope_hash") or ""),
                issuer=str(env_dict.get("issuer") or ""),
                fact_schema=str((env_dict.get("fact") or {}).get("schema") or ""),
                subject=subject,
            )

            await self._fanout(src, out_payload, subject=subject, priority=_priority_for_spine_object(env_dict))

        elif isinstance(parsed, HeadAnnouncement) and self.config.forward_head_announcements:
            ha_dict = parsed.to_dict()
            if not verify_signature_by_issuer(ha_dict):
                await self._audit_event("drop", reason="invalid_head_announcement_signature", sender=sender, channel=channel)
                return

            issuer = str(ha_dict.get("issuer") or "")
            if self.config.trusted_issuers and issuer not in self.config.trusted_issuers:
                await self._audit_event("drop", reason="issuer_not_allowed", sender=sender, channel=channel, issuer=issuer)
                return

            subject = _subject_for_spine_object(ha_dict)
            if subject is not None and not self._subject_allowed(subject):
                await self._audit_event(
                    "drop",
                    reason="subject_not_allowed",
                    sender=sender,
                    channel=channel,
                    subject=subject,
                    issuer=issuer,
                )
                return
            if isinstance(src, NATSPlaneHost) and channel and subject and channel != subject:
                await self._audit_event(
                    "drop",
                    reason="subject_mismatch",
                    sender=sender,
                    channel=channel,
                    expected_subject=subject,
                    issuer=issuer,
                )
                return

            if not self._rate_limit_issuer(issuer, size_bytes=len(payload)):
                await self._audit_event("drop", reason="rate_limited_issuer", sender=sender, channel=channel, issuer=issuer)
                return

            if subject is not None and not self._rate_limit_subject(subject, size_bytes=len(payload)):
                await self._audit_event("drop", reason="rate_limited_subject", sender=sender, channel=channel, subject=subject)
                return

            out_payload = self._encode(ha_dict)

            await self._audit_event(
                "forward",
                sender=sender,
                channel=channel,
                schema=str(ha_dict.get("schema") or ""),
                issuer=str(ha_dict.get("issuer") or ""),
                subject=subject,
            )

            await self._fanout(src, out_payload, subject=subject, priority=_priority_for_spine_object(ha_dict))

    async def _fanout(self, src: SpinePlaneHost, payload: bytes, *, subject: str | None, priority: int) -> None:
        dests = [h for h in self._hosts if h is not src]

        for host in dests:
            channel = subject if isinstance(host, NATSPlaneHost) else None
            self._enqueue_outbound(host, payload, channel=channel, priority=priority)

    def _decode(self, payload: bytes) -> dict[str, Any] | None:
        try:
            if self.config.accept_zlib_framing:
                decoded = decode_maybe_zlib_framed(payload, max_decompressed_bytes=self.config.max_decompressed_bytes)
                if decoded is None:
                    return None
                payload = decoded
            return json.loads(payload.decode("utf-8"))
        except Exception:
            return None

    def _encode(self, obj: dict[str, Any]) -> bytes:
        return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _subject_allowed(self, subject: str) -> bool:
        if not self.config.subject_allowlist:
            return True
        return any(_nats_subject_matches(p, subject) for p in self.config.subject_allowlist)

    def _enforce_capability(self, envelope_obj: dict[str, Any]) -> tuple[bool, str]:
        fact_schema = str((envelope_obj.get("fact") or {}).get("schema") or "")
        token = envelope_obj.get("capability_token")

        policy = CapabilityPolicy(
            require_token_for_fact_schemas=set(self.config.require_capability_token_for_fact_schemas),
            trusted_token_issuers=set(self.config.trusted_token_issuers),
            allow_self_issued_tokens=self.config.allow_self_issued_tokens,
        )

        requires = fact_schema in policy.require_token_for_fact_schemas
        if token is None:
            return (False, "missing_capability_token") if requires else (True, "ok")
        if not isinstance(token, dict):
            return False, "invalid_capability_token"

        required_scopes = required_scopes_for_fact_schema(fact_schema) if requires else []
        return verify_capability_token(
            token,
            envelope_issuer=str(envelope_obj.get("issuer") or ""),
            required_scopes=required_scopes,
            policy=policy,
        )

    def _disclosure_allows(self, envelope_obj: dict[str, Any]) -> bool:
        issuer = str(envelope_obj.get("issuer") or "")
        if self.config.trusted_issuers and issuer not in self.config.trusted_issuers:
            return False

        fact_schema = str((envelope_obj.get("fact") or {}).get("schema") or "")
        if self.config.fact_schema_allowlist and fact_schema not in self.config.fact_schema_allowlist:
            return False
        if self.config.fact_schema_denylist and fact_schema in self.config.fact_schema_denylist:
            return False
        if fact_schema.endswith("heartbeat.v1"):
            return self.config.forward_heartbeats
        return True

    def _rate_limit_sender(self, sender: str, *, size_bytes: int) -> bool:
        self._maybe_gc_buckets()
        return self._rate_limit_key(
            sender,
            size_bytes=size_bytes,
            bytes_buckets=self._inbound_bytes,
            msgs_buckets=self._inbound_msgs,
            bytes_rate=self.config.inbound_bytes_per_sec,
            bytes_burst=self.config.inbound_bytes_burst,
            msgs_rate=self.config.inbound_messages_per_sec,
            msgs_burst=self.config.inbound_messages_burst,
            max_entries=self.config.sender_bucket_max_entries,
        )

    def _rate_limit_issuer(self, issuer: str, *, size_bytes: int) -> bool:
        if not issuer:
            return False
        return self._rate_limit_key(
            issuer,
            size_bytes=size_bytes,
            bytes_buckets=self._issuer_bytes,
            msgs_buckets=self._issuer_msgs,
            bytes_rate=self.config.issuer_bytes_per_sec,
            bytes_burst=self.config.issuer_bytes_burst,
            msgs_rate=self.config.issuer_messages_per_sec,
            msgs_burst=self.config.issuer_messages_burst,
            max_entries=self.config.issuer_bucket_max_entries,
        )

    def _rate_limit_subject(self, subject: str, *, size_bytes: int) -> bool:
        if not subject:
            return False
        return self._rate_limit_key(
            subject,
            size_bytes=size_bytes,
            bytes_buckets=self._subject_bytes,
            msgs_buckets=self._subject_msgs,
            bytes_rate=self.config.subject_bytes_per_sec,
            bytes_burst=self.config.subject_bytes_burst,
            msgs_rate=self.config.subject_messages_per_sec,
            msgs_burst=self.config.subject_messages_burst,
            max_entries=self.config.subject_bucket_max_entries,
        )

    def _rate_limit_key(
        self,
        key: str,
        *,
        size_bytes: int,
        bytes_buckets: OrderedDict[str, TokenBucket],
        msgs_buckets: OrderedDict[str, TokenBucket],
        bytes_rate: int,
        bytes_burst: int,
        msgs_rate: float,
        msgs_burst: float,
        max_entries: int,
    ) -> bool:
        if bytes_rate > 0:
            bucket = bytes_buckets.get(key)
            if bucket is None:
                bucket = TokenBucket.create(rate_per_sec=float(bytes_rate), capacity=float(bytes_burst))
                bytes_buckets[key] = bucket
            else:
                bytes_buckets.move_to_end(key)
            if max_entries > 0:
                while len(bytes_buckets) > max_entries:
                    bytes_buckets.popitem(last=False)
            if not bucket.consume(float(size_bytes)):
                return False

        if msgs_rate > 0:
            bucket = msgs_buckets.get(key)
            if bucket is None:
                bucket = TokenBucket.create(rate_per_sec=float(msgs_rate), capacity=float(msgs_burst))
                msgs_buckets[key] = bucket
            else:
                msgs_buckets.move_to_end(key)
            if max_entries > 0:
                while len(msgs_buckets) > max_entries:
                    msgs_buckets.popitem(last=False)
            if not bucket.consume(1.0):
                return False

        return True

    def _maybe_gc_buckets(self) -> None:
        interval = float(self.config.bucket_gc_interval_secs)
        if interval <= 0:
            return

        now = time.monotonic()
        if now - self._last_bucket_gc < interval:
            return
        self._last_bucket_gc = now

        ttl = float(self.config.bucket_ttl_secs)
        if ttl <= 0:
            return

        cutoff = now - ttl
        for buckets in (
            self._inbound_bytes,
            self._inbound_msgs,
            self._issuer_bytes,
            self._issuer_msgs,
            self._subject_bytes,
            self._subject_msgs,
        ):
            while buckets:
                _k, bucket = next(iter(buckets.items()))
                if bucket.updated_at >= cutoff:
                    break
                buckets.popitem(last=False)

    def _enqueue_outbound(self, host: SpinePlaneHost, payload: bytes, *, channel: str | None, priority: int) -> None:
        try:
            self._outbound.put_nowait((priority, self._outbound_counter, host, payload, channel))
            self._outbound_counter += 1
        except asyncio.QueueFull:
            # Drop on overflow; the bridge is best-effort.
            asyncio.create_task(
                self._audit_event(
                    "drop",
                    reason="outbound_queue_full",
                    priority=priority,
                    channel=channel,
                )
            )

    async def _audit_event(self, kind: str, **fields: Any) -> None:
        if self._audit is not None:
            with suppress(Exception):
                self._audit.append({"kind": kind, **fields})

        if self._ledger is None:
            return

        ev_type = EventType.METRIC
        if kind == "forward":
            ev_type = EventType.SPINE_GATEWAY_FORWARD
        elif kind == "drop":
            ev_type = EventType.SPINE_GATEWAY_DROP
        elif kind == "bypass_rate_limit":
            ev_type = EventType.SPINE_GATEWAY_BYPASS_RATE_LIMIT
        elif kind == "send_error":
            ev_type = EventType.SPINE_GATEWAY_SEND_ERROR

        event = LedgerEvent(type=ev_type, data={"kind": kind, **fields})
        await gather_best_effort(self._ledger.emit(event))
