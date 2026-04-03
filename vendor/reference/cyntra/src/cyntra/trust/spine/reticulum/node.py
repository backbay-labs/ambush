"""Reticulum adapter node for Spine messages (Phase 0/1 scaffold)."""

from __future__ import annotations

import asyncio
import hashlib
import heapq
import json
import logging
import time
import zlib
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cyntra.trust.spine.audit import AuditLog
from cyntra.trust.spine.capabilities import (
    CapabilityPolicy,
    required_scopes_for_fact_schema,
    verify_capability_token,
)
from cyntra.trust.spine.crypto import (
    Ed25519Keypair,
    compute_envelope_hash,
    issuer_from_public_key_hex,
    sign_by_issuer,
    sign_envelope,
    verify_envelope_signature,
    verify_signature_by_issuer,
)
from cyntra.trust.spine.framing import decode_maybe_zlib_framed
from cyntra.trust.spine.ratelimit import TokenBucket
from cyntra.trust.spine.reticulum.host import ReticulumHost, ReticulumHostConfig, create_host
from cyntra.trust.spine.schemas import (
    HeadAnnouncement,
    SignedEnvelope,
    SyncRequest,
    SyncResponse,
    parse_spine_object,
)
from cyntra.trust.spine.store.envelopes import EnvelopeStore

logger = logging.getLogger(__name__)


@dataclass
class ReticulumAdapterConfig:
    data_dir: Path = field(default_factory=lambda: Path(".cyntra/spine"))
    key_path: Path | None = None
    peers: list[str] = field(default_factory=list)
    host_mode: str = "inproc"  # "inproc" or "reticulum"

    # Head announcements
    announce_period_secs: int = 300

    # Sync limits
    max_sync_envelopes: int = 256
    max_sync_bytes: int = 1_000_000
    sync_cooldown_secs: float = 2.0

    # Outbound control
    send_bytes_per_sec: int | None = None
    outbound_queue_maxsize: int = 10_000

    # Payload encoding (transport-level; decoded JSON is what gets verified)
    compress_zlib: bool = False
    compress_min_bytes: int = 512
    compress_level: int = 6
    max_decompressed_bytes: int = 2_000_000

    # Behavior
    enable_auto_sync: bool = True
    enable_forwarding: bool = True
    forward_heartbeats: bool = False
    forward_fact_schema_allowlist: list[str] = field(default_factory=list)
    forward_fact_schema_denylist: list[str] = field(default_factory=list)
    forward_fanout: int = 0  # 0 = all peers (minus sender)

    # Audit logging (JSONL + hash chain)
    audit_log_enabled: bool = True
    audit_log_path: Path | None = None

    # Peer discovery / persistence
    peerbook_enabled: bool = True
    peerbook_path: Path | None = None
    peerbook_max_peers: int = 512
    auto_peer_discovery: bool = True
    auto_peer_discovery_from_attestation: bool = True
    auto_peer_discovery_from_sender: bool = True

    # Capability enforcement (Spine v1 §7.7 step 4)
    require_capability_token_for_fact_schemas: list[str] = field(
        default_factory=lambda: [
            "aegis.spine.fact.policy_delta.v1",
            "aegis.spine.fact.revocation.v1",
            "aegis.spine.fact.log_checkpoint.v1",
        ]
    )
    trusted_token_issuers: list[str] = field(default_factory=list)
    allow_self_issued_tokens: bool = True

    # Trust bundle / allowlists (anti-sybil)
    peer_allowlist: list[str] = field(default_factory=list)
    trusted_issuers: list[str] = field(default_factory=list)
    # If a trust bundle is configured, allow (bounded) storage of unknown issuers instead of hard-dropping.
    accept_unknown_issuers: bool = False
    unknown_issuer_max_total_envelopes: int = 5_000
    unknown_issuer_max_envelopes_per_issuer: int = 200

    # Inbound rate limits (per peer)
    inbound_bytes_per_sec: int = 50_000
    inbound_bytes_burst: int = 100_000
    inbound_messages_per_sec: float = 20.0
    inbound_messages_burst: float = 40.0

    # Revocation bypass limits (applied when normal limits would drop)
    revocation_bytes_per_sec: int = 10_000
    revocation_bytes_burst: int = 20_000
    revocation_messages_per_sec: float = 5.0
    revocation_messages_burst: float = 10.0
    revocation_max_bytes: int = 16_384

    # Rate limiter cache bounds (avoid unbounded growth from many distinct peers).
    peer_bucket_ttl_secs: float = 3600.0
    peer_bucket_gc_interval_secs: float = 60.0
    peer_bucket_max_entries: int = 10_000

    # Transport binding publication
    publish_node_attestation_on_start: bool = True
    host_max_payload_bytes: int | None = None


class ReticulumAdapter:
    """Transport sidecar that speaks Spine objects over a Reticulum-like host."""

    def __init__(self, config: ReticulumAdapterConfig):
        self.config = config
        self.config.data_dir.mkdir(parents=True, exist_ok=True)

        self._audit: AuditLog | None = None
        if self.config.audit_log_enabled:
            self._audit = AuditLog.open(
                self.config.audit_log_path or (self.config.data_dir / "spine_reticulum_audit.jsonl")
            )

        key_path = config.key_path or (self.config.data_dir / "spine_ed25519.key")
        self.keypair = Ed25519Keypair.load_or_generate(key_path)
        self.issuer = issuer_from_public_key_hex(self.keypair.public_key_hex)

        self.store = EnvelopeStore(self.config.data_dir / "envelopes.db")

        # Reticulum destination directory: issuer -> destination hash (hex, no 0x).
        self._issuer_to_reticulum: dict[str, str] = {}
        self._peerbook_path = self.config.peerbook_path or (self.config.data_dir / "reticulum_peerbook.json")
        if self.config.peerbook_enabled:
            self._load_peerbook()

        self.host: ReticulumHost = create_host(
            ReticulumHostConfig(
                mode=self.config.host_mode,
                peers=list(self.config.peers),
                data_dir=self.config.data_dir,
                app_name="aegis",
                aspects=["spine"],
                announce_period_secs=self.config.announce_period_secs,
                max_payload_bytes=self.config.host_max_payload_bytes or 400,
            )
        )

        self._running = False
        self._seq = 0
        self._prev_hash: str | None = None

        self._head_task: asyncio.Task | None = None
        self._send_task: asyncio.Task | None = None

        # Outbound prioritization queue (lower number = higher priority).
        self._outbound_counter = 0
        self._outbound: asyncio.PriorityQueue[tuple[int, int, str, bytes]] = asyncio.PriorityQueue(
            maxsize=self.config.outbound_queue_maxsize
        )

        # Sync state: (peer, issuer) -> target_to_seq.
        self._sync_targets: dict[tuple[str, str], int] = {}
        self._sync_last_request: dict[tuple[str, str], float] = {}

        # Revocations (minimal v1 support).
        self._revoked_node_ids: set[str] = set()
        self._revoked_token_ids: set[str] = set()
        self._fork_incidents_emitted: set[tuple[str, int]] = set()
        self._prev_mismatch_incidents_emitted: set[tuple[str, int]] = set()

        # Inbound peer rate limits.
        self._inbound_bytes: OrderedDict[str, TokenBucket] = OrderedDict()
        self._inbound_msgs: OrderedDict[str, TokenBucket] = OrderedDict()
        self._revocation_inbound_bytes: OrderedDict[str, TokenBucket] = OrderedDict()
        self._revocation_inbound_msgs: OrderedDict[str, TokenBucket] = OrderedDict()
        self._last_peer_bucket_gc = time.monotonic()

    @property
    def address(self) -> str:
        return self.host.address

    async def start(self) -> None:
        if self._running:
            return
        self._running = True

        # Recover local chain state (best effort)
        head = self.store.get_contiguous_head(self.issuer)
        if head is not None:
            self._seq = head[0] + 1
            self._prev_hash = head[1]

        self.host.on_message(self._on_message)
        await self.host.start()

        self._send_task = asyncio.create_task(self._send_loop())

        if self.config.announce_period_secs > 0:
            self._head_task = asyncio.create_task(self._head_loop())

        if self.config.publish_node_attestation_on_start:
            # Non-fatal: transport binding publication is best-effort.
            with suppress(Exception):
                await self._publish_self_node_attestation()

    async def stop(self) -> None:
        self._running = False
        for task in (self._head_task, self._send_task):
            if not task:
                continue
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        if self.config.peerbook_enabled:
            with suppress(Exception):
                self._persist_peerbook()
        await self.host.stop()

    # --- publish primitives ---

    async def publish_fact(self, fact: dict[str, Any], *, capability_token: dict[str, Any] | None = None) -> SignedEnvelope:
        env = SignedEnvelope.new_unsigned(
            issuer=self.issuer,
            seq=self._seq,
            prev_envelope_hash=self._prev_hash,
            fact=fact,
            capability_token=capability_token,
        )
        env_dict = env.to_dict()
        env_dict["envelope_hash"] = compute_envelope_hash(env_dict)
        env_dict["signature"] = sign_envelope(env_dict, self.keypair)

        signed = SignedEnvelope.from_dict(env_dict)

        # Store locally (source=None)
        self.store.insert(signed.to_dict(), received_from=None)

        # Update local chain counters
        self._prev_hash = signed.envelope_hash
        self._seq += 1

        await self._broadcast(signed.to_dict(), priority=self._priority_for_obj(signed.to_dict()))
        return signed

    async def announce_head(self) -> HeadAnnouncement | None:
        head = self.store.get_contiguous_head(self.issuer)
        if head is None:
            return None

        seq, head_hash = head
        ha = HeadAnnouncement.new_unsigned(issuer=self.issuer, seq=seq, head_hash=head_hash)
        ha_dict = ha.to_dict()
        ha_dict["signature"] = sign_by_issuer(ha_dict, self.keypair)

        await self._maybe_set_announce_app_data(ha_dict)
        await self._broadcast(ha_dict, priority=8)
        return HeadAnnouncement.from_dict(ha_dict)

    # --- inbound handling ---

    async def _on_message(self, payload: bytes, sender: str) -> None:
        if not self._peer_allowed(sender):
            self._audit_event("drop", reason="peer_not_allowed", sender=sender, size_bytes=len(payload))
            return
        rate_limited = not self._rate_limit_peer(sender, size_bytes=len(payload))

        obj = self._decode(payload)
        if obj is None:
            self._audit_event(
                "drop",
                reason="rate_limited" if rate_limited else "invalid_payload",
                sender=sender,
                size_bytes=len(payload),
            )
            return

        parsed = parse_spine_object(obj)
        if parsed is None:
            return

        is_revocation = self._is_revocation_envelope(parsed)
        if is_revocation:
            ok, reason = self._enforce_revocation_guards(
                sender=sender,
                size_bytes=len(payload),
                bypass_rate_limit=rate_limited,
            )
            if not ok:
                self._audit_event("drop", reason=reason, sender=sender, size_bytes=len(payload))
                return

        # Revocations are high priority; even if rate-limited, attempt to process valid
        # revocation envelopes ("revocation always allowed" exception) within guardrails.
        if rate_limited and not is_revocation:
            self._audit_event("drop", reason="rate_limited", sender=sender, size_bytes=len(payload))
            return
        if rate_limited and is_revocation:
            self._audit_event(
                "bypass_rate_limit",
                reason="revocation_always_allowed",
                sender=sender,
                size_bytes=len(payload),
            )

        if isinstance(parsed, SignedEnvelope):
            await self._handle_envelope(parsed, sender)
        elif isinstance(parsed, HeadAnnouncement):
            await self._handle_head_announcement(parsed, sender)
        elif isinstance(parsed, SyncRequest):
            await self._handle_sync_request(parsed, sender)
        elif isinstance(parsed, SyncResponse):
            await self._handle_sync_response(parsed, sender)

    async def _handle_envelope(self, env: SignedEnvelope, sender: str) -> None:
        env_dict = env.to_dict()
        if compute_envelope_hash(env_dict) != env.envelope_hash:
            logger.warning("Bad envelope hash from %s", sender)
            self._audit_event(
                "drop",
                reason="invalid_envelope_hash",
                sender=sender,
                issuer=env.issuer,
                seq=env.seq,
                envelope_hash=str(env_dict.get("envelope_hash") or ""),
            )
            return
        if not verify_envelope_signature(env_dict):
            logger.warning("Bad envelope signature from %s", sender)
            self._audit_event(
                "drop",
                reason="invalid_envelope_signature",
                sender=sender,
                issuer=env.issuer,
                seq=env.seq,
                envelope_hash=env.envelope_hash,
            )
            return

        ok, reason = self._enforce_capability(env_dict)
        if not ok:
            logger.warning("Rejecting envelope due to capability policy (%s) from %s", reason, sender)
            self._audit_event(
                "drop",
                reason=reason,
                sender=sender,
                issuer=env.issuer,
                seq=env.seq,
                envelope_hash=env.envelope_hash,
                fact_schema=str((env_dict.get("fact") or {}).get("schema") or ""),
            )
            return

        if not self._issuer_allowed(env.issuer):
            self._audit_event(
                "drop",
                reason="issuer_not_allowed",
                sender=sender,
                issuer=env.issuer,
                seq=env.seq,
                envelope_hash=env.envelope_hash,
            )
            return

        ok, reason = self._check_unknown_issuer_quota(env.issuer)
        if not ok:
            self._audit_event(
                "drop",
                reason=reason,
                sender=sender,
                issuer=env.issuer,
                seq=env.seq,
                envelope_hash=env.envelope_hash,
            )
            return

        prev_mismatch = False
        expected_prev: str | None = None
        head = self.store.get_contiguous_head(env.issuer)
        if head is not None and env.seq == head[0] + 1:
            expected_prev = head[1]
            observed_prev = env.prev_envelope_hash
            if observed_prev in ("", "null"):
                observed_prev = None
            if observed_prev != expected_prev:
                prev_mismatch = True

        result = self.store.insert(env_dict, received_from=sender)
        if result.duplicate:
            return
        self._audit_event(
            "ingest",
            sender=sender,
            envelope_hash=env.envelope_hash,
            issuer=env.issuer,
            seq=env.seq,
            fact_schema=str((env_dict.get("fact") or {}).get("schema") or ""),
            out_of_order=result.out_of_order,
            fork_detected=result.fork_detected,
            prev_mismatch=prev_mismatch,
        )
        if result.fork_detected:
            logger.warning("Fork detected for issuer=%s seq=%s", env.issuer, env.seq)
            await self._emit_fork_incident(remote_issuer=env.issuer, seq=env.seq)
        if prev_mismatch:
            logger.warning(
                "Prev hash mismatch for issuer=%s seq=%s (expected=%s observed=%s)",
                env.issuer,
                env.seq,
                expected_prev,
                env.prev_envelope_hash,
            )
            await self._emit_prev_mismatch_incident(
                remote_issuer=env.issuer,
                seq=env.seq,
                expected_prev_envelope_hash=expected_prev,
                observed_prev_envelope_hash=env.prev_envelope_hash,
            )
        if result.out_of_order and self.config.enable_auto_sync and not prev_mismatch:
            await self._maybe_request_catchup(peer=sender, issuer=env.issuer, remote_seq=env.seq)
        if self.config.enable_forwarding and self._should_forward_envelope(env_dict):
            self._forward_envelope(env_dict, exclude_peer=sender)

        # Side-effect facts (revocations, etc).
        self._apply_fact_side_effects(env_dict)
        self._observe_sender_mapping(issuer=env.issuer, sender=sender)

    async def _handle_head_announcement(self, ha: HeadAnnouncement, sender: str) -> None:
        ha_dict = ha.to_dict()
        if not verify_signature_by_issuer(ha_dict):
            logger.warning("Bad head announcement signature from %s", sender)
            self._audit_event("drop", reason="invalid_head_announcement_signature", sender=sender)
            return
        self._audit_event("head", sender=sender, issuer=ha.issuer, seq=ha.seq, head_hash=ha.head_hash)
        if self.config.enable_auto_sync:
            await self._maybe_request_catchup(peer=sender, issuer=ha.issuer, remote_seq=ha.seq)

    async def _handle_sync_request(self, req: SyncRequest, sender: str) -> None:
        issuer = req.issuer
        envelopes = self.store.list_range(issuer=issuer, from_seq=req.from_seq, to_seq=req.to_seq)

        # Apply coarse limits to avoid unbounded responses. We only return a contiguous prefix
        # from `from_seq` to avoid causing the requester to skip holes.
        #
        # IMPORTANT: `req.max_bytes` is treated as a budget for the *encoded sync_response bytes*
        # (including JSON container overhead and optional compression framing), not just the
        # sum of per-envelope JSON lengths.
        limited: list[dict[str, Any]] = []
        expected_seq = req.from_seq
        stopped_due_to_limit = False

        # Align sync chunking with the local link budget. The host will still fragment
        # larger payloads if needed, but we try to keep each sync_response within the
        # configured per-message budget.
        host_budget = self.config.host_max_payload_bytes or 400
        budget = min(req.max_bytes, self.config.max_sync_bytes, host_budget)

        for env in envelopes:
            if int(env.get("seq", -1)) != expected_seq:
                break
            if len(limited) >= self.config.max_sync_envelopes:
                stopped_due_to_limit = True
                break

            candidate = limited + [env]
            probe = SyncResponse(
                schema="aegis.spine.sync_response.v1",
                issuer=issuer,
                from_seq=req.from_seq,
                envelopes=candidate,
                done=False,  # slightly larger than done=true; safe sizing
            ).to_dict()
            encoded_len = len(self._encode(probe))

            if encoded_len > budget:
                # If we can't fit even one envelope within budget, send a single-envelope
                # response anyway (it will be fragmented by the host if needed).
                if not limited:
                    limited = candidate
                    expected_seq += 1
                stopped_due_to_limit = True
                break

            limited.append(env)
            expected_seq += 1

        last_seq_sent = (expected_seq - 1) if limited else None
        done = True
        if last_seq_sent is not None and last_seq_sent < req.to_seq and stopped_due_to_limit:
            done = False

        resp = SyncResponse(
            schema="aegis.spine.sync_response.v1",
            issuer=issuer,
            from_seq=req.from_seq,
            envelopes=limited,
            done=done,
        )
        await self._send(sender, resp.to_dict(), priority=1)

    async def _handle_sync_response(self, resp: SyncResponse, sender: str) -> None:
        last_seq_received: int | None = None
        for env_obj in resp.envelopes:
            parsed = parse_spine_object(env_obj)
            if isinstance(parsed, SignedEnvelope):
                await self._handle_envelope(parsed, sender)
                last_seq_received = max(last_seq_received or parsed.seq, parsed.seq)

        key = (sender, resp.issuer)
        target = self._sync_targets.get(key)
        if target is None:
            return

        if resp.done:
            self._sync_targets.pop(key, None)
            return

        # Continue the same catch-up window with the next `from_seq`.
        if last_seq_received is None:
            self._sync_targets.pop(key, None)
            return

        next_from = last_seq_received + 1
        if next_from > target:
            self._sync_targets.pop(key, None)
            return

        await self._send_sync_request(peer=sender, issuer=resp.issuer, from_seq=next_from, to_seq=target)

    # --- transport helpers ---

    async def _broadcast(self, obj: dict[str, Any], *, priority: int) -> None:
        data = self._encode(obj)
        for peer in self.config.peers:
            self._enqueue(peer, data, priority=priority)

    async def _send(self, peer: str, obj: dict[str, Any], *, priority: int) -> None:
        self._enqueue(peer, self._encode(obj), priority=priority)

    def _encode(self, obj: dict[str, Any]) -> bytes:
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if not self.config.compress_zlib:
            return raw
        if len(raw) < self.config.compress_min_bytes:
            return raw
        compressed = zlib.compress(raw, level=self.config.compress_level)
        return b"Z1" + compressed

    def _decode(self, payload: bytes) -> dict[str, Any] | None:
        try:
            decoded = decode_maybe_zlib_framed(payload, max_decompressed_bytes=self.config.max_decompressed_bytes)
            if decoded is None:
                return None
            payload = decoded
            return json.loads(payload.decode("utf-8"))
        except Exception:
            logger.debug("Ignoring invalid spine payload")
            return None

    def _enqueue(self, peer: str, payload: bytes, *, priority: int) -> None:
        item = (priority, self._outbound_counter, peer, payload)
        self._outbound_counter += 1
        try:
            self._outbound.put_nowait(item)
            return
        except asyncio.QueueFull:
            if self._evict_outbound_for_priority(item):
                return
            logger.warning("Outbound queue full; dropping message to %s", peer)
            self._audit_event("drop", reason="outbound_queue_full", peer=peer, priority=priority)

    def _evict_outbound_for_priority(self, incoming: tuple[int, int, str, bytes]) -> bool:
        # Best-effort priority-aware eviction using the underlying heap.
        queue = self._outbound
        heap = getattr(queue, "_queue", None)
        if not heap:
            return False
        worst = max(heap)
        if incoming < worst:
            heap.remove(worst)
            heapq.heapify(heap)
            try:
                unfinished = getattr(queue, "_unfinished_tasks", None)
                if isinstance(unfinished, int) and unfinished > 0:
                    queue._unfinished_tasks = unfinished - 1
            except Exception:
                pass
            try:
                queue.put_nowait(incoming)
            except asyncio.QueueFull:
                return False
            self._audit_event(
                "drop",
                reason="outbound_queue_evicted",
                peer=str(worst[2]),
                priority=int(worst[0]),
            )
            return True
        return False

    async def _send_loop(self) -> None:
        rate = self.config.send_bytes_per_sec
        while self._running:
            try:
                priority, _counter, peer, payload = await self._outbound.get()
            except asyncio.CancelledError:
                break

            try:
                await self.host.send(peer, payload)
                if rate and rate > 0:
                    await asyncio.sleep(len(payload) / rate)
            except Exception as e:
                logger.debug("Failed sending to %s (priority=%s): %s", peer, priority, e)
                self._audit_event("send_error", peer=peer, priority=priority, error=str(e))
            finally:
                self._outbound.task_done()

    async def _head_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self.config.announce_period_secs)
                await self.announce_head()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Head announce loop error: %s", e)

    def _priority_for_obj(self, obj: dict[str, Any]) -> int:
        schema = obj.get("schema")
        if schema == "aegis.spine.envelope.v1":
            fact_schema = (obj.get("fact") or {}).get("schema")
            return self._priority_for_fact_schema(str(fact_schema or ""))
        if schema in ("aegis.spine.sync_request.v1", "aegis.spine.sync_response.v1"):
            return 1
        if schema == "aegis.spine.head_announcement.v1":
            return 8
        return 7

    def _priority_for_fact_schema(self, fact_schema: str) -> int:
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

    def _capability_policy(self) -> CapabilityPolicy:
        return CapabilityPolicy(
            require_token_for_fact_schemas=set(self.config.require_capability_token_for_fact_schemas),
            trusted_token_issuers=set(self.config.trusted_token_issuers),
            allow_self_issued_tokens=self.config.allow_self_issued_tokens,
        )

    def _enforce_capability(self, envelope_obj: dict[str, Any]) -> tuple[bool, str]:
        fact_schema = str((envelope_obj.get("fact") or {}).get("schema") or "")
        token = envelope_obj.get("capability_token")

        policy = self._capability_policy()
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
            revoked_token_ids=self._revoked_token_ids,
            revoked_issuers=self._revoked_node_ids,
        )

    def _apply_fact_side_effects(self, envelope_obj: dict[str, Any]) -> None:
        fact = envelope_obj.get("fact") or {}
        if not isinstance(fact, dict):
            return
        schema = str(fact.get("schema") or "")

        if schema == "aegis.spine.fact.revocation.v1":
            # Minimal support: accept `targets` entries of {type,value}.
            targets = fact.get("targets")
            if isinstance(targets, list):
                for t in targets:
                    if not isinstance(t, dict):
                        continue
                    ttype = str(t.get("type") or "")
                    val = str(t.get("value") or "")
                    if ttype == "node_id" and val:
                        self._revoked_node_ids.add(val)
                        self._issuer_to_reticulum.pop(val, None)
                    if ttype == "token_id" and val:
                        self._revoked_token_ids.add(val)

        if schema == "aegis.spine.fact.node_attestation.v1":
            node_id = str(fact.get("node_id") or "")
            if not node_id or node_id in self._revoked_node_ids:
                return
            transports = fact.get("transports")
            if not isinstance(transports, dict):
                return
            r = transports.get("reticulum")
            if not isinstance(r, dict):
                return
            dest = r.get("destination_hash")
            if isinstance(dest, str) and dest:
                dest_norm = dest.lower().strip()
                if dest_norm.startswith("0x"):
                    dest_norm = dest_norm[2:]
                dest_norm = dest_norm.replace(":", "")
                self._issuer_to_reticulum[node_id] = dest_norm
                if self.config.auto_peer_discovery and self.config.auto_peer_discovery_from_attestation:
                    self._maybe_add_peer(dest_norm, source="attestation")

    async def _emit_fork_incident(self, *, remote_issuer: str, seq: int) -> None:
        key = (remote_issuer, int(seq))
        if key in self._fork_incidents_emitted:
            return
        self._fork_incidents_emitted.add(key)

        hashes = sorted(self.store.list_hashes_by_issuer_seq(remote_issuer, int(seq)))
        material = f"fork|{remote_issuer}|{seq}|{','.join(hashes)}".encode()
        digest = hashlib.sha256(material).hexdigest()[:16]

        now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        head = self.store.get_contiguous_head(self.issuer)
        head_hash = head[1] if head else None

        fact = {
            "schema": "aegis.spine.fact.incident.v1",
            "fact_id": f"inc_{digest}",
            "incident_id": f"inc_fork_{digest}",
            "origin": self.issuer,
            "escalation_level": "integrity_violation",
            "outcome": "ongoing",
            "trigger": {
                "hypothesis": "spine_fork_detected",
                "initial_confidence": 1.0,
                "timestamp": now,
                "source_satellite": "spine",
                "report_id": f"rep_fork_{digest}",
            },
            "affected_runs": [],
            "anchor_actions": ["investigate"],
            "ledger": {
                "local_ledger_root": None,
                "spine_head_hash": head_hash,
            },
            "evidence": {
                "forensics_bundle_hash": None,
                "artifact_pointer_hashes": [],
            },
            "issued_at": now,
            "updated_at": now,
            # Extension fields (allowed by spec).
            "spine": {
                "kind": "fork",
                "forked_issuer": remote_issuer,
                "forked_seq": int(seq),
                "conflicting_envelope_hashes": hashes,
            },
        }

        # Never let incident emission break ingestion.
        with suppress(Exception):
            await self.publish_fact(fact)

    async def _emit_prev_mismatch_incident(
        self,
        *,
        remote_issuer: str,
        seq: int,
        expected_prev_envelope_hash: str | None,
        observed_prev_envelope_hash: str | None,
    ) -> None:
        key = (remote_issuer, int(seq))
        if key in self._prev_mismatch_incidents_emitted:
            return
        self._prev_mismatch_incidents_emitted.add(key)

        expected = str(expected_prev_envelope_hash or "")
        observed = str(observed_prev_envelope_hash or "")
        material = f"prev_mismatch|{remote_issuer}|{seq}|{expected}|{observed}".encode()
        digest = hashlib.sha256(material).hexdigest()[:16]

        now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        head = self.store.get_contiguous_head(self.issuer)
        head_hash = head[1] if head else None

        fact = {
            "schema": "aegis.spine.fact.incident.v1",
            "fact_id": f"inc_{digest}",
            "incident_id": f"inc_prev_mismatch_{digest}",
            "origin": self.issuer,
            "escalation_level": "integrity_violation",
            "outcome": "ongoing",
            "trigger": {
                "hypothesis": "spine_prev_hash_mismatch",
                "initial_confidence": 1.0,
                "timestamp": now,
                "source_satellite": "spine",
                "report_id": f"rep_prev_mismatch_{digest}",
            },
            "affected_runs": [],
            "anchor_actions": ["investigate"],
            "ledger": {
                "local_ledger_root": None,
                "spine_head_hash": head_hash,
            },
            "evidence": {
                "forensics_bundle_hash": None,
                "artifact_pointer_hashes": [],
            },
            "issued_at": now,
            "updated_at": now,
            "spine": {
                "kind": "prev_mismatch",
                "forked_issuer": remote_issuer,
                "forked_seq": max(int(seq) - 1, 0),
                "observed_seq": int(seq),
                "expected_prev_envelope_hash": expected_prev_envelope_hash,
                "observed_prev_envelope_hash": observed_prev_envelope_hash,
            },
        }

        with suppress(Exception):
            await self.publish_fact(fact)

    def _observe_sender_mapping(self, *, issuer: str, sender: str) -> None:
        # If we receive a valid signed envelope from a Reticulum destination, we can
        # treat that as verification of the issuer<->destination binding.
        if not sender:
            return
        if sender.startswith("inproc_"):
            return
        if len(sender) < 16:
            # likely a link_id or other ephemeral identifier
            return
        self._issuer_to_reticulum[issuer] = sender
        if self.config.auto_peer_discovery and self.config.auto_peer_discovery_from_sender:
            self._maybe_add_peer(sender, source="sender")

    async def _maybe_set_announce_app_data(self, obj: dict[str, Any]) -> None:
        setter = getattr(self.host, "set_announce_app_data", None)
        if setter is None:
            return
        # Announce app_data should be small and uncompressed.
        raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        await setter(raw)

    async def _publish_self_node_attestation(self) -> None:
        # Publish a minimal node_attestation with a Reticulum destination hash binding.
        addr = self.address
        if addr.startswith("inproc_"):
            return

        now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        digest = hashlib.sha256(f"na|{self.issuer}|{addr}|{now}".encode()).hexdigest()[:16]

        fact: dict[str, Any] = {
            "schema": "aegis.spine.fact.node_attestation.v1",
            "fact_id": f"na_{digest}",
            "node_id": self.issuer,
            "system_attestation": {
                "nixos_system_hash": None,
                "nixos_config_hash": None,
                "kernel_version": "unknown",
                "aegis_daemon_version": "unknown",
                "boot_timestamp": None,
                "hardware_id": None,
                "cpu_model": None,
                "attested_at": now,
            },
            "tpm_quote": None,
            "issued_at": now,
            # Extension field per reticulum profile spec.
            "transports": {
                "reticulum": {
                    "profile": "aegis.spine.reticulum.v1",
                    "destination_hash": "0x" + addr,
                    "announce_period_secs": int(self.config.announce_period_secs),
                    "supports": ["envelopes", "heads", "sync"],
                }
            },
        }

        await self.publish_fact(fact)

    def _normalize_peer(self, peer: str) -> str:
        value = str(peer or "").strip().lower()
        if value.startswith("0x"):
            value = value[2:]
        return value.replace(":", "").replace(" ", "")

    def _peer_in_allowlist(self, peer: str) -> bool:
        if not self.config.peer_allowlist:
            return True
        peer_norm = self._normalize_peer(peer)
        for allowed in self.config.peer_allowlist:
            if peer_norm == self._normalize_peer(allowed):
                return True
        return False

    def _load_peerbook(self) -> None:
        path = self._peerbook_path
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
        except Exception:
            logger.debug("Failed to read peerbook at %s", path)
            return

        peers = data.get("peers")
        if isinstance(peers, list):
            for peer in peers:
                if isinstance(peer, str):
                    self._add_peer(peer, persist=False, source="peerbook")

        mapping = data.get("issuer_map")
        if isinstance(mapping, dict):
            for issuer, dest in mapping.items():
                if not isinstance(dest, str):
                    continue
                dest_norm = self._normalize_peer(dest)
                if dest_norm:
                    self._issuer_to_reticulum[str(issuer)] = dest_norm

    def _persist_peerbook(self) -> None:
        if not self.config.peerbook_enabled:
            return
        self._peerbook_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "peers": list(self.config.peers),
            "issuer_map": dict(self._issuer_to_reticulum),
        }
        tmp_path = self._peerbook_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        tmp_path.replace(self._peerbook_path)

    def _maybe_add_peer(self, peer: str, *, source: str) -> None:
        if not self.config.auto_peer_discovery:
            return
        if not self._peer_in_allowlist(peer):
            return
        self._add_peer(peer, persist=self.config.peerbook_enabled, source=source)

    def _add_peer(self, peer: str, *, persist: bool, source: str) -> bool:
        peer_norm = self._normalize_peer(peer)
        if not peer_norm:
            return False
        existing_norm = {self._normalize_peer(p) for p in self.config.peers}
        if peer_norm in existing_norm:
            return False
        if self.config.peerbook_max_peers > 0 and len(self.config.peers) >= self.config.peerbook_max_peers:
            self._audit_event("drop", reason="peerbook_full", peer=peer_norm, source=source)
            return False
        self.config.peers.append(peer_norm)
        if persist:
            self._persist_peerbook()
        self._audit_event("peer_add", peer=peer_norm, source=source)
        return True

    def _peer_allowed(self, peer: str) -> bool:
        if not self.config.peer_allowlist:
            return True
        return self._peer_in_allowlist(peer)

    def _issuer_allowed(self, issuer: str) -> bool:
        if not self.config.trusted_issuers:
            return True
        if issuer in self.config.trusted_issuers:
            return True
        return bool(self.config.accept_unknown_issuers)

    def _check_unknown_issuer_quota(self, issuer: str) -> tuple[bool, str]:
        # Unknown issuer quotas only apply when we have a trust bundle configured.
        if not self.config.trusted_issuers:
            return True, "ok"
        if issuer in self.config.trusted_issuers:
            return True, "ok"

        if self.config.unknown_issuer_max_envelopes_per_issuer > 0:
            count = self.store.count_by_issuer(issuer)
            if count >= self.config.unknown_issuer_max_envelopes_per_issuer:
                return False, "unknown_issuer_quota_per_issuer"

        if self.config.unknown_issuer_max_total_envelopes > 0:
            total_unknown = self.store.count_excluding_issuers(self.config.trusted_issuers)
            if total_unknown >= self.config.unknown_issuer_max_total_envelopes:
                return False, "unknown_issuer_quota_total"

        return True, "ok"

    def _rate_limit_peer(self, peer: str, *, size_bytes: int) -> bool:
        self._maybe_gc_peer_buckets()
        if self.config.inbound_bytes_per_sec > 0:
            bucket = self._inbound_bytes.get(peer)
            if bucket is None:
                bucket = TokenBucket.create(
                    rate_per_sec=float(self.config.inbound_bytes_per_sec),
                    capacity=float(self.config.inbound_bytes_burst),
                )
                self._inbound_bytes[peer] = bucket
            else:
                self._inbound_bytes.move_to_end(peer)
            if self.config.peer_bucket_max_entries > 0:
                while len(self._inbound_bytes) > self.config.peer_bucket_max_entries:
                    self._inbound_bytes.popitem(last=False)
            if not bucket.consume(float(size_bytes)):
                return False

        if self.config.inbound_messages_per_sec > 0:
            bucket = self._inbound_msgs.get(peer)
            if bucket is None:
                bucket = TokenBucket.create(
                    rate_per_sec=float(self.config.inbound_messages_per_sec),
                    capacity=float(self.config.inbound_messages_burst),
                )
                self._inbound_msgs[peer] = bucket
            else:
                self._inbound_msgs.move_to_end(peer)
            if self.config.peer_bucket_max_entries > 0:
                while len(self._inbound_msgs) > self.config.peer_bucket_max_entries:
                    self._inbound_msgs.popitem(last=False)
            if not bucket.consume(1.0):
                return False

        return True

    def _rate_limit_revocation_peer(self, peer: str, *, size_bytes: int) -> bool:
        self._maybe_gc_peer_buckets()
        if self.config.revocation_bytes_per_sec > 0:
            bucket = self._revocation_inbound_bytes.get(peer)
            if bucket is None:
                bucket = TokenBucket.create(
                    rate_per_sec=float(self.config.revocation_bytes_per_sec),
                    capacity=float(self.config.revocation_bytes_burst),
                )
                self._revocation_inbound_bytes[peer] = bucket
            else:
                self._revocation_inbound_bytes.move_to_end(peer)
            if self.config.peer_bucket_max_entries > 0:
                while len(self._revocation_inbound_bytes) > self.config.peer_bucket_max_entries:
                    self._revocation_inbound_bytes.popitem(last=False)
            if not bucket.consume(float(size_bytes)):
                return False

        if self.config.revocation_messages_per_sec > 0:
            bucket = self._revocation_inbound_msgs.get(peer)
            if bucket is None:
                bucket = TokenBucket.create(
                    rate_per_sec=float(self.config.revocation_messages_per_sec),
                    capacity=float(self.config.revocation_messages_burst),
                )
                self._revocation_inbound_msgs[peer] = bucket
            else:
                self._revocation_inbound_msgs.move_to_end(peer)
            if self.config.peer_bucket_max_entries > 0:
                while len(self._revocation_inbound_msgs) > self.config.peer_bucket_max_entries:
                    self._revocation_inbound_msgs.popitem(last=False)
            if not bucket.consume(1.0):
                return False

        return True

    def _maybe_gc_peer_buckets(self) -> None:
        interval = float(self.config.peer_bucket_gc_interval_secs)
        if interval <= 0:
            return

        now = time.monotonic()
        if now - self._last_peer_bucket_gc < interval:
            return
        self._last_peer_bucket_gc = now

        ttl = float(self.config.peer_bucket_ttl_secs)
        if ttl <= 0:
            return

        cutoff = now - ttl
        for buckets in (
            self._inbound_bytes,
            self._inbound_msgs,
            self._revocation_inbound_bytes,
            self._revocation_inbound_msgs,
        ):
            while buckets:
                _k, bucket = next(iter(buckets.items()))
                if bucket.updated_at >= cutoff:
                    break
                buckets.popitem(last=False)

    def _is_revocation_envelope(self, parsed: object) -> bool:
        if not isinstance(parsed, SignedEnvelope):
            return False
        fact_schema = str((parsed.fact or {}).get("schema") or "")
        return fact_schema.endswith("revocation.v1")

    def _enforce_revocation_guards(
        self,
        *,
        sender: str,
        size_bytes: int,
        bypass_rate_limit: bool,
    ) -> tuple[bool, str]:
        max_bytes = int(self.config.revocation_max_bytes)
        if max_bytes > 0 and size_bytes > max_bytes:
            return False, "revocation_size_cap"
        if bypass_rate_limit and not self._rate_limit_revocation_peer(sender, size_bytes=size_bytes):
            return False, "revocation_rate_limited"
        return True, "ok"

    async def _maybe_request_catchup(self, *, peer: str, issuer: str, remote_seq: int) -> None:
        if issuer == self.issuer:
            # Don't sync our own chain from others.
            return

        local = self.store.get_contiguous_head(issuer)
        local_seq = local[0] if local is not None else -1
        if remote_seq <= local_seq:
            return

        now = time.monotonic()
        key = (peer, issuer)
        last = self._sync_last_request.get(key, 0.0)
        if now - last < self.config.sync_cooldown_secs:
            return
        self._sync_last_request[key] = now

        from_seq = local_seq + 1
        to_seq = remote_seq
        self._sync_targets[key] = to_seq
        await self._send_sync_request(peer=peer, issuer=issuer, from_seq=from_seq, to_seq=to_seq)

    async def _send_sync_request(self, *, peer: str, issuer: str, from_seq: int, to_seq: int) -> None:
        host_budget = self.config.host_max_payload_bytes or 400
        req = SyncRequest(
            schema="aegis.spine.sync_request.v1",
            issuer=issuer,
            from_seq=from_seq,
            to_seq=to_seq,
            max_bytes=min(self.config.max_sync_bytes, host_budget),
        )
        await self._send(peer, req.to_dict(), priority=1)

    def _should_forward_envelope(self, envelope_obj: dict[str, Any]) -> bool:
        fact_schema = str((envelope_obj.get("fact") or {}).get("schema") or "")

        if self.config.forward_fact_schema_allowlist and fact_schema not in self.config.forward_fact_schema_allowlist:
            return False
        if self.config.forward_fact_schema_denylist and fact_schema in self.config.forward_fact_schema_denylist:
            return False

        if fact_schema.endswith("heartbeat.v1"):
            return self.config.forward_heartbeats
        return True

    def _forward_envelope(self, envelope_obj: dict[str, Any], *, exclude_peer: str) -> None:
        priority = self._priority_for_obj(envelope_obj)
        payload = self._encode(envelope_obj)

        peers = [p for p in self.config.peers if p != exclude_peer]
        if self.config.forward_fanout > 0:
            peers = peers[: self.config.forward_fanout]

        for peer in peers:
            self._audit_event(
                "forward",
                from_peer=exclude_peer,
                to_peer=peer,
                envelope_hash=str(envelope_obj.get("envelope_hash") or ""),
                issuer=str(envelope_obj.get("issuer") or ""),
                seq=int(envelope_obj.get("seq") or -1),
                fact_schema=str((envelope_obj.get("fact") or {}).get("schema") or ""),
                priority=priority,
            )
            self._enqueue(peer, payload, priority=priority)

    def _audit_event(self, kind: str, **fields: Any) -> None:
        if not self._audit:
            return
        # Never let audit logging affect transport behavior.
        with suppress(Exception):
            self._audit.append({"kind": kind, **fields})


def create_adapter(config: ReticulumAdapterConfig | None = None) -> ReticulumAdapter:
    return ReticulumAdapter(config or ReticulumAdapterConfig())
