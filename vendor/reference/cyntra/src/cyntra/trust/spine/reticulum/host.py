"""Reticulum host abstraction.

Reticulum is not a mandatory dependency of this repo. This module provides:
- An in-process host (used for tests and demos)
- A placeholder for an RNS-backed host (when Reticulum is installed)
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)


class ReticulumHost(Protocol):
    @property
    def is_available(self) -> bool: ...

    @property
    def address(self) -> str: ...

    async def start(self) -> None: ...
    async def stop(self) -> None: ...

    async def send(self, to: str, payload: bytes) -> None: ...

    def on_message(self, handler: Callable[[bytes, str], Awaitable[None]]) -> None: ...


@dataclass
class ReticulumHostConfig:
    """Transport config (v0.1).

    `mode`:
    - "inproc": in-process simulation (tests/demos)
    - "reticulum": real Reticulum via `RNS`
    """

    mode: str = "inproc"
    address: str | None = None
    peers: list[str] = field(default_factory=list)

    # Reticulum (RNS) specifics
    data_dir: Path | None = None
    rns_config_dir: Path | None = None
    identity_path: Path | None = None
    app_name: str = "aegis"
    aspects: list[str] = field(default_factory=lambda: ["spine"])
    require_shared_instance: bool = False
    announce_period_secs: int = 300
    path_request_timeout_secs: float = 15.0
    link_establish_timeout_secs: float = 15.0

    # MTU-aware framing (transport payload size)
    max_payload_bytes: int = 400
    fragmentation_enabled: bool = True
    reassembly_timeout_secs: float = 30.0
    reassembly_max_pending_messages: int = 256
    reassembly_max_pending_bytes: int = 5_000_000


class InProcessReticulumBus:
    """A simple in-process router keyed by `address`."""

    def __init__(self) -> None:
        self._hosts: dict[str, InProcessReticulumHost] = {}
        self._lock = asyncio.Lock()

    async def register(self, host: InProcessReticulumHost) -> None:
        async with self._lock:
            self._hosts[host.address] = host

    async def unregister(self, host: InProcessReticulumHost) -> None:
        async with self._lock:
            self._hosts.pop(host.address, None)

    async def deliver(self, sender: str, to: str, payload: bytes) -> None:
        async with self._lock:
            recipient = self._hosts.get(to)
        if recipient is None:
            logger.debug("Inproc drop: unknown peer %s", to)
            return
        await recipient._deliver(payload=payload, sender=sender)


_INPROC_BUS = InProcessReticulumBus()


class InProcessReticulumHost:
    def __init__(self, config: ReticulumHostConfig):
        self.config = config
        self._address = config.address or f"inproc_{secrets.token_hex(8)}"
        self._handler: Callable[[bytes, str], Awaitable[None]] | None = None
        self._running = False
        self._frag = _Fragmenter(config)

    @property
    def is_available(self) -> bool:
        return True

    @property
    def address(self) -> str:
        return self._address

    def on_message(self, handler: Callable[[bytes, str], Awaitable[None]]) -> None:
        self._handler = handler

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        await _INPROC_BUS.register(self)

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        await _INPROC_BUS.unregister(self)

    async def send(self, to: str, payload: bytes) -> None:
        for part in self._frag.fragment(payload):
            await _INPROC_BUS.deliver(sender=self.address, to=to, payload=part)

    async def _deliver(self, payload: bytes, sender: str) -> None:
        if not self._handler:
            return
        for msg in self._frag.reassemble(payload, sender):
            await self._handler(msg, sender)


class RNSDataPlaneHost:
    """Reticulum-backed Spine data plane host (RNS).

    Address semantics:
    - `address` is the destination hash (hex) for our inbound SINGLE destination.
    - `send(to, payload)` accepts either:
      - a destination hash hex string (preferred), or
      - a link id hex string (for reply traffic to unknown peers).
    """

    def __init__(self, config: ReticulumHostConfig):
        self.config = config
        self._handler: Callable[[bytes, str], Awaitable[None]] | None = None
        self._running = False
        self._address = config.address or "reticulum_unconfigured"
        self._loop: asyncio.AbstractEventLoop | None = None

        self._reticulum = None
        self._identity = None
        self._destination = None
        self._announce_task: asyncio.Task | None = None

        # Link management:
        # - links_by_id: link_id_hex -> link
        # - addr_to_link_id: destination_hash_hex -> link_id_hex
        # - link_peer_addr: link_id_hex -> destination_hash_hex (when known)
        self._links_by_id: dict[str, object] = {}
        self._addr_to_link_id: dict[str, str] = {}
        self._link_peer_addr: dict[str, str] = {}
        self._link_lock = asyncio.Lock()
        self._full_name = ""
        self._frag = _Fragmenter(config)

    @property
    def is_available(self) -> bool:
        try:
            import RNS  # noqa: F401
            return True
        except Exception:
            return False

    @property
    def address(self) -> str:
        return self._address

    def on_message(self, handler: Callable[[bytes, str], Awaitable[None]]) -> None:
        self._handler = handler

    async def set_announce_app_data(self, app_data: bytes | None) -> None:
        # Used by the adapter to piggyback head announcements onto RNS announces.
        self._announce_app_data = app_data

    async def start(self) -> None:
        if self._running:
            return

        try:
            import RNS
        except Exception as e:
            raise RuntimeError(
                "Reticulum (RNS) is not available. Install it with `pip install rns` "
                "or `pip install -e '.[reticulum]'` (if configured)."
            ) from e

        self._loop = asyncio.get_running_loop()

        base_dir = self.config.data_dir or Path(".cyntra/spine")
        base_dir.mkdir(parents=True, exist_ok=True)

        config_dir = self.config.rns_config_dir or (base_dir / "rns")
        config_dir.mkdir(parents=True, exist_ok=True)

        identity_path = self.config.identity_path or (base_dir / "rns_identity")
        identity_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._reticulum = RNS.Reticulum(
                configdir=str(config_dir),
                require_shared_instance=self.config.require_shared_instance,
            )
        except Exception as e:
            raise RuntimeError(
                "Failed to start Reticulum (RNS). "
                "If this is a sandboxed environment, Reticulum may not be permitted to open sockets. "
                "Otherwise, check your RNS config directory and interfaces."
            ) from e

        identity = None
        if identity_path.exists():
            try:
                identity = RNS.Identity.from_file(str(identity_path))
            except Exception:
                identity = None
        if identity is None:
            identity = RNS.Identity()
            # Identity persistence failure is non-fatal; the destination will change on restart.
            with suppress(Exception):
                identity.to_file(str(identity_path))
        self._identity = identity

        self._destination = RNS.Destination(
            identity,
            RNS.Destination.IN,
            RNS.Destination.SINGLE,
            self.config.app_name,
            *self.config.aspects,
        )

        self._full_name = ".".join([self.config.app_name, *self.config.aspects])
        self._address = RNS.hexrep(self._destination.hash, delimit=False)

        # Accept links from peers (required for request/response semantics).
        self._destination.set_link_established_callback(self._on_link_established)

        self._announce_app_data: bytes | None = None

        # Best-effort peer discovery for this app/aspects.
        with suppress(Exception):
            RNS.Transport.register_announce_handler(_AnnounceHandler(self._full_name, self))

        # Announce our destination so peers can discover us.
        with suppress(Exception):
            self._destination.announce(app_data=self._announce_app_data)

        self._running = True
        if self.config.announce_period_secs > 0:
            self._announce_task = asyncio.create_task(self._announce_loop())

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False

        if self._announce_task is not None:
            self._announce_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._announce_task
            self._announce_task = None

        # Tear down links (best-effort).
        links = list(self._links_by_id.values())
        self._links_by_id.clear()
        self._addr_to_link_id.clear()
        self._link_peer_addr.clear()
        for link in links:
            with suppress(Exception):
                link.teardown()

    async def send(self, to: str, payload: bytes) -> None:
        if not self._running:
            raise RuntimeError("RNS host is not running")

        if not to:
            raise ValueError("Missing destination address")

        # Fast path: send to an active link by id.
        async with self._link_lock:
            link = self._links_by_id.get(_normalize_hex(to))
        if link is not None:
            await self._send_via_link(link, payload)
            return

        # Otherwise treat `to` as a destination hash.
        await self._send_to_destination(_normalize_hex(to), payload)

    async def _announce_loop(self) -> None:
        assert self._destination is not None
        while self._running:
            try:
                await asyncio.sleep(self.config.announce_period_secs)
                self._destination.announce(app_data=self._announce_app_data)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    def _on_link_established(self, link: object) -> None:
        # Called by RNS from a worker thread.
        #
        # We install callbacks synchronously to avoid missing early packets, then
        # hand off bookkeeping to the asyncio loop.
        try:
            import RNS
        except Exception:
            return
        try:
            link_id_hex = RNS.hexrep(link.link_id, delimit=False)
        except Exception:
            link_id_hex = None

        if link_id_hex:
            try:
                link.set_packet_callback(self._make_link_packet_callback(link_id_hex))
                link.set_remote_identified_callback(self._make_remote_identified_callback(link_id_hex))
                link.set_link_closed_callback(self._make_link_closed_callback(link_id_hex))
            except Exception:
                pass

        try:
            if self._identity is not None:
                link.identify(self._identity)
        except Exception:
            pass

        loop = self._loop
        if loop is None:
            return
        loop.call_soon_threadsafe(self._register_link, link)

    def _register_link(self, link: object) -> None:
        # Runs on the asyncio loop thread.
        try:
            import RNS
        except Exception:
            return
        try:
            link_id_hex = RNS.hexrep(link.link_id, delimit=False)
        except Exception:
            return

        self._links_by_id[link_id_hex] = link

        try:
            link.set_packet_callback(self._make_link_packet_callback(link_id_hex))
            link.set_remote_identified_callback(self._make_remote_identified_callback(link_id_hex))
            link.set_link_closed_callback(self._make_link_closed_callback(link_id_hex))
        except Exception:
            pass

    def _make_remote_identified_callback(self, link_id_hex: str):
        def _cb(_link: object, remote_identity: object) -> None:
            loop = self._loop
            if loop is None:
                return
            loop.call_soon_threadsafe(self._on_remote_identified, link_id_hex, remote_identity)

        return _cb

    def _on_remote_identified(self, link_id_hex: str, remote_identity: object) -> None:
        # Runs on the asyncio loop thread.
        try:
            import RNS
        except Exception:
            return
        if not self._full_name:
            return
        try:
            dest_hash = RNS.Destination.hash_from_name_and_identity(self._full_name, remote_identity)
            peer_addr = RNS.hexrep(dest_hash, delimit=False)
        except Exception:
            return

        self._link_peer_addr[link_id_hex] = peer_addr
        self._addr_to_link_id[peer_addr] = link_id_hex

    def _make_link_packet_callback(self, link_id_hex: str):
        def _cb(data: bytes, _packet: object) -> None:
            loop = self._loop
            if loop is None:
                return
            loop.call_soon_threadsafe(self._deliver_from_link, link_id_hex, data)

        return _cb

    def _make_link_closed_callback(self, link_id_hex: str):
        def _cb(_link: object) -> None:
            loop = self._loop
            if loop is None:
                return
            loop.call_soon_threadsafe(self._drop_link_id, link_id_hex)

        return _cb

    def _drop_link_id(self, link_id_hex: str) -> None:
        link = self._links_by_id.pop(link_id_hex, None)
        _ = link
        peer_addr = self._link_peer_addr.pop(link_id_hex, None)
        if peer_addr:
            existing = self._addr_to_link_id.get(peer_addr)
            if existing == link_id_hex:
                self._addr_to_link_id.pop(peer_addr, None)

    def _deliver_from_link(self, link_id_hex: str, data: bytes) -> None:
        if not self._handler:
            return
        sender = self._link_peer_addr.get(link_id_hex, link_id_hex)
        for msg in self._frag.reassemble(data, sender):
            asyncio.create_task(self._handler(msg, sender))

    def _deliver_from_announce(self, sender: str, app_data: bytes) -> None:
        if not self._handler:
            return
        for msg in self._frag.reassemble(app_data, sender):
            asyncio.create_task(self._handler(msg, sender))

    async def _send_to_destination(self, dest_hash_hex: str, payload: bytes) -> None:
        link = await self._get_or_create_link(dest_hash_hex)
        await self._send_via_link(link, payload)

    async def _get_or_create_link(self, dest_hash_hex: str):
        try:
            import RNS
        except Exception as e:
            raise RuntimeError("Reticulum (RNS) not available") from e

        async with self._link_lock:
            existing_link_id = self._addr_to_link_id.get(dest_hash_hex)
            if existing_link_id:
                existing = self._links_by_id.get(existing_link_id)
                if existing is not None:
                    return existing

        dest_hash = bytes.fromhex(dest_hash_hex)
        identity = RNS.Identity.recall(dest_hash)

        if identity is None:
            with suppress(Exception):
                RNS.Transport.request_path(dest_hash)

            deadline = asyncio.get_running_loop().time() + self.config.path_request_timeout_secs
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.25)
                identity = RNS.Identity.recall(dest_hash)
                if identity is not None:
                    break

        if identity is None:
            raise RuntimeError(
                f"Unknown Reticulum destination {dest_hash_hex}. "
                "Wait for an announce, or ensure the peer is reachable and announcing."
            )

        destination = RNS.Destination(
            identity,
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            self.config.app_name,
            *self.config.aspects,
        )

        established = asyncio.get_running_loop().create_future()

        def _on_established(link_obj: object) -> None:
            loop = self._loop
            if loop is None:
                return
            loop.call_soon_threadsafe(lambda: (not established.done()) and established.set_result(link_obj))

        def _on_closed(link_obj: object) -> None:
            loop = self._loop
            if loop is None:
                return
            loop.call_soon_threadsafe(self._on_link_closed, link_obj)

        link = RNS.Link(destination, established_callback=_on_established, closed_callback=_on_closed)

        # Register immediately (link_id exists on request creation).
        link_id_hex = RNS.hexrep(link.link_id, delimit=False)
        async with self._link_lock:
            self._links_by_id[link_id_hex] = link
            self._addr_to_link_id[dest_hash_hex] = link_id_hex
            self._link_peer_addr[link_id_hex] = dest_hash_hex

        with suppress(Exception):
            link.set_packet_callback(self._make_link_packet_callback(link_id_hex))
            link.set_remote_identified_callback(self._make_remote_identified_callback(link_id_hex))

        # Reveal our identity so the peer can map this link to our destination hash.
        with suppress(Exception):
            if self._identity is not None:
                link.identify(self._identity)

        try:
            await asyncio.wait_for(established, timeout=self.config.link_establish_timeout_secs)
        except TimeoutError as e:
            raise RuntimeError(f"Timed out establishing link to {dest_hash_hex}") from e

        return link

    def _on_link_closed(self, link: object) -> None:
        # Runs on the asyncio loop thread.
        try:
            import RNS
        except Exception:
            return
        try:
            link_id_hex = RNS.hexrep(link.link_id, delimit=False)
        except Exception:
            return
        self._links_by_id.pop(link_id_hex, None)
        peer_addr = self._link_peer_addr.pop(link_id_hex, None)
        if peer_addr:
            existing = self._addr_to_link_id.get(peer_addr)
            if existing == link_id_hex:
                self._addr_to_link_id.pop(peer_addr, None)

    async def _send_via_link(self, link: object, payload: bytes) -> None:
        try:
            import RNS
        except Exception as e:
            raise RuntimeError("Reticulum (RNS) not available") from e

        # Packet send is synchronous; wrap it to keep host.send awaitable.
        parts = self._frag.fragment(payload)

        def _send() -> None:
            for part in parts:
                p = RNS.Packet(link, part, create_receipt=False)
                p.send()

        await asyncio.to_thread(_send)


class _AnnounceHandler:
    def __init__(self, full_name: str, host: RNSDataPlaneHost):
        self.aspect_filter = full_name
        self._host = host

    def received_announce(
        self,
        destination_hash: bytes,
        announced_identity: object,
        app_data: bytes | None,
        announce_packet_hash: bytes,
        is_path_response: bool,
    ) -> None:
        # Called from an RNS worker thread.
        _ = (announced_identity, announce_packet_hash, is_path_response)

        if app_data is None:
            return

        loop = self._host._loop
        if loop is None:
            return
        try:
            import RNS

            sender = RNS.hexrep(destination_hash, delimit=False)
        except Exception:
            return

        # Deliver app_data as a "message" to allow piggybacked head announcements.
        loop.call_soon_threadsafe(self._host._deliver_from_announce, sender, app_data)


def _normalize_hex(value: str) -> str:
    v = value.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    v = v.replace(":", "")
    v = v.replace(" ", "")
    return v


_FRAG_MAGIC = b"F1"
_FRAG_ID_LEN = 8
_FRAG_HEADER_LEN = 2 + _FRAG_ID_LEN + 2 + 2


class _Fragmenter:
    def __init__(self, config: ReticulumHostConfig):
        self._max_payload_bytes = int(config.max_payload_bytes)
        self._enabled = bool(config.fragmentation_enabled)
        self._timeout = float(config.reassembly_timeout_secs)
        self._max_pending_messages = int(config.reassembly_max_pending_messages)
        self._max_pending_bytes = int(config.reassembly_max_pending_bytes)

        self._pending: dict[tuple[str, str], tuple[float, int, dict[int, bytes]]] = {}
        self._pending_bytes = 0

    def fragment(self, payload: bytes) -> list[bytes]:
        if not self._enabled or self._max_payload_bytes <= 0 or len(payload) <= self._max_payload_bytes:
            return [payload]

        chunk_size = self._max_payload_bytes - _FRAG_HEADER_LEN
        if chunk_size <= 0:
            return [payload]

        msg_id = secrets.token_bytes(_FRAG_ID_LEN)
        msg_id_hex = msg_id.hex()
        total = (len(payload) + chunk_size - 1) // chunk_size
        if total > 0xFFFF:
            # Too many fragments; fall back to raw and let the underlying transport fail loudly.
            return [payload]

        parts: list[bytes] = []
        for idx in range(total):
            start = idx * chunk_size
            end = min(len(payload), (idx + 1) * chunk_size)
            chunk = payload[start:end]
            header = _FRAG_MAGIC + msg_id + total.to_bytes(2, "big") + idx.to_bytes(2, "big")
            parts.append(header + chunk)
        _ = msg_id_hex
        return parts

    def reassemble(self, payload: bytes, sender: str) -> list[bytes]:
        if not self._enabled:
            return [payload]
        if not payload.startswith(_FRAG_MAGIC) or len(payload) < _FRAG_HEADER_LEN:
            return [payload]

        msg_id_hex = payload[2 : 2 + _FRAG_ID_LEN].hex()
        total = int.from_bytes(payload[2 + _FRAG_ID_LEN : 2 + _FRAG_ID_LEN + 2], "big")
        idx = int.from_bytes(payload[2 + _FRAG_ID_LEN + 2 : 2 + _FRAG_ID_LEN + 4], "big")
        chunk = payload[_FRAG_HEADER_LEN:]

        if total <= 0 or idx < 0 or idx >= total:
            return []

        now = time.monotonic()
        self._gc(now)

        key = (sender, msg_id_hex)
        entry = self._pending.get(key)
        if entry is None:
            entry = (now, total, {})
            self._pending[key] = entry

        created_at, expected_total, parts = entry
        if expected_total != total:
            # Malformed/conflicting fragments; drop.
            self._pending.pop(key, None)
            return []

        if idx not in parts:
            parts[idx] = chunk
            self._pending_bytes += len(chunk)

        # Update last-seen timestamp by rewriting tuple.
        self._pending[key] = (now, expected_total, parts)

        # Enforce pending caps after the insert (prevents one oversized fragment from
        # temporarily bypassing the configured limits).
        self._gc(now)
        if key not in self._pending:
            return []

        if len(parts) < expected_total:
            return []

        # Complete message
        assembled = b"".join(parts[i] for i in range(expected_total))
        self._pending.pop(key, None)
        self._pending_bytes -= sum(len(c) for c in parts.values())
        _ = created_at
        return [assembled]

    def _gc(self, now: float) -> None:
        # Expire timed-out messages.
        expired = [k for k, (ts, _total, _parts) in self._pending.items() if now - ts > self._timeout]
        for k in expired:
            _ts, _total, parts = self._pending.pop(k)
            self._pending_bytes -= sum(len(c) for c in parts.values())

        # Enforce count/bytes ceilings by dropping oldest.
        if len(self._pending) <= self._max_pending_messages and self._pending_bytes <= self._max_pending_bytes:
            return

        items = sorted(self._pending.items(), key=lambda kv: kv[1][0])  # oldest first
        for k, (_ts, _total, parts) in items:
            if len(self._pending) <= self._max_pending_messages and self._pending_bytes <= self._max_pending_bytes:
                break
            self._pending.pop(k, None)
            self._pending_bytes -= sum(len(c) for c in parts.values())


def create_host(config: ReticulumHostConfig) -> ReticulumHost:
    if config.mode == "inproc":
        return InProcessReticulumHost(config)
    if config.mode == "reticulum":
        return RNSDataPlaneHost(config)
    raise ValueError(f"Unknown reticulum host mode: {config.mode}")
