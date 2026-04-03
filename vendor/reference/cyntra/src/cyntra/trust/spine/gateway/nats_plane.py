from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field

from cyntra.trust.spine.gateway.transport import SpinePlaneHost

logger = logging.getLogger(__name__)

_NATS_AVAILABLE = False
try:
    import nats  # type: ignore

    _NATS_AVAILABLE = True
except Exception:
    _NATS_AVAILABLE = False


@dataclass
class NATSPlaneConfig:
    servers: list[str] = field(default_factory=lambda: ["nats://127.0.0.1:4222"])
    # Default publish subject if caller doesn't provide an explicit channel.
    subject: str = "aegis.spine.v1"
    # Default-deny-ish: subscribe only to the "bridgeable spine" subset by default.
    subscribe_subjects: list[str] = field(
        default_factory=lambda: [
            "aegis.spine.envelope.*.v1",
            "aegis.spine.heads.v1",
        ]
    )
    # Best-effort sender identity propagation via message headers.
    sender_header: str = "X-Aegis-Sender"
    sender: str | None = None
    name: str = "nats"


class NATSPlaneHost(SpinePlaneHost):
    def __init__(self, config: NATSPlaneConfig | None = None):
        self.config = config or NATSPlaneConfig()
        self._handler: Callable[[bytes, str, str | None], Awaitable[None]] | None = None
        self._nc = None
        self._subs: list[object] = []
        self._running = False

    @property
    def is_available(self) -> bool:
        return _NATS_AVAILABLE

    def on_message(self, handler: Callable[[bytes, str, str | None], Awaitable[None]]) -> None:
        self._handler = handler

    async def start(self) -> None:
        if self._running:
            return
        if not _NATS_AVAILABLE:
            raise RuntimeError("NATS not available; install with `pip install -e '.[nats]'`")
        self._running = True

        self._nc = await nats.connect(servers=self.config.servers)

        async def _cb(msg) -> None:
            if not self._handler:
                return
            try:
                subject = str(getattr(msg, "subject", ""))
                sender = self.config.sender or self.config.name
                headers = getattr(msg, "headers", None)
                if headers:
                    try:
                        wanted = self.config.sender_header.lower()
                        for k in headers:
                            if str(k).lower() == wanted:
                                sender = str(headers[k] or sender)
                                break
                    except Exception:
                        pass
                await self._handler(msg.data, sender=sender, channel=subject or None)
            except Exception:
                logger.debug("NATS handler failed", exc_info=True)

        subjects = list(self.config.subscribe_subjects) or [self.config.subject]
        self._subs = [await self._nc.subscribe(s, cb=_cb) for s in subjects]

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._nc is not None:
            with suppress(Exception):
                await self._nc.drain()
            with suppress(Exception):
                await self._nc.close()
        self._nc = None
        self._subs = []

    async def publish(self, payload: bytes, *, channel: str | None = None) -> None:
        if not self._running or self._nc is None:
            return
        headers = None
        if self.config.sender_header:
            headers = {self.config.sender_header: self.config.sender or self.config.name}
        await self._nc.publish(channel or self.config.subject, payload, headers=headers)
