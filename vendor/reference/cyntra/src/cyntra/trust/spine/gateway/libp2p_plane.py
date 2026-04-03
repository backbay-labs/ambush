from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyntra.trust.spine.gateway.transport import SpinePlaneHost

logger = logging.getLogger(__name__)

SPINE_PUBSUB_TOPIC = "/aegis/spine/1.0.0"

_LIBP2P_AVAILABLE = False
try:
    import multiaddr  # type: ignore
    from libp2p import new_host  # type: ignore
    from libp2p.crypto.ed25519 import create_new_key_pair as ed25519_keypair  # type: ignore
    from libp2p.peer.peerinfo import info_from_p2p_addr  # type: ignore
    from libp2p.pubsub import floodsub, gossipsub  # type: ignore

    _LIBP2P_AVAILABLE = True
except Exception:
    _LIBP2P_AVAILABLE = False


@dataclass
class LibP2PPlaneConfig:
    private_key_path: Path | None = None
    listen_addrs: list[str] = field(default_factory=lambda: ["/ip4/0.0.0.0/tcp/0"])
    bootstrap_peers: list[str] = field(default_factory=list)
    pubsub_type: str = "gossipsub"
    topic: str = SPINE_PUBSUB_TOPIC
    name: str = "libp2p"


class LibP2PPlaneHost(SpinePlaneHost):
    def __init__(self, config: LibP2PPlaneConfig | None = None):
        self.config = config or LibP2PPlaneConfig()
        self._handler: Callable[[bytes, str, str | None], Awaitable[None]] | None = None
        self._host = None
        self._pubsub = None
        self._sub = None
        self._task: asyncio.Task | None = None
        self._running = False

    @property
    def is_available(self) -> bool:
        return _LIBP2P_AVAILABLE

    def on_message(self, handler: Callable[[bytes, str, str | None], Awaitable[None]]) -> None:
        self._handler = handler

    async def start(self) -> None:
        if self._running:
            return
        if not _LIBP2P_AVAILABLE:
            raise RuntimeError("py-libp2p not available; install with `pip install -e '.[network]'`")

        self._running = True

        key_pair = ed25519_keypair()
        self._host = new_host(key_pair=key_pair)

        if self.config.pubsub_type == "gossipsub":
            self._pubsub = gossipsub.GossipSub([self._host], heartbeat_interval=1.0)
        else:
            self._pubsub = floodsub.FloodSub([self._host])

        for addr in self.config.listen_addrs:
            ma = multiaddr.Multiaddr(addr)
            await self._host.get_network().listen(ma)

        for peer_addr in self.config.bootstrap_peers:
            try:
                ma = multiaddr.Multiaddr(peer_addr)
                peer_info = info_from_p2p_addr(ma)
                await self._host.connect(peer_info)
            except Exception:
                logger.debug("Failed connecting bootstrap peer %s", peer_addr, exc_info=True)

        self._sub = await self._pubsub.subscribe(self.config.topic)
        self._task = asyncio.create_task(self._loop_messages(self._sub))

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None

        if self._pubsub is not None and self._sub is not None:
            with suppress(Exception):
                await self._pubsub.unsubscribe(self.config.topic)

        if self._host is not None:
            with suppress(Exception):
                await self._host.close()

        self._host = None
        self._pubsub = None
        self._sub = None

    async def publish(self, payload: bytes, *, channel: str | None = None) -> None:
        if not self._running or self._pubsub is None:
            return
        await self._pubsub.publish(channel or self.config.topic, payload)

    async def _loop_messages(self, subscription: Any) -> None:
        async for message in subscription:
            if not self._handler:
                continue
            try:
                sender = getattr(message.from_id, "pretty", lambda: "")()
            except Exception:
                sender = ""
            try:
                await self._handler(message.data, sender, self.config.topic)
            except Exception:
                logger.debug("libp2p handler failed", exc_info=True)
