from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from cyntra.trust.spine.gateway.transport import SpinePlaneHost
from cyntra.trust.spine.reticulum.host import ReticulumHost, ReticulumHostConfig, create_host

logger = logging.getLogger(__name__)


@dataclass
class ReticulumPlaneConfig:
    mode: str = "reticulum"  # "reticulum" or "inproc"
    data_dir: Path = field(default_factory=lambda: Path(".cyntra/spine-gateway/reticulum"))
    peers: list[str] = field(default_factory=list)
    app_name: str = "aegis"
    aspects: list[str] = field(default_factory=lambda: ["spine"])


class ReticulumPlaneHost(SpinePlaneHost):
    def __init__(self, config: ReticulumPlaneConfig | None = None):
        self.config = config or ReticulumPlaneConfig()
        self._host: ReticulumHost = create_host(
            ReticulumHostConfig(
                mode=self.config.mode,
                data_dir=self.config.data_dir,
                app_name=self.config.app_name,
                aspects=list(self.config.aspects),
                peers=list(self.config.peers),
            )
        )
        self._handler: Callable[[bytes, str, str | None], Awaitable[None]] | None = None
        self._running = False

    @property
    def is_available(self) -> bool:
        return self._host.is_available

    def on_message(self, handler: Callable[[bytes, str, str | None], Awaitable[None]]) -> None:
        self._handler = handler

    async def start(self) -> None:
        if self._running:
            return
        self._running = True

        async def _on_msg(payload: bytes, sender: str) -> None:
            if self._handler is None:
                return
            await self._handler(payload, sender, None)

        self._host.on_message(_on_msg)
        await self._host.start()

    async def stop(self) -> None:
        self._running = False
        await self._host.stop()

    async def publish(self, payload: bytes, *, channel: str | None = None) -> None:
        # Reticulum is not pubsub; we broadcast to configured peers.
        _ = channel
        if not self._running:
            return
        for peer in list(self.config.peers):
            try:
                await self._host.send(peer, payload)
            except Exception:
                logger.debug("Reticulum send failed to %s", peer, exc_info=True)
