from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol


class SpinePlaneHost(Protocol):
    @property
    def is_available(self) -> bool: ...

    async def start(self) -> None: ...
    async def stop(self) -> None: ...

    async def publish(self, payload: bytes, *, channel: str | None = None) -> None: ...

    def on_message(self, handler: Callable[[bytes, str, str | None], Awaitable[None]]) -> None: ...


@dataclass
class SpinePlaneHostConfig:
    data_dir: str = ".cyntra/spine-gateway"
    name: str = "plane"


class InProcessPlaneHost:
    """Minimal in-process pub/sub host (tests only)."""

    def __init__(self, config: SpinePlaneHostConfig):
        self.config = config
        self._handler: Callable[[bytes, str, str | None], Awaitable[None]] | None = None
        self._running = False

    @property
    def is_available(self) -> bool:
        return True

    def on_message(self, handler: Callable[[bytes, str, str | None], Awaitable[None]]) -> None:
        self._handler = handler

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    async def publish(self, payload: bytes, *, channel: str | None = None) -> None:
        if not self._running or self._handler is None:
            return
        await self._handler(payload, self.config.name, channel)


async def gather_best_effort(*aws: Awaitable[None]) -> None:
    results = await asyncio.gather(*aws, return_exceptions=True)
    _ = results
