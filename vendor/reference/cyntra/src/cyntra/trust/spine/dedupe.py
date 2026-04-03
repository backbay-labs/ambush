"""Small bounded dedupe caches for transport/gateway loops."""

from __future__ import annotations

import time
from collections import OrderedDict


class DedupeCache:
    def __init__(self, *, max_items: int = 50_000, ttl_secs: float = 3600.0):
        self._max_items = int(max_items)
        self._ttl = float(ttl_secs)
        self._items: OrderedDict[str, float] = OrderedDict()

    def seen(self, key: str) -> bool:
        now = time.monotonic()
        self._gc(now)

        if key in self._items:
            self._items.move_to_end(key)
            return True

        self._items[key] = now
        self._items.move_to_end(key)
        if len(self._items) > self._max_items:
            self._items.popitem(last=False)
        return False

    def _gc(self, now: float) -> None:
        if self._ttl <= 0:
            return
        while self._items:
            k, ts = next(iter(self._items.items()))
            if now - ts <= self._ttl:
                break
            self._items.pop(k, None)

