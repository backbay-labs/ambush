"""Rate limiting primitives (token buckets)."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class TokenBucket:
    rate_per_sec: float
    capacity: float
    tokens: float
    updated_at: float

    @classmethod
    def create(cls, *, rate_per_sec: float, capacity: float | None = None) -> "TokenBucket":
        rate = float(rate_per_sec)
        cap = float(capacity if capacity is not None else max(rate, 0.0))
        now = time.monotonic()
        return cls(rate_per_sec=rate, capacity=cap, tokens=cap, updated_at=now)

    def _refill(self, now: float) -> None:
        if self.rate_per_sec <= 0:
            self.updated_at = now
            return
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_sec)
        self.updated_at = now

    def consume(self, amount: float) -> bool:
        if amount <= 0:
            return True
        now = time.monotonic()
        self._refill(now)
        if self.rate_per_sec <= 0:
            return False
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

