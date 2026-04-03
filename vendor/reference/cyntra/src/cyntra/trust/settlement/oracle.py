"""Oracle guardrails for price-based parameters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cyntra.core.scheduler.routing import OracleConfig


@dataclass
class OracleCheckResult:
    """Result of an oracle guardrail check."""

    allowed: bool
    reason: str | None = None
    metadata: dict[str, Any] | None = None


class OracleGuardrails:
    """Validate oracle prices against safety constraints."""

    def __init__(self, config: OracleConfig) -> None:
        self.config = config

    def validate(
        self,
        *,
        price: float,
        age_seconds: int,
        deviation_bps: int,
    ) -> OracleCheckResult:
        if not self.config.enabled:
            return OracleCheckResult(allowed=True)

        if age_seconds > self.config.max_age_seconds:
            return OracleCheckResult(
                allowed=False,
                reason="stale_oracle",
                metadata={"age_seconds": age_seconds},
            )

        if deviation_bps > self.config.max_deviation_bps:
            return OracleCheckResult(
                allowed=False,
                reason="excessive_deviation",
                metadata={"deviation_bps": deviation_bps},
            )

        if self.config.min_price is not None and price < self.config.min_price:
            return OracleCheckResult(
                allowed=False,
                reason="below_min_price",
                metadata={"price": price},
            )

        if self.config.max_price is not None and price > self.config.max_price:
            return OracleCheckResult(
                allowed=False,
                reason="above_max_price",
                metadata={"price": price},
            )

        return OracleCheckResult(allowed=True)
