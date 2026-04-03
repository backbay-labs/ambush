"""Orca Whirlpool client stubs."""

from __future__ import annotations

from dataclasses import dataclass

from cyntra.core.scheduler.routing import OrcaConfig


class OrcaClientError(RuntimeError):
    """Raised when Orca client is not configured."""


@dataclass
class OrcaClient:
    """Stub client for Orca Whirlpool swaps."""

    config: OrcaConfig

    def _ensure_configured(self) -> None:
        if not self.config.enabled or not self.config.pool_id:
            raise OrcaClientError("Orca client not configured")

    def swap(self, *, amount_in: float, mint_in: str, mint_out: str) -> str:
        self._ensure_configured()
        raise NotImplementedError("Orca swap not implemented")
