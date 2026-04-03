"""Treasury automation scaffolding."""

from __future__ import annotations

from dataclasses import dataclass

from cyntra.core.scheduler.routing import TreasuryConfig
from cyntra.trust.settlement.orca import OrcaClient, OrcaClientError


@dataclass
class TreasuryBot:
    """Stub treasury bot for buybacks and distributions."""

    config: TreasuryConfig
    orca_client: OrcaClient

    def run_once(self) -> None:
        if not self.config.enabled or not self.config.buyback_enabled:
            return
        try:
            self.orca_client._ensure_configured()
        except OrcaClientError:
            return
        raise NotImplementedError("Treasury buyback automation not implemented")
