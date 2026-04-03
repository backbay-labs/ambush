"""Solana Attestation Service gatekeeper."""

from __future__ import annotations

from dataclasses import dataclass

from cyntra.core.scheduler.routing import SettlementConfig


@dataclass
class SASGatekeeper:
    """Gatekeeper for verifier credentials."""

    config: SettlementConfig

    def is_allowed(self, wallet: str) -> bool:
        if self.config.allowlist:
            return wallet in set(self.config.allowlist)
        if not self.config.sas_enabled:
            return True
        raise NotImplementedError("SAS verification not implemented")
