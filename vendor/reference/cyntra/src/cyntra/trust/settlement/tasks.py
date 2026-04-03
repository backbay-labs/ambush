"""Verifier task runner scaffolding."""

from __future__ import annotations

from dataclasses import dataclass

from cyntra.trust.settlement.solana import AegisFeeMarketClient, SolanaClientError


@dataclass
class VerifierTaskRunner:
    """Poll, claim, and submit attestations for verifier tasks."""

    fee_market: AegisFeeMarketClient

    def run_once(self) -> None:
        try:
            self.fee_market._ensure_configured()
        except SolanaClientError:
            return
        raise NotImplementedError("Verifier task runner not implemented")
