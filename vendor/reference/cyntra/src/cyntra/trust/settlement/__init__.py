"""Settlement scaffolding for Solana-based verifier economy.

Provides:
- AnchorPy clients for Aegis programs
- Oracle price guardrails
- SAS (Solana Attestation Service) gating
- Orca DEX integration
"""

# Lazy imports to handle optional dependencies

def __getattr__(name: str):
    if name in ("OracleGuardrails", "OracleCheckResult"):
        from cyntra.trust.settlement.oracle import OracleGuardrails, OracleCheckResult
        return {"OracleGuardrails": OracleGuardrails, "OracleCheckResult": OracleCheckResult}[name]
    
    elif name == "SASGatekeeper":
        from cyntra.trust.settlement.sas import SASGatekeeper
        return SASGatekeeper
    
    elif name in ("SolanaClient", "SolanaClientError", "SolanaProgramIds",
                  "AegisRegistryClient", "AegisStakingClient", "AegisFeeMarketClient"):
        from cyntra.trust.settlement import solana as _solana
        return getattr(_solana, name)
    
    elif name in ("AnchorConfig", "AegisRegistryAnchor", "AegisStakingAnchor",
                  "AegisFeeMarketAnchor", "is_anchor_available"):
        from cyntra.trust.settlement import anchor_client as _anchor
        return getattr(_anchor, name)
    
    elif name == "VerifierTaskRunner":
        from cyntra.trust.settlement.tasks import VerifierTaskRunner
        return VerifierTaskRunner
    
    elif name in ("OrcaClient", "OrcaClientError"):
        from cyntra.trust.settlement.orca import OrcaClient, OrcaClientError
        return {"OrcaClient": OrcaClient, "OrcaClientError": OrcaClientError}[name]
    
    elif name == "TreasuryBot":
        from cyntra.trust.settlement.treasury import TreasuryBot
        return TreasuryBot
    
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Oracle
    "OracleGuardrails",
    "OracleCheckResult",
    # SAS
    "SASGatekeeper",
    # Solana (basic)
    "SolanaClient",
    "SolanaClientError",
    "SolanaProgramIds",
    "AegisRegistryClient",
    "AegisStakingClient",
    "AegisFeeMarketClient",
    # Solana (Anchor)
    "AnchorConfig",
    "AegisRegistryAnchor",
    "AegisStakingAnchor",
    "AegisFeeMarketAnchor",
    "is_anchor_available",
    # Tasks
    "VerifierTaskRunner",
    # Orca
    "OrcaClient",
    "OrcaClientError",
    # Treasury
    "TreasuryBot",
]
