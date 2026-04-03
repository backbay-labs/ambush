"""
Multi-chain attestation pipeline for CNP Phase 2.

Provides attestation to:
- Rekor (Sigstore transparency log)
- EAS (Ethereum Attestation Service on Base)
- Solana Aegis (future)
"""

from cyntra.trust.attestation.schemas import (
    AttestationRef,
    RekorRef,
    EasRef,
    SolanaRef,
    AttestationBundle,
    EasReceiptData,
    is_rust_backend,
)

# Lazy imports for modules with optional dependencies
def __getattr__(name: str):
    if name == "RekorClient":
        from cyntra.trust.attestation.rekor import RekorClient
        return RekorClient
    elif name == "AttestationPipeline":
        from cyntra.trust.attestation.pipeline import AttestationPipeline
        return AttestationPipeline
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "AttestationRef",
    "RekorRef",
    "EasRef",
    "SolanaRef",
    "AttestationBundle",
    "EasReceiptData",
    "RekorClient",
    "AttestationPipeline",
    "is_rust_backend",
]
