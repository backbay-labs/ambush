"""Security and cryptography.

Security primitives, attestation, and trust infrastructure.

Sub-packages:
    primitives/     Core cryptography (merkle, envelope, registry)
    attestation/    Code/output attestation
    shields/        Security shields
    aegis/          Aegis security system
    membrane/       Boundary protection
    federation/     Multi-party trust
    settlement/     Settlement layer
    network/        Network protocols
    ledger/         Audit ledger
"""

# Re-export primitives for backward compatibility
from cyntra.trust.primitives import (
    AttestationRef,
    VerificationResult,
    AttestationRegistry,
    EventMerkleTree,
    MerkleProof,
)

# Lazy imports for modules with optional dependencies (nacl, etc.)
def __getattr__(name: str):
    if name in ("ProofBundleManifest", "ProofBundleEntry", "build_bundle_manifest"):
        from cyntra.trust.primitives import bundle as _bundle
        return getattr(_bundle, name)
    elif name in ("BundlePointer", "DataAvailabilityStore", "LocalBundleStore"):
        from cyntra.trust.primitives import availability as _availability
        return getattr(_availability, name)
    elif name == "finalize_run_artifacts":
        from cyntra.trust.primitives import pipeline as _pipeline
        return _pipeline.finalize_run_artifacts
    elif name in (
        "EncryptionEnvelope", "SealedKey", "create_envelope",
        "generate_data_key", "generate_x25519_keypair", "seal_data_key",
        "unwrap_envelope_key", "wrap_key", "unwrap_key"
    ):
        from cyntra.trust.primitives import envelope as _envelope
        return getattr(_envelope, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # Primitives
    "AttestationRef",
    "VerificationResult",
    "AttestationRegistry",
    "EventMerkleTree",
    "MerkleProof",
    "ProofBundleManifest",
    "ProofBundleEntry",
    "build_bundle_manifest",
    "BundlePointer",
    "DataAvailabilityStore",
    "LocalBundleStore",
    "finalize_run_artifacts",
    "EncryptionEnvelope",
    "SealedKey",
    "create_envelope",
    "generate_data_key",
    "generate_x25519_keypair",
    "seal_data_key",
    "unwrap_envelope_key",
    "wrap_key",
    "unwrap_key",
]
