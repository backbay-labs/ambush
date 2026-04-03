"""
Aegis Spine (truth log replication).

This package implements transport-agnostic handling of Spine Layer 4 objects:
- Signed envelopes (`aegis.spine.envelope.v1`)
- Head announcements (`aegis.spine.head_announcement.v1`)
- Catch-up sync (`aegis.spine.sync_request.v1` / `aegis.spine.sync_response.v1`)

Reticulum support is provided as a pluggable transport adapter (see `reticulum/`).
"""

# Lazy imports to keep optional deps (Reticulum) out of import time.
def __getattr__(name: str):
    if name in (
        "Ed25519Keypair",
        "issuer_from_public_key_hex",
        "parse_issuer",
        "sha256_hex_prefixed",
        "canonical_bytes_for_envelope",
        "canonical_bytes_without_signature",
        "compute_envelope_hash",
        "sign_envelope",
        "verify_envelope_signature",
        "sign_by_issuer",
        "verify_signature_by_issuer",
    ):
        from cyntra.trust.spine import crypto as _crypto
        return getattr(_crypto, name)
    if name in (
        "SignedEnvelope",
        "HeadAnnouncement",
        "SyncRequest",
        "SyncResponse",
        "parse_spine_object",
    ):
        from cyntra.trust.spine import schemas as _schemas
        return getattr(_schemas, name)
    if name in ("EnvelopeStore", "EnvelopeIngestResult"):
        from cyntra.trust.spine.store.envelopes import EnvelopeStore, EnvelopeIngestResult
        return {"EnvelopeStore": EnvelopeStore, "EnvelopeIngestResult": EnvelopeIngestResult}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # crypto
    "Ed25519Keypair",
    "issuer_from_public_key_hex",
    "parse_issuer",
    "sha256_hex_prefixed",
    "canonical_bytes_for_envelope",
    "canonical_bytes_without_signature",
    "compute_envelope_hash",
    "sign_envelope",
    "verify_envelope_signature",
    "sign_by_issuer",
    "verify_signature_by_issuer",
    # schemas
    "SignedEnvelope",
    "HeadAnnouncement",
    "SyncRequest",
    "SyncResponse",
    "parse_spine_object",
    # store
    "EnvelopeStore",
    "EnvelopeIngestResult",
]
