# Phase 71: Cryptographic Foundation -- Context

## What This Phase Does

Port battle-tested hush-core cryptographic primitives from `vendor/reference/clawdstrike/libs/hush-core/src/` into `crates/swarm-crypto/`, replacing the minimal 249-line stub implementation with production-quality Ed25519 signing, RFC 8785 canonical JSON, RFC 6962 Merkle trees, and SHA-256 hashing.

## Why It Matters

The current `swarm-crypto` has a hand-rolled canonical JSON serializer (just `serde_json::to_value` re-serialization, not RFC 8785 compliant), no Merkle tree support, and a simplified signer that derives keys from secret material rather than supporting proper keypair generation. Downstream crates (`swarm-spine` in Phase 73, approval ledgers in v1.24) need real cryptographic primitives for signed envelopes, checkpoint co-signatures, and inclusion proofs.

## Decisions

- **Port from hush-core vendor reference, not arc** -- ClawdStrike crypto primitives are security-domain-native and already vendored locally
- **Do NOT port receipt.rs** -- swarm-spine already has its own receipt types; only signing, canonical, merkle, hashing, and error modules are needed
- **Do NOT port Keccak-256** -- CRYPTO-04 requires SHA-256 only; skip sha3 dependency to keep the crate lean
- **Do NOT port TPM module** -- not needed for single-node runtime
- **Preserve backward compatibility** -- existing imports from `swarm-runtime` (`CryptoError`, `Ed25519Signer`, `DetachedSignature`, `canonical_json_bytes`, `canonical_json_string`, `normalize_canonical_json`, `sha256_hex`, `verify_detached_signature`) must continue to compile
- **Add `hex`, `ryu`, `rand_core` workspace dependencies** -- required by hush-core signing and canonical modules
- **Use hush-core's `hex` crate** instead of hand-rolled hex encode/decode -- simpler, tested, standard

## Downstream Consumers

```
swarm-runtime/src/evidence.rs imports:
  CryptoError, DetachedSignature, Ed25519Signer, canonical_json_bytes,
  normalize_canonical_json, sha256_hex, verify_detached_signature

swarm-runtime/src/review_workbench.rs imports:
  CryptoError, Ed25519Signer, canonical_json_bytes, canonical_json_string,
  normalize_canonical_json, sha256_hex, verify_detached_signature
```

These names must remain as public re-exports from `swarm_crypto` after the port.

## Source Files

| Vendor File | Lines | Target Module | Requirement |
|---|---|---|---|
| `error.rs` | 65 | `swarm-crypto/src/error.rs` | Foundation for all modules |
| `hashing.rs` | 154 | `swarm-crypto/src/hashing.rs` | CRYPTO-04 |
| `canonical.rs` | 224 | `swarm-crypto/src/canonical.rs` | CRYPTO-02 |
| `merkle.rs` | 312 | `swarm-crypto/src/merkle.rs` | CRYPTO-03 |
| `signing.rs` | 337 | `swarm-crypto/src/signing.rs` | CRYPTO-01 |
