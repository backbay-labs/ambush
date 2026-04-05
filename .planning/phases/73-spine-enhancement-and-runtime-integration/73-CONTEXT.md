# Phase 73 Context: Spine Enhancement And Runtime Integration

## What This Phase Does

Two independent work streams:

1. Port signed envelope, checkpoint statement, and hash chain modules from `vendor/reference/clawdstrike/libs/spine/src/` into `crates/swarm-spine/`, wiring them to swarm-crypto primitives instead of upstream hush-core. This gives swarm-spine cryptographic commitment capabilities for downstream governance milestones.

2. Wire the guard pipeline (from Phase 72's swarm-guard) into swarm-runtime's response authorization path so every response action passes through guards before execution. Guard rejection must prevent the response adapter from firing and record the rejection reason in the audit trail.

## Why It Matters

swarm-spine currently has audit records, replay bundles, incidents, and investigations but no cryptographic signing or checkpoint verification. Approval ledgers (v1.24) need signed envelopes and checkpoint co-signatures. The guard pipeline (Phase 72) is built but not yet integrated into the runtime -- response actions still bypass guards entirely.

## Decisions (Locked)

- **Port from clawdstrike spine vendor references** -- envelope.rs, checkpoint.rs, chain.rs from `vendor/reference/clawdstrike/libs/spine/src/`
- **Adapt hush_core references to swarm_crypto** -- The vendor code imports `hush_core::{canonicalize_json, sha256, sha256_hex, Hash, Keypair, PublicKey, Signature}`. Phase 71 ports these into swarm-crypto. The spine modules must use swarm-crypto equivalents.
- **Add spine error module** -- Port `error.rs` from vendor spine, adapting `hush_core::Error` to `swarm_crypto::CryptoError`
- **Rename issuer prefix from "aegis" to "swarm"** -- Issuer strings should be `swarm:ed25519:<hex>` not `aegis:ed25519:<hex>`
- **Add `chrono` workspace dependency** -- envelope.rs needs RFC 3339 timestamp validation. Add chrono to workspace deps.
- **Keep existing swarm-spine modules untouched** -- incident.rs, investigation.rs, store.rs stay as-is. New modules are additive.
- **swarm-spine re-exports envelope and checkpoint public APIs** -- The lib.rs re-exports key functions for downstream consumers
- **Guard pipeline integration point: before response execution, after policy approval** -- In `audit_authorize_and_execute_instrumented`, after policy says Allow/RequireHuman but before `self.response.execute()`, run the guard pipeline. If any guard rejects, produce `AuditResponseRecord::GuardRejected` instead of executing.
- **Add `AuditResponseRecord::GuardRejected` variant** -- New variant preserving guard name and rejection reason for audit
- **SwarmRuntime gains a guard pipeline field** -- The generic `SwarmRuntime<P, E>` becomes `SwarmRuntime<P, E, G>` with an optional guard pipeline, or the guard pipeline is a concrete type to avoid breaking all existing callers. Prefer Option<GuardPipeline> as a field with a builder method.

## Deferred Ideas

- Trust bundles and quorum validation from vendor `trust.rs` (not needed until v1.24)
- Attestation and SPIFFE bindings from vendor `attestation.rs` (not needed)
- NATS transport from vendor `nats_transport.rs` (not needed)
- Marketplace facts and spine from vendor (not applicable to STS)
- Hash normalization utilities from vendor `hash.rs` (defer unless needed by envelope/checkpoint)

## Claude's Discretion

- Whether to port vendor `hash.rs` (normalize_hash_hex, policy_index_key) -- only if envelope or chain modules need it
- Internal organization of spine error module -- can merge with existing error patterns or keep standalone
- Whether `SwarmRuntime` guard integration uses a new generic parameter or a concrete `Option<GuardPipeline>` field
- Guard timing instrumentation -- whether to add guard_elapsed_us to RuntimeExecutionReport

## Source Files

| Vendor File | Lines | Target | Requirement |
|---|---|---|---|
| `spine/src/error.rs` | 51 | `swarm-spine/src/spine_error.rs` | Foundation |
| `spine/src/envelope.rs` | 263 | `swarm-spine/src/envelope.rs` | SPINE-01 |
| `spine/src/checkpoint.rs` | 153 | `swarm-spine/src/checkpoint.rs` | SPINE-02 |
| `spine/src/chain.rs` | 388 | `swarm-spine/src/chain.rs` | SPINE-01 (chain verification) |

## Downstream Impact

- swarm-runtime gains guard pipeline integration (GUARD-06)
- swarm-spine gains envelope and checkpoint APIs for v1.24 approval ledgers
- swarm-runtime's AuditResponseRecord gets a new GuardRejected variant -- this may require updates to downstream match arms
