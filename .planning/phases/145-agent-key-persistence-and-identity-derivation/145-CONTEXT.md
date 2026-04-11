# Phase 145: Agent Key Persistence And Identity Derivation - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase adds the first durable agent-identity layer for the runtime: repo-owned config for key storage, file-backed Ed25519 key persistence, restart-safe identity derivation, and propagation of that identity into the signed pheromone and audited response surfaces.

</domain>

<decisions>
## Implementation Decisions

### Identity Storage
- Add a repo-owned `identity.agent_key_dir` config surface rather than hiding key files under an unrelated runtime or audit path.
- Persist one raw 32-byte Ed25519 seed per runtime agent slot in a file-backed store under the configured directory.
- Resolve relative key directories from the loaded config path so checked-in configs stay portable across environments.

### Runtime Wiring
- Keep the existing ephemeral constructors for unit tests, but add persisted-identity constructors for the real serve-mode runtime.
- Use the derived `swarm:ed25519:<hex>` string as the runtime-facing agent ID in serve mode so action requests, governance receipts, and audit trails naturally carry the stable identity.
- Centralize identity derivation and file-backed load-or-create behavior in one runtime module instead of duplicating key logic across agents.

### Deposit Compatibility
- Extend `PheromoneDeposit` with explicit `agent_identity` and `agent_role` metadata so signed deposits retain both the stable cryptographic identity and the role information other agents rely on.
- Include the new identity metadata in the deposit signing payload so the persisted identity is cryptographically bound to the deposit content.
- Update Stalker and Weaver to use the explicit deposit role metadata instead of brittle string-prefix checks.

### Claude's Discretion
- File naming and on-disk key format details are at Claude's discretion as long as the store remains deterministic, restart-safe, and future-compatible with registry and rotation work in Phase 146.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-crypto/src/signing.rs` already provides Ed25519 key and signature helpers, but runtime agents currently use `ed25519_dalek` directly.
- `crates/swarm-runtime/src/config.rs` already resolves config-relative filesystem paths for secrets and evolution artifacts.
- `crates/swarm-pheromone/src/substrate.rs` already defines the canonical pheromone deposit signing payload and verification path.

### Established Patterns
- Runtime agents currently generate ephemeral keys inside their constructors and expose a `VerifyingKey` through `SwarmAgent::identity()`.
- The serve-mode runtime is composed in `crates/swarm-runtime/src/bin/swarm_detect.rs`, which is the correct place to inject persisted identities for real agent instances.
- Repo-owned config validation lives in `crates/swarm-core/src/config.rs`, with runtime-facing loading and path resolution in `crates/swarm-runtime/src/config.rs`.

### Integration Points
- `crates/swarm-runtime/src/bin/swarm_detect.rs` owns agent registration for Whisker, Tom, Pounce, Kitten, Sphinx, Stalker, and Weaver.
- `crates/swarm-runtime/src/detection/pipeline.rs` and `crates/swarm-runtime/src/stalker_agent.rs` create and sign deposits.
- `crates/swarm-policy/src/lib.rs`, `crates/swarm-response/src/lib.rs`, and `crates/swarm-runtime/src/lib.rs` carry the request and audit structures that need the stable identity to flow through receipts and audits.

</code_context>

<specifics>
## Specific Ideas

No user-specific UX requirements surfaced for this phase. The important constraint is to keep the change Rust-native and bounded so Phase 146 can layer registry admission and rotation on top of the same persisted identity seam.

</specifics>

<deferred>
## Deferred Ideas

- Full agent registry admission, continuity proofs, and historical key retention belong to Phase 146.
- Multi-instance deposit rejection and distributed identity synchronization belong to the later governance phases.

</deferred>
