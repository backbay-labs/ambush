# Phase 238: Rotatable Token Lifecycle - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to bearer-token lifecycle behavior for the shipped
operator and platform HTTP surfaces: carrying token expiry metadata through
repo-owned config, re-reading bearer secrets without restart, and surfacing
clear status when a token is expired or rotated away. It does not add request
rate limiting or broader secret-management infrastructure.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Extend the repo-owned operator auth config with optional
  `token_expires_at_ms` metadata for both the legacy single-principal path and
  the multi-principal contract.
- Stop snapshotting long-lived bearer token plaintext in operator and platform
  auth state. Instead, validate the configured env names at startup and re-read
  the current token value from the environment on each protected request.
- Surface token lifecycle context through operator and platform status
  responses so expired principals are visible without digging through logs.

### Constraint To Acknowledge
- Rotation in this milestone means swapping the configured env var value and
  having the runtime observe that change on the next request. It does not add a
  separate token store, hot config-reload requirement, or multi-version grace
  window.

### Deferred To Later Phases
- Per-source HTTP rate limiting remains Phase 239.
- External token issuance, revocation ledgers, and multi-node token sync remain
  future work.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- [crates/swarm-core/src/config/operator.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-core/src/config/operator.rs) already owns the operator principal and platform API auth contract.
- [crates/swarm-runtime/src/http/core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc) and [crates/swarm-runtime/src/ingest/platform_api.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/platform_api.rs) already centralize protected-request auth.
- The operator and platform status payloads already have repo-owned JSON envelopes that can carry additional lifecycle context.

### Established Patterns
- The config layer validates repo-owned auth contracts before runtime startup.
- Runtime auth middleware returns explicit JSON errors and already distinguishes unauthorized versus forbidden request paths.
- Status surfaces are the preferred operator-visible audit seam for runtime state that should be visible without enabling debug logs.

### Integration Points
- `crates/swarm-core/src/config/operator.rs`
- `crates/swarm-core/src/config/validation.rs`
- `crates/swarm-runtime/src/http/core.inc`
- `crates/swarm-runtime/src/ingest/platform_api.rs`
- `crates/swarm-runtime/src/service/types.rs`
- `crates/swarm-runtime/src/service/runtime_service.rs`

</code_context>

<specifics>
## Specific Ideas

- Add optional `token_expires_at_ms` fields and validation for both legacy and
  principal-list auth config.
- Re-read operator bearer tokens, platform bearer tokens, and Providence
  context-token secrets from env on each request.
- Include per-principal expiry state in status responses and add warning text
  when configured bearer tokens are already expired.

</specifics>

<deferred>
## Deferred Ideas

- No restart-free API-key rotation in this phase.
- No token hashing, grace periods, or lease-based revocation cache in this
  milestone slice.

</deferred>
