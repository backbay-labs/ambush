# Phase 135: Serve-Surface Security And Panic Elimination - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 135 hardens the production-facing runtime surface. The owned outcomes are: removing the known panic-prone detector defaults and demo-proof unwraps, adding bearer auth to `/v2/api/*` in a way that preserves the existing platform API key model, and enabling optional TLS with optional client-certificate enforcement on both shipped HTTP servers. This phase does not own the CLI extraction or tracing work in Phase 136.

</domain>

<decisions>
## Implementation Decisions

### Replace Panic-Prone Detector Defaults With Direct Safe Construction
- The detector `Default` impls in `swarm-whisker` currently call `from_profile(Profile::default())` and panic if validation ever rejects the built-in defaults.
- The smaller, safer change is to construct each detector directly from the same default component values instead of routing through fallible validation inside `Default`.
- Fallible `from_profile(...)` remains the correct path for repo-configured overrides, while `Default` becomes panic-free and keeps the current runtime behavior.

### Remove Demo-Proof `.expect()` Calls By Propagating Guarded Missing-State Errors
- `crates/swarm-runtime/src/ingest.rs` still has two `.expect("validated above")` calls on the demo proof-export path.
- The handler already performs an unresolved-approval check before entering that loop, so the correct hardening move is to preserve that fail-closed behavior with explicit `Option` handling instead of relying on `expect`.

### Add Bearer Auth As An Outer Gate Around The Existing Platform API Key Layer
- Phases 132-133 already established scoped platform API keys carried in `x-api-key`.
- Phase 135 should add an outer bearer-token requirement on `/v2/api/*` consistent with the operator surface middleware shape, while preserving the existing platform key scope model inside the route group.
- Reusing `operator_surface.auth.token_env` and `operator_surface.auth.operator_id` is the least invasive configuration seam because it avoids introducing a second env-token contract just for the detect server.

### Treat Optional TLS As A Shared Serve Helper For Both Binaries
- `swarm_detect` and `swarmctl serve` both currently call `axum::serve(listener, app)` directly.
- Optional TLS with optional client-cert enforcement should land as a shared runtime helper, not two separate ad hoc server loops.
- The helper must be able to load PEM files, fail closed on invalid TLS material, and preserve graceful shutdown behavior for both servers.

</decisions>

<code_context>
## Existing Code Insights

### Panic Paths Are Narrow And Localized
- The detector panic paths are concentrated in the `Default` impls for `SuspiciousProcessTreeDetector`, `DnsExfiltrationDetector`, `LateralMovementDetector`, `CredentialAccessDetector`, `SuspiciousScriptingDetector`, `PersistenceDetector`, `SupplyChainDetector`, and `NetworkConnectDetector`.
- The remaining non-test `.expect()` calls called out by requirements are both in the demo proof-export loop inside `crates/swarm-runtime/src/ingest.rs`.

### Operator Bearer Auth Already Exists As A Proven Middleware Shape
- `crates/swarm-runtime/src/http/core.inc` already has `require_bearer_auth(...)` that enforces `Authorization: Bearer <token>` against the configured operator env token.
- `crates/swarm-runtime/src/ingest.rs` already layers `require_platform_api_key_auth(...)` over `/v2/api/*`.
- Phase 135 can reuse the operator bearer-auth contract and then keep the existing `PlatformApiPrincipal` insertion for API-key scope handling.

### TLS Is Not Yet Modeled In Config Or Shared Serve Wiring
- There is no current `SwarmConfig.tls` field, and neither shipped server path uses `tokio-rustls`.
- `swarm_detect` binds its listener directly in `crates/swarm-runtime/src/bin/swarm_detect.rs`, while `LocalOperatorSurface::serve()` does the same in `crates/swarm-runtime/src/http/core.inc`.
- This means TLS is the largest design surface in the phase and needs one shared helper plus config plumbing.

</code_context>

<specifics>
## Specific Ideas

- Replace the eight detector `Default` impls with direct safe constructors.
- Replace the remaining demo-proof `.expect()` calls with explicit `Option` handling.
- Add a bearer-auth middleware layer for `/v2/api/*` that reuses the operator token env contract and records authenticated identity in tracing.
- Add focused tests proving:
  - detector defaults remain usable without panic
  - platform API now requires both bearer auth and a valid platform API key
  - health and ingest surfaces stay outside the bearer gate
- If the TLS helper lands in this phase, add config coverage plus HTTP-server tests for TLS startup and client-cert enforcement.

</specifics>

<deferred>
## Deferred Ideas

- Crate extraction and OTLP tracing remain Phase 136.
- Certificate issuance, rotation, and Kubernetes ingress termination policy are out of scope for this phase.

</deferred>
