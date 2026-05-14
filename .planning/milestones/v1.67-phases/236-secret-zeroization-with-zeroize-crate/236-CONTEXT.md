# Phase 236: Secret Zeroization With zeroize Crate - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to zeroizing resolved plaintext secrets from the shipped
runtime secret seams after they are loaded into memory, without yet changing
the broader bearer-token lifecycle contract that belongs to Phases 238-239.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Add one shared `SecretString` wrapper in `swarm_core::config` backed by the
  `zeroize` crate so secret-bearing config and auth state stop carrying raw
  `String` values.
- Zeroize temporary file/env resolution buffers in `swarm-runtime::config`
  before they escape the resolver.
- Reuse the same secret wrapper for operator/platform bearer expectations and
  Providence context-token signing material so env-backed auth state also stops
  storing raw heap strings.

### Deferred To Later Phases
- Token expiry, rotation metadata, and reloadable auth-state lifecycles belong
  to Phase 238.
- Per-source HTTP request throttling belongs to Phase 239.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-runtime/src/config.rs` already centralizes `@secret:` file/env
  resolution and `reload_secrets_only()`, so the zeroization seam can be added
  in one place.
- `crates/swarm-response` adapters and Providence notification delivery already
  consume the shared config structs directly, which makes a config-level secret
  wrapper visible everywhere those secrets travel.

### Established Patterns
- Secret-bearing config currently lives in `swarm_core::config::response` as
  plain `String` and `Option<String>` fields for response adapters, SIEM
  forwarders, notification channels, and request-signature secrets.
- Operator and platform bearer auth currently snapshot env vars into in-memory
  expected-token strings inside `http/core.inc` and
  `ingest/platform_api.rs`.

### Integration Points
- `crates/swarm-core/src/config`
- `crates/swarm-runtime/src/config.rs`
- `crates/swarm-runtime/src/http/core.inc`
- `crates/swarm-runtime/src/ingest/platform_api.rs`
- `crates/swarm-response/src/http_edr.rs`
- `crates/swarm-response/src/webhook.rs`
- `crates/swarm-response/src/siem.rs`
- `crates/swarm-response/src/notification.rs`
- `crates/swarm-runtime/src/providence.rs`

</code_context>

<specifics>
## Specific Ideas

- Introduce `SecretString` as a serde-transparent, zeroize-on-drop config type
  with a redacted `Debug` implementation and `Deref<Target = str>`.
- Convert only the fields that actually hold plaintext secret material:
  outbound auth tokens, HMAC secrets, and in-memory bearer expectations.
- Add focused tests proving the wrapper zeroizes on explicit `zeroize()` and
  that resolved config/auth seams still work with the new type.

</specifics>

<deferred>
## Deferred Ideas

- Moving operator auth from env-only token material to richer repo-owned secret
  references and expiry metadata is intentionally deferred to Phase 238.

</deferred>
