# Phase 237: Release Build Hardening - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to explicit release-profile hardening for shipped
release binaries: deciding the panic strategy, enabling overflow checks, and
proving the workspace still builds the operator/runtime binaries in release
mode. It does not yet change token semantics or add HTTP throttling.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Add a workspace-level `[profile.release]` in the root [Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/Cargo.toml) so release hardening is explicit instead of relying on Cargo defaults.
- Follow the active milestone requirement and set `panic = "abort"` with
  `overflow-checks = true` for release builds.
- Add a repo-owned verification script that proves the effective compiler cfg
  for the shipped `swarm-runtime` binaries instead of relying only on static
  inspection of `Cargo.toml`.

### Constraint To Acknowledge
- The live codebase still uses `catch_unwind` in
  [crates/swarm-guard/src/lib.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-guard/src/lib.rs)
  and [crates/swarm-runtime/src/dispatcher.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/dispatcher.rs).
  With `panic = "abort"` those recovery paths stop recovering panics in release
  and instead terminate the process. That is an explicit product hardening
  tradeoff for this milestone rather than an accidental side effect.

### Deferred To Later Phases
- Token expiry and rotation mechanics remain Phase 238.
- Per-source HTTP rate limiting remains Phase 239.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- The root [Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/Cargo.toml) owns the workspace profile configuration and currently has no explicit `[profile.release]`.
- The shipped runtime binaries are `swarm_detect` and `swarmctl` from
  [crates/swarm-runtime/src/bin](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/bin).
- The repo already keeps small verification helpers under
  [tools](/Users/connor/Medica/backbay/standalone/swarm-team-six/tools).

### Established Patterns
- GSD verification for build-hardening work is usually command-driven and
  recorded in a phase verification artifact rather than via dedicated Rust
  tests.
- `cargo rustc --release -- --print cfg` exposes the effective `panic` and
  `overflow_checks` cfg for a specific compiled target and can therefore prove
  the final release profile that Cargo actually applies.

### Integration Points
- `Cargo.toml`
- `tools`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`

</code_context>

<specifics>
## Specific Ideas

- Add `panic = "abort"` and `overflow-checks = true` under `[profile.release]`.
- Add a verification script that checks both shipped runtime binaries for the
  expected release cfg values.
- Clean any incidental warnings that make the release-proof output noisy if
  they are encountered while building the hardened targets.

</specifics>

<deferred>
## Deferred Ideas

- LTO, allocator selection, and per-crate process isolation for different panic
  strategies are not part of this milestone phase.

</deferred>
