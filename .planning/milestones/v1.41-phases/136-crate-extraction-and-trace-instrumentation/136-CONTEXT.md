# Phase 136: Crate Extraction And Trace Instrumentation - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 136 owns two coupled outcomes: extract the evolution subsystem and CLI surface out of `swarm-runtime` into dedicated workspace crates, and add structured tracing plus optional OTLP export to the critical runtime path without regressing the current binaries.

</domain>

<decisions>
## Implementation Decisions

### Extract By Ownership, Then Re-Export Stable Entrypoints
- `swarm-runtime` should keep agents, HTTP surfaces, ingest, service wiring, and dispatcher ownership.
- The evolution-heavy modules (`drafting.rs`, `mutation.rs`, `evolution.rs`, `selection.rs`, `portfolio.rs`, `governance_prep.rs`, `canary.rs`, `promotion.rs`, `strategy.rs`, `evidence.rs`) should move behind a new `swarm-evolution` crate, with `swarm-runtime` re-exporting the public harness types needed by current callers.
- The CLI code path is already isolated behind `swarm_runtime::cli`; extracting it to `swarm-cli` should preserve the existing `swarmctl` binary shape while removing the 4K+ line `cli/core.inc` from runtime ownership.

### Land Tracing On The True Critical Path, Not Peripheral Helpers
- The repo currently has almost no `#[instrument]` coverage on the required hot-path functions; the only existing span seam discovered in this pass is a manual `.instrument(...)` usage in `ingest.rs`.
- Phase 136 should instrument the required functions directly and carry the existing correlation ID as `trace_id` so downstream logs and optional OTLP export stay aligned.

### Keep OTLP Optional And CLI-Owned
- The existing binaries initialize stdout JSON tracing today.
- The least disruptive Phase 136 shape is to add an optional OTLP endpoint flag through the extracted CLI crate while preserving the current stdout JSON default when no endpoint is configured.

</decisions>

<code_context>
## Existing Code Insights

### Evolution Scope Is Large But Already File-Partitioned
- The target evolution files sum to roughly 27.4K lines in `swarm-runtime`, with the heaviest modules currently `drafting.rs` (3692 lines), `mutation.rs` (3114), `evolution.rs` (2495), `evidence.rs` (2351), and `promotion.rs` (2304).
- That size argues for crate extraction by moving file ownership largely intact first, then cleaning imports and re-exports, rather than trying to refactor internals mid-move.

### CLI Extraction Has A Clean Binary Seam
- `crates/swarm-runtime/src/bin/swarmctl.rs` is only a thin wrapper over `swarm_runtime::cli::dispatch::run`.
- The real CLI surface lives in `crates/swarm-runtime/src/cli/core.inc` (~4383 lines) and depends on many runtime and evolution harness types, so the CLI crate should likely depend on both `swarm-runtime` and `swarm-evolution`.

### Tracing Coverage Is Minimal Today
- A repo-wide search across the targeted crates found only one existing `.instrument(...)` call near `crates/swarm-runtime/src/ingest.rs:1979`.
- The required Phase 136 instrumentation will be new work rather than cleanup of an already-structured tracing layer.

</code_context>

<specifics>
## Specific Ideas

- Create `crates/swarm-evolution` and move the ten evolution-centric modules there with public re-exports so existing runtime/tests keep compiling incrementally.
- Create `crates/swarm-cli` and move the current CLI args/dispatch implementation there, leaving `src/bin/swarmctl.rs` as a thin wrapper over the new crate.
- Add a shared tracing initialization helper usable from both binaries, with optional OTLP exporter setup only when the CLI flag is present.
- Instrument the required hot-path functions with stable `trace_id` fields derived from the current correlation ID instead of inventing a second trace identifier.

</specifics>

<deferred>
## Deferred Ideas

- Wider OpenTelemetry ecosystem integration beyond the optional OTLP exporter remains future work.
- Deep internal API cleanup inside the evolution modules should wait until after the first extraction lands and compiles cleanly.

</deferred>
