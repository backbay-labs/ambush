//! Ingest HTTP surface, telemetry bridge runtime, and operator control plane.
//!
//! This crate holds the code that turns telemetry and operator requests into
//! calls on the composition root: the `axum` ingest router and its handlers, the
//! telemetry bridge registry that feeds them, the operator control plane, and
//! the anti-tamper and HTTP rate-limit surfaces they depend on.
//!
//! # Why this is a separate crate (SPLIT-05, phase 282)
//!
//! `ingest/` is the largest single block left in `swarm-runtime` and it is the
//! reason the root still linked `axum`. Every consumer of the root -- including
//! the ones that never serve HTTP at all, such as `swarm-runtime-workbench` and
//! the replay lane -- compiled the whole transport surface to get at the
//! composition types next to it.
//!
//! The direction of the edge is the whole point:
//!
//! ```text
//! swarm-ingest-runtime -> swarm-runtime    (normal dependency, this crate's manifest)
//! swarm-runtime -> swarm-ingest-runtime    (dev-dependency ONLY, never a normal one)
//! ```
//!
//! The modules here read back into the root for the collaborators they serve --
//! `service`, `providence`, `evolution`, `runtime_events`, `tom_agent` -- and
//! that is fine, because it is the forward edge. What must never appear is a
//! normal `swarm-ingest-runtime` entry in `swarm-runtime`'s `[dependencies]`.
//! Cargo rejects it outright, so the invariant is enforced by the build and not
//! by review alone:
//!
//! ```text
//! error: cyclic package dependency: package `swarm-ingest-runtime` depends on itself.
//! ```
//!
//! `swarm-runtime` does carry a `[dev-dependencies]` entry for this crate, which
//! Cargo permits because dev-dependencies do not participate in the build-order
//! graph of the lib target. That edge exists so the root's own integration tests
//! can keep driving the ingest router; it is not a licence to name this crate in
//! the root's non-test code.
//!
//! # Layering above the root
//!
//! ```text
//! swarm-runtime-http ----> swarm-ingest-runtime ----> swarm-runtime
//! swarm-cli --------------^                    ^
//! swarm-evolution ------------------------------
//! ```
//!
//! `swarm-runtime-http` sits ABOVE this crate, not beside it: its `swarm_detect`
//! binary constructs `IngestState` and mounts `detect_http_router`, and a binary
//! target can only reach a normal dependency. That settled ordering is what
//! decided where `HttpRateLimiter` belongs: both that crate and this one mount a
//! rate-limited surface at different heights, so the limiter could live in
//! neither and went down to `swarm_core::http_rate_limit` instead (SPLIT-05).
