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
//!
//! # `#[cfg(test)]` on the root is invisible from here
//!
//! The forward edge is a NORMAL dependency, so this crate links the root's
//! non-test build. Nothing `swarm-runtime` gates behind `#[cfg(test)]` exists
//! in that build -- not even a `pub` one, which fails as "does not exist"
//! rather than as "is private", so a visibility keyword is not evidence of
//! reachability:
//!
//! ```text
//! error[E0432]: unresolved import
//!   `swarm_runtime::kitten_agent::load_feedback_signal_records`
//!   no `load_feedback_signal_records` in `kitten_agent`
//! ```
//!
//! This binds the tests as much as the code: `ingest/tests.rs` moves with
//! `ingest/` and becomes a unit test of THIS crate, where its `crate::` paths
//! become `swarm_runtime::` paths under exactly the same rule. SPLIT-05 hit one
//! such path and resolved it by moving the read half of the kitten feedback
//! store down to its only caller, rather than ungating the root's helper and
//! making a test-only reader permanent public API.
//!
//! The root still declares `#[cfg(test)] pub` surface that reads as reachable
//! and is not -- `providence.rs` gates a whole `pub mod tests` that way -- so
//! any later move here has to be probed against the non-test build.

// Carried over from `swarm-runtime`'s crate root, where `control.rs` lived until
// SPLIT-05 and where this same `#![allow]` sits at `lib.rs:79`. `ControlError`
// moved here with `control.rs`, so the 23 sites the lint fires on moved with it;
// the allow is part of that code's existing configuration, not a new exemption.
#![allow(clippy::result_large_err)]

pub mod anti_tamper;
pub mod bridge_runtime;
pub mod control;
pub mod ingest;
