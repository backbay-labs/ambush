//! Swarm agent role implementations.
//!
//! Each module here is one autonomous role that the composition root schedules
//! through the sealed `swarm_core::agent::SwarmAgent` trait boundary. The roles
//! hold behaviour, not wiring: they are constructed by the root, ticked by the
//! dispatcher, and never reach for the root's own composition types.
//!
//! # Why this is a separate crate (SPLIT-03, phase 282)
//!
//! `swarm-runtime` is the composition root. Role implementations are the single
//! largest block of code inside it and none of them is on the wiring path, so
//! every consumer of the root paid to compile all of them. This crate lifts them
//! out.
//!
//! The direction of the edge is the whole point:
//!
//! ```text
//! swarm-agents -> swarm-runtime        (normal dependency, this crate's manifest)
//! swarm-runtime -> swarm-agents        (dev-dependency ONLY, never a normal one)
//! ```
//!
//! Agents read back into the root for the collaborators they operate on --
//! `correlation`, `investigation`, `detection::pipeline`, `tom_agent` -- and that
//! is fine, because it is the forward edge. What must never appear is a normal
//! `swarm-agents` entry in `swarm-runtime`'s `[dependencies]`. Cargo rejects it
//! outright, so the invariant is enforced by the build and not by review alone:
//!
//! ```text
//! error: cyclic package dependency: package `swarm-agents` depends on itself.
//! ```
//!
//! `swarm-runtime` does carry a `[dev-dependencies]` entry for this crate, which
//! Cargo permits because dev-dependencies do not participate in the build-order
//! graph of the lib target. That edge exists so the root's integration tests can
//! keep constructing concrete agents; it is not a licence to name them in
//! non-test code.
//!
//! # Why only four roles live here
//!
//! Four of the eight roles moved: `pounce`, `stalker`, `weaver`, `whisker`.
//! `calico`, `kitten`, `sphinx` and `tom` are pinned inside `swarm-runtime` by
//! `ingest/`, which calls into two of them from non-test code:
//!
//! - `ingest/mod.rs` stores a `tom_agent::GovernancePolicy`
//! - `ingest/providence_handlers.rs` calls `kitten_agent::route_feedback_signal`
//!
//! Those are back-edges. Moving `tom` or `kitten` would put a normal
//! `swarm-agents` dependency in the root's manifest and produce the cycle above.
//! `calico` is pinned transitively (`kitten_agent` parses calico payloads), and
//! `sphinx` is pinned by `calico` -- moving `sphinx` alone would force nine
//! `pub(crate)` items in `calico_agent` to become permanent public API purely to
//! satisfy an ordering constraint.
//!
//! `ingest/` is SPLIT-05's file set. The remaining four roles follow it, not this
//! commit.

pub mod weaver_agent;
pub mod whisker_agent;
