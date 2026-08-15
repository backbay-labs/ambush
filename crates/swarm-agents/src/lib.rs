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
//! # Which roles live here
//!
//! Four role implementations are here: `pounce`, `stalker`, `weaver`, and
//! `whisker`. `tom_agent` remains as a compatibility re-export, while the Tom
//! implementation and authenticated governance policy live in the lower
//! `swarm-governance` crate. Three roles are still pinned in `swarm-runtime`:
//! `calico`, `kitten`, and `sphinx`.
//!
//! Tom originally came across on its own because it named nothing in the
//! composition root:
//!
//! ```text
//! $ grep -oE '(crate|super)::[A-Za-z_:]+' crates/swarm-runtime/src/tom_agent.rs | sort -u
//! super::now_ms
//! ```
//!
//! That whole module has since moved below runtime into `swarm-governance`, where
//! `GovernancePolicy` mints the concrete opaque `GovernanceAuthority` handle.
//! This crate preserves `swarm_agents::tom_agent::*` as a source-compatible
//! re-export; it no longer implements or defines the governance capability.
//!
//! The other three did not come. ADR 0004 costed their move at nine `pub(crate)`
//! `calico_agent` items and said to wait for `ingest/`; `ingest/` left, and a
//! different pin turned out to be underneath it. `kitten_agent.rs:828` calls
//! `EvolutionDetectorGenome::strategy()`, which is `pub(crate)` in
//! `swarm_runtime::mutation::types` and has 12 other callers that all stay
//! there, so the move needs a fourth widening against a baseline of three:
//!
//! ```text
//! error[E0624]: method `strategy` is private
//!    --> crates/swarm-agents/src/kitten_agent.rs:828:61
//!     |
//! 828 |                     serde_json::Value::from(detector_genome.strategy()),
//!     |                                                             ^^^^^^^^ private method
//!     |
//!    ::: crates/swarm-runtime/src/mutation/types.rs:137:5
//!     |
//! 137 |     pub(crate) fn strategy(&self) -> &'static str {
//!     |     --------------------------------------------- private method defined here
//! ```
//!
//! That call is a METHOD on an already-`pub` type from an already-`pub`
//! accessor, so it carries no `crate::` path and no path grep finds it. ADR 0007
//! records the pin and why the widening is not taken as a side effect of a file
//! move.
//!
//! When they do come, they come as one commit. `sphinx` and `kitten` both read
//! `calico`, and every one of the nine `pub(crate)` items `calico_agent.rs`
//! declares is read across those edges:
//!
//! ```text
//! sphinx -> calico   all nine
//! kitten -> calico   parse_calico_deception_interaction (non-test), and
//!                    CalicoDeceptionInteractionPayload, CalicoLifecycleStage,
//!                    CALICO_DECEPTION_INTERACTION_SCHEMA from its test module
//! kitten -> sphinx   SphinxAgent (test module)
//! ```
//!
//! Moving `calico` first leaves `swarm_agents::calico_agent` named from the
//! root's non-test code, and Cargo rejects the manifest before compiling
//! anything:
//!
//! ```text
//! error: cyclic package dependency: package `swarm-agents` depends on itself.
//! ```
//!
//! Moving either reader first leaves it naming `swarm_runtime::calico_agent::*`
//! across the crate line, and a re-export cannot launder a `pub(crate)` item
//! (`error[E0364]`), so all nine would become permanent public API to buy an
//! ordering. Together they stay `pub(crate)` inside THIS crate, which is what
//! ADR 0004 meant by waiting.

pub mod pounce_agent;
pub mod stalker_agent;
pub mod tom_agent;
pub mod weaver_agent;
pub mod whisker_agent;
