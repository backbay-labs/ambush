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
//! Five of the eight roles are here: `pounce`, `stalker`, `tom`, `weaver`,
//! `whisker`. Three are not yet -- `calico`, `kitten`, `sphinx` -- and they are a
//! closed group that has to cross in one commit.
//!
//! `tom` came across on its own because it names nothing in the composition root:
//!
//! ```text
//! $ grep -oE '(crate|super)::[A-Za-z_:]+' crates/swarm-runtime/src/tom_agent.rs | sort -u
//! super::now_ms
//! ```
//!
//! and `super::now_ms` is `tom_agent`'s own file-local helper, reached from its
//! `#[cfg(test)]` module. Its two trait impls both name their traits through the
//! defining crate rather than through the root -- `swarm_policy::governance::
//! sealed::SealedGovernanceAuthority` and `GovernanceAuthority` -- so the seal is
//! satisfied from here exactly as it was from there.
//!
//! The other three cannot be split apart. `sphinx` and `kitten` both read
//! `calico`, and all nine of the `calico_agent` items they read are `pub(crate)`:
//!
//! ```text
//! sphinx -> calico   CalicoDeceptionInteractionPayload, CalicoDeceptionInventoryPayload,
//!                    CalicoLifecycleStage, CalicoMonitoringPayload,
//!                    CALICO_DECEPTION_INTERACTION_SCHEMA, CALICO_DECEPTION_INVENTORY_SCHEMA,
//!                    CALICO_DECEPTION_INVENTORY_THREAT_CLASS,
//!                    parse_calico_deception_interaction, parse_calico_deception_inventory
//!                    -- every one of the nine `pub(crate)` items the file declares
//! kitten -> calico   parse_calico_deception_interaction (non-test),
//!                    CalicoDeceptionInteractionPayload, CalicoLifecycleStage,
//!                    CALICO_DECEPTION_INTERACTION_SCHEMA (test)
//! kitten -> sphinx   SphinxAgent (test)
//! ```
//!
//! Moving `calico` first puts `swarm_agents::calico_agent` in the root's non-test
//! code and Cargo rejects the manifest. Moving either reader first leaves it
//! naming `swarm_runtime::calico_agent::*` across the crate line, which widens
//! those `pub(crate)` items to permanent public API. One commit for the three is
//! the only order that is neither a cycle nor a widening.

pub mod pounce_agent;
pub mod stalker_agent;
pub mod tom_agent;
pub mod weaver_agent;
pub mod whisker_agent;
