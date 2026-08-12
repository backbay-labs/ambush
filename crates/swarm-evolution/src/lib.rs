//! Evolution-lane workflows extracted from the runtime composition root.
//!
//! # What this crate owns (SPLIT-04, phase 282)
//!
//! The modules declared below are compiled here, not in `swarm-runtime`. The
//! dependency runs `swarm-evolution -> swarm-runtime` and never back, which is
//! what lets these modules keep reaching `swarm_runtime::replay` while the
//! replay lane is still in the composition root.
//!
//! # What this crate still re-exports, and why
//!
//! The rest of the evolution lane -- `canary`, `drafting`, `evolution`,
//! `mutation`, `promotion`, `selection`, `strategy` -- is still compiled in
//! `swarm-runtime` and reached from here by re-export, so a consumer that
//! names `swarm_evolution::canary` keeps resolving. Those seven modules are
//! NOT movable by code motion today: `swarm-runtime`'s own `lib.rs`,
//! `ingest/`, `kitten_agent.rs`, `sphinx_agent.rs` and `evolution_status.rs`
//! name them in non-test code, and moving them would put a normal
//! `swarm-evolution` entry in `swarm-runtime`'s `[dependencies]`, which Cargo
//! rejects. The measurement and the alternatives are in
//! `docs/decisions/0005-split-04-evolution-lane-pinned-by-ingest-and-lib.md`.
#![allow(clippy::result_large_err)]

pub mod evidence;
pub mod operator_maintenance;

pub use swarm_runtime::{
    RuntimeMode, canary, config, control, detector_factory, drafting, evasion_coverage, evolution,
    governance_prep, mutation, portfolio, promotion, replay, selection, service, strategy,
};
