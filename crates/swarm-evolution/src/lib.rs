//! Evolution-lane workflows extracted from the runtime composition root.
//!
//! # What this crate owns (SPLIT-04, phase 282)
//!
//! The four modules declared below are compiled here, not in `swarm-runtime`.
//! The dependency runs `swarm-evolution -> swarm-runtime` and never back, which
//! is what lets them keep reaching `swarm_runtime::replay` while the replay
//! lane is still in the composition root.
//!
//! `operator_maintenance` is here although SPLIT-04 did not name it: it and
//! `evidence` import each other, so neither could cross the crate line alone.
//!
//! # What this crate still re-exports, and why
//!
//! The rest of the evolution lane -- `canary`, `drafting`, `evolution`,
//! `mutation`, `promotion`, `selection`, `strategy` -- is still compiled in
//! `swarm-runtime` and reached from here by re-export, so a consumer that
//! names `swarm_evolution::canary` keeps resolving. Those seven modules are
//! NOT movable by code motion, and not by any later extraction either:
//! `swarm-runtime`'s own `lib.rs` names five of them by `#[from]` on
//! `StrategyProposalRouteError`, `strategy` is named by four of those five and
//! `promotion` only by `strategy`, so the crate root alone closes over all
//! seven. Moving them would put a normal `swarm-evolution` entry in
//! `swarm-runtime`'s `[dependencies]`, which Cargo rejects. What has to happen
//! first is the sealed-boundary inversion SPLIT-03 applied to
//! `swarm_core::agent::AgentTickError`. The measurement and the alternatives
//! are in
//! `docs/decisions/0005-split-04-evolution-lane-pinned-by-the-crate-root.md`.
#![allow(clippy::result_large_err)]

pub mod evidence;
pub mod governance_prep;
pub mod operator_maintenance;
pub mod portfolio;

pub use swarm_ingest_runtime::control;
pub use swarm_runtime::{
    RuntimeMode, canary, config, detector_factory, drafting, evasion_coverage, evolution, mutation,
    promotion, replay, selection, service, strategy,
};
