//! Compatibility facade over the runtime-owned evolution workflows.
#![allow(clippy::result_large_err)]

pub use swarm_runtime::{
    RuntimeMode, canary, config, control, detector_factory, drafting, evasion_coverage, evidence,
    evolution, governance_prep, mutation, operator_maintenance, portfolio, promotion, replay,
    selection, service, strategy,
};
