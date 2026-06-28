//! Evolution-owned workflows extracted from `swarm-runtime`.
#![allow(clippy::result_large_err)]

pub use swarm_runtime::RuntimeMode;

pub mod config {
    pub use swarm_runtime::config::*;
}

pub mod control {
    pub use swarm_runtime::control::*;
}

pub mod detector_factory {
    pub use swarm_runtime::detector_factory::*;
}

pub mod evasion_coverage {
    pub use swarm_runtime::evasion_coverage::*;
}

pub mod operator_maintenance {
    pub use swarm_runtime::operator_maintenance::*;
}

pub mod replay {
    pub use swarm_runtime::replay::*;
    pub use swarm_runtime::replay::{harness, helpers, render, stores, types, validation};
}

pub mod service {
    pub use swarm_runtime::service::*;
}

pub mod canary;
pub mod drafting;
pub mod evidence;
pub mod evolution;
pub mod governance_prep;
pub mod mutation;
pub mod portfolio;
pub mod promotion;
pub mod selection;
pub mod strategy;
