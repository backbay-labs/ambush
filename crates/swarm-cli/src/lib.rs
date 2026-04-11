//! Extracted CLI surface that still delegates into the runtime-owned service APIs.

pub mod agent_identity {
    pub use swarm_runtime::agent_identity::*;
}

pub mod approval {
    pub use swarm_runtime::approval::*;
}

pub mod canary {
    pub use swarm_runtime::canary::*;
}

pub mod config {
    pub use swarm_runtime::config::*;
}

pub mod control {
    pub use swarm_runtime::control::*;
}

pub mod drafting {
    pub use swarm_runtime::drafting::*;
}

pub mod evidence {
    pub use swarm_runtime::evidence::*;
}

pub mod evolution {
    pub use swarm_runtime::evolution::*;
}

pub mod evolution_status {
    pub use swarm_runtime::evolution_status::*;
}

pub mod governance_prep {
    pub use swarm_runtime::governance_prep::*;
}

pub mod mutation {
    pub use swarm_runtime::mutation::*;
}

pub mod operator_http {
    pub use swarm_runtime::operator_http::*;
}

pub mod operator_maintenance {
    pub use swarm_runtime::operator_maintenance::*;
}

pub mod portfolio {
    pub use swarm_runtime::portfolio::*;
}

pub mod promotion {
    pub use swarm_runtime::promotion::*;
}

pub mod replay {
    pub use swarm_runtime::replay::*;
}

pub mod review_workbench {
    pub use swarm_runtime::review_workbench::*;
}

pub mod selection {
    pub use swarm_runtime::selection::*;
}

pub mod strategy {
    pub use swarm_runtime::strategy::*;
}

#[path = "core.inc"]
mod core;

pub mod args;
pub mod dispatch;
pub mod format;
pub mod tracing;
