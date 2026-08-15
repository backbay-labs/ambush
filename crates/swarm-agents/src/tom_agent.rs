//! Compatibility path for the Tom role and concrete governance implementation.
//!
//! The implementation lives below `swarm-runtime` so runtime trust consumers can
//! accept its unforgeable concrete authority handle without creating a Cargo cycle.

pub use swarm_governance::*;
