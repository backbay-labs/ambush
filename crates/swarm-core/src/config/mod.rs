//! Canonical v1 configuration types for the Rust-first runtime.

pub(super) use serde::{Deserialize, Serialize};
pub(super) use std::collections::{BTreeMap, BTreeSet};
pub(super) use std::net::SocketAddr;

pub(super) use crate::agent::SwarmMode;
pub(super) use crate::pheromone::ThreatClass;
pub(super) use crate::types::{ResponseAction, Severity};

mod bridges;
mod defaults;
mod detection;
mod evolution;
mod helpers;
mod operator;
mod perch;
mod pheromone;
mod policy;
mod response;
mod rollout;
mod root;
mod runtime;
mod secrets;
mod state;
mod storage;
mod validation;

use defaults::*;
use helpers::*;

pub use bridges::*;
pub use detection::*;
pub use evolution::*;
pub use operator::*;
pub use perch::*;
pub use pheromone::*;
pub use policy::*;
pub use response::*;
pub use rollout::*;
pub use root::*;
pub use runtime::*;
pub use secrets::*;
pub use state::*;
pub use storage::*;
pub use validation::ConfigValidationError;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
