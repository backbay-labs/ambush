//! Hot-path detection submodule.
//!
//! External consumers should import through `crate::detection::*`.

pub mod metrics;
pub mod pipeline;

pub use metrics::{CriticalPathMetrics, encode_metrics};
pub use pipeline::{DetectionPipelineOutcome, PipelineError, detect_and_deposit};
