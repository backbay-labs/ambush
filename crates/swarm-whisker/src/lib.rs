//! Whisker agents — streaming detection on the hot path.
//!
//! Whiskers are long-running, stateful stream processors.
//! They consume telemetry (eBPF syscalls, network flows, tool invocations),
//! apply fast Rust-native detection (embedding similarity, rule matching,
//! statistical anomaly), and deposit pheromones on detection.
//!
//! No LLM per signal. LLM only for ambiguous signals routed to Stalkers.

pub mod detector;
pub mod stream;
