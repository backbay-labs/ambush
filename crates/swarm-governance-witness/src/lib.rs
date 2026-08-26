#![forbid(unsafe_code)]

//! Downstream transport boundary for the authenticated governance witness.

mod jetstream_store;
mod nats_config;
pub mod raw_config;

pub use jetstream_store::NatsWitnessStore;
