#![forbid(unsafe_code)]

//! Downstream transport boundary for the authenticated governance witness.

mod jetstream_store;
mod nats_config;
mod public_dispatcher;
pub mod raw_config;
mod service_config;

pub use jetstream_store::NatsWitnessStore;
pub use public_dispatcher::{
    PublicWitnessDispatchErrorV1, PublicWitnessDispatchMappingV1, PublicWitnessDispatcher,
    PublicWitnessProxyTransportErrorV1, PublicWitnessRunnerErrorV1, PublicWitnessServiceRunner,
    PublicWitnessStoreProxyClient, dispatcher_mapping, public_witness_ingress_overload_control,
};
pub use service_config::PublicWitnessServiceConfigV1;
