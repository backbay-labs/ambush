//! Pheromone substrate — the swarm's stigmergic communication layer.
//!
//! Backed by NATS JetStream KV for persistence and replay.
//! Deposit keys are segmented primarily by threat class
//! (`exp.<gc_page>.<threat_class>...` for deposits,
//! `esc.<timestamp>.<mode>.<threat_class>...` for escalations).
//!
//! Responsibilities:
//! - Deposit signed pheromones
//! - Query concentration by threat class / region / time window
//! - Garbage-collect evaporated pheromones
//! - Enforce source diversity (one agent can't flood)
//!
//! ## Owns
//!
//! - The substrate trait and every backend behind it ([`substrate`],
//!   [`jetstream`]): in-memory, local journal, and NATS JetStream, all three
//!   answering the same queries with the same semantics.
//! - The deposit key layout, the concentration query, evaporation/GC, and the
//!   source-diversity limit that stops one agent manufacturing consensus.
//! - Verifying that a deposit was signed by an admitted identity before it is
//!   allowed to influence a query result.
//!
//! ## Does not own
//!
//! - What a deposit means. Threat classes, escalation thresholds and detection
//!   semantics belong to `swarm-core` and the detection lane.
//! - Signing keys or the signature algorithm — `swarm-crypto`'s.
//! - Authorization or execution. Nothing here decides or performs a response.
//! - Durability guarantees beyond the configured backend's own; the in-memory
//!   backend loses everything on restart by design.
//!
//! NOT in the trusted computing base, deliberately. This crate is trust-
//! sensitive because a forged or flooded deposit changes what the detection
//! lane concludes, but it links a network client (`async-nats` under the
//! default `nats` feature) and so sits above the TCB rather than inside it
//! (ADR 0009). It must not appear in `swarm-policy`, `swarm-crypto` or
//! `swarm-spine`'s manifests in any dependency kind, and
//! `tools/check-workspace-layering.sh` fails the build if it does.

pub mod jetstream;
pub mod substrate;

pub use jetstream::JetStreamPheromoneSubstrate;
pub use substrate::{
    ConfiguredPheromoneSubstrate, DepositQuery, DepositSigningPayload, InMemoryPheromoneSubstrate,
    LocalJournalPheromoneSubstrate, PerchDepositSlice, PerchSuppressionRecord, PheromoneSubstrate,
    SubstrateError, SubstrateHealth, perch_deposit_slice,
};
