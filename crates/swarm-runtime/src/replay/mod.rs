//! Replay, verification and detector-experiment machinery.
//!
//! # Placement (SPLIT-02, phase 282)
//!
//! SPLIT-02 undertook to extract this module into `swarm-runtime-replay`. It did
//! not happen, and the reason is recorded in
//! `docs/decisions/0003-split-02-replay-blocked-by-composition-root-cycle.md`.
//!
//! In short: the dependency is mutual and in non-test code both ways. Twenty
//! production files in the composition root import `crate::replay`, including
//! `lib.rs`, whose own error enum has `#[from]` variants over
//! `ReplayHarnessError`, `VerificationStoreError` and `ShadowStoreError`. Going
//! the other way, `types.rs` imports `crate::service` and `harness.rs`
//! constructs `SwarmRuntime` and `RuntimeService` outright. Cargo rejects the
//! resulting package cycle before compilation starts, and no subset of this
//! directory is both what the root needs and free of what the root provides --
//! `types.rs` defines the widely-imported manifest and lineage types AND
//! imports `crate::service`.
//!
//! IF THIS CHANGES: the unblocking move is a trait inversion on the return edge,
//! giving `harness.rs` "something that executes an event" instead of
//! `SwarmRuntime` itself, in the shape SPLIT-03 used for the policy dispatcher.
//! That is a design change, not code motion, and wants its own requirement.

#[cfg(test)]
pub(crate) mod detect_stall;
pub mod harness;
pub mod helpers;
mod metrics;
pub mod render;
pub mod stores;
pub mod types;
pub mod validation;
mod verification;

#[cfg(test)]
mod tests;

pub use harness::*;
pub use helpers::*;
pub use render::*;
pub use stores::*;
pub use types::*;
pub use validation::*;
