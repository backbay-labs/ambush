//! Operator review workbench for the Ambush runtime: review sessions, capsules,
//! delegation packets, promotion-readiness reports and maintenance handoffs.
//!
//! # Why this is a separate crate (SPLIT-02, phase 282)
//!
//! This is an offline operator lane. It reads evidence bundles and maintenance
//! records that `swarm-runtime` produces and renders operator-facing artifacts
//! from them; nothing on the live detect/respond critical path calls into it.
//! Keeping it inside the composition root meant every consumer of
//! `swarm-runtime` compiled it, including the ingest and response lanes that
//! never open a review session.
//!
//! The edge runs `swarm-runtime-workbench -> swarm-runtime` and never back.
//! `swarm-runtime` carries no `pub mod workbench` any more: the module's only
//! two upward dependencies, `evidence` and `operator_maintenance`, stay in the
//! runtime, and this crate reaches them as `swarm_runtime::evidence` and
//! `swarm_runtime::operator_maintenance`.
//!
//! Nothing in `swarm-runtime` may depend on this crate. If a runtime module
//! needs something from here, the item is in the wrong crate.
//!
//! `result_large_err` is allowed crate-wide here for the same reason it is
//! allowed in `swarm-runtime`, whose `lib.rs` carries the identical attribute,
//! and in `swarm-runtime-http`, which inherited it the same way in SPLIT-01:
//! `ReviewWorkbenchError` wraps the runtime's own large error types
//! (`EvidenceError`, `OperatorMaintenanceError`) by `#[from]`. The moved code is
//! byte-identical to what compiled under that allow before the split, so the
//! allow moves with it rather than the error types being reshaped here.
#![allow(clippy::result_large_err)]

pub mod review_workbench;
pub mod workbench;
