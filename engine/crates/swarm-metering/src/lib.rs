//! Per-lane budget metering for the swarm governor — the cost doom-loop lever.
//!
//! Harvested and rebuilt from the Arc/Chio `chio-metering` crate (Apache-2.0):
//! the `BudgetEnforcer` check/record split (`budget.rs`), the multi-dimension
//! [`AggregateSpend`] accumulator (`cost.rs`), and the org-hierarchy
//! [`BudgetTree`] (`budget_hierarchy.rs`). Collapsed onto Ambush primitives and
//! a single, locally-owned 2-field [`MonetaryAmount`] so this crate carries
//! **zero** external types and **zero** new third-party dependencies.
//!
//! # Shape
//!
//! - [`AggregateSpend`] — a draft/cumulative spend over four dimensions:
//!   `tokens`, `requests`, `bytes`, `usd_micros`.
//! - [`BudgetLimit`] — optional per-dimension caps (a lane may cap only tokens,
//!   only dollars, etc.).
//! - [`BudgetEnforcer`] — per-lane caps with a fail-closed [`BudgetEnforcer::check`]
//!   (pre-allow) and [`BudgetEnforcer::record`] (post-spend).
//! - [`BudgetTree`] — org -> dept -> team -> agent hierarchy; an evaluation
//!   walks leaf-to-root and rolls each node's **subtree** spend against that
//!   node's cap, so a child's spend counts against every ancestor.
//! - [`CostMetadata`] — the JSON payload that rides the receipt `metadata` slot.
//!
//! This crate is pure logic: no async, no network, no DB, no signing. The
//! governor owns the signing; this crate owns the arithmetic.

pub mod budget;
pub mod cost;
pub mod hierarchy;
pub mod spend;

pub use budget::{BudgetEnforcer, BudgetLimit, BudgetViolation, MeteringRequest};
pub use cost::{COST_METADATA_SCHEMA, CostMetadata};
pub use hierarchy::{
    BudgetDecision, BudgetDenyReason, BudgetError, BudgetNode, BudgetNodeId, BudgetTree,
    SpendSnapshot,
};
pub use spend::{AggregateSpend, Dimension, MonetaryAmount, USD_MICRO};
