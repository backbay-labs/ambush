//! Per-lane budget enforcement: `check()` pre-allow, `record()` post-spend.
//!
//! Mirrors the upstream `chio-metering` `BudgetEnforcer` split — a pure check
//! that never mutates, and a record that updates cumulative counters — but keys
//! tracking by *lane* (the swarm's per-lane cost doom-loop lever) instead of
//! session/agent/tool.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::spend::{AggregateSpend, Dimension};

/// Optional per-dimension spending caps. All fields are optional so partial
/// policies compose cleanly (a lane may cap only tokens, only dollars, etc.).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLimit {
    /// Maximum tokens within the lane budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    /// Maximum requests within the lane budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests: Option<u64>,
    /// Maximum bytes within the lane budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    /// Maximum monetary cost (micro-USD) within the lane budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_usd_micros: Option<u64>,
}

impl BudgetLimit {
    /// Builder: cap tokens.
    #[must_use]
    pub fn with_max_tokens(mut self, v: u64) -> Self {
        self.max_tokens = Some(v);
        self
    }

    /// Builder: cap requests.
    #[must_use]
    pub fn with_max_requests(mut self, v: u64) -> Self {
        self.max_requests = Some(v);
        self
    }

    /// Builder: cap bytes.
    #[must_use]
    pub fn with_max_bytes(mut self, v: u64) -> Self {
        self.max_bytes = Some(v);
        self
    }

    /// Builder: cap monetary cost (micro-USD).
    #[must_use]
    pub fn with_max_usd_micros(mut self, v: u64) -> Self {
        self.max_usd_micros = Some(v);
        self
    }

    /// The cap for a single dimension, if set.
    #[must_use]
    pub fn cap(&self, dim: Dimension) -> Option<u64> {
        match dim {
            Dimension::Tokens => self.max_tokens,
            Dimension::Requests => self.max_requests,
            Dimension::Bytes => self.max_bytes,
            Dimension::UsdMicros => self.max_usd_micros,
        }
    }

    /// Fail-closed check: would `current + draft` exceed any capped dimension?
    ///
    /// Returns the **first** violated dimension (in [`Dimension::ALL`] order).
    /// `lane` is recorded on the violation for auditability.
    pub fn check(
        &self,
        lane: &str,
        current: &AggregateSpend,
        draft: &AggregateSpend,
    ) -> Result<(), BudgetViolation> {
        for dim in Dimension::ALL {
            if let Some(cap) = self.cap(dim) {
                let cur = dim.of(current);
                let req = dim.of(draft);
                if cur.saturating_add(req) > cap {
                    return Err(BudgetViolation {
                        lane: lane.to_string(),
                        dimension: dim,
                        limit: cap,
                        current: cur,
                        requested: req,
                    });
                }
            }
        }
        Ok(())
    }
}

/// A budget violation describes which lane dimension would be exceeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetViolation {
    /// The lane whose cap was hit.
    pub lane: String,
    /// The dimension that overflowed.
    pub dimension: Dimension,
    /// The cap that would be exceeded.
    pub limit: u64,
    /// Current spend in that dimension before the draft.
    pub current: u64,
    /// The draft amount that pushed it over.
    pub requested: u64,
}

/// Per-lane budget enforcer.
///
/// Holds a `default_limit` applied to every lane plus optional per-lane
/// overrides, and tracks cumulative [`AggregateSpend`] per lane. Thread-safe
/// usage requires external synchronization (the governor already serializes
/// evaluation per request).
#[derive(Debug, Clone, Default)]
pub struct BudgetEnforcer {
    default_limit: BudgetLimit,
    lane_limits: HashMap<String, BudgetLimit>,
    spent: HashMap<String, AggregateSpend>,
}

impl BudgetEnforcer {
    /// Create an enforcer whose every lane is capped by `default_limit`.
    #[must_use]
    pub fn new(default_limit: BudgetLimit) -> Self {
        Self {
            default_limit,
            lane_limits: HashMap::new(),
            spent: HashMap::new(),
        }
    }

    /// Builder: override the limit for a specific lane.
    #[must_use]
    pub fn with_lane_limit(mut self, lane: impl Into<String>, limit: BudgetLimit) -> Self {
        self.lane_limits.insert(lane.into(), limit);
        self
    }

    /// Override the limit for a specific lane.
    pub fn set_lane_limit(&mut self, lane: impl Into<String>, limit: BudgetLimit) {
        self.lane_limits.insert(lane.into(), limit);
    }

    /// The effective limit for `lane` (lane override else the default).
    #[must_use]
    pub fn limit_for(&self, lane: &str) -> &BudgetLimit {
        self.lane_limits.get(lane).unwrap_or(&self.default_limit)
    }

    /// Cumulative spend recorded against `lane` so far.
    #[must_use]
    pub fn spent(&self, lane: &str) -> AggregateSpend {
        self.spent.get(lane).cloned().unwrap_or_default()
    }

    /// Fail-closed pre-allow check. Does **not** mutate state.
    pub fn check(&self, lane: &str, draft: &AggregateSpend) -> Result<(), BudgetViolation> {
        let current = self.spent(lane);
        self.limit_for(lane).check(lane, &current, draft)
    }

    /// Record an approved, executed spend. Call after the action is allowed.
    /// Saturating, so counters never overflow.
    pub fn record(&mut self, lane: &str, draft: &AggregateSpend) {
        let entry = self.spent.entry(lane.to_string()).or_default();
        *entry = entry.saturating_add(draft);
    }

    /// Convenience: check, and record only if within budget.
    ///
    /// Returns `Ok(())` after recording, or the violation without recording.
    pub fn check_and_record(
        &mut self,
        lane: &str,
        draft: &AggregateSpend,
    ) -> Result<(), BudgetViolation> {
        self.check(lane, draft)?;
        self.record(lane, draft);
        Ok(())
    }
}

/// A metering request handed to the governor: the lane, the action's draft
/// spend, and a mutable borrow of the enforcer that owns the per-lane counters.
///
/// The governor checks `draft` against `enforcer` *before* allowing, and only
/// records it *after* a fully-allowed action (post-spend).
pub struct MeteringRequest<'a> {
    /// The lane this action is charged to.
    pub lane: String,
    /// The spend this action would incur if allowed.
    pub draft: AggregateSpend,
    /// The enforcer that owns the lane's cumulative counters.
    pub enforcer: &'a mut BudgetEnforcer,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn limit() -> BudgetLimit {
        BudgetLimit::default()
            .with_max_tokens(1_000)
            .with_max_usd_micros(5_000_000)
    }

    #[test]
    fn under_budget_allows_and_records() {
        let mut enforcer = BudgetEnforcer::new(limit());
        let draft = AggregateSpend::new(400, 1, 0, 1_000_000);

        // pre-allow check passes and does NOT mutate
        assert!(enforcer.check("research", &draft).is_ok());
        assert_eq!(enforcer.spent("research"), AggregateSpend::default());

        // post-spend record updates the cumulative counters
        enforcer.record("research", &draft);
        assert_eq!(enforcer.spent("research"), draft);

        // a second under-budget action still passes against the new baseline
        let more = AggregateSpend::with_tokens(500);
        assert!(enforcer.check("research", &more).is_ok());
    }

    #[test]
    fn over_budget_denies_on_the_overflowing_dimension() {
        let mut enforcer = BudgetEnforcer::new(limit());
        enforcer.record("research", &AggregateSpend::with_tokens(900));

        // 900 + 200 = 1100 > 1000 token cap
        let err = enforcer
            .check("research", &AggregateSpend::with_tokens(200))
            .unwrap_err();
        assert_eq!(err.dimension, Dimension::Tokens);
        assert_eq!(err.limit, 1_000);
        assert_eq!(err.current, 900);
        assert_eq!(err.requested, 200);
        assert_eq!(err.lane, "research");
    }

    #[test]
    fn check_and_record_does_not_record_on_violation() {
        let mut enforcer = BudgetEnforcer::new(limit());
        enforcer.record("research", &AggregateSpend::with_tokens(900));

        let before = enforcer.spent("research");
        assert!(
            enforcer
                .check_and_record("research", &AggregateSpend::with_tokens(200))
                .is_err()
        );
        // spend is unchanged after a denied action
        assert_eq!(enforcer.spent("research"), before);
    }

    #[test]
    fn lanes_are_isolated_and_overridable() {
        let mut enforcer =
            BudgetEnforcer::new(limit()).with_lane_limit("cheap", BudgetLimit::default().with_max_tokens(10));

        // spend on one lane does not affect another
        enforcer.record("research", &AggregateSpend::with_tokens(900));
        assert!(enforcer.check("ops", &AggregateSpend::with_tokens(900)).is_ok());

        // the override is tighter than the default
        assert!(enforcer.check("cheap", &AggregateSpend::with_tokens(11)).is_err());
    }

    #[test]
    fn usd_micros_cap_is_enforced() {
        let enforcer = BudgetEnforcer::new(limit());
        let over = AggregateSpend::with_usd_micros(5_000_001);
        let err = enforcer.check("research", &over).unwrap_err();
        assert_eq!(err.dimension, Dimension::UsdMicros);
    }

    #[test]
    fn record_saturates() {
        let mut enforcer = BudgetEnforcer::new(BudgetLimit::default());
        enforcer.record("l", &AggregateSpend::with_tokens(u64::MAX - 5));
        enforcer.record("l", &AggregateSpend::with_tokens(20));
        assert_eq!(enforcer.spent("l").tokens, u64::MAX);
    }
}
