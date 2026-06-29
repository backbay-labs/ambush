//! The cost-metadata payload that rides the governor's receipt `metadata` slot.

use serde::{Deserialize, Serialize};

use crate::budget::BudgetViolation;
use crate::spend::{AggregateSpend, MonetaryAmount};

/// Schema identifier for the cost metadata stored under the receipt's
/// `metadata.cost` key.
pub const COST_METADATA_SCHEMA: &str = "ambush.metering.cost.v1";

/// Per-action cost attribution attached to a signed verdict receipt.
///
/// Serialized into the receipt `metadata` map under the `"cost"` key so every
/// governed action — allowed or budget-denied — carries an auditable, signed
/// record of what it would have spent and why it was (not) permitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostMetadata {
    /// Schema version for forward compatibility.
    pub schema: String,
    /// The lane this action was metered against.
    pub lane: String,
    /// The spend this action would incur.
    pub draft: AggregateSpend,
    /// The lane's cumulative spend (after recording if allowed; before if denied).
    pub lane_spent: AggregateSpend,
    /// The draft's monetary dimension as a denominated amount (micro-USD).
    pub monetary: MonetaryAmount,
    /// Whether the budget check passed (`false` => the action was budget-denied).
    pub allowed: bool,
    /// The violated cap, if the budget check failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation: Option<BudgetViolation>,
}

impl CostMetadata {
    /// Build a cost record for one governed action.
    #[must_use]
    pub fn new(
        lane: impl Into<String>,
        draft: AggregateSpend,
        lane_spent: AggregateSpend,
        allowed: bool,
        violation: Option<BudgetViolation>,
    ) -> Self {
        let monetary = draft.monetary();
        Self {
            schema: COST_METADATA_SCHEMA.to_string(),
            lane: lane.into(),
            draft,
            lane_spent,
            monetary,
            allowed,
            violation,
        }
    }

    /// Render as a JSON value for embedding in the receipt metadata map.
    ///
    /// A struct of primitives never fails to serialize; falls back to `Null`
    /// rather than panicking to honor the workspace `unwrap_used` lint.
    #[must_use]
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::spend::Dimension;

    #[test]
    fn allowed_cost_metadata_has_no_violation() {
        let cm = CostMetadata::new(
            "research",
            AggregateSpend::new(100, 1, 0, 2_000_000),
            AggregateSpend::new(100, 1, 0, 2_000_000),
            true,
            None,
        );
        let v = cm.to_value();
        assert_eq!(v.get("schema").unwrap(), COST_METADATA_SCHEMA);
        assert_eq!(v.get("lane").unwrap(), "research");
        assert_eq!(v.get("allowed").unwrap(), &serde_json::json!(true));
        assert!(v.get("violation").is_none());
        // monetary rides as a denominated micro-USD amount
        assert_eq!(v.pointer("/monetary/units").unwrap(), &serde_json::json!(2_000_000));
        assert_eq!(v.pointer("/monetary/currency").unwrap(), &serde_json::json!("USD_MICRO"));
    }

    #[test]
    fn denied_cost_metadata_carries_the_violation() {
        let violation = BudgetViolation {
            lane: "research".to_string(),
            dimension: Dimension::Tokens,
            limit: 1_000,
            current: 900,
            requested: 200,
        };
        let cm = CostMetadata::new(
            "research",
            AggregateSpend::with_tokens(200),
            AggregateSpend::with_tokens(900),
            false,
            Some(violation),
        );
        let v = cm.to_value();
        assert_eq!(v.get("allowed").unwrap(), &serde_json::json!(false));
        assert_eq!(v.pointer("/violation/dimension").unwrap(), &serde_json::json!("tokens"));
        assert_eq!(v.pointer("/violation/limit").unwrap(), &serde_json::json!(1_000));
    }

    #[test]
    fn cost_metadata_roundtrip() {
        let cm = CostMetadata::new(
            "ops",
            AggregateSpend::with_bytes(4096),
            AggregateSpend::with_bytes(4096),
            true,
            None,
        );
        let json = serde_json::to_string(&cm).unwrap();
        let back: CostMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cm);
    }
}
