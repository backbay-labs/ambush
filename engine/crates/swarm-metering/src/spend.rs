//! Multi-dimension spend accounting and the localized monetary type.

use serde::{Deserialize, Serialize};

/// Currency code used for the `usd_micros` dimension when rendered as a
/// [`MonetaryAmount`]: micro-US-dollars (1 USD = 1_000_000 units).
pub const USD_MICRO: &str = "USD_MICRO";

/// A monetary amount with currency denomination.
///
/// Localized 2-field port of the upstream `chio_core::capability::scope::MonetaryAmount`.
/// Uses minor-unit integers to avoid floating-point precision drift. This crate
/// owns the type outright so there is no external dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryAmount {
    /// Amount in the currency's smallest unit (e.g. micro-USD for `USD_MICRO`).
    pub units: u64,
    /// Currency code. Examples: `"USD"`, `"USD_MICRO"`, `"EUR"`, `"JPY"`.
    pub currency: String,
}

impl MonetaryAmount {
    /// Construct an amount denominated in `currency`.
    #[must_use]
    pub fn new(units: u64, currency: impl Into<String>) -> Self {
        Self {
            units,
            currency: currency.into(),
        }
    }

    /// Construct a micro-USD amount.
    #[must_use]
    pub fn from_usd_micros(micros: u64) -> Self {
        Self::new(micros, USD_MICRO)
    }
}

/// A single metered dimension. Stable serialized identifiers:
/// `"tokens"`, `"requests"`, `"bytes"`, `"usd_micros"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    /// Model tokens consumed.
    Tokens,
    /// Tool-invocation requests (commonly 1 per action).
    Requests,
    /// Data volume in bytes.
    Bytes,
    /// Monetary cost in micro-USD.
    UsdMicros,
}

impl Dimension {
    /// Every dimension, in stable order.
    pub const ALL: [Dimension; 4] = [
        Dimension::Tokens,
        Dimension::Requests,
        Dimension::Bytes,
        Dimension::UsdMicros,
    ];

    /// Extract this dimension's value from a spend.
    #[must_use]
    pub fn of(self, spend: &AggregateSpend) -> u64 {
        match self {
            Dimension::Tokens => spend.tokens,
            Dimension::Requests => spend.requests,
            Dimension::Bytes => spend.bytes,
            Dimension::UsdMicros => spend.usd_micros,
        }
    }

    /// Stable string label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Dimension::Tokens => "tokens",
            Dimension::Requests => "requests",
            Dimension::Bytes => "bytes",
            Dimension::UsdMicros => "usd_micros",
        }
    }
}

/// A draft or cumulative spend across every metered dimension.
///
/// Every dimension is optional in practice: a request that only consumes tokens
/// leaves the other fields at zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateSpend {
    /// Tokens consumed.
    #[serde(default)]
    pub tokens: u64,
    /// Number of requests.
    #[serde(default)]
    pub requests: u64,
    /// Data volume in bytes.
    #[serde(default)]
    pub bytes: u64,
    /// Monetary cost in micro-USD.
    #[serde(default)]
    pub usd_micros: u64,
}

impl AggregateSpend {
    /// Construct from explicit per-dimension values.
    #[must_use]
    pub fn new(tokens: u64, requests: u64, bytes: u64, usd_micros: u64) -> Self {
        Self {
            tokens,
            requests,
            bytes,
            usd_micros,
        }
    }

    /// Construct from a token count.
    #[must_use]
    pub fn with_tokens(tokens: u64) -> Self {
        Self {
            tokens,
            ..Self::default()
        }
    }

    /// Construct from a request count.
    #[must_use]
    pub fn with_requests(requests: u64) -> Self {
        Self {
            requests,
            ..Self::default()
        }
    }

    /// Construct from a byte count.
    #[must_use]
    pub fn with_bytes(bytes: u64) -> Self {
        Self {
            bytes,
            ..Self::default()
        }
    }

    /// Construct from a micro-USD cost.
    #[must_use]
    pub fn with_usd_micros(usd_micros: u64) -> Self {
        Self {
            usd_micros,
            ..Self::default()
        }
    }

    /// Saturating per-dimension sum. Never overflows.
    #[must_use]
    pub fn saturating_add(&self, other: &Self) -> Self {
        Self {
            tokens: self.tokens.saturating_add(other.tokens),
            requests: self.requests.saturating_add(other.requests),
            bytes: self.bytes.saturating_add(other.bytes),
            usd_micros: self.usd_micros.saturating_add(other.usd_micros),
        }
    }

    /// Render the monetary dimension as a [`MonetaryAmount`] in micro-USD.
    #[must_use]
    pub fn monetary(&self) -> MonetaryAmount {
        MonetaryAmount::from_usd_micros(self.usd_micros)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn saturating_add_never_overflows() {
        let a = AggregateSpend::new(u64::MAX - 5, 1, 1, 1);
        let b = AggregateSpend::new(10, 2, 3, 4);
        let sum = a.saturating_add(&b);
        assert_eq!(sum.tokens, u64::MAX);
        assert_eq!(sum.requests, 3);
        assert_eq!(sum.bytes, 4);
        assert_eq!(sum.usd_micros, 5);
    }

    #[test]
    fn dimension_extracts_the_right_field() {
        let s = AggregateSpend::new(11, 22, 33, 44);
        assert_eq!(Dimension::Tokens.of(&s), 11);
        assert_eq!(Dimension::Requests.of(&s), 22);
        assert_eq!(Dimension::Bytes.of(&s), 33);
        assert_eq!(Dimension::UsdMicros.of(&s), 44);
    }

    #[test]
    fn monetary_is_micro_usd() {
        let s = AggregateSpend::with_usd_micros(2_500_000);
        let amt = s.monetary();
        assert_eq!(amt.units, 2_500_000);
        assert_eq!(amt.currency, USD_MICRO);
    }

    #[test]
    fn aggregate_spend_roundtrip() {
        let s = AggregateSpend::new(1, 2, 3, 4);
        let json = serde_json::to_string(&s).unwrap();
        let back: AggregateSpend = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn dimension_serializes_snake_case() {
        let json = serde_json::to_string(&Dimension::UsdMicros).unwrap();
        assert_eq!(json, "\"usd_micros\"");
    }
}
