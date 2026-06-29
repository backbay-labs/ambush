//! SIEM event wrapper around a swarm-crypto [`SignedReceipt`].
//!
//! [`SiemEvent`] distills the receipt's [`Verdict`] into an allow/deny [`ReceiptOutcome`] and a
//! human-facing `result` label, then exposes fail-soft accessors over the optional
//! [`Provenance`] fields so the OCSF / CEF / HEC formatters never have to reach into the receipt
//! (or unwrap an `Option`) themselves.

use serde::{Deserialize, Serialize};
use swarm_crypto::{Provenance, PublicKeySet, Receipt, SignedReceipt, ViolationRef};

/// Allow/deny outcome distilled from a receipt's [`Verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    /// The gate/guard verdict passed.
    Allow,
    /// The gate/guard verdict failed.
    Deny,
}

impl ReceiptOutcome {
    /// Lowercase wire token (`"allow"` / `"deny"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// Human-facing result label (`"Allowed"` / `"Denied"`).
    #[must_use]
    pub fn result_label(self) -> &'static str {
        match self {
            Self::Allow => "Allowed",
            Self::Deny => "Denied",
        }
    }
}

/// A SIEM event wrapping a [`SignedReceipt`] with its distilled outcome and (optional) signature
/// verification state.
///
/// `signature_verified` is `None` when the event was built without a verification key set
/// (the common control-plane path that forwards already-trusted receipts) and `Some(_)` when
/// [`SiemEvent::from_receipt_verified`] checked the embedded signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    /// The full signed receipt, forwarded verbatim as OCSF `raw_data` / HEC `event`.
    pub receipt: SignedReceipt,
    /// Allow/deny outcome distilled from `receipt.verdict.passed`.
    pub outcome: ReceiptOutcome,
    /// Human-facing semantic result label (`"Allowed"`, `"Denied"`, or `"Unverified"`).
    pub result: String,
    /// Signature verification state, when a key set was supplied.
    pub signature_verified: Option<bool>,
}

impl SiemEvent {
    /// Build an event from a receipt without verifying its signatures.
    #[must_use]
    pub fn from_receipt(receipt: SignedReceipt) -> Self {
        let outcome = Self::outcome_of(&receipt);
        let result = outcome.result_label().to_string();
        Self {
            receipt,
            outcome,
            result,
            signature_verified: None,
        }
    }

    /// Build an event and verify the receipt's signatures against `keys`.
    ///
    /// When verification fails the `result` label is forced to `"Unverified"` so a tampered or
    /// wrong-key receipt is never rendered as an authoritative decision.
    #[must_use]
    pub fn from_receipt_verified(receipt: SignedReceipt, keys: &PublicKeySet) -> Self {
        let verified = receipt.verify(keys).valid;
        let outcome = Self::outcome_of(&receipt);
        let result = if verified {
            outcome.result_label().to_string()
        } else {
            "Unverified".to_string()
        };
        Self {
            receipt,
            outcome,
            result,
            signature_verified: Some(verified),
        }
    }

    fn outcome_of(receipt: &SignedReceipt) -> ReceiptOutcome {
        if receipt.receipt.verdict.passed {
            ReceiptOutcome::Allow
        } else {
            ReceiptOutcome::Deny
        }
    }

    fn inner(&self) -> &Receipt {
        &self.receipt.receipt
    }

    fn provenance(&self) -> Option<&Provenance> {
        self.inner().provenance.as_ref()
    }

    /// Whether the underlying verdict passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.inner().verdict.passed
    }

    /// RFC-3339 timestamp string from the receipt.
    #[must_use]
    pub fn timestamp(&self) -> &str {
        &self.inner().timestamp
    }

    /// The receipt id, if present.
    #[must_use]
    pub fn receipt_id(&self) -> Option<&str> {
        self.inner().receipt_id.as_deref()
    }

    /// Stable unique identifier: the receipt id when set, else the content hash hex.
    #[must_use]
    pub fn uid(&self) -> String {
        match self.inner().receipt_id.as_deref() {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => self.inner().content_hash.to_hex(),
        }
    }

    /// Content hash rendered as unprefixed lowercase hex.
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        self.inner().content_hash.to_hex()
    }

    /// The gate/guard identifier from the verdict, if present.
    #[must_use]
    pub fn gate_id(&self) -> Option<&str> {
        self.inner().verdict.gate_id.as_deref()
    }

    /// Execution provider from provenance, if present.
    #[must_use]
    pub fn provider(&self) -> Option<&str> {
        self.provenance().and_then(|p| p.provider.as_deref())
    }

    /// Engine version from provenance, if present.
    #[must_use]
    pub fn engine_version(&self) -> Option<&str> {
        self.provenance().and_then(|p| p.engine_version.as_deref())
    }

    /// Ruleset identifier from provenance, if present.
    #[must_use]
    pub fn ruleset(&self) -> Option<&str> {
        self.provenance().and_then(|p| p.ruleset.as_deref())
    }

    /// Policy configuration hash from provenance, rendered as unprefixed lowercase hex.
    #[must_use]
    pub fn policy_hash_hex(&self) -> Option<String> {
        self.provenance()
            .and_then(|p| p.policy_hash.as_ref())
            .map(|hash| hash.to_hex())
    }

    /// Violations recorded in provenance (empty slice when absent).
    #[must_use]
    pub fn violations(&self) -> &[ViolationRef] {
        self.provenance().map(|p| p.violations.as_slice()).unwrap_or(&[])
    }

    /// The guard that produced the first violation, if any.
    #[must_use]
    pub fn primary_guard(&self) -> Option<&str> {
        self.violations().first().map(|v| v.guard.as_str())
    }

    /// The message of the first violation, if any.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.violations().first().map(|v| v.message.as_str())
    }

    /// A status-detail string for a deny: the first violation message, else the gate id, else
    /// the result label.
    #[must_use]
    pub fn status_detail(&self) -> String {
        self.reason()
            .map(String::from)
            .or_else(|| self.gate_id().map(String::from))
            .unwrap_or_else(|| self.outcome.result_label().to_string())
    }
}

/// Parse an RFC-3339 timestamp into Unix epoch milliseconds.
///
/// Returns `None` on parse failure so callers can fall back to `0` (OCSF) or skip the field
/// without panicking.
pub(crate) fn epoch_millis(rfc3339: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_support::{allow_receipt, deny_receipt};
    use swarm_crypto::{Keypair, PublicKeySet};

    #[test]
    fn deny_receipt_distills_to_deny_outcome() {
        let event = SiemEvent::from_receipt(deny_receipt());
        assert_eq!(event.outcome, ReceiptOutcome::Deny);
        assert_eq!(event.result, "Denied");
        assert!(!event.passed());
        assert_eq!(event.primary_guard(), Some("ForbiddenPathGuard"));
        assert_eq!(event.reason(), Some("forbidden path"));
        assert_eq!(event.gate_id(), Some("path-guard"));
        assert_eq!(event.uid(), "rcpt-deny-001");
    }

    #[test]
    fn allow_receipt_distills_to_allow_outcome() {
        let event = SiemEvent::from_receipt(allow_receipt());
        assert_eq!(event.outcome, ReceiptOutcome::Allow);
        assert_eq!(event.result, "Allowed");
        assert!(event.passed());
        assert!(event.primary_guard().is_none());
    }

    #[test]
    fn epoch_millis_parses_fixed_timestamp() {
        assert_eq!(epoch_millis("2026-01-01T00:00:00Z"), Some(1_767_225_600_000));
        assert_eq!(epoch_millis("not-a-timestamp"), None);
    }

    #[test]
    fn verified_event_records_signature_state() {
        let keypair = Keypair::generate();
        let receipt =
            swarm_crypto::SignedReceipt::sign(deny_receipt().receipt, &keypair).unwrap();
        let keys = PublicKeySet::new(keypair.public_key());
        let event = SiemEvent::from_receipt_verified(receipt, &keys);
        assert_eq!(event.signature_verified, Some(true));
        assert_eq!(event.result, "Denied");
    }

    #[test]
    fn wrong_key_marks_event_unverified() {
        let receipt = deny_receipt();
        let wrong = Keypair::generate();
        let keys = PublicKeySet::new(wrong.public_key());
        let event = SiemEvent::from_receipt_verified(receipt, &keys);
        assert_eq!(event.signature_verified, Some(false));
        assert_eq!(event.result, "Unverified");
    }
}
