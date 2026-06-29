//! Splunk-HEC-shaped generic JSON/webhook envelope for Ambush receipts.
//!
//! Produces one HEC event envelope per [`SiemEvent`]: the full [`swarm_crypto::SignedReceipt`]
//! under the `event` key with Splunk-native `time`/`sourcetype`/`fields` siblings. The control
//! plane POSTs newline-separated envelopes (one per line) to a HEC `/services/collector/event`
//! endpoint or any generic JSON webhook; this module only renders, it never sends.

use serde_json::{Value, json};

use crate::error::SiemResult;
use crate::event::{SiemEvent, epoch_millis};

/// Default Splunk sourcetype stamped onto every HEC envelope.
pub const DEFAULT_HEC_SOURCETYPE: &str = "ambush:receipt";

/// Build a single Splunk-HEC-shaped JSON envelope for an event.
#[must_use]
pub fn hec_envelope(event: &SiemEvent) -> Value {
    let time_secs = epoch_millis(event.timestamp()).unwrap_or(0) as f64 / 1000.0;
    json!({
        "time": time_secs,
        "sourcetype": DEFAULT_HEC_SOURCETYPE,
        "event": &event.receipt,
        "fields": {
            "outcome": event.outcome.as_str(),
            "result": event.result.as_str(),
            "passed": event.passed(),
            "gate_id": event.gate_id(),
            "ruleset": event.ruleset(),
            "policy_hash": event.policy_hash_hex(),
            "signature_verified": event.signature_verified,
        },
    })
}

/// Serialize a single HEC envelope into a compact JSON line.
///
/// # Errors
/// Returns [`crate::SiemError::Serialization`] if the receipt cannot be serialized.
pub fn format_hec_line(event: &SiemEvent) -> SiemResult<String> {
    Ok(serde_json::to_string(&hec_envelope(event))?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_support::{allow_receipt, deny_receipt};

    #[test]
    fn deny_envelope_carries_fields_and_receipt() {
        let event = SiemEvent::from_receipt(deny_receipt());
        let envelope = hec_envelope(&event);

        assert_eq!(envelope["sourcetype"], "ambush:receipt");
        assert_eq!(envelope["time"], 1_767_225_600.0);
        assert_eq!(envelope["fields"]["outcome"], "deny");
        assert_eq!(envelope["fields"]["passed"], false);
        assert_eq!(envelope["fields"]["gate_id"], "path-guard");
        // The full signed receipt is forwarded verbatim under `event`.
        assert!(envelope["event"]["receipt"].is_object());
        assert!(envelope["event"]["signatures"].is_object());
    }

    #[test]
    fn allow_envelope_distinct_from_deny() {
        let allow = hec_envelope(&SiemEvent::from_receipt(allow_receipt()));
        let deny = hec_envelope(&SiemEvent::from_receipt(deny_receipt()));
        assert_eq!(allow["fields"]["outcome"], "allow");
        assert_eq!(allow["fields"]["passed"], true);
        assert_ne!(allow["fields"]["outcome"], deny["fields"]["outcome"]);
    }

    #[test]
    fn format_hec_line_is_single_line_json() {
        let line = format_hec_line(&SiemEvent::from_receipt(allow_receipt())).unwrap();
        assert!(!line.contains('\n'));
        assert!(line.starts_with('{'));
    }
}
