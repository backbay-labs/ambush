//! OCSF 1.3.0 "Authorize Session" mapping for swarm-crypto receipts.
//!
//! Transforms a [`SiemEvent`] (or a raw [`SignedReceipt`]) into a JSON object conforming to the
//! OCSF 1.3.0 "Authorize Session" event class (IAM category 3 / `class_uid` 3003). NB: 3002 is OCSF
//! Authentication — an MCP allow/deny verdict is an authorization decision, so 3003 is the right
//! class.
//!
//! Reference: <https://schema.ocsf.io/1.3.0/classes/authorize_session>
//!
//! ## Tamper hygiene
//!
//! Mapping never panics. A receipt that failed signature verification renders as `status_id = 0`
//! (Unknown) + Critical severity rather than an authoritative Success, so a forged `passed=true`
//! cannot masquerade as a clean event.

use serde_json::{Map, Value, json};
use swarm_crypto::SignedReceipt;

use crate::event::{ReceiptOutcome, SiemEvent, epoch_millis};

/// OCSF schema version targeted by this mapper.
pub const OCSF_SCHEMA_VERSION: &str = "1.3.0";

/// OCSF "Authorize Session" event class identifier (IAM category). NB: 3002 is OCSF
/// Authentication, not Authorization — an MCP allow/deny verdict is an authorization decision.
pub const OCSF_CLASS_UID: u32 = 3003;

/// OCSF "Authorize Session" class name.
pub const OCSF_CLASS_NAME: &str = "Authorize Session";

/// OCSF IAM category identifier (parent of class 3003).
pub const OCSF_CATEGORY_UID: u32 = 3;

/// OCSF IAM category name.
pub const OCSF_CATEGORY_NAME: &str = "Identity & Access Management";

/// Product name surfaced in OCSF metadata.
pub const OCSF_PRODUCT_NAME: &str = "Ambush";

/// Product vendor surfaced in OCSF metadata.
pub const OCSF_PRODUCT_VENDOR: &str = "Backbay Labs";

/// Convert a [`SignedReceipt`] into an OCSF 1.3.0 Authorization event.
#[must_use]
pub fn receipt_to_ocsf(receipt: &SignedReceipt) -> Value {
    siem_event_to_ocsf(&SiemEvent::from_receipt(receipt.clone()))
}

/// Convert an already-distilled [`SiemEvent`] into an OCSF 1.3.0 Authorization event.
#[must_use]
pub fn siem_event_to_ocsf(event: &SiemEvent) -> Value {
    let outcome = event.outcome;
    // Activity reflects the verdict: Allow assigns privileges, Deny revokes them.
    let (activity_id, activity_name) = match outcome {
        ReceiptOutcome::Allow => (1_u32, "Assign Privileges"),
        ReceiptOutcome::Deny => (2_u32, "Revoke Privileges"),
    };
    let (mut status_id, mut status_name) = status_for(outcome);
    let (mut severity_id, mut severity_name) = severity_for(outcome);
    // Tamper hygiene (#16): a receipt that FAILED signature verification must not render as an
    // authoritative Success/low-severity event — surface it as Unknown status + Critical severity.
    if event.signature_verified == Some(false) {
        status_id = 0;
        status_name = "Unknown";
        severity_id = 5;
        severity_name = "Critical";
    }
    let type_uid = OCSF_CLASS_UID * 100 + activity_id;

    let mut map = Map::new();
    map.insert("category_uid".into(), json!(OCSF_CATEGORY_UID));
    map.insert("category_name".into(), json!(OCSF_CATEGORY_NAME));
    map.insert("class_uid".into(), json!(OCSF_CLASS_UID));
    map.insert("class_name".into(), json!(OCSF_CLASS_NAME));
    map.insert("type_uid".into(), json!(type_uid));
    map.insert(
        "type_name".into(),
        json!(format!("{OCSF_CLASS_NAME}: {activity_name}")),
    );
    map.insert("activity_id".into(), json!(activity_id));
    map.insert("activity_name".into(), json!(activity_name));
    map.insert("status_id".into(), json!(status_id));
    map.insert("status".into(), json!(status_name));
    map.insert("severity_id".into(), json!(severity_id));
    map.insert("severity".into(), json!(severity_name));

    let ts = event.timestamp();
    map.insert("time".into(), json!(epoch_millis(ts).unwrap_or(0)));
    map.insert("time_dt".into(), json!(ts));

    if outcome == ReceiptOutcome::Deny {
        map.insert("status_detail".into(), json!(event.status_detail()));
    }

    map.insert(
        "metadata".into(),
        json!({
            "version": OCSF_SCHEMA_VERSION,
            "uid": event.uid(),
            "log_provider": "swarm-siem",
            "product": {
                "name": OCSF_PRODUCT_NAME,
                "vendor_name": OCSF_PRODUCT_VENDOR,
            },
        }),
    );

    map.insert(
        "api".into(),
        json!({
            "operation": event.gate_id().unwrap_or("policy.gate"),
            "service": { "name": event.provider().unwrap_or("ambush-engine") },
            "request": { "uid": event.uid() },
        }),
    );

    map.insert(
        "actor".into(),
        json!({
            "invoked_by": "ambush-engine",
            "authorizations": [
                {
                    "policy": { "uid": event.policy_hash_hex() },
                    "decision": event.result.as_str(),
                }
            ],
        }),
    );

    map.insert(
        "policy".into(),
        json!({
            "uid": event.policy_hash_hex(),
            "name": event.ruleset().unwrap_or("ambush-policy"),
        }),
    );

    map.insert("observables".into(), build_observables(event));
    map.insert("enrichments".into(), build_enrichments(event));
    map.insert("unmapped".into(), build_unmapped(event));

    match serde_json::to_string(&event.receipt) {
        Ok(raw) => {
            map.insert("raw_data".into(), Value::String(raw));
        }
        Err(err) => {
            map.insert("status_id".into(), json!(0));
            map.insert("status".into(), json!("Unknown"));
            if let Some(Value::Object(unmapped)) = map.get_mut("unmapped") {
                unmapped.insert("raw_data_error".into(), Value::String(err.to_string()));
            }
        }
    }

    Value::Object(map)
}

fn status_for(outcome: ReceiptOutcome) -> (u32, &'static str) {
    // OCSF status_id enum: 0 Unknown, 1 Success, 2 Failure, 99 Other.
    match outcome {
        ReceiptOutcome::Allow => (1, "Success"),
        ReceiptOutcome::Deny => (2, "Failure"),
    }
}

fn severity_for(outcome: ReceiptOutcome) -> (u32, &'static str) {
    // OCSF severity_id enum: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
    // 5 Critical, 6 Fatal, 99 Other. An authorization denial is operationally High.
    match outcome {
        ReceiptOutcome::Allow => (1, "Informational"),
        ReceiptOutcome::Deny => (4, "High"),
    }
}

fn build_observables(event: &SiemEvent) -> Value {
    // OCSF observable type_id enum (selected): 10 Resource UID, 20 Endpoint Name, 99 Other.
    let mut observables = vec![
        json!({
            "name": "ambush.receipt.id",
            "type": "Resource UID",
            "type_id": 10,
            "value": event.uid(),
        }),
        json!({
            "name": "ambush.content.hash",
            "type": "Resource UID",
            "type_id": 10,
            "value": event.content_hash_hex(),
        }),
    ];

    if let Some(policy_hash) = event.policy_hash_hex() {
        observables.push(json!({
            "name": "ambush.policy.hash",
            "type": "Resource UID",
            "type_id": 10,
            "value": policy_hash,
        }));
    }

    if let Some(gate) = event.gate_id() {
        observables.push(json!({
            "name": "ambush.gate.id",
            "type": "Other",
            "type_id": 99,
            "value": gate,
        }));
    }

    for violation in event.violations() {
        observables.push(json!({
            "name": "ambush.guard",
            "type": "Other",
            "type_id": 99,
            "value": violation.guard.as_str(),
        }));
    }

    Value::Array(observables)
}

fn build_enrichments(event: &SiemEvent) -> Value {
    let receipt = &event.receipt.receipt;
    let mut enrichments = vec![json!({
        "name": "ambush.verdict",
        "type": "dict",
        "value": event.outcome.as_str(),
        "data": {
            "passed": receipt.verdict.passed,
            "gate_id": receipt.verdict.gate_id.as_deref(),
            "threshold": receipt.verdict.threshold,
            "result": event.result.as_str(),
        },
    })];

    if let Some(prov) = receipt.provenance.as_ref() {
        enrichments.push(json!({
            "name": "ambush.provenance",
            "type": "dict",
            "value": prov.provider.as_deref().unwrap_or(""),
            "data": {
                "engine_version": prov.engine_version.as_deref(),
                "provider": prov.provider.as_deref(),
                "ruleset": prov.ruleset.as_deref(),
                "policy_hash": event.policy_hash_hex(),
            },
        }));

        for (index, violation) in prov.violations.iter().enumerate() {
            enrichments.push(json!({
                "name": format!("ambush.violation.{index}"),
                "type": "dict",
                "value": violation.guard.as_str(),
                "data": {
                    "guard": violation.guard.as_str(),
                    "severity": violation.severity.as_str(),
                    "message": violation.message.as_str(),
                    "action": violation.action.as_deref(),
                },
            }));
        }
    }

    Value::Array(enrichments)
}

fn build_unmapped(event: &SiemEvent) -> Value {
    let receipt = &event.receipt.receipt;
    let mut ambush = Map::new();
    ambush.insert("receipt.id".into(), json!(event.uid()));
    ambush.insert("schema_version".into(), json!(receipt.version));
    ambush.insert("content.hash".into(), json!(event.content_hash_hex()));
    ambush.insert("policy.hash".into(), json!(event.policy_hash_hex()));
    ambush.insert("outcome".into(), json!(event.outcome.as_str()));
    ambush.insert("result".into(), json!(event.result.as_str()));
    ambush.insert("verdict.passed".into(), json!(receipt.verdict.passed));

    if let Some(gate) = event.gate_id() {
        ambush.insert("gate_id".into(), json!(gate));
    }
    if let Some(provider) = event.provider() {
        ambush.insert("provider".into(), json!(provider));
    }
    if let Some(ruleset) = event.ruleset() {
        ambush.insert("ruleset".into(), json!(ruleset));
    }
    if let Some(engine_version) = event.engine_version() {
        ambush.insert("engine_version".into(), json!(engine_version));
    }
    if let Some(signature_verified) = event.signature_verified {
        ambush.insert("signature_verified".into(), json!(signature_verified));
    }
    if let Some(reason) = event.reason() {
        ambush.insert("decision.reason".into(), json!(reason));
    }

    let mut root = Map::new();
    root.insert("ambush".into(), Value::Object(ambush));
    Value::Object(root)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_support::{allow_receipt, deny_receipt};

    #[test]
    fn deny_maps_to_authorization_failure_high_severity() {
        let event = SiemEvent::from_receipt(deny_receipt());
        let ev = siem_event_to_ocsf(&event);

        assert_eq!(ev["category_uid"], 3);
        assert_eq!(ev["class_uid"], 3003);
        assert_eq!(ev["class_name"], "Authorize Session");
        assert_eq!(ev["type_uid"], 300302);
        assert_eq!(ev["activity_name"], "Revoke Privileges");
        assert_eq!(ev["status_id"], 2);
        assert_eq!(ev["status"], "Failure");
        assert_eq!(ev["severity_id"], 4);
        assert_eq!(ev["severity"], "High");
        assert_eq!(ev["status_detail"], "forbidden path");
        assert_eq!(ev["time"], 1_767_225_600_000_i64);
        assert_eq!(ev["metadata"]["uid"], "rcpt-deny-001");
        assert_eq!(ev["metadata"]["product"]["name"], "Ambush");
        assert_eq!(ev["unmapped"]["ambush"]["outcome"], "deny");
        assert_eq!(ev["unmapped"]["ambush"]["gate_id"], "path-guard");
    }

    #[test]
    fn tamper_failed_signature_renders_unknown_critical() {
        // An ALLOW receipt whose signature did NOT verify must not render as Success/Informational.
        let mut event = SiemEvent::from_receipt(allow_receipt());
        event.signature_verified = Some(false);
        let ev = siem_event_to_ocsf(&event);
        assert_eq!(ev["status_id"], 0);
        assert_eq!(ev["status"], "Unknown");
        assert_eq!(ev["severity_id"], 5);
        assert_eq!(ev["severity"], "Critical");
    }

    #[test]
    fn allow_maps_distinctly_from_deny() {
        let allow = siem_event_to_ocsf(&SiemEvent::from_receipt(allow_receipt()));
        let deny = siem_event_to_ocsf(&SiemEvent::from_receipt(deny_receipt()));

        assert_eq!(allow["status_id"], 1);
        assert_eq!(allow["status"], "Success");
        assert_eq!(allow["severity_id"], 1);
        assert_eq!(allow["severity"], "Informational");
        assert!(allow.get("status_detail").is_none());

        assert_ne!(allow["status"], deny["status"]);
        assert_ne!(allow["severity"], deny["severity"]);
        assert_eq!(allow["unmapped"]["ambush"]["outcome"], "allow");
    }

    #[test]
    fn raw_receipt_helper_matches_event_mapping() {
        let receipt = deny_receipt();
        let direct = receipt_to_ocsf(&receipt);
        let via_event = siem_event_to_ocsf(&SiemEvent::from_receipt(receipt));
        assert_eq!(direct["class_uid"], via_event["class_uid"]);
        assert_eq!(direct["status"], via_event["status"]);
    }
}
