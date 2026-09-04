#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::{ActionRequest, PolicyDecision, PolicyVerdict};

pub(crate) const T0: i64 = 1_773_739_200_000;

pub(crate) fn fixture_request(action: ResponseAction) -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-evt-1".to_string()),
        requested_by: AgentId::from_public_key_hex(&"18".repeat(32)),
        action,
        severity: Severity::Critical,
        evidence: serde_json::json!({
            "escalation": { "threat_class": "execution", "level": "alert" }
        }),
    }
}

pub(crate) fn fixture_hold(action: ResponseAction, held_at_ms: i64) -> HeldAction {
    let request = fixture_request(action);
    let detection = crate::detection::routed_detection_for_test(&request);
    HeldAction::new(
        mint_hold_id(),
        request,
        detection,
        PolicyDecision {
            verdict: PolicyVerdict::RequireHuman,
            rule_name: "static.human_gate".to_string(),
            reason: "authorized but held for human approval".to_string(),
        },
        None,
        held_at_ms,
        held_at_ms + 3_600_000,
        Some("trail-1".to_string()),
    )
}

/// The top-level object keys of one JSON document, in emitted order.
///
/// A five-line scanner rather than a parse, because every parse into a
/// `serde_json::Value` re-sorts the keys and destroys the property under test.
fn top_level_keys(json: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let bytes = json.as_bytes();
    let mut depth: i32 = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b'"' => {
                let start = index + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != b'"' {
                    // Skip an escaped character so a `\"` inside a value does not
                    // end the string early.
                    end += if bytes[end] == b'\\' { 2 } else { 1 };
                }
                let literal = &json[start..end.min(json.len())];
                let is_key = json[end + 1..]
                    .bytes()
                    .find(|byte| !byte.is_ascii_whitespace())
                    == Some(b':');
                if depth == 1 && is_key {
                    keys.push(literal.to_string());
                }
                index = end;
            }
            _ => {}
        }
        index += 1;
    }
    keys
}

#[test]
fn a_minted_hold_id_matches_the_wire_pattern_and_is_v4() {
    let id = mint_hold_id();
    assert_eq!(id.len(), 41);
    assert!(id.starts_with("hold_"));
    assert!(is_opaque_hold_id(&id));
    assert!(!id.contains(':'));
    let uuid = &id["hold_".len()..];
    assert_eq!(uuid.as_bytes()[14], b'4');
    assert!(matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
}

#[test]
fn the_pattern_refuses_the_derived_colon_form() {
    assert!(!is_opaque_hold_id("hold:hunt-evt-1:1773739200000"));
    assert!(!is_opaque_hold_id("short"));
    assert!(!is_opaque_hold_id("_leading-underscore"));
    assert!(is_opaque_hold_id("h_a07aeacf"));
}

#[test]
fn the_record_serializes_in_verdict_pane_order() {
    let hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "host-ops-1".to_string(),
        },
        T0,
    );
    // Read the key order off the SERIALIZED TEXT, not off `serde_json::to_value`:
    // `serde_json::Map` is a `BTreeMap` unless the `preserve_order` feature is on
    // (it is not, workspace-wide), so `to_value` sorts the keys alphabetically and
    // would hide the declaration order entirely. `to_string` runs the derived
    // serializer, which emits fields in declaration order — the order a consumer
    // on the wire actually sees.
    let json = serde_json::to_string(&hold).unwrap();
    let keys = top_level_keys(&json);
    // Every field, so a scanner that stopped early could not pass the order
    // assertions vacuously.
    assert_eq!(keys.len(), 18, "{keys:?}");
    // ACTION -> BLAST RADIUS -> IF YOU UNDO -> WHY WE ARE ASKING -> WHAT GRANTING OPENS
    // rides as: action_request -> rehearsal -> (inverse is derived) -> rationale -> expires_at_ms.
    let position = |name: &str| {
        keys.iter()
            .position(|key| key == name)
            .unwrap_or_else(|| panic!("no key `{name}` in {keys:?}"))
    };
    assert!(position("action_request") < position("rehearsal"));
    assert!(position("rehearsal") < position("policy_decision"));
    assert!(position("policy_decision") < position("rationale"));
    assert!(position("rationale") < position("expires_at_ms"));
    assert!(position("hold_id") == 0 && position("state") == 1);
}

#[test]
fn only_the_four_containment_actions_lease_a_containment() {
    let leased = [
        ResponseAction::QuarantineFile {
            host_id: "h".into(),
            file_path: "/tmp/x".into(),
        },
        ResponseAction::SuspendProcess {
            host_id: "h".into(),
            process_name: "p".into(),
        },
        ResponseAction::IsolateHost {
            host_id: "h".into(),
        },
        ResponseAction::TerminateUserSession {
            host_id: "h".into(),
            session_id: "s".into(),
        },
    ];
    for action in leased {
        assert!(fixture_hold(action, T0).leases_a_containment());
    }
    assert!(
        !fixture_hold(
            ResponseAction::BlockEgress {
                target: "203.0.113.10".into()
            },
            T0
        )
        .leases_a_containment()
    );
    assert!(
        !fixture_hold(
            ResponseAction::KillProcess {
                host_id: "h".into(),
                process_name: "p".into()
            },
            T0
        )
        .leases_a_containment()
    );
}

#[test]
fn decidable_is_created_notified_or_armed_and_not_expired() {
    let mut hold = fixture_hold(
        ResponseAction::IsolateHost {
            host_id: "h".into(),
        },
        T0,
    );
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    hold.state = HoldState::Notified;
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    hold.state = HoldState::Armed;
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    assert_eq!(
        hold.assert_decidable(T0 + 3_600_000).unwrap_err(),
        NotDecidable::Expired
    );
    hold.state = HoldState::Deciding;
    assert_eq!(
        hold.assert_decidable(T0 + 1).unwrap_err(),
        NotDecidable::Deciding
    );
    hold.state = HoldState::Refused;
    assert_eq!(
        hold.assert_decidable(T0 + 1).unwrap_err(),
        NotDecidable::Terminal
    );
}
