//! Leg 2's tests.
//!
//! The two properties that matter here are ORDERING and IDENTITY, and neither
//! is visible in a return value:
//!
//! - a retry must re-send the SAME bytes, never re-sign. A test that only
//!   asserts "the retry returned Ok" passes against a loop that rebuilds the
//!   body with a fresh clock — which would invalidate the signature and, worse,
//!   present the daemon with a second distinct intent id for one human
//!   decision. So the recording sender below captures every request and the
//!   test compares them byte for byte.
//! - leg 2 must not sign or stamp anything. That is structural, so it is
//!   asserted structurally, against this module's own source.

use super::*;

fn signature() -> DetachedSignature {
    DetachedSignature {
        algorithm: "ed25519".to_string(),
        key_id: "ab".repeat(32),
        public_key_hex: "cd".repeat(32),
        signature_hex: "ef".repeat(64),
    }
}

fn input() -> DecideHoldInput {
    DecideHoldInput {
        hold_id: "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13".to_string(),
        decision: PerchDecision::Grant,
        rationale: Some("two detectors agree".to_string()),
        decided_at_ms: 1_773_738_979_000,
        nostr_intent_event_id: "aa".repeat(32),
        signature: signature(),
        armed_at_ms: Some(1_773_738_977_500),
    }
}

/// A sender that answers from a script and records what it was asked to send.
struct Recorder {
    scripted: std::sync::Mutex<Vec<Result<DaemonResponse, String>>>,
    sent: std::sync::Mutex<Vec<DecideAttempt>>,
}

impl Recorder {
    fn new(scripted: Vec<Result<DaemonResponse, String>>) -> Self {
        Self {
            scripted: std::sync::Mutex::new(scripted),
            sent: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn sent(&self) -> Vec<DecideAttempt> {
        self.sent.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    async fn send(&self, attempt: DecideAttempt) -> Result<DaemonResponse, String> {
        self.sent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(attempt);
        let mut scripted = self.scripted.lock().unwrap_or_else(|p| p.into_inner());
        if scripted.is_empty() {
            return Err("the recorder ran out of scripted answers".to_string());
        }
        scripted.remove(0)
    }
}

fn ok(body: serde_json::Value) -> Result<DaemonResponse, String> {
    Ok(DaemonResponse {
        status: 200,
        body,
        retry_after_seconds: None,
    })
}

fn conflict(error: &str, retry_after_seconds: Option<u64>) -> Result<DaemonResponse, String> {
    Ok(DaemonResponse {
        status: 409,
        body: serde_json::json!({ "error": error, "message": "…" }),
        retry_after_seconds,
    })
}

fn granted_body() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "hold_id": "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13",
        "state": "executed",
        "replayed": false,
        "decision": {
            "outcome": "granted_executed",
            "dispatched": true,
            "decided_at_ms": 1_773_738_979_100_i64,
            "receipt_id": "resp:evt-1:isolate_host",
            "refusal": serde_json::Value::Null
        }
    })
}

// ── the retry property ─────────────────────────────────────────────────────

/// A `decision_in_flight` retry re-sends the SAME bytes.
///
/// The mutation this exists to catch is a loop that rebuilds the request from
/// the input on each attempt with a fresh clock or a fresh id. That mutation
/// still returns `Ok` on the second attempt, so a test asserting only the
/// outcome passes over it — while the daemon has now seen two distinct intent
/// ids for one human decision and can record two.
#[tokio::test]
async fn a_retry_re_sends_byte_identical_bytes_and_never_re_signs() {
    let recorder = Recorder::new(vec![
        conflict("decision_in_flight", Some(0)),
        ok(granted_body()),
    ]);
    let outcome = decide_with(&input(), |attempt| recorder.send(attempt))
        .await
        .expect("the retry succeeds");
    assert!(matches!(outcome.outcome, DecideOutcomeKind::Dispatched));

    let sent = recorder.sent();
    assert_eq!(sent.len(), 2, "exactly one retry");
    assert!(sent.iter().all(|a| a.kind == DecideAttemptKind::Decide));
    assert_eq!(
        sent[0].body, sent[1].body,
        "the retry re-sent different bytes; leg 2 must never re-sign or re-stamp"
    );
    // And the bytes are the ones leg 1 produced, not anything this command minted.
    assert_eq!(sent[0].body["decided_at_ms"], 1_773_738_979_000_i64);
    assert_eq!(sent[0].body["nostr_intent_event_id"], "aa".repeat(32));
    assert_eq!(sent[0].body["signature"]["signature_hex"], "ef".repeat(64));
    assert_eq!(sent[0].body["rationale"], "two detectors agree");
}

/// Exactly one retry. A second `decision_in_flight` is surfaced, not retried
/// forever: the console has to tell the operator the daemon is still applying
/// a decision rather than spin.
#[tokio::test]
async fn a_second_decision_in_flight_is_surfaced_rather_than_retried_forever() {
    let recorder = Recorder::new(vec![
        conflict("decision_in_flight", Some(0)),
        conflict("decision_in_flight", Some(0)),
    ]);
    let error = decide_with(&input(), |attempt| recorder.send(attempt))
        .await
        .expect_err("a persistent in-flight conflict is an error");
    assert_eq!(error, "decision_in_flight");
    assert_eq!(
        recorder.sent().len(),
        2,
        "one attempt and one retry, no more"
    );
}

// ── W3-17: the winner comes from a RE-READ, never from the error body ──────

/// `hold_already_decided` re-reads the hold and reports the winner from the
/// daemon's own record.
///
/// The 409 body is `{error, message}` and carries no winner. A console that
/// invented one from the error text would report a decision nobody made, which
/// is why the re-read is a second request and the test asserts it happened.
#[tokio::test]
async fn a_conflict_re_reads_the_hold_and_names_the_winner_from_the_record() {
    let re_read = serde_json::json!({
        "hold": {
            "hold_id": "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13",
            "state": "refused",
            "deciding_intent_event_id": "bb".repeat(32),
            "decision": { "decision": "refuse", "decided_at_ms": 5 }
        }
    });
    let recorder = Recorder::new(vec![conflict("hold_already_decided", None), ok(re_read)]);
    let outcome = decide_with(&input(), |attempt| recorder.send(attempt))
        .await
        .expect("a conflict is an outcome, not an error");
    assert!(matches!(outcome.outcome, DecideOutcomeKind::Superseded));
    assert_eq!(
        outcome.superseded_by.as_deref(),
        Some("bb".repeat(32).as_str())
    );
    assert_eq!(outcome.decided_at_ms, 5);

    let sent = recorder.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].kind, DecideAttemptKind::Decide);
    assert_eq!(
        sent[1].kind,
        DecideAttemptKind::ReadHold,
        "the winner must come from GET /v1/response/holds/{{hold_id}}, not the 409 body"
    );
}

/// A conflict whose re-read names OUR OWN intent is not a supersession: the
/// decision that won was this console's. Reporting it as superseded would tell
/// the operator someone overrode them when nobody did.
#[tokio::test]
async fn a_conflict_that_re_reads_our_own_intent_is_not_a_supersession() {
    let re_read = serde_json::json!({
        "hold": {
            "state": "refused",
            "deciding_intent_event_id": "aa".repeat(32),
            "decision": { "decision": "refuse", "decided_at_ms": 9 }
        }
    });
    let recorder = Recorder::new(vec![conflict("hold_already_decided", None), ok(re_read)]);
    let outcome = decide_with(&input(), |attempt| recorder.send(attempt))
        .await
        .expect("an outcome");
    assert!(
        !matches!(outcome.outcome, DecideOutcomeKind::Superseded),
        "our own winning intent is not a supersession"
    );
    assert_eq!(outcome.superseded_by, None);
}

#[tokio::test]
async fn an_expired_hold_and_an_unknown_hold_are_typed_outcomes() {
    let recorder = Recorder::new(vec![conflict("hold_expired", None)]);
    let outcome = decide_with(&input(), |a| recorder.send(a)).await.unwrap();
    assert!(matches!(outcome.outcome, DecideOutcomeKind::Expired));
    assert_eq!(recorder.sent().len(), 1, "an expired hold needs no re-read");

    let recorder = Recorder::new(vec![Ok(DaemonResponse {
        status: 404,
        body: serde_json::json!({ "error": "not_found", "message": "no hold" }),
        retry_after_seconds: None,
    })]);
    let outcome = decide_with(&input(), |a| recorder.send(a)).await.unwrap();
    assert!(matches!(outcome.outcome, DecideOutcomeKind::UnknownHold));
}

// ── the 200 mapping ────────────────────────────────────────────────────────

#[test]
fn a_200_refused_late_maps_the_rule_and_reason_verbatim() {
    let body = serde_json::json!({
        "hold_id": "h_a07aeacf", "state": "refused", "replayed": false,
        "decision": {
            "outcome": "refused_late", "dispatched": false, "decided_at_ms": 7,
            "refusal": {
                "rule": "runtime.containment_refused",
                "reason": "no containment lease store is configured"
            }
        }
    });
    let outcome = map_success(&body);
    assert!(matches!(outcome.outcome, DecideOutcomeKind::RefusedLate));
    assert_eq!(
        outcome.reason.as_deref(),
        Some("no containment lease store is configured")
    );
    assert_eq!(outcome.rule.as_deref(), Some("runtime.containment_refused"));
    assert!(!outcome.dispatched);

    let governance = serde_json::json!({
        "hold_id": "h", "state": "refused", "replayed": false,
        "decision": {
            "outcome": "refused_late", "dispatched": false, "decided_at_ms": 7,
            "refusal": { "rule": "governance.receipt_veto", "reason": "veto" }
        }
    });
    assert!(matches!(
        map_success(&governance).outcome,
        DecideOutcomeKind::RefusedLateGovernance
    ));
}

/// Every outcome the daemon can record maps to something, and `dispatched`
/// rides through untouched. A refusal the operator MADE and a refusal the
/// daemon imposed are different rows, so they are different kinds.
#[test]
fn every_daemon_outcome_maps_and_dispatched_is_carried_not_inferred() {
    let cases = [
        ("granted_executed", true, "dispatched"),
        ("granted_simulated", true, "dispatched"),
        ("granted_failed", true, "refused_late"),
        ("refused_by_operator", false, "dispatched"),
        ("refused_late", false, "refused_late"),
        ("guard_rejected", false, "refused_late"),
    ];
    for (outcome, dispatched, expected) in cases {
        let body = serde_json::json!({
            "state": "refused", "replayed": false,
            "decision": { "outcome": outcome, "dispatched": dispatched, "decided_at_ms": 1 }
        });
        let mapped = map_success(&body);
        let label = match mapped.outcome {
            DecideOutcomeKind::Dispatched => "dispatched",
            DecideOutcomeKind::RefusedLate => "refused_late",
            DecideOutcomeKind::RefusedLateGovernance => "refused_late_governance",
            DecideOutcomeKind::Expired => "expired",
            DecideOutcomeKind::UnknownHold => "unknown_hold",
            DecideOutcomeKind::Superseded => "superseded",
        };
        assert_eq!(label, expected, "{outcome}");
        assert_eq!(mapped.dispatched, dispatched, "{outcome}");
    }
}

/// A replayed decision says so. The console renders "already recorded", not a
/// second success.
#[test]
fn a_replayed_decision_is_reported_as_replayed() {
    let mut body = granted_body();
    body["replayed"] = serde_json::Value::Bool(true);
    assert!(map_success(&body).replayed);
}

// ── the structural properties ──────────────────────────────────────────────

/// Leg 2 signs nothing and stamps no clock.
///
/// This is the architectural rule — the console never authorizes, and leg 2
/// carries leg 1's signed bytes rather than making its own — and no return
/// value can show it. A future edit that reached for a signing key or a clock
/// here would produce a second intent for one decision; the scan is what
/// notices.
#[test]
fn leg_two_names_no_signing_key_and_no_clock() {
    // Strip comments first. A scan over raw source counts the doc comment that
    // EXPLAINS the rule as a violation of it — prose read as behaviour, which
    // is the exact failure this family of structural tests is prone to. The
    // stripper is checked below against a fixture carrying every needle in a
    // comment, so a stripper that silently removed everything would fail too.
    let source = strip_comments(include_str!("perch_writes.rs"));
    for needle in [
        "signing_keys()",
        "sign_with_keys(",
        "SigningKey",
        "operator_signing_key",
        "perch_record_verdict",
        "SystemTime::now",
        "Utc::now",
        "now_ms(",
    ] {
        assert!(
            !source.contains(needle),
            "leg 2 must not name `{needle}`: it re-sends leg 1's bytes, it does not mint them"
        );
    }
    // The scan is not vacuous: the code it did read still contains the things
    // leg 2 legitimately does.
    assert!(
        source.contains("perch_daemon_post"),
        "the stripper ate the code"
    );
    assert!(source.contains("decide_with"), "the stripper ate the code");
}

/// Remove `//` line comments and `/* … */` blocks, leaving string literals
/// alone.
fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        if in_string {
            if bytes[index] == b'\\' && index + 1 < bytes.len() {
                out.push_str(&source[index..index + 2]);
                index += 2;
                continue;
            }
            if bytes[index] == b'"' {
                in_string = false;
            }
            out.push(bytes[index] as char);
            index += 1;
            continue;
        }
        match (bytes[index], bytes.get(index + 1)) {
            (b'"', _) => {
                in_string = true;
                out.push('"');
                index += 1;
            }
            (b'/', Some(b'/')) => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            (b'/', Some(b'*')) => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            }
            (byte, _) => {
                out.push(byte as char);
                index += 1;
            }
        }
    }
    out
}

/// The stripper removes comments and keeps code, both directions.
///
/// Without this the structural test above could pass because the stripper
/// returned an empty string.
#[test]
fn the_comment_stripper_removes_prose_and_keeps_code() {
    let source = r#"
// SigningKey in a line comment
/* SystemTime::now in a block comment */
let kept = "SigningKey in a string literal";
fn real_code() {}
"#;
    let stripped = strip_comments(source);
    assert!(!stripped.contains("line comment"));
    assert!(!stripped.contains("block comment"));
    assert!(stripped.contains("fn real_code"));
    assert!(
        stripped.contains("SigningKey in a string literal"),
        "string literals are code and must survive"
    );
}

/// The decide route this file names is the one on the INV-01 table, and the
/// re-read is a GET that is deliberately NOT on it.
#[test]
fn the_decide_route_is_allowlisted_and_the_re_read_is_not_a_write() {
    use crate::perch::daemon_client::{is_allowlisted_write, PERCH_DAEMON_WRITES};
    assert!(is_allowlisted_write("POST", ROUTE_DECIDE_HOLD));
    assert!(
        !PERCH_DAEMON_WRITES
            .iter()
            .any(|(_, template)| *template == ROUTE_GET_HOLD),
        "the 409 re-read is a GET and must never appear on the write table"
    );
}
