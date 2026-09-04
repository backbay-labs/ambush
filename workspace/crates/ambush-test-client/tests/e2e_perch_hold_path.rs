//! The bridge's hold sequence, end to end, against a live relay:
//! 9007 -> 9000 -> kind:9 `swarm:hold:v1` -> 46010 -> 26006.
//!
//! # What this adds over the two binaries beside it
//!
//! `e2e_workflow_approval.rs` pins the 46010 write and read rules one event at a
//! time, and `e2e_operator_alarm_pgate.rs` pins the 26006 `P_GATED_KINDS` rule
//! the same way. Neither publishes the events in the order the bridge does, and
//! neither crosses from one kind to the other. This binary does exactly that and
//! nothing else: it plays the five frames of one hold in publish order from a
//! single bridge identity, and asserts that the notice and the alarm reach the
//! one operator named on them and no other.
//!
//! The ordering is the part that can fail on its own. The 46010 carries a `card`
//! tag naming the kind:9 that must already be stored, and it is refused outright
//! unless its `h` channel exists and admits the publisher -- so the 9007 and the
//! 9000 are load-bearing prefix, not setup noise.
//!
//! # Running
//!
//! ```text
//! RELAY_URL=ws://localhost:3000 cargo test -p ambush-test-client \
//!     --test e2e_perch_hold_path -- --ignored --nocapture
//! ```

use std::time::Duration;

use ambush_test_client::{AmbushTestClient, RelayMessage};
use nostr::{Alphabet, EventBuilder, Filter, Keys, Kind, SingleLetterTag, Tag};
use reqwest::Client;
use serde_json::Value;

/// Taken from `ambush_core::kind` rather than typed as literals so a constant
/// move breaks compilation instead of silently testing a different kind.
const KIND_CREATE_GROUP: u16 = ambush_core::kind::KIND_NIP29_CREATE_GROUP as u16;
const KIND_PUT_USER: u16 = ambush_core::kind::KIND_NIP29_PUT_USER as u16;
const KIND_STREAM_MESSAGE: u16 = ambush_core::kind::KIND_STREAM_MESSAGE as u16;
const KIND_APPROVAL_REQUESTED: u16 = ambush_core::kind::KIND_WORKFLOW_APPROVAL_REQUESTED as u16;
const KIND_ALARM: u16 = ambush_core::kind::KIND_OPERATOR_ALARM_FRAME as u16;

/// How long a "must not arrive" assertion waits before it is satisfied. The
/// paired positive control in the same test is what proves the publish and the
/// fan-out actually ran.
const SILENCE_WINDOW: Duration = Duration::from_secs(3);

/// The opaque hold id under test. Matches R-3's
/// `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$` and carries no colon, so it is safe in a
/// tag value; the card body below repeats it, as the bridge's does.
const HOLD_ID: &str = "h_e2e00001";

/// The card body the bridge publishes as the kind:9: marker line, one human
/// line, blank line, fenced JSON (W3-21).
const HOLD_CARD: &str = "<!-- swarm:hold:v1 -->\nhold h_e2e00001 · isolate_host · CRITICAL · host host-ops-1 · expires 2026-03-17T10:14:42Z\n\n```swarm:hold:v1\n{\"schema\":\"swarm.spine.envelope.v1\",\"issuer\":\"swarm:ed25519:00\",\"seq\":1,\"prev_envelope_hash\":null,\"issued_at\":\"2026-03-17T09:14:42Z\",\"capability_token\":null,\"fact\":{\"schema\":\"swarm.perch.hold.v1\"},\"envelope_hash\":\"0x00\"}\n```";

fn relay_url() -> String {
    std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:3000".to_string())
}

fn relay_http_url() -> String {
    relay_url()
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .trim_end_matches('/')
        .to_string()
}

fn sub_id(name: &str) -> String {
    format!("e2e-perch-hold-{name}-{}", uuid::Uuid::new_v4())
}

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client")
}

/// Every 46010 the relay stores for `pubkey`, read the way the console's
/// needs-action pane reads it: an explicit `kinds` filter narrowed by the
/// reader's own `#p`.
async fn needs_action_46010(pubkey: &str) -> Vec<Value> {
    let body = serde_json::json!([{
        "kinds": [KIND_APPROVAL_REQUESTED],
        "#p": [pubkey],
        "limit": 20,
    }]);
    let resp = http_client()
        .post(format!("{}/query", relay_http_url()))
        .header("X-Pubkey", pubkey)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("needs-action query");
    assert!(
        resp.status().is_success(),
        "needs-action query failed: {}",
        resp.status()
    );
    resp.json().await.expect("parse needs-action response")
}

/// Drain until the relay terminates `sub_id`, returning the `CLOSED` reason.
///
/// An `EOSE` for the same subscription is a hard failure rather than a timeout:
/// it means the REQ was accepted, which is the outcome being asserted against.
async fn expect_closed(client: &mut AmbushTestClient, sub_id: &str, budget: Duration) -> String {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        assert!(
            !remaining.is_zero(),
            "relay neither closed nor EOSE'd subscription {sub_id} within {budget:?}"
        );
        match client.recv_event(remaining).await {
            Ok(RelayMessage::Closed {
                subscription_id,
                message,
            }) if subscription_id == sub_id => return message,
            Ok(RelayMessage::Eose { subscription_id }) if subscription_id == sub_id => {
                panic!("subscription {sub_id} was ACCEPTED (EOSE); expected a CLOSED refusal")
            }
            Ok(_) => {}
            Err(e) => panic!("transport error while waiting for CLOSED on {sub_id}: {e}"),
        }
    }
}

/// Wait for an alarm frame whose content equals `marker`, or return `None` when
/// the silence window elapses without one.
async fn await_alarm(client: &mut AmbushTestClient, marker: &str) -> Option<String> {
    let deadline = tokio::time::Instant::now() + SILENCE_WINDOW;
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return None;
        }
        match client.recv_event(remaining).await {
            Ok(RelayMessage::Event {
                subscription_id,
                event,
            }) if event.content == marker => {
                assert_eq!(
                    event.kind,
                    Kind::Custom(KIND_ALARM),
                    "the marker arrived on the wrong kind"
                );
                return Some(subscription_id);
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
}

#[tokio::test]
#[ignore]
async fn the_hold_sequence_is_accepted_in_publish_order_and_reaches_only_the_named_operator() {
    let bridge = Keys::generate();
    let operator_a = Keys::generate();
    let operator_b = Keys::generate();
    let a_hex = operator_a.public_key().to_hex();
    let b_hex = operator_b.public_key().to_hex();
    let case = uuid::Uuid::new_v4().to_string();
    let marker = uuid::Uuid::new_v4().to_string();

    let mut bridge_conn = AmbushTestClient::connect(&relay_url(), &bridge)
        .await
        .expect("bridge connect");

    // ── 1. kind:9007 create-group: the case channel, private, with a ttl. ──
    let create = EventBuilder::new(Kind::Custom(KIND_CREATE_GROUP), "")
        .tags(vec![
            Tag::parse(["h", &case]).unwrap(),
            Tag::parse(["name", &format!("case-e2e-{case}")]).unwrap(),
            Tag::parse(["channel_type", "stream"]).unwrap(),
            Tag::parse(["visibility", "private"]).unwrap(),
            Tag::parse(["ttl", "2592000"]).unwrap(),
        ])
        .sign_with_keys(&bridge)
        .unwrap();
    let ok = bridge_conn.send_event(create).await.expect("send 9007");
    assert!(ok.accepted, "create-group rejected: {}", ok.message);

    // ── 2. kind:9000 put-user: operator A is admitted, operator B is not. ──
    let put_user = EventBuilder::new(Kind::Custom(KIND_PUT_USER), "")
        .tags(vec![
            Tag::parse(["h", &case]).unwrap(),
            Tag::parse(["p", &a_hex]).unwrap(),
            Tag::parse(["role", "member"]).unwrap(),
        ])
        .sign_with_keys(&bridge)
        .unwrap();
    let ok = bridge_conn.send_event(put_user).await.expect("send 9000");
    assert!(ok.accepted, "put-user rejected: {}", ok.message);

    // ── 3. the kind:9 card. Its id is what the notice's `card` tag names, so ──
    //      it has to be accepted and stored before the notice is published.
    let card = EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE), HOLD_CARD)
        .tags(vec![
            Tag::parse(["h", &case]).unwrap(),
            Tag::parse(["k", "hold"]).unwrap(),
        ])
        .sign_with_keys(&bridge)
        .unwrap();
    let card_id = card.id.to_hex();
    let ok = bridge_conn.send_event(card).await.expect("send kind:9");
    assert!(ok.accepted, "hold card rejected: {}", ok.message);

    // ── 4. the 46010 notice: exactly one h, one p, one hold, one card. ──
    //      Never `e` (RF-D1): an `e` tag would thread it into the timeline.
    let notice = EventBuilder::new(Kind::Custom(KIND_APPROVAL_REQUESTED), &marker)
        .tags(vec![
            Tag::parse(["h", &case]).unwrap(),
            Tag::parse(["p", &a_hex]).unwrap(),
            Tag::parse(["hold", HOLD_ID]).unwrap(),
            Tag::parse(["card", &card_id]).unwrap(),
        ])
        .sign_with_keys(&bridge)
        .unwrap();
    let ok = bridge_conn.send_event(notice).await.expect("send 46010");
    assert!(
        ok.accepted,
        "the 46010 notice was rejected: {}. If the message is \
         `restricted: unknown event kind`, the 46010 arm in `required_scope_for_kind` \
         did not land (W3-7) -- report against 11-PLAN-GROUND.md.",
        ok.message
    );

    // ── 5. the needs-action join: A sees the notice, B does not. ──
    let for_a = needs_action_46010(&a_hex).await;
    let mine: Vec<&Value> = for_a
        .iter()
        .filter(|e| e["content"].as_str() == Some(marker.as_str()))
        .collect();
    assert_eq!(
        mine.len(),
        1,
        "operator A's needs-action feed must carry exactly this hold's notice; \
         got {} of {} row(s)",
        mine.len(),
        for_a.len()
    );
    let tags = mine[0]["tags"].as_array().expect("notice tags");
    let count = |name: &str| tags.iter().filter(|t| t[0] == name).count();
    assert_eq!(count("e"), 0, "a 46010 never carries an `e` tag (RF-D1)");
    assert_eq!(count("h"), 1, "exactly one h names the case channel");
    assert_eq!(count("p"), 1, "one p per Approve principal; here, A alone");
    assert_eq!(count("hold"), 1, "exactly one hold tag");
    assert_eq!(count("card"), 1, "at most one card tag");
    let carried_card = tags
        .iter()
        .find(|t| t[0] == "card")
        .and_then(|t| t[1].as_str())
        .expect("card tag value");
    assert_eq!(
        carried_card, card_id,
        "the notice's card tag must name the kind:9 published before it"
    );
    let carried_hold = tags
        .iter()
        .find(|t| t[0] == "hold")
        .and_then(|t| t[1].as_str())
        .expect("hold tag value");
    assert_eq!(carried_hold, HOLD_ID);

    let for_b = needs_action_46010(&b_hex).await;
    assert!(
        !for_b
            .iter()
            .any(|e| e["content"].as_str() == Some(marker.as_str())),
        "operator B is neither named nor a member and must not see the notice"
    );

    // ── 6. the 26006 alarm: global, p = A only. ──
    let mut a_conn = AmbushTestClient::connect(&relay_url(), &operator_a)
        .await
        .expect("operator A connect");
    let mut b_conn = AmbushTestClient::connect(&relay_url(), &operator_b)
        .await
        .expect("operator B connect");
    let mut anon = AmbushTestClient::connect(&relay_url(), &Keys::generate())
        .await
        .expect("bystander connect");

    // A `#p`-less REQ for the alarm kind is refused at registration: without
    // the P_GATED_KINDS entry this subscription would enumerate every frame.
    let anon_sub = sub_id("anon");
    anon.subscribe(
        &anon_sub,
        vec![Filter::new().kind(Kind::Custom(KIND_ALARM))],
    )
    .await
    .expect("bystander REQ");
    let closed = expect_closed(&mut anon, &anon_sub, Duration::from_secs(5)).await;
    assert!(
        closed.contains("p-gated") || closed.contains("restricted"),
        "unexpected CLOSED reason for a #p-less alarm REQ: {closed}"
    );

    let a_sub = sub_id("a");
    a_conn
        .subscribe(
            &a_sub,
            vec![Filter::new()
                .kind(Kind::Custom(KIND_ALARM))
                .custom_tags(SingleLetterTag::lowercase(Alphabet::P), [a_hex.as_str()])],
        )
        .await
        .expect("A REQ");
    let b_sub = sub_id("b");
    b_conn
        .subscribe(
            &b_sub,
            vec![Filter::new()
                .kind(Kind::Custom(KIND_ALARM))
                .custom_tags(SingleLetterTag::lowercase(Alphabet::P), [b_hex.as_str()])],
        )
        .await
        .expect("B REQ");

    let alarm = EventBuilder::new(Kind::Custom(KIND_ALARM), &marker)
        .tags(vec![Tag::parse(["p", &a_hex]).unwrap()])
        .sign_with_keys(&bridge)
        .unwrap();
    let ok = bridge_conn.send_event(alarm).await.expect("send 26006");
    assert!(ok.accepted, "the alarm frame was rejected: {}", ok.message);

    let delivered = await_alarm(&mut a_conn, &marker).await;
    assert_eq!(
        delivered.as_deref(),
        Some(a_sub.as_str()),
        "operator A is named on the alarm and must receive it"
    );
    assert!(
        await_alarm(&mut b_conn, &marker).await.is_none(),
        "operator B received an alarm it was not named on"
    );
}
