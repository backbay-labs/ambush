#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Live-relay proof that the bridge's own bytes are admitted.
//!
//! Requires a running relay and `PERCH_TEST_RELAY_URL`; both tests are `#[ignore]`d so a plain
//! `cargo test` needs no network and CI's engine lanes never touch one. Run with:
//!
//! ```sh
//! PERCH_TEST_RELAY_URL=ws://localhost:3000 \
//!   cargo test -p swarm-perch-bridge --test relay_live -- --ignored --nocapture
//! ```
//!
//! The bridge itself issues no read frames (`publish::bridge_issues_no_req_frames`). The second
//! test opens one, from the OPERATOR's socket, because verifying that a private case channel
//! reaches its member is exactly the thing a write-only process cannot check about itself.

use std::time::Duration;

use ambush_ws_client::{NostrWsConnection, RelayMessage};
use swarm_core::config::SecretString;
use swarm_core::types::AgentId;
use swarm_perch_bridge::channels::{PublishStep, case_channel_name, step_to_event};
use swarm_perch_bridge::identity::{Identity, IdentityTable};
use swarm_perch_wire::marker::{CardKind, build_content};
use swarm_perch_wire::tags::TagSet;

fn relay_url() -> String {
    std::env::var("PERCH_TEST_RELAY_URL").expect("PERCH_TEST_RELAY_URL")
}

fn now_secs() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn table() -> IdentityTable {
    let ingest = AgentId("swarm:ed25519:".to_string() + &"ab".repeat(32));
    IdentityTable::build(
        &SecretString::new("42".repeat(32)),
        "relay-live",
        &[],
        &ingest,
        None,
    )
    .unwrap()
}

/// Publishes the lane's `kind:9007` with the alarm identity so the card below has somewhere to
/// land. A duplicate is success — the same rule the alarm drainer applies at startup.
async fn ensure_lane(alarm: &Identity, lane: uuid::Uuid) {
    let mut conn = NostrWsConnection::connect_authenticated(&relay_url(), &alarm.keys, None)
        .await
        .unwrap();
    let step = PublishStep::CreateChannel {
        channel: lane,
        name: "lane-lateral-movement".into(),
        visibility: "open",
        ttl_seconds: None,
    };
    let ok = conn
        .send_event(step_to_event(&step, &alarm.keys, now_secs()).unwrap())
        .await
        .unwrap();
    assert!(
        ok.accepted || ok.message.starts_with("duplicate: channel already exists"),
        "lane create: {}",
        ok.message
    );
}

#[tokio::test]
#[ignore = "needs PERCH_TEST_RELAY_URL and a live relay"]
async fn one_signed_card_is_accepted_by_a_live_relay() {
    let url = relay_url();
    let lane = std::env::var("PERCH_TEST_LANE_CHANNEL")
        .unwrap_or_else(|_| "154eea36-c787-4bf7-9c84-4424b0184395".into());
    let lane_uuid = uuid::Uuid::parse_str(&lane).unwrap();
    let table = table();
    let identity = table.get(table.ingest()).unwrap();
    ensure_lane(table.get(table.alarm()).unwrap(), lane_uuid).await;

    let mut conn = NostrWsConnection::connect_authenticated(&url, &identity.keys, None)
        .await
        .unwrap();
    let content = build_content(
        CardKind::Finding,
        "relay-live · lateral_movement · LOW · confidence 0.10 · host unknown · finding live-1",
        "{\"schema\":\"swarm.spine.envelope.v1\"}",
    )
    .unwrap();
    let tags = TagSet::card(
        CardKind::Finding,
        lane.clone(),
        Some("lateral_movement".into()),
        Some("LOW".into()),
    );
    tags.assert_publishable(9).unwrap();
    let nostr_tags = tags
        .to_tags()
        .into_iter()
        .map(|t| nostr::Tag::parse(t).unwrap())
        .collect::<Vec<_>>();
    let event = nostr::EventBuilder::new(nostr::Kind::Custom(9), content)
        .tags(nostr_tags)
        .sign_with_keys(&identity.keys)
        .unwrap();
    let event_id = event.id.to_hex();
    let ok = conn.send_event(event).await.unwrap();
    println!("finding card event_id={event_id} accepted={}", ok.accepted);
    assert!(ok.accepted, "relay said: {}", ok.message);
}

#[tokio::test]
#[ignore = "needs PERCH_TEST_RELAY_URL and a live relay"]
async fn a_case_channel_is_created_and_the_operator_is_a_member() {
    let url = relay_url();
    let table = table();
    let alarm = table.get(table.alarm()).unwrap();
    let operator = nostr::Keys::generate();
    let case = uuid::Uuid::new_v4();
    let steps = vec![
        PublishStep::CreateChannel {
            channel: case,
            name: case_channel_name(case),
            visibility: "private",
            ttl_seconds: Some(3600),
        },
        PublishStep::AddMember {
            channel: case,
            pubkey: operator.public_key().to_hex(),
        },
    ];
    let mut conn = NostrWsConnection::connect_authenticated(&url, &alarm.keys, None)
        .await
        .unwrap();
    for step in &steps {
        let event = step_to_event(step, &alarm.keys, now_secs()).unwrap();
        let event_id = event.id.to_hex();
        let ok = conn.send_event(event).await.unwrap();
        println!(
            "case step kind event_id={event_id} accepted={} message={}",
            ok.accepted, ok.message
        );
        assert!(
            ok.accepted || ok.message.starts_with("duplicate: channel already exists"),
            "{}",
            ok.message
        );
    }

    // The TEST reads; the bridge never does. The operator's own socket sees the channel metadata.
    let mut reader = NostrWsConnection::connect_authenticated(&url, &operator, None)
        .await
        .unwrap();
    reader
        .send_raw(&serde_json::json!([
            "REQ",
            "case-check",
            {"kinds": [39000], "#d": [case.to_string()], "limit": 1}
        ]))
        .await
        .unwrap();
    let mut saw_metadata = false;
    for _ in 0..10 {
        match reader.next_event(Duration::from_secs(5)).await.unwrap() {
            RelayMessage::Event { event, .. } if event.kind.as_u16() == 39000 => {
                println!("case metadata event_id={}", event.id.to_hex());
                saw_metadata = true;
                break;
            }
            RelayMessage::Eose { .. } => break,
            RelayMessage::Closed { message, .. } => panic!("relay closed the read: {message}"),
            _ => {}
        }
    }
    println!("case_id={case}");
    assert!(
        saw_metadata,
        "kind:39000 for the case channel must reach a member"
    );
}
