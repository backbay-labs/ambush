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

/// The lane channel `PERCH_TEST_LANE_CHANNEL` carries at least one finding card written by
/// `PERCH_TEST_EXPECT_AUTHOR`.
///
/// This is step 6 of `docs/PERCH-DEV.md`: proof that a `RuntimeEvent::Finding` left the daemon,
/// crossed the bridge and is stored by the relay, read back OUT of the daemon's process before
/// any console opens. It is a Rust test and not a `curl` because `POST /query` wants a NIP-98
/// header and the bridge's own keys must never issue a read; the socket below is opened with a
/// throwaway key that has no relationship to the bridge.
#[tokio::test]
#[ignore = "needs PERCH_TEST_RELAY_URL, a live relay, and a daemon that has published"]
async fn lane_carries_a_finding_card_from_the_ingest_identity() {
    let cards = read_lane_cards(20).await;
    assert!(
        !cards.is_empty(),
        "no kind:9 event from the expected author reached the lane"
    );
    let marked = cards
        .iter()
        .filter(|(content, _)| content.lines().next() == Some(CardKind::Finding.marker()))
        .count();
    println!("lane cards={} finding cards={marked}", cards.len());
    assert!(
        marked > 0,
        "no card on the lane opens with the exact line `{}`",
        CardKind::Finding.marker()
    );
}

/// Every card the expected author put on the lane forms one unbroken run.
///
/// # What "contiguous" means here, and what it does NOT mean
///
/// The envelope `seq` is the SPOOL's, assigned at append to every record on the issuer's stream
/// (`spool/mod.rs`), not a counter over published cards. The evidence stream spools every runtime
/// event, and the ones no producer turns into a card yet are committed as
/// `perch_bridge_skipped_unpublished_total` -- consuming their `seq` without ever reaching the
/// relay. So the published seq run is legitimately full of holes: measured against a live daemon
/// it reads `1, 2, 32, 34, 65, 66, 97, 98`, and asserting `windows(2) == 1` over it would fail on
/// a perfectly healthy bridge.
///
/// The claim that actually holds over published cards is the envelope HASH CHAIN: `chain
/// .prev_envelope_hash` advances only when a card is published (`cards.rs`), so consecutive cards
/// from one issuer link head to tail no matter how many records were skipped between them. That
/// is the stronger statement anyway -- it catches a dropped, reordered or duplicated card, which
/// a seq range cannot.
///
/// So this asserts three things: `seq` strictly increases (no replay duplicate, no reordering),
/// the hash chain is unbroken across the run, and no card carries a loss `gap`. Run it after a
/// relay outage (`docker compose stop relay; ...; start relay`) to prove the spool replayed
/// everything it had held.
#[tokio::test]
#[ignore = "needs PERCH_TEST_RELAY_URL, a live relay, and a daemon that has published"]
async fn the_lane_seq_run_is_contiguous() {
    let cards = read_lane_cards(500).await;
    let mut envelopes: Vec<serde_json::Value> = cards
        .iter()
        .filter_map(|(content, _)| {
            let parts = swarm_perch_wire::marker::parse_content(content).ok()?;
            let envelope: serde_json::Value = serde_json::from_str(parts.json).ok()?;
            envelope.get("seq")?.as_u64()?;
            Some(envelope)
        })
        .collect();
    envelopes.sort_by_key(|envelope| envelope["seq"].as_u64().unwrap_or_default());

    let seqs: Vec<u64> = envelopes
        .iter()
        .map(|envelope| envelope["seq"].as_u64().unwrap_or_default())
        .collect();
    println!("seq run: {seqs:?}");
    assert!(
        seqs.len() >= 4,
        "expected at least 4 cards from the author to judge the run, saw {}",
        seqs.len()
    );
    for pair in seqs.windows(2) {
        assert!(
            pair[1] > pair[0],
            "seq {} repeats or precedes {}: a card was replayed or reordered",
            pair[1],
            pair[0]
        );
    }

    for pair in envelopes.windows(2) {
        let previous = pair[0]["envelope_hash"].as_str().unwrap_or_default();
        let claimed = pair[1]["prev_envelope_hash"].as_str().unwrap_or_default();
        assert_eq!(
            claimed, previous,
            "the envelope chain breaks between seq {} and seq {}: a published card is missing",
            pair[0]["seq"], pair[1]["seq"]
        );
    }

    for envelope in &envelopes {
        let gap = envelope.pointer("/fact/gap");
        assert!(
            gap.is_none(),
            "card at seq {} reports a loss: {}",
            envelope["seq"],
            gap.map(ToString::to_string).unwrap_or_default()
        );
    }
}

/// One `REQ` for `kind:9` on `PERCH_TEST_LANE_CHANNEL` authored by `PERCH_TEST_EXPECT_AUTHOR`,
/// read from a throwaway socket. Returns `(content, event id hex)` per event.
///
/// The `authors` filter is what makes this an admitted-issuer check and not a "somebody wrote
/// something" check: `PERCH_TEST_EXPECT_AUTHOR` is a pubkey from
/// `GET /metrics/perch/identities`, which is the same set INV-15 lets the console render.
async fn read_lane_cards(limit: usize) -> Vec<(String, String)> {
    let url = relay_url();
    let lane = std::env::var("PERCH_TEST_LANE_CHANNEL").expect("PERCH_TEST_LANE_CHANNEL");
    let author = std::env::var("PERCH_TEST_EXPECT_AUTHOR").expect("PERCH_TEST_EXPECT_AUTHOR");
    let reader_keys = nostr::Keys::generate();
    let mut reader = NostrWsConnection::connect_authenticated(&url, &reader_keys, None)
        .await
        .unwrap();
    reader
        .send_raw(&serde_json::json!([
            "REQ",
            "lane-cards",
            {"kinds": [9], "#h": [lane], "authors": [author], "limit": limit}
        ]))
        .await
        .unwrap();

    let mut out = Vec::new();
    loop {
        match reader.next_event(Duration::from_secs(10)).await.unwrap() {
            RelayMessage::Event { event, .. } => {
                out.push((event.content.clone(), event.id.to_hex()));
            }
            RelayMessage::Eose { .. } => break,
            RelayMessage::Closed { message, .. } => panic!("relay closed the read: {message}"),
            _ => {}
        }
    }
    out
}
