//! End-to-end integration tests for kind:46010 (workflow approval requested).
//!
//! Before the ingest change these tests cover, kind:46010 was declared in
//! `ambush_core::kind`, listed in `ALL_KINDS`, selected by `query_needs_action`,
//! read by the Desktop home feed and subscribed to by the ACP harness's default
//! mention rule -- and rejected by `required_scope_for_kind` with
//! `"restricted: unknown event kind"`, so nothing could ever emit one.
//!
//! These tests pin the whole contract the change creates:
//!
//! - the write path accepts a 46010 that names its channel, and still rejects
//!   one that does not;
//! - the sibling kinds 46011 / 46012 stay unpublishable, so the change is
//!   exactly one kind wide;
//! - a channel-scoped REQ receives it live and a global REQ never does
//!   (the `fan_out_scoped` invariant, `crates/ambush-relay/src/subscription.rs`);
//! - the `p` tag reaches `event_mentions`, so `query_needs_action`'s INNER JOIN
//!   returns it through the `feed_types` bridge extension;
//! - a non-member cannot publish one into a private channel.
//!
//! # Running
//!
//! Start the relay, then run:
//!
//! ```text
//! RELAY_URL=ws://localhost:3000 cargo test -p ambush-test-client \
//!     --test e2e_workflow_approval -- --ignored --nocapture
//! ```

use std::collections::HashSet;
use std::time::Duration;

use ambush_test_client::{AmbushTestClient, RelayMessage};
use nostr::{Alphabet, EventBuilder, Filter, Keys, Kind, SingleLetterTag, Tag};
use reqwest::Client;
use serde_json::Value;

/// The wire value under test. Taken from `ambush_core` rather than typed as a
/// literal so a constant move breaks compilation instead of silently testing
/// a different kind; `kind_constant_is_the_wire_value` pins the number itself.
const KIND_APPROVAL_REQUESTED: u16 = ambush_core::kind::KIND_WORKFLOW_APPROVAL_REQUESTED as u16;
const KIND_APPROVAL_GRANTED: u16 = ambush_core::kind::KIND_WORKFLOW_APPROVAL_GRANTED as u16;
const KIND_APPROVAL_DENIED: u16 = ambush_core::kind::KIND_WORKFLOW_APPROVAL_DENIED as u16;

/// How long a "must not arrive" assertion waits before it is satisfied. Long
/// enough that a real delivery would have landed; the paired positive control
/// in the same test is what proves the publish and the fan-out actually ran.
const SILENCE_WINDOW: Duration = Duration::from_secs(3);

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
    format!("e2e-wf-approval-{name}-{}", uuid::Uuid::new_v4())
}

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client")
}

/// Create a channel via a signed kind:9007 event submitted to POST /events.
/// `visibility` is "open" or "private" -- private is what makes the membership
/// gate observable, since an open channel admits any authenticated member.
async fn create_channel(keys: &Keys, visibility: &str) -> String {
    let client = http_client();
    let channel_uuid = uuid::Uuid::new_v4();
    let event = EventBuilder::new(Kind::Custom(9007), "")
        .tags(vec![
            Tag::parse(["h", &channel_uuid.to_string()]).unwrap(),
            Tag::parse(["name", &format!("wf-approval-e2e-{channel_uuid}")]).unwrap(),
            Tag::parse(["channel_type", "stream"]).unwrap(),
            Tag::parse(["visibility", visibility]).unwrap(),
        ])
        .sign_with_keys(keys)
        .unwrap();

    let resp = client
        .post(format!("{}/events", relay_http_url()))
        .header("X-Pubkey", keys.public_key().to_hex())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&event).unwrap())
        .send()
        .await
        .expect("submit create-channel event");
    let body: Value = resp.json().await.expect("parse create-channel response");
    assert!(
        body["accepted"].as_bool().unwrap_or(false),
        "channel creation not accepted: {body}"
    );
    channel_uuid.to_string()
}

/// Build a kind:46010 carrying the tags a real approval request carries: `h`
/// names the channel the decision belongs to, `p` names each pubkey whose
/// needs-action feed it must enter.
fn build_approval_request(
    keys: &Keys,
    channel_id: Option<&str>,
    p_pubkeys: &[String],
    content: &str,
) -> nostr::Event {
    let mut tags: Vec<Tag> = Vec::new();
    if let Some(ch) = channel_id {
        tags.push(Tag::parse(["h", ch]).unwrap());
    }
    for pk in p_pubkeys {
        tags.push(Tag::parse(["p", pk.as_str()]).unwrap());
    }
    EventBuilder::new(Kind::Custom(KIND_APPROVAL_REQUESTED), content)
        .tags(tags)
        .sign_with_keys(keys)
        .unwrap()
}

#[tokio::test]
#[ignore]
async fn approval_request_with_an_h_tag_is_accepted() {
    let keys = Keys::generate();
    let channel = create_channel(&keys, "open").await;
    let mut client = AmbushTestClient::connect(&relay_url(), &keys)
        .await
        .expect("connect");

    let event = build_approval_request(
        &keys,
        Some(&channel),
        &[keys.public_key().to_hex()],
        r#"{"step_id":"deploy","message":"promote to prod?"}"#,
    );
    let ok = client.send_event(event).await.expect("send 46010");

    assert!(
        ok.accepted,
        "kind:46010 must be publishable into a channel, got: {}",
        ok.message
    );
    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn approval_request_without_an_h_tag_is_rejected() {
    let keys = Keys::generate();
    // Create a channel first so the account is a normal community member and
    // the rejection below is specifically the channel-scoping rule.
    create_channel(&keys, "open").await;
    let mut client = AmbushTestClient::connect(&relay_url(), &keys)
        .await
        .expect("connect");

    let event = build_approval_request(
        &keys,
        None,
        &[keys.public_key().to_hex()],
        r#"{"step_id":"deploy","message":"promote to prod?"}"#,
    );
    let ok = client.send_event(event).await.expect("send h-less 46010");

    assert!(
        !ok.accepted,
        "an h-less kind:46010 must be rejected, not stored community-globally"
    );
    assert_eq!(
        ok.message,
        "invalid: channel-scoped events must include an h tag"
    );
    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn approval_granted_and_denied_kinds_stay_unpublishable() {
    // The change is exactly one kind wide. 46011 and 46012 have no producer and
    // no reader contract, so they keep the default rejection.
    let keys = Keys::generate();
    let channel = create_channel(&keys, "open").await;
    let mut client = AmbushTestClient::connect(&relay_url(), &keys)
        .await
        .expect("connect");

    for kind in [KIND_APPROVAL_GRANTED, KIND_APPROVAL_DENIED] {
        let event = EventBuilder::new(Kind::Custom(kind), "")
            .tags([Tag::parse(["h", channel.as_str()]).unwrap()])
            .sign_with_keys(&keys)
            .unwrap();
        let ok = client.send_event(event).await.expect("send sibling kind");
        assert!(!ok.accepted, "kind:{kind} must still be rejected");
        assert_eq!(ok.message, "restricted: unknown event kind");
    }
    client.disconnect().await.expect("disconnect");
}

#[tokio::test]
#[ignore]
async fn channel_subscription_receives_it_and_a_global_subscription_never_does() {
    // The single most load-bearing behaviour for any consumer built on this
    // kind: once 46010 is channel-scoped, `fan_out_scoped` routes it through the
    // channel indexes only, so a global REQ -- even one whose `#p` names the
    // reader -- can never deliver it. Both subscriptions live on ONE connection
    // so neither can pass by being disconnected.
    let reader_keys = Keys::generate();
    let writer_keys = Keys::generate();
    let reader_hex = reader_keys.public_key().to_hex();
    let channel = create_channel(&reader_keys, "open").await;

    let mut reader = AmbushTestClient::connect(&relay_url(), &reader_keys)
        .await
        .expect("reader connect");

    let channel_sub = sub_id("channel-scoped");
    reader
        .subscribe(
            &channel_sub,
            vec![Filter::new()
                .kind(Kind::Custom(KIND_APPROVAL_REQUESTED))
                .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [channel.as_str()])],
        )
        .await
        .expect("subscribe channel-scoped");
    reader
        .collect_until_eose(&channel_sub, Duration::from_secs(5))
        .await
        .expect("channel-scoped EOSE");

    let global_sub = sub_id("global-p");
    reader
        .subscribe(
            &global_sub,
            vec![Filter::new()
                .kind(Kind::Custom(KIND_APPROVAL_REQUESTED))
                .custom_tags(
                    SingleLetterTag::lowercase(Alphabet::P),
                    [reader_hex.as_str()],
                )],
        )
        .await
        .expect("subscribe global");
    reader
        .collect_until_eose(&global_sub, Duration::from_secs(5))
        .await
        .expect("global EOSE");

    let mut writer = AmbushTestClient::connect(&relay_url(), &writer_keys)
        .await
        .expect("writer connect");
    let marker = uuid::Uuid::new_v4().to_string();
    let ok = writer
        .send_event(build_approval_request(
            &writer_keys,
            Some(&channel),
            std::slice::from_ref(&reader_hex),
            &marker,
        ))
        .await
        .expect("writer send");
    assert!(ok.accepted, "writer publish rejected: {}", ok.message);

    // Drain for the whole silence window and record which subscriptions the
    // event reached. Draining past the first hit is what makes the negative
    // assertion meaningful.
    let deadline = tokio::time::Instant::now() + SILENCE_WINDOW;
    let mut delivered_to: HashSet<String> = HashSet::new();
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            break;
        }
        match reader.recv_event(remaining).await {
            Ok(RelayMessage::Event {
                subscription_id,
                event,
            }) if event.content == marker => {
                delivered_to.insert(subscription_id);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    // Positive control first: if this fails the negative assertion below proves
    // nothing, because the event may simply never have been fanned out.
    assert!(
        delivered_to.contains(&channel_sub),
        "channel-scoped REQ must receive the approval request; delivered_to = {delivered_to:?}"
    );
    assert!(
        !delivered_to.contains(&global_sub),
        "a global REQ must NEVER receive a channel-scoped event, even with a matching #p; \
         see the symmetric scoping invariant in crates/ambush-relay/src/subscription.rs"
    );

    reader.disconnect().await.expect("reader disconnect");
    writer.disconnect().await.expect("writer disconnect");
}

#[tokio::test]
#[ignore]
async fn approval_request_reaches_the_needs_action_feed() {
    // Exercises `query_needs_action`'s INNER JOIN on `event_mentions`. That
    // index is written on a SEPARATE transaction from the event insert and a
    // failure is only a `warn!`, so a stored, OK'd 46010 can be permanently
    // invisible to every `#p` feed. This is the test that would catch it.
    let reader_keys = Keys::generate();
    let writer_keys = Keys::generate();
    let reader_hex = reader_keys.public_key().to_hex();
    let channel = create_channel(&reader_keys, "open").await;

    let mut writer = AmbushTestClient::connect(&relay_url(), &writer_keys)
        .await
        .expect("writer connect");
    let marker = uuid::Uuid::new_v4().to_string();
    let ok = writer
        .send_event(build_approval_request(
            &writer_keys,
            Some(&channel),
            std::slice::from_ref(&reader_hex),
            &marker,
        ))
        .await
        .expect("writer send");
    assert!(ok.accepted, "writer publish rejected: {}", ok.message);
    writer.disconnect().await.expect("writer disconnect");

    // `feed_types` is a POST /query extension `nostr::Filter` silently drops,
    // so the body is hand-built JSON. The kindless filter clears the p-gate
    // only because `#p` is exactly the reader -- the same shape `ambush feed get`
    // sends.
    let body = serde_json::json!([{
        "#p": [reader_hex],
        "limit": 50,
        "feed_types": ["needs_action"],
    }]);
    let resp = http_client()
        .post(format!("{}/query", relay_http_url()))
        .header("X-Pubkey", &reader_hex)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("needs_action query");
    assert!(
        resp.status().is_success(),
        "query failed: {}",
        resp.status()
    );
    let events: Vec<Value> = resp.json().await.expect("parse needs_action response");

    assert!(
        events
            .iter()
            .any(|e| e["content"].as_str() == Some(marker.as_str())),
        "the approval request must appear in the needs_action feed -- the p tag \
         must have reached event_mentions; got {} event(s)",
        events.len()
    );
}

#[tokio::test]
#[ignore]
async fn non_member_cannot_publish_into_a_private_channel() {
    // Channel scoping brings the membership gate with it: 46010 is not on the
    // skip-membership list, so a publisher who is not a member of a private
    // channel is refused. Any producer must join the channel before it can
    // request an approval in it.
    let owner_keys = Keys::generate();
    let outsider_keys = Keys::generate();
    let channel = create_channel(&owner_keys, "private").await;

    let mut outsider = AmbushTestClient::connect(&relay_url(), &outsider_keys)
        .await
        .expect("outsider connect");
    let ok = outsider
        .send_event(build_approval_request(
            &outsider_keys,
            Some(&channel),
            &[owner_keys.public_key().to_hex()],
            r#"{"step_id":"deploy","message":"promote to prod?"}"#,
        ))
        .await
        .expect("outsider send");

    assert!(
        !ok.accepted,
        "a non-member must not be able to publish an approval request into a private channel"
    );
    assert_eq!(ok.message, "restricted: not a channel member");
    outsider.disconnect().await.expect("outsider disconnect");
}
