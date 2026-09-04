//! End-to-end integration tests for kind:26006 (operator alarm frame) and the
//! `P_GATED_KINDS` read rule that this change adds for it.
//!
//! # What is under test
//!
//! An operator alarm frame is an ephemeral event whose `p` tags name the
//! principals expected to act on it. Ephemeral events never reach
//! `ingest_event`: `handle_event` branches at
//! `crates/ambush-relay/src/handlers/event.rs:701` into `handle_ephemeral_event`,
//! which at `:850` looks for an `h` tag and takes one of two very different
//! routes.
//!
//! - **With an `h` tag** it membership-checks the publisher and fans out with
//!   `channel_id = Some(..)`, so the frame travels the channel indexes and
//!   `filter_fanout_by_access` re-checks each recipient's membership on a
//!   private channel. `KIND_HUDDLE_REACTION` is the in-tree precedent for an
//!   ephemeral kind that does this.
//! - **Without one** it fans out with `channel_id = None`, and
//!   `filter_fanout_by_access` returns every subscription match at
//!   `event.rs:178` without ever consulting `p` tags. Nothing else in the
//!   pipeline looks at them either.
//!
//! So an `h`-less alarm frame is readable by any authenticated community member
//! who opens `REQ {"kinds":[26006]}`. The `P_GATED_KINDS` entry is the fence for
//! that second route, applied at REQ registration by
//! `p_gated_filters_authorized` (`crates/ambush-relay/src/handlers/req.rs:1182`).
//!
//! # The rule these tests exist to pin
//!
//! `p_gated_filters_authorized` runs only when `channel_id.is_none()`
//! (`req.rs:219`), and `channel_id` comes from `extract_channel_id_from_filters`
//! (`req.rs:1153`), which returns `None` when **any** filter in the REQ lacks an
//! `h` constraint **or** when the filters name **two different** channels. The
//! gate then applies `.all()` across every filter, so one alarm filter that
//! cannot satisfy it closes the entire subscription — including the unrelated
//! filters sharing the frame.
//!
//! Tests 5 and 6 are that rule. They are the reason a client may not fold an
//! alarm filter into a multi-channel or mixed REQ to save a subscription slot.
//!
//! # Running
//!
//! Start the relay, then run:
//!
//! ```text
//! RELAY_URL=ws://localhost:3000 cargo test -p ambush-test-client \
//!     --test e2e_operator_alarm_pgate -- --ignored --nocapture
//! ```

use std::collections::HashSet;
use std::time::Duration;

use ambush_test_client::{AmbushTestClient, RelayMessage};
use nostr::{Alphabet, EventBuilder, Filter, Keys, Kind, SingleLetterTag, Tag};
use reqwest::Client;
use serde_json::Value;

/// The wire value under test, taken from `ambush_core` rather than typed as a
/// literal so a constant move breaks compilation instead of silently testing a
/// different kind. `operator_alarm_frame_is_the_wire_value` in
/// `ambush-core/src/kind.rs` pins the number itself.
const KIND_ALARM: u16 = ambush_core::kind::KIND_OPERATOR_ALARM_FRAME as u16;

/// A second ephemeral kind, used only as the *global* half of the mixed-filter
/// REQ in test 5. The relay applies no kind allowlist to REQ filters, so this
/// number needs no registration; it stands in for any colony-wide telemetry
/// frame a client might reasonably subscribe to in the same breath.
const KIND_UNGATED_EPHEMERAL: u16 = 26001;

/// The exact `CLOSED` reason `handle_req` sends when the p-gate refuses a
/// subscription (`crates/ambush-relay/src/handlers/req.rs:222-225`). Asserted as a
/// string equality so a reworded refusal is a deliberate decision rather than a
/// silent one.
const P_GATE_REFUSAL: &str = "restricted: p-gated events require #p matching your pubkey";

/// How long a "must not arrive" assertion drains before it is satisfied. Every
/// negative assertion in this file is paired with a positive control drained in
/// the same window, so a silent relay cannot make one pass vacuously.
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
    format!("e2e-alarm-{name}-{}", uuid::Uuid::new_v4())
}

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client")
}

/// Create a channel via a signed kind:9007 event submitted to POST /events.
/// `visibility` is "open" or "private"; private is what makes the publisher-side
/// membership gate observable, since an open channel admits any authenticated
/// member.
async fn create_channel(keys: &Keys, visibility: &str) -> String {
    let client = http_client();
    let channel_uuid = uuid::Uuid::new_v4();
    let event = EventBuilder::new(Kind::Custom(9007), "")
        .tags(vec![
            Tag::parse(["h", &channel_uuid.to_string()]).unwrap(),
            Tag::parse(["name", &format!("alarm-pgate-e2e-{channel_uuid}")]).unwrap(),
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

/// Build a kind:26006 carrying the tags a real alarm frame carries: one `p` per
/// principal expected to act, and optionally an `h` naming the standing
/// operations channel the frame is compartmented to.
fn build_alarm_frame(
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
    EventBuilder::new(Kind::Custom(KIND_ALARM), content)
        .tags(tags)
        .sign_with_keys(keys)
        .unwrap()
}

/// Drain until the relay terminates `sub_id`, returning the `CLOSED` reason.
///
/// An `EOSE` for the same subscription is a hard failure rather than a timeout:
/// it means the REQ was *accepted*, which is exactly the outcome the caller is
/// asserting against, and reporting it as "timed out" would hide the defect.
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

/// Drain for the whole silence window and report which subscriptions received an
/// event whose content equals `marker`. Draining past the first hit is what lets
/// a positive control and a negative assertion share one window.
async fn drain_deliveries(client: &mut AmbushTestClient, marker: &str) -> HashSet<String> {
    let deadline = tokio::time::Instant::now() + SILENCE_WINDOW;
    let mut delivered_to: HashSet<String> = HashSet::new();
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return delivered_to;
        }
        match client.recv_event(remaining).await {
            Ok(RelayMessage::Event {
                subscription_id,
                event,
            }) if event.content == marker => {
                delivered_to.insert(subscription_id);
            }
            Ok(_) => {}
            Err(_) => return delivered_to,
        }
    }
}

// ── 1. the gate refuses ──────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn global_alarm_subscription_without_a_p_filter_is_closed() {
    // The direction that matters. Before the P_GATED_KINDS entry this REQ was
    // registered and received every channel-less alarm frame in the community.
    let reader_keys = Keys::generate();
    let mut reader = AmbushTestClient::connect(&relay_url(), &reader_keys)
        .await
        .expect("reader connect");

    let sub = sub_id("global-no-p");
    reader
        .subscribe(&sub, vec![Filter::new().kind(Kind::Custom(KIND_ALARM))])
        .await
        .expect("subscribe global without #p");

    let reason = expect_closed(&mut reader, &sub, Duration::from_secs(5)).await;
    assert_eq!(reason, P_GATE_REFUSAL);
    reader.disconnect().await.expect("reader disconnect");
}

#[tokio::test]
#[ignore]
async fn global_alarm_subscription_naming_another_pubkey_is_closed() {
    // `#p` must equal the reader's OWN pubkey, not merely be present. Without
    // this case the gate would pass a subscription that harvests another
    // operator's alarm frames.
    let reader_keys = Keys::generate();
    let other_hex = Keys::generate().public_key().to_hex();
    let mut reader = AmbushTestClient::connect(&relay_url(), &reader_keys)
        .await
        .expect("reader connect");

    let sub = sub_id("global-foreign-p");
    reader
        .subscribe(
            &sub,
            vec![Filter::new().kind(Kind::Custom(KIND_ALARM)).custom_tags(
                SingleLetterTag::lowercase(Alphabet::P),
                [other_hex.as_str()],
            )],
        )
        .await
        .expect("subscribe global with a foreign #p");

    let reason = expect_closed(&mut reader, &sub, Duration::from_secs(5)).await;
    assert_eq!(reason, P_GATE_REFUSAL);
    reader.disconnect().await.expect("reader disconnect");
}

// ── 2. the gate admits, and delivers only what it should ─────────────────────

#[tokio::test]
#[ignore]
async fn a_named_principal_receives_the_frame_and_an_unnamed_one_does_not() {
    // Positive control and negative assertion in one window: A is `p`-tagged and
    // must receive; B holds an equally well-formed self-`#p` subscription and
    // must not, because the frame does not name B.
    let a_keys = Keys::generate();
    let b_keys = Keys::generate();
    let publisher_keys = Keys::generate();
    let a_hex = a_keys.public_key().to_hex();
    let b_hex = b_keys.public_key().to_hex();

    let mut a = AmbushTestClient::connect(&relay_url(), &a_keys)
        .await
        .expect("A connect");
    let mut b = AmbushTestClient::connect(&relay_url(), &b_keys)
        .await
        .expect("B connect");

    let a_sub = sub_id("a-self-p");
    a.subscribe(
        &a_sub,
        vec![Filter::new()
            .kind(Kind::Custom(KIND_ALARM))
            .custom_tags(SingleLetterTag::lowercase(Alphabet::P), [a_hex.as_str()])],
    )
    .await
    .expect("A subscribe");
    a.collect_until_eose(&a_sub, Duration::from_secs(5))
        .await
        .expect("A EOSE — a self-#p alarm subscription must be ACCEPTED");

    let b_sub = sub_id("b-self-p");
    b.subscribe(
        &b_sub,
        vec![Filter::new()
            .kind(Kind::Custom(KIND_ALARM))
            .custom_tags(SingleLetterTag::lowercase(Alphabet::P), [b_hex.as_str()])],
    )
    .await
    .expect("B subscribe");
    b.collect_until_eose(&b_sub, Duration::from_secs(5))
        .await
        .expect("B EOSE");

    let mut publisher = AmbushTestClient::connect(&relay_url(), &publisher_keys)
        .await
        .expect("publisher connect");
    let marker = uuid::Uuid::new_v4().to_string();
    let ok = publisher
        .send_event(build_alarm_frame(
            &publisher_keys,
            None,
            std::slice::from_ref(&a_hex),
            &marker,
        ))
        .await
        .expect("publish alarm frame");
    assert!(ok.accepted, "alarm frame rejected: {}", ok.message);

    let a_got = drain_deliveries(&mut a, &marker).await;
    let b_got = drain_deliveries(&mut b, &marker).await;

    // Positive control first: without it the negative below proves nothing,
    // because the frame may simply never have been fanned out.
    assert!(
        a_got.contains(&a_sub),
        "the named principal must receive the frame; delivered_to = {a_got:?}"
    );
    assert!(
        b_got.is_empty(),
        "an operator the frame does not name must receive nothing; got {b_got:?}"
    );

    a.disconnect().await.expect("A disconnect");
    b.disconnect().await.expect("B disconnect");
    publisher.disconnect().await.expect("publisher disconnect");
}

#[tokio::test]
#[ignore]
async fn an_alarm_frame_is_never_stored() {
    // The storage half of the P_GATED contract (a NULL `search_tsv`) is
    // deliberately not paid for this kind. That is only sound while the frame is
    // never written, so this asserts the premise rather than assuming it.
    let reader_keys = Keys::generate();
    let reader_hex = reader_keys.public_key().to_hex();
    let mut publisher = AmbushTestClient::connect(&relay_url(), &reader_keys)
        .await
        .expect("publisher connect");

    let marker = uuid::Uuid::new_v4().to_string();
    let ok = publisher
        .send_event(build_alarm_frame(
            &reader_keys,
            None,
            std::slice::from_ref(&reader_hex),
            &marker,
        ))
        .await
        .expect("publish alarm frame");
    assert!(ok.accepted, "alarm frame rejected: {}", ok.message);
    publisher.disconnect().await.expect("publisher disconnect");

    // `#p` is the reader's own pubkey, which is what clears the same p-gate on
    // the POST /query path (`crates/ambush-relay/src/api/bridge.rs:1076`).
    let body = serde_json::json!([{
        "kinds": [KIND_ALARM],
        "#p": [reader_hex],
        "limit": 50,
    }]);
    let resp = http_client()
        .post(format!("{}/query", relay_http_url()))
        .header("X-Pubkey", &reader_hex)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .expect("query");
    assert!(
        resp.status().is_success(),
        "query failed: {}",
        resp.status()
    );
    let events: Vec<Value> = resp.json().await.expect("parse query response");
    assert!(
        !events
            .iter()
            .any(|e| e["content"].as_str() == Some(marker.as_str())),
        "an ephemeral alarm frame must never be stored; {} event(s) came back",
        events.len()
    );
}

// ── 3. the h-tagged route, and the membership it brings ──────────────────────

#[tokio::test]
#[ignore]
async fn a_channel_scoped_frame_reaches_a_member_and_no_global_subscriber() {
    // The complementary mechanism. An `h`-tagged frame takes the channel route
    // at `event.rs:853`, so it is compartmented by channel membership — and a
    // global subscription, even one whose `#p` names the reader and which the
    // p-gate therefore admitted, can never receive it (`subscription.rs:487`).
    let reader_keys = Keys::generate();
    let publisher_keys = Keys::generate();
    let reader_hex = reader_keys.public_key().to_hex();
    // Both parties must be members to publish and to subscribe; an open channel
    // gives the publisher membership without a join flow.
    let channel = create_channel(&reader_keys, "open").await;

    let mut reader = AmbushTestClient::connect(&relay_url(), &reader_keys)
        .await
        .expect("reader connect");

    let channel_sub = sub_id("h-scoped");
    reader
        .subscribe(
            &channel_sub,
            vec![Filter::new()
                .kind(Kind::Custom(KIND_ALARM))
                .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [channel.as_str()])],
        )
        .await
        .expect("subscribe h-scoped");
    reader
        .collect_until_eose(&channel_sub, Duration::from_secs(5))
        .await
        .expect(
            "an h-scoped alarm REQ naming exactly one channel must be ACCEPTED: \
             `channel_id` is Some, so the p-gate at req.rs:219 does not run",
        );

    let global_sub = sub_id("global-self-p");
    reader
        .subscribe(
            &global_sub,
            vec![Filter::new().kind(Kind::Custom(KIND_ALARM)).custom_tags(
                SingleLetterTag::lowercase(Alphabet::P),
                [reader_hex.as_str()],
            )],
        )
        .await
        .expect("subscribe global with self #p");
    reader
        .collect_until_eose(&global_sub, Duration::from_secs(5))
        .await
        .expect("global self-#p EOSE");

    let mut publisher = AmbushTestClient::connect(&relay_url(), &publisher_keys)
        .await
        .expect("publisher connect");
    let marker = uuid::Uuid::new_v4().to_string();
    let ok = publisher
        .send_event(build_alarm_frame(
            &publisher_keys,
            Some(&channel),
            std::slice::from_ref(&reader_hex),
            &marker,
        ))
        .await
        .expect("publish channel-scoped alarm frame");
    assert!(ok.accepted, "alarm frame rejected: {}", ok.message);

    let delivered_to = drain_deliveries(&mut reader, &marker).await;

    assert!(
        delivered_to.contains(&channel_sub),
        "the channel-scoped REQ must receive the frame; delivered_to = {delivered_to:?}"
    );
    assert!(
        !delivered_to.contains(&global_sub),
        "a global REQ must NEVER receive a channel-scoped event, even with a matching #p; \
         see the symmetric scoping invariant in crates/ambush-relay/src/subscription.rs"
    );

    reader.disconnect().await.expect("reader disconnect");
    publisher.disconnect().await.expect("publisher disconnect");
}

#[tokio::test]
#[ignore]
async fn a_non_member_cannot_publish_a_channel_scoped_frame() {
    // `handle_ephemeral_event` membership-checks the PUBLISHER at
    // `event.rs:853-855`. Any producer that compartments its frames with an `h`
    // tag must therefore join that channel first — the same precondition the
    // durable kind:46010 carries.
    let owner_keys = Keys::generate();
    let outsider_keys = Keys::generate();
    let channel = create_channel(&owner_keys, "private").await;

    let mut outsider = AmbushTestClient::connect(&relay_url(), &outsider_keys)
        .await
        .expect("outsider connect");
    let ok = outsider
        .send_event(build_alarm_frame(
            &outsider_keys,
            Some(&channel),
            &[owner_keys.public_key().to_hex()],
            "alarm from an outsider",
        ))
        .await
        .expect("outsider publish");

    assert!(
        !ok.accepted,
        "a non-member must not be able to publish a channel-scoped alarm frame"
    );
    assert_eq!(ok.message, "restricted: not a channel member");
    outsider.disconnect().await.expect("outsider disconnect");
}

// ── 4. the composition rule ──────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn mixing_an_h_scoped_alarm_filter_with_a_global_filter_closes_the_whole_req() {
    // The hazard this file exists for. `extract_channel_id_from_filters`
    // (`req.rs:1153`) returns None as soon as ONE filter lacks an `h`, so the
    // whole REQ counts as global at `req.rs:219` and the p-gate runs — and
    // `p_gated_filters_authorized` uses `.all()`, so the alarm filter takes the
    // unrelated telemetry filter down with it. The author of such a REQ believes
    // it is channel-scoped and gets a refusal about `#p` tags.
    let reader_keys = Keys::generate();
    let channel = create_channel(&reader_keys, "open").await;
    let mut reader = AmbushTestClient::connect(&relay_url(), &reader_keys)
        .await
        .expect("reader connect");

    let sub = sub_id("mixed-scope");
    reader
        .subscribe(
            &sub,
            vec![
                Filter::new()
                    .kind(Kind::Custom(KIND_ALARM))
                    .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [channel.as_str()]),
                Filter::new().kind(Kind::Custom(KIND_UNGATED_EPHEMERAL)),
            ],
        )
        .await
        .expect("subscribe mixed");

    let reason = expect_closed(&mut reader, &sub, Duration::from_secs(5)).await;
    assert_eq!(
        reason, P_GATE_REFUSAL,
        "a REQ mixing an h-scoped alarm filter with a global filter must be refused \
         by the p-gate, not silently registered"
    );
    reader.disconnect().await.expect("reader disconnect");
}

#[tokio::test]
#[ignore]
async fn naming_two_channels_in_one_req_closes_an_alarm_filter() {
    // The second half of the same rule, and the less obvious one: every filter
    // here names a channel and the reader is a member of both, yet
    // `extract_channel_id_from_filters` still returns None because the ids
    // differ, so the p-gate runs anyway. The rule is "exactly one channel across
    // the whole REQ", not "every filter has an h".
    let reader_keys = Keys::generate();
    let ops_channel = create_channel(&reader_keys, "open").await;
    let case_channel = create_channel(&reader_keys, "open").await;
    let mut reader = AmbushTestClient::connect(&relay_url(), &reader_keys)
        .await
        .expect("reader connect");

    let sub = sub_id("two-channels");
    reader
        .subscribe(
            &sub,
            vec![
                Filter::new().kind(Kind::Custom(KIND_ALARM)).custom_tags(
                    SingleLetterTag::lowercase(Alphabet::H),
                    [ops_channel.as_str()],
                ),
                Filter::new()
                    .kind(Kind::Custom(ambush_core::kind::KIND_STREAM_MESSAGE as u16))
                    .custom_tags(
                        SingleLetterTag::lowercase(Alphabet::H),
                        [case_channel.as_str()],
                    ),
            ],
        )
        .await
        .expect("subscribe two-channel");

    let reason = expect_closed(&mut reader, &sub, Duration::from_secs(5)).await;
    assert_eq!(
        reason, P_GATE_REFUSAL,
        "two distinct #h values collapse `channel_id` to None, so the p-gate runs \
         even though every filter names a channel"
    );
    reader.disconnect().await.expect("reader disconnect");
}
