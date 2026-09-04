//! ONE command: `perch_record_verdict`. Leg 1 of the two-legged write — the
//! operator's signed intent card, published to the RELAY, carrying no authority
//! whatsoever. It POSTs nothing to the daemon, so it is deliberately not in
//! `perch_writes.rs` and is not counted by INV-01's five-route table. The
//! relay-published set is closed here instead: the operator's own key publishes
//! exactly one kind and exactly one marker, and exactly one command may do it.
//!
//! # Why this file has to exist
//!
//! `crate::perch_sign_gate::perch_sign_gate` refuses any `kind:9` whose line 0
//! is a swarm marker, on every content-signing command. That refusal only means
//! something because a sanctioned path exists, and this is it. A test below
//! proves the gate refuses the exact line 0 this command publishes.
//!
//! # Two chains, never conflated
//!
//! NOSTR, secp256k1 Schnorr: the chat identity, `state.signing_keys()`. It
//! signs the `kind:9` EVENT and says who published the card.
//!
//! OPERATOR, Ed25519: a separate secret in the same OS keyring blob. It signs
//! the DECISION PREIMAGE and says who decided. The secret never crosses IPC;
//! only `public_key_hex` does, and it must, because the daemon derives the
//! voter id from it. Because `SecretStore` keeps one blob per service and the
//! sign-out path enumerates that blob rather than an allowlist, this key is
//! destroyed by the existing wipe with no new code.

use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tauri::State;

use crate::app_state::AppState;
use crate::perch::daemon_client::{fetch_admitted_issuers, operator_id};
use swarm_perch_wire::marker::{build_content, parse_content, CardKind};
use swarm_perch_wire::tags::TagSet;
use swarm_perch_wire::KIND_CARD;

/// The kinds the operator's own key publishes. Closed; widening it needs an
/// argument, not an edit.
pub const PERCH_RELAY_PUBLISHED_KINDS: [u32; 1] = [9];
/// The markers the operator's own key publishes. Closed, for the same reason.
pub const PERCH_RELAY_PUBLISHED_MARKERS: [&str; 1] = ["swarm:verdict:v1"];

// The closed sets are not decoration: the kind below is what the command
// publishes, checked at compile time, and the marker is checked against the
// built body before the event is signed. A widened set with an unchanged
// command does not compile.
const _: () = assert!(PERCH_RELAY_PUBLISHED_KINDS.len() == 1);
const _: () = assert!(PERCH_RELAY_PUBLISHED_KINDS[0] == KIND_CARD as u32);

pub(crate) const OPERATOR_ED25519_SECRET_KEY: &str = "perch.operator_ed25519";
/// The daemon read leg 1 builds a hold verdict from. A GET, so it is not on
/// the INV-01 write table.
pub(crate) const ROUTE_GET_HOLD: &str = "/v1/response/holds/{hold_id}";
const CASE_INCIDENT_PREFIX: &str = "incident:perch-case:";
const FINDING_FACT_SCHEMA: &str = "swarm.perch.finding.v1";
pub(crate) const VERDICT_FACT_SCHEMA: &str = "swarm.perch.verdict.v1";

/// The operator's three verbs on a finding (D-FC-3), from the wire crate.
///
/// Re-exported rather than redeclared: two hand-written copies of one wire
/// object is the drift the shared crate exists to prevent, and the daemon
/// verifies bytes this crate must not be free to spell differently.
pub use swarm_perch_wire::cards::FindingVerdictWord;

/// The Ed25519 chain, and the only thing that joins the two legs.
///
/// `signature_hex` is byte-identical on the relay card and on the daemon's
/// record, and it is unforgeable, so a reconciler matches on it. The leg-1
/// event id is a lookup convenience and is never part of the signed record.
/// One definition, in the wire crate, under the name this command's output
/// uses.
pub use swarm_perch_wire::cards::WireDetachedSignature as DetachedSignature;

/// What the renderer supplies: ids and a decision, and nothing that ends up in
/// the card's factual content.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordVerdictInput {
    /// Nostr event id of the finding card being ruled on, 64 lowercase hex.
    pub finding_card_id: String,
    /// The case channel this verdict is published into.
    pub case_channel: String,
    /// The incident the daemon minted for this case.
    pub incident_id: String,
    /// The operator's verb.
    pub decision: FindingVerdictWord,
    /// The operator's own words. Bound by its digest in the preimage, so
    /// nothing holding the bearer token can replay a valid signature with
    /// substituted free text.
    pub rationale: Option<String>,
}

/// What leg 2 needs, and nothing else.
#[derive(Debug, Serialize)]
pub struct RecordVerdictOutput {
    /// The published card's event id, 64 lowercase hex. Leg 2's idempotency key.
    pub nostr_intent_event_id: String,
    /// Stamped by this process's clock at signing time, and inside the preimage.
    pub decided_at_ms: i64,
    /// The detached Ed25519 signature leg 2 sends back.
    pub signature: DetachedSignature,
    /// Read out of the relay's admitted finding card, never from the input.
    pub finding_id: String,
}

/// Lowercase hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Builds the detached signature a verdict card carries.
///
/// Extracted so a test can exercise THIS construction rather than rebuild one
/// beside it: a test that assembles its own `DetachedSignature` asserts a rule,
/// not the code, and passes even when the command is wrong.
///
/// `key_id` is `sha256` of the key's RAW 32 bytes — never the operator's id,
/// and never the hash of its hex spelling.
///
/// `swarm_crypto::verify_detached_signature` parses `public_key_hex` into a
/// `PublicKey` and compares against `sha256(public_key.as_bytes())`, which is
/// the raw form. Hashing the hex string produces a different digest and fails
/// verification exactly as an operator id does, so getting this wrong twice
/// looks identical from inside this crate.
///
/// Naming the operator here made every verdict signature this console produced
/// verify nowhere. It stayed invisible because the finding-feedback route
/// records `operator-bearer:{operator_id}` and never checks the signature; the
/// hold's decide route does, and tier-2 verification will.
fn sign_verdict(key: &SigningKey, preimage: &[u8]) -> DetachedSignature {
    let public_key = key.verifying_key().to_bytes();
    DetachedSignature {
        algorithm: "ed25519".to_string(),
        key_id: sha256_hex(&public_key),
        public_key_hex: hex::encode(public_key),
        signature_hex: hex::encode(key.sign(preimage).to_bytes()),
    }
}

/// The exact bytes the operator's Ed25519 key signs.
///
/// Four members, RFC 8785 canonical: `{decided_at_ms, decision, finding_id,
/// rationale_sha256}` — W3-16's shape with `finding_id` in `hold_id`'s place
/// (D-FC-3). The rationale is bound by its digest rather than by its text, so
/// the free text is not part of the canonical shape and an absent rationale
/// still has a digest (the empty string's) rather than a hole.
///
/// The shared canonicalizer from the wire crate is the signature contract;
/// `serde_json::to_vec` is not, because its key order is the order the value
/// was built in.
///
/// # Panics
///
/// Never: the input is a four-member object of scalars, which canonicalizes.
#[must_use]
pub fn verdict_preimage(
    decided_at_ms: i64,
    decision: &str,
    finding_id: &str,
    rationale: Option<&str>,
) -> Vec<u8> {
    let value = serde_json::json!({
        "decided_at_ms": decided_at_ms,
        "decision": decision,
        "finding_id": finding_id,
        "rationale_sha256": sha256_hex(rationale.unwrap_or("").as_bytes()),
    });
    swarm_perch_wire::envelope::canonical_bytes(&value).unwrap_or_default()
}

pub(crate) fn is_hex64_lower(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

/// RFC 3339 at second precision, UTC, the form every card's `issued_at` uses.
pub(crate) fn iso_seconds(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Load the operator's Ed25519 seed, minting one on first use.
///
/// The seed lives in the same keyring blob as the chat identity and is
/// destroyed by the same sign-out path. It never leaves this process, and the
/// stored value is wrapped so it cannot be printed on the way out.
pub(crate) fn operator_seed() -> Result<[u8; 32], String> {
    let store = crate::secret_store::SecretStore::shared(crate::app_state::keyring_service());
    if let Some(stored) = store.load(OPERATOR_ED25519_SECRET_KEY)? {
        return OperatorSecret::new(stored).decode();
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("entropy source: {e}"))?;
    store.store(OPERATOR_ED25519_SECRET_KEY, &hex::encode(seed))?;
    tracing::info!("perch: minted the operator Ed25519 key");
    Ok(seed)
}

/// Load the operator's Ed25519 key, minting it on first use.
///
/// Delegates to [`operator_seed`] so there is ONE loader, one mint path and one
/// redaction boundary for this secret. Two loaders for one key is how the two
/// drift and how one of them ends up printing what the other protects.
pub(crate) fn operator_signing_key() -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&operator_seed()?))
}

// ===========================================================================
// The case channel has to exist before a card is published into it.
// ===========================================================================
//
// The daemon mints `case_id` and returns it (W3-14) BEFORE the bridge has seen
// `RuntimeEvent::CasePromoted` and created the channel. Between those two
// moments the console holds a channel UUID that names nothing. A `kind:9` with
// an `h` tag for a channel the relay does not know is not held for later: it is
// refused, or it is stored where nobody is subscribed. Either way the operator
// is told a decision was recorded when no reader will ever see it, which is the
// one failure this whole two-legged design exists to prevent.
//
// So leg 1 waits, with explicit filters, and refuses rather than guesses.

/// NIP-29 channel metadata. Its `d` tag carries the channel id.
const KIND_CHANNEL_METADATA: u16 = 39000;
/// NIP-29 membership. Its `d` tag carries the channel id, its `p` tags members.
const KIND_CHANNEL_MEMBERSHIP: u16 = 39002;

/// How long leg 1 waits for the bridge to create the daemon-minted channel.
const CASE_CHANNEL_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// The gap between probes.
const CASE_CHANNEL_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// The stable prefix that means: nothing was signed, nothing was published,
/// nothing was sent to the daemon, and the same call may be made again.
pub const CASE_CHANNEL_PENDING_PREFIX: &str = "case-channel-pending:";

/// The two filters that prove the case channel exists AND that this operator
/// is in it. Explicit `kinds` on both: an omitted `kinds` trips the relay's
/// p-gate with a 403 rather than answering.
#[must_use]
fn case_channel_filters(case_channel: &str, my_pubkey: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "kinds": [KIND_CHANNEL_METADATA],
            "#d": [case_channel],
            "limit": 1,
        }),
        serde_json::json!({
            "kinds": [KIND_CHANNEL_MEMBERSHIP],
            "#d": [case_channel],
            "#p": [my_pubkey],
            "limit": 1,
        }),
    ]
}

/// One relay event reduced to what the probe reads. Keeping the decision over
/// this shape rather than over `nostr::Event` is what lets the rule be tested
/// without a relay and without signing anything.
struct ChannelProof {
    kind: u16,
    tags: Vec<Vec<String>>,
}

impl ChannelProof {
    /// Whether some tag on this event is exactly `[name, value]`-prefixed.
    fn has(&self, name: &str, value: &str) -> bool {
        self.tags
            .iter()
            .any(|tag| tag.len() >= 2 && tag[0] == name && tag[1] == value)
    }
}

/// Narrow relay events to the probe's shape.
fn channel_proofs(events: &[nostr::Event]) -> Vec<ChannelProof> {
    events
        .iter()
        .map(|event| ChannelProof {
            kind: event.kind.as_u16(),
            tags: event
                .tags
                .iter()
                .map(|tag| tag.as_slice().to_vec())
                .collect(),
        })
        .collect()
}

/// Both halves, re-checked here rather than trusted from the filter: a relay
/// that ignored `#p` would otherwise let a non-member publish into a case.
#[must_use]
fn case_channel_is_visible(proofs: &[ChannelProof], case_channel: &str, my_pubkey: &str) -> bool {
    let metadata = proofs
        .iter()
        .any(|p| p.kind == KIND_CHANNEL_METADATA && p.has("d", case_channel));
    let membership = proofs.iter().any(|p| {
        p.kind == KIND_CHANNEL_MEMBERSHIP && p.has("d", case_channel) && p.has("p", my_pubkey)
    });
    metadata && membership
}

/// Poll `probe` every [`CASE_CHANNEL_POLL`] until it answers true or
/// [`CASE_CHANNEL_WAIT`] is spent.
///
/// A probe error stops the wait immediately and is returned unchanged: a relay
/// this command cannot read is a fault to surface, not a reason to keep asking
/// for five seconds. Dropping the returned future stops the polling; nothing
/// here is spawned.
pub(crate) async fn await_case_channel<P, F>(mut probe: P) -> Result<(), String>
where
    P: FnMut() -> F,
    F: std::future::Future<Output = Result<bool, String>>,
{
    let started = tokio::time::Instant::now();
    loop {
        if probe().await? {
            return Ok(());
        }
        if started.elapsed() >= CASE_CHANNEL_WAIT {
            return Err(format!(
                "{CASE_CHANNEL_PENDING_PREFIX} the case channel is not on the relay after {} seconds. The bridge creates it when the daemon publishes CasePromoted; nothing was signed or sent.",
                CASE_CHANNEL_WAIT.as_secs()
            ));
        }
        tokio::time::sleep(CASE_CHANNEL_POLL).await;
    }
}

/// The finding facts this command is allowed to copy into the verdict card.
struct AdmittedFinding {
    finding_id: String,
}

/// Read the finding card off the relay and refuse anything the console must not
/// build a verdict from.
async fn admitted_finding_card(
    state: &AppState,
    finding_card_id: &str,
) -> Result<AdmittedFinding, String> {
    let issuers = fetch_admitted_issuers(state).await?;
    let events = crate::relay::query_relay(
        state,
        &[serde_json::json!({ "ids": [finding_card_id], "kinds": [9], "limit": 1 })],
    )
    .await?;
    let [event] = events.as_slice() else {
        return Err("finding card not found on the relay".to_string());
    };
    if !issuers.issuers.contains(&event.pubkey.to_hex()) {
        return Err("finding card signer is not an admitted bridge identity".to_string());
    }
    if event.content.lines().next() != Some(CardKind::Finding.marker()) {
        return Err("the named event is not a swarm:finding:v1 card".to_string());
    }
    let parts = parse_content(&event.content).map_err(|e| format!("finding card body: {e}"))?;
    let envelope: serde_json::Value =
        serde_json::from_str(parts.json).map_err(|e| format!("finding card body: {e}"))?;
    let fact = &envelope["fact"];
    if fact["schema"] != FINDING_FACT_SCHEMA {
        return Err(format!(
            "finding card fact.schema is {}, expected {FINDING_FACT_SCHEMA}",
            fact["schema"]
        ));
    }
    let finding_id = fact["locator"]["finding_id"]
        .as_str()
        .ok_or_else(|| "finding card carries no locator.finding_id".to_string())?
        .to_string();
    Ok(AdmittedFinding { finding_id })
}

/// Build, sign and publish the leg-1 `swarm:verdict:v1` card for a finding.
///
/// The renderer supplies ids, a decision and free text. Every factual field in
/// the card body comes from the relay's own admitted finding card, queried by
/// id, so a compromised webview cannot forge what the verdict claims to be
/// about. A successful return means an intent record exists and the world has
/// not changed; leg 2 is a separate command.
///
/// # Errors
///
/// When an id is malformed, when the finding card is missing or was signed by
/// an unadmitted issuer, when the operator or chat identity is unavailable, or
/// when the relay refuses the event.
#[tauri::command]
pub async fn perch_record_verdict(
    input: RecordVerdictInput,
    state: State<'_, AppState>,
) -> Result<RecordVerdictOutput, String> {
    if !is_hex64_lower(&input.finding_card_id) {
        return Err("findingCardId must be 64 lowercase hex".to_string());
    }
    if uuid::Uuid::parse_str(&input.case_channel).is_err() {
        return Err("caseChannel must be a UUID".to_string());
    }
    if !input.incident_id.starts_with(CASE_INCIDENT_PREFIX) {
        return Err(format!(
            "incidentId must start with `{CASE_INCIDENT_PREFIX}`"
        ));
    }

    // Before anything is signed or stamped: the channel this card names must
    // exist and must list this operator. Failing here costs nothing — no
    // signature, no relay event, no daemon call — and the caller may retry.
    let keys = state.signing_keys()?;
    let my_pubkey = keys.public_key().to_hex();
    {
        let app: &AppState = &state;
        let case_channel = input.case_channel.clone();
        let pubkey = my_pubkey.clone();
        await_case_channel(move || {
            let filters = case_channel_filters(&case_channel, &pubkey);
            let case_channel = case_channel.clone();
            let pubkey = pubkey.clone();
            async move {
                let events = crate::relay::query_relay(app, &filters).await?;
                Ok(case_channel_is_visible(
                    &channel_proofs(&events),
                    &case_channel,
                    &pubkey,
                ))
            }
        })
        .await?;
    }

    let finding = admitted_finding_card(&state, &input.finding_card_id).await?;
    let decided_at_ms = now_ms();
    let operator = operator_id()?;
    let key = operator_signing_key()?;
    let public_key_hex = hex::encode(key.verifying_key().to_bytes());
    let decision = input.decision.as_str();
    let rationale_sha256 = sha256_hex(input.rationale.as_deref().unwrap_or("").as_bytes());
    let preimage = verdict_preimage(
        decided_at_ms,
        decision,
        &finding.finding_id,
        input.rationale.as_deref(),
    );
    // Unreachable for a four-member object of scalars, and checked anyway: an
    // empty preimage would be a signature over nothing that still verifies
    // against itself.
    if preimage.is_empty() {
        return Err("could not canonicalize the verdict preimage".to_string());
    }
    // One construction, so a test that exercises `sign_verdict` is exercising
    // what this command actually publishes rather than a rule rebuilt beside it.
    let signature = sign_verdict(&key, &preimage);

    let fact = serde_json::json!({
        "schema": VERDICT_FACT_SCHEMA,
        "issuer": {
            "swarm_agent_id": operator,
            "role": serde_json::Value::Null,
            // The same key the case-channel membership probe asked about, so
            // the card's issuer and the member the relay admitted are one.
            "nostr_pubkey": my_pubkey,
        },
        "emitted_at_ms": decided_at_ms,
        "locator": {
            "subject": "finding",
            "finding_id": finding.finding_id,
            "finding_card_id": input.finding_card_id,
            "case_channel": input.case_channel,
            "incident_id": input.incident_id,
        },
        "decision": {
            "subject": "finding",
            "decision": decision,
            "finding_id": finding.finding_id,
            "decided_at_ms": decided_at_ms,
            "operator_id": operator,
            "rationale_sha256": rationale_sha256,
            "rationale": input.rationale,
        },
        "signature": signature,
        "leg2": {
            "state": "sending",
            "receipt_id": serde_json::Value::Null,
            "refusal_check": serde_json::Value::Null,
            "superseded_by": serde_json::Value::Null,
            "superseded_at_ms": serde_json::Value::Null,
        },
    });
    // The console has no envelope chain: every operator card is `seq: 1` with
    // no predecessor and no detached envelope signature, which pins it at
    // tier 0 like every other card today.
    let envelope = swarm_perch_wire::envelope::CardEnvelope::seal_unsigned(
        CardKind::Verdict,
        &format!("swarm:ed25519:{public_key_hex}"),
        1,
        None,
        iso_seconds(decided_at_ms),
        fact,
    )
    .map_err(|e| format!("verdict envelope: {e}"))?;
    let human = format!(
        "{decision} · finding {} · by {operator} · {}",
        finding.finding_id,
        iso_seconds(decided_at_ms)
    );
    let body = serde_json::to_string(&envelope).map_err(|e| e.to_string())?;
    let content = build_content(CardKind::Verdict, &human, &body)
        .map_err(|e| format!("verdict card: {e}"))?;
    // The body must carry the one marker the closed set names, or this command
    // is publishing something the set does not describe.
    let published_marker = format!("<!-- {} -->", PERCH_RELAY_PUBLISHED_MARKERS[0]);
    if content.lines().next() != Some(published_marker.as_str()) {
        return Err("the verdict card does not carry the one published marker".to_string());
    }

    // `h` and `k` and nothing else: no `t`/`l` (the threat class and severity
    // belong to the finding, not to the human's decision), no `p` (a card may
    // not mention), and no `e` (D-FC-3 — it would point across channels).
    let tags = TagSet::card(CardKind::Verdict, input.case_channel.clone(), None, None);
    tags.assert_publishable(KIND_CARD)
        .map_err(|e| format!("verdict tags: {e}"))?;
    let nostr_tags: Vec<nostr::Tag> = tags
        .to_tags()
        .into_iter()
        .map(nostr::Tag::parse)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("verdict tags: {e}"))?;

    let event = nostr::EventBuilder::new(nostr::Kind::Custom(KIND_CARD), content)
        .tags(nostr_tags)
        .sign_with_keys(&keys)
        .map_err(|e| format!("signing the verdict card: {e}"))?;
    let submitted = crate::relay::submit_signed_event_at_with_keys(
        &event,
        &state,
        &crate::relay::relay_api_base_url_with_override(&state),
        &keys,
    )
    .await?;
    if !submitted.accepted {
        return Err(format!(
            "relay refused the verdict card: {}",
            submitted.message
        ));
    }

    Ok(RecordVerdictOutput {
        nostr_intent_event_id: event.id.to_hex(),
        decided_at_ms,
        signature,
        finding_id: finding.finding_id,
    })
}

// ── B2 leg 1: a verdict on a HOLD ──────────────────────────────────────────

/// The operator's stored Ed25519 seed, in a shape nothing can print.
///
/// The hex is private to this module and has no accessor: [`decode`] hands
/// back the 32 bytes and the string never escapes. `Display` and `Debug` both
/// redact, so the leak this guards against — an error that interpolates the
/// stored value on its way across IPC into the webview — is not merely
/// detectable but unrepresentable.
///
/// [`decode`]: OperatorSecret::decode
mod operator_secret {
    /// A stored Ed25519 seed. See the module doc.
    pub struct OperatorSecret(String);

    impl OperatorSecret {
        /// Wrap a stored hex seed.
        #[must_use]
        pub fn new(hex: String) -> Self {
            Self(hex)
        }

        /// The 32 raw bytes.
        ///
        /// # Errors
        ///
        /// When the stored value is not 32 bytes of hex. Neither error names
        /// any part of the value.
        pub fn decode(&self) -> Result<[u8; 32], String> {
            let bytes = hex::decode(self.0.trim())
                .map_err(|_| "the stored operator key is not hex".to_string())?;
            bytes
                .try_into()
                .map_err(|_| "the stored operator key is not 32 bytes".to_string())
        }
    }

    impl std::fmt::Display for OperatorSecret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("<redacted>")
        }
    }

    impl std::fmt::Debug for OperatorSecret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("<redacted>")
        }
    }
}

pub use operator_secret::OperatorSecret;

/// Every command in this file that publishes to the relay.
///
/// `#[cfg(test)]` because nothing in the production path consults it: it is an
/// inventory the tests below compare against the file's actual
/// `#[tauri::command]` declarations, so a new publisher cannot land without
/// being named here. Unlike `PERCH_RELAY_PUBLISHED_KINDS`, which the signing
/// path itself reads, this one asserts about the source rather than gating it.
#[cfg(test)]
pub const PERCH_RELAY_PUBLISHING_COMMANDS: [&str; 3] = [
    "perch_record_verdict",
    "perch_record_hold_verdict",
    "perch_publish_verdict_update",
];

/// The commands in this file that publish NOTHING. Written down so the
/// inverse assertion below can be exact: a new command lands in one list or
/// the other, and a new publisher that lands in neither fails the test.
#[cfg(test)]
pub const PERCH_NON_PUBLISHING_COMMANDS: [&str; 1] = ["perch_operator_identity"];

#[cfg(test)]
#[path = "perch_verdict_tests.rs"]
mod tests;
