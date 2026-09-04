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

const OPERATOR_ED25519_SECRET_KEY: &str = "perch.operator_ed25519";
const CASE_INCIDENT_PREFIX: &str = "incident:perch-case:";
const FINDING_FACT_SCHEMA: &str = "swarm.perch.finding.v1";
const VERDICT_FACT_SCHEMA: &str = "swarm.perch.verdict.v1";

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
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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

fn is_hex64_lower(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

/// RFC 3339 at second precision, UTC, the form every card's `issued_at` uses.
fn iso_seconds(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Load the operator's Ed25519 key, minting it on first use.
///
/// The secret lives in the same keyring blob as the chat identity and is
/// destroyed by the same sign-out path. It never leaves this process.
fn operator_signing_key() -> Result<SigningKey, String> {
    let store = crate::secret_store::SecretStore::shared(crate::app_state::keyring_service());
    if let Some(stored) = store.load(OPERATOR_ED25519_SECRET_KEY)? {
        let bytes = hex::decode(stored.trim())
            .map_err(|e| format!("the stored operator key is not hex: {e}"))?;
        let secret: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "the stored operator key is not 32 bytes".to_string())?;
        return Ok(SigningKey::from_bytes(&secret));
    }
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|e| format!("entropy source: {e}"))?;
    let key = SigningKey::from_bytes(&secret);
    store.store(OPERATOR_ED25519_SECRET_KEY, &hex::encode(secret))?;
    tracing::info!("perch: minted the operator Ed25519 key");
    Ok(key)
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
    let signature = DetachedSignature {
        algorithm: "ed25519".to_string(),
        key_id: operator.clone(),
        public_key_hex: public_key_hex.clone(),
        signature_hex: hex::encode(key.sign(&preimage).to_bytes()),
    };

    let keys = state.signing_keys()?;
    let fact = serde_json::json!({
        "schema": VERDICT_FACT_SCHEMA,
        "issuer": {
            "swarm_agent_id": operator,
            "role": serde_json::Value::Null,
            "nostr_pubkey": keys.public_key().to_hex(),
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

#[cfg(test)]
#[path = "perch_verdict_tests.rs"]
mod tests;
