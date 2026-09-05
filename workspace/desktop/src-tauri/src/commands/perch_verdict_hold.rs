//! The HOLD half of the operator's leg-1 relay writes.
//!
//! Split from `perch_verdict.rs` when that file crossed the 1000-line ceiling.
//! The cut is by SUBJECT, not by size: everything here is about deciding a
//! held action, and everything left there is about ruling on a finding. The
//! signing machinery both share — the preimage, the operator key, the case
//! channel wait — stays in `perch_verdict` and is used from here.
//!
//! The relay-publisher inventory also stays in `perch_verdict`, and its tests
//! scan BOTH files, so a command added here is still refused unless it is
//! named there.

use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::app_state::AppState;
use crate::perch::daemon_client::operator_id;
use swarm_perch_wire::marker::{build_content, parse_content, CardKind};
use swarm_perch_wire::tags::TagSet;
use swarm_perch_wire::KIND_CARD;

use super::perch_verdict::{
    is_hex64_lower, iso_seconds, now_ms, operator_seed, operator_signing_key, sha256_hex,
    DetachedSignature, PERCH_RELAY_PUBLISHED_MARKERS, ROUTE_GET_HOLD, VERDICT_FACT_SCHEMA,
};
/// The operator's two words on a hold. Never `deny`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HoldVerdictWord {
    /// Let the held action run.
    Grant,
    /// Refuse it.
    Refuse,
}

impl HoldVerdictWord {
    /// The wire word, which is also the one inside the signature preimage.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Refuse => "refuse",
        }
    }
}

/// What the renderer supplies for a hold verdict: an id, a word, and free text.
///
/// Every factual field in the card comes from the daemon's own record of the
/// hold, fetched by id, so a compromised webview cannot forge what the verdict
/// claims to be about.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordHoldVerdictInput {
    /// The hold being decided.
    pub hold_id: String,
    /// Grant or refuse.
    pub decision: HoldVerdictWord,
    /// The operator's own words. Bound by its digest in the preimage.
    pub rationale: Option<String>,
}

/// What leg 2 needs from leg 1, and nothing else.
// NO `rename_all`: the renderer reads this snake_case, exactly as it reads the
// finding path's `RecordVerdictOutput`. A camelCase rename here survived every
// hold E2E because the mock spoke snake_case while this struct emitted
// `decidedAtMs` — `leg1.decided_at_ms` would have been `undefined` in a real
// build. Found by reading this signature against the wrapper while preparing
// the live walking skeleton, not by any test.
#[derive(Debug, Serialize)]
pub struct RecordHoldVerdictOutput {
    /// The published card's event id. Leg 2's idempotency key.
    pub nostr_intent_event_id: String,
    /// Stamped once here, and inside the preimage. Leg 2 forwards it verbatim.
    pub decided_at_ms: i64,
    /// The detached Ed25519 signature leg 2 sends back.
    pub signature: DetachedSignature,
    /// Read out of the daemon's record, never from the input.
    pub hold_id: String,
    /// The channel the card was published into.
    pub case_channel: String,
}

/// The public half of the operator's verdict key, for the operator to paste
/// into the daemon's principal entry as `verdict_public_key_hex`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorIdentityOutput {
    /// 64 lowercase hex.
    pub public_key_hex: String,
    /// `sha256(public_key)`, which is what the daemon's verifier checks.
    pub key_id: String,
}

/// Derive the public identity from a seed. Pure, so the IPC shape is testable
/// without a keyring.
#[must_use]
pub(crate) fn operator_identity_from_seed(seed: &[u8; 32]) -> OperatorIdentityOutput {
    let public = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    OperatorIdentityOutput {
        public_key_hex: hex::encode(public),
        key_id: sha256_hex(&public),
    }
}

/// Sign the four-member hold preimage.
///
/// `key_id` is `sha256(public_key)`, which is what
/// `swarm_crypto::verify_detached_signature` checks: it refuses any other
/// value, so a `key_id` carrying a display name would be a signature nobody
/// could verify. The preimage comes from the shared wire crate rather than a
/// local `json!`, because the daemon rebuilds it with that same function and
/// two hand-written copies of one canonical form is the drift the shared crate
/// exists to prevent.
pub(crate) fn sign_hold_decision(
    seed: &[u8; 32],
    decided_at_ms: i64,
    decision: HoldVerdictWord,
    hold_id: &str,
    rationale: Option<&str>,
) -> DetachedSignature {
    let key = SigningKey::from_bytes(seed);
    let digest = swarm_perch_wire::verdict::rationale_sha256_hex(rationale);
    let preimage = swarm_perch_wire::verdict::decision_preimage_bytes(
        decided_at_ms,
        decision.as_str(),
        hold_id,
        digest.as_deref(),
    );
    let public = key.verifying_key().to_bytes();
    DetachedSignature {
        algorithm: "ed25519".to_string(),
        key_id: sha256_hex(&public),
        public_key_hex: hex::encode(public),
        signature_hex: hex::encode(key.sign(&preimage).to_bytes()),
    }
}

/// Refuse locally what the daemon would refuse anyway, and say why.
///
/// A card published for a hold the daemon will not decide is an intent record
/// with no possible outcome, and the operator learns nothing from a 409 they
/// could have been told about before they pressed anything.
pub(crate) fn assert_hold_decidable(hold: &serde_json::Value) -> Result<(String, String), String> {
    if hold["expired"].as_bool().unwrap_or(true) {
        return Err(
            "this hold has expired; the daemon will refuse it and no card is published".to_string(),
        );
    }
    match hold["state"].as_str().unwrap_or_default() {
        "created" | "notified" | "armed" => {}
        state => return Err(format!("this hold is `{state}` and cannot be decided")),
    }
    let case_channel = hold["case_channel"]
        .as_str()
        .filter(|channel| !channel.is_empty())
        .ok_or_else(|| {
            "this hold has no case channel yet; the bridge has not filed it, so there is nowhere \
             to publish the intent card"
                .to_string()
        })?;
    let hold_id = hold["hold_id"]
        .as_str()
        .ok_or_else(|| "the hold record carries no hold_id".to_string())?;
    Ok((hold_id.to_string(), case_channel.to_string()))
}

/// `h` and `k` and nothing else.
///
/// No `e`: the hold card lives in the case channel and an `e` tag across
/// channels would make the relay's thread resolver mutate another channel's
/// reply counts (D-FC-3). No `p`: a card may not mention. No `t`/`l`: the
/// threat class and severity belong to the hold, not to the human's decision.
pub(crate) fn hold_verdict_tags(case_channel: &str) -> TagSet {
    TagSet::card(CardKind::Verdict, case_channel.to_string(), None, None)
}

/// Build the three-part leg-1 body for a hold subject.
///
/// # Errors
///
/// When the envelope or the card grammar refuses the assembled parts.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_hold_verdict_card(
    hold: &serde_json::Value,
    case_channel: &str,
    decision: HoldVerdictWord,
    decided_at_ms: i64,
    rationale: Option<&str>,
    operator_id: &str,
    nostr_pubkey: &str,
    signature: &DetachedSignature,
) -> Result<String, String> {
    let hold_id = hold["hold_id"].as_str().unwrap_or_default();
    let action_kind = hold["action_kind"].as_str().unwrap_or_default();
    let fact = serde_json::json!({
        "schema": VERDICT_FACT_SCHEMA,
        "issuer": {
            "swarm_agent_id": operator_id,
            "role": serde_json::Value::Null,
            "nostr_pubkey": nostr_pubkey,
        },
        "emitted_at_ms": decided_at_ms,
        "locator": {
            "subject": "hold",
            "hold_id": hold_id,
            "case_channel": case_channel,
            "hold_card_id": hold["card_event_id"],
        },
        "decision": {
            "subject": "hold",
            "decision": decision.as_str(),
            "hold_id": hold_id,
            "decided_at_ms": decided_at_ms,
            "operator_id": operator_id,
            "rationale_sha256": swarm_perch_wire::verdict::rationale_sha256_hex(rationale),
            "rationale": rationale,
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
    let envelope = swarm_perch_wire::envelope::CardEnvelope::seal_unsigned(
        CardKind::Verdict,
        &format!("swarm:ed25519:{}", signature.public_key_hex),
        1,
        None,
        iso_seconds(decided_at_ms),
        fact,
    )
    .map_err(|e| format!("verdict envelope: {e}"))?;
    let human = format!(
        "{} · hold {hold_id} · {action_kind} · by {operator_id} · {}",
        decision.as_str(),
        iso_seconds(decided_at_ms)
    );
    let body = serde_json::to_string(&envelope).map_err(|e| e.to_string())?;
    build_content(CardKind::Verdict, &human, &body).map_err(|e| format!("verdict card: {e}"))
}

/// The public half of this console's verdict key, minting it on first use.
///
/// The operator pastes `publicKeyHex` into the daemon's principal entry as
/// `verdict_public_key_hex`; until they do, every decision this console submits
/// is refused, which is the fail-closed direction.
///
/// # Errors
///
/// When the keyring is unreadable or holds a corrupt key.
#[tauri::command]
pub async fn perch_operator_identity(
    _state: State<'_, AppState>,
) -> Result<OperatorIdentityOutput, String> {
    Ok(operator_identity_from_seed(&operator_seed()?))
}

/// LEG 1 of a hold decision: publish the operator's signed intent as a
/// `swarm:verdict:v1` card, and return what leg 2 needs.
///
/// The renderer supplies a hold id, a word and free text. Every factual field
/// in the card comes from the daemon's own record of that hold, fetched here by
/// id, so a compromised webview cannot forge what the verdict claims to be
/// about. A successful return means an intent record exists and the world has
/// not changed; leg 2 is a separate command.
///
/// The clock is stamped ONCE, here, and it is inside the signature. Leg 2
/// forwards it verbatim rather than restating it.
///
/// # Errors
///
/// When the hold id is malformed, when the daemon is unreachable or has no such
/// hold, when the hold is not decidable, when the operator or chat identity is
/// unavailable, or when the relay refuses the event.
#[tauri::command]
pub async fn perch_record_hold_verdict(
    input: RecordHoldVerdictInput,
    state: State<'_, AppState>,
) -> Result<RecordHoldVerdictOutput, String> {
    if !swarm_perch_wire::tags::is_opaque_hold_id(&input.hold_id) {
        return Err("holdId must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$".to_string());
    }
    let detail = crate::perch::daemon_client::perch_daemon_get(
        &state,
        &crate::perch::daemon_client::route(ROUTE_GET_HOLD, &[("hold_id", &input.hold_id)])?,
    )
    .await?;
    if detail.status != 200 {
        return Err(format!(
            "daemon answered {}: {}",
            detail.status,
            detail.body["message"].as_str().unwrap_or_default()
        ));
    }
    let hold = &detail.body["hold"];
    let (hold_id, case_channel) = assert_hold_decidable(hold)?;

    let decided_at_ms = now_ms();
    let operator = operator_id()?;
    let seed = operator_seed()?;
    let signature = sign_hold_decision(
        &seed,
        decided_at_ms,
        input.decision,
        &hold_id,
        input.rationale.as_deref(),
    );
    let keys = state.signing_keys()?;
    let content = build_hold_verdict_card(
        hold,
        &case_channel,
        input.decision,
        decided_at_ms,
        input.rationale.as_deref(),
        &operator,
        &keys.public_key().to_hex(),
        &signature,
    )?;
    let published_marker = format!("<!-- {} -->", PERCH_RELAY_PUBLISHED_MARKERS[0]);
    if content.lines().next() != Some(published_marker.as_str()) {
        return Err("the verdict card does not carry the one published marker".to_string());
    }

    let tags = hold_verdict_tags(&case_channel);
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

    Ok(RecordHoldVerdictOutput {
        nostr_intent_event_id: event.id.to_hex(),
        decided_at_ms,
        signature,
        hold_id,
        case_channel,
    })
}

// ── B2 supersession: publish an update when another console wins ──────

/// Everything the supersession update needs. The case channel is deliberately
/// absent: it is read from the daemon's own hold record, never from the
/// renderer.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictUpdateInput {
    /// The hold whose decision was lost.
    pub hold_id: String,
    /// This console's own leg-1 card. The update is a NIP-10 reply to it.
    pub own_intent_event_id: String,
    /// The winning intent's event id, learned by RE-READING the hold (W3-17).
    pub superseded_by: String,
    /// When the console learned it had lost.
    pub superseded_at_ms: i64,
}

/// What `perch_publish_verdict_update` returns.
#[derive(Debug, Serialize)]
pub struct VerdictUpdateOutput {
    /// The update card's own event id.
    pub nostr_intent_event_id: String,
}

/// This console's own leg-1 verdict card, read back off the relay.
struct OwnVerdictCard {
    /// The card's whole `fact` object, so the update restates it verbatim.
    fact: serde_json::Value,
    /// The case channel the card was published into.
    case_channel: String,
}

/// Read this console's own leg-1 card off the relay and refuse anything else.
///
/// Read back rather than taken from the renderer for the same reason
/// `admitted_finding_card` exists: every factual field in the update comes from
/// an event that was actually published, so a compromised webview cannot make
/// this console sign a statement about a decision it never recorded. The signer
/// check is the sharp one — a card this console did not publish is not this
/// console's to supersede, and marking somebody else's verdict superseded is
/// exactly the forgery the two-console rule has to survive.
async fn own_verdict_card(
    state: &AppState,
    own_intent_event_id: &str,
    hold_id: &str,
) -> Result<OwnVerdictCard, String> {
    let keys = state.signing_keys()?;
    let events = crate::relay::query_relay(
        state,
        &[serde_json::json!({ "ids": [own_intent_event_id], "kinds": [9], "limit": 1 })],
    )
    .await?;
    let [event] = events.as_slice() else {
        return Err("the leg-1 verdict card was not found on the relay".to_string());
    };
    if event.pubkey.to_hex() != keys.public_key().to_hex() {
        return Err(
            "that verdict card was published by another key; a console supersedes only its own"
                .to_string(),
        );
    }
    if event.content.lines().next() != Some(CardKind::Verdict.marker()) {
        return Err("the named event is not a swarm:verdict:v1 card".to_string());
    }
    let parts = parse_content(&event.content).map_err(|e| format!("verdict card body: {e}"))?;
    let envelope: serde_json::Value =
        serde_json::from_str(parts.json).map_err(|e| format!("verdict card body: {e}"))?;
    let fact = envelope["fact"].clone();
    if fact["schema"] != VERDICT_FACT_SCHEMA {
        return Err(format!(
            "verdict card fact.schema is {}, expected {VERDICT_FACT_SCHEMA}",
            fact["schema"]
        ));
    }
    if fact["locator"]["subject"] != "hold" {
        return Err("that verdict card is not about a hold".to_string());
    }
    if fact["locator"]["hold_id"] != hold_id {
        return Err("that verdict card is about a different hold".to_string());
    }
    let case_channel = fact["locator"]["case_channel"]
        .as_str()
        .ok_or_else(|| "the verdict card carries no locator.case_channel".to_string())?
        .to_string();
    Ok(OwnVerdictCard { fact, case_channel })
}

/// Publish the supersession update: a NIP-10 reply to this console's own leg-1
/// card, marking it `leg2.state: "superseded"`.
///
/// Published rather than left silent because the losing card is a genuine,
/// correctly signed decision that will sit in the case channel forever. Somebody
/// reading that channel next month must be able to see from the channel alone
/// that it did not run. Nothing here re-signs the decision preimage: the update
/// restates the original card's `decision` and `signature` verbatim, so one act
/// keeps one signature.
///
/// The `e` tag points at this console's OWN card in the SAME channel. It never
/// points across channels: an `e` to an event elsewhere would make the relay's
/// NIP-10 resolver mutate a foreign root's reply counters (D-FC-3).
///
/// # Errors
///
/// When an id is malformed, when the leg-1 card is missing, was published by
/// another key, or is about another hold, or when the relay refuses the event.
#[tauri::command]
pub async fn perch_publish_verdict_update(
    input: VerdictUpdateInput,
    state: State<'_, AppState>,
) -> Result<VerdictUpdateOutput, String> {
    if !swarm_perch_wire::tags::is_opaque_hold_id(&input.hold_id) {
        return Err("holdId must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$".to_string());
    }
    if !is_hex64_lower(&input.own_intent_event_id) {
        return Err("ownIntentEventId must be 64 lowercase hex".to_string());
    }
    if !is_hex64_lower(&input.superseded_by) {
        return Err("supersededBy must be 64 lowercase hex".to_string());
    }
    if input.superseded_by == input.own_intent_event_id {
        return Err("a card cannot supersede itself".to_string());
    }

    let own = own_verdict_card(&state, &input.own_intent_event_id, &input.hold_id).await?;
    let mut fact = own.fact;
    fact["emitted_at_ms"] = serde_json::json!(input.superseded_at_ms);
    fact["leg2"] = serde_json::json!({
        "state": "superseded",
        "receipt_id": serde_json::Value::Null,
        "refusal_check": serde_json::Value::Null,
        "superseded_by": input.superseded_by,
        "superseded_at_ms": input.superseded_at_ms,
    });

    let operator = operator_id()?;
    let keys = state.signing_keys()?;
    let key = operator_signing_key()?;
    let public_key_hex = hex::encode(key.verifying_key().to_bytes());
    let envelope = swarm_perch_wire::envelope::CardEnvelope::seal_unsigned(
        CardKind::Verdict,
        &format!("swarm:ed25519:{public_key_hex}"),
        1,
        None,
        iso_seconds(input.superseded_at_ms),
        fact,
    )
    .map_err(|e| format!("verdict update envelope: {e}"))?;
    let human = format!(
        "superseded · hold {} · by {operator} · {}",
        input.hold_id,
        iso_seconds(input.superseded_at_ms)
    );
    let body = serde_json::to_string(&envelope).map_err(|e| e.to_string())?;
    let content = build_content(CardKind::Verdict, &human, &body)
        .map_err(|e| format!("verdict update card: {e}"))?;
    let published_marker = format!("<!-- {} -->", PERCH_RELAY_PUBLISHED_MARKERS[0]);
    if content.lines().next() != Some(published_marker.as_str()) {
        return Err("the verdict update does not carry the one published marker".to_string());
    }

    let mut tags = TagSet::card(CardKind::Verdict, own.case_channel, None, None);
    tags.e = Some(input.own_intent_event_id.clone());
    tags.assert_publishable(KIND_CARD)
        .map_err(|e| format!("verdict update tags: {e}"))?;
    let nostr_tags: Vec<nostr::Tag> = tags
        .to_tags()
        .into_iter()
        .map(nostr::Tag::parse)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("verdict update tags: {e}"))?;

    let event = nostr::EventBuilder::new(nostr::Kind::Custom(KIND_CARD), content)
        .tags(nostr_tags)
        .sign_with_keys(&keys)
        .map_err(|e| format!("signing the verdict update: {e}"))?;
    let submitted = crate::relay::submit_signed_event_at_with_keys(
        &event,
        &state,
        &crate::relay::relay_api_base_url_with_override(&state),
        &keys,
    )
    .await?;
    if !submitted.accepted {
        return Err(format!(
            "relay refused the verdict update: {}",
            submitted.message
        ));
    }
    Ok(VerdictUpdateOutput {
        nostr_intent_event_id: event.id.to_hex(),
    })
}
