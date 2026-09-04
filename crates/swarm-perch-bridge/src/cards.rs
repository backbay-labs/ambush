//! Marker card assembly. **The body schemas are `swarm-perch-wire`'s, not this crate's.**
//!
//! This module assembles: it picks the marker, builds the issuer block, attaches the `gap` block,
//! writes the human fallback line, and hands a finished body to the pacer. It does not define
//! field names — every one of them is a field on a `swarm_perch_wire` type, so an upstream
//! rename is a compile error here rather than a silently absent key on the wire.
//!
//! # The three-part body, in this order (00-DECISIONS W3-21)
//!
//! ````text
//! <!-- swarm:finding:v1 -->
//! whisker-7a3f · data_exfiltration · HIGH · confidence 0.82 · host web-04 · finding f2c9a1b4
//!
//! ```swarm:finding:v1
//! {"schema":"swarm.spine.envelope.v1","issuer":"swarm:ed25519:…","seq":41,…}
//! ```
//! ````
//!
//! The human line is the degradation contract: it is what the Flutter app, the web client, an FTS
//! snippet and `ambush --format compact messages thread` show, so it must carry the identifiers a
//! human needs to go find the real thing.
//!
//! **No `signature`, `signed_by` or `verified` field appears in a body this crate constructs.**
//! The Nostr envelope's own `sig` is the transport's, is visible to any reader of the raw event,
//! and needs no help from the body.

use sha2::{Digest, Sha256};
use swarm_core::agent::AgentRole;
use swarm_core::config::PerchBridgeConfig;
use swarm_perch_wire::{
    CARD_CONTENT_MAX_BYTES, Card, CardEnvelope, CardKind, EvidenceTruncated, FactIssuer,
    FindingCard, FindingLocator, GapBlock, GapBlockCause, HeldAction as WireHeldAction,
    HoldAlarm as WireHoldAlarm, HoldCard, HoldLocator, KIND_CARD, TagSet, WireAgentRole,
    build_content,
};
use swarm_runtime::held_action::HeldAction;
use swarm_runtime::runtime_events::RuntimeEvent;
use uuid::Uuid;

use crate::error::BridgeError;
use crate::identity::{Identity, Slot};
use crate::spool::{GapCause, IssuerIdx, Record, Seq};
use crate::stream::{
    action_request_to_wire, finding_to_wire, hold_decision_record_to_wire, hold_rationale_to_wire,
    hold_state_to_wire, policy_decision_to_wire, rehearsal_to_wire, response_action_kind_to_wire,
    severity_label, severity_to_wire, threat_class_slug,
};

/// A finished card body, ready for the pacer to stamp and sign.
#[derive(Debug, Clone)]
pub struct CardBody {
    /// Which marker opens the content.
    pub kind: CardKind,
    /// The channel the `h` tag names.
    pub channel: Uuid,
    /// The three-part body.
    pub content: String,
    /// Nostr tags, in registry order.
    pub tags: Vec<Vec<String>>,
    /// The `(issuer, seq)` this card discharges, committed only on `OK true`.
    pub covers: (IssuerIdx, Seq),
}

/// The per-issuer envelope chain.
///
/// `seq` is the spool's; this carries the other half of the continuity claim, the hash of the
/// previous envelope from the same issuer. The pacer restores the previous value when a frame is
/// not acknowledged, so an unpublished card never advances the chain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeqChain {
    /// `None` only at the issuer's first published envelope.
    pub prev_envelope_hash: Option<String>,
}

/// Builds the `swarm:finding:v1` card for a spooled `RuntimeEvent::Finding`.
///
/// Returns `Ok(None)` for any other event: this milestone publishes findings and case-channel
/// provisioning, and a record whose card type has no producer yet is committed by the pacer and
/// counted, never dropped silently.
///
/// # Errors
///
/// [`BridgeError::MissingLaneChannel`] when the finding's threat class has no configured lane —
/// a `Custom` class with no lane must land somewhere deliberate rather than nowhere;
/// [`BridgeError::Encode`] when the envelope, the content or the tag set is refused.
///
/// Eight parameters, deliberately: the card is a projection of eight independent inputs and the
/// alternative — a context struct built at the one call site — would hide which of them the
/// builder actually reads.
#[allow(clippy::too_many_arguments)]
pub fn build_finding_card(
    record: &Record,
    event: &RuntimeEvent,
    issuer: &Identity,
    colony_id: &str,
    config: &PerchBridgeConfig,
    chain: &mut SeqChain,
    gaps: &[GapCause],
    now_ms: i64,
) -> Result<Option<CardBody>, BridgeError> {
    let RuntimeEvent::Finding {
        emitted_at_ms,
        host_id,
        finding,
    } = event
    else {
        return Ok(None);
    };

    let Some(lane) = config.lane_channel(&finding.threat_class) else {
        let threat_class = threat_class_slug(&finding.threat_class);
        tracing::error!(
            module = module_path!(),
            colony_id,
            threat_class = %threat_class,
            "perch.lane_channels has no lane for this threat class; refusing to publish"
        );
        return Err(BridgeError::MissingLaneChannel { threat_class });
    };

    let mut card = FindingCard {
        issuer: FactIssuer {
            swarm_agent_id: issuer.slot.label().to_string(),
            role: role_of(&issuer.slot),
            nostr_pubkey: Some(issuer.keys.public_key().to_hex()),
        },
        emitted_at_ms: *emitted_at_ms,
        locator: FindingLocator {
            finding_id: finding.finding_id.clone(),
            event_id: finding.event_id.clone(),
            strategy_id: finding.strategy_id.clone(),
            host_id: host_id.clone(),
            lane_channel: lane.to_string(),
        },
        finding: finding_to_wire(finding),
        evidence_truncated: None,
        gap: gaps.first().map(|cause| gap_block(cause, now_ms)),
    };

    let spine_issuer = format!("swarm:ed25519:{}", issuer.keys.public_key().to_hex());
    let issued_at = issued_at_secs(now_ms);
    let mut json = seal(
        &card,
        &spine_issuer,
        record.seq,
        chain.prev_envelope_hash.clone(),
        &issued_at,
    )?;

    // The evidence blob is the only unbounded field in the registry and it is built from
    // telemetry an adversary can shape. When the card would not fit, it is REPLACED by a byte
    // count and a hash, so the card renders an explicit absence rather than a silently smaller
    // blob. The 256-byte allowance covers the marker, the human line and the fence.
    if json.len() + 256 > CARD_CONTENT_MAX_BYTES {
        let evidence = serde_json::to_vec(&card.finding.evidence)
            .map_err(|error| BridgeError::Encode(error.to_string()))?;
        card.evidence_truncated = Some(EvidenceTruncated {
            bytes: evidence.len(),
            sha256: format!("0x{}", hex::encode(Sha256::digest(&evidence))),
        });
        card.finding.evidence = serde_json::Value::Null;
        json = seal(
            &card,
            &spine_issuer,
            record.seq,
            chain.prev_envelope_hash.clone(),
            &issued_at,
        )?;
    }

    let human = Card::Finding(Box::new(card)).human_line();
    let content = build_content(CardKind::Finding, &human, &json)
        .map_err(|error| BridgeError::Encode(error.to_string()))?;

    let tags = TagSet::card(
        CardKind::Finding,
        lane.to_string(),
        Some(threat_class_slug(&finding.threat_class)),
        Some(severity_label(finding.severity).to_string()),
    );
    tags.assert_publishable(KIND_CARD)
        .map_err(|error| BridgeError::Encode(error.to_string()))?;

    let envelope: CardEnvelope =
        serde_json::from_str(&json).map_err(|error| BridgeError::Encode(error.to_string()))?;
    chain.prev_envelope_hash = Some(envelope.envelope_hash);

    Ok(Some(CardBody {
        kind: CardKind::Finding,
        channel: lane,
        content,
        tags: tags.to_tags(),
        covers: (record.issuer, record.seq),
    }))
}

/// Wraps the card in a spine envelope and returns its one-line JSON.
fn seal(
    card: &FindingCard,
    spine_issuer: &str,
    seq: Seq,
    prev_envelope_hash: Option<String>,
    issued_at: &str,
) -> Result<String, BridgeError> {
    let fact = serde_json::to_value(Card::Finding(Box::new(card.clone())))
        .map_err(|error| BridgeError::Encode(error.to_string()))?;
    let envelope = CardEnvelope::seal_unsigned(
        CardKind::Finding,
        spine_issuer,
        seq,
        prev_envelope_hash,
        issued_at.to_string(),
        fact,
    )
    .map_err(|error| BridgeError::Encode(error.to_string()))?;
    serde_json::to_string(&envelope).map_err(|error| BridgeError::Encode(error.to_string()))
}

/// The role of the identity that PUBLISHES the card, when the slot names one.
///
/// # Why this is inferred and not asserted
///
/// `swarm_perch_wire::FactIssuer::role` is REQUIRED and NULLABLE, and its contract is explicit:
/// `null` means "the producing path could not name a role", and *a console renders the absence;
/// it never substitutes a role*. `RuntimeEvent::Finding` carries no producer id and no role at
/// all, so a finding from the HTTP ingest lane is attributed to the ingest identity, whose
/// `AgentId` is `swarm:ed25519:<hex>` — exactly the shape the engine's own `infer_agent_role`
/// returns `None` for. Stamping a role there would be the substitution the wire crate forbids,
/// so this mirrors that function's prefix match and yields `None` otherwise.
fn role_of(slot: &Slot) -> Option<WireAgentRole> {
    let Slot::Agent(id) = slot else {
        return None;
    };
    role_from_agent_id(&id.0)
}

/// The role a role-shaped `AgentId` names, or `None`.
///
/// Mirrors the engine's own `infer_agent_role` prefix match. `swarm:ed25519:<hex>` — the shape a
/// key-derived agent id takes — yields `None`, and the wire contract is explicit that a console
/// RENDERS that absence and never substitutes a role.
fn role_from_agent_id(value: &str) -> Option<WireAgentRole> {
    let role = if value.starts_with("whisker-") {
        AgentRole::Whisker
    } else if value.starts_with("stalker-") {
        AgentRole::Stalker
    } else if value.starts_with("weaver-") {
        AgentRole::Weaver
    } else if value.starts_with("pounce-") || value.starts_with("pouncer-") {
        AgentRole::Pouncer
    } else if value.starts_with("tom-") {
        AgentRole::Tom
    } else if value.starts_with("kitten-") {
        AgentRole::Kitten
    } else if value.starts_with("sphinx-") {
        AgentRole::Sphinx
    } else if value.starts_with("calico-") {
        AgentRole::Calico
    } else {
        return None;
    };
    Some(crate::stream::agent_role_to_wire(role))
}

/// The wire `gap` block for one recorded loss.
///
/// A [`GapCause::BroadcastLagged`] carries a count and NO seq range, ever: no seq was assigned to
/// what was never received, and saying so is the honest rendering. The three spool causes carry
/// an exact inclusive range and no count.
pub fn gap_block(cause: &GapCause, noticed_at_ms: i64) -> GapBlock {
    match cause {
        GapCause::BroadcastLagged { count } => GapBlock {
            cause: GapBlockCause::BroadcastLagged,
            count: Some(*count),
            from_seq: None,
            to_seq: None,
            noticed_at_ms,
        },
        GapCause::SpoolEvicted { from_seq, to_seq } => GapBlock {
            cause: GapBlockCause::SpoolEvicted,
            count: None,
            from_seq: Some(*from_seq),
            to_seq: Some(*to_seq),
            noticed_at_ms,
        },
        GapCause::SpoolTornTail { from_seq, to_seq } => GapBlock {
            cause: GapBlockCause::SpoolTornTail,
            count: None,
            from_seq: Some(*from_seq),
            to_seq: Some(*to_seq),
            noticed_at_ms,
        },
        GapCause::PublishWindowExpired { from_seq, to_seq } => GapBlock {
            cause: GapBlockCause::PublishWindowExpired,
            count: None,
            from_seq: Some(*from_seq),
            to_seq: Some(*to_seq),
            noticed_at_ms,
        },
    }
}

/// RFC 3339 at SECOND precision with a `Z` suffix — the engine's `now_rfc3339` spelling, which
/// `build_signed_envelope` parses and rejects anything else.
fn issued_at_secs(now_ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ─────────────────────────────────────────────────────────── the hold card

/// Projects the daemon's `HeldAction` onto the wire DTO the `swarm:hold:v1` card carries.
///
/// # Why the projection lives here and not in `swarm-perch-wire`
///
/// 00-DECISIONS W3-27: the wire crate depends on no package whose name starts with `swarm-`, so
/// it cannot accept an engine `HeldAction`. The bridge converts; the wire crate defines. Every
/// member is destructured, so a field added to the engine record is a compile error at this line
/// rather than a silently absent key on an operator's card.
///
/// # What is deliberately NOT on the card
///
/// - `detection` and `audit_trail_id`: daemon-side joins with no console route behind them.
/// - `notified_at_ms`, `notice_event_id`, `card_event_id`, `case_channel`: the bridge's own
///   publishing bookkeeping. `case_channel` reappears in the LOCATOR, where it belongs.
/// - `deciding_intent_event_id`, `cas_instant_ms`, `prior_state`: the decide route's
///   compare-and-set internals.
/// - `remaining_ms` and `expired`, which `HeldActionView` serves and this card must not carry: a
///   card is immutable, so baking a countdown into it freezes it at its publish value forever.
///   The console recomputes both from `expires_at_ms` (INV-06).
///
/// `leases_a_containment` is ADDED, from `is_containment_action`, so a card for one of the eight
/// non-containment kinds renders NO pending containment-lease slot rather than an empty one.
/// `inverse_resolution` is ADDED EMPTY: it is derived from `resolve_inverse`, which lives behind
/// the daemon's read route, and a bridge that guessed it would be inventing the IF YOU UNDO slot.
pub fn hold_view_from_record(hold: &HeldAction) -> Result<WireHeldAction, BridgeError> {
    let HeldAction {
        hold_id,
        state,
        action_request,
        rehearsal,
        detection: _,
        policy_decision,
        rationale,
        held_at_ms,
        expires_at_ms,
        audit_trail_id: _,
        case_channel: _,
        notified_at_ms: _,
        notice_event_id: _,
        card_event_id: _,
        decision,
        deciding_intent_event_id: _,
        cas_instant_ms: _,
        prior_state: _,
    } = hold;
    Ok(WireHeldAction {
        hold_id: hold_id.clone(),
        state: hold_state_to_wire(*state),
        action_kind: response_action_kind_to_wire(&action_request.action),
        severity: severity_to_wire(action_request.severity),
        held_at_ms: *held_at_ms,
        expires_at_ms: *expires_at_ms,
        action_request: action_request_to_wire(action_request)?,
        policy_decision: policy_decision_to_wire(policy_decision),
        rationale: hold_rationale_to_wire(rationale),
        leases_a_containment: hold.leases_a_containment(),
        rehearsal: rehearsal.as_ref().map(rehearsal_to_wire),
        inverse_resolution: Vec::new(),
        decision: decision.as_ref().map(hold_decision_record_to_wire),
    })
}

/// Builds the `swarm:hold:v1` card body for one held action.
///
/// Three parts in the ruled order (00-DECISIONS W3-21): the marker line, ONE human line, a blank
/// line, then the fenced spine envelope. The human line is
/// [`swarm_perch_wire::HoldCard::human_line`]'s, not this crate's — a hold with no rehearsal says
/// `scope unresolved` rather than guessing a scope from the action payload, and
/// `swarm-perch-wire/tests/human_lines.rs` pins that string.
///
/// `reply_to` is `None` on the OPEN card and the open card's Nostr event id on the TERMINAL one,
/// which is what makes the terminal card a NIP-10 reply. An `e` tag is legal on a `kind:9` card
/// and FORBIDDEN on the `kind:46010` notice (RF-D1); the two are separate events for exactly
/// that reason.
///
/// # Errors
///
/// [`BridgeError::Encode`] when the envelope, the content grammar or the tag set is refused —
/// including a card body over [`CARD_CONTENT_MAX_BYTES`], which a hold reaches only through an
/// oversized `action_request.evidence`.
#[allow(clippy::too_many_arguments)]
pub fn hold_card(
    hold: &HeldAction,
    case_channel: Uuid,
    finding_card_id: Option<&str>,
    reply_to: Option<&str>,
    issuer: &Identity,
    seq: Seq,
    chain: &mut SeqChain,
    covers: (IssuerIdx, Seq),
    now_ms: i64,
) -> Result<CardBody, BridgeError> {
    let card = HoldCard {
        // The FACT issuer is the agent that requested the destructive action; the ENVELOPE
        // issuer below is the bridge's own spine identity. They are different parties and the
        // card says so, because "who asked for this" is the first question the verdict pane
        // answers. `nostr_pubkey` is `None`: a requesting agent has no relay identity, and
        // inventing the bridge's own here would attribute the request to the publisher.
        issuer: FactIssuer {
            swarm_agent_id: hold.action_request.requested_by.0.clone(),
            role: role_from_agent_id(&hold.action_request.requested_by.0),
            nostr_pubkey: None,
        },
        emitted_at_ms: hold.held_at_ms,
        locator: HoldLocator {
            hold_id: hold.hold_id.clone(),
            case_channel: case_channel.to_string(),
            hunt_id: hold.action_request.hunt_id.0.clone(),
            finding_card_id: finding_card_id.map(str::to_string),
        },
        hold: hold_view_from_record(hold)?,
    };

    let human = card.human_line();
    let spine_issuer = format!("swarm:ed25519:{}", issuer.keys.public_key().to_hex());
    let fact = serde_json::to_value(Card::Hold(Box::new(card)))
        .map_err(|error| BridgeError::Encode(error.to_string()))?;
    let envelope = CardEnvelope::seal_unsigned(
        CardKind::Hold,
        &spine_issuer,
        seq,
        chain.prev_envelope_hash.clone(),
        issued_at_secs(now_ms),
        fact,
    )
    .map_err(|error| BridgeError::Encode(error.to_string()))?;
    let json =
        serde_json::to_string(&envelope).map_err(|error| BridgeError::Encode(error.to_string()))?;
    let content = build_content(CardKind::Hold, &human, &json)
        .map_err(|error| BridgeError::Encode(error.to_string()))?;

    let mut tags = TagSet::card(
        CardKind::Hold,
        case_channel.to_string(),
        Some(threat_class_slug(&hold.rationale.threat_class)),
        Some(severity_label(hold.action_request.severity).to_string()),
    );
    tags.e = reply_to.map(str::to_string);
    tags.assert_publishable(KIND_CARD)
        .map_err(|error| BridgeError::Encode(error.to_string()))?;

    chain.prev_envelope_hash = Some(envelope.envelope_hash);

    Ok(CardBody {
        kind: CardKind::Hold,
        channel: case_channel,
        content,
        tags: tags.to_tags(),
        covers,
    })
}

/// The `kind:46010` tag set: exactly `h`, one `p` per Approve principal, `hold`, and `card`.
///
/// NEVER an `e` tag (RF-D1). The relay does not enforce that — `requires_h_channel_scope` gates
/// `resolve_nip10_thread_meta`, so an `e`-tagged 46010 becomes a NIP-10 reply, mutates its root's
/// `reply_count`/`descendant_count` inside the insert transaction and emits a relay-signed
/// `kind:39005` thread summary — so this producer and
/// [`TagSet::assert_publishable`] are the only things holding the line.
pub fn hold_notice_tags(
    case_channel: Uuid,
    approve_pubkeys: &[String],
    hold_id: &str,
    card_event_id: Option<&str>,
) -> TagSet {
    TagSet::hold_notice(
        case_channel.to_string(),
        approve_pubkeys.to_vec(),
        hold_id,
        card_event_id.map(str::to_string),
    )
}

/// The `kind:26006` tag set: one `p` per Approve principal and NOTHING else (R-1).
pub fn hold_alarm_tags(approve_pubkeys: &[String]) -> TagSet {
    TagSet::hold_alarm(approve_pubkeys.to_vec())
}

/// The five-key `26006` payload for one hold.
///
/// The SHAPE is [`swarm_perch_wire::HoldAlarm`]'s, not this crate's: the wire crate owns every
/// body schema, and building the payload through its type is what makes an upstream rename a
/// compile error here instead of an absent key on the widest-audience event in the registry.
///
/// `hunt_id` is deliberately absent. It is the telemetry event id — a join key into detection
/// data — and this frame is community-global.
pub fn hold_alarm_payload(hold: &HeldAction, case_channel: Uuid) -> WireHoldAlarm {
    WireHoldAlarm {
        hold_id: hold.hold_id.clone(),
        action_kind: response_action_kind_to_wire(&hold.action_request.action),
        severity: severity_to_wire(hold.action_request.severity),
        case_channel: case_channel.to_string(),
        expires_at_ms: hold.expires_at_ms,
    }
}

/// The `kind:46010` content: the card's human line, VERBATIM.
///
/// One line, no marker, no JSON. The notice is a queue row, and the queue row and the card must
/// read identically or an operator reconciling the two learns to distrust both.
pub fn hold_notice_content(card: &CardBody) -> String {
    card.content
        .lines()
        .nth(1)
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::config::SecretString;
    use swarm_core::types::AgentId;
    use swarm_perch_wire::CARD_CONTENT_MAX_BYTES;

    use crate::identity::IdentityTable;

    const LANES: [(&str, &str); 12] = [
        ("lateral_movement", "154eea36-c787-4bf7-9c84-4424b0184395"),
        ("data_exfiltration", "2c8d1a90-6e40-4b1f-9f18-1b3f5c2d7a01"),
        (
            "privilege_escalation",
            "3a1b7c22-9d55-4c07-8f2a-6d4e91b0c3f2",
        ),
        (
            "command_and_control",
            "4b2c8d33-ae66-4d18-9034-7e5f02c1d4a3",
        ),
        ("initial_access", "5c3d9e44-bf77-4e29-a145-8f6013d2e5b4"),
        ("persistence", "6d4eaf55-c088-4f3a-b256-900124e3f6c5"),
        ("supply_chain", "7e5fb066-d199-4a4b-c367-a11235f407d6"),
        ("defense_evasion", "8f60c177-e2aa-4b5c-d478-b2234605918e"),
        ("credential_access", "9071d288-f3bb-4c6d-e589-c334570629f8"),
        ("discovery", "a182e399-04cc-4d7e-f69a-d44568173a09"),
        ("execution", "b293f4aa-15dd-4e8f-07ab-e55679284b1a"),
        ("impact", "c3a405bb-26ee-4f90-18bc-f6678a395c2b"),
    ];

    fn fixture() -> (Identity, PerchBridgeConfig) {
        let table = IdentityTable::build(
            &SecretString::new("11".repeat(32)),
            "c",
            &[],
            &AgentId("swarm:ed25519:".to_string() + &"ab".repeat(32)),
            None,
        )
        .unwrap();
        let identity = table.get(table.ingest()).unwrap().clone();
        let mut config = PerchBridgeConfig::default();
        for (slug, uuid) in LANES {
            config
                .lane_channels
                .insert(slug.to_string(), uuid.to_string());
        }
        config.case_ttl_seconds.insert("default".into(), 2_592_000);
        (identity, config)
    }

    fn finding_event(finding_id: &str, threat_class: &str, severity: &str) -> RuntimeEvent {
        serde_json::from_value(serde_json::json!({
            "event_type": "finding", "emitted_at_ms": 1_700_000_000_000i64, "host_id": "web-04",
            "finding": {"schema": "swarm_finding", "finding_id": finding_id, "event_id": "tel-8831",
                        "strategy_id": "dns_exfil_beaconing", "threat_class": threat_class,
                        "severity": severity, "confidence": 0.82, "evidence": {}}
        }))
        .unwrap()
    }

    #[test]
    fn a_finding_record_becomes_a_three_part_card_with_the_lane_tags() {
        let (identity, config) = fixture();
        let event = finding_event("f2c9a1b4", "data_exfiltration", "HIGH");
        let record = Record {
            seq: 41,
            ..Record::from_event(&event, 0).unwrap()
        };
        let mut chain = SeqChain::default();
        let body = build_finding_card(
            &record,
            &event,
            &identity,
            "c",
            &config,
            &mut chain,
            &[],
            1_700_000_005_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            body.content.lines().next(),
            Some("<!-- swarm:finding:v1 -->")
        );
        assert!(
            body.content
                .lines()
                .nth(1)
                .unwrap()
                .contains("data_exfiltration · HIGH · confidence"),
            "{}",
            body.content
        );
        let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
        let envelope: CardEnvelope = serde_json::from_str(parts.json).unwrap();
        assert_eq!(envelope.seq, 41);
        assert!(envelope.is_tier_zero());
        assert!(envelope.hash_matches().unwrap());
        assert_eq!(envelope.fact["schema"], "swarm.perch.finding.v1");
        assert_eq!(
            envelope.fact["locator"]["lane_channel"],
            config.lane_channels["data_exfiltration"]
        );
        assert_eq!(
            envelope.fact["issuer"]["swarm_agent_id"],
            identity.slot.label()
        );
        // The ingest identity is `swarm:ed25519:<hex>`, which names no role. The wire contract
        // says the console renders that absence and never substitutes a role.
        assert_eq!(envelope.fact["issuer"]["role"], serde_json::Value::Null);
        assert_eq!(
            body.tags,
            vec![
                vec![
                    "h".to_string(),
                    config.lane_channels["data_exfiltration"].clone()
                ],
                vec!["t".to_string(), "data_exfiltration".to_string()],
                vec!["l".to_string(), "HIGH".to_string()],
                vec!["k".to_string(), "finding".to_string()],
            ]
        );
        assert_eq!(body.covers, (0, 41));
        assert_eq!(
            chain.prev_envelope_hash.as_deref(),
            Some(envelope.envelope_hash.as_str())
        );
    }

    #[test]
    fn the_chain_links_each_envelope_to_the_previous_one() {
        let (identity, config) = fixture();
        let mut chain = SeqChain::default();

        let first = finding_event("f1", "execution", "LOW");
        let record_one = Record::from_event(&first, 0).unwrap();
        let body_one = build_finding_card(
            &record_one,
            &first,
            &identity,
            "c",
            &config,
            &mut chain,
            &[],
            1,
        )
        .unwrap()
        .unwrap();
        let first_hash = chain.prev_envelope_hash.clone().unwrap();
        let parts = swarm_perch_wire::marker::parse_content(&body_one.content).unwrap();
        let envelope: CardEnvelope = serde_json::from_str(parts.json).unwrap();
        assert!(
            envelope.prev_envelope_hash.is_none(),
            "the first envelope of an issuer chains to nothing"
        );

        let second = finding_event("f2", "execution", "LOW");
        let record_two = Record {
            seq: 2,
            ..Record::from_event(&second, 0).unwrap()
        };
        let body_two = build_finding_card(
            &record_two,
            &second,
            &identity,
            "c",
            &config,
            &mut chain,
            &[],
            1,
        )
        .unwrap()
        .unwrap();
        let parts = swarm_perch_wire::marker::parse_content(&body_two.content).unwrap();
        let envelope: CardEnvelope = serde_json::from_str(parts.json).unwrap();
        assert_eq!(
            envelope.prev_envelope_hash.as_deref(),
            Some(first_hash.as_str())
        );
        assert_ne!(body_one.content, body_two.content);
    }

    #[test]
    fn a_pending_gap_rides_inside_the_next_card() {
        let (identity, config) = fixture();
        let event = finding_event("f1", "execution", "LOW");
        let record = Record::from_event(&event, 0).unwrap();
        let gaps = vec![GapCause::BroadcastLagged { count: 7 }];
        let body = build_finding_card(
            &record,
            &event,
            &identity,
            "c",
            &config,
            &mut SeqChain::default(),
            &gaps,
            1,
        )
        .unwrap()
        .unwrap();
        let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
        let fact: serde_json::Value =
            serde_json::from_str::<serde_json::Value>(parts.json).unwrap()["fact"].clone();
        assert_eq!(fact["gap"]["cause"], "broadcast_lagged");
        assert_eq!(fact["gap"]["count"], 7);
        assert!(
            fact["gap"].get("from_seq").is_none(),
            "a lag has no seq range, ever"
        );

        let evicted = vec![GapCause::SpoolEvicted {
            from_seq: 4,
            to_seq: 9,
        }];
        let body = build_finding_card(
            &record,
            &event,
            &identity,
            "c",
            &config,
            &mut SeqChain::default(),
            &evicted,
            1,
        )
        .unwrap()
        .unwrap();
        let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
        let fact: serde_json::Value =
            serde_json::from_str::<serde_json::Value>(parts.json).unwrap()["fact"].clone();
        assert_eq!(fact["gap"]["cause"], "spool_evicted");
        assert_eq!(fact["gap"]["from_seq"], 4);
        assert_eq!(fact["gap"]["to_seq"], 9);
        assert!(fact["gap"].get("count").is_none());
    }

    #[test]
    fn oversized_evidence_is_replaced_by_a_byte_count_and_a_hash() {
        let (identity, config) = fixture();
        let mut event = finding_event("big", "impact", "CRITICAL");
        if let RuntimeEvent::Finding { finding, .. } = &mut event {
            finding.evidence = serde_json::json!({ "blob": "x".repeat(CARD_CONTENT_MAX_BYTES) });
        }
        let record = Record::from_event(&event, 0).unwrap();
        let body = build_finding_card(
            &record,
            &event,
            &identity,
            "c",
            &config,
            &mut SeqChain::default(),
            &[],
            1,
        )
        .unwrap()
        .unwrap();
        assert!(body.content.len() <= CARD_CONTENT_MAX_BYTES);
        let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
        let fact: serde_json::Value =
            serde_json::from_str::<serde_json::Value>(parts.json).unwrap()["fact"].clone();
        assert_eq!(fact["finding"]["evidence"], serde_json::Value::Null);
        assert!(
            fact["evidence_truncated"]["bytes"].as_u64().unwrap() > CARD_CONTENT_MAX_BYTES as u64
        );
        assert!(
            fact["evidence_truncated"]["sha256"]
                .as_str()
                .unwrap()
                .starts_with("0x")
        );
    }

    #[test]
    fn a_non_finding_evidence_record_builds_no_card() {
        let (identity, config) = fixture();
        let event: RuntimeEvent = serde_json::from_value(serde_json::json!({
            "event_type": "escalation", "emitted_at_ms": 1, "threat_class": "execution",
            "level": "alert", "total_strength": 2.5, "distinct_sources": 2,
            "peak_confidence": 0.9, "mode_changed": false, "current_mode": "alert"
        }))
        .unwrap();
        let record = Record::from_event(&event, 0).unwrap();
        assert!(
            build_finding_card(
                &record,
                &event,
                &identity,
                "c",
                &config,
                &mut SeqChain::default(),
                &[],
                1
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn a_threat_class_with_no_lane_is_refused_by_name() {
        let (identity, mut config) = fixture();
        config.lane_channels.remove("impact");
        let event = finding_event("f1", "impact", "LOW");
        let record = Record::from_event(&event, 0).unwrap();
        let error = build_finding_card(
            &record,
            &event,
            &identity,
            "c",
            &config,
            &mut SeqChain::default(),
            &[],
            1,
        )
        .unwrap_err();
        assert!(
            matches!(error, BridgeError::MissingLaneChannel { ref threat_class } if threat_class == "impact"),
            "{error}"
        );
    }

    fn hold_fixture(action: swarm_core::types::ResponseAction, held_at_ms: i64) -> HeldAction {
        swarm_runtime::held_action_fixtures::fixture_hold(action, held_at_ms)
    }

    fn isolate_host_hold() -> HeldAction {
        hold_fixture(
            swarm_core::types::ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            1_773_738_882_600,
        )
    }

    const CASE: &str = "27799e23-ab25-4659-b381-3de47ea7ca4d";

    fn case_channel() -> Uuid {
        Uuid::parse_str(CASE).unwrap()
    }

    #[test]
    fn the_hold_card_body_is_three_parts_in_the_ruled_order_and_names_no_signature() {
        let (identity, _config) = fixture();
        let hold = isolate_host_hold();
        let mut chain = SeqChain::default();
        let body = hold_card(
            &hold,
            case_channel(),
            None,
            None,
            &identity,
            3,
            &mut chain,
            (0, 3),
            1_773_738_882_700,
        )
        .unwrap();

        let mut lines = body.content.split('\n');
        assert_eq!(lines.next(), Some("<!-- swarm:hold:v1 -->"));
        let human = lines.next().unwrap();
        // The scope slot comes from the rehearsal's blast radius. This fixture has none, and the
        // wire crate's contract -- pinned by `swarm-perch-wire/tests/human_lines.rs` -- is that a
        // hold with no rehearsal SAYS SO rather than guessing a scope from the action payload.
        assert_eq!(
            human,
            format!(
                "hold {} · isolate_host · CRITICAL · scope unresolved · expires 2026-03-17T10:14:42Z",
                hold.hold_id
            ),
            "{human}"
        );
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.next(), Some("```swarm:hold:v1"));

        let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
        let json: serde_json::Value = serde_json::from_str(parts.json).unwrap();
        assert_eq!(json["schema"], "swarm.spine.envelope.v1");
        assert_eq!(json["seq"], 3);
        assert_eq!(json["fact"]["schema"], "swarm.perch.hold.v1");
        assert_eq!(json["fact"]["locator"]["case_channel"], CASE);
        assert_eq!(json["fact"]["locator"]["hunt_id"], "hunt-evt-1");
        assert_eq!(json["fact"]["locator"]["hold_id"], hold.hold_id);
        assert_eq!(json["fact"]["hold"]["leases_a_containment"], true);
        assert_eq!(json["fact"]["hold"]["state"], "created");
        assert_eq!(json["fact"]["hold"]["action_kind"], "isolate_host");
        assert_eq!(
            json["fact"]["hold"]["action_request"]["action"],
            serde_json::json!({"type": "isolate_host", "host_id": "host-ops-1"})
        );
        // T-16: no card body this crate builds names a signature, a signer or a verification.
        assert!(json.get("signature").is_none());
        assert!(!body.content.contains("signed_by") && !body.content.contains("verified"));
        // The two clock-derived `HeldActionView` fields are NOT on an immutable card (INV-06).
        assert!(json["fact"]["hold"].get("remaining_ms").is_none());
        assert!(json["fact"]["hold"].get("expired").is_none());
        // Nor is the daemon's own publishing bookkeeping or its detection join.
        for absent in [
            "detection",
            "case_channel",
            "notified_at_ms",
            "notice_event_id",
            "card_event_id",
            "deciding_intent_event_id",
            "cas_instant_ms",
            "prior_state",
            "audit_trail_id",
        ] {
            assert!(
                json["fact"]["hold"].get(absent).is_none(),
                "{absent} must not ride a hold card"
            );
        }
        // The envelope's issuer is the BRIDGE; the fact's issuer is the requesting agent.
        assert_eq!(
            json["issuer"],
            format!("swarm:ed25519:{}", identity.keys.public_key().to_hex())
        );
        assert_eq!(
            json["fact"]["issuer"]["swarm_agent_id"],
            hold.action_request.requested_by.0
        );
        assert_eq!(json["fact"]["issuer"]["role"], serde_json::Value::Null);
        assert_eq!(
            json["fact"]["issuer"]["nostr_pubkey"],
            serde_json::Value::Null
        );

        assert_eq!(
            body.tags,
            vec![
                vec!["h".to_string(), CASE.to_string()],
                vec!["t".to_string(), "execution".to_string()],
                vec!["l".to_string(), "CRITICAL".to_string()],
                vec!["k".to_string(), "hold".to_string()],
            ],
            "a kind:9 card never carries a p tag"
        );
        assert_eq!(body.kind, CardKind::Hold);
        assert_eq!(body.channel, case_channel());
        assert_eq!(body.covers, (0, 3));
        assert_eq!(
            chain.prev_envelope_hash.as_deref(),
            Some(json["envelope_hash"].as_str().unwrap())
        );
    }

    #[test]
    fn a_rehearsed_hold_names_its_blast_radius_in_the_human_line() {
        let (identity, _config) = fixture();
        let mut hold = isolate_host_hold();
        hold.rehearsal = Some(swarm_core::types::ResponseRehearsalPreview {
            rehearsal_id: "rehearsal-1".into(),
            source_bundle_id: "bundle-1".into(),
            prepared_at_ms: 1_773_738_882_500,
            simulated_only: true,
            blast_radius: swarm_core::types::ResponseBlastRadiusPreview {
                scope_kind: swarm_core::types::ResponseRehearsalScopeKind::Host,
                scope_value: "host-ops-1".into(),
                impact: swarm_core::types::ResponseBlastRadiusImpact::HostConnectivityIsolated,
                max_affected_scopes: 1,
                affected_capabilities: vec!["network".into()],
                summary: "one host loses connectivity".into(),
            },
            rollback: swarm_core::types::ResponseRollbackPreview {
                required: true,
                summary: "restore connectivity".into(),
                steps: vec![swarm_core::types::ResponseRollbackStep {
                    kind: swarm_core::types::ResponseRollbackStepKind::RestoreHostConnectivity,
                    summary: "reconnect the host".into(),
                }],
            },
        });
        let body = hold_card(
            &hold,
            case_channel(),
            Some(&"ad".repeat(32)),
            None,
            &identity,
            4,
            &mut SeqChain::default(),
            (0, 4),
            1_773_738_882_700,
        )
        .unwrap();
        assert_eq!(
            body.content.lines().nth(1).unwrap(),
            format!(
                "hold {} · isolate_host · CRITICAL · host host-ops-1 · expires 2026-03-17T10:14:42Z",
                hold.hold_id
            )
        );
        let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
        let json: serde_json::Value = serde_json::from_str(parts.json).unwrap();
        assert_eq!(json["fact"]["locator"]["finding_card_id"], "ad".repeat(32));
        assert_eq!(
            json["fact"]["hold"]["rehearsal"]["blast_radius"]["impact"],
            "host_connectivity_isolated"
        );
        assert_eq!(
            json["fact"]["hold"]["rehearsal"]["rollback"]["steps"][0]["kind"],
            "restore_host_connectivity"
        );
        // DERIVED, NOT SERVED: the bridge never guesses the IF YOU UNDO slot.
        assert_eq!(
            json["fact"]["hold"]["inverse_resolution"],
            serde_json::json!([])
        );
    }

    #[test]
    fn a_terminal_card_replies_to_the_open_one_and_an_open_card_threads_nothing() {
        let (identity, _config) = fixture();
        let mut hold = isolate_host_hold();
        hold.state = swarm_runtime::held_action::HoldState::Refused;
        let open_card_id = "03".repeat(32);
        let body = hold_card(
            &hold,
            case_channel(),
            None,
            Some(&open_card_id),
            &identity,
            5,
            &mut SeqChain::default(),
            (0, 5),
            1,
        )
        .unwrap();
        assert!(
            body.tags
                .contains(&vec!["e".to_string(), open_card_id.clone()]),
            "{:?}",
            body.tags
        );
        let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
        let json: serde_json::Value = serde_json::from_str(parts.json).unwrap();
        assert_eq!(json["fact"]["hold"]["state"], "refused");

        let open = hold_card(
            &isolate_host_hold(),
            case_channel(),
            None,
            None,
            &identity,
            6,
            &mut SeqChain::default(),
            (0, 6),
            1,
        )
        .unwrap();
        assert!(
            !open
                .tags
                .iter()
                .any(|tag| tag.first().map(String::as_str) == Some("e")),
            "{:?}",
            open.tags
        );
    }

    #[test]
    fn the_notice_carries_exactly_the_four_tag_names_and_the_alarm_exactly_five_keys() {
        let notice = hold_notice_tags(
            case_channel(),
            &["68".repeat(32)],
            "h_a07aeacf",
            Some(&"b9".repeat(32)),
        );
        notice
            .assert_publishable(swarm_perch_wire::KIND_HOLD_NOTICE)
            .unwrap();
        assert!(
            notice.e.is_none() && notice.t.is_none() && notice.l.is_none() && notice.k.is_none()
        );
        assert_eq!(notice.p.len(), 1);
        assert_eq!(
            notice
                .to_tags()
                .iter()
                .map(|tag| tag[0].clone())
                .collect::<Vec<_>>(),
            vec!["h", "p", "hold", "card"]
        );

        let alarm =
            serde_json::to_value(hold_alarm_payload(&isolate_host_hold(), case_channel())).unwrap();
        let mut keys: Vec<&str> = alarm
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "action_kind",
                "case_channel",
                "expires_at_ms",
                "hold_id",
                "severity"
            ]
        );

        let alarm_tags = hold_alarm_tags(&["68".repeat(32)]);
        assert!(alarm_tags.h.is_none(), "26006 is global (R-1)");
        alarm_tags
            .assert_publishable(swarm_perch_wire::KIND_HOLD_ALARM)
            .unwrap();
        assert_eq!(alarm_tags.to_tags().len(), 1);
        assert!(matches!(
            hold_alarm_tags(&[]).assert_publishable(swarm_perch_wire::KIND_HOLD_ALARM),
            Err(swarm_perch_wire::TagError::NoRecipients(26006))
        ));
    }

    #[test]
    fn rf_d1_the_notice_this_producer_builds_can_never_be_threaded() {
        // RF-D1 is producer-enforced and only producer-enforced. The relay ADMITS an e-tagged
        // 46010 and threads it -- `requires_h_channel_scope` also gates
        // `resolve_nip10_thread_meta`, so the notice becomes a NIP-10 reply, mutates its root's
        // reply_count/descendant_count inside the insert transaction, and produces a
        // relay-signed kind:39005 thread summary. Two things hold the line, and this asserts
        // both: the builder never sets `e`, and the assert refuses one that was set by hand.
        let notice = hold_notice_tags(
            case_channel(),
            &["68".repeat(32)],
            "h_a07aeacf",
            Some(&"b9".repeat(32)),
        );
        assert!(notice.e.is_none(), "the builder has no e-tag input at all");
        let mut threaded = notice.clone();
        threaded.e = Some("f".repeat(64));
        assert_eq!(
            threaded.assert_publishable(swarm_perch_wire::KIND_HOLD_NOTICE),
            Err(swarm_perch_wire::TagError::ThreadedHoldNotice)
        );
        // And every OTHER way a notice can be undeliverable is refused before signing too.
        assert_eq!(
            hold_notice_tags(case_channel(), &[], "h_a07aeacf", None)
                .assert_publishable(swarm_perch_wire::KIND_HOLD_NOTICE),
            Err(swarm_perch_wire::TagError::NoRecipients(46010))
        );
        assert!(matches!(
            hold_notice_tags(
                case_channel(),
                &["68".repeat(32)],
                "hold:hunt-evt-1:1773738882600",
                None
            )
            .assert_publishable(swarm_perch_wire::KIND_HOLD_NOTICE),
            Err(swarm_perch_wire::TagError::MalformedHoldId(_))
        ));
        assert!(matches!(
            hold_notice_tags(case_channel(), &["68".repeat(31)], "h_a07aeacf", None)
                .assert_publishable(swarm_perch_wire::KIND_HOLD_NOTICE),
            Err(swarm_perch_wire::TagError::MalformedPubkey(_))
        ));
        let mut no_hold = notice.clone();
        no_hold.hold = None;
        assert_eq!(
            no_hold.assert_publishable(swarm_perch_wire::KIND_HOLD_NOTICE),
            Err(swarm_perch_wire::TagError::MissingHoldTag)
        );
    }

    #[test]
    fn the_notice_content_is_the_card_line_verbatim() {
        let (identity, _config) = fixture();
        let hold = isolate_host_hold();
        let body = hold_card(
            &hold,
            case_channel(),
            None,
            None,
            &identity,
            1,
            &mut SeqChain::default(),
            (0, 1),
            1,
        )
        .unwrap();
        let content = hold_notice_content(&body);
        assert_eq!(content, body.content.lines().nth(1).unwrap());
        assert!(!content.contains("<!--"), "the notice carries no marker");
        assert!(!content.contains('{'), "the notice carries no JSON");
        assert!(!content.contains('\n'), "the notice is exactly one line");
        assert!(content.starts_with(&format!("hold {}", hold.hold_id)));
    }

    #[test]
    fn the_hold_view_projects_every_action_kind_without_losing_its_payload() {
        // The kind is compile-checked by `response_action_kind_to_wire`'s exhaustive match; the
        // PAYLOAD rides `WireResponseAction`'s flatten map, so this asserts the two halves
        // reassemble into the engine's own serde bytes for all fifteen.
        for action in every_response_action() {
            let engine = serde_json::to_value(&action).unwrap();
            let hold = hold_fixture(action, 1);
            let view = hold_view_from_record(&hold).unwrap();
            assert_eq!(
                serde_json::to_value(&view.action_request.action).unwrap(),
                engine
            );
            assert_eq!(
                view.leases_a_containment,
                view.action_kind.leases_a_containment(),
                "{engine}"
            );
        }
    }

    fn every_response_action() -> Vec<swarm_core::types::ResponseAction> {
        use swarm_core::types::ResponseAction as A;
        vec![
            A::BlockEgress {
                target: "10.0.0.1".into(),
            },
            A::IsolateHost {
                host_id: "web-04".into(),
            },
            A::RevokeCredential {
                credential_id: "cred-1".into(),
            },
            A::SinkholeDns {
                domain: "evil.example".into(),
            },
            A::TerminateUserSession {
                host_id: "web-04".into(),
                session_id: "sess-1".into(),
            },
            A::TriggerEdrScan {
                host_id: "web-04".into(),
                scan_profile: "full".into(),
            },
            A::InjectFirewallRule {
                host_id: "web-04".into(),
                rule_name: "deny-egress".into(),
                direction: "egress".into(),
                cidr: "10.0.0.0/8".into(),
                port: Some(443),
            },
            A::QuarantineFile {
                host_id: "web-04".into(),
                file_path: "/tmp/x".into(),
            },
            A::KillProcess {
                host_id: "web-04".into(),
                process_name: "beacon".into(),
            },
            A::SuspendProcess {
                host_id: "web-04".into(),
                process_name: "beacon".into(),
            },
            A::DisableUserAccount {
                user_id: "acct-1".into(),
            },
            A::ForcePasswordReset {
                user_id: "acct-1".into(),
            },
            A::RemoveScheduledTask {
                host_id: "web-04".into(),
                task_name: "task-1".into(),
            },
            A::DeployDecoy {
                decoy_type: "honeypot".into(),
                target_zone: "dmz".into(),
            },
            A::Escalate {
                summary: "needs a human".into(),
                urgency: swarm_core::types::Severity::High,
            },
        ]
    }

    #[test]
    fn a_role_is_inferred_only_from_a_role_shaped_agent_id() {
        assert_eq!(
            role_of(&Slot::Agent(AgentId("whisker-7a3f".into()))),
            Some(swarm_perch_wire::WireAgentRole::Whisker)
        );
        assert_eq!(
            role_of(&Slot::Agent(AgentId(
                "swarm:ed25519:".to_string() + &"ab".repeat(32)
            ))),
            None
        );
        assert_eq!(role_of(&Slot::Alarm), None);
        assert_eq!(role_of(&Slot::Telemetry), None);
    }
}
