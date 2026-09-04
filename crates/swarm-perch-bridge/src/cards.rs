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
    FindingCard, FindingLocator, GapBlock, GapBlockCause, KIND_CARD, TagSet, build_content,
};
use swarm_runtime::runtime_events::RuntimeEvent;
use uuid::Uuid;

use crate::error::BridgeError;
use crate::identity::{Identity, Slot};
use crate::spool::{GapCause, IssuerIdx, Record, Seq};
use crate::stream::{finding_to_wire, severity_label, threat_class_slug};

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
fn role_of(slot: &Slot) -> Option<swarm_perch_wire::WireAgentRole> {
    let Slot::Agent(id) = slot else {
        return None;
    };
    let value = id.0.as_str();
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
