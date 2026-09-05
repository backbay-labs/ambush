//! The `swarm.spine.envelope.v1` wrapper, as Perch publishes it.
//!
//! This is not a Perch envelope. The field set, the ordering of the signing
//! preimage, the canonicalization and the hash are the engine's spine envelope
//! (`crates/swarm-spine/src/envelope.rs`, `build_signed_envelope`), which the
//! daemon already calls once from the approval-ledger vote path. This module
//! re-states that contract with transport-neutral code so the crate depends on
//! no `swarm-*` package (W3-27): [`canonical_bytes`] is RFC 8785 / JCS via
//! `serde_json_canonicalizer`, and [`compute_envelope_hash_hex`] is SHA-256 over
//! those bytes with the schema's `0x` prefix. The bridge's differential corpus
//! test proves the two implementations agree byte for byte.
//!
//! # Why the wrapper ships before B6
//!
//! [`compute_envelope_hash_hex`] takes **no keypair** — it canonicalizes and
//! hashes. So does the engine's `verify_chain_link`, which reads only `issuer`,
//! `seq`, `prev_envelope_hash` and `envelope_hash` and compares them against a
//! persisted chain head. Publishing the envelope shape now buys two things and
//! costs about 200 bytes a card:
//!
//! 1. **B6 becomes additive.** It adds a configured key and two fields. Without
//!    the wrapper it would be a `v1` -> `v2` marker bump, and every card ever
//!    published stays `v1` forever, so both renderers live in the tree for good.
//! 2. **Gap detection exists at all.** `GET /v1/events/stream` ids events by
//!    `emitted_at_ms` — a millisecond timestamp that collides at the
//!    concentration monitor's 10 Hz cadence and is not monotonic across
//!    issuers — and `RuntimeEvent` has no `seq` field at all. The bridge's own
//!    `seq` is the first sequence number anywhere on this path.
//!
//! # What the wrapper does NOT buy
//!
//! **It does not raise the verification tier.** `08` §6.2 defines tier 1 as a
//! detached Ed25519 signature over the body; a keyless hash is not one. A card
//! with `envelope_hash` and no `signature` renders **tier 0**, and the
//! sequence-continuity result renders as its own separate, explicitly
//! non-cryptographic row. [`CardEnvelope::is_tier_zero`] is the assertion that
//! keeps that honest.
//!
//! **It does not prove the bridge saw everything the daemon sent.** The
//! runtime's broadcaster drops a lagged receiver silently. A `seq` gap proves
//! the CONSOLE lost a card. Loss upstream of the bridge is countable only as
//! `perch_bridge_broadcast_lagged_total`, which the bridge publishes separately.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cards::WireAgentRole;
use crate::marker::CardKind;

/// The envelope schema constant, the engine's `ENVELOPE_SCHEMA_V1`.
pub const ENVELOPE_SCHEMA_V1: &str = "swarm.spine.envelope.v1";

/// Who produced the fact, as distinct from who published the envelope.
///
/// The top-level envelope `issuer` is the publishing identity — the bridge —
/// and must parse as `swarm:ed25519:` plus 64 hex characters, because the
/// engine's `verify_chain_link` runs it through `parse_issuer_pubkey_hex`. This
/// block sits inside `fact`, where it belongs, because the Whisker that produced
/// a finding did not publish it and must not appear to have signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactIssuer {
    /// The engine `AgentId` verbatim: `{role}-{short_id}`, or the Whisker's
    /// `{derived_identity}:{agent_id}`. Neither is a Nostr pubkey and neither
    /// is a `swarm:ed25519:` identity.
    pub swarm_agent_id: String,
    /// One of eight, or `None`.
    ///
    /// **NULLABLE AND REQUIRED**, and the two words are both load-bearing. Two
    /// production paths fill this and they disagree: the Whisker's tick passes
    /// its role explicitly, so a finding produced there carries one; the
    /// deposit path's `infer_agent_role` is a prefix match over the eight role
    /// names and returns `None` for anything else — including every
    /// `swarm:ed25519:<hex>` identity the HTTP ingest lane uses.
    ///
    /// So `null` means "the producing path could not name a role", NOT "no
    /// agent". A console renders the absence; it never substitutes a role.
    ///
    /// NOT `#[serde(default)]`, and not a bare `Option` either: serde's derive
    /// quietly reads a MISSING `Option` field as `None`, so the field goes
    /// through [`required_nullable`], which makes a missing key a decode error
    /// while a genuine absence stays an explicit `null`. Collapsing the two
    /// would let a truncated body decode as an unattributed fact.
    /// `13-WIRE-SCHEMAS.md` §9 amendment `W-A1`.
    #[serde(deserialize_with = "required_nullable")]
    pub role: Option<WireAgentRole>,
    /// **`None` in every deployment today.** No engine agent holds a Nostr
    /// keypair and no config field carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
}

/// WHO PRODUCED THE FACT, when the producer is a PERSON.
///
/// A separate type from [`FactIssuer`], used by `swarm:verdict:v1` and nothing
/// else — the one card in the registry a human, not the bridge, publishes.
///
/// The whole reason it exists is `role: NeverARole`, a unit type that serializes
/// as `null` and cannot hold anything else. The agent-role enum is a closed
/// eight-variant set of SWARM agents with no human member, and `tom` is
/// "Governance — enforces policy, manages lifecycle": the VETO actor. Stamping
/// `tom` on an operator's own decision conflates the human's *refuse* with
/// governance's *veto*, which `APPENDIX-NORMATIVE.md` §7 forbids and `adr/0016`
/// spends a document keeping apart. Reusing [`FactIssuer`] here makes that
/// conflation a value a producer could pick; a distinct type makes it a compile
/// error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorFactIssuer {
    /// The configured operator principal id. Not an `AgentId` and not a
    /// `swarm:ed25519:` identity.
    pub swarm_agent_id: String,
    /// Structurally `null`. See the type doc.
    pub role: NeverARole,
    /// The operator's OWN Nostr pubkey — the signer of the leg-1 event. Unlike
    /// an agent's this one is populated in a working deployment: it is the key
    /// the console publishes with. Still `Option` because a card built before
    /// the operator's pubkey is configured must say so rather than guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
}

/// Deserialize a REQUIRED, NULLABLE field.
///
/// serde's derive maps a missing `Option<T>` key to `None` on its own, which is
/// exactly the collapse `FactIssuer::role` forbids. Routing the field through a
/// `deserialize_with` function removes that shortcut: a missing key surfaces as
/// serde's `missing field` error, and only an explicit `null` becomes `None`.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// A field that is always `null` on the wire and has no other inhabitant.
///
/// `serde` serializes a unit struct as `null` and refuses to deserialize
/// anything else into it, so `{"role":"tom"}` fails to decode with the same
/// force the JSON Schema's `"type": "null"` rejects it. That symmetry is the
/// point: the schema and the decoder refuse the same byte sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeverARole;

/// A Perch card body: a spine envelope carrying one card as its `fact`.
///
/// Field order here is the field order the engine's `build_signed_envelope`
/// uses. It does not affect the signature — canonicalization sorts keys — but
/// keeping them in the same order means a reviewer diffing this struct against
/// that `json!` macro checks one thing, not two.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CardEnvelope {
    /// Always [`ENVELOPE_SCHEMA_V1`].
    pub schema: String,
    /// `swarm:ed25519:{64 hex}` — the BRIDGE's spine identity, one per colony.
    /// On an `swarm:verdict:v1` card only, it is the OPERATOR's, because the
    /// operator publishes that card with their own key.
    pub issuer: String,
    /// Per-issuer, per-stream monotonic counter assigned by the bridge.
    pub seq: u64,
    /// `None` only at `seq == 1` for a given issuer and stream.
    pub prev_envelope_hash: Option<String>,
    /// RFC 3339, SECOND precision, `Z` suffix — the engine's `now_rfc3339` is
    /// `chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)`, and its
    /// `build_signed_envelope` parses and rejects anything else.
    pub issued_at: String,
    /// Always `null`. The engine hardcodes it.
    pub capability_token: Value,
    /// The card.
    pub fact: Value,
    /// sha256 over the RFC 8785 canonical form of this object with
    /// `envelope_hash` and `signature` absent. Keyless.
    pub envelope_hash: String,
    /// **Absent until B6.** Ed25519 over the same bytes. Kept as an optional
    /// string so a signed engine envelope deserializes without this crate
    /// naming a crypto type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Envelope construction failures.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// `fact.schema` did not match the card kind it was built for.
    #[error("fact.schema is `{found}`, expected `{expected}`")]
    SchemaMismatch {
        /// What the fact said.
        found: String,
        /// What the card kind requires.
        expected: &'static str,
    },
    /// RFC 8785 canonicalization failed (a non-finite number, or a value that
    /// is not JSON).
    #[error("canonicalization failed: {0}")]
    Canonical(String),
    /// The fact was not a JSON object with a string `schema`.
    #[error("fact must be a JSON object with a string `schema`")]
    FactNotObject,
    /// The envelope handed to the hash was not a JSON object.
    #[error("an envelope must be a JSON object")]
    EnvelopeNotObject,
}

/// The RFC 8785 (JCS) canonical bytes of any serializable value.
///
/// Keys are sorted by UTF-16 code unit, numbers are ES6-formatted, and no
/// whitespace is emitted — the same form the engine's `canonicalize_json`
/// produces, so a signature over these bytes verifies against either
/// implementation.
///
/// # Errors
///
/// [`EnvelopeError::Canonical`] when the value cannot be represented as JSON
/// (a non-finite float, a map with non-string keys).
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, EnvelopeError> {
    serde_json_canonicalizer::to_vec(value).map_err(|e| EnvelopeError::Canonical(e.to_string()))
}

/// The keyless `envelope_hash`: `0x` + lowercase hex SHA-256 over the canonical
/// bytes of `envelope` with `envelope_hash` and `signature` removed.
///
/// Accepts either an unsigned envelope or one that already carries both fields,
/// so a reader can recompute and compare the hash on a card it received.
///
/// # Errors
///
/// [`EnvelopeError::EnvelopeNotObject`] when `envelope` is not a JSON object;
/// [`EnvelopeError::Canonical`] when canonicalization fails.
pub fn compute_envelope_hash_hex(envelope: &Value) -> Result<String, EnvelopeError> {
    let Value::Object(map) = envelope else {
        return Err(EnvelopeError::EnvelopeNotObject);
    };
    let mut unsigned = map.clone();
    unsigned.remove("envelope_hash");
    unsigned.remove("signature");
    let bytes = canonical_bytes(&Value::Object(unsigned))?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("0x{}", hex::encode(digest)))
}

impl CardEnvelope {
    /// Wrap a card, computing `envelope_hash` with no key.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::SchemaMismatch`] when the serialized card's `schema`
    /// does not equal `kind.fact_schema()` — the one check that stops a
    /// `HoldCard` shipping under an `swarm:receipt:v1` marker —
    /// [`EnvelopeError::FactNotObject`] when the fact has no string `schema`,
    /// and [`EnvelopeError::Canonical`] when canonicalization fails.
    pub fn seal_unsigned(
        kind: CardKind,
        issuer: &str,
        seq: u64,
        prev_envelope_hash: Option<String>,
        issued_at: String,
        fact: Value,
    ) -> Result<Self, EnvelopeError> {
        let found = fact
            .get("schema")
            .and_then(Value::as_str)
            .ok_or(EnvelopeError::FactNotObject)?;
        if found != kind.fact_schema() {
            return Err(EnvelopeError::SchemaMismatch {
                found: found.to_string(),
                expected: kind.fact_schema(),
            });
        }

        // Exactly the unsigned map the engine's `build_signed_envelope` builds,
        // so the hash this computes is the hash B6's signature will cover.
        let unsigned = serde_json::json!({
            "schema": ENVELOPE_SCHEMA_V1,
            "issuer": issuer,
            "seq": seq,
            "prev_envelope_hash": prev_envelope_hash,
            "issued_at": issued_at,
            "capability_token": Value::Null,
            "fact": fact,
        });
        let envelope_hash = compute_envelope_hash_hex(&unsigned)?;

        Ok(Self {
            schema: ENVELOPE_SCHEMA_V1.to_string(),
            issuer: issuer.to_string(),
            seq,
            prev_envelope_hash,
            issued_at,
            capability_token: Value::Null,
            fact: unsigned
                .get("fact")
                .cloned()
                .ok_or(EnvelopeError::FactNotObject)?,
            envelope_hash,
            signature: None,
        })
    }

    /// Whether this envelope pins its card at verification tier 0.
    ///
    /// True whenever `signature` is absent, regardless of `envelope_hash`. A
    /// keyless hash is a continuity fact, not an authorship fact, and `08` §6.2
    /// defines tier 1 as a detached Ed25519 signature over the body.
    #[must_use]
    pub const fn is_tier_zero(&self) -> bool {
        self.signature.is_none()
    }

    /// Recompute the keyless hash over this envelope and compare it with the
    /// `envelope_hash` it carries.
    ///
    /// # Errors
    ///
    /// Propagates [`EnvelopeError::Canonical`] when the envelope cannot be
    /// canonicalized.
    pub fn hash_matches(&self) -> Result<bool, EnvelopeError> {
        let value =
            serde_json::to_value(self).map_err(|e| EnvelopeError::Canonical(e.to_string()))?;
        Ok(compute_envelope_hash_hex(&value)? == self.envelope_hash)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fact(schema: &str) -> Value {
        serde_json::json!({"schema": schema, "issuer": {}, "emitted_at_ms": 1, "locator": {}})
    }

    #[test]
    fn a_card_cannot_ship_under_the_wrong_marker() {
        let err = CardEnvelope::seal_unsigned(
            CardKind::Receipt,
            "swarm:ed25519:00",
            1,
            None,
            "2026-08-30T02:41:07Z".into(),
            fact("swarm.perch.hold.v1"),
        )
        .expect_err("must reject");
        assert!(matches!(err, EnvelopeError::SchemaMismatch { .. }));
    }

    #[test]
    fn a_fact_without_a_schema_is_refused() {
        let err = CardEnvelope::seal_unsigned(
            CardKind::Hold,
            "swarm:ed25519:00",
            1,
            None,
            "2026-08-30T02:41:07Z".into(),
            serde_json::json!({"issuer": {}}),
        )
        .expect_err("must reject");
        assert!(matches!(err, EnvelopeError::FactNotObject));
    }

    #[test]
    fn an_unsigned_envelope_is_tier_zero_even_with_a_hash() {
        let env = CardEnvelope::seal_unsigned(
            CardKind::Hold,
            "swarm:ed25519:00",
            1,
            None,
            "2026-08-30T02:41:07Z".into(),
            fact("swarm.perch.hold.v1"),
        )
        .expect("seals");
        assert!(env.envelope_hash.starts_with("0x"));
        assert_eq!(env.envelope_hash.len(), 2 + 64);
        assert!(env.is_tier_zero());
        assert!(env.hash_matches().expect("canonicalizes"));
    }

    #[test]
    fn signature_is_omitted_from_the_wire_when_absent() {
        let env = CardEnvelope::seal_unsigned(
            CardKind::Hold,
            "swarm:ed25519:00",
            1,
            None,
            "2026-08-30T02:41:07Z".into(),
            fact("swarm.perch.hold.v1"),
        )
        .expect("seals");
        let json = serde_json::to_value(&env).expect("serializes");
        // Present-as-null would be a different fact from absent, and B6's
        // signing preimage excludes the field entirely.
        assert!(json.get("signature").is_none());
    }

    /// Insertion order deliberately reversed: serde emits struct fields in
    /// declaration order, so `zulu` comes first on a plain `to_vec` and the
    /// canonicalizer must sort it last.
    #[derive(Serialize)]
    struct Reversed {
        zulu: u32,
        mike: Vec<f64>,
        alpha: Nested,
    }

    #[derive(Serialize)]
    struct Nested {
        second: &'static str,
        first: Option<bool>,
    }

    #[test]
    fn canonical_bytes_are_rfc_8785_ordered_and_formatted() {
        let value = Reversed {
            zulu: 26,
            mike: vec![0.0, 1.5, 1e21, 2.696_884],
            alpha: Nested {
                second: "é\u{1F41D}",
                first: None,
            },
        };
        let bytes = canonical_bytes(&value).expect("canonicalizes");
        assert_eq!(
            String::from_utf8(bytes).expect("utf8"),
            "{\"alpha\":{\"first\":null,\"second\":\"é\u{1F41D}\"},\"mike\":[0,1.5,1e+21,2.696884],\"zulu\":26}"
        );
        // The plain serializer would have started with `zulu`.
        assert!(
            serde_json::to_string(&value)
                .unwrap()
                .starts_with("{\"zulu\"")
        );
    }

    #[test]
    fn a_non_finite_number_cannot_be_canonicalized() {
        let err = canonical_bytes(&f64::NAN).expect_err("NaN is not JSON");
        assert!(matches!(err, EnvelopeError::Canonical(_)));
    }

    #[test]
    fn the_hash_excludes_envelope_hash_and_signature_and_nothing_else() {
        let unsigned = serde_json::json!({
            "schema": ENVELOPE_SCHEMA_V1,
            "issuer": "swarm:ed25519:00",
            "seq": 1,
            "prev_envelope_hash": null,
            "issued_at": "2026-08-30T02:41:07Z",
            "capability_token": null,
            "fact": fact("swarm.perch.hold.v1"),
        });
        let expected = compute_envelope_hash_hex(&unsigned).expect("hashes");
        // The digest is exactly sha256 over the canonical bytes, `0x`-prefixed.
        let by_hand = format!(
            "0x{}",
            hex::encode(Sha256::digest(canonical_bytes(&unsigned).unwrap()))
        );
        assert_eq!(expected, by_hand);

        let mut signed = unsigned.clone();
        signed["envelope_hash"] = Value::String(expected.clone());
        signed["signature"] = Value::String("0xdeadbeef".into());
        assert_eq!(compute_envelope_hash_hex(&signed).unwrap(), expected);

        let mut tampered = unsigned;
        tampered["seq"] = Value::from(2);
        assert_ne!(compute_envelope_hash_hex(&tampered).unwrap(), expected);

        assert!(matches!(
            compute_envelope_hash_hex(&Value::Null),
            Err(EnvelopeError::EnvelopeNotObject)
        ));
    }

    #[test]
    fn a_verdict_issuer_cannot_carry_an_agent_role() {
        // `{"role":"tom"}` fails to decode with the same force the JSON
        // Schema's `"type": "null"` rejects it.
        let tom = serde_json::json!({"swarm_agent_id": "perch-operator-1", "role": "tom"});
        assert!(serde_json::from_value::<OperatorFactIssuer>(tom).is_err());
        let human: OperatorFactIssuer = serde_json::from_value(
            serde_json::json!({"swarm_agent_id": "perch-operator-1", "role": null}),
        )
        .expect("decodes");
        assert_eq!(human.role, NeverARole);
        assert_eq!(serde_json::to_value(human.role).unwrap(), Value::Null);
    }

    #[test]
    fn a_fact_issuer_role_is_required_and_nullable() {
        let missing = serde_json::json!({"swarm_agent_id": "whisker-7a3f"});
        assert!(serde_json::from_value::<FactIssuer>(missing).is_err());
        let explicit: FactIssuer =
            serde_json::from_value(serde_json::json!({"swarm_agent_id": "x", "role": null}))
                .expect("decodes");
        assert_eq!(explicit.role, None);
        let whisker: FactIssuer =
            serde_json::from_value(serde_json::json!({"swarm_agent_id": "x", "role": "whisker"}))
                .expect("decodes");
        assert_eq!(whisker.role, Some(WireAgentRole::Whisker));
    }
}

// ═════════════════════════════════════════════ chain verification (B6)
//
// Transport-neutral and KEYLESS. This crate performs no signature operation and
// names no crypto type: it says what a well-formed link looks like, and the
// bridge — which does hold a key — says whether the signature over those bytes
// is good. Splitting it this way is what lets a console verify the CHAIN
// without shipping a verifier for the engine's key material.

/// The last envelope this issuer published, as a verifier remembers it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerChainHead {
    /// `swarm:ed25519:{64 hex}`.
    pub issuer: String,
    /// The `seq` of that envelope.
    pub seq: u64,
    /// Its `envelope_hash`, which the next link must name as `prev_envelope_hash`.
    pub envelope_hash: String,
}

/// Why a link did or did not continue its chain.
///
/// Four outcomes rather than a bool: an operator told only "invalid" cannot
/// tell a replay from a gap from a fork, and those need different responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainLinkVerdict {
    /// The link continues the chain.
    Valid,
    /// The envelope names a different issuer than the head.
    IssuerMismatch,
    /// `seq` is not exactly one past the head's.
    SequenceGap,
    /// `prev_envelope_hash` does not name the head's hash.
    HashMismatch,
}

/// The envelope as it is HASHED and SIGNED: itself, without the two fields that
/// are derived from it.
///
/// Exposed because a verifier must rebuild exactly these bytes, and rebuilding
/// them by hand somewhere else is how the two sides drift.
///
/// # Errors
///
/// [`EnvelopeError::EnvelopeNotObject`] when `envelope` is not a JSON object.
pub fn unsigned_envelope_value(envelope: &Value) -> Result<Value, EnvelopeError> {
    let Value::Object(map) = envelope else {
        return Err(EnvelopeError::EnvelopeNotObject);
    };
    let mut unsigned = map.clone();
    unsigned.remove("envelope_hash");
    unsigned.remove("signature");
    Ok(Value::Object(unsigned))
}

/// Whether `envelope` continues `head`'s chain, and if not, how it failed.
///
/// Checks only the three structural facts a chain is: same issuer, the next
/// sequence number, and a back-pointer at the head's hash. It does NOT check
/// the signature, because this crate holds no keys.
#[must_use]
pub fn verify_chain_link(head: &IssuerChainHead, envelope: &CardEnvelope) -> ChainLinkVerdict {
    if envelope.issuer != head.issuer {
        return ChainLinkVerdict::IssuerMismatch;
    }
    if envelope.seq != head.seq.saturating_add(1) {
        return ChainLinkVerdict::SequenceGap;
    }
    if envelope.prev_envelope_hash.as_deref() != Some(head.envelope_hash.as_str()) {
        return ChainLinkVerdict::HashMismatch;
    }
    ChainLinkVerdict::Valid
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod chain_tests {
    use super::*;

    fn head() -> IssuerChainHead {
        IssuerChainHead {
            issuer: format!("swarm:ed25519:{}", "ab".repeat(32)),
            seq: 4,
            envelope_hash: format!("0x{}", "cd".repeat(32)),
        }
    }

    fn link(head: &IssuerChainHead) -> CardEnvelope {
        CardEnvelope {
            schema: ENVELOPE_SCHEMA_V1.to_string(),
            issuer: head.issuer.clone(),
            seq: head.seq + 1,
            prev_envelope_hash: Some(head.envelope_hash.clone()),
            issued_at: "2026-09-04T00:00:00Z".to_string(),
            capability_token: Value::Null,
            fact: serde_json::json!({}),
            envelope_hash: format!("0x{}", "ef".repeat(32)),
            signature: None,
        }
    }

    #[test]
    fn a_well_formed_link_continues_the_chain() {
        let head = head();
        assert_eq!(
            verify_chain_link(&head, &link(&head)),
            ChainLinkVerdict::Valid
        );
    }

    /// Each failure is named, not collapsed into "invalid". A replay, a gap and
    /// a fork need different responses from whoever is reading.
    #[test]
    fn each_way_a_link_can_break_is_reported_as_itself() {
        let head = head();

        let mut foreign = link(&head);
        foreign.issuer = format!("swarm:ed25519:{}", "11".repeat(32));
        assert_eq!(
            verify_chain_link(&head, &foreign),
            ChainLinkVerdict::IssuerMismatch
        );

        let mut skipped = link(&head);
        skipped.seq = head.seq + 2;
        assert_eq!(
            verify_chain_link(&head, &skipped),
            ChainLinkVerdict::SequenceGap
        );

        // A replay of the head itself is a gap, not a valid link.
        let mut replayed = link(&head);
        replayed.seq = head.seq;
        assert_eq!(
            verify_chain_link(&head, &replayed),
            ChainLinkVerdict::SequenceGap
        );

        let mut forked = link(&head);
        forked.prev_envelope_hash = Some(format!("0x{}", "99".repeat(32)));
        assert_eq!(
            verify_chain_link(&head, &forked),
            ChainLinkVerdict::HashMismatch
        );

        // A first-link envelope arriving against an existing head is a fork too.
        let mut rooted = link(&head);
        rooted.prev_envelope_hash = None;
        assert_eq!(
            verify_chain_link(&head, &rooted),
            ChainLinkVerdict::HashMismatch
        );
    }

    /// The bytes a verifier rebuilds are the bytes the hash was taken over.
    #[test]
    fn the_unsigned_value_is_what_the_hash_is_computed_from() {
        let head = head();
        let envelope = link(&head);
        let value = serde_json::to_value(&envelope).unwrap();
        let unsigned = unsigned_envelope_value(&value).unwrap();
        assert!(unsigned.get("envelope_hash").is_none());
        assert!(unsigned.get("signature").is_none());
        assert_eq!(
            compute_envelope_hash_hex(&value).unwrap(),
            compute_envelope_hash_hex(&unsigned).unwrap(),
            "removing the derived fields twice must not change the digest"
        );
    }
}
