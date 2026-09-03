//! The `swarm.spine.envelope.v1` wrapper, as Perch publishes it.
//!
//! This is not a Perch envelope. The field set, the ordering of the signing
//! preimage, the canonicalization and the hash are
//! `AMB crates/swarm-spine/src/envelope.rs:71-101` (`build_signed_envelope`),
//! which the daemon already calls once, from the approval-ledger vote path at
//! `AMB crates/swarm-runtime/src/approval.rs:1810`.
//!
//! # Why the wrapper ships before B6
//!
//! `compute_envelope_hash_hex` (`envelope.rs:47-51`) takes **no keypair** — it
//! canonicalizes with `swarm_crypto::canonicalize_json`
//! (`AMB crates/swarm-crypto/src/lib.rs:37`) and hashes. So does
//! `verify_chain_link` (`AMB crates/swarm-spine/src/chain.rs:75`), which reads
//! only `issuer`, `seq`, `prev_envelope_hash` and `envelope_hash` and compares
//! them against a persisted `IssuerChainHead` (`chain.rs:9-15`). Both are `pub`
//! and both work today.
//!
//! Publishing the envelope shape now buys two things and costs about 200 bytes a
//! card:
//!
//! 1. **B6 becomes additive.** It adds a configured key and two fields. Without
//!    the wrapper it would be a `v1` -> `v2` marker bump, and every card ever
//!    published stays `v1` forever, so both renderers live in the tree for good.
//! 2. **Gap detection exists at all.** `GET /v1/events/stream` sets
//!    `.id(event.emitted_at_ms().to_string())`
//!    (`AMB crates/swarm-ingest-runtime/src/ingest/demo.rs:1703`) — a millisecond
//!    timestamp that collides at the concentration monitor's 10 Hz cadence and is
//!    not monotonic across issuers — and `RuntimeEvent` has no `seq` field at all
//!    (`AMB crates/swarm-runtime/src/runtime_events.rs:214-305`). The bridge's own
//!    `seq` is the first sequence number anywhere on this path.
//!
//! # What the wrapper does NOT buy
//!
//! **It does not raise the verification tier.** `08` §6.2 defines tier 1 as a
//! detached Ed25519 signature over the body; a keyless hash is not one. A card
//! with `envelope_hash` and no `signature` renders **tier 0**, and the
//! sequence-continuity result renders as its own separate, explicitly
//! non-cryptographic row. `is_tier_zero` below is the assertion that keeps that
//! honest, and `16-INVARIANT-TESTS.md` should pin it.
//!
//! **It does not prove the bridge saw everything the daemon sent.**
//! `RuntimeEventBroadcaster::publish` is `let _ = self.tx.send(event)`
//! (`AMB crates/swarm-runtime/src/runtime_events.rs:116-118`) and both existing
//! subscribers drop a `Lagged` silently with
//! `let Ok(event) = result else { return None; }`
//! (`ingest/demo.rs:1689`, `ingest/platform_api.rs:1388`); `rg 'Lagged|RecvError'`
//! over `AMB crates/` returns zero matches. A `seq` gap proves the CONSOLE lost a
//! card. Loss upstream of the bridge is countable only as
//! `perch_bridge_broadcast_lagged_total`, which the bridge publishes separately.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::marker::CardKind;

/// `AMB crates/swarm-spine/src/envelope.rs:11`.
pub const ENVELOPE_SCHEMA_V1: &str = "swarm.spine.envelope.v1";

/// Who produced the fact, as distinct from who published the envelope.
///
/// The plan set's `03` §3.2 sketch put a three-field issuer block at the top
/// level. It cannot live there: `verify_chain_link` reads `issuer` as a string
/// and runs it through `parse_issuer_pubkey_hex`
/// (`AMB crates/swarm-spine/src/chain.rs:36-39`), which requires the literal
/// `swarm:ed25519:` prefix and exactly 64 hex characters. So the top-level
/// `issuer` is the publishing identity — the bridge — and this block sits inside
/// `fact`, where it belongs, because the Whisker that produced a finding did not
/// publish it and must not appear to have signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactIssuer {
    /// The `AgentId` verbatim. `AMB crates/swarm-core/src/types.rs:9-13` makes it
    /// `{role}-{short_id}`; `WhiskerAgent::tick` makes it
    /// `{derived_identity}:{agent_id}`
    /// (`AMB crates/swarm-agents/src/whisker_agent.rs:148-149`). Neither is a
    /// Nostr pubkey and neither is a `swarm:ed25519:` identity.
    pub swarm_agent_id: String,
    /// One of eight (`AMB crates/swarm-core/src/agent.rs:14-34`), or `None`.
    ///
    /// **NULLABLE AND REQUIRED**, and the two words are both load-bearing. Two
    /// production paths fill this and they disagree:
    ///
    /// - `WhiskerAgent::tick` passes `Some(AgentRole::Whisker)` explicitly into
    ///   `detect_and_deposit_with_role`
    ///   (`AMB crates/swarm-agents/src/whisker_agent.rs:150-156`, inside
    ///   `swarm_detect --serve`), so a finding produced there carries a role.
    /// - `infer_agent_role`
    ///   (`AMB crates/swarm-runtime/src/detection/pipeline.rs:583-604`) is a
    ///   prefix match over `whisker-` / `stalker-` / `weaver-` /
    ///   `pounce(r)-` / `tom-` / `kitten-` / `sphinx-` / `calico-` and returns
    ///   `None` for anything else — including every `swarm:ed25519:<hex>`
    ///   identity the HTTP ingest lane uses, and every operator id.
    ///
    /// So `null` means "the producing path could not name a role", NOT "no
    /// agent". A console renders the absence; it never substitutes a role.
    ///
    /// NOT `#[serde(default)]`: a MISSING key must be a decode error while a
    /// genuine absence is an explicit `null`. Collapsing the two would let a
    /// truncated body decode as an unattributed fact. `13-WIRE-SCHEMAS.md` §9
    /// amendment `W-A1`.
    pub role: Option<swarm_core::agent::AgentRole>,
    /// **`None` in every deployment today.** No Ambush agent holds a Nostr
    /// keypair and no config field carries one:
    /// `OperatorPrincipalConfig` is `{operator_id, token_env,
    /// token_expires_at_ms?, scopes}` with `#[serde(deny_unknown_fields)]`
    /// (`AMB crates/swarm-core/src/config/operator.rs:116-129`), and
    /// `grep -rn 'pubkey|npub|nostr' crates/swarm-core/src/config/` returns
    /// nothing. This is the same gap that forces the bridge to hold the
    /// operator_id -> npub map for `p` tags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
}

/// WHO PRODUCED THE FACT, when the producer is a PERSON.
///
/// A separate type from [`FactIssuer`], used by `ambush:verdict:v1` and nothing
/// else — the one card in the registry a human, not the bridge, publishes.
///
/// The whole reason it exists is `role: NeverARole`, a unit type that serializes
/// as `null` and cannot hold anything else. `AgentRole` is a closed
/// eight-variant enum of SWARM agents (`AMB crates/swarm-core/src/agent.rs:14-34`)
/// with no human member, and `AgentRole::Tom` is "Governance — enforces policy,
/// manages lifecycle" (`agent.rs:26-27`): the VETO actor. Stamping `tom` on an
/// operator's own decision conflates the human's *refuse* with governance's
/// *veto*, which `APPENDIX-NORMATIVE.md` §7 forbids and `adr/0016` spends a
/// document keeping apart. Reusing `FactIssuer` here makes that conflation a
/// value a producer could pick; a distinct type makes it a compile error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorFactIssuer {
    /// The configured Ambush operator principal id
    /// (`AMB crates/swarm-core/src/config/operator.rs:116-129`). Not an
    /// `AgentId` and not a `swarm:ed25519:` identity.
    pub swarm_agent_id: String,
    /// Structurally `null`. See the type doc.
    pub role: NeverARole,
    /// The operator's OWN Nostr pubkey — the signer of the leg-1 event. Unlike
    /// an agent's this one is populated in a working deployment: it is the key
    /// the console publishes with. Still `Option` because the
    /// `operator_id -> Nostr pubkey` mapping is an unbudgeted config addition
    /// (`OperatorPrincipalConfig` is `#[serde(deny_unknown_fields)]`), and a card
    /// built before it lands must say so rather than guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
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
/// Field order here is the field order `build_signed_envelope` uses
/// (`AMB crates/swarm-spine/src/envelope.rs:86-93`). It does not affect the
/// signature — `canonicalize_json` sorts keys — but keeping them in the same
/// order means a reviewer diffing this struct against that `json!` macro checks
/// one thing, not two.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CardEnvelope {
    /// Always [`ENVELOPE_SCHEMA_V1`].
    pub schema: String,
    /// `swarm:ed25519:{64 hex}` — the BRIDGE's spine identity, one per colony.
    /// On an `ambush:verdict:v1` card only, it is the OPERATOR's, because the
    /// operator publishes that card with their own key.
    pub issuer: String,
    /// Per-issuer, per-stream monotonic counter assigned by the bridge.
    pub seq: u64,
    /// `None` only at `seq == 1` for a given issuer and stream.
    pub prev_envelope_hash: Option<String>,
    /// RFC 3339, SECOND precision, `Z` suffix.
    /// `build_signed_envelope` parses and rejects anything else
    /// (`AMB crates/swarm-spine/src/envelope.rs:78-83`), and
    /// `now_rfc3339` (`:13-16`) is
    /// `chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)`.
    pub issued_at: String,
    /// Always `null`. `AMB crates/swarm-spine/src/envelope.rs:89` hardcodes it.
    pub capability_token: Value,
    /// The card.
    pub fact: Value,
    /// sha256 over the RFC 8785 canonical form of this object with
    /// `envelope_hash` and `signature` absent. Keyless.
    pub envelope_hash: String,
    /// **Absent until B6.** Ed25519 over the same bytes.
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
    /// Canonicalization or hashing failed.
    #[error("spine error: {0}")]
    Spine(#[from] swarm_spine::SpineError),
    /// The fact was not a JSON object.
    #[error("fact must be a JSON object")]
    FactNotObject,
}

impl CardEnvelope {
    /// Wrap a card, computing `envelope_hash` with no key.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::SchemaMismatch`] when the serialized card's `schema`
    /// does not equal `kind.fact_schema()` — the one check that stops a
    /// `HoldCard` shipping under an `ambush:receipt:v1` marker — and
    /// [`EnvelopeError::Spine`] when canonicalization fails.
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

        // Exactly the unsigned map `build_signed_envelope` builds
        // (`AMB crates/swarm-spine/src/envelope.rs:86-93`), so the hash this
        // computes is the hash B6's signature will cover.
        let unsigned = serde_json::json!({
            "schema": ENVELOPE_SCHEMA_V1,
            "issuer": issuer,
            "seq": seq,
            "prev_envelope_hash": prev_envelope_hash,
            "issued_at": issued_at,
            "capability_token": Value::Null,
            "fact": fact,
        });
        let envelope_hash = swarm_spine::envelope::compute_envelope_hash_hex(&unsigned)?;

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
}

#[cfg(test)]
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
            fact("ambush.perch.hold.v1"),
        )
        .expect_err("must reject");
        assert!(matches!(err, EnvelopeError::SchemaMismatch { .. }));
    }

    #[test]
    fn an_unsigned_envelope_is_tier_zero_even_with_a_hash() {
        let env = CardEnvelope::seal_unsigned(
            CardKind::Hold,
            "swarm:ed25519:00",
            1,
            None,
            "2026-08-30T02:41:07Z".into(),
            fact("ambush.perch.hold.v1"),
        )
        .expect("seals");
        assert!(!env.envelope_hash.is_empty());
        assert!(env.is_tier_zero());
    }

    #[test]
    fn signature_is_omitted_from_the_wire_when_absent() {
        let env = CardEnvelope::seal_unsigned(
            CardKind::Hold,
            "swarm:ed25519:00",
            1,
            None,
            "2026-08-30T02:41:07Z".into(),
            fact("ambush.perch.hold.v1"),
        )
        .expect("seals");
        let json = serde_json::to_value(&env).expect("serializes");
        // Present-as-null would be a different fact from absent, and B6's
        // signing preimage excludes the field entirely.
        assert!(json.get("signature").is_none());
    }
}
