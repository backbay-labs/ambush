//! Marker card assembly. **The body schemas are `13-WIRE-SCHEMAS.md`'s, not this crate's.**
//!
//! This module assembles: it picks the marker, builds the issuer block, attaches the `gap` and
//! `coalesced` blocks, writes the human fallback line, and hands a `serde_json::Value` to the
//! pacer. It does not define field names. Where a shape is named below it is a citation of
//! `13-WIRE-SCHEMAS.md`, not a second definition of it.

use serde_json::Value;

use crate::coalesce::CoalescedBlock;
use crate::spool::GapCause;

/// The four markers this crate produces. Three of the seven frozen markers are produced elsewhere:
///
/// - `ambush:verdict:v1` -- the console, leg 1 of the two-legged write.
/// - `ambush:rollback:v1` -- the console for an operator release; nobody for a TTL expiry until
///   the proposed **B1c** thirteenth `RuntimeEvent` variant lands
///   (`11-BRIDGE-CRATE.md` section 9.4).
/// - `ambush:lease:v1` -- this crate, but from the containment-lease poll rather than a
///   `RuntimeEvent`, so it is listed here for completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    Finding,
    Escalation,
    Hold,
    Receipt,
    Lease,
}

impl Marker {
    /// The HTML comment that opens the body. Version is IN THE MARKER, not only in the JSON, so a
    /// renderer routes before it parses and a `v1` renderer meeting `v2` falls through to the
    /// fallback line.
    pub const fn comment(self) -> &'static str {
        match self {
            Self::Finding => "<!-- ambush:finding:v1 -->",
            Self::Escalation => "<!-- ambush:escalation:v1 -->",
            Self::Hold => "<!-- ambush:hold:v1 -->",
            Self::Receipt => "<!-- ambush:receipt:v1 -->",
            Self::Lease => "<!-- ambush:lease:v1 -->",
        }
    }

    /// The `k` tag value. A display and post-filter hint only: `filter_fully_pushable`
    /// (`buzz-relay/src/handlers/req.rs:851-895`) pushes only `kinds`, `authors`, `ids`,
    /// `since`/`until`, `#h`, a SINGLE `#p`, `#d` on NIP-33-only kind filters, and `#e`.
    /// `#k` is post-filtered over a fetched page, and no document may describe it as indexed
    /// selection.
    pub const fn k_tag(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Escalation => "escalation",
            Self::Hold => "hold",
            Self::Receipt => "receipt",
            Self::Lease => "lease",
        }
    }
}

/// The three-part body, in this order. Assembled here; the middle part's schema is
/// `13-WIRE-SCHEMAS.md`'s.
///
/// ```text
/// <!-- ambush:finding:v1 -->
/// {"schema":"ambush.perch.finding.v1","seq":41,"issuer":{...},"finding":{...},"locator":{...}}
/// whisker-7a3f - dns_exfiltration - HIGH - conf 0.82 - host web-04 - finding f2c9...
/// ```
///
/// The third line is the degradation contract: it must carry the identifiers a human needs to go
/// find the real thing, because it is what the Flutter app, the web client,
/// `buzz messages thread` and an FTS snippet show. The JSON is ONE line so the fallback is
/// separable by the first newline.
pub struct CardBody {
    pub marker: Marker,
    pub json: Value,
    pub fallback_line: String,
}

/// Every card carries an optional `gap` block and an optional `coalesced` block.
///
/// This is `11-BRIDGE-CRATE.md` section 3.6's decision, and it is why loss needs no eighth marker.
/// The gap cannot be lost independently of the card it precedes, because it is inside the same
/// signed envelope.
///
/// **Binding on `13-WIRE-SCHEMAS.md`:** a card with an EMPTY payload array and a populated `gap`
/// block is legal and must render. A schema that sets `minItems: 1` on a payload array breaks gap
/// flushing (see [`crate::pacer::PERCH_GAP_FLUSH_TICKS`]).
pub fn attach_loss_blocks(
    json: &mut Value,
    gaps: &[GapCause],
    coalesced: Option<&CoalescedBlock>,
) {
    let _ = (json, gaps, coalesced);
    todo!("insert `gap` and/or `coalesced`; both absent on a normal card")
}

/// The issuer block, present in every card body.
///
/// ```jsonc
/// "issuer": {
///   "swarm_agent_id": "swarm:ed25519:9f3c...64hex",   // AgentId, types.rs:16-18, verbatim
///   "nostr_pubkey":   "a71b...64hex",
///   "role": "whisker"
/// }
/// ```
///
/// **No `signature`, `signed_by` or `verified` field appears here or anywhere else in a body this
/// crate constructs.** The Nostr envelope's own `sig` is the transport's, is visible to any reader
/// of the raw event, and needs no help from the body. Four of the seven marker card types wrap
/// objects that carry no signature at all -- `DetectionFinding`
/// (`swarm-whisker/src/detector.rs:51-59`), `SwarmFindingEnvelope`
/// (`swarm-response/src/siem.rs:17-27`), `ResponseReceipt` (`swarm-response/src/lib.rs:100-116`),
/// and the proposed `HeldAction` record -- and the chain machinery the plan set cites is nearly
/// dead code: `build_signed_envelope` has 1 non-test caller and `verify_chain_link` has 0
/// consumers outside its own module. Test T-16 asserts the absence.
pub fn issuer_block(swarm_agent_id: &str, nostr_pubkey: &str, role: &str) -> Value {
    let _ = (swarm_agent_id, nostr_pubkey, role);
    todo!("13-WIRE-SCHEMAS.md owns the field names")
}

/// The hold card's body order IS the verdict-pane render order:
/// `action` -> `rehearsal.blast_radius` -> `inverse` -> `policy` -> `lease_on_grant`.
///
/// Keeping serialization order and render order identical means a reviewer diffing a card against
/// a screenshot checks one thing, not two.
///
/// `hold_id` is an **opaque random token**, never `hold:{hunt_id}:{held_at_ms}`. `hunt_id` is the
/// telemetry event id (`swarm-runtime/src/service/runtime_service.rs:391`), a join key into
/// detection data; it lives in the body, which is channel-compartmented, and never in the
/// community-global `26006` frame.
pub fn hold_card(/* the B1 HeldAction record */) -> CardBody {
    todo!("assemble in verdict-pane order")
}

/// The `26006` payload, and the reason it is a narrow struct rather than a `RuntimeEvent`.
///
/// The relay does NOT enforce `#p` on delivery of a global ephemeral: `filter_fanout_by_access`
/// (`buzz-relay/src/handlers/event.rs:115-222`) applies only the receiver tenant label
/// (`:126-131`), `AUTHOR_ONLY_KINDS` (`:139-152`) and `SHARED_GATED_KINDS` (`:157-175`) to a
/// channel-less event, then returns every match at `:177-179`. Any authenticated community member
/// who opens `REQ {"kinds":[26006]}` receives every hold alarm.
///
/// `10-RELAY-FORK.md` owns that decision. The bridge's obligation is unconditional either way: the
/// payload is exactly these five fields, built from a narrow type so a `RuntimeEvent` field can
/// never leak into it by a careless `serde` derive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HoldAlarm {
    pub hold_id: String,
    pub action_kind: String,
    /// `Severity` serializes SCREAMING_SNAKE_CASE (`swarm-core/src/types.rs:407-414`) while ~40
    /// sibling enums serialize snake_case. Any codegen that lowercases uniformly breaks exactly
    /// this field.
    pub severity: String,
    pub case_channel: String,
    pub expires_at_ms: i64,
}
