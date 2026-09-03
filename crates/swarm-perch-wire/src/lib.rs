#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Wire types for the Perch operator console.
//!
//! ## Owns
//!
//! - The seven `swarm:*:v1` marker constants and the card-kind slug they encode.
//! - The three-part card content grammar (marker line, human line, fenced JSON)
//!   and the only parser for it.
//! - The `swarm.spine.envelope.v1` wrapper as Perch publishes it, its RFC 8785
//!   canonical bytes and its keyless hash, including the rule that `signature`
//!   is absent until B6 and that its absence pins the card at verification
//!   tier 0.
//! - The wire-owned DTOs every card and frame is built from: the twelve-plus-one
//!   threat classes, the four severities, the agent roles, the action, receipt,
//!   lease and rollback records. They mirror the JSON Schemas under
//!   `docs/plans/ambush-ui/build/schemas/` field for field and are serialized
//!   contracts, not aliases of engine types.
//! - The tag builders, the opaque hold-id contract, and the assertions that
//!   must pass before a card is signed.
//!
//! ## Does not own
//!
//! - Any authorization decision. Nothing in this crate grants, refuses, verifies
//!   a policy verdict or mints a capability lease. A `VerdictCard` is a record of a human
//!   intent; the daemon re-derives authority from scratch on a separate process
//!   boundary (`POST /v1/response/holds/{id}/decide`).
//! - Transport. No socket, no HTTP client, no Nostr signing. `swarm-perch-bridge`
//!   owns those; this crate hands it bytes.
//! - The engine's domain types, or any conversion from them. This crate depends
//!   on no package whose name starts with `swarm-` (`00-DECISIONS.md` D2 and
//!   W3-27). The bridge converts `SwarmFindingEnvelope`, `ThreatClass`,
//!   `Severity`, `AgentRole` and `RuntimeEvent` into the DTOs here, and the
//!   bridge is where a `RuntimeEvent` is narrowed to a card or a frame.
//! - Rendering. Nothing here produces a label, a badge or a colour.
//!
//! (The two headings above are RULE 5's exact required lines in
//! `tools/check-workspace-layering.sh`. This crate is not on the
//! `TRUST_SENSITIVE` list so the rule does not fire on it; carrying them anyway
//! costs two lines and means the crate can be added to that list later without a
//! second edit.)
//!
//! # The three-part content grammar
//!
//! Every `kind:9` marker card's `content` is exactly:
//!
//! ````text
//! <!-- swarm:finding:v1 -->
//! whisker-7a3f · data_exfiltration · HIGH · confidence 0.82 · host web-04 · finding f2c9a1b4
//!
//! ```swarm:finding:v1
//! {"schema":"swarm.spine.envelope.v1", ...}
//! ```
//! ````
//!
//! Line 0 is the marker and nothing else, because `INV-15` requires the sniff to
//! fire only on an exact whole-first-line match. Line 1 is the human fallback and
//! is deliberately second rather than last: the desktop's search preview is
//! `buildSearchResultPreview(content, query, maxLength = 96)`
//! (`workspace/desktop/src/features/search/lib/searchMatch.ts`), which slices
//! the first 96 characters when the query does not match, so anything after the
//! first ~70 characters of readable text is invisible in a search result. Putting
//! the JSON second spends the whole preview on
//! `{"schema":"swarm.spine.envelope.v1","issuer":"swarm:ed25519:...`.
//!
//! The JSON is fenced rather than bare for the same reason `ambush-acp` fences
//! its own structured payload (the ```` ```ambush:config-nudge ```` block): a
//! fence is a contained block in every markdown renderer, and an unfenced JSON
//! line is a wall of text in all of them.

/// Card body types, one per `swarm:*:v1` marker, and the wire vocabulary.
pub mod cards;
/// The `swarm.spine.envelope.v1` wrapper, its canonical bytes and its keyless hash.
pub mod envelope;
/// The `26000`-`26006` ephemeral frame bodies.
pub mod frames;
/// Marker constants, the card-kind slug, and the content grammar.
pub mod marker;
/// Tag builders, the opaque hold id, and the assertions that run before a card is signed.
pub mod tags;

pub use cards::{
    Card, ConcentrationCrossing, Decision, EscalationBody, EscalationCard, EscalationLocator,
    EvidenceTruncated, FindingCard, FindingLocator, GapBlock, GapBlockCause, HUMAN_SEP, HeldAction,
    HoldCard, HoldDecisionRecord, HoldLocator, HoldRationale, HoldState, InverseResolution,
    InverseVerdict, LeaseCard, LeaseLocator, Leg2Outcome, Leg2State, ModeTransitionBody,
    ReceiptCard, ReceiptLocator, ReleaseOutcome, RollbackCard, RollbackLocator,
    SourceCountMechanism, SourceIdsAbsentReason, TamperFailClosed, TtlSource, VerdictBody,
    VerdictCard, VerdictLocator, WireActionRequest, WireAgentHealth, WireAgentRole,
    WireAuditResponseRecord, WireAuditTrail, WireBlastRadiusImpact, WireBlastRadiusPreview,
    WireCapabilityLease, WireContainmentLease, WireDetachedSignature, WireDetectionFinding,
    WireExecutionMode, WireFindingEnvelope, WirePartitionState, WirePolicyDecision,
    WirePolicyRecord, WirePolicyVerdict, WireRehearsalPreview, WireRehearsalScopeKind,
    WireResponseAction, WireResponseActionKind, WireResponseFailure, WireResponseGovernanceAudit,
    WireResponsePolicyAudit, WireResponseReceipt, WireResponseReceiptAudit, WireResponseStatus,
    WireRollbackPreview, WireRollbackReceipt, WireRollbackStep, WireRollbackStepKind,
    WireRollbackStepOutcome, WireRollbackStepStatus, WireRollbackTrigger, WireSeverity,
    WireSwarmMode, WireThreatClass, severity_label, threat_class_slug,
};
pub use envelope::{
    CardEnvelope, ENVELOPE_SCHEMA_V1, EnvelopeError, FactIssuer, NeverARole, OperatorFactIssuer,
    canonical_bytes, compute_envelope_hash_hex,
};
pub use frames::{
    AgentHealthEntry, AgentHealthFrame, ConcentrationFrame, EscalationLevel, Frame, FrameBody,
    FrameHeader, FrameKind, GovernanceStatusFrame, HoldAlarm, IngestRate, ModeTransitionFrame,
    Stream, TamperAlertFrame, ThreatConcentration,
};
pub use marker::{
    CARD_CONTENT_MAX_BYTES, CardKind, ContentParts, MarkerError, build_content, parse_content,
};
pub use tags::{HoldId, TagError, TagSet, is_opaque_hold_id, is_relay_pubkey};

/// Nostr kind of every marker card.
///
/// `kind:9` is already `Scope::MessagesWrite` in the relay's
/// `required_scope_for_kind` and already in `requires_h_channel_scope`
/// (`workspace/crates/ambush-relay/src/handlers/ingest.rs`), so the entire
/// evidence stream costs the relay nothing — and, because the relay itself
/// demands the `h` tag, the case compartment on a verdict card is *enforced*
/// rather than asserted.
pub const KIND_CARD: u16 = 9;

/// Nostr kind of the hold notice — the one stored kind the relay fork admits.
///
/// `KIND_WORKFLOW_APPROVAL_REQUESTED` in `workspace/crates/ambush-core/src/kind.rs`.
/// The fork is two match arms in `ingest.rs`; see
/// `docs/plans/ambush-ui/build/10-RELAY-FORK.md`, which owns it.
pub const KIND_HOLD_NOTICE: u16 = 46010;

/// `kind:26006` — the hold alarm, and the only frame in the block with `p` tags.
///
/// GLOBAL. It carries no `h` tag; its compartmenting is `P_GATED_KINDS` in
/// `workspace/crates/ambush-core/src/kind.rs` (`adr/0017` clause C3). See
/// [`crate::tags::TagError::ScopedHoldAlarm`].
pub const KIND_HOLD_ALARM: u16 = 26006;

/// First kind of the Perch ephemeral block.
pub const FRAME_KIND_MIN: u16 = 26000;
/// Last kind of the Perch ephemeral block.
pub const FRAME_KIND_MAX: u16 = 26006;

/// Whether `kind` is one of Perch's ephemeral frames.
///
/// The whole block sits inside the relay's ephemeral range (20000-29999,
/// `workspace/crates/ambush-core/src/kind.rs`), and `26000`-`26006` are unused
/// in-tree: the ephemeral kinds the relay actually ships are 20001, 20002,
/// 22242, 24134, 24200, 24242, 24243, 24810, 27235 and 28936.
#[must_use]
pub const fn is_perch_frame_kind(kind: u16) -> bool {
    kind >= FRAME_KIND_MIN && kind <= FRAME_KIND_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_frame_block_is_contiguous_and_closed() {
        assert!(is_perch_frame_kind(FRAME_KIND_MIN));
        assert!(is_perch_frame_kind(KIND_HOLD_ALARM));
        assert!(!is_perch_frame_kind(FRAME_KIND_MIN - 1));
        assert!(!is_perch_frame_kind(FRAME_KIND_MAX + 1));
        assert!(!is_perch_frame_kind(KIND_CARD));
        assert!(!is_perch_frame_kind(KIND_HOLD_NOTICE));
    }
}
