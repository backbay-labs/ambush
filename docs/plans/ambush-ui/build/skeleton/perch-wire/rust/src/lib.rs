#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Wire types for the Perch operator console.
//!
//! ## Owns
//!
//! - The seven `ambush:*:v1` marker constants and the card-kind slug they encode.
//! - The three-part card content grammar (marker line, human line, fenced JSON)
//!   and the only parser for it.
//! - The `swarm.spine.envelope.v1` wrapper as Perch publishes it, including the
//!   rule that `signature` is absent until B6 and that its absence pins the card
//!   at verification tier 0.
//! - The narrowing from a `RuntimeEvent` to a card or a frame, and the record of
//!   what each narrowing deliberately drops.
//! - The tag builders, and the assertions that must pass before a card is signed.
//!
//! ## Does not own
//!
//! - Any authorization decision. Nothing in this crate grants, refuses, verifies
//!   a policy verdict or mints a capability lease. A `VerdictCard` is a record of a human
//!   intent; the daemon re-derives authority from scratch on a separate process
//!   boundary (`POST /v1/response/holds/{id}/decide`).
//! - Transport. No socket, no HTTP client, no Nostr signing. `swarm-perch-bridge`
//!   owns those; this crate hands it bytes.
//! - The domain types themselves. `DetectionFinding`, `AuditTrail`,
//!   `ContainmentLease`, `RollbackReceipt` and friends are re-exported from the
//!   crates that define them and are never redefined here. Where a wire type
//!   narrows a domain type, `narrowing.rs` says so at the narrowing site.
//! - Rendering. Nothing here produces a label, a badge or a colour.
//!
//! (The two headings above are RULE 5's exact required lines in
//! `tools/check-workspace-layering.sh:547-567`. This crate is not on the
//! `TRUST_SENSITIVE` list so the rule does not fire on it; carrying them anyway
//! costs two lines and means the crate can be added to that list later without a
//! second edit.)
//!
//! # The three-part content grammar
//!
//! Every `kind:9` marker card's `content` is exactly:
//!
//! ```text
//! <!-- ambush:finding:v1 -->
//! Whisker-7a3f · data_exfiltration · HIGH · confidence 0.82 · host web-04 · finding f2c9a1b4
//!
//! ```ambush:finding:v1
//! {"schema":"swarm.spine.envelope.v1", ...}
//! ```
//! ```
//!
//! Line 0 is the marker and nothing else, because `INV-15` requires the sniff to
//! fire only on an exact whole-first-line match. Line 1 is the human fallback and
//! is deliberately second rather than last: the desktop's search preview is
//! `buildSearchResultPreview(content, query, maxLength = 96)`
//! (`BUZZ desktop/src/features/search/lib/searchMatch.ts:169-200`), which slices
//! the first 96 characters when the query does not match, so anything after the
//! first ~70 characters of readable text is invisible in a search result. Putting
//! the JSON second, as `03` §3.2's sketch does, spends the whole preview on
//! `{"schema":"swarm.spine.envelope.v1","issuer":"swarm:ed25519:...`.
//!
//! The JSON is fenced rather than bare for the same reason `buzz-acp` fences its
//! own structured payload (`BUZZ crates/buzz-acp/src/setup_mode.rs:296`, which
//! emits ```` ```buzz:config-nudge ```` and is parsed by
//! `BUZZ desktop/src/shared/lib/configNudge.ts:94-114`): a fence is a contained
//! block in every markdown renderer, and an unfenced JSON line is a wall of text
//! in all of them.

/// Card body types, one per `ambush:*:v1` marker.
pub mod cards;
/// The `swarm.spine.envelope.v1` wrapper and its keyless hash.
pub mod envelope;
/// The `26000`-`26006` ephemeral frame bodies.
pub mod frames;
/// Marker constants, the card-kind slug, and the content grammar.
pub mod marker;
/// `RuntimeEvent` -> card / frame, with every deliberate narrowing named.
#[cfg(feature = "narrowing")]
pub mod narrowing;
/// Tag builders and the assertions that run before a card is signed.
pub mod tags;

pub use cards::{
    Card, EscalationBody, EscalationCause, FindingCard, HoldCard, Leg2Outcome, Leg2State,
    LeaseCard, ReceiptCard, RollbackCard, SourceCountMechanism, SourceIdsAbsentReason,
    VerdictCard,
};
pub use envelope::{
    CardEnvelope, EnvelopeError, FactIssuer, NeverARole, OperatorFactIssuer,
    ENVELOPE_SCHEMA_V1,
};
pub use frames::{Frame, FrameKind};
pub use marker::{CardKind, ContentParts, MarkerError, CARD_CONTENT_MAX_BYTES};
pub use tags::{is_opaque_hold_id, is_relay_pubkey, TagError, TagSet};

/// Nostr kind of every marker card.
///
/// `kind:9` is already `Scope::MessagesWrite` in `required_scope_for_kind`
/// (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:437-547`) and already in
/// `requires_h_channel_scope` (`:704-733`, the `KIND_STREAM_MESSAGE` arm at
/// `:707`), so the entire evidence stream costs the relay nothing — and, because
/// the relay itself demands the `h` tag, the case compartment on a verdict card
/// is *enforced* rather than asserted.
pub const KIND_CARD: u16 = 9;

/// Nostr kind of the hold notice — the one stored kind the relay fork admits.
///
/// `KIND_WORKFLOW_APPROVAL_REQUESTED` at
/// `BUZZ crates/buzz-core/src/kind.rs:578`. The fork is two match arms in
/// `ingest.rs`; see `docs/plans/ambush-ui/build/10-RELAY-FORK.md`, which owns it.
pub const KIND_HOLD_NOTICE: u16 = 46010;

/// First kind of the Perch ephemeral block.
/// `kind:26006` — the hold alarm, and the only frame in the block with `p` tags.
///
/// GLOBAL. It carries no `h` tag; its compartmenting is `P_GATED_KINDS` in
/// `BUZZ crates/buzz-core/src/kind.rs:159-169` (`adr/0017` clause C3). See
/// [`crate::tags::TagError::ScopedHoldAlarm`].
pub const KIND_HOLD_ALARM: u16 = 26006;

pub const FRAME_KIND_MIN: u16 = 26000;
/// Last kind of the Perch ephemeral block.
pub const FRAME_KIND_MAX: u16 = 26006;

/// Whether `kind` is one of Perch's ephemeral frames.
///
/// The whole block sits inside Buzz's ephemeral range (20000-29999,
/// `BUZZ crates/buzz-core/src/kind.rs:769-771`), and `26000`-`26006` are unused
/// in-tree: the ephemeral kinds Buzz actually ships are 20001, 20002, 22242,
/// 24134, 24200, 24242, 24243, 24810, 27235 and 28936.
#[must_use]
pub const fn is_perch_frame_kind(kind: u16) -> bool {
    kind >= FRAME_KIND_MIN && kind <= FRAME_KIND_MAX
}
