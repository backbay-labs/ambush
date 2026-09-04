//! Marker constants, the card-kind slug, and the three-part content grammar.
//!
//! The marker format is the chat client's, not an invention: the one
//! HTML-comment content marker it ships is
//! `WAVE_MESSAGE_MARKER = "<!-- buzz:wave:v1 -->"`
//! (`workspace/desktop/src/features/messages/lib/waveMessage.ts`), sniffed by
//! `parseWaveMessageContent` from the message body's `default:` arm in the
//! renderer process. Perch's markers are the same shape with `swarm` in place
//! of `buzz`, which is why they cost zero of the four client registration
//! points: `kind:9` is already registered at all four.
//!
//! Perch's sniff is HARDENED in two ways the wave sniff is not, both required by
//! `INV-15`:
//!
//! 1. The wave predicate is `content.trimStart().startsWith(MARKER)`, which
//!    fires on a marker anywhere at the start of the body including mid-line.
//!    Perch's requires the marker to be the ENTIRE first line.
//! 2. The wave sniff has no issuer check at all. Perch's fires only when the
//!    event's raw signer resolves to an admitted bridge identity. The shipped
//!    precedent for that predicate is `getConfigNudgeAuthorPubkey`
//!    (`workspace/desktop/src/features/messages/ui/configNudgeAuthPubkey.ts`),
//!    whose doc comment states the reason: it authenticates against
//!    `message.signerPubkey`, the raw event signer, and NOT `message.pubkey`,
//!    which may be a relay-delegated display author.
//!
//! The issuer check does not live in this crate — it needs the admitted-identity
//! set, which is client configuration. This module produces and parses the
//! grammar; `TagSet::assert_publishable` and the client's admission predicate are
//! the two gates around it.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The seven card kinds. The slug is the second marker segment AND the `k` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardKind {
    /// One `DetectionFinding`, in a lane channel.
    Finding,
    /// A concentration crossing, a mode transition into incident, or a
    /// fail-closed tamper alert. In a lane channel.
    Escalation,
    /// One held destructive action, in a case channel.
    Hold,
    /// One human decision — leg 1 of the two-legged write. In a case channel.
    Verdict,
    /// One `AuditTrail`, in a case channel.
    Receipt,
    /// One containment lease on open, in a case channel.
    Lease,
    /// One `RollbackReceipt`, in a case channel.
    Rollback,
}

impl CardKind {
    /// The slug: the second marker segment and the `k` tag value.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Escalation => "escalation",
            Self::Hold => "hold",
            Self::Verdict => "verdict",
            Self::Receipt => "receipt",
            Self::Lease => "lease",
            Self::Rollback => "rollback",
        }
    }

    /// The whole marker line, e.g. `<!-- swarm:finding:v1 -->`.
    #[must_use]
    pub const fn marker(self) -> &'static str {
        match self {
            Self::Finding => "<!-- swarm:finding:v1 -->",
            Self::Escalation => "<!-- swarm:escalation:v1 -->",
            Self::Hold => "<!-- swarm:hold:v1 -->",
            Self::Verdict => "<!-- swarm:verdict:v1 -->",
            Self::Receipt => "<!-- swarm:receipt:v1 -->",
            Self::Lease => "<!-- swarm:lease:v1 -->",
            Self::Rollback => "<!-- swarm:rollback:v1 -->",
        }
    }

    /// The fence info string, e.g. `swarm:finding:v1`.
    #[must_use]
    pub const fn fence_info(self) -> &'static str {
        match self {
            Self::Finding => "swarm:finding:v1",
            Self::Escalation => "swarm:escalation:v1",
            Self::Hold => "swarm:hold:v1",
            Self::Verdict => "swarm:verdict:v1",
            Self::Receipt => "swarm:receipt:v1",
            Self::Lease => "swarm:lease:v1",
            Self::Rollback => "swarm:rollback:v1",
        }
    }

    /// The `fact.schema` constant, e.g. `swarm.perch.finding.v1`.
    #[must_use]
    pub const fn fact_schema(self) -> &'static str {
        match self {
            Self::Finding => "swarm.perch.finding.v1",
            Self::Escalation => "swarm.perch.escalation.v1",
            Self::Hold => "swarm.perch.hold.v1",
            Self::Verdict => "swarm.perch.verdict.v1",
            Self::Receipt => "swarm.perch.receipt.v1",
            Self::Lease => "swarm.perch.lease.v1",
            Self::Rollback => "swarm.perch.rollback.v1",
        }
    }

    /// Route a whole `content` body by its first line alone, without parsing.
    ///
    /// This is the hot path: it runs once per timeline row per render pass in the
    /// client. It allocates nothing and never parses JSON.
    #[must_use]
    pub fn route(content: &str) -> Option<Self> {
        let first_line = content.split('\n').next()?.trim_end_matches('\r');
        Self::ALL
            .iter()
            .copied()
            .find(|kind| first_line == kind.marker())
    }

    /// Every variant, in registry order.
    pub const ALL: [Self; 7] = [
        Self::Finding,
        Self::Escalation,
        Self::Hold,
        Self::Verdict,
        Self::Receipt,
        Self::Lease,
        Self::Rollback,
    ];
}

impl fmt::Display for CardKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Ceiling on a serialized card body, in bytes.
///
/// The relay's hard cap is 256 KB (`MAX_EVENT_CONTENT_BYTES`,
/// `workspace/crates/ambush-relay/src/handlers/ingest.rs`, checked inside
/// `ingest_event` in the relay process after signature verification and before
/// scope resolution, rejecting with
/// `"invalid: content exceeds maximum size of 262144 bytes (got N)"`). Perch
/// stops at 192 KB — 75% — so the marker line, the human line, the fence and any
/// future field cannot push a card over a limit that is enforced AFTER signing,
/// where the only remedy is to re-sign.
///
/// PROPOSED. The 75% is a judgement, not a measurement. The only unbounded field
/// in the registry is the finding's `evidence` (a `serde_json::Value` built
/// from telemetry), which the bridge replaces with a byte count and a hash
/// (`FindingCard::evidence_truncated`) rather than a smaller blob.
pub const CARD_CONTENT_MAX_BYTES: usize = 192 * 1024;

/// The three parts of a card body, after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentParts<'a> {
    /// Which card this is, from the first line.
    pub kind: CardKind,
    /// The human fallback line. The degradation contract: this is what the
    /// Flutter app, an FTS snippet and `ambush --format compact messages thread`
    /// show, and it must carry the identifiers a human needs to go find the real
    /// thing.
    pub human_line: &'a str,
    /// The raw JSON between the fences. Not parsed here.
    pub json: &'a str,
}

/// Why a card body could not be parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MarkerError {
    /// The first line was not exactly one of the seven markers.
    #[error("first line is not a swarm marker")]
    NoMarker,
    /// There was no human fallback line, or it was empty.
    #[error("missing the human fallback line")]
    MissingHumanLine,
    /// The fence was absent, unterminated, or carried the wrong info string.
    #[error("missing or malformed `{0}` fence")]
    MalformedFence(&'static str),
    /// The body exceeded `CARD_CONTENT_MAX_BYTES`.
    #[error("card body is {found} bytes, over the {limit}-byte ceiling")]
    TooLarge {
        /// Actual size.
        found: usize,
        /// `CARD_CONTENT_MAX_BYTES`.
        limit: usize,
    },
}

/// Build a card body from its three parts.
///
/// # Errors
///
/// Returns `TooLarge` when the result would exceed [`CARD_CONTENT_MAX_BYTES`],
/// and `MissingHumanLine` when `human_line` is empty or contains a newline. A
/// newline in the human line would push the fence off its expected position and
/// silently break every degraded renderer's one-line contract.
pub fn build_content(kind: CardKind, human_line: &str, json: &str) -> Result<String, MarkerError> {
    let human_line = human_line.trim();
    if human_line.is_empty() || human_line.contains('\n') {
        return Err(MarkerError::MissingHumanLine);
    }
    let body = format!(
        "{}\n{}\n\n```{}\n{}\n```",
        kind.marker(),
        human_line,
        kind.fence_info(),
        json.trim()
    );
    if body.len() > CARD_CONTENT_MAX_BYTES {
        return Err(MarkerError::TooLarge {
            found: body.len(),
            limit: CARD_CONTENT_MAX_BYTES,
        });
    }
    Ok(body)
}

/// Parse a card body into its three parts.
///
/// Mirrors `parseCardContent` in the TypeScript module character for character;
/// `tests/golden.rs` and `golden.test.mjs` run the same vectors through both.
///
/// # Errors
///
/// See [`MarkerError`]. This function never panics and never allocates on the
/// failure path, because it runs in a render loop on adversary-adjacent content.
pub fn parse_content(content: &str) -> Result<ContentParts<'_>, MarkerError> {
    let kind = CardKind::route(content).ok_or(MarkerError::NoMarker)?;

    let rest = content
        .split_once('\n')
        .map(|(_, rest)| rest)
        .ok_or(MarkerError::MissingHumanLine)?;
    let (human_line, after_human) = rest.split_once('\n').unwrap_or((rest, ""));
    let human_line = human_line.trim();
    if human_line.is_empty() {
        return Err(MarkerError::MissingHumanLine);
    }

    let fence_open = format!("```{}\n", kind.fence_info());
    let open_at = after_human
        .find(&fence_open)
        .ok_or(MarkerError::MalformedFence("open"))?;
    let json_start = open_at + fence_open.len();
    let json_len = after_human[json_start..]
        .find("\n```")
        .ok_or(MarkerError::MalformedFence("close"))?;
    Ok(ContentParts {
        kind,
        human_line,
        json: after_human[json_start..json_start + json_len].trim(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn route_requires_the_marker_to_be_the_whole_first_line() {
        assert_eq!(
            CardKind::route("<!-- swarm:finding:v1 -->\nx\n\n```swarm:finding:v1\n{}\n```"),
            Some(CardKind::Finding)
        );
        // INV-15: a marker that merely PREFIXES the first line does not route.
        // The chat client's own parseWaveMessageContent would accept this one.
        assert_eq!(CardKind::route("<!-- swarm:finding:v1 --> and more"), None);
        assert_eq!(CardKind::route("  <!-- swarm:finding:v1 -->"), None);
        assert_eq!(CardKind::route("<!-- swarm:finding:v2 -->"), None);
        assert_eq!(CardKind::route("<!-- buzz:wave:v1 -->"), None);
    }

    #[test]
    fn a_v2_marker_falls_through_rather_than_mis_rendering() {
        // The version is in the MARKER, not only in the JSON, so a v1 renderer
        // meeting a v2 card routes to the prose fallback instead of parsing a
        // body it does not understand.
        assert!(parse_content("<!-- swarm:hold:v2 -->\nx\n").is_err());
    }

    #[test]
    fn round_trip() {
        let body = build_content(
            CardKind::Hold,
            "hold h_1 · isolate_host · HIGH",
            "{\"a\":1}",
        )
        .expect("builds");
        let parts = parse_content(&body).expect("parses");
        assert_eq!(parts.kind, CardKind::Hold);
        assert_eq!(parts.human_line, "hold h_1 · isolate_host · HIGH");
        assert_eq!(parts.json, "{\"a\":1}");
    }

    #[test]
    fn slugs_and_markers_agree() {
        for kind in CardKind::ALL {
            assert_eq!(kind.marker(), format!("<!-- swarm:{}:v1 -->", kind.slug()));
            assert_eq!(kind.fence_info(), format!("swarm:{}:v1", kind.slug()));
            assert_eq!(
                kind.fact_schema(),
                format!("swarm.perch.{}.v1", kind.slug())
            );
        }
    }

    #[test]
    fn the_registry_is_exactly_seven() {
        // An eighth marker needs the justification shape in 03 section 4.4 —
        // what an operator cannot reconstruct without it after the ephemeral has
        // decayed — and a written argument. This assertion is where that
        // conversation starts.
        assert_eq!(CardKind::ALL.len(), 7);
    }
}
