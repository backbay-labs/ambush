//! Tag builders, and the assertions that must pass before a card is signed.
//!
//! # The single-letter budget is closed
//!
//! `h` (channel, mandatory), `e`/`p` (NIP-10 + mentions), `t` (threat-class
//! slug), `l` (`Severity`, SCREAMING_SNAKE), `k` (card-kind slug), `d`
//! (addressable kinds, which Perch never publishes). Nothing else.
//!
//! # Pushdown, and its two binding consequences
//!
//! `filter_fully_pushable`
//! (`BUZZ crates/buzz-relay/src/handlers/req.rs:851-895`) runs in the relay
//! process and decides whether a filter can use the fast COUNT path. It pushes
//! `h` (whose complete authorized set the caller has already put through
//! `EventQuery::channel_id`/`channel_ids`), a SINGLE `p` (via the
//! `event_mentions` join — two or more return `false` at `:869-874`), `e` (any
//! count, via JSONB containment), and `d` ONLY when every kind in the filter is
//! NIP-33. Its default arm returns `false` for every other generic tag, naming
//! `#t` and `#a` explicitly. `EventQuery` has no generic tag field beyond
//! `custom_tag: Option<(String, String)>` — ONE pair
//! (`BUZZ crates/buzz-db/src/store/event.rs:81-83`).
//!
//! 1. **Paging depth must be sized for dilution.** A REQ of
//!    `{kinds:[9], #h:[case], #k:["receipt"]}` fetches a page of ALL `kind:9` in
//!    the case and drops non-matching rows afterwards; a `limit:200` on a busy
//!    case can return a handful of receipts. Where per-card-type selection
//!    matters, Perch fetches one page of `{kinds:[9], #h:[case]}` and partitions
//!    client-side on the parsed marker.
//! 2. **Such a filter disqualifies the fast COUNT path.** So does a NIP-50
//!    `search` filter (`req.rs:892-895`).
//!
//! `t`, `l` and `k` are DISPLAY AND POST-FILTER HINTS. No document may describe
//! them as indexed selection.
//!
//! # `kind:46010` carries FOUR tag names and no others
//!
//! `h`, one `p` per Approve-scoped principal, `hold`, `card`. No `e` (RF-D1),
//! no `t`, no `l`, no `k`. [`TagSet::assert_publishable`] has refused all four
//! since the first draft; what was missing was the same rule in the SCHEMA,
//! whose `items` was an open `array of string` while its description claimed
//! the set was closed — so a fixture carrying `t`/`l`/`k` validated silently
//! and three artifacts shipped three answers. The schema now enumerates the
//! four names in `items.prefixItems[0].enum`, and the peer demo fixture's two
//! 46010 files FAIL against it until those three tags are removed.
//!
//! The cost of the three was never zero: all are single-letter, so the relay
//! indexes each on insert, widening `APPENDIX-NORMATIVE.md` §3's closed index
//! budget; and all three land in `filter_fully_pushable`'s default arm
//! (`req.rs:885-890`), so a filter naming one is not pushed to SQL and loses
//! the fast COUNT path. Index cost, no query benefit.
//!
//! # `kind:26006` carries `p` tags and nothing else
//!
//! No `h`. See [`TagError::ScopedHoldAlarm`] for why an `h` tag would REOPEN
//! the disclosure it appears to close.
//!
//! # The permanent cost, named
//!
//! `strategy_id`, `host_id`, `receipt_id`, `lease_id` and `hunt_id` are reachable
//! through NIP-50 FTS only, never as a `#filter`. The events are signed and
//! cannot be re-tagged. FTS works on them because `search_tsv` is
//! `to_tsvector('simple', content)` and the privacy `CASE` at
//! `BUZZ schema/schema.sql:223-227` nulls it only for kinds
//! `{1059, 30179, 30300, 30350, 30622, 44100, 44101, 44200}` — neither `9` nor
//! `46010` is among them.

use crate::marker::CardKind;

/// A card's tag set, ready to sign.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TagSet {
    /// `h` — the channel UUID. Mandatory on every Perch event.
    pub h: Option<String>,
    /// `e` — NIP-10 threading. FORBIDDEN on `kind:46010` (RF-D1).
    pub e: Option<String>,
    /// `p` — mentions. Present ONLY on `kind:46010` and `kind:26006`.
    pub p: Vec<String>,
    /// `t` — threat-class slug, or `custom`.
    pub t: Option<String>,
    /// `l` — `Severity`, SCREAMING_SNAKE.
    pub l: Option<String>,
    /// `k` — card-kind slug.
    pub k: Option<String>,
    /// `broadcast` — `"1"` on a mode-transition-to-incident escalation card only.
    pub broadcast: bool,
    /// `hold` — the opaque hold id. `kind:46010` only.
    pub hold: Option<String>,
    /// `card` — the sibling card's Nostr event id. `kind:46010` only.
    pub card: Option<String>,
}

/// Why a tag set may not be signed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TagError {
    /// No `h` tag. After the fork the relay rejects an `h`-less 46010 with
    /// `"invalid: channel-scoped events must include an h tag"`
    /// (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:2460-2464`), and `kind:9`
    /// has always been in `requires_h_channel_scope` (`:707`).
    #[error("missing the mandatory h tag")]
    MissingChannel,
    /// A `p` value that is not exactly 64 lowercase hex characters.
    ///
    /// THE SILENT FAILURE THIS EXISTS TO PREVENT. `insert_mentions` filters any
    /// p-tag value that is not exactly 64 ASCII-hex with a `tracing::debug!`
    /// and lowercases the survivors
    /// (`BUZZ crates/buzz-db/src/runtime/mod.rs:65-81`), and it runs on a
    /// SEPARATE pool transaction AFTER `tx.commit()` with any failure downgraded
    /// to `tracing::warn!` (`:943-948`, identically at
    /// `BUZZ crates/buzz-db/src/store/event.rs:1690-1696`). So a malformed or
    /// uppercase pubkey produces a stored event, an `OK true` to the publisher,
    /// and NO row in `event_mentions` — which `query_needs_action` INNER JOINs
    /// (`BUZZ crates/buzz-db/src/store/feed.rs:183`). A republish is deduplicated
    /// by event id, so the hole is not self-healing. This assert is the only
    /// thing between a bad byte and a destructive action awaiting a human nobody
    /// showed it to.
    #[error("p tag `{0}` is not 64 lowercase hex characters")]
    MalformedPubkey(String),
    /// An `e` tag on a `kind:46010`.
    ///
    /// `requires_h_channel_scope` ALSO gates `resolve_nip10_thread_meta`
    /// (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:2987-2997`), so an
    /// `e`-tagged 46010 becomes a NIP-10 reply, mutates
    /// `reply_count`/`descendant_count` on its root inside the insert
    /// transaction, and emits a relay-signed `kind:39005` thread summary
    /// (`:3219-3226`). Binding decision RF-D1 in `10-RELAY-FORK.md` §4.2.
    #[error("kind:46010 may not carry an e tag (RF-D1)")]
    ThreadedHoldNotice,
    /// A `t`, `l` or `k` tag on a `kind:46010`. RF-D1 fixes its single-letter
    /// set at `{h, p}`.
    #[error("kind:46010 may not carry a `{0}` tag (RF-D1)")]
    ExtraNoticeTag(&'static str),
    /// A `p` tag on a card. `p` appears exactly twice in the whole registry:
    /// on `kind:46010` and on `kind:26006`.
    #[error("a kind:9 card may not carry a p tag")]
    CardMentions,
    /// A `kind:46010` with no `hold` tag.
    ///
    /// Layer 3 of the hold path reconciles each relay row against
    /// `GET /v1/response/holds`, and `INV-35` requires rendering a 46010 present
    /// on the relay and absent from the daemon as the forgery it is. Both need
    /// the hold id OFF THE EVENT. Without this assert a notice publishes fine,
    /// pages the operator, and reconciles against nothing.
    #[error("kind:46010 must carry a hold tag")]
    MissingHoldTag,
    /// A `kind:46010` with no `p` tag at all.
    ///
    /// `query_needs_action` INNER JOINs `event_mentions`
    /// (`BUZZ crates/buzz-db/src/store/feed.rs:183`), so a p-less notice is
    /// stored, acknowledged `OK true`, and delivered to NOBODY. Under `C3` the
    /// same is true of a p-less `26006`: `p_gated_filters_authorized` requires a
    /// `#p` on the reader's filter (`req.rs:1211-1213`), and a frame with no `p`
    /// tag matches no such filter.
    #[error("kind:{0} must carry at least one p tag or it reaches nobody")]
    NoRecipients(u16),
    /// A hold id that does not match `common.schema.json#/$defs/HoldId`.
    ///
    /// `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`: URL-safe because it is a path
    /// parameter on `POST /v1/response/holds/{hold_id}/decide`, and COLON-FREE so
    /// the forbidden `hold:{hunt_id}:{held_at_ms}` derived form cannot be
    /// published. `hunt_id` is the telemetry event id
    /// (`AMB crates/swarm-runtime/src/service/runtime_service.rs:391`), a join
    /// key into detection data, and it must not ride an event this wide.
    #[error("hold id `{0}` is not an opaque token matching ^[A-Za-z0-9][A-Za-z0-9_-]{{7,63}}$")]
    MalformedHoldId(String),
    /// An `h` tag on a `26006` hold alarm.
    ///
    /// `26006` is GLOBAL under `adr/0017` clause C3 and its compartmenting comes
    /// from `P_GATED_KINDS`, whose gate `p_gated_filters_authorized` runs ONLY
    /// for `channel_id.is_none()`
    /// (`BUZZ crates/buzz-relay/src/handlers/req.rs:218`, comment at `:215-217`).
    /// An `h` tag routes the frame through the channel index instead, where the
    /// gate is never consulted — reopening the disclosure inside the channel's
    /// membership — and it also delivers zero frames to the shipped client
    /// filter, which is global. Withdrawn amendment `W-1` is what this variant
    /// exists to make unpublishable.
    #[error("kind:26006 is global and may not carry an h tag (adr/0017 C3; W-1 withdrawn)")]
    ScopedHoldAlarm,
}

/// True iff `value` matches `common.schema.json#/$defs/HoldId`.
///
/// Deliberately hand-written rather than a `regex` dependency: this crate is
/// depended on by the bridge, which sits below the TCB, and the assert must be
/// readable at the call site by a reviewer who is not going to open a regex
/// engine's source.
#[must_use]
pub fn is_opaque_hold_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (8..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

/// True iff `value` is exactly 64 lowercase hex characters.
#[must_use]
pub fn is_relay_pubkey(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl TagSet {
    /// Tags for a `kind:9` marker card.
    #[must_use]
    pub fn card(
        kind: CardKind,
        channel: impl Into<String>,
        threat_class_slug: Option<String>,
        severity: Option<String>,
    ) -> Self {
        Self {
            h: Some(channel.into()),
            k: Some(kind.slug().to_string()),
            t: threat_class_slug,
            l: severity,
            ..Self::default()
        }
    }

    /// Tags for the `kind:46010` hold notice.
    ///
    /// `hold` and `card` are MULTI-LETTER and therefore outside RF-D1's scope by
    /// its own wording ("its only SINGLE-LETTER tags are `h` and `p`"). Neither
    /// is ever used in a filter — nothing selects a 46010 by tag; the desktop's
    /// needs-action query is
    /// `{"kinds":[46010,46011,46012],"#p":[me],"limit":20}`
    /// (`BUZZ desktop/src-tauri/src/commands/messages.rs:97-101`) — and both are
    /// read from an event the client already holds, because `FeedItemInfo`
    /// carries `tags` and `pubkey` across the Tauri boundary
    /// (`BUZZ desktop/src-tauri/src/models.rs:198-210`). It does NOT carry `sig`,
    /// so the client cannot re-verify the Nostr signature and relies on the
    /// relay's ingest check.
    #[must_use]
    pub fn hold_notice(
        channel: impl Into<String>,
        operators: Vec<String>,
        hold_id: impl Into<String>,
        card_event_id: Option<String>,
    ) -> Self {
        Self {
            h: Some(channel.into()),
            p: operators,
            hold: Some(hold_id.into()),
            card: card_event_id,
            ..Self::default()
        }
    }

    /// Tags for the `kind:26006` hold alarm: `p` tags and NOTHING ELSE.
    ///
    /// No `h`, deliberately — see [`TagError::ScopedHoldAlarm`]. Under
    /// `adr/0017` C3 the `p` tags are not a client-side paging hint; they are the
    /// relay's own authorization test, because `p_gated_filters_authorized`
    /// (`BUZZ crates/buzz-relay/src/handlers/req.rs:1182-1215`) refuses any
    /// global filter naming a `P_GATED_KINDS` member unless every `#p` value on
    /// that filter equals the reader's own pubkey.
    #[must_use]
    pub fn hold_alarm(operators: Vec<String>) -> Self {
        Self {
            p: operators,
            ..Self::default()
        }
    }

    /// Assert this tag set may be signed for `kind`.
    ///
    /// # Errors
    ///
    /// See [`TagError`]. Every variant is a silent failure at the relay if it is
    /// not caught here.
    pub fn assert_publishable(&self, kind: u16) -> Result<(), TagError> {
        // `h` is mandatory on the two STORED kinds and forbidden on the
        // ephemeral block. It is not a universal rule and never was; before C3
        // this function required it everywhere because no frame was built
        // through a TagSet.
        if kind == crate::KIND_HOLD_ALARM {
            if self.h.is_some() {
                return Err(TagError::ScopedHoldAlarm);
            }
        } else if self.h.is_none() {
            return Err(TagError::MissingChannel);
        }
        for pubkey in &self.p {
            if !is_relay_pubkey(pubkey) {
                return Err(TagError::MalformedPubkey(pubkey.clone()));
            }
        }
        if let Some(hold_id) = &self.hold {
            if !is_opaque_hold_id(hold_id) {
                return Err(TagError::MalformedHoldId(hold_id.clone()));
            }
        }
        match kind {
            crate::KIND_HOLD_NOTICE => {
                if self.e.is_some() {
                    return Err(TagError::ThreadedHoldNotice);
                }
                if self.t.is_some() {
                    return Err(TagError::ExtraNoticeTag("t"));
                }
                if self.l.is_some() {
                    return Err(TagError::ExtraNoticeTag("l"));
                }
                if self.k.is_some() {
                    return Err(TagError::ExtraNoticeTag("k"));
                }
                if self.hold.is_none() {
                    return Err(TagError::MissingHoldTag);
                }
                if self.p.is_empty() {
                    return Err(TagError::NoRecipients(kind));
                }
            }
            crate::KIND_HOLD_ALARM => {
                if self.p.is_empty() {
                    return Err(TagError::NoRecipients(kind));
                }
                for (name, present) in [
                    ("e", self.e.is_some()),
                    ("t", self.t.is_some()),
                    ("l", self.l.is_some()),
                    ("k", self.k.is_some()),
                ] {
                    if present {
                        return Err(TagError::ExtraNoticeTag(match name {
                            "e" => "e",
                            "t" => "t",
                            "l" => "l",
                            _ => "k",
                        }));
                    }
                }
            }
            crate::KIND_CARD => {
                if !self.p.is_empty() {
                    return Err(TagError::CardMentions);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Render as Nostr tags, in registry order.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Vec<String>> {
        let mut out = Vec::new();
        if let Some(h) = &self.h {
            out.push(vec!["h".into(), h.clone()]);
        }
        if let Some(e) = &self.e {
            out.push(vec!["e".into(), e.clone()]);
        }
        for p in &self.p {
            out.push(vec!["p".into(), p.clone()]);
        }
        if let Some(t) = &self.t {
            out.push(vec!["t".into(), t.clone()]);
        }
        if let Some(l) = &self.l {
            out.push(vec!["l".into(), l.clone()]);
        }
        if let Some(k) = &self.k {
            out.push(vec!["k".into(), k.clone()]);
        }
        if self.broadcast {
            out.push(vec!["broadcast".into(), "1".into()]);
        }
        if let Some(hold) = &self.hold {
            out.push(vec!["hold".into(), hold.clone()]);
        }
        if let Some(card) = &self.card {
            out.push(vec!["card".into(), card.clone()]);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";

    #[test]
    fn an_uppercase_pubkey_is_refused_before_signing() {
        let tags = TagSet::hold_notice("uuid", vec![PK.to_uppercase()], "h_1", None);
        assert!(matches!(
            tags.assert_publishable(crate::KIND_HOLD_NOTICE),
            Err(TagError::MalformedPubkey(_))
        ));
    }

    #[test]
    fn a_truncated_pubkey_is_refused_before_signing() {
        let tags = TagSet::hold_notice("uuid", vec![PK[..63].to_string()], "h_1", None);
        assert!(tags.assert_publishable(crate::KIND_HOLD_NOTICE).is_err());
    }

    #[test]
    fn rf_d1_forbids_an_e_tag_on_the_hold_notice() {
        let mut tags = TagSet::hold_notice("uuid", vec![PK.into()], "h_1", None);
        tags.e = Some("f".repeat(64));
        assert_eq!(
            tags.assert_publishable(crate::KIND_HOLD_NOTICE),
            Err(TagError::ThreadedHoldNotice)
        );
    }

    #[test]
    fn rf_d1_forbids_t_l_and_k_on_the_hold_notice() {
        // The Rust producer has always refused these. The SCHEMA did not until
        // this revision: its `items` was an open `array of string` while its
        // description claimed the set was closed, so the peer demo fixture's
        // two 46010 files carried t/l/k and validated silently. Both sides now
        // refuse, and this test is the Rust half of that pair.
        for mutate in [
            (|t: &mut TagSet| t.t = Some("execution".into())) as fn(&mut TagSet),
            |t: &mut TagSet| t.l = Some("CRITICAL".into()),
            |t: &mut TagSet| t.k = Some("hold".into()),
        ] {
            let mut tags = TagSet::hold_notice("uuid", vec![PK.into()], "h_a07aeacf", None);
            mutate(&mut tags);
            assert!(matches!(
                tags.assert_publishable(crate::KIND_HOLD_NOTICE),
                Err(TagError::ExtraNoticeTag(_))
            ));
        }
    }

    #[test]
    fn a_hold_notice_with_no_hold_tag_reconciles_against_nothing() {
        let mut tags = TagSet::hold_notice("uuid", vec![PK.into()], "h_a07aeacf", None);
        tags.hold = None;
        assert_eq!(
            tags.assert_publishable(crate::KIND_HOLD_NOTICE),
            Err(TagError::MissingHoldTag)
        );
    }

    #[test]
    fn a_hold_notice_with_no_p_tag_reaches_nobody() {
        let tags = TagSet::hold_notice("uuid", vec![], "h_a07aeacf", None);
        assert_eq!(
            tags.assert_publishable(crate::KIND_HOLD_NOTICE),
            Err(TagError::NoRecipients(crate::KIND_HOLD_NOTICE))
        );
    }

    #[test]
    fn a_colon_derived_hold_id_is_refused_before_signing() {
        // `hold:{hunt_id}:{held_at_ms}` is the forbidden derived form. Six
        // formats were in circulation across the wave-2 artifact set and two of
        // them used this prefix; the pattern is what makes it unpublishable
        // rather than merely discouraged.
        let tags = TagSet::hold_notice(
            "uuid",
            vec![PK.into()],
            "hold:hunt-evt-1:1773738882600",
            None,
        );
        assert!(matches!(
            tags.assert_publishable(crate::KIND_HOLD_NOTICE),
            Err(TagError::MalformedHoldId(_))
        ));
    }

    #[test]
    fn the_hold_id_pattern_admits_every_shipped_form_and_refuses_the_derived_one() {
        // The canonical demo fixture's form, a UUID (12-BACKEND-BILL-API's
        // commitment for B1), and a dashed form all pass; the two colon forms
        // and anything path-shaped do not.
        for good in [
            "h_a07aeacf",
            "27799e23-ab25-4659-b381-3de47ea7ca4d",
            "hold-9c1e77b204",
            "01K3QJ7ZV9M2R4TX8N6B0DWCA5",
        ] {
            assert!(is_opaque_hold_id(good), "{good} should be admitted");
        }
        for bad in [
            "hold:01K3QJ7ZV9M2R4TX8N6B0DWCA5",
            "hold:hunt-evt-1:1773738882600",
            "h_a07ae",
            "h/../../etc/passwd",
            "_leading",
        ] {
            assert!(!is_opaque_hold_id(bad), "{bad} should be refused");
        }
    }

    #[test]
    fn a_hold_alarm_may_not_carry_an_h_tag() {
        // Withdrawn amendment W-1 is what this test exists to make
        // unpublishable. The p-gate runs ONLY for channel_id.is_none()
        // (BUZZ crates/buzz-relay/src/handlers/req.rs:218), so an h-tagged 26006
        // is delivered through the channel index where the gate is never
        // consulted -- narrowing the disclosure ring to the ops channel's
        // membership rather than closing it -- and it delivers zero frames to
        // the shipped client's global filter.
        let mut tags = TagSet::hold_alarm(vec![PK.into()]);
        tags.h = Some("uuid".into());
        assert_eq!(
            tags.assert_publishable(crate::KIND_HOLD_ALARM),
            Err(TagError::ScopedHoldAlarm)
        );
    }

    #[test]
    fn a_hold_alarm_with_no_p_tag_matches_no_admitted_filter() {
        // Under C3 a reader's filter MUST carry #p=self
        // (req.rs:1211-1213), so a frame with no p tag matches nothing.
        let tags = TagSet::hold_alarm(vec![]);
        assert_eq!(
            tags.assert_publishable(crate::KIND_HOLD_ALARM),
            Err(TagError::NoRecipients(crate::KIND_HOLD_ALARM))
        );
    }

    #[test]
    fn a_well_formed_hold_alarm_publishes() {
        let tags = TagSet::hold_alarm(vec![PK.into()]);
        assert_eq!(tags.assert_publishable(crate::KIND_HOLD_ALARM), Ok(()));
        assert_eq!(tags.to_tags(), vec![vec!["p".to_string(), PK.to_string()]]);
    }

    #[test]
    fn a_card_never_carries_a_p_tag() {
        // p appears exactly twice in the registry: kind:46010 and kind:26006.
        // A p tag on a kind:9 card would also put the card in the desktop's
        // mentions queue and double-count the hold.
        let mut tags = TagSet::card(CardKind::Hold, "uuid", None, None);
        tags.p.push(PK.into());
        assert_eq!(
            tags.assert_publishable(crate::KIND_CARD),
            Err(TagError::CardMentions)
        );
    }

    #[test]
    fn every_event_carries_h() {
        let tags = TagSet::default();
        assert_eq!(
            tags.assert_publishable(crate::KIND_CARD),
            Err(TagError::MissingChannel)
        );
    }
}
