//! Case-channel provisioning, and the `hunt_id -> case_channel` routing table.
//!
//! # Two triggers, one creator, one sequence
//!
//! The settled case-promotion bar (`00-BRIEF.md` section 8.2) has three clauses: *a held
//! destructive action*, *a `CorrelatedIncident` with >= 2 included members*, or *manual
//! promotion*. ADR 0018 clause C4 ships all three as configuration with **only manual promotion
//! enabled in the first build** — which is the one clause that emits no
//! `RuntimeEvent::ResponseHeld`. An earlier draft of this module scoped channel creation to
//! `ResponseHeld` alone, and the consequence was that on the only enabled clause nothing created
//! the channel at all: `POST /v1/operator/incidents` requires `case_id` (it is in
//! `IncidentMintRequest`'s `required` list and is described as "The Perch case's channel UUID"),
//! and the console cannot create it either, because
//! `14-CLIENT-ARCHITECTURE.md`'s eleven Tauri commands contain no channel-create.
//!
//! So [`CaseRouting::ensure_case_channel`] is the ONE entry point, and it takes a
//! [`CasePromotionTrigger`]. Both triggers plan the same ordered, idempotent sequence.
//!
//! # Why the bridge, and not the console
//!
//! Not a preference — a membership fact. `create_channel_with_id`
//! (`BUZZ crates/buzz-db/src/store/channel.rs:171-263`, called in the relay process from
//! `ingest_event` when it stores a `kind:9007`) bootstraps **`created_by` and only `created_by`**
//! as `owner` in `channel_members`, inside the same transaction and only when `was_created`
//! (`channel.rs:224-242`). A console-created case channel therefore makes the *operator* the
//! owner and leaves the bridge a non-member — and a channel-scoped `46010` from a non-member is
//! rejected, because `46010` is not on `ingest.rs:2517-2522`'s six-kind `skip_membership` list and
//! `check_channel_membership` (`ingest.rs:742-772`, called at `:2533`) returns
//! `Err("restricted: not a channel member")` for a non-member of a channel whose `visibility` is
//! not `"open"`. Case channels are private by construction (ADR 0018 C7), so there is no
//! open-channel fallback. The creator must be the party that later publishes into it.
//!
//! `10-RELAY-FORK.md` section 9.3 already scopes INV-RF1 to the *bridge* and explicitly places
//! "creating a case channel (`kind:9007`), membership, reactions, ordinary `kind:9` chat in a
//! case" outside it, so a console-side create would not violate INV-RF1. It would violate the
//! membership fact above, which is the stronger constraint and the reason this module exists.

use uuid::Uuid;

use crate::error::BridgeError;

/// What caused a case to be promoted. Both arms plan the identical
/// [`PublishStep`] sequence; they differ only in who minted the `case_id`.
#[derive(Debug, Clone)]
pub enum CasePromotionTrigger {
    /// Clause 1 — a `RuntimeEvent::ResponseHeld` arrived and there is no case for its `hunt_id`
    /// yet. The bridge mints the UUID, because nothing upstream has one: `ResponseHeld`'s seven
    /// fields (`12-BACKEND-BILL-API.md`, bill item B1) carry `hunt_id` and `hold_id` and no case
    /// id.
    Held { hunt_id: String, hold_id: String },
    /// Clauses 2 and 3 — the daemon promoted a finding (by hand, or because a `CorrelatedIncident`
    /// crossed the configured member count) and told the bridge in a
    /// `RuntimeEvent::CasePromoted`. **PROPOSED as bill item B1d**; see
    /// `11-BRIDGE-CRATE.md` section 9.1. The `case_id` is supplied, not minted here.
    Promoted {
        hunt_id: String,
        case_id: Uuid,
        /// Which clause fired. Carried so the promoted/suppressed counter ADR 0018 C4 requires
        /// can be broken down without a second source.
        clause: PromotionClause,
    },
}

/// The three clauses of the promotion bar, as a closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionClause {
    /// A held destructive action. Reaches the bridge as [`CasePromotionTrigger::Held`].
    HeldAction,
    /// A `CorrelatedIncident` with at least the configured number of included members.
    CorrelatedIncident,
    /// An operator promoted a finding by hand. The only clause ADR 0018 C4 enables first.
    Manual,
}

/// One step in an ordered, idempotent provisioning sequence. A hold's four steps are ONE spool
/// record, so a crash between them replays the whole sequence rather than half of it.
#[derive(Debug, Clone)]
pub enum PublishStep {
    /// kind:9007, NIP-29 create-group, with a client-supplied UUID in the `h` tag.
    ///
    /// Requires `Scope::ChannelsWrite`
    /// (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:518`:
    /// `KIND_NIP29_CREATE_GROUP | KIND_CANVAS => Ok(Scope::ChannelsWrite)`).
    ///
    /// Idempotent: `create_channel_with_id`
    /// (`BUZZ crates/buzz-db/src/store/channel.rs:171-263`) is
    /// `INSERT ... ON CONFLICT (community_id, id) DO NOTHING`, and the relay answers
    /// `"duplicate: channel already exists"` with `accepted: false` (`ingest.rs:2879-2884`).
    /// [`crate::publish::ConnectionSupervisor::classify_ok`] treats that as success.
    ///
    /// Also bootstraps the creator as `owner` in `channel_members` INSIDE THE SAME TRANSACTION
    /// (`channel.rs:224-242`), so `perch-alarm` is a member the instant the channel exists and the
    /// membership precondition on a channel-scoped `46010` (`ingest.rs:2523-2552` ->
    /// `check_channel_membership` at `:742-772`; `46010` is not in the skip list at `:2517-2522`)
    /// is satisfied without a second event.
    CreateCaseChannel {
        channel: Uuid,
        name: String,
        /// Written into the `ttl` tag, read by `resolve_ttl`
        /// (`BUZZ crates/buzz-relay/src/handlers/mod.rs:46-66`) and stored as
        /// `ttl_deadline = NOW() + (ttl || ' seconds')::interval` (`channel.rs:206`).
        /// A relay-side `BUZZ_EPHEMERAL_TTL_OVERRIDE` REPLACES the value when set, but only when
        /// a `ttl` tag was present: the arm is `(Some(original), Some(ovr))` and the fall-through is
        /// `(ttl, _) => ttl` (`handlers/mod.rs:55-65`). Always set the tag.
        ///
        /// This closes one of the four things three or more plan documents rely on and none owns.
        ttl_seconds: i32,
    },
    /// kind:9000, NIP-29 put-user, one event per principal holding `OperatorScope::Approve`.
    ///
    /// Requires `Scope::AdminChannels` (`BUZZ ingest.rs:485-487`:
    /// `KIND_NIP29_PUT_USER | KIND_NIP29_REMOVE_USER | KIND_NIP29_DELETE_GROUP =>
    /// Ok(Scope::AdminChannels)`). Unconditional -- there is no channel-owner shortcut. The
    /// alternative, creating case channels `visibility = "open"`, removes the need for the scope
    /// and removes the compartment with it. The compartment is the point.
    AddOperator { channel: Uuid, operator_pubkey: String },
    /// kind:46010 + `swarm:hold:v1`, `h` = the case channel, `p` = each principal holding
    /// `OperatorScope::Approve`. Durable; this is the record.
    ///
    /// Only planned under [`CasePromotionTrigger::Held`]. A promotion that is not a hold creates
    /// the channel and stops; the case is empty until a card is published into it, which is
    /// correct — a promoted finding is not a held action.
    PublishHold { channel: Uuid, hold_id: HoldId },
    /// Ephemeral 26006. Carries `h` = the standing `#watch` ops channel AND one `p` per principal
    /// holding `OperatorScope::Approve`. The nudge, with no authority.
    ///
    /// Payload is exactly `{hold_id, action_kind, severity, case_channel, expires_at_ms}` and
    /// `hold_id` is an opaque token (see [`HoldId`]), never `hold:{hunt_id}:{held_at_ms}` --
    /// `hunt_id` is the telemetry event id
    /// (`AMBUSH crates/swarm-runtime/src/service/runtime_service.rs:391`), a join key into
    /// detection data.
    ///
    /// # Why both tags, and which one enforces
    ///
    /// The `h` tag is what actually closes the disclosure hole, and the `p` tag is what makes the
    /// frame useful and safe if it is ever read globally. Measured in `BUZZ` at `eed74bde2`:
    ///
    /// - `handle_ephemeral_event` (`handlers/event.rs:795-906`, the relay-process handler
    ///   `handle_event` calls at `:733-741` for any `is_ephemeral` kind) calls
    ///   `extract_channel_id(&event)` at `:850` and, when there is one, runs
    ///   `check_channel_membership` on the PUBLISHER at `:851-852` before publishing anything. So
    ///   `perch-alarm` must be a member of `#watch` or every alarm is answered `OK false`. That is
    ///   failure mode F19.
    /// - Delivery then goes through `fan_out_event_to_local_subscribers` with
    ///   `StoredEvent::new(event, Some(ch_id))` (`:873-874`), whose
    ///   `filter_fanout_by_access` (`:115-222`) returns early at `:195` for a non-private channel
    ///   but, for a private one, filters every recipient through
    ///   `is_member_cached(community_id, channel_id, &pubkey)` at `:205-221`. `#watch` MUST
    ///   therefore be `visibility: "private"`; an open `#watch` returns every match unfiltered and
    ///   the hole is exactly as wide as it was.
    /// - `P_GATED_KINDS` (`buzz-core/src/kind.rs:159-169`, six kinds today) is enforced in
    ///   exactly two places -- `req.rs:221` and `count.rs:44` -- and BOTH are inside
    ///   `if channel_id.is_none()` (`req.rs:219`, whose own comment reads "Only applies to GLOBAL
    ///   subscriptions"). A console subscribing `{kinds:[26006],"#h":[watch]}` resolves a channel
    ///   id through `extract_channel_id_from_filters` (`req.rs:1153-1180`) and never reaches the
    ///   gate. So adding `26006` to `P_GATED_KINDS` (ADR 0017) is NOT what protects the h-scoped
    ///   subscription; it protects only a global `{kinds:[26006]}` REQ, which it answers with
    ///   `CLOSED "restricted: p-gated events require #p matching your pubkey"` unless every `#p`
    ///   value equals the authenticated pubkey (`req.rs:1212-1214`).
    ///
    /// - The console side pays for the `h` tag too: a channel-scoped REQ filters its requested
    ///   channel ids against `accessible_channels` (`req.rs:189-195`, populated from
    ///   `state.db.is_member(...)` at `:155-177`) and answers
    ///   `CLOSED "restricted: not a channel member"` when nothing survives (`:200-208`). Every
    ///   operator console must be a member of `#watch`, and a console that is not gets a terminal
    ///   notice rather than a quiet queue.
    ///
    /// The two mechanisms are complementary, not destructive: `{kinds:[26006],"#h":[watch]}` and
    /// `{kinds:[26006],"#h":[watch],"#p":[me]}` both pass, and a bare `{kinds:[26006]}` is closed.
    ///
    /// The bridge does NOT create `#watch` -- it is standing configuration
    /// (`perch.watch_channel`), and the bridge cannot pre-flight its own membership because it
    /// holds no read path at all (zero `REQ`, test T-9). The first alarm is the test; a failure is
    /// [`BridgeError::WatchChannelMembership`], alarmed and never retried.
    ///
    /// See `11-BRIDGE-CRATE.md` section 8.6 for the full reconciliation.
    PublishAlarm { watch_channel: Uuid, hold_id: HoldId },
}

/// A daemon-minted, opaque hold identifier, checked at the publish seam.
///
/// The bridge NEVER mints one — B1's `HeldActionStore` does, and `12-BACKEND-BILL-API.md` records
/// it as "opaque (uuid)". The bridge's job is to refuse to publish anything that does not look
/// like one, because a `hold_id` reaches two places with different blast radii: the
/// channel-compartmented `46010` body, and the `26006` frame that every member of `#watch` sees.
/// A derived id (`hold:{hunt_id}:{held_at_ms}`) leaks the telemetry event id and the exact hold
/// instant to that wider audience.
///
/// Accepted shape, asserted in [`HoldId::parse`] before any event is built: a lowercase
/// hyphenated UUID, i.e. `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`. A
/// colon anywhere is a hard refusal, since that is the shape of the derived form the schemas warn
/// against. Failure is [`BridgeError::MalformedHoldId`] and no event is constructed — the same
/// discipline as the `p`-tag assert in [`crate::identity`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HoldId(String);

impl HoldId {
    /// # Errors
    ///
    /// [`BridgeError::MalformedHoldId`] when `raw` is not a lowercase hyphenated UUID.
    pub fn parse(raw: &str) -> Result<Self, BridgeError> {
        let _ = raw;
        todo!(
            "reject on length, on any ':', on any uppercase hex, and on a failed Uuid::parse_str"
        )
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `hunt_id -> case_channel`, and `receipt_id -> hunt_id`. Durable, in a sidecar beside the alarm
/// spool cursor.
///
/// # Why the entry outlives channel archival
///
/// `refresh_channel_ttl_after_event_insert` (`BUZZ schema/schema.sql:960-993`, fired by the
/// `events_refresh_channel_ttl` constraint trigger at `:995-998`) has an
/// `EXCEPTION WHEN OTHERS` arm that downgrades a failed refresh to `RAISE WARNING`
/// (`schema.sql:984-988`), so a case channel whose refresh silently fails keeps a stale
/// `ttl_deadline` and can archive under an open investigation. The daemon's case record, not the
/// channel row, answers "is this case open" -- so the routing entry is kept until the daemon says
/// the hold is decided, and channel archival is never read as case closure.
pub struct CaseRouting {
    _private: (),
}

impl CaseRouting {
    pub fn open(sidecar: &std::path::Path) -> Result<Self, BridgeError> {
        let _ = sidecar;
        todo!("load or create the hunt_id/receipt_id maps")
    }

    /// THE single entry point. Returns the case channel for this trigger's `hunt_id`, plus the
    /// steps that must be published for it to exist.
    ///
    /// The map is **single-valued and first-write-wins**. One `hunt_id` has one case channel for
    /// the life of the map, so:
    ///
    /// - [`CasePromotionTrigger::Held`] on a `hunt_id` already routed returns the existing channel
    ///   and an EMPTY step list (plus the caller's own `PublishHold`/`PublishAlarm`).
    /// - [`CasePromotionTrigger::Promoted`] whose `case_id` equals the routed one is a no-op.
    /// - [`CasePromotionTrigger::Promoted`] whose `case_id` DIFFERS from the routed one is
    ///   [`BridgeError::CaseChannelConflict`]. The bridge does not create a second channel for one
    ///   `hunt_id`, and it does not silently adopt the new id, because the daemon has by then
    ///   already minted an incident record pointing at the id it sent. It counts
    ///   `perch_bridge_case_channel_conflict_total` and logs at `error`. The console renders the
    ///   case it was sent to and finds no channel, which is failure mode F20 — visible, not blank.
    ///
    /// That conflict is reachable only if two parties mint case ids for one `hunt_id`. It disappears
    /// entirely if the daemon is the sole minter, which is the amendment
    /// `11-BRIDGE-CRATE.md` section 9.1 files against `12-BACKEND-BILL-API.md`.
    ///
    /// # Errors
    ///
    /// [`BridgeError::CaseChannelConflict`] as above; [`BridgeError::Spool`] if the sidecar write
    /// fails, because a routing entry that is not durable produces a second channel after a
    /// restart.
    pub fn ensure_case_channel(
        &mut self,
        trigger: &CasePromotionTrigger,
        operators: &[String],
        ttl_seconds: i32,
    ) -> Result<(Uuid, Vec<PublishStep>), BridgeError> {
        let _ = (trigger, operators, ttl_seconds);
        todo!(
            "lookup by hunt_id; Held => reuse or Uuid::new_v4; Promoted => reuse, adopt, or \
             CaseChannelConflict; then CreateCaseChannel + one AddOperator per operator"
        )
    }

    /// Recorded when a `RuntimeEvent::ResponseExecution` carries `receipt_id: Some(_)`
    /// (`AMBUSH crates/swarm-runtime/src/runtime_events.rs:263-275`). It is the only join from a
    /// `ContainmentLease.origin_receipt_id` back to a case.
    pub fn record_receipt(&mut self, receipt_id: &str, hunt_id: &str) {
        let _ = (receipt_id, hunt_id);
        todo!("insert into the receipt map and persist")
    }

    pub fn case_for_receipt(&self, receipt_id: &str) -> Option<Uuid> {
        let _ = receipt_id;
        todo!("receipt_id -> hunt_id -> case_channel")
    }
}
