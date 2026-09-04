//! Case-channel provisioning, and the `hunt_id -> case_channel` routing table.
//!
//! # Two triggers, one creator, one sequence
//!
//! The settled case-promotion bar has three clauses: *a held destructive action*, *a
//! `CorrelatedIncident` with >= 2 included members*, or *manual promotion*. ADR 0018 clause C4
//! ships all three as configuration with **only manual promotion enabled in the first build** —
//! which is the one clause that emits no `RuntimeEvent::ResponseHeld`. An earlier draft scoped
//! channel creation to `ResponseHeld` alone, and the consequence was that on the only enabled
//! clause nothing created the channel at all: `POST /v1/operator/incidents` mints the `case_id`
//! and the console cannot create a channel either, because none of its Tauri commands can.
//!
//! So [`CaseRouting::ensure_case_channel`] is the ONE entry point, and it takes a
//! [`CasePromotionTrigger`]. Both triggers plan the same ordered, idempotent sequence.
//!
//! # Why the bridge, and not the console
//!
//! Not a preference — a membership fact. `create_channel_with_id` (called in the relay process
//! when it stores a `kind:9007`) bootstraps **`created_by` and only `created_by`** as `owner` in
//! `channel_members`, inside the same transaction and only when `was_created`. A console-created
//! case channel therefore makes the *operator* the owner and leaves the bridge a non-member — and
//! a channel-scoped `46010` from a non-member is rejected, because `46010` is not on the relay's
//! six-kind `skip_membership` list and `check_channel_membership` returns
//! `Err("restricted: not a channel member")` for a non-member of a channel whose `visibility` is
//! not `"open"`. Case channels are private by construction (ADR 0018 C7), so there is no
//! open-channel fallback. The creator must be the party that later publishes into it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use swarm_core::config::PerchBridgeConfig;
use swarm_runtime::runtime_events::CasePromotionClause;
use uuid::Uuid;

use crate::error::BridgeError;
use crate::identity::normalize_p_tag;
use crate::spool::cursor::write_atomic;

/// The relay kind that creates a NIP-29 group with a client-supplied UUID.
pub const KIND_CREATE_CHANNEL: u16 = 9007;
/// The relay kind that adds a member to a NIP-29 group.
pub const KIND_PUT_USER: u16 = 9000;

/// What caused a case to be promoted. Both arms plan the identical [`PublishStep`] sequence; they
/// differ only in who minted the `case_id`.
#[derive(Debug, Clone)]
pub enum CasePromotionTrigger {
    /// Clause 1 — a `RuntimeEvent::ResponseHeld` arrived and there is no case for its `hunt_id`
    /// yet. The bridge mints the UUID, because nothing upstream has one. Reached by The hold,
    /// not by this milestone.
    Held {
        /// The hunt the held action belongs to.
        hunt_id: String,
        /// The daemon-minted hold id.
        hold_id: String,
    },
    /// Clauses 2 and 3 — the daemon promoted a finding and told the bridge in a
    /// `RuntimeEvent::CasePromoted`. The `case_id` is supplied, not minted here (00-DECISIONS
    /// W3-14).
    Promoted {
        /// The hunt the promoted finding belongs to.
        hunt_id: String,
        /// The case channel UUID the daemon minted.
        case_id: Uuid,
        /// Which clause fired. Carried so the promoted/suppressed counter ADR 0018 C4 requires
        /// can be broken down without a second source.
        clause: PromotionClause,
    },
}

impl CasePromotionTrigger {
    /// The hunt this trigger routes.
    pub fn hunt_id(&self) -> &str {
        match self {
            Self::Held { hunt_id, .. } | Self::Promoted { hunt_id, .. } => hunt_id,
        }
    }
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

impl PromotionClause {
    /// The snake_case label the metric and the log carry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeldAction => "held_action",
            Self::CorrelatedIncident => "correlated_incident",
            Self::Manual => "manual",
        }
    }
}

impl From<CasePromotionClause> for PromotionClause {
    fn from(value: CasePromotionClause) -> Self {
        match value {
            CasePromotionClause::HeldAction => Self::HeldAction,
            CasePromotionClause::CorrelatedIncident => Self::CorrelatedIncident,
            CasePromotionClause::Manual => Self::Manual,
        }
    }
}

/// One step in an ordered, idempotent provisioning sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishStep {
    /// kind:9007, NIP-29 create-group, with a client-supplied UUID in the `h` tag.
    ///
    /// Requires `Scope::ChannelsWrite`. Idempotent: the relay's insert is
    /// `ON CONFLICT (community_id, id) DO NOTHING` and it answers
    /// `"duplicate: channel already exists"`, which
    /// [`crate::publish::ConnectionSupervisor::classify_ok`] treats as success.
    ///
    /// Also bootstraps the creator as `owner` in `channel_members` INSIDE THE SAME TRANSACTION,
    /// so the alarm identity is a member the instant the channel exists.
    CreateChannel {
        /// The channel UUID, which is also the `h` tag value.
        channel: Uuid,
        /// The `name` tag. The relay validates it at ingest.
        name: String,
        /// `"open"` for a lane, `"private"` for a case.
        visibility: &'static str,
        /// The `ttl` tag in seconds, or `None` for a channel that does not expire. A relay-side
        /// TTL override REPLACES the value but only when a `ttl` tag was present, so a case
        /// channel always sets one.
        ttl_seconds: Option<i32>,
    },
    /// kind:9000, NIP-29 put-user, one event per principal holding `OperatorScope::Approve`.
    ///
    /// Requires `Scope::AdminChannels`, unconditionally — there is no channel-owner shortcut. The
    /// alternative, creating case channels `visibility = "open"`, removes the need for the scope
    /// and removes the compartment with it. The compartment is the point.
    AddMember {
        /// The channel to add to.
        channel: Uuid,
        /// The member's Nostr pubkey, 64 lowercase hex.
        pubkey: String,
    },
    /// kind:9 `swarm:hold:v1` into the case channel. FIRST of the three hold steps, so the
    /// notice can point at the card it describes.
    ///
    /// `reply_to` is the open card's Nostr event id on a TERMINAL card, and `None` on the open
    /// one. A terminal card is a NIP-10 reply so a case timeline reads top to bottom without a
    /// join; that `e` tag is legal here and forbidden on the notice (RF-D1).
    PublishHoldCard {
        /// The case channel.
        channel: Uuid,
        /// The daemon-minted hold id.
        hold_id: HoldId,
        /// The open card's event id, on a terminal card only.
        reply_to: Option<String>,
    },
    /// kind:46010, the hold notice: `h` + one `p` per Approve principal + `hold` + `card`, and
    /// NEVER an `e` tag. SECOND, because `card_event_id` is the id the card step returned.
    PublishHoldNotice {
        /// The case channel.
        channel: Uuid,
        /// The daemon-minted hold id.
        hold_id: HoldId,
        /// The sibling card's Nostr event id, once the relay has returned one.
        card_event_id: Option<String>,
    },
    /// Ephemeral 26006, the hold alarm. GLOBAL: no `h` tag, one `p` per Approve principal
    /// (R-1). LAST, and the only step that bypasses the pacer.
    PublishAlarm {
        /// The daemon-minted hold id.
        hold_id: HoldId,
    },
}

impl PublishStep {
    /// The snake_case name a log line, a metric and a sequence assertion use.
    ///
    /// `create_channel` and `add_member` keep the generic names deliberately: the same two
    /// variants provision the twelve OPEN lane channels, where `create_case_channel` and
    /// `add_operator` would both be false.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CreateChannel { .. } => "create_channel",
            Self::AddMember { .. } => "add_member",
            Self::PublishHoldCard { .. } => "publish_hold_card",
            Self::PublishHoldNotice { .. } => "publish_hold_notice",
            Self::PublishAlarm { .. } => "publish_alarm",
        }
    }

    /// The channel this step writes into, or `None` for the global alarm frame.
    pub const fn channel(&self) -> Option<Uuid> {
        match self {
            Self::CreateChannel { channel, .. }
            | Self::AddMember { channel, .. }
            | Self::PublishHoldCard { channel, .. }
            | Self::PublishHoldNotice { channel, .. } => Some(*channel),
            Self::PublishAlarm { .. } => None,
        }
    }
}

/// A daemon-minted, opaque hold identifier, checked at the publish seam.
///
/// The bridge NEVER mints one. Its job is to refuse to publish anything that does not look like
/// one, because a `hold_id` reaches two places with different blast radii: the
/// channel-compartmented `46010` body, and the `26006` frame every operator sees. A derived id
/// (`hold:{hunt_id}:{held_at_ms}`) leaks the telemetry event id and the exact hold instant to that
/// wider audience.
///
/// The accepted shape is R-3's pattern as amended by 00-DECISIONS W3-15:
/// `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`. A colon anywhere is a hard refusal, since that is the shape
/// of the derived form. The hold milestone pins this again with its full boundary corpus.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HoldId(String);

impl HoldId {
    /// # Errors
    ///
    /// [`BridgeError::MalformedHoldId`] when `raw` is not an opaque token of the R-3 shape.
    pub fn parse(raw: &str) -> Result<Self, BridgeError> {
        if swarm_perch_wire::is_opaque_hold_id(raw) {
            return Ok(Self(raw.to_string()));
        }
        Err(BridgeError::MalformedHoldId {
            value: raw.to_string(),
        })
    }

    /// The token, verbatim.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `hunt_id -> case_channel`, and `receipt_id -> hunt_id`. Durable, in a sidecar beside the alarm
/// spool cursor.
///
/// # Why the entry outlives channel archival
///
/// The relay's `refresh_channel_ttl_after_event_insert` trigger has an `EXCEPTION WHEN OTHERS`
/// arm that downgrades a failed refresh to `RAISE WARNING`, so a case channel whose refresh
/// silently fails keeps a stale `ttl_deadline` and can archive under an open investigation. The
/// daemon's case record, not the channel row, answers "is this case open" — so the routing entry
/// is kept until the daemon says the hold is decided, and channel archival is never read as case
/// closure.
#[derive(Debug)]
pub struct CaseRouting {
    path: PathBuf,
    state: RoutingState,
}

/// The sidecar's on-disk shape.
///
/// Channel ids are held as strings, not `Uuid`: the workspace pins `uuid` with the `v4` feature
/// only, and widening a shared dependency's feature set for one sidecar would change the resolved
/// graph every crate in the workspace sees. Every read parses, and a value that no longer parses
/// is a routing miss rather than a panic.
#[derive(Debug, Default, Serialize, Deserialize)]
struct RoutingState {
    #[serde(default)]
    hunts: BTreeMap<String, String>,
    #[serde(default)]
    receipts: BTreeMap<String, String>,
    #[serde(default)]
    hold_cards: BTreeMap<String, HoldCardLedger>,
    /// Channels whose `CreateChannel` step the relay ACCEPTED.
    ///
    /// Distinct from `hunts`, which records only that a channel id was chosen. A hunt is routed
    /// the moment an id is minted, but the channel does not exist until the relay says so, and
    /// the two must not be conflated: `ensure_case_channel` used to return no steps for any
    /// routed hunt, so a refused create was retried into an empty step list, the caller's
    /// all-succeeded flag stayed true over zero steps, and the record was committed with the
    /// channel never created — leaving a daemon incident pointing at nothing.
    #[serde(default)]
    created_channels: BTreeSet<String>,
}

/// What has already been published for one hold, keyed by `hold_id`.
///
/// # Why the bridge keeps its own ledger rather than reading the daemon's state
///
/// The store record answers "has the NOTICE been accepted" (`created -> notified`) and nothing
/// else. It has no field for "the open card was accepted" and none for "the terminal card was
/// accepted", and the store trait this crate consumes has no method that could set one. Two
/// windows are open without this ledger:
///
/// 1. The relay accepts the `kind:9` open card, the process dies before the `46010`. The record
///    is still `created`, so a replay of the spooled `ResponseHeld` republishes the card under a
///    fresh `created_at` -- a NEW event id, because `created_at` is inside the Nostr signature --
///    and the case timeline carries the same hold twice.
/// 2. A terminal `ResponseHeld` is redelivered. Every terminal state is a legal `plan` input and
///    the record is already terminal, so nothing in the store distinguishes "publish it" from
///    "already published it".
///
/// Both are closed by writing the accepted event id here, `fsync`-durably, the instant the relay
/// OKs it -- which is also the id the notice's `card` tag needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct HoldCardLedger {
    /// The `swarm:hold:v1` OPEN card's Nostr event id, once accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    open: Option<String>,
    /// The TERMINAL card's Nostr event id, once accepted. Exactly one per hold, ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<String>,
    /// Whether the `kind:26006` alarm for this hold reached the relay.
    ///
    /// Ephemeral events leave no trace to reconcile against, and the store's `notice_event_id`
    /// answers a different question, so a deferred alarm would be indistinguishable from a sent
    /// one and "deferred, never dropped" would be a claim rather than a property.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    alarm: bool,
}

impl CaseRouting {
    /// Loads or creates the sidecar at `path`.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the file exists and cannot be read or parsed. A corrupt
    /// routing table is never silently reset: doing so would mint a second channel for an open
    /// investigation.
    pub fn open(path: &Path) -> Result<Self, BridgeError> {
        let state = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| BridgeError::SpoolIo {
                path: path.display().to_string(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => RoutingState::default(),
            Err(error) => {
                return Err(BridgeError::SpoolIo {
                    path: path.display().to_string(),
                    source: error,
                });
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            state,
        })
    }

    /// The case channel already routed for `hunt_id`.
    pub fn case_for_hunt(&self, hunt_id: &str) -> Option<Uuid> {
        Uuid::parse_str(self.state.hunts.get(hunt_id)?).ok()
    }

    /// THE single entry point. Returns the case channel for this trigger's `hunt_id`, plus the
    /// steps that must be published for it to exist.
    ///
    /// The map is **single-valued and first-write-wins**. One `hunt_id` has one case channel for
    /// the life of the map, so:
    ///
    /// - [`CasePromotionTrigger::Held`] on a routed hunt returns the existing channel and an
    ///   EMPTY step list.
    /// - [`CasePromotionTrigger::Promoted`] whose `case_id` equals the routed one is a no-op.
    /// - [`CasePromotionTrigger::Promoted`] whose `case_id` DIFFERS is
    ///   [`BridgeError::CaseChannelConflict`]. The bridge does not create a second channel for
    ///   one `hunt_id`, and it does not silently adopt the new id, because the daemon has by then
    ///   already minted an incident record pointing at the id it sent.
    ///
    /// # Errors
    ///
    /// [`BridgeError::CaseChannelConflict`] as above; [`BridgeError::SpoolIo`] when the sidecar
    /// write fails, because a routing entry that is not durable produces a second channel after a
    /// restart.
    pub fn ensure_case_channel(
        &mut self,
        trigger: &CasePromotionTrigger,
        operators: &[String],
        ttl_seconds: i32,
    ) -> Result<(Uuid, Vec<PublishStep>), BridgeError> {
        let hunt_id = trigger.hunt_id().to_string();
        let existing = self.case_for_hunt(&hunt_id);
        let channel = match (trigger, existing) {
            (_, Some(existing)) => {
                if let CasePromotionTrigger::Promoted { case_id, .. } = trigger
                    && *case_id != existing
                {
                    return Err(BridgeError::CaseChannelConflict {
                        hunt_id,
                        existing: existing.to_string(),
                        incoming: case_id.to_string(),
                    });
                }
                if self.state.created_channels.contains(&existing.to_string()) {
                    return Ok((existing, Vec::new()));
                }
                // Routed but never confirmed created: re-plan the steps. Both are idempotent
                // (the relay answers a duplicate 9007 with `duplicate: channel already exists`,
                // which the publisher treats as success), so replanning is safe and skipping it
                // is not.
                return Ok((
                    existing,
                    self.case_channel_steps(existing, operators, ttl_seconds),
                ));
            }
            (CasePromotionTrigger::Held { .. }, None) => Uuid::new_v4(),
            (CasePromotionTrigger::Promoted { case_id, .. }, None) => *case_id,
        };

        self.state.hunts.insert(hunt_id, channel.to_string());
        self.persist()?;

        Ok((
            channel,
            self.case_channel_steps(channel, operators, ttl_seconds),
        ))
    }

    /// The steps that make one case channel exist: create it, then admit each operator.
    ///
    /// Both are idempotent at the relay, so replanning them for a routed-but-unconfirmed channel
    /// is safe.
    fn case_channel_steps(
        &self,
        channel: Uuid,
        operators: &[String],
        ttl_seconds: i32,
    ) -> Vec<PublishStep> {
        let mut steps = Vec::with_capacity(1 + operators.len());
        steps.push(PublishStep::CreateChannel {
            channel,
            name: case_channel_name(channel),
            visibility: "private",
            ttl_seconds: Some(ttl_seconds),
        });
        for pubkey in operators {
            steps.push(PublishStep::AddMember {
                channel,
                pubkey: pubkey.clone(),
            });
        }
        steps
    }

    /// Recorded when a `RuntimeEvent::ResponseExecution` carries `receipt_id: Some(_)`. It is the
    /// only join from a `ContainmentLease.origin_receipt_id` back to a case.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the sidecar cannot be written.
    pub fn record_receipt(&mut self, receipt_id: &str, hunt_id: &str) -> Result<(), BridgeError> {
        self.state
            .receipts
            .insert(receipt_id.to_string(), hunt_id.to_string());
        self.persist()
    }

    /// `receipt_id -> hunt_id -> case_channel`.
    pub fn case_for_receipt(&self, receipt_id: &str) -> Option<Uuid> {
        let hunt_id = self.state.receipts.get(receipt_id)?.clone();
        self.case_for_hunt(&hunt_id)
    }

    /// Whether the relay has ACCEPTED the `kind:9007` for `channel`.
    ///
    /// [`CaseRouting::ensure_case_channel`] writes its routing entry before anything is
    /// published and returns no steps on a second call, so a refused `9007` would otherwise
    /// never be retried: the hunt is routed, the create is never re-planned, and the next step
    /// publishes a card into a channel that does not exist. This set is the separate question
    /// "did the create land", and only an `OK` writes it.
    pub fn channel_is_created(&self, channel: Uuid) -> bool {
        self.state.created_channels.contains(&channel.to_string())
    }

    /// Records a `kind:9007` the relay accepted. `duplicate: channel already exists` is an
    /// acceptance (F14), so a channel another daemon created is recorded here too.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the sidecar write fails.
    pub fn record_channel_created(&mut self, channel: Uuid) -> Result<(), BridgeError> {
        if !self.state.created_channels.insert(channel.to_string()) {
            return Ok(());
        }
        self.persist()
    }

    /// Whether the `26006` alarm for this hold has reached the relay.
    pub fn alarm_published_for_hold(&self, hold_id: &str) -> bool {
        self.state
            .hold_cards
            .get(hold_id)
            .is_some_and(|ledger| ledger.alarm)
    }

    /// Records the `26006` the relay accepted, so a deferred alarm is re-planned and a sent one
    /// is not.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the sidecar write fails.
    pub fn record_alarm_published(&mut self, hold_id: &str) -> Result<(), BridgeError> {
        let entry = self
            .state
            .hold_cards
            .entry(hold_id.to_string())
            .or_default();
        if entry.alarm {
            return Ok(());
        }
        entry.alarm = true;
        self.persist()
    }

    /// The OPEN `swarm:hold:v1` card's event id, when the relay has already accepted one.
    ///
    /// Also the value the `46010`'s `card` tag carries.
    pub fn open_card_for_hold(&self, hold_id: &str) -> Option<&str> {
        self.state.hold_cards.get(hold_id)?.open.as_deref()
    }

    /// The TERMINAL card's event id, when one has already been accepted. `Some` means the hold's
    /// terminal card is published and MUST NOT be published again.
    pub fn terminal_card_for_hold(&self, hold_id: &str) -> Option<&str> {
        self.state.hold_cards.get(hold_id)?.terminal.as_deref()
    }

    /// Records the OPEN card the relay accepted. Idempotent: the first id wins, because the
    /// second call can only be a replay of a card the relay deduplicated.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the sidecar write fails. The caller must treat that as a
    /// publish failure: an unrecorded card id is the one that produces a duplicate on restart.
    pub fn record_open_card(&mut self, hold_id: &str, event_id: &str) -> Result<(), BridgeError> {
        let entry = self
            .state
            .hold_cards
            .entry(hold_id.to_string())
            .or_default();
        if entry.open.is_some() {
            return Ok(());
        }
        entry.open = Some(event_id.to_string());
        self.persist()
    }

    /// Records the TERMINAL card the relay accepted. Idempotent for the same reason.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the sidecar write fails.
    pub fn record_terminal_card(
        &mut self,
        hold_id: &str,
        event_id: &str,
    ) -> Result<(), BridgeError> {
        let entry = self
            .state
            .hold_cards
            .entry(hold_id.to_string())
            .or_default();
        if entry.terminal.is_some() {
            return Ok(());
        }
        entry.terminal = Some(event_id.to_string());
        self.persist()
    }

    fn persist(&self) -> Result<(), BridgeError> {
        let bytes =
            serde_json::to_vec_pretty(&self.state).map_err(|error| BridgeError::SpoolIo {
                path: self.path.display().to_string(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
            })?;
        write_atomic(&self.path, &bytes)
    }
}

/// `case-{first 8 of the uuid}`.
pub fn case_channel_name(channel: Uuid) -> String {
    let text = channel.to_string();
    format!("case-{}", &text[..8])
}

/// The twelve standing lane channels, open, with no TTL, plus one membership step per operator.
///
/// Idempotent by construction: a duplicate `kind:9007` is answered
/// `"duplicate: channel already exists"`, which the OK classifier treats as success. Decision
/// D-FC-5 makes the bridge the creator, so the dev provisioning script mints no lanes.
pub fn lane_channel_steps(config: &PerchBridgeConfig, operators: &[String]) -> Vec<PublishStep> {
    let mut steps = Vec::new();
    for (slug, value) in &config.lane_channels {
        let Ok(channel) = Uuid::parse_str(value) else {
            tracing::error!(
                module = module_path!(),
                slug = %slug,
                value = %value,
                "perch.lane_channels holds a value that is not a UUID; skipping that lane"
            );
            continue;
        };
        steps.push(PublishStep::CreateChannel {
            channel,
            name: format!("lane-{}", slug.replace('_', "-")),
            visibility: "open",
            ttl_seconds: None,
        });
        for pubkey in operators {
            steps.push(PublishStep::AddMember {
                channel,
                pubkey: pubkey.clone(),
            });
        }
    }
    steps
}

/// Signs one provisioning step into the relay event it is.
///
/// # Errors
///
/// [`BridgeError::MalformedPTag`] when a member pubkey is not 64 hex characters;
/// [`BridgeError::Encode`] when a tag or the signature is refused; and
/// [`BridgeError::InvalidConfig`] for a step this function does not build (the two hold steps,
/// which The hold milestone owns).
pub fn step_to_event(
    step: &PublishStep,
    keys: &nostr::Keys,
    created_at_secs: u64,
) -> Result<nostr::Event, BridgeError> {
    let (kind, tags) = match step {
        PublishStep::CreateChannel {
            channel,
            name,
            visibility,
            ttl_seconds,
        } => {
            let mut tags = vec![
                vec!["h".to_string(), channel.to_string()],
                vec!["name".to_string(), name.clone()],
                vec!["visibility".to_string(), (*visibility).to_string()],
                vec!["channel_type".to_string(), "stream".to_string()],
            ];
            if let Some(ttl) = ttl_seconds {
                tags.push(vec!["ttl".to_string(), ttl.to_string()]);
            }
            (KIND_CREATE_CHANNEL, tags)
        }
        PublishStep::AddMember { channel, pubkey } => (
            KIND_PUT_USER,
            vec![
                vec!["h".to_string(), channel.to_string()],
                vec!["p".to_string(), normalize_p_tag(pubkey)?],
            ],
        ),
        // The three hold steps carry a BODY, not just tags: the card is a sealed spine
        // envelope over the store record, the notice repeats that card's human line, and the
        // alarm is a `26006` frame. `crate::holds` builds all three, because each needs the
        // hold record, the issuer's envelope chain and the Approve set -- none of which a
        // tag-only builder can see.
        PublishStep::PublishHoldCard { .. }
        | PublishStep::PublishHoldNotice { .. }
        | PublishStep::PublishAlarm { .. } => {
            return Err(BridgeError::InvalidConfig {
                reason: format!(
                    "step `{}` carries a body; build it through crate::holds, not step_to_event",
                    step.label()
                ),
            });
        }
    };

    let parsed: Vec<nostr::Tag> = tags
        .into_iter()
        .map(nostr::Tag::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| BridgeError::Encode(error.to_string()))?;
    nostr::EventBuilder::new(nostr::Kind::Custom(kind), "")
        .tags(parsed)
        .custom_created_at(nostr::Timestamp::from(created_at_secs))
        .sign_with_keys(keys)
        .map_err(|error| BridgeError::Encode(error.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn twelve_lane_config() -> PerchBridgeConfig {
        let mut config = PerchBridgeConfig::default();
        for (index, slug) in swarm_core::config::STANDARD_THREAT_CLASS_SLUGS
            .iter()
            .enumerate()
        {
            config.lane_channels.insert(
                (*slug).to_string(),
                format!("00000000-0000-4000-8000-{:012x}", index + 1),
            );
        }
        config
    }

    #[test]
    fn a_manual_promotion_plans_create_plus_one_add_per_operator_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut routing = CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let case = uuid::Uuid::parse_str("9499a6e2-8872-453b-80d9-dafc6fc7fc69").unwrap();
        let trigger = CasePromotionTrigger::Promoted {
            hunt_id: "hunt-evt-1".into(),
            case_id: case,
            clause: PromotionClause::Manual,
        };
        let ops = vec!["a".repeat(64), "b".repeat(64)];
        let (channel, steps) = routing
            .ensure_case_channel(&trigger, &ops, 2_592_000)
            .unwrap();
        assert_eq!(channel, case);
        assert!(
            matches!(
                &steps[0],
                PublishStep::CreateChannel {
                    channel,
                    name,
                    visibility: "private",
                    ttl_seconds: Some(2_592_000)
                } if *channel == case && name == "case-9499a6e2"
            ),
            "{:?}",
            steps[0]
        );
        assert_eq!(steps.len(), 3);
        // Replay BEFORE the relay accepted the create: the steps must come back, because the
        // channel is routed but does not exist yet.
        assert_eq!(
            routing
                .ensure_case_channel(&trigger, &ops, 1)
                .unwrap()
                .1
                .len(),
            3,
            "a routed-but-unconfirmed channel must replan its steps, not return none"
        );
        // Replay AFTER acceptance: no steps.
        routing.record_channel_created(case).unwrap();
        assert!(
            routing
                .ensure_case_channel(&trigger, &ops, 1)
                .unwrap()
                .1
                .is_empty()
        );
        let other = CasePromotionTrigger::Promoted {
            hunt_id: "hunt-evt-1".into(),
            case_id: uuid::Uuid::new_v4(),
            clause: PromotionClause::Manual,
        };
        assert!(matches!(
            routing.ensure_case_channel(&other, &ops, 1),
            Err(BridgeError::CaseChannelConflict { .. })
        ));
        // Durable across reopen.
        let reopened = CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        assert_eq!(reopened.case_for_hunt("hunt-evt-1"), Some(case));
    }

    #[test]
    fn a_held_trigger_mints_its_own_uuid_and_joins_the_same_map() {
        let dir = tempfile::tempdir().unwrap();
        let mut routing = CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let trigger = CasePromotionTrigger::Held {
            hunt_id: "hunt-2".into(),
            hold_id: "27799e23-ab25-4659-b381-3de47ea7ca4d".into(),
        };
        let (channel, steps) = routing.ensure_case_channel(&trigger, &[], 60).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(routing.case_for_hunt("hunt-2"), Some(channel));
        // A later promotion naming the same channel is a no-op, not a conflict -- but only once
        // the relay has accepted the create. Before that the steps must come back, or a refused
        // create would be retried into an empty list and committed as a success.
        let promoted = CasePromotionTrigger::Promoted {
            hunt_id: "hunt-2".into(),
            case_id: channel,
            clause: PromotionClause::HeldAction,
        };
        assert_eq!(
            routing
                .ensure_case_channel(&promoted, &[], 60)
                .unwrap()
                .1
                .len(),
            1,
            "unconfirmed: the create must still be planned"
        );
        routing.record_channel_created(channel).unwrap();
        assert!(
            routing
                .ensure_case_channel(&promoted, &[], 60)
                .unwrap()
                .1
                .is_empty()
        );
    }

    /// A refused `9007` must not be committed as a success.
    ///
    /// `ensure_case_channel` recorded the hunt before anything was published and then returned
    /// no steps for any routed hunt. The alarm loop iterates the steps and commits when none
    /// failed, so a retry after a refused create iterated an EMPTY list, kept its
    /// all-succeeded flag, and committed — leaving a daemon incident record pointing at a
    /// channel the relay never created, with no further retry.
    #[test]
    fn a_refused_create_replans_its_steps_instead_of_committing_silently() {
        let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let mut routing = CaseRouting::open(&dir.path().join("routing.json"))
            .unwrap_or_else(|error| panic!("open: {error}"));
        let case = Uuid::new_v4();
        let trigger = CasePromotionTrigger::Promoted {
            hunt_id: "hunt-refused".into(),
            case_id: case,
            clause: PromotionClause::Manual,
        };
        let ops = vec!["a".repeat(64)];

        let (_, first) = routing
            .ensure_case_channel(&trigger, &ops, 60)
            .unwrap_or_else(|error| panic!("first: {error}"));
        assert_eq!(first.len(), 2, "create + one operator");

        // The publish is refused, so nothing marks the channel created. Every later tick must
        // still offer the work.
        for attempt in 0..3 {
            let (_, retry) = routing
                .ensure_case_channel(&trigger, &ops, 60)
                .unwrap_or_else(|error| panic!("retry {attempt}: {error}"));
            assert_eq!(
                retry.len(),
                2,
                "attempt {attempt}: a channel the relay never accepted must be replanned"
            );
        }

        // A sidecar reopen must not lose that distinction either.
        drop(routing);
        let mut reopened = CaseRouting::open(&dir.path().join("routing.json"))
            .unwrap_or_else(|error| panic!("reopen: {error}"));
        assert_eq!(
            reopened
                .ensure_case_channel(&trigger, &ops, 60)
                .unwrap()
                .1
                .len(),
            2,
            "the unconfirmed channel must survive a restart as unconfirmed"
        );

        reopened
            .record_channel_created(case)
            .unwrap_or_else(|error| panic!("mark: {error}"));
        assert!(
            reopened
                .ensure_case_channel(&trigger, &ops, 60)
                .unwrap()
                .1
                .is_empty(),
            "once the relay accepted it, replanning must stop"
        );
    }

    #[test]
    fn lane_steps_cover_all_twelve_lanes_open_with_no_ttl() {
        let config = twelve_lane_config();
        let steps = lane_channel_steps(&config, &["c".repeat(64)]);
        let creates = steps
            .iter()
            .filter(|step| {
                matches!(
                    step,
                    PublishStep::CreateChannel {
                        visibility: "open",
                        ttl_seconds: None,
                        ..
                    }
                )
            })
            .count();
        let adds = steps
            .iter()
            .filter(|step| matches!(step, PublishStep::AddMember { .. }))
            .count();
        assert_eq!((creates, adds), (12, 12));
        assert!(steps.iter().any(|step| matches!(
            step,
            PublishStep::CreateChannel { name, .. } if name == "lane-lateral-movement"
        )));
    }

    #[test]
    fn steps_become_the_relay_events_the_sdk_would_build() {
        let keys = nostr::Keys::generate();
        let case = uuid::Uuid::nil();
        let create = step_to_event(
            &PublishStep::CreateChannel {
                channel: case,
                name: "case-00000000".into(),
                visibility: "private",
                ttl_seconds: Some(60),
            },
            &keys,
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(create.kind.as_u16(), 9007);
        let tags: Vec<Vec<String>> = create.tags.iter().map(|t| t.clone().to_vec()).collect();
        assert_eq!(
            tags,
            vec![
                vec!["h".to_string(), case.to_string()],
                vec!["name".to_string(), "case-00000000".to_string()],
                vec!["visibility".to_string(), "private".to_string()],
                vec!["channel_type".to_string(), "stream".to_string()],
                vec!["ttl".to_string(), "60".to_string()],
            ]
        );
        let add = step_to_event(
            &PublishStep::AddMember {
                channel: case,
                pubkey: "A".repeat(64),
            },
            &keys,
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(add.kind.as_u16(), 9000);
        assert_eq!(
            add.tags.iter().nth(1).map(|t| t.clone().to_vec()),
            Some(vec!["p".to_string(), "a".repeat(64)])
        );
        // A lane carries no `ttl` tag at all: an absent tag is what "does not expire" means, and
        // a relay-side override only replaces a tag that was present.
        let lane = step_to_event(
            &PublishStep::CreateChannel {
                channel: case,
                name: "lane-impact".into(),
                visibility: "open",
                ttl_seconds: None,
            },
            &keys,
            1_700_000_000,
        )
        .unwrap();
        assert!(
            !lane
                .tags
                .iter()
                .any(|tag| tag.clone().to_vec().first().map(String::as_str) == Some("ttl"))
        );
        // A malformed member pubkey never becomes an event.
        assert!(matches!(
            step_to_event(
                &PublishStep::AddMember {
                    channel: case,
                    pubkey: "nope".into()
                },
                &keys,
                1
            ),
            Err(BridgeError::MalformedPTag { .. })
        ));
    }

    #[test]
    fn hold_id_shape_is_asserted_to_the_r3_pattern() {
        // R-3 as amended by 00-DECISIONS W3-15: `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`. The daemon
        // mints `hold_` + a lowercase v4 UUID (41 characters), which is inside it.
        for ok in [
            "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13",
            "h_a07aeacf",
            "abcdefgh",
            &swarm_runtime::held_action::mint_hold_id(),
            &"a".repeat(64),
        ] {
            assert!(HoldId::parse(ok).is_ok(), "{ok} should be admitted");
        }
        for bad in [
            "hold:01K3QJ7ZV9M2R4TX8N6B0DWCA5",
            "hold:hunt-evt-1:1773739200000",
            "short",
            "",
            "_x1234567",
            "-x1234567",
            "h/../../etc/passwd",
            "has space",
            &"a".repeat(65),
        ] {
            assert!(
                matches!(HoldId::parse(bad), Err(BridgeError::MalformedHoldId { .. })),
                "{bad:?} should be refused"
            );
        }
        // The bridge's gate and the wire crate's gate are ONE predicate, not two that agree
        // today: a second copy is how the frame and the notice end up disagreeing about a
        // colon.
        for candidate in ["h_a07aeacf", "hold:x:1", "_leading", &"z".repeat(64)] {
            assert_eq!(
                HoldId::parse(candidate).is_ok(),
                swarm_perch_wire::is_opaque_hold_id(candidate),
                "{candidate:?}"
            );
        }
    }

    #[test]
    fn a_held_trigger_on_an_unrouted_hunt_plans_create_then_operators_and_mints_the_case() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routing.json");
        let mut routing = CaseRouting::open(&path).unwrap();
        let trigger = CasePromotionTrigger::Held {
            hunt_id: "hunt-evt-1".into(),
            hold_id: "h_a07aeacf".into(),
        };
        let operators = vec!["68".repeat(32), "69".repeat(32)];
        let (case, steps) = routing
            .ensure_case_channel(&trigger, &operators, 2_592_000)
            .unwrap();
        assert!(
            matches!(
                steps[0],
                PublishStep::CreateChannel {
                    channel,
                    visibility: "private",
                    ttl_seconds: Some(2_592_000),
                    ..
                } if channel == case
            ),
            "{:?}",
            steps[0]
        );
        assert_eq!(
            steps
                .iter()
                .filter(|s| matches!(s, PublishStep::AddMember { .. }))
                .count(),
            2
        );
        assert_eq!(
            steps.len(),
            3,
            "the caller appends PublishHoldCard/PublishHoldNotice/PublishAlarm itself"
        );
        // Routed is NOT created. Until the relay accepts the create, the same hunt
        // must re-emit the plan: a refused create that returned an empty step list
        // let the caller's all-succeeded flag stand over zero steps and commit a
        // record pointing at a channel that was never made.
        let (retry, again_steps) = routing
            .ensure_case_channel(&trigger, &operators, 2_592_000)
            .unwrap();
        assert_eq!(retry, case);
        assert_eq!(
            again_steps.len(),
            3,
            "a routed-but-uncreated channel must re-emit its create plan"
        );

        // Idempotent once the relay has ACCEPTED the create: same channel, no steps.
        routing.record_channel_created(case).unwrap();
        let (again, more) = routing
            .ensure_case_channel(&trigger, &operators, 2_592_000)
            .unwrap();
        assert_eq!(again, case);
        assert!(more.is_empty());
        // Durable across a reopen.
        drop(routing);
        let reopened = CaseRouting::open(&path).unwrap();
        assert_eq!(reopened.case_for_hunt("hunt-evt-1"), Some(case));
    }

    #[test]
    fn the_hold_card_ledger_is_write_once_and_survives_a_reopen() {
        // The two windows the ledger closes: a crash between the accepted card and the accepted
        // notice, and a redelivered terminal event. Both are answered by an id on disk.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routing.json");
        let mut routing = CaseRouting::open(&path).unwrap();
        assert_eq!(routing.open_card_for_hold("h_a07aeacf"), None);
        assert_eq!(routing.terminal_card_for_hold("h_a07aeacf"), None);
        routing
            .record_open_card("h_a07aeacf", &"03".repeat(32))
            .unwrap();
        routing
            .record_terminal_card("h_a07aeacf", &"04".repeat(32))
            .unwrap();
        // Write-once: a replay does not overwrite the id the relay already accepted.
        routing
            .record_open_card("h_a07aeacf", &"ff".repeat(32))
            .unwrap();
        routing
            .record_terminal_card("h_a07aeacf", &"ee".repeat(32))
            .unwrap();
        drop(routing);
        let reopened = CaseRouting::open(&path).unwrap();
        assert_eq!(
            reopened.open_card_for_hold("h_a07aeacf"),
            Some("03".repeat(32).as_str())
        );
        assert_eq!(
            reopened.terminal_card_for_hold("h_a07aeacf"),
            Some("04".repeat(32).as_str())
        );
        assert_eq!(reopened.open_card_for_hold("h_other01"), None);
    }

    #[test]
    fn a_step_that_carries_a_body_is_refused_by_the_tag_only_builder() {
        let keys = nostr::Keys::generate();
        let hold = HoldId::parse("h_a07aeacf").unwrap();
        for step in [
            PublishStep::PublishHoldCard {
                channel: uuid::Uuid::nil(),
                hold_id: hold.clone(),
                reply_to: None,
            },
            PublishStep::PublishHoldNotice {
                channel: uuid::Uuid::nil(),
                hold_id: hold.clone(),
                card_event_id: None,
            },
            PublishStep::PublishAlarm {
                hold_id: hold.clone(),
            },
        ] {
            let error = step_to_event(&step, &keys, 1).unwrap_err();
            assert!(
                matches!(error, BridgeError::InvalidConfig { ref reason } if reason.contains(step.label())),
                "{error}"
            );
        }
    }

    #[test]
    fn every_step_names_itself_and_its_channel() {
        let hold = HoldId::parse("h_a07aeacf").unwrap();
        let case = uuid::Uuid::nil();
        let labels: Vec<(&str, Option<uuid::Uuid>)> = [
            PublishStep::CreateChannel {
                channel: case,
                name: "case-00000000".into(),
                visibility: "private",
                ttl_seconds: Some(60),
            },
            PublishStep::AddMember {
                channel: case,
                pubkey: "a".repeat(64),
            },
            PublishStep::PublishHoldCard {
                channel: case,
                hold_id: hold.clone(),
                reply_to: None,
            },
            PublishStep::PublishHoldNotice {
                channel: case,
                hold_id: hold.clone(),
                card_event_id: None,
            },
            PublishStep::PublishAlarm { hold_id: hold },
        ]
        .iter()
        .map(|step| (step.label(), step.channel()))
        .collect();
        assert_eq!(
            labels,
            vec![
                ("create_channel", Some(case)),
                ("add_member", Some(case)),
                ("publish_hold_card", Some(case)),
                ("publish_hold_notice", Some(case)),
                // R-1: the alarm is community-global and carries no `h` tag at all.
                ("publish_alarm", None),
            ]
        );
    }

    #[test]
    fn a_hold_id_with_a_colon_is_refused() {
        assert!(HoldId::parse("hold:hunt-evt-1:1773738882600").is_err());
        assert!(HoldId::parse("27799e23-ab25-4659-b381-3de47ea7ca4d").is_ok());
        assert_eq!(
            HoldId::parse("27799e23-ab25-4659-b381-3de47ea7ca4d")
                .unwrap()
                .as_str(),
            "27799e23-ab25-4659-b381-3de47ea7ca4d"
        );
        assert!(HoldId::parse("short").is_err());
    }

    #[test]
    fn the_three_promotion_clauses_map_one_for_one() {
        assert_eq!(
            PromotionClause::from(CasePromotionClause::Manual),
            PromotionClause::Manual
        );
        assert_eq!(
            PromotionClause::from(CasePromotionClause::HeldAction),
            PromotionClause::HeldAction
        );
        assert_eq!(
            PromotionClause::from(CasePromotionClause::CorrelatedIncident),
            PromotionClause::CorrelatedIncident
        );
        for clause in [
            CasePromotionClause::Manual,
            CasePromotionClause::HeldAction,
            CasePromotionClause::CorrelatedIncident,
        ] {
            assert_eq!(PromotionClause::from(clause).as_str(), clause.as_str());
        }
    }
}
