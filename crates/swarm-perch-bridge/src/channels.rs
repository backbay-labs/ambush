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

use std::collections::BTreeMap;
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
    /// kind:46010 + `swarm:hold:v1`, `h` = the case channel. Durable; this is the record.
    /// Planned only under [`CasePromotionTrigger::Held`], which The hold milestone owns.
    PublishHold {
        /// The case channel.
        channel: Uuid,
        /// The daemon-minted hold id.
        hold_id: HoldId,
    },
    /// Ephemeral 26006, the hold alarm. Planned only under [`CasePromotionTrigger::Held`].
    PublishAlarm {
        /// The daemon-minted hold id.
        hold_id: HoldId,
    },
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
                return Ok((existing, Vec::new()));
            }
            (CasePromotionTrigger::Held { .. }, None) => Uuid::new_v4(),
            (CasePromotionTrigger::Promoted { case_id, .. }, None) => *case_id,
        };

        self.state.hunts.insert(hunt_id, channel.to_string());
        self.persist()?;

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
        Ok((channel, steps))
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
        PublishStep::PublishHold { .. } | PublishStep::PublishAlarm { .. } => {
            return Err(BridgeError::InvalidConfig {
                reason: "the hold steps are built by 13-PLAN-THE-HOLD, not by this milestone"
                    .to_string(),
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
        // Replay: same hunt, same case → no steps. Different case → conflict, never a second
        // channel.
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
        // A later promotion naming the same channel is a no-op, not a conflict.
        let promoted = CasePromotionTrigger::Promoted {
            hunt_id: "hunt-2".into(),
            case_id: channel,
            clause: PromotionClause::HeldAction,
        };
        assert!(
            routing
                .ensure_case_channel(&promoted, &[], 60)
                .unwrap()
                .1
                .is_empty()
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
