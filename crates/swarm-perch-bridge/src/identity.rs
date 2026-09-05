//! The bridge's Nostr identities: derivation, the table, and the `p`-tag assert.

use nostr::Keys;
use sha2::{Digest, Sha256};
use swarm_core::config::{OperatorPrincipalConfig, OperatorScope, SecretString};
use swarm_core::types::AgentId;

use crate::error::BridgeError;
use crate::spool::IssuerIdx;

/// Domain separation for key derivation. Changing this string rotates every bridge key and
/// invalidates the relay-side admission list, so it is versioned and never edited in place.
///
/// Decision D-FC-1, recorded in `docs/plans/ambush-ui/integration/00-DECISIONS.md` §3.
pub const DERIVATION_DOMAIN: &[u8] = b"swarm.perch.bridge.nostr.v1";

/// The largest number of identity slots a table may hold. `IssuerIdx` is one byte on disk and
/// `255` is reserved so a full table can never collide with a sentinel.
pub const MAX_SLOTS: usize = 254;

/// What an identity slot is for. The evidence slots are sized from
/// `admitted_identities` (`swarm_detect.rs`, handed to
/// `dispatcher.set_admitted_identities`), whose length varies with config gates --
/// Calico, Kitten, Sphinx, Stalker and Weaver each register only when their feature is enabled.
/// Sizing from the 8-variant `AgentRole` enum instead would provision keys for agents that are
/// not running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// One per admitted agent. Signs evidence cards so a finding is attributed to the agent that
    /// produced it. Needs `Scope::MessagesWrite`.
    Agent(AgentId),
    /// Signs `26000`-`26005`. Needs `Scope::MessagesWrite`.
    Telemetry,
    /// Signs `46010`, `26006`, and case-channel provisioning. Needs `Scope::MessagesWrite`,
    /// `Scope::ChannelsWrite` (kind:9007) and `Scope::AdminChannels`
    /// (kind:9000, unconditional -- there is no channel-owner shortcut). `AdminChannels` is the
    /// single largest authority the bridge holds and it exists only so a private case channel
    /// can have the on-shift operators added to it.
    Alarm,
}

impl Slot {
    /// The label mixed into derivation. For an agent this is the `AgentId` string, which is
    /// `swarm:ed25519:<64 hex>` (`swarm-core/src/types.rs`) -- the same value the card
    /// body's `issuer.swarm_agent_id` carries, so no transformation is needed anywhere.
    pub fn label(&self) -> &str {
        match self {
            Self::Agent(id) => id.0.as_str(),
            Self::Telemetry => "perch-telemetry",
            Self::Alarm => "perch-alarm",
        }
    }

    /// The relay scopes this slot needs, for the provisioning report.
    pub const fn scopes(&self) -> &'static str {
        match self {
            Self::Agent(_) | Self::Telemetry => "MessagesWrite",
            Self::Alarm => "MessagesWrite,ChannelsWrite,AdminChannels",
        }
    }
}

/// One provisioned identity.
#[derive(Clone)]
pub struct Identity {
    /// What this key is for.
    pub slot: Slot,
    /// The derived secp256k1 keypair.
    pub keys: Keys,
    /// The NIP-OA owner attestation tag attached to the AUTH event.
    ///
    /// NOT decoration. `build_auth_event(challenge, relay_url, keys, auth_tag)`
    /// (`workspace/crates/ambush-ws-client/src/message.rs`) attaches it; the relay's
    /// `handlers/auth.rs` extracts the owner and sets `auth_ctx.agent_owner_pubkey`; and
    /// `connection.rs` then selects `agent_standard_messages_per_min` (120) instead of
    /// `human_messages_per_min` (60) for every EVENT frame.
    ///
    /// `None` is legal and halves the quota. At 1 Hz the pacer spends 60/min, so 60/min is 100%
    /// of budget with zero head room and the first case-creation burst collides with the limiter.
    /// [`IdentityTable::build`] logs the consequence by name at startup.
    pub auth_tag: Option<nostr::Tag>,
}

/// Every identity the bridge signs with, in slot order.
///
/// Index 0 is always the ingest identity, so a record whose producer is unknown -- every finding
/// from the HTTP ingest lane -- has a deliberate home rather than a default one. The last index
/// is always [`Slot::Alarm`].
pub struct IdentityTable {
    slots: Vec<Identity>,
    alarm: IssuerIdx,
    colony_id: String,
}

impl IdentityTable {
    /// Derives every identity from a configured secret root.
    ///
    /// ```text
    /// root            = 32 bytes from `perch.nostr_seed_env`
    /// nostr_secret[i] = SHA-256( DERIVATION_DOMAIN || 0x00 || root
    ///                            || 0x00 || colony_id || 0x00 || slot.label() )
    /// ```
    ///
    /// # Why the root is a secret and not just the colony id
    ///
    /// This is the distinction correction C-6 exists to protect. The workspace's single
    /// production use of the envelope signer derives its keypair as
    /// `Keypair::from_seed(sha256(format!("approval-ledger-envelope:{}", ledger.ledger_id)))`
    /// (`swarm-runtime/src/approval.rs`) -- from a **public identifier anyone can
    /// reproduce** -- and then discards the signature and keeps only `envelope_hash`.
    /// A bridge key derived that way would let any reader of a colony id forge a card that the
    /// console's admitted-issuer rule would then honour.
    ///
    /// # Errors
    ///
    /// [`BridgeError::MissingNostrSeed`] when the seed is not 32 bytes of hex;
    /// [`BridgeError::InvalidConfig`] when the table would exceed [`MAX_SLOTS`] or a derived
    /// scalar is not a valid secp256k1 secret key.
    pub fn build(
        seed: &SecretString,
        colony_id: &str,
        admitted: &[AgentId],
        ingest: &AgentId,
        auth_tag: Option<nostr::Tag>,
    ) -> Result<Self, BridgeError> {
        let mut labels: Vec<Slot> = vec![Slot::Agent(ingest.clone())];
        for id in admitted {
            if id != ingest && !labels.contains(&Slot::Agent(id.clone())) {
                labels.push(Slot::Agent(id.clone()));
            }
        }
        labels.push(Slot::Telemetry);
        labels.push(Slot::Alarm);

        if labels.len() > MAX_SLOTS {
            return Err(BridgeError::InvalidConfig {
                reason: format!(
                    "the perch identity table holds {} slots; the on-disk issuer index is one \
                     byte and admits at most {MAX_SLOTS}",
                    labels.len()
                ),
            });
        }

        let mut slots = Vec::with_capacity(labels.len());
        for slot in labels {
            let keys = derive_keys(seed, colony_id, slot.label())?;
            slots.push(Identity {
                slot,
                keys,
                auth_tag: auth_tag.clone(),
            });
        }

        let alarm = (slots.len() - 1) as IssuerIdx;
        let table = Self {
            slots,
            alarm,
            colony_id: colony_id.to_string(),
        };

        tracing::info!(
            module = module_path!(),
            colony_id,
            slots = table.slots.len(),
            report = %table.provisioning_report(),
            "perch bridge identities derived"
        );
        if auth_tag.is_none() {
            for identity in &table.slots {
                tracing::warn!(
                    module = module_path!(),
                    slot = identity.slot.label(),
                    "no NIP-OA owner attestation; this identity is on the 60/min human tier"
                );
            }
        }
        Ok(table)
    }

    /// The identity at `idx`, or `None` when the index is past the table.
    pub fn get(&self, idx: IssuerIdx) -> Option<&Identity> {
        self.slots.get(idx as usize)
    }

    /// The index of `slot`, or `None` when the table has no such slot.
    pub fn index_of(&self, slot: &Slot) -> Option<IssuerIdx> {
        self.slots
            .iter()
            .position(|identity| &identity.slot == slot)
            .map(|index| index as IssuerIdx)
    }

    /// The alarm slot: always the last index.
    pub const fn alarm(&self) -> IssuerIdx {
        self.alarm
    }

    /// The ingest slot: always index 0.
    pub const fn ingest(&self) -> IssuerIdx {
        0
    }

    /// The colony this table was derived for.
    pub fn colony_id(&self) -> &str {
        &self.colony_id
    }

    /// How many slots the table holds.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the table is empty. It never is — `build` always adds telemetry and alarm.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Emitted at `info` on first start. This listing is the operator's provisioning input and is
    /// the only place the public keys exist in human-readable form.
    pub fn provisioning_report(&self) -> String {
        self.slots
            .iter()
            .map(|identity| {
                format!(
                    "{}  npub={}  scopes={}",
                    identity.slot.label(),
                    identity.keys.public_key().to_hex(),
                    identity.slot.scopes()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Every slot label, in table order.
    ///
    /// B6 derives one spine keypair per label, so this is the list the signer
    /// is built from and the set of issuers whose chains the head store tracks.
    #[must_use]
    pub fn slot_labels(&self) -> Vec<String> {
        self.slots
            .iter()
            .map(|identity| identity.slot.label().to_string())
            .collect()
    }

    /// `(slot label, hex public key)` for every slot — what
    /// `GET /metrics/perch/identities` serves under decision D-FC-2. Public halves only.
    pub fn public_identities(&self) -> Vec<(String, String)> {
        self.slots
            .iter()
            .map(|identity| {
                (
                    identity.slot.label().to_string(),
                    identity.keys.public_key().to_hex(),
                )
            })
            .collect()
    }
}

/// Reads the 32-byte derivation root from the environment variable named by
/// `perch.nostr_seed_env`.
///
/// # Errors
///
/// [`BridgeError::MissingNostrSeed`] when the variable is unset, is not hex, or does not decode
/// to exactly 32 bytes.
pub fn seed_from_env(var: &str) -> Result<SecretString, BridgeError> {
    let raw = std::env::var(var).ok();
    seed_from_raw(var, raw.as_deref())
}

/// The pure half of [`seed_from_env`], so the four input cases are testable without mutating the
/// process environment (which is `unsafe` in edition 2024 and would need a lock besides).
fn seed_from_raw(var: &str, raw: Option<&str>) -> Result<SecretString, BridgeError> {
    let trimmed = raw.unwrap_or_default().trim();
    let bytes = hex::decode(trimmed).unwrap_or_default();
    if bytes.len() != 32 {
        return Err(BridgeError::MissingNostrSeed {
            env: var.to_string(),
        });
    }
    Ok(SecretString::new(trimmed.to_string()))
}

/// SHA-256 over the domain, the root, the colony and the slot label, each separated by a zero
/// byte so no two field boundaries can be confused for one another.
fn derive_keys(seed: &SecretString, colony_id: &str, label: &str) -> Result<Keys, BridgeError> {
    let root = hex::decode(seed.expose_secret()).map_err(|error| BridgeError::InvalidConfig {
        reason: format!("seed is not hex: {error}"),
    })?;
    let mut hasher = Sha256::new();
    for part in [
        DERIVATION_DOMAIN,
        &[0u8][..],
        &root,
        &[0u8][..],
        colony_id.as_bytes(),
        &[0u8][..],
        label.as_bytes(),
    ] {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let secret =
        nostr::SecretKey::from_slice(&digest).map_err(|error| BridgeError::InvalidConfig {
            reason: format!("derived scalar rejected for `{label}`: {error}"),
        })?;
    Ok(Keys::new(secret))
}

/// Normalizes a Nostr pubkey to lowercase 64-hex and asserts.
///
/// # Why a failed assert is a bridge error and never a published event
///
/// `query_needs_action` (`workspace/crates/ambush-db/src/store/feed.rs`) `INNER JOIN`s
/// `event_mentions` on `m.pubkey_hex`, and `event_mentions` is populated **only** from
/// `p` tags by `insert_mentions`, which:
///
/// - **drops a malformed tag silently** -- a value that is not exactly 64 ASCII-hex characters is
///   filtered out with a `tracing::debug!`, and pubkeys are lowercased before insert;
/// - **runs outside the event transaction** -- `Db::insert_event_with_thread_metadata`
///   commits the event, then calls `insert_mentions` on a separate pool transaction, and
///   downgrades any failure to `tracing::warn!("Failed to insert mentions")`;
/// - **is attempted once** -- the guard is `if result.1`, i.e. only when the row was newly
///   inserted, and the `events` insert is `ON CONFLICT DO NOTHING`. A republish of identical
///   bytes is a no-op and does not retry the mention write. The hole is not self-healing.
///
/// So a hold can be stored, `OK true`'d, and permanently invisible to every `#p` feed. An
/// unpublished hold alarms; a hold published with a malformed `p` tag is a destructive action
/// awaiting a human that no human is shown.
///
/// # Errors
///
/// [`BridgeError::MalformedPTag`] when the value is not 64 hex characters.
pub fn normalize_p_tag(raw: &str) -> Result<String, BridgeError> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BridgeError::MalformedPTag {
            value_len: trimmed.len(),
        });
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// The `OperatorScope::Approve` operator pubkeys a `46010` and a `26006` must name, and the
/// members every case channel the bridge creates is given.
///
/// `OperatorPrincipalConfig` carries `nostr_pubkey: Option<String>` since Ground task 8; a
/// principal without one cannot be addressed and is skipped rather than guessed at.
///
/// # Errors
///
/// [`BridgeError::MalformedPTag`] when a configured key is not 64 hex characters;
/// [`BridgeError::HoldUndeliverable`] when no principal survives the filter.
pub fn approve_scoped_operator_pubkeys(
    principals: &[OperatorPrincipalConfig],
) -> Result<Vec<String>, BridgeError> {
    let mut out = Vec::new();
    for principal in principals {
        if !principal.scopes.contains(&OperatorScope::Approve) {
            continue;
        }
        let Some(pubkey) = principal.nostr_pubkey.as_deref() else {
            continue;
        };
        let normalized = normalize_p_tag(pubkey)?;
        if !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    if out.is_empty() {
        return Err(BridgeError::HoldUndeliverable);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn agent(tag: &str) -> AgentId {
        AgentId(format!("swarm:ed25519:{}", tag.repeat(32)))
    }

    #[test]
    fn derivation_is_deterministic_and_slot_separated() {
        let seed = SecretString::new("11".repeat(32));
        let a = agent("aa");
        let t1 = IdentityTable::build(&seed, "colony", std::slice::from_ref(&a), &a, None).unwrap();
        let t2 = IdentityTable::build(&seed, "colony", std::slice::from_ref(&a), &a, None).unwrap();
        assert_eq!(
            t1.get(t1.alarm()).unwrap().keys.public_key(),
            t2.get(t2.alarm()).unwrap().keys.public_key()
        );
        assert_ne!(
            t1.get(t1.alarm()).unwrap().keys.public_key(),
            t1.get(t1.ingest()).unwrap().keys.public_key()
        );
        let other = IdentityTable::build(&seed, "other-colony", std::slice::from_ref(&a), &a, None)
            .unwrap();
        assert_ne!(
            t1.get(t1.alarm()).unwrap().keys.public_key(),
            other.get(other.alarm()).unwrap().keys.public_key()
        );
    }

    #[test]
    fn the_table_is_ingest_then_admitted_then_telemetry_then_alarm() {
        let seed = SecretString::new("11".repeat(32));
        let ingest = agent("aa");
        let extra = agent("bb");
        let table = IdentityTable::build(
            &seed,
            "colony",
            // The ingest identity appears in `admitted` too, as it does in the daemon: it must
            // not be given a second slot.
            &[extra.clone(), ingest.clone()],
            &ingest,
            None,
        )
        .unwrap();
        assert_eq!(table.len(), 4);
        assert_eq!(table.ingest(), 0);
        assert_eq!(table.alarm(), 3);
        assert_eq!(table.get(0).unwrap().slot, Slot::Agent(ingest.clone()));
        assert_eq!(table.get(1).unwrap().slot, Slot::Agent(extra));
        assert_eq!(table.get(2).unwrap().slot, Slot::Telemetry);
        assert_eq!(table.get(3).unwrap().slot, Slot::Alarm);
        assert_eq!(table.index_of(&Slot::Agent(ingest)), Some(0));
        assert_eq!(table.index_of(&Slot::Alarm), Some(3));
        assert!(table.get(9).is_none());

        let report = table.provisioning_report();
        assert_eq!(report.lines().count(), 4);
        assert!(report.contains("perch-alarm  npub="));
        assert!(report.contains("scopes=MessagesWrite,ChannelsWrite,AdminChannels"));
        let listed = table.public_identities();
        assert_eq!(listed.len(), 4);
        assert!(listed.iter().all(|(_, key)| key.len() == 64));
        assert_eq!(table.colony_id(), "colony");
    }

    #[test]
    fn a_short_seed_is_refused_by_name() {
        let err = seed_from_raw("PERCH_TEST_SEED_SHORT", Some("abcd")).unwrap_err();
        assert!(
            matches!(err, BridgeError::MissingNostrSeed { ref env } if env == "PERCH_TEST_SEED_SHORT")
        );
        assert!(matches!(
            seed_from_raw("PERCH_TEST_SEED_UNSET", None),
            Err(BridgeError::MissingNostrSeed { .. })
        ));
        assert!(matches!(
            seed_from_raw("PERCH_TEST_SEED_NOT_HEX", Some(&"z".repeat(64))),
            Err(BridgeError::MissingNostrSeed { .. })
        ));
        let ok = seed_from_raw(
            "PERCH_TEST_SEED_OK",
            Some(&format!("  {}  ", "ab".repeat(32))),
        )
        .unwrap();
        assert_eq!(ok.expose_secret(), "ab".repeat(32));
    }

    #[test]
    fn approve_scoped_pubkeys_come_only_from_principals_with_a_key() {
        let with = OperatorPrincipalConfig {
            operator_id: "a".into(),
            token_env: "T".into(),
            token_expires_at_ms: None,
            scopes: vec![OperatorScope::Approve],
            nostr_pubkey: Some("C0FFEE".repeat(10) + "c0ff"),
            verdict_public_key_hex: None,
        };
        let read_only = OperatorPrincipalConfig {
            scopes: vec![OperatorScope::Read],
            nostr_pubkey: Some("a".repeat(64)),
            verdict_public_key_hex: None,
            ..with.clone()
        };
        let keyless = OperatorPrincipalConfig {
            nostr_pubkey: None,
            verdict_public_key_hex: None,
            ..with.clone()
        };
        let keys = approve_scoped_operator_pubkeys(&[with.clone(), read_only, keyless]).unwrap();
        assert_eq!(
            keys,
            vec!["c0ffee".repeat(10) + "c0ff"],
            "lowercased, Approve only"
        );
        assert!(matches!(
            approve_scoped_operator_pubkeys(&[]).unwrap_err(),
            BridgeError::HoldUndeliverable
        ));

        let malformed = OperatorPrincipalConfig {
            nostr_pubkey: Some("not-a-key".into()),
            verdict_public_key_hex: None,
            ..with
        };
        assert!(matches!(
            approve_scoped_operator_pubkeys(&[malformed]).unwrap_err(),
            BridgeError::MalformedPTag { .. }
        ));
    }

    #[test]
    fn a_p_tag_is_lowercased_and_length_checked() {
        assert_eq!(normalize_p_tag(&"AB".repeat(32)).unwrap(), "ab".repeat(32));
        assert!(matches!(
            normalize_p_tag("abc"),
            Err(BridgeError::MalformedPTag { value_len: 3 })
        ));
        assert!(matches!(
            normalize_p_tag(&"g".repeat(64)),
            Err(BridgeError::MalformedPTag { value_len: 64 })
        ));
    }
}
