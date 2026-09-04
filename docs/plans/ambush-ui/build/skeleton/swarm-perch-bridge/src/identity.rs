//! The bridge's Nostr identities: derivation, the table, and the `p`-tag assert.

use nostr::Keys;
use swarm_core::config::SecretString;
use swarm_core::types::AgentId;

use crate::error::BridgeError;

/// Domain separation for key derivation. Changing this string rotates every bridge key and
/// invalidates the relay-side admission list, so it is versioned and never edited in place.
pub const DERIVATION_DOMAIN: &[u8] = b"swarm.perch.bridge.nostr.v1";

/// What an identity slot is for. The evidence slots are sized from
/// `admitted_identities` (`swarm_detect.rs:768-962`, handed to
/// `dispatcher.set_admitted_identities` at `:963`), whose length varies with config gates --
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
    /// `Scope::ChannelsWrite` (kind:9007, `BUZZ ingest.rs:518`) and `Scope::AdminChannels`
    /// (kind:9000, `BUZZ ingest.rs:485-487`, unconditional -- there is no channel-owner
    /// shortcut). `AdminChannels` is the single largest authority the bridge holds and it exists
    /// only so a private case channel can have the on-shift operators added to it.
    Alarm,
}

impl Slot {
    /// The label mixed into derivation. For an agent this is the `AgentId` string, which is
    /// `swarm:ed25519:<64 hex>` (`swarm-core/src/types.rs:16-18`) -- the same value the card
    /// body's `issuer.swarm_agent_id` carries, so no transformation is needed anywhere.
    pub fn label(&self) -> &str {
        match self {
            Self::Agent(id) => id.0.as_str(),
            Self::Telemetry => "perch-telemetry",
            Self::Alarm => "perch-alarm",
        }
    }
}

/// One provisioned identity.
pub struct Identity {
    pub slot: Slot,
    pub keys: Keys,
    /// The NIP-OA owner attestation tag attached to the AUTH event.
    ///
    /// NOT decoration. `build_auth_event(challenge, relay_url, keys, auth_tag)`
    /// (`BUZZ crates/buzz-ws-client/src/message.rs:172-190`) attaches it;
    /// `BUZZ crates/buzz-relay/src/handlers/auth.rs:244-274` extracts the owner and sets
    /// `auth_ctx.agent_owner_pubkey`; and `BUZZ crates/buzz-relay/src/connection.rs:662-668,
    /// 689-692` then selects `agent_standard_messages_per_min` (120) instead of
    /// `human_messages_per_min` (60) for every EVENT frame.
    ///
    /// `None` is legal and halves the quota. At 1 Hz the pacer spends 60/min, so 60/min is 100%
    /// of budget with zero head room and the first case-creation burst collides with the limiter.
    /// [`IdentityTable::build`] logs the consequence by name at startup.
    pub auth_tag: Option<nostr::Tag>,
}

pub struct IdentityTable {
    _private: (),
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
    /// (`swarm-runtime/src/approval.rs:1807-1809`) -- from a **public identifier anyone can
    /// reproduce** -- and then discards the signature and keeps only `envelope_hash` (`:1836-1840`).
    /// A bridge key derived that way would let any reader of a colony id forge a card that the
    /// console's admitted-issuer rule would then honour.
    ///
    /// # Errors
    ///
    /// [`BridgeError::MissingNostrSeed`] when the variable is unset or under 32 bytes. Mirrors
    /// `OperatorAuthState::from_config`'s `MissingTokenEnv`
    /// (`swarm-runtime-http/src/http/auth.rs:57-82`), whose loud failure at
    /// `swarm_detect.rs:1127-1132` is the pattern.
    pub fn build(
        seed: &SecretString,
        colony_id: &str,
        admitted: &[AgentId],
        auth_tag: Option<nostr::Tag>,
    ) -> Result<Self, BridgeError> {
        let _ = (seed, colony_id, admitted, auth_tag, DERIVATION_DOMAIN);
        todo!("derive one Keys per slot; log every npub at info; warn per slot when auth_tag is None")
    }

    /// Emitted at `info` on first start. This listing is the operator's provisioning input for
    /// `11-BRIDGE-CRATE.md` section 8.3 and is the only place the npubs exist in human-readable
    /// form.
    pub fn provisioning_report(&self) -> String {
        todo!("one line per slot: label, npub, and the relay scopes it needs")
    }
}

/// Normalizes a Nostr pubkey to lowercase 64-hex and asserts.
///
/// # Why a failed assert is a bridge error and never a published event
///
/// `query_needs_action` (`BUZZ crates/buzz-db/src/store/feed.rs:171-201`) `INNER JOIN`s
/// `event_mentions` on `m.pubkey_hex` (`:183`), and `event_mentions` is populated **only** from
/// `p` tags (`BUZZ crates/buzz-db/src/runtime/mod.rs:41-53`) by `insert_mentions`, which:
///
/// - **drops a malformed tag silently** -- a value that is not exactly 64 ASCII-hex characters is
///   filtered out with a `tracing::debug!`, and pubkeys are lowercased before insert
///   (`runtime/mod.rs:66-81`);
/// - **runs outside the event transaction** -- `Db::insert_event_with_thread_metadata`
///   (`BUZZ crates/buzz-db/src/store/event.rs:1673-1698`) commits the event, then calls
///   `insert_mentions` on a separate pool transaction, and downgrades any failure to
///   `tracing::warn!(event_id = %event.id, "Failed to insert mentions: {e}")` (`:1690-1696`);
/// - **is attempted once** -- the guard is `if result.1`, i.e. only when the row was newly
///   inserted, and the `events` insert is `ON CONFLICT DO NOTHING`. A republish of identical
///   bytes is a no-op and does not retry the mention write. The hole is not self-healing.
///
/// So a hold can be stored, `OK true`'d, and permanently invisible to every `#p` feed. An
/// unpublished hold alarms; a hold published with a malformed `p` tag is a destructive action
/// awaiting a human that no human is shown.
pub fn normalize_p_tag(raw: &str) -> Result<String, BridgeError> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BridgeError::MalformedPTag {
            value_len: trimmed.len(),
        });
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// The `OperatorScope::Approve` operator pubkeys a `46010` and a `26006` must name.
///
/// # BLOCKER, and it lands here
///
/// `APPENDIX-NORMATIVE.md` section 4 layer 1 requires `p` tags naming every principal holding
/// `OperatorScope::Approve`, via `OperatorAuthConfig::effective_principals()`
/// (`swarm-core/src/config/operator.rs:153-168`). That returns `Vec<OperatorPrincipalConfig>`,
/// which is `{ operator_id, token_env, token_expires_at_ms, scopes }` (`operator.rs:117-129`)
/// under `#[serde(deny_unknown_fields)]`, and
/// `grep -rn 'pubkey|npub|nostr' crates/swarm-core/src/config/` returns nothing.
///
/// **It cannot produce a 32-byte Nostr pubkey.** The fix taken by `11-BRIDGE-CRATE.md` section 7.5
/// is a typed field addition, `nostr_pubkey: Option<String>` with `#[serde(default)]` so the
/// digest-signed `rulesets/default.yaml` keeps loading. Until it lands, this returns empty and the
/// caller refuses to publish, loudly.
pub fn approve_scoped_operator_pubkeys(
    principals: &[swarm_core::config::OperatorPrincipalConfig],
) -> Result<Vec<String>, BridgeError> {
    let _ = principals;
    todo!("filter scopes.contains(OperatorScope::Approve); map the (proposed) nostr_pubkey; \
           normalize_p_tag each; Err(HoldUndeliverable) when the result is empty")
}
