// Vendored from block/buzz crates/buzz-ws-client/src/message.rs @ eed74bde2, Apache-2.0.
// MODIFIED: none required -- upstream message.rs has no panic sites. Vendored rather than
// depended on because `deny.toml` sets `[sources] unknown-git = "deny"` with `allow-git = []`,
// and because the crate it lives in is deleted by 02-ARCHITECTURE-INTEGRATION.md section 5.

use nostr::{Event, EventBuilder, Keys, RelayUrl, Tag};
use serde_json::Value;

use crate::ws::error::WsClientError;

/// A message received from a Nostr relay. Upstream `message.rs:6-47`, verbatim.
#[derive(Debug, Clone)]
pub enum RelayMessage {
    Event {
        subscription_id: String,
        event: Box<Event>,
    },
    Ok(OkResponse),
    Eose {
        subscription_id: String,
    },
    Closed {
        subscription_id: String,
        message: String,
    },
    Notice {
        message: String,
    },
    Auth {
        challenge: String,
    },
    Count {
        subscription_id: String,
        count: u64,
    },
}

/// Upstream `message.rs:49-58`, verbatim.
#[derive(Debug, Clone)]
pub struct OkResponse {
    pub event_id: String,
    pub accepted: bool,
    /// On rejection this is the relay's typed reason string, and
    /// [`crate::publish::ConnectionSupervisor::classify_ok`] is the only place it is interpreted.
    /// Six prefixes matter: `duplicate: channel already exists`,
    /// `rate-limited: shared admission unavailable`, `rate-limited`,
    /// `restricted: unknown event kind`, `restricted: not a channel member`, and
    /// `invalid: event timestamp too far`.
    pub message: String,
}

/// Upstream `message.rs:60-166`, verbatim. Note `RelayMessage::Event` and `Eose` and `Count` are
/// parsed but never produced for this crate, because the bridge issues no `REQ` and no `COUNT`.
#[allow(clippy::result_large_err)]
pub fn parse_relay_message(text: &str) -> Result<RelayMessage, WsClientError> {
    let _: Result<Vec<Value>, _> = serde_json::from_str(text);
    todo!("verbatim from upstream message.rs:62-166")
}

/// Builds a NIP-42 AUTH event, optionally injecting the NIP-OA authorization tag.
/// Upstream `message.rs:168-190`, verbatim.
///
/// The `auth_tag` parameter is what makes the bridge an agent rather than a human to the relay's
/// limiter -- see [`crate::ws::connection::NostrWsConnection::connect_authenticated`].
pub fn build_auth_event(
    challenge: &str,
    relay_url: &str,
    keys: &Keys,
    auth_tag: Option<&Tag>,
) -> Result<Event, WsClientError> {
    let url = RelayUrl::parse(relay_url).map_err(|e| WsClientError::Url(e.to_string()))?;
    let builder = EventBuilder::auth(challenge, url);
    let builder = if let Some(tag) = auth_tag {
        builder.tags([tag.clone()])
    } else {
        builder
    };
    builder
        .sign_with_keys(keys)
        .map_err(|e| WsClientError::EventBuilder(e.to_string()))
}
