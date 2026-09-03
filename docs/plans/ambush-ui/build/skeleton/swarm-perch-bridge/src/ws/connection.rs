// Vendored from block/buzz crates/buzz-ws-client/src/connection.rs @ eed74bde2, Apache-2.0.
// MODIFIED: four panic sites removed, send_event dropped, the stream split for a concurrent
// OK reaper. See ws/mod.rs for the full list.

use std::collections::VecDeque;
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use nostr::{Event, Keys, Tag};
use serde_json::{json, Value};
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::ws::error::WsClientError;
use crate::ws::message::{OkResponse, RelayMessage};

type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type WsWriter = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

/// Upstream `connection.rs:17`. Unchanged.
pub const AUTH_CHALLENGE_TIMEOUT_SECS: u64 = 20;
/// Upstream `connection.rs:20`. Unchanged.
pub const AUTH_OK_TIMEOUT_SECS: u64 = 20;
/// Upstream `connection.rs:23`. Retained as the reaper's per-frame deadline, NOT as a blocking
/// wait: the bridge never holds a task on one OK.
pub const PUBLISH_OK_TIMEOUT_SECS: u64 = 30;

/// The write half. One per identity.
pub struct NostrWsConnection {
    writer: WsWriter,
    relay_url: String,
}

impl NostrWsConnection {
    /// Connects and performs NIP-42 authentication, then returns the write half and a reaper for
    /// the read half.
    ///
    /// `auth_tag` is the NIP-OA owner attestation and it is not decoration: it is what makes
    /// `agent_owner_pubkey` `Some` on the relay's auth context
    /// (`BUZZ crates/buzz-relay/src/handlers/auth.rs:244-274`) and therefore what selects
    /// `agent_standard_messages_per_min` = 120 over `human_messages_per_min` = 60 for every EVENT
    /// frame (`BUZZ crates/buzz-relay/src/connection.rs:662-668, 689-692`).
    pub async fn connect_authenticated(
        url: &str,
        keys: &Keys,
        auth_tag: Option<&Tag>,
    ) -> Result<(Self, OkReaper), WsClientError> {
        let _ = (url, keys, auth_tag, AUTH_CHALLENGE_TIMEOUT_SECS, AUTH_OK_TIMEOUT_SECS);
        todo!("connect_async; StreamExt::split; wait for AUTH; build_auth_event; send; await OK")
    }

    /// Sends a raw JSON value as a text frame. Upstream `connection.rs:121-126`, unchanged except
    /// that it writes to the split sink.
    pub async fn send_raw(&mut self, value: &Value) -> Result<(), WsClientError> {
        let text = serde_json::to_string(value)?;
        tracing::debug!(module = module_path!(), "-> relay: {text}");
        futures_util::SinkExt::send(&mut self.writer, Message::Text(text.into())).await?;
        Ok(())
    }

    /// Fire-and-forget publish. The reaper resolves the OK.
    ///
    /// Upstream's `send_event` (`connection.rs:96-101`) is deliberately NOT vendored: it awaits
    /// `wait_for_ok` inline, which caps a connection at one in-flight event and makes throughput
    /// RTT-bound.
    pub async fn send_event_no_wait(&mut self, event: &Event) -> Result<(), WsClientError> {
        self.send_raw(&json!(["EVENT", event])).await
    }

    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }
}

/// The read half. Owns the message buffer and resolves in-flight frames by event id.
pub struct OkReaper {
    reader: WsReader,
    /// Upstream kept this on the connection (`connection.rs:28`); here it belongs to the reaper,
    /// which is the only thing that reads.
    buffer: VecDeque<RelayMessage>,
    pending_challenge: Option<String>,
}

impl OkReaper {
    /// Runs until the socket closes, resolving `OK` frames and forwarding `NOTICE` / `CLOSED` /
    /// re-`AUTH` to the supervisor.
    ///
    /// Also answers `Ping` with `Pong` (upstream `connection.rs:148-150`, `:208-210`, `:262-264`,
    /// which the split makes a single site instead of three).
    pub async fn run(mut self, sink: tokio::sync::mpsc::Sender<ReapedMessage>) {
        let _ = (&mut self.reader, &mut self.buffer, &mut self.pending_challenge, sink,
                 Duration::from_secs(PUBLISH_OK_TIMEOUT_SECS));
        todo!("loop next(); parse_relay_message; dispatch")
    }

    /// Upstream `wait_for_auth_challenge` (`connection.rs:157-215`), PANIC SITES REMOVED.
    ///
    /// Upstream, at `:165-174`:
    ///
    /// ```text
    /// if let Some(idx) = self.buffer.iter().position(|m| matches!(m, RelayMessage::Auth { .. })) {
    ///     match self.buffer.remove(idx).unwrap() {          // <- :170
    ///         RelayMessage::Auth { challenge } => return Ok(challenge),
    ///         _ => unreachable!(),                          // <- :172
    ///     }
    /// }
    /// ```
    ///
    /// Both are "cannot happen" claims about a `VecDeque` that another `&mut self` method could
    /// have mutated. They become typed errors rather than an argument.
    async fn take_buffered_challenge(&mut self) -> Result<Option<String>, WsClientError> {
        let Some(idx) = self
            .buffer
            .iter()
            .position(|m| matches!(m, RelayMessage::Auth { .. }))
        else {
            return Ok(None);
        };
        let taken = self.buffer.remove(idx).ok_or(WsClientError::BufferRace)?;
        match taken {
            RelayMessage::Auth { challenge } => Ok(Some(challenge)),
            other => {
                self.buffer.push_back(other);
                Err(WsClientError::BufferRace)
            }
        }
    }

    /// Upstream `wait_for_ok` (`connection.rs:217-269`), PANIC SITES REMOVED — same shape as
    /// above at `:229` and `:231`.
    fn take_buffered_ok(&mut self, event_id: &str) -> Result<Option<OkResponse>, WsClientError> {
        let Some(idx) = self
            .buffer
            .iter()
            .position(|m| matches!(m, RelayMessage::Ok(ok) if ok.event_id == event_id))
        else {
            return Ok(None);
        };
        let taken = self.buffer.remove(idx).ok_or(WsClientError::BufferRace)?;
        match taken {
            RelayMessage::Ok(ok) => Ok(Some(ok)),
            other => {
                self.buffer.push_back(other);
                Err(WsClientError::BufferRace)
            }
        }
    }
}

/// What the reaper forwards to the connection supervisor.
#[derive(Debug, Clone)]
pub enum ReapedMessage {
    Ok(OkResponse),
    /// The relay closed a subscription. The bridge opens none, so this is only ever informational
    /// -- but it is forwarded rather than dropped, because a `CLOSED` on a connection that issued
    /// no `REQ` would be a real anomaly worth logging.
    Closed { subscription_id: String, message: String },
    Notice { message: String },
    /// A mid-session re-AUTH challenge. Upstream stashes it on `pending_challenge`
    /// (`connection.rs:255-258`); here it is forwarded so the supervisor can re-authenticate
    /// without tearing the socket down.
    ReAuth { challenge: String },
    Disconnected,
}
