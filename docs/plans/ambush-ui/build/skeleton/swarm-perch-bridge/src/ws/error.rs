// Vendored from block/buzz crates/buzz-ws-client/src/error.rs @ eed74bde2, Apache-2.0.
// MODIFIED: one variant added (`BufferRace`) to carry the four removed panic sites.

use thiserror::Error;

/// Errors returned by [`crate::ws::NostrWsConnection`] and [`crate::ws::OkReaper`].
#[derive(Debug, Error)]
pub enum WsClientError {
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Nostr event builder error: {0}")]
    EventBuilder(String),

    #[error("URL parse error: {0}")]
    Url(String),

    #[error("Timeout waiting for relay message")]
    Timeout,

    #[error("Connection closed unexpectedly")]
    ConnectionClosed,

    #[error("Unexpected relay message: {0}")]
    UnexpectedMessage(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Event rejected by relay: {0}")]
    EventRejected(String),

    #[error("No AUTH challenge received from relay")]
    NoAuthChallenge,

    /// NEW, and the reason this crate is a vendored copy rather than a dependency.
    ///
    /// Upstream states "cannot happen" four times with `.unwrap()` and `unreachable!()`
    /// (`buzz-ws-client/src/connection.rs:170, 172, 229, 231`) about a `VecDeque` whose index was
    /// computed by an earlier `position()` call. Under `unwrap_used = "deny"` and
    /// `panic = "abort"`, a claim of that shape is either a typed error or a process kill in the
    /// daemon that holds the containment lease store. It is a typed error.
    #[error("relay message buffer changed between position() and remove()")]
    BufferRace,
}

impl From<nostr::event::builder::Error> for WsClientError {
    fn from(e: nostr::event::builder::Error) -> Self {
        WsClientError::EventBuilder(e.to_string())
    }
}
