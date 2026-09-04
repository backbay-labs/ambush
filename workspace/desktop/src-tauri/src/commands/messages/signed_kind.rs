//! Which kind `send_channel_message` actually signs.
//!
//! Split out of `messages.rs` to keep that file under the repository's
//! 1000-gate-line ceiling; it is one self-contained rule with one caller.

/// The kind `send_channel_message`'s builder actually signs for a requested kind.
///
/// Its match keeps the two forum kinds and routes everything else to
/// `events::build_message`, which signs kind 9. INV-29 gates on this value:
/// gating the caller's requested kind instead let any value outside the forum
/// pair skip the swarm-marker check while still producing a signed kind 9 event
/// that the console's card router would read.
pub(crate) fn signed_message_kind(requested: u32) -> u32 {
    match requested {
        ambush_core_pkg::kind::KIND_FORUM_POST => ambush_core_pkg::kind::KIND_FORUM_POST,
        ambush_core_pkg::kind::KIND_FORUM_COMMENT => ambush_core_pkg::kind::KIND_FORUM_COMMENT,
        _ => ambush_core_pkg::kind::KIND_STREAM_MESSAGE,
    }
}
