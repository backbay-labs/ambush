//! VENDORED from `block/buzz` `crates/buzz-ws-client` @ `eed74bde2`, Apache-2.0, **and modified**.
//!
//! `02-ARCHITECTURE-INTEGRATION.md` decision 5: *"`buzz-ws-client` is vendored **and modified**,
//! not depended on. `deny.toml` sets `[sources] unknown-git = "deny"` with `allow-git = []`. The
//! copy is not verbatim: four panic sites in production code must become typed errors before the
//! crate's first commit compiles."*
//!
//! # The four, and what they became
//!
//! All in upstream `crates/buzz-ws-client/src/connection.rs`:
//!
//! | Upstream line | Site | Now |
//! |---|---|---|
//! | `:170` | `self.buffer.remove(idx).unwrap()` in `wait_for_auth_challenge` | `.ok_or(WsClientError::BufferRace)?` |
//! | `:172` | `_ => unreachable!()` on the removed element | push it back and return `BufferRace` |
//! | `:229` | `self.buffer.remove(idx).unwrap()` in `wait_for_ok` | `.ok_or(WsClientError::BufferRace)?` |
//! | `:231` | `_ => unreachable!()` | push it back and return `BufferRace` |
//!
//! `tools/check-runtime-panic-contract.sh` matches ONLY `.unwrap(` and `.expect(` -- deliberately
//! not `unreachable!` -- so two of the four are hard gate failures and two are review items. All
//! four are fixed: `[lints] workspace = true` inherits `unwrap_used = "deny"` /
//! `expect_used = "deny"` (`Cargo.toml:135-137`), and `[profile.release] panic = "abort"`
//! (`:139-141`) makes any surviving panic a process kill in the daemon that holds the containment
//! containment lease store.
//!
//! This lives under `crates/swarm-perch-bridge/src/ws/` and NOT under `vendor/`, precisely so the
//! panic-contract gate does scan it -- `vendor/reference/` is on that script's deliberate
//! exclusion list.
//!
//! # Two functional changes on top of the four fixes
//!
//! 1. **`send_event` is not used.** It is strictly serial -- send, then `wait_for_ok` up to
//!    `PUBLISH_OK_TIMEOUT_SECS = 30` (upstream `connection.rs:96-101`, `:23`). One in-flight event
//!    per connection is an RTT-bound ceiling. The bridge uses `send_raw` (upstream `:121-126`,
//!    already `pub`) plus a separate OK reaper that owns the read half.
//! 2. **The connection is split.** Upstream owns a single `WsStream` and every method takes
//!    `&mut self`. Here it splits into a `SplitSink`/`SplitStream` pair so the writer and the
//!    reaper run concurrently, and the `pending_challenge`/`buffer` machinery collapses into the
//!    reaper's own state.
//!
//! `NOTICE`: each file carries the upstream Apache-2.0 header and a provenance line naming
//! `block/buzz` and the source SHA.

pub mod connection;
pub mod error;
pub mod message;

pub use connection::{NostrWsConnection, OkReaper};
pub use error::WsClientError;
pub use message::{build_auth_event, parse_relay_message, OkResponse, RelayMessage};
