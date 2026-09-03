// Target path in BUZZ: desktop/src-tauri/src/commands/perch_verdict.rs  (NEW file)
//
// ONE command: `perch_record_verdict`. It is leg 1 of the two-legged write —
// the operator's signed intent card, published to the RELAY, carrying no
// authority whatsoever. It touches no Ambush host except a GET, so it is
// deliberately NOT in perch_writes.rs and is NOT counted by INV-01's
// five-daemon-write table. INV-RF1 closes this set instead: the operator's own
// key publishes exactly one kind (`kind:9` / `swarm:verdict:v1`) and exactly
// one command may do it.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE HAS TO EXIST AT ALL
//
// `perch_sign_gate` (16-INVARIANT-TESTS.md INV-29, implemented at
// commands/identity_perch_gate.rs) is called on the first line of `sign_event`
// (BUZZ desktop/src-tauri/src/commands/identity.rs:107-135 — the Tauri Rust
// process; it takes `kind`, `content`, `created_at`, `tags`, signs with
// `state.signing_keys()` and returns the event JSON to the renderer) and
// REFUSES any content whose first line is an `ambush:<slug>:v<n>` marker. Its
// refusal string names `perch_record_verdict` as the alternative. Without this
// file that alternative does not exist and the console cannot publish leg 1 at
// all — a two-legged write with one leg, which is how four wave-2 artifacts
// came to rest an argument on a command nobody had declared.
//
// A SECOND SIGNING PATH EXISTS AND MUST ALSO BE GATED. `send_channel_message`
// (BUZZ desktop/src-tauri/src/commands/messages.rs:409-...) takes an arbitrary
// `content: String` and an optional `kind: Option<u32>`, snapshots
// `state.signing_keys()` at :447, and publishes. Gating only `sign_event`
// leaves a renderer able to sign a `kind:9` whose body is an `ambush:*:v1`
// marker through that command instead. `perch_sign_gate(kind_num, &content)`
// must be called there too, immediately after `kind_num` is resolved at
// messages.rs:452. Handed to 16-INVARIANT-TESTS.md as an INV-29 completeness
// finding; recorded here because this file is the sanctioned path and its
// value depends on the unsanctioned ones being closed.
// ---------------------------------------------------------------------------
//
// Gate-line budget: 1000 (src-tauri/src is governed). Targets ~260.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::app_state::AppState;

/// The one daemon route this file touches, and it is a GET: the card body is
/// built from the daemon's own hold record, never from renderer-supplied
/// fields, so a compromised webview cannot forge an ACTION sentence, a blast
/// radius or a severity. INV-01 gates non-GET only, so this route does not
/// belong in `PERCH_WRITE_ROUTES`.
const ROUTE_GET_HOLD: &str = "/v1/response/holds/{hold_id}";

/// The one relay write. Exported so INV-RF1's gate reads a closed set out of
/// this file the way `tools/check-perch-write-allowlist.sh` reads one out of
/// perch_writes.rs.
pub const PERCH_RELAY_PUBLISHED_KINDS: [u32; 1] = [9];
pub const PERCH_RELAY_PUBLISHED_MARKERS: [&str; 1] = ["swarm:verdict:v1"];

// ---------------------------------------------------------------------------
// KEY MATERIAL — where it lives, and why the renderer can never hold it.
//
// Two chains, never conflated (ADR 0016):
//
//   NOSTR, secp256k1 Schnorr. Buzz's existing identity, reachable in this
//   process as `state.signing_keys()` (BUZZ desktop/src-tauri/src/app_state.rs:278-291,
//   which refuses while `identity_lost` or `keyring_locked` is set). It signs
//   the kind:9 EVENT. It says who published the card.
//
//   AMBUSH OPERATOR, Ed25519. A SEPARATE secret, stored as a sibling entry in
//   the same OS keyring the identity uses:
//   `SecretStore::shared(keyring_service())` (app_state.rs:435;
//   `keyring_service()` is "buzz-desktop", or "buzz-desktop-dev" in debug
//   builds, at app_state_keyring.rs:9-17) with `store(key, value)` /
//   `load(key)` (secret_store.rs:729-741, :549). It signs the DECISION
//   PREIMAGE. It says who decided.
//
// Two verified consequences of using that store rather than inventing one:
//
//   * `SecretStore::store` mutates the service's single keyring BLOB
//     (secret_store.rs:731-734), and `delete_all_with_legacy_cleanup`
//     (:756-800) enumerates that blob's key names at wipe time rather than
//     consulting a fixed allowlist. So the operator's Ed25519 secret is
//     destroyed by Buzz's existing sign-out path with ZERO new code, and there
//     is no allowlist that can be forgotten.
//   * No `#[tauri::command]` in this file, or in perch_reads.rs or
//     perch_writes.rs, returns either secret or any type that could carry one.
//     `public_key_hex` crosses IPC — it must, because the decide route derives
//     `voter_id` from it — and it is public by construction.
//
// PROVISIONING IS NOT DESIGNED HERE. Who mints the operator keypair, how its
// `public_key_hex` reaches `OperatorPrincipalConfig`, and what happens on a
// second workstation are 12-BACKEND-BILL-API.md's and 20-TASK-BREAKDOWN.md's
// (task B0). This file states only that the secret lives in that store and
// never crosses IPC.
// ---------------------------------------------------------------------------

const OPERATOR_ED25519_SECRET_KEY: &str = "perch.operator_ed25519";

/// `swarm_crypto::DetachedSignature` — the Ed25519 chain, and the ONLY thing
/// that joins the two legs. `signature_hex` is byte-identical on the relay card
/// and on the daemon's decision record, and it is unforgeable, so a reconciler
/// (and a Ledger export) matches on it. The leg-1 event id is a lookup
/// convenience and is never rendered as part of the signed record.
///
/// Shared with perch_writes.rs rather than duplicated: two hand-written copies
/// of one wire object is the drift this file exists to avoid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachedSignature {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictDecision {
    Grant,
    Refuse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordVerdictInput {
    pub hold_id: String,
    pub decision: VerdictDecision,
    /// The operator's own words. Hashed into the preimage as
    /// `rationale_sha256`, so nothing holding the bearer token can replay a
    /// valid signature with substituted free text.
    pub rationale: Option<String>,
    /// When the grant control was armed. Advisory, carried to leg 2, OUTSIDE
    /// the preimage — a daemon that enforced a client clock would be gating a
    /// destructive action on a value the client controls.
    pub armed_at_ms: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RecordVerdictOutput {
    /// The published card's event id, 64 lowercase hex. Leg 2's idempotency
    /// key and an UNSIGNED POINTER.
    pub nostr_intent_event_id: String,
    /// Stamped by THIS process's clock at signing time and carried into the
    /// preimage. Leg 2 must send this exact value.
    pub decided_at_ms: i64,
    pub signature: DetachedSignature,
}

/// Build, sign and publish the leg-1 `swarm:verdict:v1` card.
///
/// Runs in the Tauri Rust process. Order of operations, and every step is
/// load-bearing:
///
/// 1. **Validate `hold_id` locally** against the pinned `hold_<uuidv4>` form.
///    A malformed id is refused before a socket opens.
/// 2. **GET `ROUTE_GET_HOLD`** and refuse locally unless the hold is decidable.
///    The card's ACTION sentence, severity, case channel and blast radius are
///    built from THIS answer. The renderer supplies only the decision, the
///    rationale and the arming timestamp — the three things a human actually
///    produced.
/// 3. **Stamp `decided_at_ms`** from this process's clock.
/// 4. **Sign the preimage**: the RFC 8785 canonical JSON of
///    `{decided_at_ms, decision, hold_id, rationale_sha256}` — four members,
///    key-sorted, with `rationale_sha256` the lowercase hex SHA-256 of the
///    rationale's UTF-8 bytes or JSON `null`. Ed25519, operator key. This is
///    byte-identical to what the decide route verifies, so ONE signature serves
///    both legs and there is no window in which the card and the decision
///    record could disagree.
/// 5. **Build the card body** in 13-WIRE-SCHEMAS.md's grammar: line 0 is the
///    marker and nothing else, line 1 is the one-line human fallback, a blank
///    line, then a fenced block whose info string is the marker, holding one
///    line of JSON.
/// 6. **Sign the `kind:9` event** with the Nostr identity and publish it to the
///    case channel with an `h` tag and NO `e` tag (RF-D1: an e-tagged card
///    becomes a NIP-10 reply, mutating `reply_count`/`descendant_count` and
///    emitting a relay-signed kind:39005).
/// 7. **Return** the three values leg 2 needs, and nothing else.
///
/// IT DOES NOT CALL THE DAEMON'S DECIDE ROUTE. Leg 2 is a separate command in a
/// separate file, invoked separately by the renderer, so that "Perch never
/// authorizes" is a property of the process graph and not of a code comment. A
/// successful return from this command means an intent record exists and the
/// world has not changed — which is exactly the `recorded` phase of the write
/// state machine (14 §4.4) and must never render as a completed action.
#[tauri::command]
pub async fn perch_record_verdict(
    input: RecordVerdictInput,
    state: State<'_, AppState>,
) -> Result<RecordVerdictOutput, String> {
    let _ = (
        &input,
        &state,
        ROUTE_GET_HOLD,
        OPERATOR_ED25519_SECRET_KEY,
        PERCH_RELAY_PUBLISHED_KINDS,
        PERCH_RELAY_PUBLISHED_MARKERS,
    );
    todo!(
        "GET the hold; build the card from THAT record; sign the RFC 8785 \
         preimage with the operator Ed25519 key; sign and publish the kind:9 \
         event with the Nostr identity; return {{event_id, decided_at_ms, \
         signature}}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INV-RF1, the console half. The operator's own key publishes exactly one
    /// kind and exactly one marker. Widening either needs an argument, not an
    /// edit.
    #[test]
    fn the_operator_key_publishes_exactly_one_kind_and_one_marker() {
        assert_eq!(PERCH_RELAY_PUBLISHED_KINDS, [9]);
        assert_eq!(PERCH_RELAY_PUBLISHED_MARKERS, ["swarm:verdict:v1"]);
    }

    /// The gate at commands/identity_perch_gate.rs must refuse the exact
    /// content this command produces, or the two are not describing one rule.
    /// A marker the gate lets through is a marker the renderer could have
    /// signed itself.
    #[test]
    fn the_generic_signer_refuses_what_this_command_publishes() {
        let card_line_0 = "<!-- swarm:verdict:v1 -->";
        assert!(
            crate::commands::identity_perch_gate::perch_sign_gate(9, card_line_0)
                .is_err(),
            "sign_event must refuse the body perch_record_verdict publishes"
        );
    }

    /// The daemon route this command touches is a GET, so it must not appear in
    /// INV-01's daemon-write table. Asserted rather than assumed, because the
    /// two tables are in two files.
    #[test]
    fn this_files_daemon_route_is_not_a_write() {
        assert!(
            !crate::commands::perch_writes::PERCH_WRITE_ROUTES.contains(&ROUTE_GET_HOLD),
            "a GET must never enter the non-GET allowlist"
        );
    }
}
