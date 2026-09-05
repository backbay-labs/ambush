# The walking skeleton — the console half, driven headless

**Recorded:** 2026-09-05, on `codex/ambush-hold-watch` (PR #16's head). **Driver:**
`workspace/desktop/src-tauri/src/commands/perch_live_tests.rs`. **Stack:** the native dev stack of
`docs/PERCH-DEV.md`, on a fresh relay database.

Every claim names the command or the id that produced it. This record supersedes the sentence
"the console half was never driven against that stack" in `first-card.md`, `the-hold.md` and
`operator-complete.md`; it does not retire the seam it names at the end.

## What was driven, and how

The desktop's daemon surface goes through Tauri commands that hold the bearer and the operator's
Ed25519 key, so a browser cannot drive it and every Playwright spec runs against a mock. What CAN
drive it without a window is Tauri's own test runtime: `tauri::test::mock_builder()` with the real
`invoke_handler`, built on the app's generated context so the capabilities apply, and
`get_ipc_response` sending each request **exactly as the renderer's `invokeTauri` sends it** — the
same JSON, deserialized by Tauri's invoke pipeline, reaching the same command bodies, which sign
with the same keyring-held key, publish to the relay over the same `POST /events`, and call the
daemon over the same client. The React tree above those commands is the one layer this leaves
to the mock, and the mock now refuses every shape the Rust side refuses.

```bash
# relay: fresh database, the repo's dev key; daemon: rulesets-dev/perch-hold-dev.yaml with
# PERCH_BRIDGE_NOSTR_SEED and PERCH_BRIDGE_SPINE_SEED set (PERCH-DEV.md steps 11–12)
set -a; . .perch-dev/operator.env; set +a          # AMBUSH_PRIVATE_KEY = the operator's nsec
export AMBUSH_DEV_KEYRING_SERVICE=ambush-desktop-dev.perch-live-driver   # the driver's own blob
export PERCH_LIVE_DAEMON_URL=http://127.0.0.1:9090 PERCH_LIVE_DAEMON_BEARER=perch-dev-operator-token
export PERCH_LIVE_VERDICT_PUBKEY=c6e5010572535d01b679633b2c1f4c5a2238ea12a4cd0ea280dd25a67a458042
export PERCH_LIVE_OPERATOR_ID=console PERCH_LIVE_RELAY_URL=ws://localhost:3000
export PERCH_LIVE_INGEST_EVENTS=$PWD/.perch-dev/events-grant.json,$PWD/.perch-dev/events.json
cd workspace/desktop/src-tauri && cargo test --lib -- ipc_tests live_tests --include-ignored --nocapture --test-threads=1
```

Result on the run this record is taken from: **5 passed, 0 failed, 143.6 s.** The three
`ipc_tests` pin the IPC seam; the two `live_tests` are the hold path and the finding path below.

## The IPC seam, and the two defects found before any of this ran

Preparing this run meant reading the Rust command signatures against the client, which found
two defects no test could reach because the E2E mock spoke the TypeScript contract and every
one of the forty-five perch specs passed against it (`4ce2dcdb1`):

- `perchDecideHold` sent its fields flat; the command binds one parameter named `input`, so
  Tauri would have answered **"missing required key input"** and no hold decision would ever
  have reached the daemon.
- `RecordHoldVerdictOutput` and `DecideOutcome` serialized camelCase while the renderer reads
  `decided_at_ms`, `receipt_id`, `superseded_by`, `winning_decision` — `undefined` in a real
  build.

Both are now pinned from three sides: the mock refuses flat arguments and any of the five keys
missing; a cross-language test reads every `#[tauri::command]` and asserts `{ input }` and
snake_case outputs; and `perch_ipc_tests.rs` sends a flat request through Tauri's real invoke
pipeline and asserts Tauri's own refusal, then a wrapped one and asserts it reaches the
command's first validation. Under `mock_context` those tests could prove nothing — every app
command is "not allowed" with no capabilities — so `lib.rs` now exposes the one
`generate_context!()` expansion as `app_context()` for the app and the tests alike.

## The hold path

| Step | Evidence |
|---|---|
| operator identity | `perch_operator_identity` → `public_key_hex` = `c6e50105…8042`, the key `perch-hold-dev.yaml` pins as `verdict_public_key_hex`; the seed is the well-known dev material in the driver's own keyring blob |
| grant, leg 1 | `perch_record_hold_verdict` on `hold_7665ad0e-a1c6-476f-815a-bb4ec094a7e9` → card `c0bd867343a023bcb401c2a29c018658130522c2f1a4ab3bdae0337742776715` in case `d29fadb1-a867-423c-995e-f7a0b9f007c3`, signed by the operator's nostr key `1fa40f70991b6b98…`, `decided_at_ms 1788619264945` |
| grant, leg 2 | `perch_decide_hold` forwarding leg 1 verbatim → `outcome: dispatched`, `dispatched: true`, receipt `resp:hunt-evt-2-r19199:lease:hunt-evt-2-r19199:isolate_host:1788619264963`; the daemon's record: `state: executed`, `outcome: granted_executed`, `audit_trail_id: trail:hunt-evt-2-r19199:1788619264963`, `governance_clearance: receipt_signature_ok`, `nostr_intent_event_id` = leg 1's card |
| the leases | daemon log 14:41:04.968 `containment leased`, `lease_id containment:hunt-evt-2-r19199:isolate_host:…`, `scope host-ops-1`, `expires_at_ms 1788620164963` — the runtime's containment TTL, **900,000 ms** after the decision instant `1788619264963`. The decision's *capability* lease (`policy.lease_ttl_ms: 60000`, W3-34's restated criterion 2) is in the daemon's decide response body; the console's `DecideOutcome` maps the receipt and not the lease, so this driver does not see it and does not claim it |
| refuse, leg 1 + 2 | `hold_031eb921-bd9c-4f32-a481-3e63deba0898` → card `671b86bb5de369eac15ceead71c5d8b510e61dffde57563d0d66e315c92d6a0b` in case `877f238f-0075-4c93-9ac3-f1aadfb89388`; leg 2 `outcome: dispatched`, `dispatched: false`, no receipt; record `state: refused`, `outcome: refused_by_operator` |
| replay | the same leg-2 body again on each hold → `replayed: true`, state unchanged |
| the relay | both cards read back from their case channels under the operator's pubkey, line 0 `<!-- swarm:verdict:v1 -->` |

Two earlier runs the same afternoon, same code: at 13:35 a refuse (`hold_d6f4203b…`) and a grant
(`hold_2c818a48…`, `granted_executed`, receipt `resp:hunt-evt-grant-2:lease:…`) both dispatched;
at 14:28 and again at 14:39 a grant answered **`refused_late`, rule `policy.scope_rate_limit`,
"scope `host-ops-1` exceeded 5 actions per minute"** — the daemon counting the hold creations of
the ingest that raised the hold as actions in the same minute. Every hold on this profile scopes
to `host-ops-1` whatever host the telemetry names, because the profile's escalation hardcodes
`isolate_host` with `host_id: host-ops-1` (`perch-hold-dev.yaml`); a demo target, not a defect. The console carried the outcome
and its rule intact. That is The hold's exit criterion 5 *outcome* reproduced live, by a
different rule than the plan's containment-refusal recipe, which still does not reproduce
(W3-35). The driver now waits out the minute before a grant, because the executed path is the
one it is there to walk; the late refusal remains a legitimate answer it accepts and records.

## The finding path (First card, Task 24 steps 4 and 5)

| Step | Evidence |
|---|---|
| the card | `ff2c280de33a7017868c11326d312a307b01af7e58cc81ac58894761234b0baf` on lane `a30249d7-446b-4135-8e9f-8704a5a052b1`, author `c194c3606ccb910e…` — one of the six identities `perch_admitted_issuers` returned; the JSON block is a B6 spine envelope (`swarm.spine.envelope.v1`) carrying the `swarm.perch.finding.v1` fact |
| `E` | `perch_mint_incident` → incident `incident:perch-case:fb850416-bc03-4b32-a851-494b3537e0a1`, case `fb850416-bc03-4b32-a851-494b3537e0a1` (`created: false` on this run — the first run of the driver at 14:16 minted it, `mint_created: True`); `hunt_id` derived as `swarm:finding:{finding_id}`, as `first-card.md` records |
| `D`, leg 1 | `perch_record_verdict` built from the relay's admitted card → verdict card `116d2f5984bf5853fd4ebb23d364a1264e2ee51856ecd2113cc1d32be2872057` in case `fb850416-bc03-4b32-a851-494b3537e0a1`; the daemon's review record unchanged |
| daemon down between the legs | the keyring's daemon URL pointed at a closed port; leg 2 `perch_finding_feedback` failed with `daemon unreachable: error sending request for url ([redacted…`; the review record unchanged; URL restored; **the retry re-sent leg 2 with the same `verdict_event_id`** and nothing re-signed leg 1 |
| the acknowledgement | only then did the review move: `reviewed_at_ms 1788619327818`, `action dismiss`, `analyst_id console`, `false_positive true` |
| unadmitted signer | the same marker and body re-published under the operator's own key as `78aa29ac0b7123d9e3cee5251fef7905aaece1d7d5510aa6c1bc9e93272a7424` — the relay stored it (it admits any authenticated key) and `perch_record_verdict` refused it: **"finding card signer is not an admitted bridge identity"** |

The daemon keeps ONE review per finding and incident and updates it in place, so the claim is
the record's timestamp moving only on the acknowledged leg, never a count.

## Found by this run, filed rather than fixed

- **W3-38** — the bridge's alarm stream is one ordered log across every case. Started on a spool
  written against the abandoned database, it retried `add_member` on a channel the fresh relay
  never had, every tick, for twenty-five minutes, and a hold created meanwhile stayed `created`
  with no notice until the spool was set aside.
- **W3-39** — a hold whose alarm steps were lost with the spool is never re-filed; the sweep ran
  for twenty-five minutes and the daemon still called it durable. It expired at its TTL.
- **W3-40** — `perch_operator_identity` had no renderer caller; the dev flow provisions keys out
  of band, and a production operator had no surface that shows the public key the daemon pins.
  Settings → Detector now shows it (and mounts the sidecar panel, which was also unmounted).
- The bridge's relay socket dropped at four publish moments (`Connection closed unexpectedly`,
  `IO error`) and re-authenticated two seconds later each time; every step then landed. Recorded,
  not ruled.
- `perch_list_holds` returns every hold the daemon has, decided and expired included; the console
  filters. Noted for whoever reads the raw list.
- `perch-hold-dev.yaml` lacked the `spine_seed_env` the spine requires; the profile is re-signed
  with it and step 12 of the recipe exports the seed.

## What this does NOT demonstrate

- **The rendered React tree on a real window.** Selecting a hold, the dwell-gated two-stroke
  grant and the two rendered leg states ran against the mock bridge, which now carries the same
  wire shapes the Rust side binds. Task 24's literal "start the actual Tauri desktop" is not met
  by a headless Tauri; it is met up to the WebKit view, and that seam is stated here rather than
  argued away. **Acceptance of First card, The hold and Operator-complete on this record is the
  owner's read, not this record's claim.** The `perch` preview flag stays off by default.
- **`refused_late` from a containment refusal** (W3-35) — the outcome reproduced by another rule.
- **`expired`** and a daemon killed between the compare-and-set and the outcome write were not
  driven; the stale hold reached `expired` on its own TTL during the session.
- The `superseded` update card and the two-screen conflict rendering were not exercised live.

## Toolchains and services

| Component | Detail |
|---|---|
| Postgres | Homebrew PostgreSQL 14 on 127.0.0.1:5433, socket `/tmp/pgh`, **fresh database `ambush_ws`** |
| Redis | Homebrew Redis on 127.0.0.1:6380 |
| Relay | `cargo build -p ambush-relay`, `AMBUSH_RELAY_PRIVATE_KEY` = the repo's dev key (`justfile`), `RELAY_URL=ws://localhost:3000`, `AMBUSH_AUTO_MIGRATE=true`, `AMBUSH_GIT_CONFORMANCE_PROBE=false` |
| Daemon | `target/debug/swarm_detect --config rulesets-dev/perch-hold-dev.yaml --serve --bind 127.0.0.1:9090`, re-attested after rebuild, spool at `/tmp/ambush-perch-dev/spool` |
| Driver | the desktop crate's lib tests on `tauri::test::MockRuntime`, Rust 1.95.0, `tauri` 2.11.5 |
