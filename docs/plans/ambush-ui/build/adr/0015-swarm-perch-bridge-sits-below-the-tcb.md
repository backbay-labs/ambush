# ADR 0015: `swarm-perch-bridge` Sits Below The Trusted Computing Base, Is Trust-Sensitive, And Is Write-Only

## Status

Proposed on 2026-08-30. Perch, Phase 0 item 0.7.

**Extends ADR 0009.** It adds one crate to `TRUST_SENSITIVE` in
`tools/check-workspace-layering.sh`, which brings that crate under rule 5 (the
`//! ## Owns` / `//! ## Does not own` requirement). It adds no crate to the TCB, changes no
allow-list, and needs no new `RESOLVED_TRANSPORT_BASELINE` entry. It also names a gap in
ADR 0009's rule 1 that this crate is the first to walk into.

Path prefix convention as in ADR 0011: `BUZZ ` is `block/buzz` at `eed74bde2`.

## Context

`swarm-perch-bridge` is the new crate that carries Ambush facts to the relay: it subscribes
to `RuntimeEvent` in-process, spools to disk, coalesces, and publishes signed Nostr events
over a WebSocket. It is a twenty-first workspace member (`Cargo.toml:3-24` declares 20
today) and it is the only new crate this project adds.

It is also the first crate in this workspace that links a network client *for the purpose
of leaving the deployment*, running inside the process that holds the containment lease map.
That is worth an ADR on its own terms.

### Fact 1: ADR 0009's transport ban does not see this crate's transports

`tools/check-workspace-layering.sh:181` sets `TCB = ("swarm-crypto", "swarm-policy",
"swarm-spine")` and `:194` sets `TRANSPORTS = ("axum", "clap", "hyper", "reqwest")` —
TCBOUND-03's four named crates, not a general notion of "network client". `tokio-tungstenite`,
`nostr` and `buzz-ws-client` are invisible to every one of the five rules. `swarm-ingest-runtime`
already names `axum` and `reqwest`, so a sibling naming a WebSocket stack trips nothing.

That is not a loophole to exploit quietly. It is a gap to name: the gate answers
"is a *named* transport declared by a TCB crate", and it will keep answering that correctly
while a different transport appears one layer up. The mitigation this ADR chooses is a
placement rule plus rule-5 coverage, not a widening of `TRANSPORTS` — widening it would
force a re-derivation of `RESOLVED_TRANSPORT_BASELINE`, whose two accepted edges
(`(swarm-spine, hyper)` and `(swarm-spine, reqwest)`) are the subject of a written
follow-up in ADR 0009 and should not be perturbed by an unrelated project.

### Fact 2: the bridge shares a process with the thing that must not die

The ingress is in-process by design. `IngestState::subscribe_runtime_events()`
(`crates/swarm-ingest-runtime/src/ingest/mod.rs:1875-1882`) returns
`Option<broadcast::Receiver<RuntimeEvent>>` over a channel built once at
`crates/swarm-runtime-http/src/bin/swarm_detect.rs:726` with
`DEFAULT_RUNTIME_EVENT_CAPACITY = 1_024` (`crates/swarm-runtime/src/runtime_events.rs:13`)
and cloned into `IngestState` at `:752`. Choosing this over the HTTP route deletes four
problems at once: the absent CORS layer, the wildcard-`ACAO` unauthenticated
`/v1/events/stream`, an ALPN-pinned HTTP/1.1 hostile to long-lived SSE, and a network hop.

The cost is that the bridge's failures are the daemon's failures. `Cargo.toml:139-141` sets
`panic = "abort"` and `overflow-checks = true` for the release profile, and
`tools/verify-release-hardening.sh:23-24` proves `-C panic=abort` actually reaches the
release `rustc` invocation for the shipped binaries. **`catch_unwind` cannot help.** A
panic anywhere in the bridge — including inside a dependency's WebSocket frame handling —
aborts `swarm_detect --serve`, the process that holds the containment lease map, the
receipt counter and `previous_commit_hash`.

`BUZZ crates/buzz-ws-client/src/connection.rs` — the 314-line NIP-42 client the plan set
names for egress (`00-BRIEF.md` §4.6) — contains four production panic sites: `.unwrap()`
at `:170` and `:229` and `unreachable!()` at `:172` and `:231`, all four inside the same
two `match self.buffer.remove(idx).unwrap()` blocks.
`tools/check-runtime-panic-contract.sh` scans production code in `crates/*/src` of **this**
workspace and matches only `.unwrap(` and `.expect(` — its header says `unreachable!` is
deliberately out of scope. So consumed as an external dependency, all four are invisible to
the gate and live inside the daemon.

### Fact 3: lag is dropped silently, in three places, and nothing counts it

`RuntimeEventBroadcaster::publish` is `let _ = self.tx.send(event)`, discarding the
no-receiver error (`runtime_events.rs:105-123`). Both existing subscribers —
`platform_findings_stream_handler` (`ingest/platform_api.rs:1388`) and
`runtime_events_handler` (`ingest/demo.rs:1689`) — do
`let Ok(event) = result else { return None; }`, and `rg` over `crates/` finds **zero**
matches for `Lagged` or `RecvError` anywhere in the workspace. A slow consumer loses frames
and learns nothing.

For a chat product a dropped frame is a performance problem. Here it produces the exact
failure `00-BRIEF.md` §8.1 forbids: a coherent, signed, **incomplete** story with nothing
marking the gap.

## Decision

**`swarm-perch-bridge` is a sibling of `swarm-ingest-runtime`, strictly downstream of the
trusted computing base, added to `TRUST_SENSITIVE`, and write-only.**

**C1. Placement.** The crate depends on `swarm-core` and `swarm-ingest-runtime` and on
whatever it needs for egress. **No TCB crate may depend on it, in any dependency kind.**
That is already enforced by ADR 0009 rule 2, which derives "above the TCB" from
`cargo metadata` rather than from a list, so the bridge is classified by its edges on the
commit that adds it. This ADR asserts the property and adds no exemption.

**C2. `swarm-perch-bridge` joins `TRUST_SENSITIVE`.** The argument is `swarm-pheromone`'s,
one object over: ADR 0009 puts `swarm-pheromone` in that list because "a forged or flooded
deposit changes what the detection lane concludes". A dropped or forged card changes what
the **operator** concludes, and the operator is the party who authorizes destructive
actions. One line in the registry at `tools/check-workspace-layering.sh:184-192`, and rule 5
then requires the crate's `lib.rs` to carry the literal `//! ## Owns` and
`//! ## Does not own` headings — which is the mechanism that stops the next contributor
from adding a read path to it.

Its `Owns` line is: the in-process `RuntimeEvent` subscription, the disk spool, the
per-issuer sequence, the coalescer, the Nostr identities, and the publish path. Its
`Does not own` line is: deciding anything, reading anything from the relay, and the
contents of a card body beyond the schema it is handed.

**C3. Write-only. Zero `REQ` frames, zero `COUNT` frames, ever.** This is
`11-BRIDGE-CRATE.md`'s decision 6 and it is recorded here because it is a boundary property,
not an implementation choice. Three things follow: the bridge cannot learn who the operators
are (so the `p`-tag mapping is a config problem, not a bridge problem — see Follow-On);
the bridge cannot read back what it published (so reconciliation is the console's job
against the daemon, per ADR 0012 clause 3); and the bridge's WebSocket admission budget is
spent on `EVENT` frames only. That last one matters:
`BUZZ crates/buzz-relay/src/connection.rs:671-681` charges **every** inbound `EVENT`, `REQ`
and `COUNT` frame against a 50-frames-per-5-second budget
(`BUZZ crates/buzz-relay/src/admission.rs:9,40-45`: `WS_BURST_WINDOW_SECS = 5` ×
`human_ws_events_per_sec = 10`) with **no** agent exemption. A bridge that opened one `REQ`
per case channel on reconnect could exhaust its own publish budget before sending a frame.

**C4. The receive loop imports `stream`, `spool` and `metrics`, and nothing else.** It
cannot acquire a network call by accident, because the module it lives in cannot name one.
It does exactly `recv` → classify → append-to-spool. Network I/O happens on a separate task
reading the spool. This is what makes "the bridge must never be the slow consumer"
(`00-BRIEF.md` §4.3 item 2) a structural property rather than a performance hope.

**C5. `subscribe_runtime_events()` returning `None` is a startup failure, loudly.** `None`
means no broadcaster is wired; a bridge that idles in that state publishes nothing and
reports nothing, which is the worst available behaviour. It mirrors
`OperatorAuthState::from_config`'s `MissingTokenEnv`
(`crates/swarm-runtime-http/src/http/auth.rs:57-82`) and the reason
`swarm_detect.rs:1127-1132` logs a containment-router build failure loudly rather than
shipping a daemon with no release route.

**C6. The relay egress is vendored into `crates/`, and its four panic sites become typed
errors, before any bridge logic is written.** Both repositories are Apache-2.0, so this is
a licensing non-event; `BUZZ crates/buzz-ws-client` is 564 lines across four files and
low-churn, so the rebase cost is small and bounded. Vendoring is what puts the code under
`tools/check-runtime-panic-contract.sh`, which is the only mechanism that keeps it panic-free
as it changes. The two `unreachable!()` sites are outside that gate's stated scope and are
therefore a review item named here explicitly rather than left to be caught.

**C7. The spool writes to a configured directory and never defaults into the repository.**
`tools/check-worktree-clean.sh` runs after the test job and fails on a stray artifact, so a
spool that defaults to `./` turns every local test run into a red build.

## Alternatives Considered

**Run the bridge as its own process, consuming `/v1/events/stream`.** Removes the panic
blast radius entirely and is the reason it is tempting. Rejected on four counts, all
measured: the route is wildcard-`CORS`'d on every response including error paths
(`with_demo_cors`, `ingest/demo.rs:361-369`, 26 call sites); its scope check inverts —
`resolve_demo_scope` (`ingest/mod.rs:636-652`) returns `Ok(requested_scope)` with no
verification when `context_token` is absent, and `runtime_event_matches_scope` short-circuits
`true` on an empty scope (`:699-701`), so an **anonymous** caller receives `TamperAlert`,
`AgentHealth` and `EvolutionStatus` while a token-bearing scoped caller is denied all three
at `:766-768`; its SSE `id` is `emitted_at_ms` (`demo.rs:1703`), a millisecond timestamp that
collides at the monitor's 10 Hz cadence and is not monotonic across issuers, so a consumer
cannot detect a gap; and it adds a hop whose failure mode is the silent lag-drop of Fact 3
with a network in the middle. C6 addresses the panic blast radius directly instead.

**Widen `TRANSPORTS` to include `tokio-tungstenite` and `nostr`.** Would make ADR 0009's
rule 1 see the new stack. Rejected for now: the rule bans transports **in the TCB**, and no
TCB crate will name these; widening the list would force a re-derivation of
`RESOLVED_TRANSPORT_BASELINE` for an unrelated reason and risks a stale-baseline failure
that has nothing to do with this project. Recorded as follow-on work, not declined outright.

**Put the bridge inside `swarm-ingest-runtime`.** Cheapest by file count. Rejected: that
crate is already the composition point for the daemon's HTTP surface and its `IngestState`
has 30-odd private fields; adding an outbound network publisher to it makes the "does not
own" boundary unwritable, and rule 5 would then have nothing to enforce.

## Consequences

### Positive

- The bridge is classified by its edges, on the commit that adds it, by a gate that already
  runs on every PR.
- Rule 5 gives it a written boundary that a reviewer can hold a PR to — the same instrument
  that keeps `swarm-response` honest about owning execution but not the decision.
- Write-only makes the crate's whole attack surface one direction. It cannot be induced to
  read a case it is not entitled to, because it has no read path at all.

### Negative

- A panic in the bridge aborts the daemon. C6 reduces the probability; it does not change
  the topology. This is the price of in-process ingress and it should be stated in the
  crate's own module doc, not only here.
- `TRUST_SENSITIVE` membership is a documentation obligation the gate checks textually
  (ADR 0009 rule 5 requires the exact heading lines). A crate can satisfy it with a stale
  section. That is a known weakness of rule 5 and it is not this ADR's to fix.
- Vendoring the WebSocket client creates a second rebase surface alongside the desktop
  fork. It is 564 lines against 322,393, so it does not change the K2 arithmetic
  meaningfully — but it is a second thing, and D5's named rebase owner owns both.

## Verification

- `tools/check-workspace-layering.sh` already proves it can fail before it is trusted to
  pass: ten fixture cases, one control and nine deliberately broken, including
  "a trust-sensitive crate losing its Owns section is caught". Adding
  `swarm-perch-bridge` to `TRUST_SENSITIVE` inherits that fixture unchanged.
- `tools/check-runtime-panic-contract.sh` covers the vendored egress from the commit that
  vendors it (its enumeration is `crates/*/src`, both `.rs` and `.inc`).
- `tools/check-gates-wired.sh` enumerates every `tools/check-*.sh` — tracked **or
  untracked** — and fails on any not named by a real workflow `run:` step. **Every new gate
  this project proposes must land with its workflow edit in the same PR**, or CI fails in a
  way that looks like the gate is broken. That is decision D9 and it applies to all four
  scripts the plan set proposes, none of which exists today.
- **PROPOSED** a test asserting the receive-loop module's import set, so C4 is mechanical.

## Follow-On Work

- **`tools/check-copy-banned-terms.sh` does not exist in either repository, and the count
  in revision 1 was wrong.** `APPENDIX-NORMATIVE.md` §2 and §7 name it as the enforcing gate
  for the vocabulary bans and the banned verdict key. Re-measured this session: this
  workspace's `tools/` holds **23 files, of which 14 are `check-*.sh` and one is
  `verify-*.sh`** — revision 1 read the directory count as the script count — and
  `block/buzz` has no `tools/` directory at all. `16-INVARIANT-TESTS.md` now ships the
  AMBUSH-side script and `copy-ban-list.tsv` as skeletons, so the remaining gap is
  **`BUZZ desktop/scripts/check-copy-banned-terms.mjs`**, which that artifact's decision D2
  requires to read the same TSV byte for byte and to return identical verdicts over
  `tools/fixtures/copy-corpus/`. That parity test cannot exist until the `.mjs` half is
  written; it is the one missing gate another delivered artifact depends on. Until then every
  vocabulary ban and `08` INV-31 is advisory. Proposed brief amendment **AD-A4**.
- **`check-perch-write-allowlist.sh` gains a rule it does not have today**, and it is the
  mechanism ADR 0014 C1 obligation 3 depends on: every `#[tauri::command]` in
  `desktop/src-tauri/src/commands/` that reaches `state.signing_keys()` **and** takes a
  parameter named `content` must call `perch_sign_gate` in the same function. The baseline is
  the 33 call sites across 17 files measured in ADR 0014 Fact 3. Like every gate here it must
  land with its workflow `run:` step in the same commit, per `tools/check-gates-wired.sh`.
- Consider whether ADR 0009's `TRANSPORTS` should become a derived notion (any crate
  reaching a socket) rather than four names, and re-baseline deliberately if so.
- The `p`-tag mapping. `OperatorPrincipalConfig`
  (`crates/swarm-core/src/config/operator.rs:118-129`) is
  `{operator_id, token_env, token_expires_at_ms?, scopes}` with
  `#[serde(deny_unknown_fields)]`, and `grep -rn 'pubkey|npub|nostr'` over
  `crates/swarm-core/src/config/` returns nothing. `APPENDIX-NORMATIVE.md` §4 layer 1
  requires the bridge to `p`-tag every principal holding `OperatorScope::Approve` via
  `effective_principals()` (`operator.rs:153-168`), which yields operator ids and
  environment-variable names, never 32-byte Nostr public keys. Because C3 forbids the bridge
  from reading anything, it cannot discover the mapping either. **The fix is a typed config
  field — `nostr_pubkey: Option<String>` on `OperatorPrincipalConfig`, `#[serde(default)]` —
  and it is a bill item nobody budgeted.** The alternative, a bridge-local
  `operator_id → npub` map, is an unsigned trust root the entire hold-delivery path depends
  on, and a wrong entry means the hold reaches nobody, silently (ADR 0012's negative
  consequence). Sized in `21-ADRS.md` question 3.
