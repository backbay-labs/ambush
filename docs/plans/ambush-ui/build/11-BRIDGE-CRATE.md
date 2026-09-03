# 11 — `swarm-perch-bridge`, the crate

**Status:** buildable design. Skeleton source under
`docs/plans/ambush-ui/build/skeleton/swarm-perch-bridge/`.
**Owns:** the bridge's module layout, its four transport streams, the spool format, the
coalescer, the pacer, the identity table, the relay write path, its metrics, and its failure
modes. **Cites, never restates:** `APPENDIX-NORMATIVE.md` §3 (wire registry), §4 (how a hold
reaches one human), §6 (shared constants), §7 (vocabulary), §8 (render laws).
**Does not own:** the on-wire card bodies (`13-WIRE-SCHEMAS.md`), the daemon routes the console
calls (`12-BACKEND-BILL-API.md`), the relay patch (`10-RELAY-FORK.md`), or anything the console
does (`14-CLIENT-ARCHITECTURE.md`).

Every `path:line` below was read from source this session against
`BUZZ` @ `eed74bde2` and the `AMBUSH` working tree. Where I propose rather than report, the
line says **PROPOSED**.

### Revision 2 — what changed after red-team review, and what was rebutted

Four changes are substantive. Each is argued at the section named, from source re-read this
session, not from the review note.

| # | Change | Section | Why it was wrong |
|:-:|---|---|---|
| 1 | The skeleton's `//! # ## Owns` / `//! # ## Does not own` headings lose the stray `# `, and **RULE 5 is documented as applying**, not as inapplicable | §1.4 row 5, new §1.4a | ADR 0015 puts this crate in `TRUST_SENSITIVE`, and `check-workspace-layering.sh:237-238` matches the two literals as exact whole lines. The old headings would have failed the layering gate in the commit that lands the crate. The gate's own predicate was executed against the corrected file |
| 2 | Case-channel creation gains a **second trigger**. `channels.rs` exposes one entry point, `ensure_case_channel`, taking a two-arm `CasePromotionTrigger`; the second arm is a new bill item **B1d** | §9.1 (rewritten, six subsections) | The first draft fired only on `RuntimeEvent::ResponseHeld`. ADR 0018 C4 enables **only manual promotion** in the first build, and manual promotion emits no `ResponseHeld` — so on the only enabled clause nothing created the channel, and `IncidentMintRequest` requires a `case_id` that would never exist |
| 3 | §8.6 is rewritten from "here is a hole somebody else owns" to a **reconciliation of the two competing fixes**, with the enforcement path measured on both the publish and the subscribe side | §8.6 | `13-WIRE-SCHEMAS.md`'s W-1 (`h` tag) and ADR 0017 (`P_GATED_KINDS`) each read as the whole answer. They are not the same mechanism and only one protects the subscription the console opens — and the `h` tag turns out to cost three provisioning obligations nobody had written down, one of which reaches a human as a relay `CLOSED` |
| 4 | `hold_id` gets a shape assert at the publish seam (`HoldId::parse`), and `#watch` gains three provisioning items and three failure modes | §8.3 items 8–10, §8.6, §12 F19–F21 | Six `hold_id` formats are in circulation across the wave-2 artifacts, two of them using the `hold:` prefix the schemas warn against; and an `h`-tagged `26006` makes publisher membership a hard precondition nobody had written down |

**Two review claims are rebutted with evidence, in the artifact rather than in a reply**, so the
objections cannot recur:

- *"INV-RF1 restricts the operator key to one published kind, so the console cannot create the case
  channel."* — `10-RELAY-FORK.md` §9.3 explicitly places `kind:9007` channel creation **outside**
  INV-RF1. What actually forbids a console-side create is a membership fact in
  `create_channel_with_id`. §9.1.3.
- *"Applying both `26006` fixes closes the subscription entirely."* — it does not. The
  `P_GATED_KINDS` gate at `req.rs:219` runs only when `channel_id.is_none()`, and an `#h`-carrying
  filter resolves a channel id at `req.rs:1153-1180`. `{kinds:[26006],"#h":[watch]}` and
  `{kinds:[26006],"#h":[watch],"#p":[me]}` both pass; a bare `{kinds:[26006]}` is refused. §8.6.

---

## 0. The one sentence

`swarm-perch-bridge` is a library crate in the Ambush workspace that subscribes **in-process** to
`RuntimeEvent`, classifies each event into exactly one of four streams by an exhaustive `match`
with no `_` arm, appends it to a bounded disk spool before any network I/O, and drains that spool
through a 1 Hz pacer that stamps `created_at`, signs a Nostr envelope, and writes it to the Buzz
relay over a NIP-42 WebSocket.

Every design decision below follows from one measured fact and its consequence:

> `DEFAULT_RUNTIME_EVENT_CAPACITY = 1_024`
> (`AMBUSH crates/swarm-runtime/src/runtime_events.rs:13`) is the capacity of the
> `tokio::sync::broadcast` channel that `RuntimeEventBroadcaster::publish`
> (`runtime_events.rs:116-118`, called in the `swarm_detect --serve` process by the concentration
> monitor, the dispatcher and the ingest path) writes into with `let _ = self.tx.send(event);` —
> the return value, and therefore every "no receivers" signal, is discarded. On the receive side a
> slow subscriber is served `Err(RecvError::Lagged(n))` and **`rg 'Lagged|RecvError'` over
> `AMBUSH crates/` returns zero matches**: both shipped subscribers
> (`ingest/demo.rs:1688-1691` serving `GET /v1/events/stream`, and
> `ingest/platform_api.rs:1387-1390` serving `GET /v2/api/stream/findings`) write
> `let Ok(event) = result else { return None; };` and throw the lag away.
>
> At the measured hot-path rate of 3,645 events/sec (`AMBUSH README.md:536`), 1,024 slots are
> **281 ms** of head room. Any TLS handshake, any DNS lookup, any `fsync`-per-record, any relay
> round trip inside the receive loop exceeds it — and the loss is silent, uncounted and
> unrecoverable.

So the receive loop does three things and nothing else: `recv()`, classify, append. Everything
that can block is downstream of a disk write.

---

## 1. Where the crate sits

### 1.1 Process

One process: **`swarm_detect --serve`**. Not `swarmctl serve`.

This is not a preference. `IngestState::subscribe_runtime_events()`
(`AMBUSH crates/swarm-ingest-runtime/src/ingest/mod.rs:1874-1881`) returns
`Option<tokio::sync::broadcast::Receiver<RuntimeEvent>>` by calling
`RuntimeEventBroadcaster::subscribe` on the `Option<RuntimeEventBroadcaster>` field that
`IngestState::with_runtime_events` installed. That broadcaster is constructed exactly once, at
`AMBUSH crates/swarm-runtime-http/src/bin/swarm_detect.rs:726`
(`RuntimeEventBroadcaster::new(DEFAULT_RUNTIME_EVENT_CAPACITY)`), and cloned into both the
`IngestState` (`:753`, `.with_runtime_events(runtime_events.clone())`) and the `AgentDispatcher`
(`:767`). `LocalOperatorSurface` (`swarm-runtime-http/src/http/state.rs:106`, served by
`swarm-cli/src/core.inc:3344-3400` on `127.0.0.1:7766`) builds its own control plane in its own
process and holds **no** broadcaster at all. A bridge mounted there would subscribe to nothing.

`crates/swarm-runtime-http/src/http/containment.rs:19-33` already writes the general form of this
argument for the containment routes, and it applies verbatim here.

### 1.2 Mount point

Beside the containment router, in the same block, for the same reason. `swarm_detect.rs:1100-1143`
binds one listener and assembles one router; the bridge is spawned as a background task next to
the concentration monitor (`swarm_detect.rs:1002-1006`) and the containment sweep
(`:1061-1075`), and its metrics router is merged the way `containment_operator_router` is merged
at `:1113-1125`.

```rust
// swarm_detect.rs, PROPOSED insertion, immediately after the containment-sweep block
// (currently ends at :1075) and before `let bridge_metrics = ...` at :1076.
//
// admitted_identities is the Vec<AgentId> assembled at :768-962 and handed to
// dispatcher.set_admitted_identities(...) at :963. The bridge is built from a CLONE of it,
// so evidence cards are attributed to the same agent identities the dispatcher admitted.
let mut perch_bridge_handle = match swarm_perch_bridge::PerchBridge::build(
    swarm_perch_bridge::BridgeBuildInput {
        config: config.perch.clone(),
        colony_id: config.name.clone(),
        events: state.subscribe_runtime_events(),
        admitted_identities: admitted_identities.clone(),
        containment: containment_sweep.clone(),
        shutdown: shutdown_rx.clone(),
    },
) {
    Ok(Some(bridge)) => {
        router = router.merge(bridge.metrics_router());
        tracing::info!(module = module_path!(), "perch bridge started");
        Some(tokio::spawn(async move { bridge.run().await }))
    }
    Ok(None) => {
        tracing::info!(module = module_path!(), "perch bridge disabled in config");
        None
    }
    // Loud, and FATAL. See §12 row F1: a bridge that cannot start is a console with no
    // evidence and a hold nobody is shown. `containment_operator_router`'s failure is
    // logged and survived because the runtime still refuses to contain what it cannot
    // hold under a containment lease; there is no equivalent backstop here.
    Err(error) => return Err(Box::new(error)),
};
```

Shutdown follows the house pattern exactly: `tokio::sync::watch::Receiver<bool>` in,
`await_background_task("perch_bridge", handle)` (`swarm_detect.rs:623-637`, 30 s
`GRACEFUL_SHUTDOWN_TIMEOUT_SECS`) in the `tokio::select!` arms at `:1150+`.

`admitted_identities` is a plain local `Vec<AgentId>` in `main`, so cloning it costs nothing and
introduces no ordering constraint; it is already fully populated at `:963`.

### 1.3 Dependency edges

```
                 swarm-runtime-http  (the binary: swarm_detect)
                          │
        ┌─────────────────┼──────────────────────┐
        ▼                 ▼                      ▼
 swarm-ingest-runtime  swarm-runtime      swarm-perch-bridge   ◄── NEW
        │                 │                      │
        └────────┬────────┘                      │
                 ▼                               │
          swarm-response ◄─────────────────────  ┤
                 │                               │
                 ▼                               ▼
            swarm-core ◄─────────────────────────┘

 third-party, new to the workspace:  nostr, tokio-tungstenite, url, futures-util(*), prometheus-client(*)
 (*) already workspace dependencies
```

**Declared dependencies** (the full manifest is in the skeleton's `Cargo.toml`):

| Dependency | Why, precisely |
|---|---|
| `swarm-runtime` | `RuntimeEvent`, `RuntimeEventKind`, `EscalationLevel`, `RuntimeThreatConcentration` (`runtime_events.rs:186-338`); `containment::ContainmentSweep::open_leases()` (`containment.rs:537-539`) |
| `swarm-response` | `ContainmentLease` (`containment.rs:130-138`) for the lease card |
| `swarm-core` | `AgentId` (`types.rs:9-23`), `Severity` (`types.rs:407-414`), `ResponseAction::kind()` (`types.rs:559-577`), `ThreatClass`, `AgentRole`, `SwarmMode`, `AgentHealth`, `SecretString` (`config/secrets.rs:9`), and the new `PerchBridgeConfig` |
| `nostr` | event construction, secp256k1 signing, NIP-42 AUTH |
| `tokio-tungstenite`, `futures-util`, `url` | the vendored WebSocket client (§8.1) |
| `tokio`, `serde`, `serde_json`, `thiserror`, `tracing`, `hex`, `sha2`, `uuid` | workspace-standard |
| `prometheus-client` | the `perch`-prefixed registry (§11) |

**Deliberately NOT declared:**

- **`swarm-ingest-runtime`.** The bridge takes an
  `Option<broadcast::Receiver<RuntimeEvent>>` as a build input rather than an `IngestState`. That
  keeps the crate testable from a plain `broadcast::channel(16)` in a unit test, and it keeps the
  dependency arrow one-way: `swarm-runtime-http → swarm-perch-bridge`, never back.
- **`swarm-runtime-http`.** Naming it would be a cycle (`swarm-runtime-http` mounts the bridge).
  This is why the lease card is built from `swarm_response::ContainmentLease` and **not** from
  `swarm_runtime_http::http::containment::ContainmentLeaseView` (`containment.rs:72-88`). The two
  fields that view adds — `remaining_ms` and `expired` — are clock-derived, and
  `APPENDIX-NORMATIVE.md` §3 already forbids baking them into an immutable card.
- **`swarm-spine`.** Nothing the bridge receives is an `AuditTrail`;
  `RuntimeEvent::ResponseExecution` (`runtime_events.rs:263-275`) carries eleven flat fields
  including `receipt_id: Option<String>` and `policy_verdict`. Not naming a TCB crate keeps §1.4
  trivial.
- **`reqwest` / `axum` / `hyper` / `clap`.** The bridge has no HTTP client and no HTTP handlers
  of its own beyond one `axum::Router` it *returns* — see §11.3 for why that is a
  `swarm_runtime_http`-side edit rather than an `axum` dependency here.

### 1.4 `tools/check-workspace-layering.sh` — the rule, quoted, and the verdict

The gate is a shell wrapper around an embedded Python engine
(`AMBUSH tools/check-workspace-layering.sh:155-601`), run in CI over `cargo metadata`. Exit 0
holds, 1 violated, 2 vacuous. Its policy block is `:180-233`:

```python
# ADR 0009 / TCBOUND-01.
TCB = ("swarm-crypto", "swarm-policy", "swarm-spine")

TRUST_SENSITIVE = (
    "swarm-policy", "swarm-pheromone", "swarm-response",
    "swarm-guard", "swarm-crypto", "swarm-spine",
)

# TCBOUND-03's four named transport/CLI crates.
TRANSPORTS = ("axum", "clap", "hyper", "reqwest")
```

Five rules. Each is quoted from the violation message it emits, followed by the verdict for
`swarm-perch-bridge`.

| # | Rule id | The rule, as the gate states it | Verdict |
|:-:|---|---|---|
| 1 | `tcb-declared-transport` (`:405-414`) | *"the TCB must never name a transport or CLI crate in any dependency section (ADR 0009, TCBOUND-03)"* — iterated over `for crate in sorted(TCB)` | **Cannot fire.** Scoped to the three TCB crates' own manifests. `swarm-perch-bridge` is not one and names none. |
| 2 | `tcb-declared-downstream` (`:416-492`) | *"the TCB may name only crates below it, and adding one is a deliberate, reviewable act"*. The allow-list at `:445-465` is `swarm-crypto: {}`, `swarm-policy: {swarm-core}`, `swarm-spine: {swarm-core, swarm-crypto, swarm-policy, swarm-response, swarm-whisker}` | **Cannot fire.** The rule is an allow-list over what a TCB crate *declares*. No TCB manifest names `swarm-perch-bridge`, and this design never asks one to. |
| 3 | `tcb-resolved-transport-new` / `-stale` (`:494-519`) | *"{crate} reaches transport '{transport}' on the resolved NORMAL graph and that edge is not on the accepted baseline"* — computed as `reached = {name(i) for i in reach_cache[crate]} for crate in TCB`, against `RESOLVED_TRANSPORT_BASELINE = {("swarm-spine","hyper"), ("swarm-spine","reqwest")}` (`:219-233`) | **Cannot fire.** Reachability is measured *out of* each TCB crate. `swarm-perch-bridge` is strictly downstream — `swarm-runtime-http → swarm-perch-bridge → swarm-runtime → swarm-policy` — so no TCB crate reaches it, and nothing it pulls enters any TCB closure. This is the load-bearing half of `00-BRIEF.md` §4.6's claim, and it is stronger than that claim: it does not depend on `tokio-tungstenite` and `nostr` being absent from `TRANSPORTS` (they are, `:194`), it depends on the direction of the arrow. |
| 4 | `advisory-declared` / `advisory-resolved` (`:521-545`) | *"the advisory lane must never gate the critical path (ADR 0009, TCBOUND-04)"* — note that ADR 0009's *advisory lane* is an upstream term of art for the `sphinx_agent` / `correlation` modules and is unrelated to Perch's ruled word for a threat-class channel — `ADVISORY_CONSUMERS = ("swarm-policy", "swarm-response")` must neither declare nor reach the crates hosting `crates/swarm-runtime/src/sphinx_agent.rs` and `crates/swarm-runtime/src/correlation.rs` | **Cannot fire.** Neither advisory consumer gains an edge. |
| 5 | `missing-owns-section` (`:547-567`) | *"{crate}/src/lib.rs crate-level doc comment is missing '//! ## Owns' and '//! ## Does not own' (TCBOUND-02)"* — iterated over `TRUST_SENSITIVE` | **APPLIES.** ADR 0015 adds this crate to `TRUST_SENSITIVE`. See §1.4a — the heading literals are exact, and turning the rule on is a three-part edit to the gate. |

#### 1.4a RULE 5 applies to this crate, and turning it on is three edits, not one

**A correction to an earlier draft of this document, and to the skeleton.** The first version of
`skeleton/swarm-perch-bridge/src/lib.rs` wrote its headings as `//! # ## Owns` and
`//! # ## Does not own`, and this table's row 5 said RULE 5 "does not apply". Both were wrong once
ADR 0015 landed, and together they would have failed the layering gate in the very commit that adds
the crate. The headings are fixed and the mechanism is written down here so the mistake cannot
recur.

`:237-238` sets the two literals:

```python
OWNS_HEADING = "//! ## Owns"
NOT_OWNS_HEADING = "//! ## Does not own"
```

and RULE 5 (`:549-565`) does an **exact whole-line** membership test after right-stripping:

```python
for crate in sorted(TRUST_SENSITIVE):
    lib_rs = os.path.join(member_dirs[crate], "src", "lib.rs")
    ...
    lines = [line.rstrip("\n").rstrip() for line in handle]
    absent = [h for h in (OWNS_HEADING, NOT_OWNS_HEADING) if h not in lines]
```

A leading `# `, a `###`, or a trailing non-whitespace character all fail it. Every shipped
`TRUST_SENSITIVE` crate gets it right — `crates/swarm-pheromone/src/lib.rs:14` and `:24` are the
model. Verified against the corrected skeleton by executing the gate's own predicate:

```console
$ python3 -c "lines=[l.rstrip() for l in open('src/lib.rs')]; \
    print([(h, h in lines) for h in ('//! ## Owns','//! ## Does not own')])"
[('//! ## Owns', True), ('//! ## Does not own', True)]
```

**Adding the crate to `TRUST_SENSITIVE` is three edits to `check-workspace-layering.sh`, in one
commit.** The single-edit version fails, and it fails *before* the gate ever looks at the real
workspace:

| # | Edit | What happens without it |
|:-:|---|---|
| 1 | the `TRUST_SENSITIVE` tuple, `:184-191` | RULE 5 never evaluates this crate — the hole ADR 0015 closes |
| 2 | a `FIXTURE_CRATES` row, `:618-633` | the self-test builds a throwaway fixture workspace (`build_fixture`, `:639-690`) that does **not** contain this crate, so the vacuity guard at `:289-294` raises `Vacuity("policy names crates that are not workspace members, so the rules about them could never fire: swarm-perch-bridge")`. The clean-fixture control case (`fixture_case "clean fixture passes" 0`, `:794`) then fails, and `:858-863` exits 1 with *"The gate's own rules are not behaving as documented … Fix the engine first."* |
| 3 | `FIXTURE_DOCUMENTED`, `:637` | the fixture stub for this crate is written without the two headings (`:659-671` writes them only for crates named in that list), so the same control case fails with `missing-owns-section` |

The `FIXTURE_CRATES` row should mirror the real manifest —
`swarm-perch-bridge|swarm-core swarm-runtime swarm-response` — so the fixture exercises the same
shape the real graph has. Nothing in RULES 1–4 fires on it: `TRUST_SENSITIVE` membership is read
only at `:285` (the vacuity guard's name union) and `:549` (RULE 5). It is not a TCB tuple and
carries none of the TCB's constraints.

**Vacuity guards** (all exit 2, not 1) and their verdicts:
`:289-294` every policy-named crate must be a workspace member — **this is the guard edit 2 above
satisfies**; on the real workspace it holds the moment the crate is a member. `:298-304` every
`TRANSPORTS` name must exist somewhere in the graph — still true. `:352-363` all three
`NAMED_PRODUCT_CRATES` must be among the derived downstream set — adding a 21st member does not
remove any of them. `:374-379` both `ADVISORY_MODULES` paths must exist — untouched.

**ADR 0009's boundary, quoted** (`AMBUSH docs/decisions/0009-trusted-computing-base-boundary.md:133-136`):

> `swarm-core` is inside the TCB *closure* and is enforced as such by rule 1 — a transport added
> to `swarm-core` fails this gate — but it is not itself named TCB, because it is the workspace's
> shared type vocabulary and every crate depends on it.

The one consequence that binds this crate: **`swarm-perch-bridge` may add a field to `swarm-core`
(the config block, §13) but may never add a dependency to it.** A transport named by `swarm-core`
fails RULE 1 for all three TCB crates at once. The config block is pure `serde` types over
`String`/`u64`/`bool` and adds no dependency.

`02-ARCHITECTURE-INTEGRATION.md` decision 3 states the target — *"legal under
`tools/check-workspace-layering.sh` by construction, not by exemption"* — and the table above is
that claim discharged rule by rule.

### 1.5 The supply-chain bill, and one measurement that could delete it

`AMBUSH deny.toml:31-33` sets `multiple-versions = "deny"` and `wildcards = "deny"`.
`02-ARCHITECTURE-INTEGRATION.md` decision 6 records one expected duplicate: *"`nostr 0.44.7` pulls
`chacha20 0.9.1` against Ambush's locked `chacha20 0.10.1`"*. Both halves verified —
`BUZZ Cargo.lock:5867-5868` locks `nostr 0.44.7`, `BUZZ Cargo.lock:1582-1584` carries
`chacha20 0.9.1`, `AMBUSH Cargo.lock:381-383` carries `chacha20 0.10.1`.

**But `BUZZ Cargo.toml:72` declares `nostr = { version = "0.44", features = ["nip44", "nip98"] }`
— `nip44` is an opt-in feature, and NIP-44 is where `chacha20` enters.** The bridge needs neither
NIP-44 nor NIP-98; it needs event construction, secp256k1 signing and NIP-42 AUTH. So the
skeleton's manifest declares:

```toml
nostr = { version = "0.44", default-features = false, features = ["std"] }
```

**PROPOSED, unmeasured** — the `nostr` crate source is not present in this environment, so I will
not assert that this deletes the duplicate. The measurement is three commands and it should be run
before the crate's first commit, because a clean result deletes a standing bill item:

```bash
cargo tree -p swarm-perch-bridge -i chacha20 -e normal   # expect: nothing
cargo tree -p swarm-perch-bridge -i hyper     -e normal   # expect: nothing (tokio-tungstenite has no hyper edge)
cargo deny check bans
```

Two further duplicates to measure in the same pass, neither recorded anywhere in the plan set:
`tokio-tungstenite`'s `rand` generation against Ambush's `rand_core 0.6`
(`AMBUSH Cargo.toml:85`), and `tungstenite`'s `base64` against Ambush's `base64 0.22`
(`Cargo.toml:79`). Each is either absent, or one dated `[[bans.skip]]` entry argued in review in
the shape `deny.toml:35-49` already documents. **Do not reach for `-A duplicate`**; `deny.toml`'s
own comment explains at length why that turns the gate into a no-op.

---

## 2. Module layout

```
crates/swarm-perch-bridge/
├── Cargo.toml
└── src/
    ├── lib.rs           PerchBridge, BridgeBuildInput, run(); the //! ## Owns headings.  ~180
    ├── error.rs         BridgeError, one typed variant per failure mode in §12.           ~120
    ├── config.rs        PerchBridgeConfig mirror + resolution against the environment.    ~200
    ├── stream.rs        Stream, classify(&RuntimeEvent) -> Stream. EXHAUSTIVE, no `_`.    ~140
    ├── receive.rs       THE receive loop. recv / classify / append. Nothing else.         ~150
    ├── spool/
    │   ├── mod.rs       Spool trait, DiskSpool, MemorySpool, Cursor, GapSlot.             ~320
    │   ├── segment.rs   Segment header, record framing, torn-tail recovery.               ~330
    │   └── checksum.rs  CRC-32C, table-driven, no new dependency.                          ~60
    ├── coalesce.rs      10 Hz -> 1 Hz, edge-trigger, tallies, the accounting invariant.   ~340
    ├── pacer.rs         1 Hz tick, front-run packing, 64 KB frames, created_at stamping.  ~280
    ├── identity.rs      The identity table, key derivation, p-tag normalization.          ~240
    ├── cards.rs         Marker card assembly. Body schemas are 13-WIRE-SCHEMAS.md's.      ~260
    ├── channels.rs      Case-channel provisioning on both triggers; HoldId; kind 9007
    │                    + kind 9000, idempotent.                                          ~280
    ├── leases.rs        1 Hz containment-lease diff -> ambush:lease:v1.                   ~180
    ├── publish.rs       Connection supervisor, OK reaper, backoff, admission handling.    ~380
    ├── metrics.rs       prometheus-client Registry::with_prefix("perch") + axum router.   ~220
    └── ws/              VENDORED from BUZZ crates/buzz-ws-client, four panic sites removed.
        ├── mod.rs                                                                          ~20
        ├── connection.rs                                                                  ~330
        ├── message.rs                                                                     ~195
        └── error.rs                                                                        ~60
```

Roughly 4,260 lines including the ~600 vendored. No file approaches a size limit —
`AMBUSH` has no file-size gate on `crates/` at all, and `BUZZ`'s
`scripts/check-file-sizes-core.mjs` governs only `desktop/`, `web/` and `mobile/` roots. That is a
freedom, not a licence; the layout above is sized so no module holds two responsibilities.

**One structural rule, enforced by review and by the module boundary:** `receive.rs` may import
`stream`, `spool` and `metrics`, and nothing else. It may not import `publish`, `pacer`,
`channels`, `identity` or `ws`. If the receive loop can name the relay client, someone will
eventually call it from there, and the 281 ms budget will be gone with no test failing.

---

## 3. The subscription, and the silent lag-drop

### 3.1 Startup: `None` is a real state and it is fatal

```rust
let Some(rx) = input.events else {
    return Err(BridgeError::NoBroadcaster);
};
```

`IngestState::subscribe_runtime_events` (`ingest/mod.rs:1874-1881`) returns `None` when
`IngestState.runtime_events` is `None`, which is the state of any `IngestState` that was not built
through `.with_runtime_events(...)`. `publish_runtime_event` (`ingest/mod.rs:1913-1917`) is then a
silent no-op. A bridge that starts anyway idles forever while the daemon believes it is
publishing. `BridgeError::NoBroadcaster` is returned from `build()` and, per §1.2, aborts daemon
startup.

### 3.2 The loop, in full

```rust
// src/receive.rs — the whole hot path. Nothing that can block appears here.
loop {
    tokio::select! {
        biased;
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() { break; }
        }
        result = rx.recv() => match result {
            Ok(event) => {
                let stream = stream::classify(&event);
                metrics.ingested(stream);
                spools.append(stream, Record::from_event(&event))?;   // target <= 2 ms
            }
            // The one case both shipped subscribers throw away.
            Err(RecvError::Lagged(n)) => {
                metrics.broadcast_lagged(n);
                // A lag is not attributable to a stream: the events are GONE and the
                // bridge never saw their discriminants. It is recorded against EVERY
                // spooled stream, because any of them may have lost content.
                spools.mark_gap_all(GapCause::BroadcastLagged { count: n });
            }
            Err(RecvError::Closed) => break,
        }
    }
}
```

`biased;` puts shutdown first so a draining daemon is never starved by a hot broadcast.

### 3.3 Why this is a correctness hazard and not a quality-of-service one

A telemetry frame lost to lag is replaced by the next tick 1,000 ms later; the operator sees a
gauge that is one second stale. A **finding, escalation, receipt or hold** lost to lag is gone from
the console permanently:

- The relay is not the record and never had it — the bridge is the only writer of daemon-sourced
  facts.
- The daemon does not retain it either. `RuntimeEvent` is fan-out only; there is no durable
  `runtime_events` store and no route that replays one. `GET /v1/events/stream`
  (`ingest/mod.rs:2572` → `ingest/demo.rs:1644-1718`) is a live tail with **no `Last-Event-ID`
  resumption** — it sets `.id(event.emitted_at_ms().to_string())` (`demo.rs:1703`), a millisecond
  timestamp that collides at the concentration monitor's 10 Hz cadence and is not monotonic across
  issuers.
- The underlying artifact may still exist (a `ReplayBundle`, an `IncidentRecord`), but the bridge
  has no key with which to ask for it: it never saw the event, so it has no `finding_id`, no
  `receipt_id`, no `hunt_id`.

**Therefore: a lag on a spooled stream is unrecoverable, and the only honest response is to say
so, exactly, at the position where it happened.** That is what the dropped-at-source stream is
for.

### 3.4 The three loss causes, named apart

The set's copy laws forbid smoothing loss. They also forbid conflating three different things
under one word. The bridge distinguishes three, and each renders differently:

| Cause | When | What the bridge knows | Wire representation |
|---|---|---|---|
| `BroadcastLagged { count }` | the 1,024-slot channel overran before the bridge saw the events | **the count only** — never which events, never a `seq` range, because no `seq` was ever assigned | `gap` block, `from_seq`/`to_seq` absent |
| `SpoolEvicted { from_seq, to_seq }` | the disk spool hit `PERCH_SPOOL_MAX_BYTES` and unlinked its oldest segment | the exact range, because `seq` is assigned at append (§5.3) | `gap` block with an exact range |
| `Coalesced { from_ms, to_ms, suppressed }` | the coalescer folded N events into one by a **meaning-preserving** rule (§4) | everything: the window and the suppressed keys | `coalesced` block — **not** a gap |

A coalesce is not a gap and must never render as one. `07-REALTIME-AND-DATA.md` §5.5's row
`— 340 finding cards coalesced into 12 (bridge over budget 14:22:01–14:22:09) —` is the third
case, and the operator's correct reaction to it ("open the disclosure, read the suppressed
triples") is different from the correct reaction to the first two ("re-fetch from the daemon, and
if it cannot answer, this is missing").

### 3.5 The dropped-at-source stream

`APPENDIX-NORMATIVE.md` §7 fixes the vocabulary: **stream** is one of the bridge's four transport
classes, and `dropped-at-source` is the fourth. It is the only stream that never carries a domain
fact. It carries counts, ranges and one gauge, and it has three outlets:

1. **The `26000` ingest-rate gauge.** `RuntimeEvent::Ingest` is published once per accepted
   telemetry event (`ingest/mod.rs:1122,1135,1200`) and is reduced, deliberately, to
   `{accepted, rejected, by_source}` at 1 Hz. `RuntimeEvent::Replay` and
   `RuntimeEvent::EvolutionStatus` are dropped with no outlet at all
   (`07-REALTIME-AND-DATA.md` §4). All three are counted.
2. **The `gap` block on the next card of the affected stream.** See §3.6 — this is the decision
   this document makes, and it is what lets loss render inside the seven frozen markers.
3. **The counters in §11**, which are what make "we dropped detail" a fact rather than a
   suspicion.

The dropped-at-source stream is **not disk-spooled**. Its state is a small `GapSlot` per spooled
stream plus a counter set, and the `GapSlot` is persisted **inside the affected stream's spool
cursor file**, so a bridge crash between a lag and the next card does not lose the knowledge that
the lag happened. That is deliberate: the one thing that must survive a crash is the record that
something did not.

### 3.6 DECIDED — loss rides in the card, not in an eighth marker

`APPENDIX-NORMATIVE.md` §3 freezes seven markers and requires `03` §4.4's justification shape for
an eighth: *what an operator cannot reconstruct without it after the ephemeral has decayed*.
`07-REALTIME-AND-DATA.md` §5.5 nonetheless requires a durable timeline row for a gap and a
coalesce. Both cannot be satisfied by adding a marker.

**Decision.** Every marker card body carries two optional blocks:

```jsonc
"gap": {
  "cause": "broadcast_lagged" | "spool_evicted" | "publish_window_expired",
  "count": 275,                       // always present
  "from_seq": 4118, "to_seq": 4393,   // present ONLY for spool_evicted
  "window_ms": [1756512121000, 1756512129000]
},
"coalesced": {
  "from_ms": 1756512121000, "to_ms": 1756512129000,
  "input_count": 340, "output_count": 12,
  "suppressed": [ { "threat_class": "lateral_movement", "host_id": "web-04", "count": 31 } ]
}
```

Both are absent on a normal card. The renderer draws `07` §5.5's separator rows from these blocks.
Cost: **zero markers, zero relay changes, zero extra events.** The gap cannot be lost independently
of the card it precedes, because it is inside the same signed envelope.

**The one edge case, and its rule.** A loss followed by silence would never publish its gap. So:
when a stream holds a pending `GapSlot` and the pacer has produced no payload for that stream for
`PERCH_GAP_FLUSH_TICKS` consecutive ticks, the pacer emits a **gap-only card** — the same marker,
the same schema, a populated `gap` block and an **empty payload array**. The renderer draws only
the separator.

`PERCH_GAP_FLUSH_TICKS = 3` — **PROPOSED**, no measurement behind it; three ticks is the smallest
value that does not race a busy stream's own next card.

> **Commitment for `13-WIRE-SCHEMAS.md`:** every `ambush:*:v1` body schema carries optional
> `gap` and `coalesced` blocks, and a card with an **empty payload array and a populated `gap`
> block is legal and must render**. A schema that makes the payload array `minItems: 1` breaks
> gap flushing.

### 3.7 The `seq`, and what it can honestly prove

`seq` is a per-`(colony_id, issuer)` monotonic `u64`, assigned **at spool append**, persisted in
the segment header, and carried in the card body.

Assigned at append, not at publish, because the two losses that matter happen on opposite sides of
the spool: an eviction must renumber nothing, or it would hide itself. A `Lagged` cannot be given
a range at all, because the bridge never saw the events — and saying so is the honest rendering.

What the `seq` proves: **no envelope from this issuer, after the bridge saw it, is missing.**
What it does not prove: that the daemon did not drop something before the bridge saw it. The only
signal for that is `perch_bridge_broadcast_lagged_total` and its `gap` block, and `07` §5.4 is
right that no wording may imply otherwise.

`(colony_id, issuer)`, never `issuer` alone — `07-REALTIME-AND-DATA.md` §11 item 1. Two colonies
each running a Whisker both start at `seq: 1`.

**Dependency on B6, stated rather than hidden.** `AMBUSH crates/swarm-spine/src/envelope.rs:71`'s
`build_signed_envelope(keypair, seq, prev_envelope_hash, fact, issued_at)` takes `seq` as a
parameter. If **B6** lands, the bridge's `seq` becomes the spine's `seq` and a gap becomes a
`ChainLinkVerdict::SequenceMismatch` (`swarm-spine/src/chain.rs`, five outcomes, **zero consumers
outside its own module** — re-checked with `rg` over `AMBUSH crates/`). Until then it is a bridge-local
counter and the copy must say so. `09` §3.1 records B6 as "separable"; that is true of the
transport and false of the *claim* — the bridge is honest either way, but the claim it can make
is smaller before B6.

---

## 4. The four streams

### 4.1 Classification is an exhaustive match with no `_` arm

```rust
// src/stream.rs
pub fn classify(event: &RuntimeEvent) -> Stream {
    match event {
        RuntimeEvent::ResponseHeld { .. }         => Stream::Alarm,      // B1's 12th variant
        RuntimeEvent::ModeTransition { .. }       => Stream::Alarm,
        RuntimeEvent::TamperAlert { .. }          => Stream::Alarm,
        RuntimeEvent::Escalation { .. }           => Stream::Evidence,
        RuntimeEvent::Finding { .. }              => Stream::Evidence,
        RuntimeEvent::ResponseExecution { .. }    => Stream::Evidence,
        RuntimeEvent::ConcentrationSnapshot { .. }=> Stream::Telemetry,
        RuntimeEvent::AgentHealth { .. }          => Stream::Telemetry,
        RuntimeEvent::AgentAction { .. }          => Stream::Telemetry,
        RuntimeEvent::Ingest { .. }               => Stream::DroppedAtSource,
        RuntimeEvent::Replay { .. }               => Stream::DroppedAtSource,
        RuntimeEvent::EvolutionStatus { .. }      => Stream::DroppedAtSource,
    }
}
```

No `_` arm, by design: `RuntimeEvent` has **11** variants today (`runtime_events.rs:214-305`,
counted this session) and B1 adds a twelfth. When it does, this function fails to compile and
somebody must decide which stream a held action belongs to. That is the point.

Note this is one of **seven** places a twelfth variant must be edited, six of them in
`swarm-runtime` (`runtime_events.rs:127-139`, `:142-156`, `:158-173`, `:214-305`, `:308-322`,
`:324-338`) plus the exhaustive `runtime_event_matches_scope` at
`swarm-ingest-runtime/src/ingest/mod.rs:698-770`, which decides whether the hold alarm leaks on
`/v1/events/stream`. `12-BACKEND-BILL-API.md` owns that edit; the arm must default to `false`,
alongside `TamperAlert`/`AgentHealth`/`EvolutionStatus` at `ingest/mod.rs:766-768`.

**`ModeTransition` and `TamperAlert` are dual-routed.** They are classified `Alarm` for scheduling
(never coalesced, never shed, bypass the pacer), and the alarm publisher *additionally* emits their
telemetry ephemeral — `26003` and `26005` — so the Watchfloor sees them without a second
subscription. One `RuntimeEvent`, two frames, one stream for policy purposes. The classifier
returns the **scheduling** class, which is the one that governs backpressure.

### 4.2 The per-stream policy table

| | **Evidence** | **Telemetry** | **Alarm** | **Dropped-at-source** |
|---|---|---|---|---|
| Carries | `Finding`, `Escalation`, `ResponseExecution`; and the containment-lease diff (§9) | `ConcentrationSnapshot`, `AgentHealth`, `AgentAction` | `ResponseHeld`, `ModeTransition`, `TamperAlert` | `Ingest`, `Replay`, `EvolutionStatus`, plus every loss record |
| Wire | `kind:9` + `ambush:finding\|escalation\|receipt\|lease:v1`, into a **lane** or **case** channel | ephemeral `26001`, `26002`, global, no `h` | `kind:46010` + `ambush:hold:v1` into the case channel; ephemeral `26006`/`26003`/`26005`, global | ephemeral `26000` gauge; `gap`/`coalesced` blocks on other streams' cards |
| Durable at the relay | **yes** | no (ephemeral kinds are never stored) | 46010 yes; 26006/26003/26005 no | no |
| Identity | one per admitted agent (§7) | `perch-telemetry` | `perch-alarm` | `perch-telemetry` (the gauge) |
| Coalescing | last-wins per `(threat_class, level)` for `Escalation`; batch by `(threat_class, host_id)` for `Finding`; none for `ResponseExecution` | last-wins per key, 10 Hz → 1 Hz | **none, ever** | n/a |
| Shedding | oldest-first eviction, counted, `gap {spool_evicted}` | drop older silently — last-wins is lossless in meaning, so this is not loss | **never shed.** Three-tier rule below | n/a |
| Spool | **disk**, `PERCH_SPOOL_MAX_BYTES` | **memory**, depth 1 per key (§5.1 — proposed amendment) | **disk**, `PERCH_SPOOL_MAX_BYTES`, refuse-don't-evict | none; `GapSlot` + counters, persisted in the sibling cursors |
| Pacer | 1 Hz, ≤ `PERCH_FRAME_MAX_BYTES` per frame per identity | 1 Hz | **bypasses the pacer** — the ≤400 ms budget in `APPENDIX-NORMATIVE.md` §4 is on this stream's `26006` frame | n/a |
| Signing | agent identity, at publish | `perch-telemetry`, at publish | `perch-alarm`, at publish | n/a |

**The alarm rule, three tiers, stated once** (`07-REALTIME-AND-DATA.md` §4 settles this and the
bridge implements it literally):

1. Alarm work is never coalesced and never shed.
2. When the alarm spool cannot drain, the bridge **stops accepting evidence-stream work** — the
   evidence stream sheds so the alarm stream keeps its relay budget — and the console's governance
   strip says `holds are not reaching the console`.
3. If the alarm spool itself reaches `PERCH_SPOOL_MAX_BYTES`, the bridge **refuses new alarm work
   and alarms**: it logs at `error`, increments `perch_bridge_alarm_spool_full_total`, and surfaces
   the refusal. **It never blocks `recv()`.** A bridge that blocks its receive loop to protect one
   stream destroys all four inside 281 ms.

`PERCH_ALARM_SPOOL_WARN_BYTES = 1 MiB` — **PROPOSED**. The refusal point stays at the appendix's
`PERCH_SPOOL_MAX_BYTES`; this is the level at which the bridge starts saying so, because an alarm
spool that has quietly reached a quarter-gigabyte has hidden a number of held destructive actions
nobody should ever discover at the ceiling.

---

## 5. The spool

### 5.1 PROPOSED brief amendment — the telemetry stream is not disk-spooled

`APPENDIX-NORMATIVE.md` §6 records `PERCH_SPOOL_MAX_BYTES` = **256 MiB per stream** (status:
proposed, owner `07` §5.3). I am not silently using a different number. I am proposing that the row
read:

> `PERCH_SPOOL_MAX_BYTES` | **256 MiB per disk-spooled stream** (evidence, alarm). The telemetry
> stream is not disk-spooled.

The argument, in two parts:

1. **A replayed telemetry frame is a lie.** Ephemeral kinds are not stored by the relay
   (`BUZZ crates/buzz-relay/src/handlers/event.rs:794-906`, `handle_ephemeral_event` writes nothing
   to Postgres in either branch). A `26001` concentration snapshot drained from disk forty minutes
   after a reconnect paints the Watchfloor with a stale picture that carries no marker saying so —
   and `emitted_at_ms` in the body would be the only clue, on a surface whose whole job is "what is
   happening now".
2. **Last-wins at depth 1 is already lossless in meaning.** `07-REALTIME-AND-DATA.md` §4 assigns
   `ConcentrationSnapshot` "last-wins, 10→1", `AgentHealth` "last-wins per `agent_id`", and
   `AgentAction` "rolled up per tick". A disk spool for a stream whose retention policy is
   *keep exactly one* buys nothing and costs a fsync path, 256 MiB, and a stale-publish bug class.

So the telemetry spool is `MemorySpool`: a `BTreeMap<TelemetryKey, Record>` of at most
12 + `N_agents` entries, cleared into each tick's frame. Its worst case is a few kilobytes.

Everything else in the appendix's row stands: 256 MiB, per stream, for evidence and alarm.

### 5.2 On-disk layout

```
{perch.spool_dir}/{colony_id}/
├── evidence/
│   ├── 00000000000000000000.seg      # segment, named by its first seq, zero-padded to 20
│   ├── 00000000000000131072.seg
│   └── CURSOR                        # committed offset + the persisted GapSlot
└── alarm/
    ├── 00000000000000000000.seg
    └── CURSOR
```

`perch.spool_dir` **must be set** and must resolve outside the repository. This is not style:
`AMBUSH tools/check-worktree-clean.sh` is run `if: always()` after the CI test job and asserts on
`git status --porcelain` **and** on a `find` over known store roots — `find` was chosen precisely
because it "is immune to .gitignore and does see empty directories"
(`check-worktree-clean.sh:31-35`). A spool that defaults into `crates/` fails the clean-tree
contract on the first test run that exercises it, and it fails in a way that blames the test suite.
`config.rs` refuses a `spool_dir` that is empty or that canonicalizes under the workspace root, and
the crate's own tests use `tempfile`-style unique directories under the OS temp dir.

### 5.3 Segment header and record framing

```
SEGMENT HEADER — 48 bytes, written once at create, fsynced with the file's first roll
  0  ..  8   magic          b"PERCHSPL"
  8  .. 10   format_version u16 le            = 1
 10  .. 11   stream          u8                = 1 evidence | 3 alarm   (2 telemetry never lands here)
 11  .. 12   reserved        u8                = 0
 12  .. 20   first_seq       u64 le
 20  .. 28   created_at_ms   i64 le
 28  .. 44   colony_hash     [u8;16]           first 16 bytes of sha256(colony_id)
 44  .. 48   header_crc      u32 le            CRC-32C over bytes 0..44

RECORD — variable, appended, never rewritten
  0  ..  4   len             u32 le            length of `payload`
  4  ..  8   crc             u32 le            CRC-32C over bytes 8..(24+len)
  8  .. 16   seq             u64 le
 16  .. 24   emitted_at_ms   i64 le
 24  .. 25   issuer_idx       u8               index into the identity table (§7)
 25  .. 26   flags            u8               bit0 = payload is a containment-lease diff, not a RuntimeEvent
 26  ..(26+len) payload                        serde_json of the RuntimeEvent, UNSIGNED
```

**The spool holds unsigned bodies.** `created_at` is stamped and the envelope signed in the pacer,
at publish time (§6.3). Nothing in the spool is a signed artifact, so the spool is not a second
record and cannot be mistaken for one. `07-REALTIME-AND-DATA.md` §5.1 states this and it is load
bearing for §6.3's timestamp rule.

`CRC-32C` (Castagnoli) is implemented table-driven in `spool/checksum.rs`, about 60 lines, **no new
dependency**. `crc32fast` would be faster and is one more supply-chain line; at ~3,645 records/sec
over payloads of a few hundred bytes the table version is not the bottleneck, and `deny.toml`'s
duplicate gate makes every added crate a review item.

### 5.4 Rotation

Roll when the active segment reaches `PERCH_SPOOL_SEGMENT_BYTES` = **8 MiB** (**PROPOSED**; 32
segments per 256 MiB budget, so eviction granularity is 1/32 of the budget — coarse enough that
eviction is rare, fine enough that one eviction is not a quarter of the history).

`fsync` on roll, **not per record**. A per-record `fsync` is a syscall with a disk round trip
inside the 281 ms budget; the whole point of the spool is that appending is a page-cache write. The
loss window on a hard power failure is therefore one segment's unflushed tail, and §5.5 makes that
detectable rather than silent.

### 5.5 Crash recovery

On open, for each spooled stream:

1. Read `CURSOR`: `{ committed_seq, segment_first_seq, offset, gap_slot }`. A missing or
   short-read `CURSOR` is not fatal — it resets to the oldest segment's start and republishes,
   which is safe because the relay dedupes on event id (§10.4).
2. Validate every segment header. A bad magic, an unknown `format_version`, or a `colony_hash`
   that does not match the configured colony refuses to open — that last one is the guard against
   a spool directory shared between two colonies, which would merge two `seq` namespaces and
   produce a false continuity, which `07` §11 item 1 names as the worse of the two failures.
3. Scan the newest segment forward from `offset`. Stop at the first record whose `len` runs past
   EOF or whose `crc` fails. **Truncate the segment there** — that is a torn tail from a crash, not
   corruption — and increment `perch_bridge_spool_torn_tail_total`. Record the truncated range as
   `GapCause::SpoolEvicted { from_seq, to_seq }` on the `GapSlot`, because from the operator's
   point of view a torn tail and an eviction are the same fact: content the bridge accepted and
   cannot deliver.
4. Resume `seq` at `last_valid_seq + 1`. `seq` never rewinds. If step 3 truncated, the `seq`
   numbers in the truncated tail are burned and never reused — that is what makes the gap visible
   downstream.

A CRC failure **in the middle** of a segment (not at the tail) is different: it is corruption, not
a crash. The segment is quarantined by rename to `*.seg.corrupt`, `perch_bridge_spool_corrupt_total`
is incremented, and the whole segment's `seq` range is recorded as a gap. The bridge continues.
Refusing to start over one bad segment would take the console down for a disk problem that has
already cost only its oldest history.

### 5.6 Replay on reconnect, and the publish window

The pacer drains from `committed_seq`. `CURSOR` advances **only after the relay's `OK true`** for
the frame containing that record — never on send. So a disconnect mid-flight republishes, and
§10.4 explains why that is idempotent.

**A record cannot be replayed forever.** `MAX_TIMESTAMP_DRIFT_SECS` is **900 s and it rejects**
(`BUZZ crates/buzz-relay/src/handlers/ingest.rs:2224-2231`, `const MAX_TIMESTAMP_DRIFT_SECS: i64 =
900;` then `if (event_ts - now).abs() > MAX_TIMESTAMP_DRIFT_SECS { return Err(... "invalid: event
timestamp too far from server time") }`, running inside `ingest_event` in the relay process after
signature verification and before scope resolution). Because `created_at` is stamped at drain
(§6.3), a spooled record is *always* publishable no matter how long it waited — the age shows up in
the body's `emitted_at_ms` and is marked `late-published`, not in a rejection.

The one case where the window does bite is a frame **already signed and in flight** when the
connection drops. Its `created_at` is fixed inside the signature. Rule:

- Retry the **identical signed bytes** while `now - created_at < 900 - PERCH_PUBLISH_WINDOW_MARGIN_SECS`.
- Past that, discard the signed frame, return its records to the spool head, and let the pacer
  re-stamp and re-sign them on the next tick. The re-signed frame is a **new event id**, so it
  cannot collide with the original — and if the original was in fact accepted, the relay now holds
  two rows for the same facts. That is why the margin exists and why the discard is counted:
  `perch_bridge_dropped_events_total{cause="publish_window_expired"}`.

`PERCH_PUBLISH_WINDOW_MARGIN_SECS = 120` — **PROPOSED**. Two minutes of slack against a 900 s
window, sized so a clock skew inside the ±30 s warning band (`APPENDIX-NORMATIVE.md` §6) cannot
push a frame over the edge.

### 5.7 Eviction and the accounting invariant

When a spooled stream's total segment bytes exceed `PERCH_SPOOL_MAX_BYTES`, the **oldest whole
segment** is unlinked — oldest first, because `07` §5.3 quotes `buzz-acp`'s specification
(*"the OLDEST events are dropped (the viewer wants recent state) with accounting"*,
`BUZZ crates/buzz-acp/src/lib.rs:434-439`) and because in a security console the recent state is
the one an operator is looking at.

Eviction records `GapCause::SpoolEvicted { from_seq, to_seq }`. Whole segments only, so the range
is exactly the segment's header `first_seq` through its last record's `seq`.

**The alarm stream never evicts.** It refuses, per §4.2 tier 3.

The invariant `buzz-acp` states verbatim at `lib.rs:453` —

> `ingested == dropped + Σ source_events over published`

— is the one line of the specification that must be asserted in a unit test. In this crate it is
per stream, over the process lifetime, and it is exported as three counters (§11) so an operator
can check it without a debugger:

```
perch_bridge_ingested_total{stream}
  == perch_bridge_dropped_events_total{stream, cause}   summed over cause
   + perch_bridge_source_events_published_total{stream}
```

`cause` takes exactly four values: `broadcast_lagged`, `spool_evicted`, `spool_torn_tail`,
`publish_window_expired`. A coalesce is **not** a drop and never appears here — a coalesced input
is counted in `perch_bridge_source_events_published_total`, because its meaning was published.

---

## 6. The coalescer

Runs **between** the spool and the pacer, in the pacer's task, once per tick. Never in the receive
loop.

### 6.1 `26001` — the 10 Hz firehose, and the arithmetic that forces this

`ConcentrationMonitor::run_until_shutdown` ticks every `CONCENTRATION_MONITOR_INTERVAL_MS = 100`
(`AMBUSH crates/swarm-runtime-http/src/bin/swarm_detect.rs:40`, spawned at `:1002-1006`), and
`evaluate_all` (`crates/swarm-runtime/src/escalation.rs:105-206`) calls
`publish_concentration_snapshot` **unconditionally on every tick** (`:198-199` → `:282-292`), each
snapshot carrying all twelve classes from `standard_threat_classes()`. At rest, with zero
telemetry, that is **864,000 snapshots per day**.

Against that: `enforce_ws_admission` (`BUZZ crates/buzz-relay/src/connection.rs:652-706`, run in
the relay process on **every** inbound `EVENT`/`REQ`/`COUNT` frame before dispatch) charges the
`LimitType::Messages` counter for every `EVENT` at `agent_standard_messages_per_min` = **120/min**
(`BUZZ crates/buzz-auth/src/rate_limit.rs:105`, default fn `default_agent_std_msg()` at `:129-131`,
selected at `connection.rs:690-692`). A pre-coalescing 10 Hz stream is 600/min against 120/min —
5× over, on the telemetry identity alone — and it also consumes the entire 50-frames-per-5-second
`WsEvents` budget (`connection.rs:671-681` × `admission.rs:9,40-45`,
`WS_BURST_WINDOW_SECS = 5` × `human_ws_events_per_sec = 10`).

So `APPENDIX-NORMATIVE.md` §3's *"coalesced 10 Hz → 1 Hz in the bridge, before IPC"* is a hard
requirement. The rule:

```rust
// TelemetryKey::Concentration is a single key: the snapshot carries all 12 classes,
// so "last wins" over the whole snapshot is lossless in meaning.
spool.telemetry.insert(TelemetryKey::Concentration, record);   // depth 1, overwrite
```

Nine of ten snapshots per second are overwritten in memory and never reach the relay, disk, or
`serde_json`. `perch_bridge_coalesced_total{stream="telemetry",key="concentration"}` counts them.

### 6.2 CORRECTION — the ten ticks in a second are **not** byte-identical

`ambush-touchpoints.md` blocker B-3 offers a free mitigation: *"`now` is `unix_timestamp_secs()`
(`escalation.rs:228`), so all ten ticks in a second emit byte-identical events — the bridge can
dedupe on `(threat_class, level, timestamp)`."* **That is wrong, and a producer who implements it
will find the dedupe never fires.**

Read from source this session:

```rust
// AMBUSH crates/swarm-runtime/src/escalation.rs:247-264 — publish_escalation
runtime_events.publish(RuntimeEvent::Escalation {
    emitted_at_ms: now_ms(),          // <-- FRESH MILLISECOND CLOCK, EVERY TICK
    threat_class: event_threat_class(event).clone(),
    level: match event { Alert => EscalationLevel::Alert, Incident => EscalationLevel::Incident },
    total_strength: event_total_strength(event),
    ...
});
```

`RuntimeEvent::Escalation` (`runtime_events.rs:288-297`) has **no `timestamp` field at all**. The
seconds-resolution `now` that `run_until_shutdown` passes (`escalation.rs:228`) reaches the
substrate's `EscalationRecord` (`escalation.rs:166-174`) and the concentration query, never the
broadcast event. `publish_concentration_snapshot` does the same (`:288`).

The *useful* half of the finding survives and is stronger than the stated one: because
`query_concentration(threat_class, now)` receives seconds, `total_strength`, `distinct_sources`
and `peak_confidence` are **identical across all ten ticks within a second** unless a deposit
lands mid-second. So the ten events differ in exactly one field, `emitted_at_ms`.

**The bridge's actual rule for `Escalation`, in two layers:**

```rust
// Layer 1 — edge trigger. The escalation predicate is a pure level comparison with no
// memory of prior state (escalation.rs:78-101: two `exceeds_threshold` tests, each
// returning Some(EscalationEvent) on EVERY evaluation while over threshold), so a
// level-triggered producer needs an edge-triggered consumer.
let key = (threat_class.clone(), level);
let is_edge = self.last_level.get(&threat_class) != Some(&level);

// Layer 2 — bounded republish, so a class that has been at Incident for an hour is not
// silently absent from a console that connected ten minutes ago.
let is_heartbeat = now_ms - self.last_published_ms.get(&key).copied().unwrap_or(0)
                   >= PERCH_ESCALATION_HEARTBEAT_MS;

if is_edge || is_heartbeat { emit(key, record); } else { coalesced += 1; }
```

Plus the de-escalation edge: `evaluate_all` drops a class out of `events` entirely when it falls
below threshold (`escalation.rs:153-195`), so the bridge also emits on
`last_level.remove(&threat_class)`.

`PERCH_ESCALATION_HEARTBEAT_MS = 60_000` — **PROPOSED**. Worst case with all twelve classes at
Incident: 12 frames/min on the evidence identities, against 8 × 120/min. Compare the uncoalesced
rate: up to **120 events/second**, which `ambush-touchpoints.md` B-3 correctly calls unshippable.

### 6.3 `Finding` — batch by `(threat_class, host_id)` within a slot

`RuntimeEvent::Finding { emitted_at_ms, host_id, finding }` (`runtime_events.rs:224-228`). Note the
`host_id` is on the **wrapper**, not inside `SwarmFindingEnvelope` — which is exactly what
`GET /v2/api/stream/findings` throws away (`platform_api.rs:1391-1414`) and one of the reasons
`07` §2 rejects that transport.

Findings are **not** last-wins: two findings are two facts. They are batched — one `kind:9` card
per `(threat_class, host_id)` per tick, carrying an array of findings — until the frame reaches
`PERCH_FRAME_MAX_BYTES`. Overflow spills to the next tick from the spool; overflow past
`PERCH_SPOOL_MAX_BYTES` is an eviction, which is a gap, not a coalesce.

`07` §5.5's example row — `— 340 finding cards coalesced into 12 —` — is this rule producing the
`coalesced` block of §3.6, with `suppressed` carrying the `(threat_class, host_id, count)` triples.

### 6.4 `AgentHealth` + `AgentAction` → one `26002` frame

Last-wins per `agent_id` for health; a `BTreeMap<(AgentId, String), u64>` tally for actions.

**`AgentAction.details` never crosses the wire.** `publish_agent_action` sets
`details: serde_json::to_value(action)` over the entire `SwarmAction`
(`AMBUSH crates/swarm-runtime/src/dispatcher.rs:951`), which is adversary-influenced content, and
there is no route that serves it — so "fetch the full details from the daemon on demand" would be
fiction. The bridge drops the field at classification time, before it is ever written to the spool,
so it never reaches disk either.

**The tally key vocabulary is not closed.** `action_kind` takes nine `&'static str` values from
`swarm_action_kind` (`dispatcher.rs:1251-1263`), plus the literal `"agent_restart"` (`:1142`),
plus whatever `governance_policy.drain_runtime_events()` supplies (`:1034`). The bridge allowlists
the known ten and buckets everything else as `other`, with
`perch_bridge_unknown_action_kind_total` counting it — a nonzero value is a signal that the daemon
grew a kind and the allowlist is stale, not a bug in the bridge.

### 6.5 `ModeTransition`, `TamperAlert` — never coalesced, but edge-triggered at the source check

Both are alarm-class and therefore exempt from coalescing. But `TamperAlert` comes from an
anti-tamper loop on a **5 s default check interval** (`AMBUSH crates/swarm-core/src/config/defaults.rs:61`),
and a level-triggered producer at 5 s is 12 frames/min forever once a condition is true.

Rule: the alarm publisher emits `26005` on a change of the tuple
`(debugger_attached, tracer_pid, unexpected_library_loads.len(), fail_closed)`, and republishes at
most once per `PERCH_ALARM_HEARTBEAT_MS` = **60_000** (**PROPOSED**). This is *state-change
detection*, not coalescing — no alarm is ever discarded because a budget was tight, only because
it said the same thing as the one before it. The distinction matters because §4.2 tier 1 says alarm
work is never coalesced, and this rule must not be read as an exception to it.

`26005` carries **counts, not paths** (`APPENDIX-NORMATIVE.md` §3). `unexpected_library_loads:
Vec<String>` (`runtime_events.rs:250-257`) is reduced to its `.len()` at classification, before the
spool. Library paths are one of the things `07` §2 names as a reason `/v1/events/stream` must be
gated; the bridge must not be the second leak.

---

## 7. Identity and signing

### 7.1 The identity table

| Slot | Count | Publishes | Relay scopes needed |
|---|:-:|---|---|
| `agent[i]`, one per `admitted_identities` entry | 2–8 | evidence cards, attributed to the agent that produced the fact | `MessagesWrite` |
| `perch-telemetry` | 1 | `26000`–`26005` | `MessagesWrite` |
| `perch-alarm` | 1 | `46010`, `26006`, and case-channel provisioning | `MessagesWrite`, `ChannelsWrite`, `AdminChannels` |

`admitted_identities` is the `Vec<AgentId>` assembled in `swarm_detect.rs:768-962` and handed to
`dispatcher.set_admitted_identities(...)` at `:963`. Its length varies with config gates — Calico,
Kitten, Sphinx, Stalker and Weaver each register only when their feature is enabled — so the
bridge sizes its identity table from that vector rather than from the 8-variant `AgentRole` enum.

`AgentId::from_public_key_hex` yields `swarm:ed25519:<64 hex>`
(`AMBUSH crates/swarm-core/src/types.rs:16-18`), which is exactly the `issuer.swarm_agent_id`
format `13-WIRE-SCHEMAS.md` puts in every card body. No transformation is needed.

### 7.2 Where the secp256k1 keys come from — PROPOSED

Nostr needs secp256k1. `grep -rn 'secp256k1' AMBUSH crates/ tools/` returns **nothing**: the
workspace is Ed25519 throughout (`swarm-crypto/Cargo.toml` names `ed25519-dalek`, `sha2`,
`serde`, `serde_json`, `thiserror`, `hex`, `rand_core`, `ryu` and nothing else). The `nostr`
dependency brings secp256k1 with it.

**PROPOSED:** each Nostr key is derived deterministically from the identity it represents, so that
no new key material is provisioned, nothing extra can be lost, and the mapping
`swarm_agent_id → nostr_pubkey` is reproducible by the operator:

```
nostr_secret[i] = SHA-256( DOMAIN || 0x00 || colony_id || 0x00 || slot_label )
    DOMAIN     = b"ambush.perch.bridge.nostr.v1"
    slot_label = the AgentId string for an agent slot ("swarm:ed25519:<hex>"),
                 or b"perch-telemetry" / b"perch-alarm"
```

with the seed material taken from a **configured secret**, not from the public identity string.
This is the distinction correction **C-6** exists to protect:
`build_vote_envelope_hash` derives its keypair as
`Keypair::from_seed(sha256(format!("approval-ledger-envelope:{}", ledger.ledger_id)))`
(`AMBUSH crates/swarm-runtime/src/approval.rs:1807-1809`) — from a **public identifier anyone can
reproduce** — and then discards the signature and keeps only `envelope_hash` (`:1836-1840`). A
bridge key derived that way would let any reader of a colony id forge a card that the console's
admitted-issuer rule would then honour.

So the concatenation above is prefixed with a secret root:

```
root = the 32 bytes read from `perch.nostr_seed_env` (a SecretString, config/secrets.rs:9-19)
nostr_secret[i] = SHA-256( DOMAIN || 0x00 || root || 0x00 || colony_id || 0x00 || slot_label )
```

`perch.nostr_seed_env` names an environment variable, exactly as
`OperatorPrincipalConfig.token_env` does (`config/operator.rs:117-120`). Absent or short: the
bridge refuses to start with `BridgeError::MissingNostrSeed`, mirroring
`OperatorAuthState::from_config`'s `MissingTokenEnv` behaviour
(`swarm-runtime-http/src/http/auth.rs:57-82`), which is the reason `swarm_detect.rs:1127-1132`
logs a containment-router build failure loudly rather than shipping a daemon with no release route.

The bridge prints its ten npubs at `info` on first start. That listing is the operator's
provisioning input for §8.3, and it is the only place they exist in human-readable form.

### 7.3 What the signature proves, and the sentence nobody may write

The bridge signs the Nostr envelope with a secp256k1 key at publish time. That proves **this
bridge published this body**. The per-issuer `seq` proves **no envelope from this issuer, after
the bridge saw it, is missing**.

Neither proves the daemon said it. Four of the seven marker card types wrap objects that carry no
signature at all — `DetectionFinding` (`swarm-whisker/src/detector.rs:51-59`, 7 fields),
`SwarmFindingEnvelope` (`swarm-response/src/siem.rs:17-27`, 8 fields), `ResponseReceipt`
(`swarm-response/src/lib.rs:100-116`), the proposed `HeldAction` record — and the chain machinery
the plan set cites is nearly dead code (`build_signed_envelope`: **1** non-test caller;
`verify_chain_link`: **0** consumers outside its module; both re-checked with `rg` over
`AMBUSH crates/`).

`APPENDIX-NORMATIVE.md` §7 already bans `signed` and `verified` on a finding, escalation, hold,
containment-lease or bare response-receipt card. The bridge-side obligation is narrower and absolute:
**the bridge must never put a `signature`, `signed_by` or `verified` field in a card body it
constructs.** The Nostr envelope's own `sig` is the transport's, it is visible to any reader who
looks at the raw event, and it needs no help from the body.

### 7.4 The `p`-tag assert — a correctness gate, not a validation nicety

`APPENDIX-NORMATIVE.md` §4 layer 1 makes the `p` tag load-bearing: `query_needs_action`
(`BUZZ crates/buzz-db/src/store/feed.rs:171-201`) `INNER JOIN`s `event_mentions` on
`m.pubkey_hex` at `:183`, and `event_mentions` is populated **only** from `p` tags
(`BUZZ crates/buzz-db/src/runtime/mod.rs:41-53`) by `insert_mentions`, which:

- **drops a malformed tag silently.** A value that is not exactly 64 ASCII-hex characters is
  filtered out with a `tracing::debug!` and pubkeys are lowercased before insert
  (`runtime/mod.rs:66-81`).
- **runs outside the event transaction.** `Db::insert_event_with_thread_metadata`
  (`BUZZ crates/buzz-db/src/store/event.rs:1673-1698`) commits the event, then calls
  `insert_mentions` on a separate pool transaction, and downgrades any failure to
  `tracing::warn!(event_id = %event.id, "Failed to insert mentions: {e}")` (`:1690-1696`).
- **is attempted once.** The guard is `if result.1` — i.e. only when the event row was newly
  inserted. The `events` insert is `ON CONFLICT DO NOTHING` (`buzz-db/src/store/event.rs:1189-1193`), so a
  republish of identical bytes is a no-op and **does not retry the mention write**. The hole is
  not self-healing.

So a hold can be stored, `OK true`'d to the bridge, and permanently invisible to every `#p` feed.
The bridge's half of the defence:

```rust
/// Normalizes to lowercase 64-hex and asserts. A failed assert is a BRIDGE ERROR,
/// never a published event: an unpublished hold alarms; a hold published with a
/// malformed p tag is silently invisible to the operator it names.
fn normalize_p_tag(raw: &str) -> Result<String, BridgeError> { … }
```

The other half is not the bridge's: `APPENDIX-NORMATIVE.md` §4 layer 3 makes the console's
reconcile against `GET /v1/response/holds` (**B2r**) the only detector, counted as
`perch_queue_reconcile_divergences_total`. That counter is the **console's**, not the bridge's
(§11.4).

### 7.5 BLOCKER, restated because it lands on this crate — no operator Nostr pubkey exists

`APPENDIX-NORMATIVE.md` §4 layer 1 requires the bridge to `p`-tag *every operator principal
holding `OperatorScope::Approve`*, via `OperatorAuthConfig::effective_principals()`
(`AMBUSH crates/swarm-core/src/config/operator.rs:150-165`, re-read this session). That function
returns `Vec<OperatorPrincipalConfig>`, and `OperatorPrincipalConfig` is
`{ operator_id: String, token_env: String, token_expires_at_ms: Option<i64>, scopes: Vec<OperatorScope> }`
(`operator.rs:114-127`) with `#[serde(deny_unknown_fields)]`. `grep -rn 'pubkey|npub|nostr'` over
`AMBUSH crates/swarm-core/src/config/` returns nothing.

**`effective_principals()` cannot produce a 32-byte Nostr pubkey.** There are two ways out and this
document takes the first:

1. **Add `nostr_pubkey: Option<String>` to `OperatorPrincipalConfig`** — a typed field addition
   under `deny_unknown_fields`, `#[serde(default)]` so the shipped digest-signed
   `rulesets/default.yaml` keeps loading. Cost: one field, one validation rule, one
   `docs/CONFIGURATION.md` paragraph. **This is a bill item nobody budgeted and it is a
   prerequisite for B1's usefulness**, because a hold with no valid `p` tag reaches nobody.
2. The bridge carries its own `operator_id → npub` map in `perch.operator_pubkeys`. Rejected: it
   becomes an unsigned trust root that the entire hold-delivery path depends on, in a different
   file from the principal list it mirrors, with nothing keeping the two in step.

Until option 1 lands, the bridge starts, refuses to publish any `46010`, logs at `error`, and
increments `perch_bridge_hold_undeliverable_total`. It does **not** publish a hold with an empty
`p` tag set — that would be a stored, `OK`'d, permanently invisible destructive action awaiting a
human, which is the precise failure `APPENDIX-NORMATIVE.md` §4 exists to prevent.

---

## 8. The relay write path

### 8.1 The vendored WebSocket client

`02-ARCHITECTURE-INTEGRATION.md` decision 5: *"`buzz-ws-client` is vendored **and modified**, not
depended on. `deny.toml` sets `[sources] unknown-git = "deny"` with `allow-git = []`. The copy is
not verbatim: four panic sites in production code must become typed errors before the crate's
first commit compiles."*

The four, read from source, all in `BUZZ crates/buzz-ws-client/src/connection.rs`:

| Line | Site | Why it is there | Replacement |
|---|---|---|---|
| `:170` | `self.buffer.remove(idx).unwrap()` in `wait_for_auth_challenge` | `idx` came from `position()` on the same `VecDeque` | `.ok_or(WsClientError::BufferRace)?` |
| `:172` | `_ => unreachable!()` on the removed element | `position()` matched `RelayMessage::Auth` | `other => { self.buffer.push_back(other); return Err(WsClientError::BufferRace); }` |
| `:229` | `self.buffer.remove(idx).unwrap()` in `wait_for_ok` | same shape | `.ok_or(WsClientError::BufferRace)?` |
| `:231` | `_ => unreachable!()` | same shape | same shape |

`AMBUSH tools/check-runtime-panic-contract.sh` scans production (non-`cfg(test)`) code in
`crates/*/src` and — per its own header — *"matches ONLY `.unwrap(` and `.expect(`"*, deliberately
**not** `unreachable!`. So the two `.unwrap()` calls are hard gate failures and the two
`unreachable!()` calls are review items. Fix all four: the crate's `[lints] workspace = true`
inherits `unwrap_used = "deny"` / `expect_used = "deny"`
(`AMBUSH Cargo.toml:135-137`) and `[profile.release] panic = "abort"` (`:139-141`) makes any
surviving panic a process kill in the daemon that holds the containment lease store.

**Two functional changes on top of the four fixes**, both required by `07` §2:

1. **`send_event` is not used.** It is *strictly serial* — send, then `wait_for_ok` up to
   `PUBLISH_OK_TIMEOUT_SECS = 30` (`connection.rs:96-101`, `:23`). One in-flight event per
   connection is an RTT-bound ceiling. The bridge uses `send_raw` (`:121-126`, already `pub`) plus
   a separate **OK reaper** task that owns the read half and resolves in-flight frames by event id.
2. **The connection is split.** `NostrWsConnection` owns a single `WsStream` and every method
   takes `&mut self`. The vendored copy splits it into a `SplitSink`/`SplitStream` pair
   (`futures_util::StreamExt::split`) so the writer and the reaper can run concurrently, with the
   `pending_challenge`/`buffer` machinery collapsing into the reaper's own state.

`NOTICE`: the vendored files carry the upstream Apache-2.0 header and a provenance line naming
`block/buzz` and the source SHA. `AMBUSH vendor/reference/PROVENANCE.md` is the existing pattern —
though note the vendored ws client lives in `crates/swarm-perch-bridge/src/ws/`, **not** under
`vendor/`, precisely so the panic-contract gate does scan it (`vendor/reference/` is on that
script's deliberate exclusion list).

### 8.2 NIP-42, and the tag that doubles the quota

`build_auth_event(challenge, relay_url, keys, auth_tag)`
(`BUZZ crates/buzz-ws-client/src/message.rs:172-190`) builds `EventBuilder::auth(challenge, url)`
and, when `auth_tag` is `Some`, attaches it. That parameter is not decoration:

```rust
// BUZZ crates/buzz-relay/src/handlers/auth.rs:244-274 — in the relay process, on the
// AUTH frame, after signature verification. `extract_nip_oa_owner` reads the auth tag
// and `materialize_nip_oa_owner` confirms the first-write-wins agent→owner mapping.
if let Some(owner) = nip_oa_owner {
    if crate::api::relay_members::materialize_nip_oa_owner(&state, &conn.tenant, &pubkey, &owner).await {
        auth_ctx.agent_owner_pubkey = Some(owner);
    } else { warn!(…, "NIP-OA owner could not be materialized"); }
}
```

and then, on every subsequent `EVENT` frame:

```rust
// BUZZ crates/buzz-relay/src/connection.rs:662-668, :689-692
AuthState::Authenticated(ctx) => (ctx.pubkey, ctx.agent_owner_pubkey.is_some()),
…
let message_limit = if is_agent { limits.agent_standard_messages_per_min }   // 120
                    else        { limits.human_messages_per_min };            // 60
```

**Therefore: every bridge identity must present a NIP-OA owner attestation in its AUTH event, or
it is on 60/min.** §8.4 shows why 60 is not enough. The bridge's config carries one auth tag per
identity slot (or one shared owner attestation covering all ten, depending on how the relay
operator provisions them), and a missing tag is a **startup warning with the measured
consequence**, not a silent halving:

```
WARN perch bridge identity `perch-alarm` has no NIP-OA owner attestation;
     relay quota is 60/min not 120/min and the 1 Hz pacer will spend all of it
```

> **INTEGRATOR RULING, 2026-08-30 — see [`00-REGISTRY.md`](00-REGISTRY.md) R-1.** The `h`-tag
> layer described below is **retracted**. `kind:26006` is **global and carries no `h` tag**;
> `P_GATED_KINDS` is the whole delivery fence, and every Perch REQ that can match `26006` carries
> `#p` equal to the reader's own pubkey on every filter. The measurements here are correct and
> unchanged — what is overruled is the conclusion that both layers should ship. Consequence for this
> file: `perch.watch_channel` becomes **dead configuration**, the three `#watch` provisioning
> obligations and failure mode F19 are **retired** (not deleted — R-1 records the one condition
> under which they return), and `PublishAlarm` sets `p` tags only.

### 8.3 What the relay operator must provision, once

This is the largest external precondition in this document and none of it is optional.

| # | Thing | Why | Verified at |
|:-:|---|---|---|
| 1 | Ten pubkeys admitted to the community | NIP-42 AUTH must succeed for each socket | `handlers/auth.rs:240-285` |
| 2 | A NIP-OA owner attestation per pubkey | 120/min instead of 60/min | `connection.rs:665, 689-692` |
| 3 | `Scope::MessagesWrite` on all ten | `kind:9`, `46010`, and every ephemeral | `ingest.rs:480-484`; ephemerals separately at `handlers/event.rs:699-707` |
| 4 | `Scope::ChannelsWrite` on `perch-alarm` | `kind:9007` create-group | `ingest.rs:518` (`KIND_NIP29_CREATE_GROUP \| KIND_CANVAS => Ok(Scope::ChannelsWrite)`) |
| 5 | `Scope::AdminChannels` on `perch-alarm` | `kind:9000` put-user, to add operators to a private case channel | `ingest.rs:485-487` (`KIND_NIP29_PUT_USER \| KIND_NIP29_REMOVE_USER \| KIND_NIP29_DELETE_GROUP => Ok(Scope::AdminChannels)`) — **unconditional; there is no channel-owner shortcut** |
| 6 | The twelve lane channels exist and all ten identities are members | evidence cards are channel-scoped `kind:9`, and `kind:9` is already in `requires_h_channel_scope` (`ingest.rs:707`) | `ingest.rs:2509-2552` → `check_channel_membership` (`:742-772`) |
| 7 | The relay carries the two-arm 46010 fork | without it `required_scope_for_kind`'s default arm at `ingest.rs:545` returns `Err("restricted: unknown event kind")` and every hold is rejected at ingest | `10-RELAY-FORK.md` |
| 8 | The standing `#watch` ops channel exists and is **`visibility: "private"`** | the `26006` alarm is `h`-scoped to it (§8.6). `filter_fanout_by_access` returns every match unfiltered for a non-private channel (`handlers/event.rs:195`), so an **open** `#watch` makes the whole disclosure fix a no-op | `handlers/event.rs:193-221` |
| 9 | `perch-alarm` is a **member** of `#watch` | `handle_ephemeral_event` runs `check_channel_membership` on the PUBLISHER for any `h`-tagged ephemeral (`event.rs:850-852`), so a non-member gets `OK false` on every alarm and no hold ever reaches the shift | `event.rs:850-852` → `ingest.rs:742-772` |
| 10 | **every operator console's pubkey** is a member of `#watch` | a channel-scoped REQ filters requested channels against `accessible_channels` (`req.rs:189-195`, from `state.db.is_member(...)` at `:155-177`) and answers `CLOSED "restricted: not a channel member"` when nothing survives (`:200-208`). A non-member operator gets a terminal notice on the alarm subscription, not an empty one | `req.rs:189-208` |

Items 8–10 are new in this revision and follow from §8.6's reconciliation. None is optional and
none has a runtime workaround — a membership row is provisioning, not backoff. Item 10 is the one
that reaches a human: it is `14-CLIENT-ARCHITECTURE.md`'s obligation to render that `CLOSED` as
*"you are not on the watch floor"* rather than as a quiet shift.

Item 5 is worth naming plainly: **`AdminChannels` is the single largest authority the bridge
holds**, and it exists only so that a private case channel can have the on-shift operators added
to it. The alternative — creating case channels with `visibility = "open"` — removes the need for
`AdminChannels` and removes the compartment with it. The compartment is the point, so the scope
stays and is documented here rather than discovered later.

### 8.4 The write-budget arithmetic, and the quota resolved explicitly

Two relay ceilings, both per-pubkey, both re-read this session:

| Ceiling | Value | Charged on | Source |
|---|---|---|---|
| `LimitType::WsEvents` | `human_ws_events_per_sec` (10) × `WS_BURST_WINDOW_SECS` (5) = **50 frames per rolling 5 s** | **every** inbound `EVENT`, `REQ` and `COUNT` — **no agent exemption** | `connection.rs:671-681`; `admission.rs:9, 40-45`; `rate_limit.rs:102, 126-128` |
| `LimitType::Messages` | **120/min** with a NIP-OA attestation, **60/min** without | `EVENT` frames only, ephemerals included | `connection.rs:686-703`; `rate_limit.rs:105, 117-119, 129-131` |

**The resolution, and it is structural rather than statistical:**

1. **The pacer publishes at most one `EVENT` frame per identity per `PERCH_PUBLISH_TICK`.**
   `PERCH_PUBLISH_TICK` = 1 s, so the steady-state ceiling is **60 EVENT/min per pubkey against a
   120/min quota — exactly half**. This is not a measurement that might drift; it is the pacer's
   loop shape, and `07` §5.3 cites `buzz-acp`'s own statement of the same rule
   (`BUZZ crates/buzz-acp/src/lib.rs:382-394`: *"AT MOST ONE relay frame per tick — not one per
   channel, and not one per drain… At 1 frame/s telemetry spends at most 60/min — half that
   budget"*).
2. **The bridge issues zero `REQ` and zero `COUNT` frames.** It is write-only. It never subscribes,
   never queries, and never counts — it learns everything it needs from `OK` responses on frames it
   sent. So the 50-per-5-second `WsEvents` budget carries at most 5 frames per window per pubkey:
   **10% used**, with the other 90% available to absorb an alarm burst. This is a design commitment
   and it is testable (§14 T-9), and it is the answer to `buzz-touchpoints.md`'s blocker that *"no
   plan document budgets REQ frames against this counter"*.
3. **The alarm stream bypasses the pacer** to meet `APPENDIX-NORMATIVE.md` §4's ≤400 ms budget on
   the `26006` frame, so it is the one stream that can exceed 1 frame/s. It is bounded by
   `PERCH_ALARM_BURST_PER_MIN` = **40** (**PROPOSED**), leaving 80/min of the alarm identity's
   quota unspent. A hold costs at most four frames (`9007` + P×`9000` + `46010` + `26006`, with
   P = 1 in the shipped default), so 40/min is ten new cases per minute — an order of magnitude
   above anything a single-analyst deployment produces, and the excess spills to the pacer with
   `perch_bridge_alarm_deferred_total` incremented rather than being dropped.
4. **Aggregate:** at 1 Hz across 10 sockets that is 10 EVENT/s = 600/min spread over 10 pubkeys,
   each of which is allowed 120/min. Identity count *is* capacity, because `rate_limit_key` is
   `buzz:{community}:ratelimit:{pubkey}:{suffix}` (`rate_limit.rs:167-172`).
5. **The elevated and platform tiers are not a lever.** `agent_elevated_messages_per_min` (300) and
   `agent_platform_messages_per_min` (600) exist in `RateLimitConfig` (`rate_limit.rs:109-114`),
   are defaulted, and are settable by env (`BUZZ crates/buzz-relay/src/config.rs:418-425`) — and
   are read by **no enforcement site**; `connection.rs:690` selects
   `agent_standard_messages_per_min` unconditionally. Do not plan capacity on them.

**Without the NIP-OA attestation the arithmetic fails**, and this is the number that makes item 2
of §8.3 mandatory: 60 EVENT/min produced against a 60/min quota is 100% of budget with zero head
room, so the first case-creation burst, the first alarm, and the first spool drain each collide
with the limiter and are rejected as `rate-limited: …`. That is why §8.2's startup warning names
the consequence.

### 8.5 Ephemerals need a socket; the HTTP bridge is not an option

`POST /events` routes straight into `ingest_event`
(`BUZZ crates/buzz-relay/src/api/bridge.rs:925`), which has no ephemeral branch — a `26xxx` posted
over HTTP reaches `required_scope_for_kind` and is rejected `"restricted: unknown event kind"`
(`ingest.rs:545`). The bypass that makes the `26000`–`26006` block need **zero relay changes**
lives only on the WebSocket path: the ephemeral branch of `handle_event`
(`BUZZ crates/buzz-relay/src/handlers/event.rs:608`; the branch is `:698-752`) tests
`is_ephemeral(kind)` at `:698`, checks `Scope::MessagesWrite` (`:699-706`), checks the community
write fence (`:707-732`), calls `handle_ephemeral_event` at `:733`, and **returns at `:751`, before
`super::ingest::ingest_event(...)` is reached at `:761`**. The test `ephemeral_kinds_not_in_scope_allowlist`
(`ingest.rs:3851-3854`) is the in-tree evidence for it.

So the bridge holds live WebSockets. It does not fall back to HTTP for anything.

> **INTEGRATOR RULING, 2026-08-30 — see [`00-REGISTRY.md`](00-REGISTRY.md) R-1.** The `h`-tag
> layer described below is **retracted**. `kind:26006` is **global and carries no `h` tag**;
> `P_GATED_KINDS` is the whole delivery fence, and every Perch REQ that can match `26006` carries
> `#p` equal to the reader's own pubkey on every filter. The measurements here are correct and
> unchanged — what is overruled is the conclusion that both layers should ship. Consequence for this
> file: `perch.watch_channel` becomes **dead configuration**, the three `#watch` provisioning
> obligations and failure mode F19 are **retired** (not deleted — R-1 records the one condition
> under which they return), and `PublishAlarm` sets `p` tags only.

### 8.6 The `26006` disclosure hole — reconciled, with the mechanism measured

This item was unowned in wave 1: `10-RELAY-FORK.md` §11 and an earlier draft of this section each
named the other as owner. Wave 2 then produced **two** owners with different mechanisms, each of
which reads in its own text as the whole answer:

- `13-WIRE-SCHEMAS.md` amendment **W-1** — the `26006` frame gains an `h` tag naming the standing
  `#watch` ops channel, and The Watch's live REQ becomes `{kinds:[26006],"#h":[watch]}`.
- **ADR 0017** — `26006` is added to `P_GATED_KINDS` in `BUZZ crates/buzz-core/src/kind.rs`, a third
  fork site.

This section settles which one is load-bearing, because the bridge is the process that builds the
frame and its tags. **Both can land; they are complementary, not destructive. But only W-1 protects
the subscription the console actually opens, and a reader of ADR 0017 alone would believe otherwise.**
Every claim below was executed against `BUZZ` at `eed74bde2`.

#### The hole, restated exactly

`filter_fanout_by_access` (`BUZZ crates/buzz-relay/src/handlers/event.rs:115-222`) is the single
guarded send chokepoint for relay-local WS delivery, called by
`fan_out_event_to_local_subscribers` at `:247`. For a **channel-less** event it applies the
receiver tenant-label filter (`:126-131`), `AUTHOR_ONLY_KINDS` (`:139-152`) and
`SHARED_GATED_KINDS` (`:157-175`), then hits

```rust
let Some(channel_id) = stored_event.channel_id else {
    return matches;
};
```

at `:177-179` and returns **every** match without consulting `p` tags. A `26006` published as a
global ephemeral is therefore readable by any authenticated community member who opens
`REQ {"kinds":[26006]}`.

#### What `P_GATED_KINDS` actually does, and where it stops

`P_GATED_KINDS` (`BUZZ crates/buzz-core/src/kind.rs:159-169`, six kinds today, including one
ephemeral — `KIND_AGENT_OBSERVER_FRAME` — precisely so it can be used for filter-layer enforcement)
is consulted in exactly **two** places in the relay: `req.rs:221` and `count.rs:44`. Both are inside
this guard at `req.rs:219`, whose own comment states the limit:

```rust
// Only applies to GLOBAL subscriptions (channel_id = None):
// channel-scoped subs can never receive globally-stored events because of
// the fan_out() invariant in subscription.rs.
if channel_id.is_none() {
    let authed_pubkey_hex = hex::encode(&pubkey_bytes);
    if !p_gated_filters_authorized(&filters, &authed_pubkey_hex) {
        conn.send(RelayMessage::closed(
            &sub_id, "restricted: p-gated events require #p matching your pubkey"));
        return;
    }
```

`channel_id` here comes from `extract_channel_id_from_filters` (`req.rs:1153-1180`), which returns
`Some(uuid)` when **every** filter in the REQ carries exactly one parseable `#h` UUID and they all
agree, and `None` otherwise. And `p_gated_filters_authorized` (`:1182-1216`) requires, for any
filter that can match a p-gated kind, that `filter.generic_tags[#p]` is non-empty and every value
equals the authenticated pubkey (`:1212-1214`) — it never looks at `#h`.

**Therefore:** a console subscribing `{kinds:[26006],"#h":[watch]}` resolves a channel id and never
reaches the gate. ADR 0017's entry protects only a bare global `{kinds:[26006]}` REQ, which it
answers with `CLOSED "restricted: p-gated events require #p matching your pubkey"`.

#### What the `h` tag does, and why it is the load-bearing half

An ephemeral is not `ingest_event`'s business (§8.5), so the `h` tag reaches a different code path
— `handle_ephemeral_event` (`event.rs:795-906`), which `handle_event` calls at `:733-741`:

1. **Publish precondition.** `extract_channel_id(&event)` at `:850`; when it is `Some(ch_id)`,
   `check_channel_membership(&conn.tenant, &state, ch_id, &pubkey_bytes, None)` runs at `:851-852`
   with `?`, so a non-member publisher gets `OK false: "restricted: not a channel member"` and the
   frame is never fanned out at all. **`perch-alarm` must be a member of `#watch`.** New failure
   mode **F19**.
2. **Delivery.** `StoredEvent::new(event.clone(), Some(ch_id))` at `:873` and
   `fan_out_event_to_local_subscribers` at `:874`, so `filter_fanout_by_access` takes the
   channel-scoped branch: `Ok(v) if v != "private" => return matches` at `:195` — a **non-private**
   `#watch` returns every match unfiltered and closes nothing — otherwise every recipient is
   filtered through `is_member_cached(community_id, channel_id, &pubkey)` at `:205-221`, with
   `Err` treated as not-a-member.

So the closure is **membership of a private `#watch`**, which is strictly stronger than `#p`: it
does not depend on the frame carrying a `p` tag, and it survives a client that forgets one.

#### DECIDED, for the bridge

1. **The `26006` frame carries BOTH an `h` tag (`#watch`) and one `p` tag per principal holding
   `OperatorScope::Approve`.** The `h` tag is what enforces; the `p` tags are what make the frame
   safe if it is ever read through a global filter, and what let the console tell "this hold names
   me" from "this hold is on the floor". Costing nothing and closing both forms is the right trade.
2. **`#watch` MUST be provisioned `visibility: "private"`.** An open `#watch` makes W-1 a no-op —
   `:195` returns early. This joins §8.3's provisioning table as item 8.
3. **`#watch` is provisioned once by the relay operator, not created by the bridge**, and
   `perch-alarm` MUST be a member of it before the first alarm. The bridge does not create it
   because `#watch` is a standing channel shared across colonies and shifts, not a per-`hunt_id`
   artifact — and because the bridge would then also have to add every operator to it, which is the
   `AdminChannels` authority in §8.3 item 5 applied to a permanent object rather than a
   TTL-bounded one. `perch.watch_channel` is therefore configuration.

   **The bridge cannot pre-flight this**, and that is a direct consequence of decision 6 (write-only,
   zero `REQ`): it has no read path with which to check a membership row. **The first alarm is the
   test.** A failure surfaces as `BridgeError::WatchChannelMembership`, is alarmed at `error`, and
   is **never retried** — no amount of backoff adds a membership row. The trade is deliberate: a
   read path bought only for a startup pre-flight would be the first `REQ` in the crate, and T-9
   exists to stop exactly that.
4. **ADR 0017's `P_GATED_KINDS` entry is compatible and should land**, described honestly as *"it
   closes the global form"* rather than *"it closes the hole"*. Both `{kinds:[26006],"#h":[watch]}`
   and `{kinds:[26006],"#h":[watch],"#p":[me]}` pass the gate untouched (channel-scoped), and a bare
   `{kinds:[26006]}` is refused. There is no combination in which applying both closes a
   subscription the console needs. **This rebuts the reading that the two decisions are mutually
   destructive.**
5. **Every operator console must be a member of `#watch` too — and a console that is not gets a
   `CLOSED`, not silence.** This is the consequence of the `h` tag that costs the most and was
   easiest to miss. A channel-scoped REQ has its requested channel ids filtered against
   `accessible_channels` (`req.rs:189-195`, populated from `state.db.is_member(...)` at
   `:155-177`), and when nothing survives the relay answers
   `CLOSED "restricted: not a channel member"` (`:200-208`). So an operator who is `p`-tagged on a
   hold but not a member of `#watch` receives no alarm **and** a terminal notice on the
   subscription that was supposed to carry it. **Consequence for `14-CLIENT-ARCHITECTURE.md`:** a
   `CLOSED` on the alarm subscription must render as *"you are not on the watch floor"* with the
   remedy, never as an empty queue. Provisioning item 10.
6. **Relay-change accounting, so §8.5's "zero relay changes" claim stays honest.** `h`-tagging the
   `26006` costs **zero** relay change — `handle_ephemeral_event` already handles an `h`-tagged
   ephemeral natively, and an ephemeral never reaches `requires_h_channel_scope` because it never
   reaches `ingest_event`. ADR 0017's entry is a separate one-line change to
   `buzz-core/src/kind.rs`, correctly described by ADR 0017 as a third fork site. The two costs are
   not the same cost and should not be quoted as one.
5. The payload obligation is unchanged and unconditional under either mechanism: **the `26006`
   payload is exactly `{hold_id, action_kind, severity, case_channel, expires_at_ms}`, built from a
   narrow struct so no `RuntimeEvent` field can leak through a careless `serde` derive, and
   `hold_id` is an opaque daemon-minted token.** `hunt_id` is the telemetry event id
   (`AMBUSH crates/swarm-runtime/src/service/runtime_service.rs:391`), a join key into detection
   data; it lives only in the `46010` body, which is channel-compartmented.

#### `hold_id`'s shape is asserted at the publish seam

The bridge never mints a `hold_id` — B1's `HeldActionStore` does, and `12-BACKEND-BILL-API.md`
records it as *"opaque (uuid)"*. But the schemas that carry it
(`card-ambush-hold-v1`, `card-ambush-verdict-v1`, `frame-26006-hold-alarm`) declare it as a bare
`"type": "string"` with the constraint stated only in prose, and six different shapes are in
circulation across the wave-2 artifacts, two of them using the `hold:` colon prefix the schema
descriptions warn against.

So `channels.rs` carries a `HoldId` newtype whose `parse` is the only constructor, accepting a
lowercase hyphenated UUID and refusing anything with a colon, any uppercase hex, or any other
length, with `BridgeError::MalformedHoldId` and **no event built** — the same discipline as the
`p`-tag assert in §7.4, and for the same reason: a bad value here reaches a community-visible frame.
This is a bridge-side fence, not a wire contract; **`13-WIRE-SCHEMAS.md` owns pinning the pattern
once in `common.schema.json`'s `$defs`**, and the bridge will conform to whatever it pins.

---

## 9. Case-channel provisioning, and the two cards nobody assigned

Case channels, their TTL, `ambush:lease:v1` and `ambush:rollback:v1` — the four things in this
document's scope that no plan document assigned an owner. All four are decided or have a named,
priced bill item below.

### 9.1 The bridge creates the case channel — on TWO triggers, not one

**This section is rewritten. The first version scoped case-channel creation to
`RuntimeEvent::ResponseHeld` alone, and that leaves the only promotion clause the first build
enables with no creator at all.** The correction, its evidence and its cost are below; the
conclusion — the bridge is the creator — survives, and is now argued from a membership fact rather
than assumed.

#### 9.1.1 Why a case channel must exist before a hold can be published

`APPENDIX-NORMATIVE.md` §4 layer 1 requires the `46010` to carry an `h` tag naming the case channel
UUID. After the fork, `requires_h_channel_scope` (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:704`)
covers `46010`, and `ingest_event` — the relay-process function that validates and stores every
persistent event — rejects an `h`-less hold at `:2460-2464` with
`"invalid: channel-scoped events must include an h tag"`. So the case channel must exist, and the
publisher must be a member of it, **before** the first hold is published.

#### 9.1.2 THE GAP, and how the first draft produced it

The settled case-promotion bar (`00-BRIEF.md` §8.2) is *a held destructive action **OR** a
`CorrelatedIncident` with ≥ 2 included members **OR** manual promotion*. The first draft took the
first clause — *a hold is itself a promotion* — and made it the whole trigger list.

**ADR 0018 clause C4 ships all three clauses as configuration and enables only clause 3, manual
promotion, in the first build.** That is the one clause that emits no `ResponseHeld`. So on the
only enabled path:

- the bridge never fires, and no case channel exists;
- `POST /v1/operator/incidents` cannot mint the incident either — `IncidentMintRequest` lists
  `case_id` in its `required` array and describes it as *"The Perch case's channel UUID"*
  (`openapi/perch-operator-v1.yaml`);
- the console cannot create it: `14-CLIENT-ARCHITECTURE.md`'s eleven Tauri commands are seven reads
  plus five daemon writes, and none is a channel create.

`20-TASK-BREAKDOWN.md`'s P1-22 card already names the bridge's `channels.rs` (task P0-19) as *"the
producer"* for case channels while listing its own risk as *"E has nowhere to promote to"* — the
gap written down without being closed. It is closed here.

#### 9.1.3 REBUTTAL — INV-RF1 is not what blocks a console-side create

One reading of this gap is that `10-RELAY-FORK.md`'s INV-RF1 restricts the operator's key to a
single published kind and therefore forbids a console-side `kind:9007`. **That reading is wrong, and
recording why matters, because it is the reason the real argument had to be found.**
`10-RELAY-FORK.md` §9.3 states the scope explicitly:

> **Ordinary Buzz writes by the operator's own key** — creating a case channel (`kind:9007`),
> membership, reactions, ordinary `kind:9` chat in a case. Those are the operator acting as a Buzz
> user and are outside INV-RF1, which binds the *bridge*.

So INV-RF1 permits it. What forbids it is a membership fact, measured in `BUZZ` at `eed74bde2`:

`create_channel_with_id` (`BUZZ crates/buzz-db/src/store/channel.rs:171-263`, called in the relay
process from `ingest_event` when it stores a `kind:9007`, writing the `channels` row) bootstraps
**`created_by` and only `created_by`** as `owner` in `channel_members`, in the same transaction and
only when `was_created` (`channel.rs:224-242`):

```rust
if was_created {
    // Bootstrap the creator as owner.
    sqlx::query(r#"INSERT INTO channel_members (community_id, channel_id, pubkey, role, invited_by)
                   VALUES ($1, $2, $3, 'owner', $4) ..."#)
```

A console-created case channel therefore makes the **operator** the owner and leaves the bridge a
non-member. And `46010` is **not** on the six-kind `skip_membership` list at `ingest.rs:2517-2522`
(`KIND_NIP29_JOIN_REQUEST | KIND_NIP29_CREATE_GROUP | KIND_STREAM_MESSAGE_EDIT |
KIND_NIP29_EDIT_METADATA | KIND_NIP29_DELETE_EVENT | KIND_NIP29_DELETE_GROUP`), so
`check_channel_membership` runs at `:2533` and returns
`Err("restricted: not a channel member")` (`ingest.rs:742-772`, `:770`) for a non-member of a
channel whose `visibility` is not `"open"`. Case channels are private by construction
(ADR 0018 C7), so there is no open-channel fallback.

**The party that creates the channel is the party that can publish into it.** That is the whole
argument, and it is why the fix is a second trigger for the bridge rather than a second creator.

#### 9.1.4 DECIDED — `ensure_case_channel`, one entry point, two triggers

`channels.rs` exposes exactly one entry point, `CaseRouting::ensure_case_channel(trigger,
operators, ttl_seconds)`, taking a closed two-arm `CasePromotionTrigger`:

| Arm | Fires on | `case_id` | Steps planned |
|---|---|---|---|
| `Held { hunt_id, hold_id }` | `RuntimeEvent::ResponseHeld` (bill **B1**) with no case routed for its `hunt_id` | **minted here** (`Uuid::new_v4`) — `ResponseHeld`'s seven fields carry `hunt_id` and `hold_id` and no case id | `CreateCaseChannel` + one `AddOperator` per operator, then the caller's `PublishHold` + `PublishAlarm` |
| `Promoted { hunt_id, case_id, clause }` | `RuntimeEvent::CasePromoted` (bill **B1d**, PROPOSED below) | **supplied** by the daemon route that promoted | `CreateCaseChannel` + one `AddOperator` per operator, and nothing else — a promoted finding is not a held action and must not alarm the shift |

The routing map is **single-valued and first-write-wins**, keyed on `hunt_id`:

- `Held` on an already-routed `hunt_id` → the existing channel, no create steps.
- `Promoted` whose `case_id` equals the routed one → no-op.
- `Promoted` whose `case_id` **differs** → `BridgeError::CaseChannelConflict`, counted as
  `perch_bridge_case_channel_conflict_total`, logged at `error`. The bridge does not create a second
  channel for one investigation, and it does not silently adopt the newer id, because by then the
  daemon has minted an incident record naming the id it sent. Failure mode **F20**: the console
  navigates to the case it was told about and finds no channel, which is visible; a silent second
  channel is not.

The full sequence, both arms:

```
ensure_case_channel(trigger, operators, ttl):
  case_channel = routing.get(trigger.hunt_id)
    or else:
      uuid   = trigger.case_id  (Promoted)  |  Uuid::new_v4()  (Held)
      step 1: kind:9007  h=uuid  name=<case slug>  visibility=private
                         channel_type=stream  ttl=<perch.case_ttl_seconds>
      step 2: kind:9000  h=uuid  p=<each OperatorScope::Approve principal>   (one event each)
      routing.put(trigger.hunt_id, uuid)                      # durable, before step 3
  # Held only:
  step 3: kind:46010  h=uuid  p=<same set>  + ambush:hold:v1
  step 4: ephemeral 26006  h=<#watch>  p=<same set>
```

Steps are **one spool record**, an ordered `Vec<PublishStep>`, so a crash between them replays the
whole sequence. Steps 1 and 2 are idempotent by construction:

- `kind:9007` with a client-supplied UUID in the `h` tag reaches `create_channel_with_id`, whose
  `INSERT … ON CONFLICT (community_id, id) DO NOTHING` (`channel.rs:202-208`) yields
  `was_created = false` and the relay answers `"duplicate: channel already exists"`
  (`ingest.rs:2879-2884`) with `accepted: false`. The bridge treats that `OK` as **success**, not as
  an error (failure mode F14).
- The same function makes the creator a member inside that transaction, so `perch-alarm` is a member
  the instant the channel exists and step 3's membership precondition is satisfied without a second
  event.
- `kind:9000` is `ON CONFLICT … DO UPDATE` shaped on the same table and is safe to repeat.

#### 9.1.5 PROPOSED BILL ITEM B1d — `RuntimeEvent::CasePromoted`

```rust
RuntimeEvent::CasePromoted {
    emitted_at_ms: i64,
    case_id: String,        // the case channel UUID, minted by the daemon at promotion
    hunt_id: String,
    finding_id: String,
    threat_class: ThreatClass,
    severity: Severity,
    clause: PromotionClause, // held_action | correlated_incident | manual
    promoted_by: Option<String>,  // AuthenticatedOperatorPrincipal.operator_id on the manual clause
}
```

**Cost, measured against the shipped enum rather than estimated.** A new `RuntimeEvent` variant is
seven edits, not one — the same seven B1's twelfth variant pays and the same seven §9.4's B1c pays:

| # | Site | Why it is not optional |
|:-:|---|---|
| 1 | `RuntimeEventKind` enum, `AMBUSH crates/swarm-runtime/src/runtime_events.rs:127-139` | the parallel kind enum, 11 members today |
| 2 | `RuntimeEventKind::as_str`, `:143-155` | exhaustive `match self` |
| 3 | `RuntimeEventKind::parse`, `:158-173` | the `_ => None` arm makes a missing entry silent, so this one is a review item rather than a compile error |
| 4 | `RuntimeEvent` enum, `:214-305` | the variant itself |
| 5 | `RuntimeEvent::emitted_at_ms`, `:309-322` | exhaustive |
| 6 | `RuntimeEvent::kind`, `:325-338` | exhaustive |
| 7 | `runtime_event_matches_scope`, `AMBUSH crates/swarm-ingest-runtime/src/ingest/mod.rs:698-770` | exhaustive with **no `_` arm** (its last arm is an explicit `EvolutionStatus \| AgentHealth \| TamperAlert => false`), and it is what decides whether the new fact reaches the Providence context stream. `CasePromoted` returns **`false`**, grouped with `TamperAlert`: it carries an operator id and a case channel UUID and belongs on no unauthenticated stream. |

Plus this crate's `classify` arm (`stream.rs`), which fails to compile until somebody chooses.
`CasePromoted` is **`Stream::Alarm`**, not `Evidence`: coalescing or shedding it would leave a
daemon incident record whose `case_id` names a channel that does not exist. It carries no `26006`
frame, so it costs nothing against the alarm identity's burst budget.

**~0.5 engineer-weeks. NOT cuttable** while ADR 0018 C4 enables manual promotion first — cutting it
removes the case room from the first build, which is the surface the whole product is organized
around.

#### 9.1.6 PROPOSED AMENDMENT to `12-BACKEND-BILL-API.md` — mint `case_id` daemon-side

`ensure_case_channel`'s conflict arm exists only because two parties can mint a case id for one
`hunt_id`. It disappears entirely if the daemon is the sole minter.

**The request:** on the promotion route, `case_id` becomes a **response** field, not a request
field — the daemon mints the UUID, records `hunt_id → case_id` alongside the incident, emits
`CasePromoted`, and returns the id. The console navigates to `/cases/{case_id}` and renders a
"provisioning" state until the channel appears.

**The alternative, and its cost, so this can be overridden with an argument rather than by
accident:** keep `case_id` client-supplied exactly as `IncidentMintRequest` has it today, and let
the console mint the UUID. That needs **zero** change to the OpenAPI document, which is a real
advantage. It costs the conflict arm above, plus a rule nobody owns for what happens when a
manually promoted finding's `hunt_id` later produces a hold — the hold path would find the promoted
channel and reuse it, which is correct, but only because the map is keyed on `hunt_id` and written
durably before step 3. Either shape works. **`12-BACKEND-BILL-API.md` owns the route; this document
owns only the bridge's behaviour under whichever is chosen, and that behaviour is identical apart
from whether the conflict arm is reachable.**

**Consequences for peers, stated so nobody assumes them:**

- `14-CLIENT-ARCHITECTURE.md` — a case whose channel has not yet appeared is a state that must
  render. The bridge's pacer publishes at 1 Hz (§10.1) and the relay round-trips, so a freshly
  promoted case is reachable within roughly one to two seconds on a healthy path, and never on an
  unhealthy one. "Not yet" and "the bridge is down" are different sentences.
- `20-TASK-BREAKDOWN.md` — P1-22's acceptance list gains the second trigger, and B1d is a new
  Phase-1 row on the Rust engineer's load.
- `16-INVARIANT-TESTS.md` — the assertion worth having is that a promotion produces a channel the
  bridge is a member of, checked by publishing a `kind:9` into it as the bridge identity.

### 9.2 DECIDED — `ttl_seconds` on a case channel comes from the `9007` event

`spec-extract.md` §13 lists "what sets `ttl_seconds` on an Ambush case channel" as one of four
things three or more documents rely on and no document owns. It is owned here.

`resolve_ttl(&event, state.config.ephemeral_ttl_override)`
(`BUZZ crates/buzz-relay/src/handlers/mod.rs:46-66`) reads a `ttl` tag off the create event, parses
it as `i32` seconds, and `create_channel_with_id` writes it as
`ttl_deadline = NOW() + (ttl || ' seconds')::interval` (`channel.rs:206`). A relay-side
`BUZZ_EPHEMERAL_TTL_OVERRIDE` replaces the value when set — but only when a `ttl` tag was present
to begin with: the override arm is `(Some(original), Some(ovr))` and the fall-through is
`(ttl, _) => ttl` (`handlers/mod.rs:55-65`), so an override cannot give a TTL to a create event
that omitted the tag. The bridge therefore always sets the tag.

So: **the bridge sets `ttl` on the `kind:9007` event, from `perch.case_ttl_seconds`, resolved per
threat class.** `perch.case_ttl_seconds` is a config map with a default, not a constant.

One honesty note that must reach the console: the TTL refresh trigger
`refresh_channel_ttl_after_event_insert` (`BUZZ schema/schema.sql:960-993`, fired by the
`events_refresh_channel_ttl` constraint trigger at `:995-998`) has an
`EXCEPTION WHEN OTHERS` arm that downgrades a failed refresh to `RAISE WARNING`
(`schema.sql:984-988`), so a case channel whose refresh silently fails keeps a stale
`ttl_deadline` and can archive under an open investigation. `07` §1 already draws the correct
conclusion — the daemon's case record, not the channel row, answers "is this case open" — and this
document adds only that **the bridge must not treat channel archival as case closure** and must
keep its `hunt_id → case_channel` routing entry until the daemon says the hold is decided.

### 9.3 `ambush:lease:v1` — the 1 Hz containment-lease diff

There is no `RuntimeEvent` for a containment lease opening. So the bridge polls.

`ContainmentSweep::open_leases()` (`AMBUSH crates/swarm-runtime/src/containment.rs:537-539`) is
`pub` and returns `Result<Vec<ContainmentLease>, ContainmentStoreError>` off the process's **one**
`Arc<ContainmentSweep>` — the same `Arc` that `swarm_detect.rs:1022-1075` builds and hands to both
the TTL task and the operator release route, for the reason the comment there states at length: two
sweeps over a `MemoryContainmentLeaseStore` are two different maps.

The bridge holds `Option<Arc<ContainmentSweep>>` (the same option `swarm_detect` already computes),
polls at 1 Hz, and diffs by `lease_id`:

- **appeared** → build `ambush:lease:v1` from the `ContainmentLease` and publish it on the evidence
  stream into the case channel resolved through `lease.origin_receipt_id` → `receipt_id → hunt_id`
  (recorded when the `ResponseExecution` came through) → `hunt_id → case_channel`.
- **disappeared** → §9.4.
- **`None`** (no containment lease store — the shipped default, `ContainmentSettings.lease_store_path`
  defaults to `None`, `AMBUSH crates/swarm-core/src/config/runtime.rs:93-95`) → publish nothing,
  and export `perch_bridge_lease_store_absent` as a gauge = 1 so `/leases` can render
  `no-lease-store-configured` — naming `runtime.containment.lease_store_path` — as a first-class
  state rather than an empty list.

The card carries the containment lease's own fields and **never** `remaining_ms` or `expired`.
Those are
clock-derived: `ContainmentLeaseView`'s own doc comment
(`AMBUSH crates/swarm-runtime-http/src/http/containment.rs:75-86`) says `remaining_ms`
*"SATURATES AT ZERO"* and therefore cannot distinguish "expires in an instant" from "expired an
hour ago and the sweep has not managed to release it", which is why `expired` is a separate field.
Baking either into an immutable card would freeze a lie.

### 9.4 OPEN — `ambush:rollback:v1` has no assigned producer, and here is the smallest fix

`APPENDIX-NORMATIVE.md` §3 assigns `ambush:rollback:v1` a payload (`RollbackReceipt`, as a NIP-10
reply to the containment-lease card) and a channel (case). `07-REALTIME-AND-DATA.md` §4's stream table does not
list it, because no `RuntimeEvent` carries it. It has two possible producers and they cover
different events:

| Release cause | Who holds the `RollbackReceipt` | Can publish the card? |
|---|---|---|
| Operator release — the console `POST`s `/v1/operator/containment/leases/{id}/release` (one of INV-01's five permitted non-GETs) and gets `ContainmentReleaseResponse` back (`containment.rs:128-145`) | the console | **yes** — as leg 1 of the release, the same shape as `ambush:verdict:v1` |
| TTL expiry — `ContainmentSweep::sweep` (`swarm-runtime/src/containment.rs:568+`) produces a `ContainmentSweepReport { expired, receipts: Vec<RollbackReceipt>, failures }` and `run_until_shutdown` consumes it internally | nobody outside the sweep | **no** |

**Decision, in two parts:**

1. **The console publishes `ambush:rollback:v1` for an operator release**, as leg 1, exactly like
   `ambush:verdict:v1`. This is `14-CLIENT-ARCHITECTURE.md`'s to implement; recorded here as a
   commitment so it is not assumed to be the bridge's.
2. **A TTL-expiry release needs a thirteenth `RuntimeEvent` variant**, and I am naming it rather
   than assuming it: **B1c — `RuntimeEvent::ContainmentReleased { emitted_at_ms, lease_id, trigger,
   receipt }`**, published from `ContainmentSweep::sweep` for each receipt in the report. Cost is
   the same six edits as B1's twelfth variant (`runtime_events.rs:127-139`, `:142-156`, `:158-173`,
   `:214-305`, `:308-322`, `:324-338`) plus the exhaustive `runtime_event_matches_scope` arm
   (`ingest/mod.rs:698-770`, default `false`) plus this crate's `classify` arm. **PROPOSED**, ~0.5
   engineer-weeks, cuttable with a rendered consequence.

Until B1c lands, the bridge detects the disappearance of a containment lease from `open_leases()`
and does **not** invent a rollback card for it. It records the disappearance in the
containment-lease card's successor state and the console renders
`containment lease no longer open — release receipt not available`, which is
true. Inventing a receipt the bridge never saw would be exactly the class of claim
`APPENDIX-NORMATIVE.md` §8 law 3 exists to forbid.

---

## 10. The pacer, and `created_at`

### 10.1 Loop shape

```rust
let mut ticker = tokio::time::interval(Duration::from_millis(PERCH_PUBLISH_TICK_MS));
ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);   // never burst-catch-up
loop {
    tokio::select! {
        biased;
        _ = shutdown.changed() => { drain_best_effort().await; break; }
        _ = ticker.tick() => { self.tick().await; }
    }
}
```

`MissedTickBehavior::Delay`, not the default `Burst`. A pacer that catches up after a stall fires
N ticks back to back and hands the relay N frames inside one second — which is the shape that
trips the 50-per-5-second `WsEvents` budget and turns a stall into a rate-limit window.

### 10.2 Packing: greedy over the front run of one channel

`07` §5.3 quotes the specification and its rationale from `buzz-acp`'s `next_frame`
(`BUZZ crates/buzz-acp/src/lib.rs:551-585`): take `self.events.front()`'s channel, gather only that
channel's run, stop at the frame cap. *"A front-run packer degrades to one event per slot under
round-robin producers; a channel-scan packer starves the tail. Buzz learned that; we do not
re-learn it, and we do not copy the code to inherit it."*

The bridge's version is the same shape with one Perch-specific addition: the run is keyed on
`(identity, channel)`, not channel alone, because evidence cards are attributed per agent and two
agents writing to the same lane must not be packed into one frame signed by one of them.

Per tick, per identity: **at most one frame, at most `PERCH_FRAME_MAX_BYTES`.**

### 10.3 `created_at` is stamped at drain, and that is forced

`PERCH_FRAME_MAX_BYTES` = 64 KB sits under `MAX_EVENT_CONTENT_BYTES` = 256 KB
(`BUZZ ingest.rs:2233-2240`, `const MAX_EVENT_CONTENT_BYTES: usize = 256 * 1024;`) and under
`DEFAULT_MAX_FRAME_BYTES` = 512 KiB (`BUZZ crates/buzz-relay/src/config.rs:14`), so a full frame is
never a protocol risk.

`created_at` is stamped **inside the pacer, immediately before signing**, from the daemon's clock.
This is forced, not preferred: `MAX_TIMESTAMP_DRIFT_SECS` is 900 s and it **rejects**
(`ingest.rs:2224-2231`), and `created_at` is inside the Nostr signature, so a spooled card carrying
its true emit time in `created_at` becomes permanently unpublishable fifteen minutes after it was
produced and cannot be corrected without re-signing. A 68-minute spool under that design would
drain fifteen minutes of backlog and then reject every remaining frame, one at a time, forever.

Consequences the bridge implements:

- **`emitted_at_ms` in the body is the domain timestamp.** Every card body carries it, from the
  `RuntimeEvent` itself (`runtime_events.rs:308-322`, `emitted_at_ms()` over all eleven variants).
- **`created_at` is a transport timestamp** and the copy calls it one. The bridge writes it into no
  body field.
- **`late-published` is computed by the bridge, not the console**, and rides in the card:
  when `created_at * 1000 - emitted_at_ms > PERCH_PUBLISH_TICK_MS * PERCH_LATE_PUBLISHED_TICKS`
  the body carries `"late_published_ms": <delta>` and the console renders
  `late-published — held in the bridge spool 22 min`. `PERCH_LATE_PUBLISHED_TICKS = 2` —
  **invented**, per `APPENDIX-NORMATIVE.md` §6, and it stays invented until somebody measures a
  real spool drain.
- **`perch_bridge_late_published_seconds`** observes the same delta.

### 10.4 Retry is idempotent, and here is the mechanism

`INSERT INTO events (…) VALUES (…) ON CONFLICT DO NOTHING`
(`BUZZ crates/buzz-db/src/store/event.rs:1189-1193`, inside
`insert_event_with_thread_metadata_tx` at `:1160`, which is what `Db::insert_event_with_thread_metadata`
calls from the relay's write path), with `was_inserted = result.rows_affected() > 0` at `:1211`.
A Nostr event id is a hash over
`(pubkey, created_at, kind, tags, content)`, so re-sending **identical signed bytes** produces an
identical id and the second insert is a no-op.

Two consequences, both load-bearing:

1. **Retry the bytes, never re-stamp** — within the §5.6 window. A re-stamped frame is a new id and
   duplicates.
2. **A retry does not repair a missing mention row.** `insert_mentions` is called only under
   `if result.1` (`store/event.rs:1690`), i.e. only on the first insert. So §7.4's hole is not
   self-healing by republication, which is why the console's daemon reconcile is mandatory rather
   than best-effort.

---

## 11. Metrics

### 11.1 The registry, and the naming trap

The daemon already exposes `GET /metrics` (`AMBUSH crates/swarm-ingest-runtime/src/ingest/mod.rs:2547`
→ `ingest/health.rs:677-702`), which encodes **only** `CriticalPathMetrics`
(`AMBUSH crates/swarm-runtime/src/detection/metrics.rs:71-98`). That struct's `registry` field is
private and has **no public accessor** — the only public function over it is
`encode_metrics(&CriticalPathMetrics) -> String` (`metrics.rs:446-454`). So the bridge cannot
register into it without editing `swarm-runtime`.

**Decision: the bridge owns its own registry and its own route.**

```rust
// src/metrics.rs
let mut registry = Registry::with_prefix("perch");
let broadcast_lagged = Counter::default();
registry.register(
    "bridge_broadcast_lagged",     // NOTE: no `_total` suffix — see below
    "Events lost to a lagged tokio broadcast receiver before the bridge saw them",
    broadcast_lagged.clone(),
);
```

served at **`GET /metrics/perch`** from a two-route `axum::Router` the bridge returns and
`swarm_detect` merges beside `containment_operator_router` (§1.2). A second path rather than a
merge into `/metrics` because merging requires editing `ingest/health.rs`, which is
`swarm-ingest-runtime`'s file and outside this crate's blast radius.

**The naming trap, and the in-tree evidence for it.** `prometheus-client` appends `_total` to
counter sample names on encode. The existing code proves the convention: the variable
`ingest_events_total` is a `Family<IngestOutcomeLabels, Counter>` registered under the name
`"ingest_events"` (`metrics.rs:101, 129-133`), and the registry prefix is
`Registry::with_prefix("swarm")` (`metrics.rs:126`). So a counter registered as `"ingest_events"`
encodes as `swarm_ingest_events_total`.

Applying the same rule with prefix `perch`, every name in `APPENDIX-NORMATIVE.md`'s counter list
comes out **byte-exact** if and only if the `_total` suffix is omitted at registration:

| Register as | Type | Emitted name |
|---|---|---|
| `bridge_broadcast_lagged` | `Counter` | `perch_bridge_broadcast_lagged_total` |
| `bridge_dropped_events` | `Family<{stream,cause}, Counter>` | `perch_bridge_dropped_events_total` |
| `bridge_alarm_spool_full` | `Counter` | `perch_bridge_alarm_spool_full_total` |
| `bridge_admission_rejections` | `Family<{reason}, Counter>` | `perch_bridge_admission_rejections_total` |
| `bridge_spool_bytes` | `Family<{stream}, Gauge<u64>>` | `perch_bridge_spool_bytes` |
| `bridge_publish_latency_seconds` | `Histogram` | `perch_bridge_publish_latency_seconds{_bucket,_sum,_count}` |
| `bridge_late_published_seconds` | `Histogram` | `perch_bridge_late_published_seconds{…}` |

Registering `"bridge_broadcast_lagged_total"` would emit
`perch_bridge_broadcast_lagged_total_total`. A unit test asserts the encoded text contains each of
the seven appendix names exactly once (§14 T-11), because this is the kind of mistake that ships and
then lives in a dashboard forever.

### 11.2 The seven the appendix names

All seven from `APPENDIX-NORMATIVE.md` §6 / `07` §12, minus the one that is not the bridge's
(§11.4). Every one is exported from day one, because §4's honesty rules are only credible if they
are measured.

### 11.3 Five the bridge adds, and five more it needs to stay honest

| Metric | Type | Why it must exist |
|---|---|---|
| `perch_bridge_ingested_total{stream}` | Counter | first term of the accounting invariant (§5.7) |
| `perch_bridge_source_events_published_total{stream}` | Counter | third term. Together with `dropped` these make the invariant checkable from a scrape rather than a debugger |
| `perch_bridge_coalesced_total{stream,key}` | Counter | a coalesce is not a drop and must not be counted as one |
| `perch_bridge_spool_torn_tail_total`, `perch_bridge_spool_corrupt_total` | Counter | §5.5's two recovery paths, which are otherwise invisible |
| `perch_bridge_connection_state{identity}` | Gauge | 0 down / 1 connecting / 2 authenticated. Ten sockets and no per-socket signal is a debugging dead end |

Plus five that exist to make §7.5, §8.6, §9.1 and §9.3 renderable rather than inferable — four
in the table, and `perch_bridge_watch_membership_refused_total` noted under it:

| Metric | Type | Why it must exist |
|---|---|---|
| `perch_bridge_hold_undeliverable_total` | Counter | §7.5 — no operator carries a Nostr pubkey, or a `hold_id` failed its shape assert (F18, F21) |
| `perch_bridge_lease_store_absent` | Gauge | §9.3 — `/leases` renders `no-lease-store-configured` rather than an empty list (F16) |
| `perch_bridge_case_channel_conflict_total` | Counter | §9.1.4 — a non-zero value means two parties minted case ids for one `hunt_id` and a daemon incident record names a channel that was never created (F20). It should be permanently zero, and the amendment in §9.1.6 makes it structurally so |
| `perch_bridge_case_channels_created_total{clause}` | Counter | §9.1.4 — the denominator ADR 0018 C4's promoted/suppressed ratio needs, split by the three promotion clauses, from the process that did the creating. With only clause 3 enabled, the other two labels reading zero is how "the bar is configured off" is *shown* rather than believed |

The `clause` label has exactly three values (`held_action`, `correlated_incident`, `manual`),
mirroring `channels::PromotionClause`. `perch_bridge_watch_membership_refused_total` (F19) is a
fifth, deliberately un-labelled: there is one `#watch` and one alarm identity, so a label would
carry no information.

### 11.4 One counter that is **not** the bridge's

`perch_queue_reconcile_divergences_total` (`APPENDIX-NORMATIVE.md` §4 layer 3) counts divergences
between `query_needs_action` and `GET /v1/response/holds`. Both reads happen in the console. The
bridge cannot observe either — it holds no relay read path at all (§8.4 item 2). It belongs to
`14-CLIENT-ARCHITECTURE.md`. Recorded here so it is not implemented twice or, worse, once in the
wrong process where it would always read zero.

---

## 12. Failure modes, and what the operator sees

Every row is a real, reachable state. The last column is the obligation this table places on
`14-CLIENT-ARCHITECTURE.md` and `06`'s copy library.

| # | Failure | How the bridge detects it | Bridge behaviour | Counter | Console shows |
|:-:|---|---|---|---|---|
| F1 | `subscribe_runtime_events()` returns `None` | at `build()` | `BridgeError::NoBroadcaster`; daemon startup aborts | — | daemon did not start; nothing to render |
| F2 | broadcast lag | `RecvError::Lagged(n)` | `GapSlot` on every spooled stream; loop continues | `…broadcast_lagged_total` | gap row: `N events were lost before the bridge saw them — the daemon does not retain them` |
| F3 | broadcast closed | `RecvError::Closed` | drain the spool best-effort, then exit | — | `bridge: down (last envelope HH:MM:SS)` in the governance strip |
| F4 | spool append fails, evidence | `io::Error` on write | shed oldest, `gap {spool_evicted}`, continue | `…dropped_events_total{cause="spool_evicted"}` | gap row with an exact `seq` range and a `re-fetch from the daemon` control |
| F5 | evidence spool at budget | byte accounting | evict oldest segment | same | same |
| F6 | alarm spool at budget | byte accounting | **refuse** new alarm work, log `error` | `…alarm_spool_full_total` | `holds are not reaching the console` — destructive register |
| F7 | relay unreachable | connect error | exponential backoff, spool grows | `…connection_state{identity}=0` | banner; the verdict queue falls back to the daemon's open-hold list, marked stale |
| F8 | relay up, Redis down | `OK false` with `rate-limited: shared admission unavailable` (`connection.rs:728-735`, from `AdmissionError::Unavailable` at `admission.rs:33-36`) | distinct backoff; **never** rendered as "connected" | `…admission_rejections_total{reason="unavailable"}` | `relay admission unavailable — nothing is being published`. Note the string carries **no** `retry in Ns` hint, so the client gate falls back to `DEFAULT_RATE_LIMIT_SECONDS = 10` (`BUZZ desktop/src/shared/api/relayRateLimitGate.ts:15`) |
| F9 | rate limited with a hint | `OK false` / `CLOSED` with `retry in Ns` | honour the hint; clamp at 300 s | `…admission_rejections_total{reason="exceeded"}` | quiet — this is the pacer working |
| F10 | `OK false: restricted: not a channel member` | on a `46010` | do not advance the cursor; retry once; then F13 | `…hold_undeliverable_total` | `hold could not be filed in its case` |
| F11 | `OK false: invalid: event timestamp too far from server time` | on any frame | **P0.** log `error`, compare against the daemon clock, stop publishing that identity | `…admission_rejections_total{reason="timestamp"}` | `bridge and relay clocks disagree — nothing is being published` |
| F12 | `OK false: restricted: unknown event kind` on a `46010` | at ingest | the relay fork is not applied. Log `error` naming `10-RELAY-FORK.md`; hold stream is dead; alarm | `…hold_undeliverable_total` | `holds are not reaching the console` |
| F13 | OK never arrives within the publish window | timer | discard the signed frame, return records to the spool head, re-stamp next tick (§5.6) |  `…dropped_events_total{cause="publish_window_expired"}` | gap row, `cause: publish_window_expired` |
| F14 | `duplicate: channel already exists` on `9007` | `OK false` with that message | **treat as success**, adopt the UUID, continue to step 2 | — | nothing; benign |
| F15 | mention row silently missing | **the bridge cannot detect this at all** | none available | — | the console's daemon reconcile is the only detector; `perch_queue_reconcile_divergences_total` |
| F16 | no containment lease store configured (`lease_store_path` unset) | `state.current_containment_store()` was `None`, so `containment` is `None` | publish no containment-lease cards | `…lease_store_absent = 1` | `/leases` renders `no-lease-store-configured` — naming `runtime.containment.lease_store_path` — as a first-class state, not an empty list |
| F17 | no NIP-OA attestation on an identity | `agent_owner_pubkey` cannot be observed from the client; detected as sustained F9 at 60/min | log the warning at §8.2 on startup | `…admission_rejections_total` rising | `the bridge is publishing at half rate` |
| F18 | no operator Nostr pubkey configured | `effective_principals()` yields no `nostr_pubkey` (§7.5) | refuse to publish any `46010`; log `error` | `…hold_undeliverable_total` | `no operator is configured to receive holds` — and `/settings` says which config key |
| F19 | `OK false: restricted: not a channel member` on a `26006` | the alarm identity is not a member of `#watch` (`event.rs:850-852`) | `BridgeError::WatchChannelMembership`; alarm immediately, **do not retry** — backoff cannot add a membership row | `…watch_membership_refused_total` | `hold alarms are not reaching the floor` — destructive register, naming `#watch` and the provisioning step |
| F20 | a `CasePromoted` names a `case_id` different from the one already routed for its `hunt_id` | the routing map lookup (§9.1.4) | `BridgeError::CaseChannelConflict`; create **nothing**, log `error` | `…case_channel_conflict_total` | the case the console was sent to has no channel — rendered as a named provisioning failure, never as an empty case |
| F21 | a `hold_id` of the wrong shape reaches the publish seam | `HoldId::parse` (§8.6) | `BridgeError::MalformedHoldId`; **no event is built**, so nothing reaches `46010` or `26006` | `…hold_undeliverable_total` | `hold could not be filed in its case` — same string as F10; the operator's remedy is identical |

F15 is the one row with no bridge-side answer, and it is the reason
`APPENDIX-NORMATIVE.md` §4 layer 3's reconciliation is specified as mandatory.

F19 and F20 are new in this revision. Both are **provisioning or contract** failures rather than
transient ones, and both are alarmed rather than retried: the distinguishing test is whether the
same request would succeed later without a human changing something. For F7–F9 it would; for
F19–F21 it would not.

---

## 13. Configuration

`SwarmConfig` is `#[serde(deny_unknown_fields)]` (`AMBUSH crates/swarm-core/src/config/root.rs:4-6`),
so a `perch` block is a typed field addition, not a free key. Every field carries
`#[serde(default)]` for the reason `ContainmentSettings` documents verbatim
(`AMBUSH crates/swarm-core/src/config/runtime.rs:88-92`):

> `rulesets/default.yaml` does NOT set it, and cannot: that file is digest-signed by
> `rulesets/default.yaml.sig.json` and the signing key is not in the repository, so adding a key to
> it fails its own load gate. Every field here is `#[serde(default)]` for that reason — the shipped
> ruleset keeps loading, and a deployment adds the block to its own config.

```yaml
# a deployment's own config, never rulesets/default.yaml
perch:
  enabled: true
  relay_url: "wss://relay.example.internal"
  # Environment variable holding 32 bytes of hex. Absent => refuse to start (§7.2).
  nostr_seed_env: "PERCH_BRIDGE_NOSTR_SEED"
  # Environment variable holding the NIP-OA owner attestation tag JSON (§8.2).
  auth_tag_env: "PERCH_BRIDGE_AUTH_TAG"
  # MUST resolve outside the repository. Refused otherwise (§5.2).
  spool_dir: "/var/lib/ambush/perch-spool"
  spool_max_bytes: 268435456        # PERCH_SPOOL_MAX_BYTES, appendix §6
  segment_bytes: 8388608            # PROPOSED
  publish_tick_ms: 1000             # PERCH_PUBLISH_TICK, appendix §6
  frame_max_bytes: 65536            # PERCH_FRAME_MAX_BYTES, appendix §6
  escalation_heartbeat_ms: 60000    # PROPOSED, §6.2
  alarm_heartbeat_ms: 60000         # PROPOSED, §6.5
  alarm_burst_per_min: 40           # PROPOSED, §8.4
  gap_flush_ticks: 3                # PROPOSED, §3.6
  late_published_ticks: 2           # invented, appendix §6
  publish_window_margin_secs: 120   # PROPOSED, §5.6
  case_ttl_seconds:                 # §9.2; per threat class, with a default
    default: 2592000                # 30 days
  # The standing ops channel the 26006 alarm is h-scoped to (§8.6). Provisioned
  # ONCE by the relay operator, never created by the bridge. MUST be
  # visibility: private; perch-alarm AND every operator console MUST be members
  # (§8.3 items 8-10). None of the three is checkable from here -- the bridge
  # holds no read path -- so the first alarm is the test. Absent while `enabled`
  # is true => refuse to start; the alternative is a bridge that alarms nobody
  # and says nothing.
  watch_channel: "…uuid…"
  lane_channels:                    # the twelve standing threat-class channel UUIDs
    lateral_movement: "…uuid…"
    # … eleven more, in escalation.rs:315-330's order …
```

**`enabled` defaults to `false`.** A daemon that gains this crate must opt in; the bridge holds
`AdminChannels` on a relay and writes to a colony's record, and neither should arrive by upgrade.

`lane_channels` is a required map when `enabled` is true, validated at load against
`standard_threat_classes()` (`AMBUSH crates/swarm-runtime/src/escalation.rs:315-330`, twelve
entries, verified). A missing class is a config error, not a runtime surprise, because
`ThreatClass::Custom(String)` exists (`swarm-core/src/pheromone.rs:16-31`) and a `Custom` finding
with no lane must land somewhere deliberate rather than nowhere.

---

## 14. Test plan

**This crate adds zero CI gates.** All of these run under the existing `cargo test` job; none needs
a new `tools/check-*.sh`, which matters because `AMBUSH tools/check-gates-wired.sh` enumerates every
`tools/check-*.sh` — tracked
or untracked — and fails on any not named by a real workflow `run:` step. Adding a gate is a
two-part change; these tests are not gates.

The one CI-facing change the crate does force is the **three-part edit to the already-wired
`tools/check-workspace-layering.sh`** (§1.4a). That adds no script, so `check-gates-wired.sh` has
nothing new to find. T-17 exists so the heading regression that motivated §1.4a fails in
`cargo test` — seconds — rather than in the layering gate at the end of CI.

| # | Test | Asserts |
|:-:|---|---|
| T-1 | `classify_is_exhaustive` | a compile-time test: `classify` has no `_` arm. Enforced by the absence itself — the test is a `#[test]` that constructs one of each of the 11 variants and asserts a total mapping, so a 12th variant fails the build in two places |
| T-2 | `receive_loop_records_lagged` | drive a `broadcast::channel(4)` past capacity with a parked receiver; assert `perch_bridge_broadcast_lagged_total` moves and a `GapSlot` is set on **every** spooled stream |
| T-3 | `accounting_invariant_holds_under_eviction` | `ingested == Σdropped + published`, per stream, after forcing eviction. This is `buzz-acp lib.rs:453`'s invariant and it is the one line of the specification that must be asserted |
| T-4 | `coalesce_is_not_a_drop` | 10 snapshots in one second produce 1 frame, `coalesced_total` = 9, `dropped_events_total` = 0 |
| T-5 | `escalation_edge_triggers` | 600 identical `Escalation` events over 60 s at one level produce **2** frames (one edge + one heartbeat), not 600. Guards against the corrected `emitted_at_ms` finding in §6.2 |
| T-6 | `torn_tail_truncates_and_gaps` | write a segment, truncate its last record mid-payload, reopen; assert truncation, `torn_tail_total`, and an exact `gap` range |
| T-7 | `colony_hash_mismatch_refuses_open` | a spool created under colony A refuses to open under colony B |
| T-8 | `p_tag_assert_blocks_publish` | an uppercase or 63-char pubkey yields `BridgeError::MalformedPTag` and **no** event is built |
| T-9 | `bridge_issues_no_req_frames` | a fake relay records every inbound frame over a full run; assert zero `REQ` and zero `COUNT`. This is §8.4 item 2 as a test |
| T-10 | `frame_never_exceeds_cap` | property test over random record sizes; every frame ≤ `PERCH_FRAME_MAX_BYTES` and ≥ 1 record |
| T-11 | `metric_names_match_the_appendix` | encode the registry and assert each of the seven `APPENDIX-NORMATIVE.md` §6 names appears exactly once. Guards the `_total` trap in §11.1 |
| T-12 | `created_at_is_stamped_at_drain` | spool a record, advance a fake clock 40 minutes, drain; assert `created_at` is within 1 s of drain time and the body carries `late_published_ms ≈ 2_400_000` |
| T-13 | `retry_reuses_identical_bytes` | drop the connection mid-flight; assert the retried frame is byte-identical, and that past the §5.6 window it is discarded and re-stamped instead |
| T-14 | `duplicate_channel_is_success` | a fake relay answering `duplicate: channel already exists` advances to step 2 |
| T-15 | `alarm_never_shed` | fill the evidence spool to eviction while alarms flow; assert zero alarm drops and that evidence shed instead |
| T-16 | `no_signature_field_in_any_card_body` | serialize one card of each of the four bridge-produced markers; assert none contains `signature`, `signed_by` or `verified`. §7.3 as a test |
| T-17 | `owns_headings_are_the_gate_literals` | read this crate's own `src/lib.rs` at test time, right-strip each line as the gate does, and assert both `"//! ## Owns"` and `"//! ## Does not own"` are present as whole lines. Twelve lines of test that make the §1.4a failure impossible to reintroduce, and it runs in `cargo test` rather than waiting for the layering gate in CI |
| T-18 | `both_promotion_triggers_plan_a_create` | `ensure_case_channel` with a `Held` trigger and with a `Promoted` trigger, each on an unrouted `hunt_id`, both yield a `CreateCaseChannel` plus one `AddOperator` per operator. §9.1.4; this is the test that would have failed against the first draft |
| T-19 | `case_id_conflict_creates_nothing` | route one `hunt_id` → `A` via `Held`, then a `Promoted { hunt_id, case_id: B }` yields `CaseChannelConflict`, the counter moves, and the returned step list is empty |
| T-20 | `hold_id_shape_is_asserted` | `HoldId::parse` accepts a lowercase hyphenated UUID and rejects `hold:01K3…`, `hold_a1f4c2e9`, an uppercase-hex UUID, and the empty string, each with `MalformedHoldId` and no event constructed |
| T-21 | `alarm_frame_carries_both_h_and_p` | the built `26006` has exactly one `h` tag equal to `perch.watch_channel` and one `p` per `OperatorScope::Approve` principal, and its payload has exactly the five keys of §8.6 item 5 — asserted over the serialized JSON, so a widened struct fails |

An **integration** test against a real relay belongs in `crates/buzz-test-client/tests/`
(`02-ARCHITECTURE-INTEGRATION.md` decision 11 keeps that crate for exactly this reason) and is
`16-INVARIANT-TESTS.md`'s to place.

---

## 15. What this document decided, and what it left open

**Decided here** (bind to these; they are in `commitments`):

1. The receive loop imports `stream`, `spool`, `metrics` and nothing else, so it cannot acquire a
   network call by accident.
2. Loss rides in an optional `gap` / `coalesced` block on the existing seven markers — **no eighth
   marker** — and a card with an empty payload and a populated `gap` block is legal (§3.6).
3. Three loss causes, named apart: `broadcast_lagged` (count only, never a range),
   `spool_evicted` (exact range), `coalesced` (not loss).
4. `seq` is assigned at spool append, per `(colony_id, issuer)`, and never rewinds.
5. The telemetry stream is **not** disk-spooled — a proposed amendment to
   `APPENDIX-NORMATIVE.md` §6's `PERCH_SPOOL_MAX_BYTES` row (§5.1).
6. The bridge is **write-only**: zero `REQ`, zero `COUNT` frames, ever (§8.4).
7. The bridge is the **only** creator of case channels, on **two** triggers — `ResponseHeld`
   (clause 1) and the proposed `CasePromoted` (clauses 2 and 3) — through one entry point,
   `ensure_case_channel`. It sets the channel's `ttl` on the `kind:9007` event from
   `perch.case_ttl_seconds`, and requires `ChannelsWrite` + `AdminChannels` on `perch-alarm`
   (§9.1, §9.2, §8.3). The routing map is single-valued and first-write-wins; a conflicting
   `case_id` is refused, never adopted.
8. `ambush:lease:v1` comes from a 1 Hz `open_leases()` diff and never carries `remaining_ms` or
   `expired` (§9.3).
9. `ambush:rollback:v1` for an operator release is the **console's** leg-1 publish, not the
   bridge's (§9.4).
10. Metrics live on a `perch`-prefixed registry at `GET /metrics/perch`, registered without the
    `_total` suffix (§11.1).
11. `perch.enabled` defaults to `false`.
12. The `26006` frame carries **both** an `h` tag naming a **private** `#watch` and one `p` tag per
    `OperatorScope::Approve` principal. The `h` tag is the load-bearing half — `P_GATED_KINDS` is
    enforced only for global subscriptions (`req.rs:219`) and is skipped for the h-scoped REQ the
    console opens — and W-1 and ADR 0017 are complementary rather than mutually destructive
    (§8.6, measured).
13. `#watch` is standing configuration (`perch.watch_channel`), provisioned **private**, with
    `perch-alarm` **and every operator console** as members — provisioning items 8, 9 and 10 (§8.3).
    The bridge does not create it and cannot pre-flight it (zero `REQ`); the first alarm is the
    test, and a failure is alarmed and never retried (F19). A non-member console gets a relay
    `CLOSED`, which `14-CLIENT-ARCHITECTURE.md` must render as *"you are not on the watch floor"*.
14. `hold_id` is asserted to be a lowercase hyphenated UUID at the publish seam
    (`HoldId::parse`), with a colon anywhere a hard refusal. The bridge never mints one; pinning the
    pattern once on the wire is `13-WIRE-SCHEMAS.md`'s (§8.6).

**Left open, with the smallest fix named:**

| Open | Owner | Smallest fix |
|---|---|---|
| No operator Nostr pubkey exists in Ambush config; `46010` cannot be `p`-tagged (§7.5) | the backend bill | `nostr_pubkey: Option<String>` on `OperatorPrincipalConfig`, `#[serde(default)]` |
| TTL-expiry releases produce no `ambush:rollback:v1` (§9.4) | the backend bill | **B1c** — a thirteenth `RuntimeEvent::ContainmentReleased`, PROPOSED, ~0.5 ew |
| Whether `nostr` with `default-features = false` deletes the `chacha20` duplicate (§1.5) | this crate's first commit | three commands, listed |
| Every constant marked PROPOSED in §13 | measurement, after the first real spool drain | — |
| Manual promotion — the only clause ADR 0018 C4 enables first — has no case-channel creator (§9.1.2) | the backend bill | **B1d** — a `RuntimeEvent::CasePromoted`, PROPOSED, ~0.5 ew, seven upstream edits itemised in §9.1.5. **Not cuttable** while clause 3 is the enabled one |
| Whether `case_id` is minted by the daemon or by the console (§9.1.6) | `12-BACKEND-BILL-API.md` | daemon-side removes the conflict arm; console-side needs zero OpenAPI change. Either works; the bridge's behaviour is identical apart from whether `CaseChannelConflict` is reachable |
| Two operators deciding one hold — the daemon's CAS picks a winner, the relay keeps both signed `ambush:verdict:v1` cards forever, and nothing marks the loser | `13-WIRE-SCHEMAS.md` (a `leg2.state` value) + `16-INVARIANT-TESTS.md` (the invariant and its two-console E2E) | **Not the bridge's, and recorded here so nobody assumes it is.** The bridge publishes no verdict card; it publishes the `46010` and the `26006` whose `p` tag sets are what make more than one console eligible in the first place (`APPENDIX-NORMATIVE.md` §4 layer 1 p-tags *every* `OperatorScope::Approve` principal). The bridge cannot dedupe: a `kind:9` is immutable and the bridge has no relay read path (§8.4). Even B1's hold-state republish would produce a lifecycle card, not a mark on the losing verdict |
| The `26006` reconciliation's *upstream* half — whether `26006` actually joins `P_GATED_KINDS` | `10-RELAY-FORK.md` / ADR 0017 | land it, described as closing the **global** form only. §8.6 shows the two mechanisms do not conflict; what must change is ADR 0017's claim to be the whole answer |

**Proposed amendments this document files, collected:**

| id | Against | Change |
|---|---|---|
| §5.1 | `APPENDIX-NORMATIVE.md` §6 | `PERCH_SPOOL_MAX_BYTES` reads "256 MiB per **disk-spooled** stream (evidence, alarm); the telemetry stream is not disk-spooled" |
| B0 | the backend bill | `nostr_pubkey: Option<String>` on `OperatorPrincipalConfig` (§7.5) |
| B1c | the backend bill | `RuntimeEvent::ContainmentReleased`, so a TTL-expiry release can produce `ambush:rollback:v1` (§9.4) |
| **B1d** | the backend bill | `RuntimeEvent::CasePromoted`, so the manual-promotion clause has a case-channel creator (§9.1.5). **New in revision 2, and the one that is not cuttable** |
| §9.1.6 | `12-BACKEND-BILL-API.md` | mint `case_id` daemon-side and return it, rather than requiring it in `IncidentMintRequest` — removes the conflict arm entirely. The alternative is spelled out with its cost |
| §8.3 items 8–9 | ADR 0017 / the relay operator's runbook | `#watch` is provisioned **private**, and `perch-alarm` is a member of it. Without both, `26006` disclosure is unchanged or the alarm path is dead |
| §8.6 item 4 | ADR 0017 | describe the `P_GATED_KINDS` entry as closing the **global** `26006` form, not as closing the hole. The h-scoped REQ the console opens never reaches that gate (`req.rs:219`) |
| **C-A4** | `tools/copy-ban-list.tsv` (`16-INVARIANT-TESTS.md`'s) | the `approve` row needs an identifier exemption in the same shape the `deny-label` row already has (`PolicyVerdict\|policy_verdict`): `OperatorScope::Approve\|operator_scope\|scopes\.contains`. `OperatorScope::Approve` is Ambush's own typed variant (`swarm-core/src/config/operator.rs:84-90`) and is the only way to name who a hold is addressed to. Scope note: the shipped gate reads `docs/assets/*.svg` and `$PERCH_DESKTOP_ROOT`'s `.ts`/`.tsx` roots and **never** `crates/**/*.rs`, so this crate is mechanically out of its scope today; the amendment matters for the strings this document hands the console, and if the gate is ever widened |

Two further regex overreaches worth handing the copy-gate owner rather than working around: the
`bare-source-count` row's `(^|[^a-z])sources?([^a-z]|$)` fires on `thiserror`'s `#[source]`
attribute and on `deny.toml`'s `[sources]` table, and the `bare-lane` row fires on ADR 0009's
*advisory lane* — an upstream term of art for the `sphinx_agent` / `correlation` modules that has
nothing to do with a threat-class channel. Neither is a false negative, so neither is urgent; both
would be noise on the first widened scan.

**One correction issued to the ground survey**, because a producer would otherwise implement a
dedupe that never fires: `ambush-touchpoints.md` blocker B-3's *"all ten ticks in a second emit
byte-identical events"* is false. `RuntimeEvent::Escalation` and
`RuntimeEvent::ConcentrationSnapshot` both stamp `emitted_at_ms: now_ms()` at publish
(`AMBUSH crates/swarm-runtime/src/escalation.rs:253` and `:288`) and neither carries the
seconds-resolution `now`. The mitigation is edge-triggering, not deduplication (§6.2).
