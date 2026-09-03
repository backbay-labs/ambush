# ADR 0012: The Buzz Relay Is The Read Substrate, And `swarm_detect --serve` Stays The Only Writer Of Ambush State

## Status

Proposed on 2026-08-30. Perch, Phase 0 (relay fork) and Phase 1 (the bill).

**Extends ADR 0010.** That ADR established, for containment release, that the writer has
to be the process that opens the containment leases, sweeps them, and holds the governance
authority.
This ADR generalizes the same argument to every route the Perch bill adds, and states the
symmetric half — what a *second* store, the relay, is allowed to be.

Path prefix convention as in ADR 0011: `BUZZ ` is `block/buzz` at `eed74bde2`.

## Context

Perch needs two things that pull in opposite directions. It needs a read surface that can
enumerate, page, search and fan out live to many clients across a network. And it needs
every mutation of Ambush state to happen in exactly one process, because that process
holds a hash chain, a receipt counter and a containment-lease map in memory.

The temptation is to satisfy both with one store. That is the failure this ADR forecloses.

### Fact 1: what the relay actually does per delivery, not what it is described as

`filter_fanout_by_access` (`BUZZ crates/buzz-relay/src/handlers/event.rs:115-222`) is the
single guarded send chokepoint in the relay process for local WebSocket delivery. It is
called on the ingest fan-out path and on the Redis cross-node `subscribe_local` path — the
comment at `:135-138` says so and names why the gate lives there. For a channel-scoped
event it re-resolves the receiver's community label (`:126-131`), applies
`AUTHOR_ONLY_KINDS` (`:139-152`) and `SHARED_GATED_KINDS` (`:157-175`), and then checks
channel membership. Not at subscription time: at **delivery** time, every time. A member
removed from a case stops receiving its events on the next frame, with no subscription
teardown and no client cooperation.

That property is the compartment. Ambush has nothing like it and building it is not a
route, it is a subsystem.

Three more, each measured rather than described:

- **Search is the write.** `BUZZ schema/schema.sql:223-227` declares
  `search_tsv TSVECTOR GENERATED ALWAYS AS (CASE WHEN kind IN (…) THEN NULL::tsvector ELSE
  to_tsvector('simple', content) END) STORED`. The index update is the row insert; there
  is no indexer to run, fall behind, or reconcile. The `CASE` excludes eight privacy-gated
  kinds and **46010 is not one of them**, so the fork of ADR 0013 needs no schema change
  and no migration.
- **Scoping is symmetric and stated in source.** `fan_out_scoped`
  (`BUZZ crates/buzz-relay/src/subscription.rs:379-495`) routes an event with
  `channel_id = Some(..)` through the channel indexes only and an event with
  `channel_id = None` through the global indexes only; the comment at `:487-492` states
  the invariant in both directions. Neither family can leak into the other. (The
  appendix's citation of `:486-491` is off by one at both ends; the claim is exact.)
- **Enumeration is server-authoritative.** `apply_channel_scope_to_query`
  (`BUZZ crates/buzz-relay/src/handlers/req.rs:1069-1092`) runs in the relay process for
  both `REQ` (`req.rs:345`) and `POST /query` (`bridge.rs:1372`, `:1670`); with no `#h` it
  sets `query.channel_ids = accessible_channels` and leaves
  `channel_ids_include_global = true`, which the SQL builder
  (`BUZZ crates/buzz-db/src/store/event.rs:442-461`) renders as
  `AND (channel_id IS NULL OR channel_id IN (…))`.

### Fact 2: two processes, and the plan set conflated them

`docs/plans/ambush-ui/09-ROADMAP-AND-RISKS.md` §3.1 assigns every bill item to
`swarm_detect --serve` and separately cites `crates/swarm-runtime-http/src/http/state.rs`
as "the operator router". Both statements are true and jointly impossible.

- `LocalOperatorSurface::router()` (`http/state.rs:292-488`, 49 `.route(` calls) is built
  by `Command::Serve` in `crates/swarm-cli/src/core.inc:3344-3400` and served on
  `config.operator.bind_addr`, default `127.0.0.1:7766`
  (`crates/swarm-core/src/config/defaults.rs:210-212`) — process **`swarmctl serve`**.
- `detect_http_router` (`crates/swarm-ingest-runtime/src/ingest/mod.rs:2540-2576`) plus the
  merged `containment_operator_router` is served on `cli.bind` by **`swarm_detect --serve`**,
  whose operator-facing default base URL is `http://127.0.0.1:9090`
  (`defaults.rs:214-216`) — the value `swarmctl quarantine` already targets.

`LocalOperatorSurface::from_config` builds its own `DefaultControlPlane`, which builds its
own `ConfiguredRuntimeStack`. The consequences are concrete, not stylistic. Its incident
store is a different map: `CorrelationSettings.incident_store` is
`#[serde(default)] BundleStoreConfig`, whose `#[default]` variant is `Memory`
(`crates/swarm-core/src/config/storage.rs:62-71`). Its containment lease store is a
different map, for exactly the reason `http/containment.rs:19-33` already writes down. It
holds no `RuntimeEventBroadcaster` at all. A hold route mounted there would answer
"no such hold" for every hold the daemon is holding — ADR 0010's Fact 1, one object up.

### Fact 3: the relay copy will be faster, prettier, and wrong to trust

The relay's copy of every finding and receipt will be quicker to query, nicer to render
and searchable. An operator under time pressure will start treating it as the record. If
the bridge drops frames, the console then shows a coherent, signed, **incomplete** story
with nothing marking the gap. `docs/plans/ambush-ui/00-BRIEF.md` §8.1 names this as the
first of four risks that must be mechanized rather than managed.

## Decision

**The Buzz relay is the read / subscribe / search substrate. `swarm_detect --serve`
remains the only writer of Ambush state. The relay is never the record.**

Five clauses.

**1. Every route the Perch bill adds is mounted by `swarm_detect --serve`.** None is added
to `LocalOperatorSurface::router()`. This is commitment C1 of
`docs/plans/ambush-ui/build/12-BACKEND-BILL-API.md` §1.1 and it is recorded here because it
is an architecture decision, not an API detail. The crate split it forces — the engine in
`crates/swarm-ingest-runtime/src/ingest/` where `IngestState`'s private fields are
reachable, the routes in `crates/swarm-runtime-http/src/http/perch.rs` where
`require_bearer_auth` and `require_operator_api_scope` live — is that file's to specify.

**2. The console process issues no write to any Ambush store outside a named allowlist.**
The allowlist is exactly five: `POST /v1/response/holds/{id}/decide`,
`POST /v1/operator/findings/{id}/feedback`, the incident-minting write behind
promote-to-case, `POST /v1/operator/containment/leases/{id}/release`, and
`POST /v1/operator/review/sessions`. Any other Ambush-bound non-`GET` from the console tree
fails CI. This is `08` INV-01, and it is the mechanized form of "Perch never authorizes"
(ADR 0014).

**3. The relay holds the conversation and the notification. The daemon holds the record.**
Every rendered receipt carries a verify affordance that reads the **daemon** (`B2r`), not
the relay. A `kind:46010` present on the relay and absent from `GET /v1/response/holds`
renders as **FORGED**, in the destructive register, and is excluded from any export bundle
(`08` INV-35). The divergence is counted, not merely displayed.

**4. Every published envelope carries a monotonic per-issuer sequence, and a gap renders as
a gap.** This is non-negotiable and it is what makes clause 3 checkable rather than
aspirational. The sequence is assigned by the bridge at spool append, per
`(colony_id, issuer)` — a decision `11-BRIDGE-CRATE.md` §15 makes and this ADR binds to,
because it has a consequence for scheduling: gap-marking does **not** depend on B6.
`docs/plans/ambush-ui/09-ROADMAP-AND-RISKS.md` §3.1 records B6 as the source of `seq`; with
the bridge subscribing in-process it is not.

**5. The relay fork stays a bug fix.** Kind 46010 is defined
(`BUZZ crates/buzz-core/src/kind.rs:578`), listed in `ALL_KINDS` (`:745`), queried by the
desktop needs-action feed, and rejected at ingest because it is absent from
`required_scope_for_kind` — whose default arm at
`BUZZ crates/buzz-relay/src/handlers/ingest.rs:545` is
`_ => Err("restricted: unknown event kind")`. `required_scope_for_kind` is called only by
`ingest_event` at `ingest.rs:2249-2252`, in the relay process on the shared WebSocket +
HTTP ingest task, and its `Err` becomes `IngestError::Rejected`, dropping the event before
storage, before the mention index and before fan-out. Fixing that is upstreamable. The size
and shape of the patch is `docs/plans/ambush-ui/build/10-RELAY-FORK.md`'s; the *rule* is
this ADR's: **no proposal may add a stored kind without a written argument against the
marker path and a named maintainer for the three-registry sync** (ADR 0013).

## Alternatives Considered

**Put the hold store in the relay.** Postgres is already there, it is durable, it has
migrations, and it would delete B1's persistence work. Rejected on ADR 0010's argument
without needing a new one: the daemon holds `previous_commit_hash` and `receipt_counter` in
memory and mints the capability lease at decision time, so a second writer advances a chain
the first cannot see. The relay would also become the thing an attacker edits to change
what was authorized. `00-BRIEF.md` §10 Q5's trigger to revisit is "never, without
revisiting ADR 0010's single-writer argument", and this ADR endorses that wording.

**Have Perch read the daemon directly and skip the relay.** Loses the compartment, the
search, the pagination and the resumable live path from Fact 1, and puts a
`127.0.0.1`-bound daemon on the network. Rejected. Note the shape it would take is real
and already exists in miniature: `swarmctl quarantine` is an HTTP client against
`runtime_base_url` (`core.inc:3101-3120`), and leg 2 of every Perch write is exactly that
shape (ADR 0014).

**Mount the bill on `LocalOperatorSurface` because that is where the other 49 routes are.**
Rejected on Fact 2. The symmetry is superficial and the stores are different objects.

## Consequences

### Positive

- Ambush gets enumeration, pagination, FTS, resumable fan-out and per-delivery compartment
  re-authorization without building any of them.
- The single-writer property that ADR 0010 established for one object now covers the hold
  store, the incident store and the receipt chain, stated once.
- The relay fork is genuinely offerable upstream, which keeps the rebase cost bounded in
  the one crate family Perch does not want to hard-fork.

### Negative

- Two stores means a reconciliation path, and reconciliation that is optional is
  reconciliation that does not run. The relay's mention index makes this sharper than
  usual: `Db::insert_event_with_thread_metadata`
  (`BUZZ crates/buzz-db/src/store/event.rs:1673-1698`) commits the event, then writes
  `event_mentions` on a **separate** pool transaction and downgrades any failure to
  `tracing::warn!` (`:1690-1696`). The publish still returns `OK true`. A hold can be
  stored, acknowledged, and permanently invisible to every `#p` feed — and because the
  `events` insert is `ON CONFLICT DO NOTHING`, a republish of identical bytes does not
  retry the mention write, so the hole is not self-healing. **Reconciliation against
  `GET /v1/response/holds` is therefore mandatory, not best-effort**, and
  `perch_queue_reconcile_divergences_total` is a P0 counter.
- Three new services (relay, Postgres, Redis) against Ambush's shipped two-service compose.
  That is decision D22's budgeted Phase-2 packaging line and it has an owner.
- `swarm_detect --serve` grows an operator write surface it did not have. Every route on it
  inherits `require_bearer_auth` (`crates/swarm-runtime-http/src/http/auth.rs:182-220`),
  which rate-limits, requires `Authorization: Bearer` and inserts
  `AuthenticatedOperatorPrincipal` — **and performs no scope check**. Scope is opt-in per
  handler via `require_operator_api_scope` (`auth.rs:154-166`), called at exactly nine
  sites in the workspace today. Every Perch route must opt in explicitly; forgetting is
  silent.

## Verification

- **PROPOSED** `tools/check-perch-write-allowlist.sh`: greps the Perch feature tree for
  Ambush-bound non-`GET` calls and fails on anything outside clause 2's five. Wired as a
  workflow step in the same PR (ADR 0009's `check-gates-wired.sh` rule).
- **PROPOSED** an integration test that mounts the bill's routes on
  `LocalOperatorSurface` and asserts they answer "no such hold" for a hold the daemon
  holds — the fixture form of Fact 2, in the spirit of ADR 0009's deliberately-broken
  variants. Without it, clause 1 is a comment.
- The relay fork's own test list is `10-RELAY-FORK.md` §6.

## Follow-On Work

- Specify the reconcile cadence precisely. `APPENDIX-NORMATIVE.md` §4 layer 3 says
  "`query_needs_action` on connect, on reconnect and on every `26006`", but **no desktop
  code path reaches `query_needs_action`**: that function
  (`BUZZ crates/buzz-db/src/store/feed.rs:171-201`) is reachable only through the
  `feed_types` extension on `POST /query` (`bridge.rs:1155-1246`), whose only producer in
  the repository is `BUZZ crates/buzz-cli/src/commands/feed.rs:59`. The desktop's
  needs-action query is `BUZZ desktop/src-tauri/src/commands/messages.rs:97-101`, a
  hand-built `{"kinds":[46010,46011,46012],"#p":[me],"limit":20}` POSTed to `/query` with
  NIP-98 auth — and the same file returns `activity` and `agent_activity` as literal empty
  `Vec`s at `:156-157`. Proposed brief amendment **AD-A2**: `APPENDIX-NORMATIVE.md` §4
  item 3 must name which of the two paths it means and budget the change.
- Decide whether `get_feed`'s hard-coded `limit: 20` is raised or replaced. It ignores the
  caller's requested limit, which caps the visible queue at 20 regardless of
  `PERCH_QUEUE_DEPTH_ALARM`.
