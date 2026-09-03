# Code integration: fork strategy, topology, and the module-by-module plan

The engineering plan for putting Perch on Buzz's body. Three repositories, not one:
the Ambush workspace stays a Rust-only cargo workspace and gains exactly one crate;
Buzz's desktop shell and relay become a pruned soft fork; the one relay change is a
bug-fix PR upstream, not a maintained divergence. This document settles where every
line of code lives, which Buzz crate and feature directory survives, how the bridge
links `IngestState` in-process without touching the ADR 0009 layering gate, and what
the merge cost actually is — measured against both repos' shipped CI gates.

**Revision note.** This is the post-review revision. Seven claims in the first draft
were wrong and are corrected in place, each with the measurement that falsified it:
the daemon's operator read surface (§3), the "unmodified" vendored WebSocket client
and the kept/deleted crate arithmetic (§5), the presence justification (§5), the
desktop TypeScript denominator (§6), the CORS parenthetical (§7), the CI keep-list
versus the `buzz-test-client` deletion (§9), and the Ed25519 verification claim
(§13). One scheduling decision is reversed (§14 step 0), two backend-bill items are
added (§14 steps 3.5 and 6b), and one scope question is closed (§15). Section 16 is
the full changelog.

## 0. How to read the citations in this document

A citation-dense plan has one characteristic failure mode: it proves that a name
exists and infers that the name does what the plan needs. `swarm-spine/src/envelope.rs:71`
is real — it also has exactly one non-test caller. The 49 operator routes are real —
they run in a different process from the one the bridge lives in.

So every load-bearing citation in this document answers three questions in the same
sentence as the path:line, and where the answer is "nothing," "a different one," or
"less than claimed," it says so:

1. **Who calls this?** (`build_signed_envelope` — one non-test caller, §13.)
2. **What process is it in?** (`/v1/operator/replay` — `swarmctl serve`, not the daemon, §3.1.)
3. **What does it do to the data?** (`providence_feedback_handler` — writes onto an
   `IncidentRecord`, so a finding with no incident has nowhere to put a verdict, §14.)

Where I could not answer one of the three, the claim is marked `unverified` inline.

## Decisions made here

1. **Three repos.** `backbay-labs/perch` (pruned soft fork of `block/buzz`: relay crates + desktop shell), `backbay-labs/ambush` (unchanged + one crate + eight backend-bill items, five of which are new routes), and `block/buzz` upstream, which receives the two-arm relay fix as a PR.
2. **The Ambush cargo workspace never gains a Buzz crate.** Buzz's six relay-side crates carry 4,213 `.unwrap()`/`.expect(` sites against a workspace that denies both; the workspaces cannot merge.
3. **`swarm-perch-bridge` is a normal downstream Ambush crate**, a peer of `swarm-ingest-runtime`, mounted into `swarm_detect --serve` from `swarm-runtime-http`'s existing binary. It is legal under `tools/check-workspace-layering.sh` by construction, not by exemption.
4. **The bridge hydrates in-process, not over HTTP.** `IngestState` already exposes `current_replay_store()`, `current_incident_store()`, `current_investigation_store()` and `current_containment_store()`. The bridge names no HTTP client at all.
5. **`buzz-ws-client` is vendored *and modified*, not depended on.** `deny.toml` sets `[sources] unknown-git = "deny"` with `allow-git = []`. The copy is not verbatim: four panic sites in production code must become typed errors before the crate's first commit compiles.
6. **One measured supply-chain bill item:** `nostr 0.44.7` pulls `chacha20 0.9.1` against Ambush's locked `chacha20 0.10.1`, and Ambush sets `multiple-versions = "deny"`. One dated `[[bans.skip]]` entry, argued in review.
7. **The Tauri process speaks HTTP to the daemon and never links `swarm-runtime`.** In-process linkage happens once, inside the daemon. The console is a client.
8. **Desktop ships in v1. `web/` is pruned and preserved unbuilt. `mobile/` is deleted.**
9. **The relay patch is carried as a two-hunk patch file, not a branch.** If upstream merges it, the patch deletes itself; if not, it re-applies cleanly across every Buzz release.
10. **The file splits happen in the fork, on day one.** `block/buzz` landed 1,867 commits in 90 days and touched `AppShell.tsx` 103 times; a ~1,000-line split of a third party's two hottest files is not a schedule gate we control.
11. **`buzz-test-client` is kept.** It is the only independent proof the relay fork still behaves, and three CI jobs Perch keeps are implemented entirely by it.
12. **Perch inherits Buzz's `just ci` + lefthook wholesale; Ambush adopts two Buzz guards** (`check-px-text`, `check-pubkey-truncation` extended to Ed25519) as `tools/check-*.sh`, which is the only way they run — `tools/check-gates-wired.sh` requires every gate be named by a real `run:` step.

---

## 1. Why not one repo

The obvious move — vendor Buzz's desktop tree into `ambush/console/` and its relay crates into `ambush/crates/` — is the one the two repos' own CI configuration forbids. Four independent collisions, each verified:

| Collision | Ambush | Buzz | Consequence of merging |
|---|---|---|---|
| Panic lints | `[workspace.lints.clippy] unwrap_used = "deny"`, `expect_used = "deny"` (`Cargo.toml:135-137`), enforced additionally by `tools/check-runtime-panic-contract.sh` over all `crates/*/src` | No `[workspace.lints]` block at all; `just clippy` is `cargo clippy --workspace --all-targets -- -D warnings` (`justfile:122`) | 4,213 `.unwrap()`/`.expect(` matches across `buzz-relay/src`, `buzz-core/src`, `buzz-db/src`, `buzz-auth/src`, `buzz-pubsub/src`, `buzz-search/src` alone. Not a cleanup; a rewrite. |
| Duplicate deps | `[bans] multiple-versions = "deny"`, `wildcards = "deny"`, 19 dated `[[bans.skip]]` entries (`deny.toml:108-160`) | `[bans] multiple-versions = "warn"`, `wildcards = "allow"` (`deny.toml`, tail) | Buzz's graph carries `chacha20` 0.9.1 **and** 0.10.0, `getrandom` 0.2/0.3/0.4, `rustls` 0.23.42 vs Ambush's 0.23.40. Every one becomes a CI failure requiring a written justification. |
| Sources | `[sources] unknown-git = "deny"`, `allow-git = []` | `mesh-llm-*` crates come from a pinned git URL, with six `[[licenses.clarify]]` entries to make them pass | `cargo deny check sources` fails on the first `mesh-llm` edge. Not fixable by configuration — only by deleting the feature. |
| Licenses | 12 allowed SPDX expressions, `exceptions = []` | 19 allowed, including `MPL-2.0`, `OpenSSL`, `Zlib`, `bzip2-1.0.6`, `BlueOak-1.0.0`, plus `[licenses.private] ignore = true` | Ambush's allow-list would have to widen to Buzz's. `deny.toml:80-100` records that Ambush already refused to widen it once (for the `tonic`/`prost` 0.14 migration, blocked on Zlib-licensed `foldhash`) precisely so a license decision is never made as a side effect of a dependency cleanup. |

Add the toolchain: Buzz pins `1.95.0` (`rust-toolchain.toml`), Ambush pins `1.97.1` with a written reason (`rust-toolchain.toml:1-14` — phase 280 verified clippy clean on 1.93.0 while CI ran 1.97.1 and found 21 violations). One repo means one pin, which means one side eats a clippy migration on day one.

There is a narrower version of the merge that survives the workspace gates: exclude the Tauri crate the way Buzz already does (`Cargo.toml:33`, `exclude = ["desktop/src-tauri"]`) and vendor only the desktop TypeScript. That fails on a different axis — `tools/check-gates-wired.sh` enumerates `git ls-files` over `tools/check-*.sh` and `tools/verify-*.sh` and demands each be named by a real `run:` step in a workflow, and `tools/check-visibility-baseline.sh` compares declaration sets under `crates/*/src` across two revisions. Neither has a concept of "a subtree the Rust gates should skip." Every gate would need a scope argument added, and a gate that grows a scope argument is exactly the "check reporting success over a region it never inspected" pattern that `tools/check-workspace-layering.sh`'s own header (lines 12-22) says this repository has shipped ten times.

**Decision: three repositories.** The seam between them is a wire protocol and a vendored 564-line client, both of which are reviewable artifacts. The seam inside one repository would be a set of CI exemptions, which are not.

---

## 2. The three repositories

```
block/buzz  (upstream, unchanged)
     │
     │  ① PR: two match arms in crates/buzz-relay/src/handlers/ingest.rs
     │     (46010 scope + h-channel scope — a bug fix, not a feature)
     │  ② PR: AppShell.tsx / MessageRow.tsx split, offered, NOT depended on
     │
     ▼
backbay-labs/perch                        backbay-labs/ambush
┌──────────────────────────────┐          ┌──────────────────────────────────┐
│ crates/           (13 kept)  │          │ crates/  (20 → 21 members)       │
│   buzz-relay, buzz-core,     │          │   + swarm-perch-bridge  ← NEW    │
│   buzz-db, buzz-auth,        │          │     vendors buzz-ws-client (564, │
│   buzz-pubsub, buzz-search,  │          │     4 panic sites rewritten)     │
│   buzz-media, buzz-audit,    │  ◄──ws── │                                  │
│   buzz-sdk, buzz-admin,      │  kind:9  │   swarm-runtime-http/src/bin/    │
│   buzz-conformance,          │  + 46010 │     swarm_detect.rs mounts the   │
│   buzz-test-client,          │          │     bridge next to the           │
│   buzz-workflow (types only) │          │     containment router           │
│                              │──http──► │                                  │
│ console/    (was desktop/)   │  :9090   │   backend bill: 5 new routes,    │
│ web/        (pruned, unbuilt)│          │   1 hardened, 3 non-route items  │
│ migrations/ schema/ scripts/ │          │   ci.yml: 12 jobs, 14 gates,     │
│ justfile lefthook.yml bin/   │          │   unchanged shape                │
└──────────────────────────────┘          └──────────────────────────────────┘
```

### Repo 1 — `block/buzz`: upstream, receives two PRs, blocks on neither

**PR ① — the relay fix.** This is genuinely a bug fix and should be argued that way. `KIND_WORKFLOW_APPROVAL_REQUESTED` (46010) is defined in `crates/buzz-core/src/kind.rs:578`, is in `ALL_KINDS` (`:745`), is queried by the desktop needs-action feed (`crates/buzz-db/src/store/feed.rs:192-199` — `needs_action` is literally `kind IN (46010, 40007)`), and *cannot be published by anything*, because `required_scope_for_kind`'s default arm at `crates/buzz-relay/src/handlers/ingest.rs:545` is `Err("restricted: unknown event kind")` and 46010 is not above it. Verified: the arm list ends at `KIND_APPROVAL_GRANT | KIND_APPROVAL_DENY => Ok(Scope::MessagesWrite)` (`:706`). Its intended producer is a TODO (`crates/buzz-workflow/src/executor.rs:727`).

The second arm is not optional and is the part an upstream reviewer will miss. `requires_h_channel_scope` (`ingest.rs:704-732`) does not list 46010 either — verified against the full `matches!` body — and 46010 is not in `is_global_only_kind`. Adding only the scope arm admits a hold as a **global** event with no `h` tag, and a global hold defeats the compartment that the entire case-channel model rests on.

No `search_tsv` change: `schema/schema.sql:224`'s privacy CASE lists 1059, 30179, 30300, 30350, 30622, 44100, 44101, 44200. 46010 is not among them.

**Carry it as a patch, not a branch.** `perch/patches/0001-relay-46010-scope.patch`, applied by the relay build recipe. Two hunks in one file. If upstream merges, the patch stops applying and the build recipe deletes it. If upstream does not merge for a year, the patch still applies across every Buzz release, because `required_scope_for_kind` and `requires_h_channel_scope` are append-only match lists that churn by insertion, not restructuring. A long-lived fork branch of `ingest.rs` (2,200+ lines, 40 commits in 90 days) would conflict on every upstream release; a two-hunk patch will not.

**PR ② — the file splits, offered but not depended on.** See §14 step 0. `AppShell.tsx` (997 lines) and `MessageRow.tsx` (998) are split *in the fork*, and the same refactor is offered upstream as a good-citizen PR with no schedule dependency. The measurement that settles this: `block/buzz` landed **1,867 commits in the last 90 days**, and `desktop/src/app/AppShell.tsx` alone was touched **103 times** in that window (`git log --since="90 days ago" --oneline -- <path> | wc -l`; `MessageRow.tsx`: 54). Gating a four-phase plan on a ~1,000-line split of a third party's two hottest files is scheduling work we do not control. The kill threshold in 01-POSITIONING must therefore measure something we do control — *"the patch file still applies"* — not an external merge latency.

### Repo 2 — `backbay-labs/perch`: pruned soft fork

Fork `block/buzz` at a tagged release, delete on the first commit, and never rebase — merge. The distinction matters: a rebase-based fork replays Perch's deletions against every upstream commit and conflicts forever. A merge-based fork records the deletion once, and `git merge upstream/main` afterwards only conflicts on files Perch still owns.

The prune (§5 and §6) removes 42% of the crate LOC and roughly two thirds of the desktop feature tree. Deleted files never conflict again. The residual merge surface is `shared/` (45,219), `app/` (7,684), the retained feature directories (~91k), plus 13 crates. That is the ongoing tax, and it is priced in §9.

### Repo 3 — `backbay-labs/ambush`: +1 crate, +8 bill items

Nothing about the existing 20 workspace members changes. (`ls crates/` returns 21 directories; `swarm-governance-witness` is a directory with an empty `src/bin` and no `[workspace] members` entry — verified against `Cargo.toml:3-24`. Nothing in this plan depends on it.)

The backend bill is eight numbered items (§14): **five new routes** (`POST .../holds/{id}/decide`, `GET /v1/response/holds`, `GET /v1/response/holds/{id}`, `POST .../findings/{id}/feedback`, `GET .../pheromone/deposits`), **one existing route hardened** (`/v1/events/stream`), and **three non-route items** (the `HeldActionStore`, threading the approver into the receipt, and signing the fact before publish). All of it lands on the daemon (`swarm_detect --serve`, :9090), for the reason `crates/swarm-runtime-http/src/http/containment.rs:1-39` already documents: only that process holds the lease store `Arc`, the receipt counter, the `previous_commit_hash` chain, and the governance keyring, and `GovernancePersistence::save` is a tmp-write-plus-rename with no lock. A second writer forks the audit chain.

---

## 3. Process topology

**Correction from the first draft.** The first draft drew "the daemon" as one HTTP surface with 49 operator routes on it. That is false, and the error propagated into the Tauri command table and the bridge's hydration story. The 49 routes are on `LocalOperatorSurface::router()` (`crates/swarm-runtime-http/src/http/state.rs:293-497`, `grep -c '\.route(' = 49`), which is constructed by `swarmctl serve` (`crates/swarm-cli/src/core.inc:3345`) **in a different process**, and `http/containment.rs:29-33` says in its own module doc why those routes are not merged into the daemon: *"`LocalOperatorSurface` builds its own `DefaultControlPlane` in its own process and therefore has exactly that problem."*

```
                          OPERATOR WORKSTATION
   ┌───────────────────────────────────────────────────────────────────┐
   │  Perch (Tauri 2 + React 19)                                       │
   │  ┌─────────────────────────────────────────────────────────────┐  │
   │  │  webview                                                    │  │
   │  │    invokeTauri(cmd, args)  ── 264 call sites, 205 command   │  │
   │  │    (shared/api/tauri.ts:296)   name literals                │  │
   │  │    RelayClient singleton ── plugin:websocket|connect        │  │
   │  └───────────────┬──────────────────────────┬──────────────────┘  │
   │                  │ IPC                      │ IPC (websocket plugin)
   │  ┌───────────────▼──────────────────────────▼──────────────────┐  │
   │  │  perch_lib (Rust)                                           │  │
   │  │    relay.rs  ──── NIP-42 / NIP-98 ─────────────┐            │  │
   │  │    ambush/   ──── bearer HTTP ────────┐        │            │  │
   │  │    secret_store ── OS keyring (nsec + daemon bearer token)  │  │
   │  └───────────────────────────────────────┼────────┼────────────┘  │
   └──────────────────────────────────────────┼────────┼───────────────┘
                                              │        │
      ═══════════ operator network boundary ══╪════════╪═══════════════
                                              │        │
   ┌──────────────────────────────────────────▼──┐  ┌──▼───────────────┐
   │  PROCESS A: swarm_detect --serve    :9090   │  │  PROCESS C:      │
   │  detect_http_router (ingest/mod.rs:2540)    │  │  buzz-relay      │
   │   6 health + /v1/ingest/events + 5 demo     │  │  (Perch fork)    │
   │   + 2 providence + /v1/soar/verdicts        │  │                  │
   │   + /v1/events/stream + /api/v1 + /v2/api   │  │  Postgres        │
   │  MERGED (swarm_detect.rs:1113-1143):        │  │  Redis           │
   │   containment_operator_router — 2 routes    │  │  (2 containers   │
   │  + 5 NEW routes (the backend bill)          │  │   + data dir)    │
   │  ┌────────────────────────────────────────┐ │  │                  │
   │  │ IngestState  (the ONLY writer)         │ │  │                  │
   │  │   RuntimeEventBroadcaster (cap 1024)   │ │  │                  │
   │  │   HeldActionStore    ← NEW             │ │  │                  │
   │  │   lease store / receipt chain / keyring│ │  │                  │
   │  │   current_{replay,incident,            │ │  │                  │
   │  │     investigation,containment}_store() │ │  │                  │
   │  └──────────┬─────────────────────────────┘ │  │                  │
   │             │ subscribe_runtime_events()    │  │                  │
   │             │ (ingest/mod.rs:1875) + the    │  │                  │
   │             │ current_*_store() accessors   │  │                  │
   │  ┌──────────▼─────────────────────────────┐ │  │                  │
   │  │ swarm-perch-bridge   ← NEW CRATE       │ │  │                  │
   │  │   recv → disk spool → publish          │─┼──┼─► kind:9 markers │
   │  │   per-issuer monotonic sequence        │ │  │   + 46010 holds  │
   │  │   1 Hz coalescer for snapshots         │─┼──┼─► ephemeral 2xxxx│
   │  │   NO reqwest. NO HTTP hop.             │ │  └──────────────────┘
   │  └────────────────────────────────────────┘ │
   └─────────────────────────────────────────────┘
   ┌─────────────────────────────────────────────┐
   │  PROCESS B: swarmctl serve  (LocalOperator- │  ← 49 routes.
   │  Surface, http/state.rs:293-497)            │    Builds its OWN
   │  /v1/operator/{status,replay,incident,      │    DefaultControlPlane.
   │   investigation,review/*,evidence/*,        │    NOT Perch's transport.
   │   approval-*,evolution/*,maintenance/*}     │    Kept for swarmctl
   │  + /metrics (the only unauthenticated one)  │    and /metrics.
   └─────────────────────────────────────────────┘
```

Four processes, two of which already exist unchanged. The console never writes Ambush state; it publishes a signed intent record to the relay and POSTs a decision to the daemon, which re-evaluates policy and governance from scratch.

### 3.1. Route inventory: which process serves what

This table exists because the first draft got it wrong, and because every downstream document's read path depends on it.

| Route | Process | Exists today? | Perch v1 consumer |
|---|---|---|---|
| `GET /v1/operator/containment/leases` | **A** (`containment.rs:262-271`, merged at `swarm_detect.rs:1113-1143`) | **Yes** | `/leases`. This is the one operator read Perch inherits for free. |
| `POST /v1/operator/containment/leases/{id}/release` | **A** (same router) | **Yes** | `/leases` release. |
| `GET /v2/api/runtime/status` | **A** (`platform_api.rs:821`, nested at `ingest/mod.rs:2573`) | **Yes** | `/tuning`. Carries `alert_tuning: build_alert_tuning_report(&incidents)` (`platform_api.rs:1323`). **On demand only, never polled** — the handler loads incidents with `.recent(usize::MAX)`. See §15. |
| `GET /v1/events/stream` | **A** (`ingest/mod.rs:2570`) | **Yes, and unauthenticated with wildcard CORS** | **Not used by Perch.** The bridge subscribes in-process. Fixed anyway; §7. |
| `POST /v1/response/holds/{id}/decide` | **A** | **No — bill item 2** | The verdict row's leg 2. |
| `GET /v1/response/holds` + `GET /v1/response/holds/{id}` | **A** | **No — bill item 6a** | The queue's reconciliation read and the receipt's "verify against the daemon" affordance. The relay carries the notification; the daemon is the record, so *something* must read the daemon. |
| `POST /v1/operator/findings/{id}/feedback` | **A** | **No — bill item 3** | Confirm/Dismiss/Investigate. See the incident-binding constraint in §14. |
| `GET /v1/operator/pheromone/deposits` | **A** | **No — bill item 4** | `/watch-floor` and the Dismiss arithmetic. |
| `/v1/operator/replay`, `/incident`, `/investigation`, `/review/**`, `/evidence/**`, `/approval-*`, `/evolution/**`, `/maintenance/**` (49 total) | **B** | Yes | **None in v1.** See below. |
| `/metrics` | **B** (unauthenticated, `state.rs:484`) *and* **A** (`health::metrics_handler`, `ingest/mod.rs:2548`) | Yes | Ops scrape, not Perch. |

**The two-control-plane divergence, confronted.** Process B's 49 routes hold the objects three Perch surfaces want: `CorrelatedIncident` (`/cases` canvas seed), `ReplayBundle` (evidence drill-down), and `ReviewSession` (`/handoff`). Perch does not read them, for the reason `containment.rs:19-33` gives: B builds a second `DefaultControlPlane`, so with `runtime.containment.lease_store_path` unset its stores are *different objects* from the daemon's, and a console reading B while deciding against A would render one process's state next to another's authority.

The resolution is that **the bridge reads those stores in-process on side A and publishes what the console needs**, which is why decision 4 exists. `IngestState` already exposes the accessors: `current_replay_store()` (`ingest/mod.rs:2033`), `current_investigation_store()` (`:2043`), `current_incident_store()` (`:2051`), `current_containment_store()` (`:1776`), plus `current_correlation_engine()` (`:2047`). A `CorrelatedIncident` becomes a case channel and a seeded canvas; a `ReplayBundle` is reachable through a `locator` on the evidence card, resolved by a narrow daemon route rather than by pointing the console at B.

Consequence, stated so 09's *"Perch/swarmctl disagreements exactly zero"* metric is not assumed away: **that metric is only meaningful for objects both processes compute from the same store.** In v1 that is exactly the containment leases and the pheromone deposits. For incidents and review sessions, the honest statement is that Perch reads A and `swarmctl` reads B, and the deployment doc must say that a single-process deployment (`runtime.containment.lease_store_path` and the incident store both file-backed) is the configuration in which the two agree at all.

---

## 4. `swarm-perch-bridge`: linking in-process without touching the TCB

### Why the layering gate does not fire

`tools/check-workspace-layering.sh` embeds a Python rule engine. Five rules, and the new crate is out of scope for all of them by construction:

| Rule | What it reads | Scope | Does `swarm-perch-bridge` trip it? |
|---|---|---|---|
| RULE 1 `tcb-declared-transport` | Declared edges, **all kinds** | Iterates `TCB = ("swarm-crypto","swarm-policy","swarm-spine")` only (`:181`, used at `:405-415`) | No — not a TCB crate. |
| RULE 2 `tcb-declared-downstream` | Declared edges, all kinds, against `TCB_ALLOWED_WORKSPACE_DEPS` (`:434-459`) | Same three crates. The allow-list has exactly one row per TCB crate, enforced by a vacuity guard. | No. Critically: nothing may make a TCB crate *name* the bridge. |
| RULE 3 `tcb-resolved-transport-*` | **Resolved normal** graph reach from each TCB crate, against `RESOLVED_TRANSPORT_BASELINE = {(swarm-spine,hyper),(swarm-spine,reqwest)}` (`:219-229`) | Same three crates' reach | No — the bridge is strictly downstream, so no TCB crate reaches it. This is also the rule that actually enforces ADR 0009's claim about `swarm-core`: `swarm-policy → swarm-core → <transport>` would appear in `swarm-policy`'s resolved reach. (ADR 0009:133 attributes this to rule 1; the shipped engine's RULE 1 iterates `TCB` only, so RULE 3 is the mechanism. Worth noting, not worth fixing here.) |
| RULE 4 `advisory-*` | Declared **and** resolved, for `ADVISORY_CONSUMERS = ("swarm-policy","swarm-response")` reaching `swarm-runtime` (host of `sphinx_agent.rs` and `correlation.rs`) | Two crates | No. |
| RULE 5 `missing-owns-section` | `//! ## Owns` / `//! ## Does not own` in `src/lib.rs` for `TRUST_SENSITIVE` (six crates, `:185-191`) | Six named crates | No — but the bridge should carry the sections anyway. Free discipline, and it makes the crate's authority claim ("owns transport; owns no decision") legible. |

The precedent holds and is verified in the manifest, not inferred: `crates/swarm-ingest-runtime/Cargo.toml:12-17` names `axum`, `clap 4.5` and `reqwest` as normal dependencies and the gate is green. A sibling naming `tokio-tungstenite` and `nostr` is the same shape.

**The one live hazard.** RULE 2 is an allow-list *precisely because* the first version of this gate was evadable by adding the forbidden edge (see the 60-line comment at `:426-448`: adding a normal `swarm-spine → swarm-pheromone` edge put `swarm-pheromone` into the closure and removed it from the rule's own scope; measured evadable for 7 of 14 crates). So: **no TCB crate may ever name `swarm-perch-bridge`.** That is not a risk today — the dependency direction runs the other way — but it is the one line in a code review that must be a hard no.

### Where it sits in the graph

```
swarm-runtime-http  ──────────────► swarm-perch-bridge  (NEW)
   (owns src/bin/swarm_detect.rs)         │
   already ──► swarm-ingest-runtime ◄─────┘
                     │
                     └──► swarm-runtime, swarm-spine, swarm-policy, swarm-core …
```

No cycle: `crates/swarm-runtime-http/Cargo.toml:31` already declares `swarm-ingest-runtime`, and `swarm-ingest-runtime` does not name `swarm-runtime-http` (verified in both manifests). The bridge needs `IngestState` (for `subscribe_runtime_events()` and the `current_*_store()` accessors) and `RuntimeEvent` (from `swarm-runtime`), both of which it gets by depending on `swarm-ingest-runtime` and `swarm-runtime`. The binary that mounts it is `crates/swarm-runtime-http/src/bin/swarm_detect.rs`, alongside the containment router merge at `:1113-1143`.

### The manifest

```toml
# crates/swarm-perch-bridge/Cargo.toml
[package]
name = "swarm-perch-bridge"
description = "Publishes runtime events to a Perch relay. Owns transport; owns no decision."
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
# Ambush side. Strictly downstream of the TCB; this crate is named by no TCB crate.
# swarm-ingest-runtime gives us BOTH the event stream and the read side:
# subscribe_runtime_events() plus current_{replay,incident,investigation,
# containment}_store(). There is no HTTP client here on purpose.
swarm-core.workspace = true
swarm-runtime.workspace = true
swarm-ingest-runtime.workspace = true

# Nostr transport. Legal here for the same reason swarm-ingest-runtime may name
# axum/clap/reqwest: this crate is not in TCB = (swarm-crypto, swarm-policy,
# swarm-spine) and is not reached by any of them on the resolved normal graph.
# See tools/check-workspace-layering.sh RULE 1-3.
nostr = { version = "0.44", default-features = false, features = ["std"] }
tokio-tungstenite = { version = "0.28", features = ["rustls-tls-webpki-roots"] }

secp256k1 = { version = "0.29", features = ["global-context"] }
futures-util.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio.workspace = true
tokio-stream = { workspace = true, features = ["sync"] }
tracing.workspace = true
url = "2"

[lints]
workspace = true   # unwrap_used = deny, expect_used = deny. Mandatory.
```

`[lints] workspace = true` is not decorative, and it has a concrete first casualty (§5). `Cargo.toml:135-137` sets `unwrap_used = "deny"` and `expect_used = "deny"` at the workspace level, so those are hard compile errors, not warnings. On top of that, `tools/check-runtime-panic-contract.sh` scans production (non-`cfg(test)`) code in every `crates/*/src`, `.rs` and `.inc`, matching `PANIC_CALL = re.compile(r"\.(unwrap|expect)\s*\(")` (`:83`) with a single escape hatch: the literal marker `SAFETY: runtime panic contract exception` on the nearest line above (`:82`). A new crate is in scope from its first commit.

The `secp256k1` feature set is a sketch, not a tested build — `unverified` until the vendored signing path compiles.

### The receive loop, and why the spool is inside it

`DEFAULT_RUNTIME_EVENT_CAPACITY = 1_024` (`crates/swarm-runtime/src/runtime_events.rs:13`), and a lagged `broadcast::Receiver` drops silently. `runtime_events_handler` demonstrates the failure exactly: `let Ok(event) = result else { return None; }` (`ingest/demo.rs:1690-1693`) maps a `BroadcastStream` lag error to *nothing at all*. For a product whose claim is "a signed receipt for every decision," a dropped frame is a correctness bug.

```rust
// Sketch. The ordering is the contract: nothing that can block on the network
// runs between recv() and the spool append.
loop {
    match rx.recv().await {
        Ok(event) => spool.append(seq.next(), &event)?,   // fsync-batched, local disk
        Err(RecvError::Lagged(n)) => {
            // NOT a metric. A gap is a first-class artifact: the console renders
            // it as a gap, with the count and the sequence range it spans.
            spool.append_gap(seq.next(), n)?;
            tracing::error!(dropped = n, "runtime event broadcast lagged");
        }
        Err(RecvError::Closed) => break,
    }
}
// A separate task drains the spool to the relay and only truncates on OK.
```

Every published envelope carries a monotonic per-issuer sequence, so the console can render a gap as a gap rather than as silence. `ConcentrationSnapshot` is coalesced to 1 Hz **before** it reaches the publisher, not in the webview — the coalescing has to happen on the far side of the IPC boundary or the boundary is the bottleneck.

---

## 5. Buzz crates: verdict by crate

Thirty crates, measured (`for c in $(ls crates); do find crates/$c -name '*.rs' | xargs cat | wc -l; done`).

| Crate | LOC | Verdict | Reason |
|---|---:|---|---|
| `buzz-relay` | 82,560 | **Keep, patched** | The substrate. Two match arms in `handlers/ingest.rs`. Delete the huddle audio host and the git smart-HTTP transport in a second pass, not the first — they are inert if unrouted. |
| `buzz-db` | 46,319 | **Keep** | Postgres event store, `thread_metadata` materialized counters (`schema/schema.sql:514`), `top_level` windows, composite keyset cursors. Nothing to change. |
| `buzz-test-client` | 18,250 | **Keep, specs pruned** | **Reversed from the first draft.** Three CI jobs Perch keeps are implemented entirely by this crate (§9), and it is the only independent proof the relay fork still behaves — including the regression test that makes PR ① a bug fix. Keep the crate; delete the ten spec files whose subjects are deleted (below). |
| `buzz-sdk` | 11,689 | **Keep, trimmed** | `nip_oa.rs` is the owner-attestation builder — load-bearing. `builders.rs` builds the kind:9 the bridge emits. Trim the git/NIP-34 builders. |
| `buzz-core` | 9,648 | **Keep** | The kind registry is the dispatch switch. No new stored kinds (brief C1), so no edit. |
| `buzz-media` | 7,592 | **Keep** | Evidence attachments, canvases with images. Blossom is the only authenticated upload path either product has. |
| `buzz-auth` | 5,754 | **Keep** | NIP-42, the ban gate, the NIP-OA owner cascade (`handlers/auth.rs:106-184`). This is how banning an operator bans every agent key. |
| `buzz-workflow` | 5,247 | **Keep as presentation types only** | `request_approval` is a stub (`executor.rs:727`). The hold lives in the daemon. Keep `WorkflowRunTrace` / `StepProgress` as pure presentation over Ambush's state machine; delete the executor's action sinks. |
| `buzz-pubsub` | 2,144 | **Keep** | Redis fan-out. See the presence correction below. |
| `buzz-search` | 1,946 | **Keep** | NIP-50 → Postgres FTS. The row insert is the index update; `/ledger` depends on there being no consistency window. |
| `buzz-conformance` | 1,775 | **Keep** | The multi-tenant replay checker with golden fixtures. It is the only independent proof the colony fence holds, and Ambush's whole gate culture says an unproven fence is not a fence. |
| `buzz-audit` | 1,127 | **Keep** | Relay-side operation chain (11 `AuditAction` variants — it audits relay ops, not findings). Runs *alongside* the Ed25519 receipt chain. Never conflated with it. |
| `buzz-admin` | 649 | **Keep** | Operator CLI for relay administration. Cheap, and the alternative is `psql`. |
| `buzz-acp` | 45,867 | **Delete** | ACP harness for spawning external agent subprocesses. Ambush's agents are in-process Rust roles. Also `buzz-acp/src/lib.rs:5087` passes `BUZZ_PRIVATE_KEY` as a bech32 nsec in subprocess env — in a threat-hunting product that is the first finding of its own first pentest. |
| `buzz-agent` | 33,636 | **Delete** | Same. |
| `buzz-cli` | 22,123 | **Delete** | Agent-first CLI over the relay. `swarmctl` is Ambush's CLI and ~124 of its 126 subcommands are not HTTP clients; a second CLI over a second store is a second source of truth. |
| `buzz-backend-kubernetes` | 6,651 | **Delete** | Block-internal backend provisioning. |
| `buzz-dev-mcp` | 5,854 | **Delete** | Shell + file tools for `buzz-agent`. The PTY panel covers the operator case honestly; this covers the agent case, which Ambush does not have. |
| `buzz-push-gateway` | 5,246 | **Delete** | Mobile push. Mobile is out of v1. |
| `buzz-persona` | 5,197 | **Delete** | `AgentRole` is a closed 8-variant enum (`swarm-core/src/agent.rs:17`). Personas are premature until the open-agent-protocol roadmap item lands. |
| `buzz-voice` | 3,210 | **Delete** | Huddle audio. |
| `buzz-relay-mesh` | 3,139 | **Delete** | Inter-relay mesh over `iroh`. |
| `git-sign-nostr` | 2,511 | **Delete** | Git forge is an explicit non-goal. |
| `buzz-pair-relay` | 2,445 | **Delete** | NIP-AB device pairing sidecar. |
| `buzz-deletion` | 2,391 | **Delete** | NIP-09 deletion tooling; the evidence store does not delete. |
| `git-credential-nostr` | 625 | **Delete** | Git forge. |
| `buzz-pairing-cli` | 623 | **Delete** | NIP-AB interop CLI. |
| `buzz-ws-client` | 564 | **Delete from Perch; vendor into Ambush** | See below. |
| `buzz-datastore-tracing` | 417 | **Delete** | Block-internal datastore instrumentation. |
| `sprig` | 53 | **Delete** | Bundles `buzz-acp` + `buzz-agent` + `buzz-dev-mcp`. |

**Kept: 13 crates, 194,700 LOC. Deleted: 17 crates, 140,552 LOC.** 13 + 17 = 30, which is `ls crates/ | wc -l`. That is a 42% cut of the Rust surface, and every deleted crate is a file that never conflicts on an upstream merge again. (The first draft said "11 kept / 19 deleted," which summed to 30 only by leaving `buzz-workflow` out of both columns and counting `buzz-ws-client` twice. Corrected.)

**`buzz-test-client` spec prune.** Keep `e2e_relay.rs` (3,206), `conformance_multitenant.rs` (2,749), `e2e_nostr_interop.rs` (1,987), `e2e_event_reminder.rs` (1,178), `e2e_media_extended.rs` (804), `e2e_media_video.rs` (678), `e2e_media.rs` (460), `regression_relay_admin_ban_gate.rs` (377), `nip42_host_binding_live.rs` (159) — 11,598 lines, all of which exercise subsystems Perch keeps. Delete `e2e_persona.rs` (1,591), `e2e_human_edit_agent_content.rs` (991), `e2e_project.rs` (603), `e2e_git.rs` (555), `e2e_long_form.rs` (538), `e2e_team_catalog.rs` (484), `e2e_managed_agent.rs` (368), `e2e_mesh_llm.rs` (293), `e2e_user_status.rs` (273), `e2e_team.rs` (212) — 5,908 lines whose subjects are deleted crates or deleted feature directories. The CI consequence is one step edit, spelled out in §9.

**Presence correction.** The first draft's note on `buzz-pubsub` said presence "is single-node with no `PUBLISH`." That is false, and it was inherited rather than read. `crates/buzz-relay/src/handlers/event.rs:844-846` says the opposite in a comment — *"Presence is a channel-less ephemeral event. After updating Redis presence state, let it fall through to the shared global ephemeral publish/fan-out path below so other relay nodes receive the live delta"* — and the fall-through does `publish_event(&conn.tenant, EventTopic::Global, &event)` at `:888`. **The decision is unchanged; the reason is different.** Agent liveness reads the ephemeral `AgentHealth` stream because presence is a *TTL-decayed status with a lie window*: `PRESENCE_TTL_SECS = 180` (`crates/buzz-pubsub/src/presence.rs:16`) on a 60-second heartbeat (`crates/buzz-pubsub/src/lib.rs:331`), so a dead agent reads "online" for up to three minutes. For a security console, three minutes of "the Whisker is fine" after it stopped is the wrong failure.

### The `buzz-ws-client` decision, and the four panic sites

`crates/buzz-ws-client` is 564 LOC across four files: `connection.rs` (314), `message.rs` (190), `error.rs` (51), `lib.rs` (9). It does exactly one thing — connect, wait for the AUTH challenge, sign a kind:22242, send EVENT, wait for OK. Its manifest names `nostr`, `tokio`, `tokio-tungstenite`, `futures-util`, `serde_json`, `thiserror`, `url`, `tracing`.

Three ways to get it into Ambush:

1. **Git dependency on `block/buzz`.** Fails. `deny.toml` sets `[sources] unknown-git = "deny"` with `allow-git = []`, and `tools/check-supply-chain.sh` runs `cargo deny check ... sources` unconditionally. Adding a `[sources] allow-git` entry is a supply-chain policy change for a security product, made to save 564 lines.
2. **Publish `buzz-ws-client` to crates.io.** The durable answer. Requires an upstream release decision Perch does not control, and the crate has no independent release cadence today. (`unverified`: crates.io was not queried; inferred from the workspace-inherited `0.1.0` and absent publish metadata.)
3. **Vendor it.** `crates/swarm-perch-bridge/src/ws/` — four files with per-file provenance headers, listed in `NOTICE`. `docs/VENDOR-REFERENCES.md` already establishes the repo's convention, and rule 2 there ("if a concept is promoted into Ambush proper, rewrite it in local crates") is satisfied by keeping the vendored copy *out of* `vendor/reference/` — that tree is explicitly "not a build dependency."

**Take (3) now, pursue (2) in parallel — but the copy is not verbatim, and the first draft was wrong to say it was.** Measured:

```
crates/buzz-ws-client/src/connection.rs:170:  match self.buffer.remove(idx).unwrap() {
crates/buzz-ws-client/src/connection.rs:172:      _ => unreachable!(),
crates/buzz-ws-client/src/connection.rs:229:  match self.buffer.remove(idx).unwrap() {
crates/buzz-ws-client/src/connection.rs:231:      _ => unreachable!(),
crates/buzz-ws-client/src/connection.rs:296:  #[cfg(test)]        ← the boundary; all four are ABOVE it
```

All four are production code. `[lints] workspace = true` makes the two `.unwrap()` calls hard compile errors before `tools/check-runtime-panic-contract.sh`'s regex ever runs, and §14 step 4 requires the gates be proven green *before* any bridge logic exists — so this is the crate's first failing commit, not a later cleanup.

**The fix is four typed errors.** `remove(idx)` after an `iter().position()` cannot return `None` and the `match` arm cannot be reached — but "cannot" is exactly the shape of claim this repository's own gate headers say has been wrong ten times. Rewrite both to `let Some(x) = … else { return Err(WsClientError::BufferDesync) }` and both `unreachable!()` arms to the same typed error (the enum is `WsClientError`, `buzz-ws-client/src/error.rs:5`; the new variant is ours). That is a real, reviewable behavioural change to vendored code, so:

- The per-file provenance header records it: `Modified: yes — 4 panic sites (connection.rs:170,172,229,231) rewritten to typed errors for the workspace panic contract.`
- `NOTICE` says "copied and modified," not "copied."
- 09's item 0.7 gains half an engineer-week.

**The alternative, named and rejected in writing.** A `#[allow(clippy::unwrap_used, clippy::expect_used)]` on the vendored module would compile, and `check-runtime-panic-contract.sh`'s `SAFETY: runtime panic contract exception` marker would silence the bash gate on four lines. Rejected: a blanket allow over a whole module inside a security product's only network-facing new crate is precisely the vacuous-gate pattern `check-workspace-layering.sh:12-22` says this repo has shipped ten times, and the marker escape is designed for a line, not a file. Four typed errors cost less than the review argument for the allow.

---

## 6. Desktop feature directories: verdict by directory

Measured with `find desktop/src/features \( -name '*.ts' -o -name '*.tsx' \) | xargs cat | wc -l` (includes colocated tests). **30 directories, 254,557 lines.** The first draft said 283,255, which matches neither the per-row values below (they sum to exactly 254,557) nor `desktop/src` as a whole (322,393 with `testing/`, 307,646 without). Corrected; 09 §6's reuse ratio should be rechecked against this denominator.

| Directory | Files | LOC | Verdict | Reason |
|---|---:|---:|---|---|
| `home` | 34 | 7,131 | **Keep — becomes The Watch** | `lib/inbox.ts` `FeedItemCategory` maps 1:1 onto the four queues. `conversationId` is stable across new evidence, which is why a row does not jump at 02:41. |
| `channels` | 137 | 24,444 | **Keep, heavily trimmed** | Cases and threat-class lanes. Keep the timeline, threads, members sidebar, `ChannelCanvas.tsx` (kind 40100), TTL. Delete channel creation flows, templates UI, invite flows. |
| `messages` | 209 | 40,447 | **Keep, trimmed** | The evidence timeline. `MessageRow.tsx` is 998 lines against a hard cap — the renderer registry lifts out first (§14 step 0). Delete GIF, custom-emoji, link-preview, huddle-row paths. |
| `sidebar` | 46 | 10,617 | **Keep** | Open channels, topic, badges. The threat-class lane list. |
| `search` | 10 | 2,675 | **Keep** | `lib/parseSearchOperators.ts` is `/ledger`. Slack-operator grammar generalizes to `from:whisker-7a3f in:case-0042`. |
| `terminal` | 11 | 3,329 | **Keep** | Real PTY, channel-scoped. The only honest answer to ~124 non-HTTP `swarmctl` subcommands. |
| `workflows` | 48 | 10,892 | **Keep ~20%** | Keep the YAML document view (`/policy`), `WorkflowRunTrace`, `CronExpressionInput`'s human-description pattern, and `WorkflowApprovalCard` (a 30-line stub that becomes the verdict pane). Delete the form builder and the executor UI. |
| `moderation` | 10 | 940 | **Keep — becomes `/tuning`** | Reports-as-signals-never-triggers is the exact model for `AlertTuningRecommendation` review. Small, well-shaped. |
| `notifications` | 11 | 2,020 | **Keep, narrowed to four classes** | The 8-slot taxonomy narrows to the brief's four. Four of the eight (`job_*`) are already dead — nothing emits 43001-43006. |
| `reminders` | 12 | 1,658 | **Keep** | Snooze. NIP-ER kind 30300, encrypted, with a target and a status. `/handoff` reads it. |
| `communities` | 27 | 5,690 | **Keep — becomes the colony rail** | `useCommunityInit.ts:54-84` `resetCommunityState()` becomes a typed registry with an exhaustiveness check *in the same change that adds the first Ambush singleton*. A missed reset here is cross-tenant disclosure. |
| `presence` | 4 | 733 | **Keep, re-sourced** | Keep the components; source liveness from the ephemeral agent-health stream, not kind 20001 (§5). |
| `local-archive` | 8 | 1,381 | **Keep** | Offline evidence retention when the relay is down. The eager-for-ephemeral / deferred-for-durable ordering rule is a hard-won lesson. |
| `settings` | 45 | 12,752 | **Keep ~30%** | Must first become a real route: `/settings` is declared in `routes.ts:8` but `AppShell` swaps the whole layout on `location.pathname === "/settings"` (`AppShell.tsx:173`). Delete accent picker, sounds, emoji, huddle, agent config panes. |
| `onboarding` | 49 | 13,450 | **Rewrite ~15%** | Key generation, encrypted backup with test-restore, and the daemon bearer-token capture. Delete harness detection, community creation, invites. |
| `profile` | 63 | 17,302 | **Keep ~10%** | Agent and operator identity cards only. Delete social profile editing, banners, link previews. |
| `agents` | 228 | 45,522 | **Keep ~15%** | Keep the roster, `AgentStatusBadge`, and the 15 `AgentActivityRenderClass` values with their exhaustive presenter table. **Delete the process-management half** — ACP harnesses, model discovery, persona catalogs, deploy/restart. That is the single largest deletion in the tree. |
| `huddle` | 27 | 5,932 | **Delete (surgery)** | `AppHuddleShell` wraps the whole layout; `huddleWindowChannelId()` is branched on in `main.tsx`, `App.tsx` and the channel route; 45 Rust files under `src-tauri/src/huddle`; 10 `--huddle-*` vars emitted by `createThemeVars` and consumed in `utilities.css`. Removing it edits the theme engine, not just CSS. |
| `projects` | 212 | 37,267 | **Delete** | Git forge. Explicit non-goal. |
| `forum` | 13 | 1,973 | **Delete** | Third lens, no Ambush counterpart in v1. |
| `pulse` | 11 | 1,650 | **Reshape into `/watch-floor`** | Keep the layout shell; the substrate view is net-new hand-authored SVG. |
| `mesh-compute` | 7 | 1,081 | **Delete** | `mesh-llm` is a git dependency. Non-starter under Ambush's source policy even at arm's length. |
| `community-members` | 9 | 2,539 | **Delete** | Social membership management; case membership is the NIP-29 members sidebar in `channels`. |
| `agent-memory` | 3 | 851 | **Delete** | Engrams are a real Sphinx analogue but v2 — the surface list is closed at fourteen. |
| `gifs`, `custom-emoji`, `user-status`, `chat`, `identity-archive`, `channel-templates` | 15 | 2,281 | **Delete** | GIFs and link previews are egress from an analyst workstation. |

Shared code: `shared/` is 313 files / 45,219 lines, of which `shared/ui` is 118 files / 20,183 (only 19 with any Nostr mention) — **taken wholesale**. `shared/theme` — kept, one theme pair added, accent picker deleted. `shared/api` — 21 of its files are the `relay*` reconnect/replay subsystem, **kept**, because Perch's transport is a long-lived socket and rebuilding an equivalent is strictly worse than inheriting one with more test LOC than source. `app/` 67 files / 7,684 lines — kept, with `AppShell.tsx` split first.

**Retained desktop TS: roughly 90-100k of the 254,557-line feature tree** (summing the per-row percentages above), plus `shared/` and `app/` (52,903) taken nearly whole. Call it ~145k of 322k for `desktop/src` as a whole, excluding `testing/`.

---

## 7. The Tauri backend

336 commands in one `generate_handler!` at `desktop/src-tauri/src/lib.rs:519-863` (counted: 336 entries, 285 of them imported at root, plus `archive` 17, `huddle` 10, `terminal_runtime` 9, `tray_menu` 4, `macos_notifications` 3, `channel_head_cache` 3, `observed_unread` 2, and three singletons). The frontend reaches them through one wrapper — `invokeTauri` at `shared/api/tauri.ts:296-309` — with **264 call sites and 205 distinct command-name literals**:

```
grep -roE 'invokeTauri(<[^>]*>)?\(' desktop/src | wc -l                       # 264
grep -rhoE 'invokeTauri(<[^>]*>)?\(\s*"[a-zA-Z0-9_]+"' desktop/src \
  | grep -oE '"[a-zA-Z0-9_]+"' | sort -u | wc -l                              # 205
```

Everything above that wrapper is backend-agnostic. **The brief's "209 call sites" and 09's F3 sizing note that inherited it are both wrong**; 264/205 is the measurement, and it should appear once, in the shared appendix the coherence review asks for, rather than three times.

| Family (by name substring; overlapping) | ~count | Verdict |
|---|---:|---|
| `agent*` (managed agents, models, deploy, logs, providers) | 43 | **Delete.** Ambush's agents are in-process Rust roles inside the daemon. |
| `channel*` | 30 | **Keep.** Cases and threat-class lanes. Note `get_channels` is hash-gated (`commands/channels.rs:46-60`): a matching `known_hash` returns `channels: null` to avoid multi-MB IPC. Any reimplementation that ignores this breaks the sidebar non-obviously. |
| `project*` / `*git*` | 25 | **Delete.** |
| `relay*` | 16 | **Keep.** Centralized in `src-tauri/src/relay.rs` (`query_relay:360`, `submit_event_with_keys:624`, NIP-98 header builder:120). |
| `huddle*` | 15 | **Delete.** |
| `builderlab*` | 13 | **Delete.** Block-internal community provisioning. |
| `identity*` / `key*` / `pairing*` | 20 | **Keep.** Keyring, three hard failure modes (`app_state.rs:61-100`) each with a blocking screen. |
| `team*` / `persona*` | 18 | **Delete.** |
| `archive*` | 9 | **Keep.** Local SQLite evidence retention. |
| `terminal_*` | 9 | **Keep.** |
| `workflow*` | 8 | **Keep 2 of 8.** `grant_approval` / `deny_approval` (`lib.rs:773-774`) are the consumer half and are production-grade; they get re-pointed at the daemon. The rest go. |
| `media*` | 8 | **Keep.** |
| `mesh*` | 6 | **Delete.** |
| `workspace*` | 4 | **Keep.** `apply_workspace` (`commands/workspace.rs:153-169`) is the existing "repoint the whole app at another backend" primitive, serialized by a lock plus a generation counter. It becomes colony switching. |
| Window chrome, tray, notifications, deep links, updater, os-idle | ~30 | **Keep.** |

**New: `src-tauri/src/ambush/` — the daemon client.** A single module, patterned on `relay.rs`: one `reqwest` client, one bearer token read from `secret_store`, one schema-version header, and thin `#[tauri::command]` functions over it. Every command below targets **process A (:9090) only**, and the "exists?" column is the honest bill:

| Command | Route | On :9090 today? |
|---|---|---|
| `ambush_list_leases` | `GET /v1/operator/containment/leases` | **Yes** — `containment.rs:263-266`, merged at `swarm_detect.rs:1113-1143`. |
| `ambush_release_lease` | `POST /v1/operator/containment/leases/{id}/release` | **Yes** — `containment.rs:267-270`. |
| `ambush_tuning_report` | `GET /v2/api/runtime/status` | **Yes** — `platform_api.rs:821`; carries `alert_tuning` at `:1323`. On-demand only. |
| `ambush_list_holds` / `ambush_get_hold` | `GET /v1/response/holds[/{id}]` | **No — bill 6a.** |
| `ambush_decide_hold` | `POST /v1/response/holds/{id}/decide` | **No — bill 2.** |
| `ambush_finding_feedback` | `POST /v1/operator/findings/{id}/feedback` | **No — bill 3.** |
| `ambush_pheromone_deposits` | `GET /v1/operator/pheromone/deposits` | **No — bill 4.** |

Two of these seven already exist, which is worth saying out loud: the daemon *does* have a small operator read surface, it is exactly the containment pair, and it is there because those two routes need the process's one `ContainmentSweep`.

### In-process vs HTTP, settled at two different boundaries

**The console links no Ambush crate.** Three reasons, in order of weight:

1. **ADR 0010.** `swarm_detect --serve` is the sole writer. `FileContainmentLeaseStore::locked()` is a `std::sync::Mutex` inside one process; `GovernancePersistence::save` is tmp-write-plus-rename with no lock. A Tauri process holding a `swarm-runtime` would be a second writer by construction, and `crates/swarm-runtime-http/src/http/containment.rs:1-39` documents exactly this as the reason containment release became a daemon-only route rather than a CLI subcommand.
2. **The TCB would enter a GUI process.** Linking `swarm-runtime` drags `swarm-policy`, `swarm-crypto` and `swarm-spine` into a webview host with a 3.4 MB PNG and a Radix dependency tree. Nothing in the layering gate forbids it — the Tauri crate is `exclude`d from the workspace and invisible to `cargo metadata` — which is exactly why it must be a written rule instead.
3. **Practicality.** The Tauri crate would need Ambush's 453-crate lock merged with its own (Tauri, wry, webkit2gtk, objc2, keyring). Two lockfiles, one of which fails `cargo deny` on contact.

**The daemon links in-process exactly once**, and that is the whole point of `swarm-perch-bridge`: `IngestState::subscribe_runtime_events()` (`ingest/mod.rs:1875`) for the stream, and the `current_*_store()` accessors (`:1776`, `:2033-2051`) for the read side. That deletes one network hop, the `keep_alive(false)` HTTP/1.1 server (`crates/swarm-runtime-http/src/serve.rs:143`, ALPN pinned to `http/1.1` at `:215`) that is hostile to long-lived SSE, and the need for the bridge to hold a bearer token at all.

**CORS correction.** The first draft said in-process ingress "deletes the absent CORS layer (verified: tower-http, CorsLayer and any Access-Control header are absent from every crate)." Half of that is true and the important half is false. `CorsLayer` and `tower-http` genuinely do not appear anywhere in `crates/` (re-verified). But the header is set by hand, which is why a literal-string grep missed it:

```rust
// crates/swarm-ingest-runtime/src/ingest/demo.rs:361-369
pub(super) fn with_demo_cors(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
```

`runtime_events_handler` (`demo.rs:1644-1717`) routes **every** response through it — the 401, the 400, the 503, and the SSE stream itself at `:1717` — and, unlike its siblings (compare `demo.rs:1279-1291`), it has no `demo_mode_enabled()` check anywhere in its body. Combined with `resolve_demo_scope` (`ingest/mod.rs:636-647`), which returns `Ok(requested_scope)` when no `context_token` is supplied — a token only ever *narrows* scope — the exposure is materially worse than "unauthenticated on the network": **any web page the operator's browser loads can `new EventSource('http://<daemon>:9090/v1/events/stream')` and read the live runtime event stream cross-origin, with no credentials.** That stream carries `TamperAlert` library paths, response executions with receipt ids and policy verdicts, and arbitrary agent detail.

The in-process decision stands on its other three legs. Backend bill item 5 is restated: **gate `/v1/events/stream` AND remove the wildcard ACAO from it** (or scope `with_demo_cors` to the configured demo origin). Ship it regardless of Perch; the wildcard is the part that makes the leak remotely reachable.

### Where the bearer token lives

OS keyring via the existing `secret_store.rs`, injected into the request by the Rust command, never present in the webview. `desktop/src-tauri/tauri.conf.json:39` sets `connect-src 'self' ipc: … https: http: wss: ws:` — the webview *can* reach the daemon directly, and the CSP will not stop it. The rule that stops it is that no `fetch()` to :9090 exists above the seam, enforceable with a lint on the string `9090` in `console/src`.

---

## 8. Build system reconciliation

Perch inherits Buzz's toolchain unchanged, because it *is* Buzz's tree. Ambush's is untouched.

| Concern | Perch (fork of Buzz) | Ambush | Reconciliation |
|---|---|---|---|
| Rust toolchain | `rust-toolchain.toml` = 1.95.0 | 1.97.1, with a written reason | **None needed.** Separate repos, separate pins. Perch tracks Buzz's pin so upstream merges compile. |
| Cargo workspace | 30 members → 13, `exclude = ["desktop/src-tauri"]` retained (rename to `console/src-tauri`) | 20 → 21 | Two workspaces, two lockfiles, one wire protocol between them. |
| JS | pnpm + Vite + `tsc` + Biome; `pnpm build:e2e` compiles the mock bridge, plain `pnpm build` silently does not | none | Inherited verbatim. |
| Toolchain pinning | Hermit (`bin/` with cargo, node, pnpm, biome, just, lefthook, cargo-deny, pgschema, flutter, dart) | none — CI installs Rust stable via action | Perch keeps Hermit and drops `flutter`/`dart` from `bin/hermit.hcl` with mobile. Ambush gains nothing. |
| Task runner | `just` (~340-line justfile) | plain `bash tools/*.sh` from `.github/workflows/ci.yml` | Deliberately not unified. Ambush's gates are self-testing bash by design (`check-workspace-layering.sh` builds a fixture workspace and breaks it seven ways on every invocation). Wrapping them in `just` adds a layer and subtracts nothing. |
| Moon | Backbay workspace-level orchestration | n/a | Both repos sit under `standalone/`-style checkouts, invoked by their own runners. No moon target is added. |
| DB tooling | `pgschema` desired-state + `scripts/reconcile-schema-after-pgschema.sql` for the DML `pgschema` omits | file-backed JSON stores | Perch keeps it. Ambush's stores are untouched — the relay's Postgres holds conversation, not record. |

Renames, in one commit, before anything else: `desktop/` → `console/`, `productName: "Buzz"` → `"Perch"`, `identifier: "xyz.block.buzz.app"` → `"labs.backbay.perch"`, deep-link scheme `"buzz"` → `"ambush"`. The scheme rename touches `src-tauri/src/deep_link.rs` (seven recognized hosts) and every `buzz://` literal. The `buzz-media:` custom protocol and the `--buzz-*` CSS variable prefix are **not** renamed in v1 — they are internal identifiers, the CSP names `buzz-media:` explicitly, and ~780 lines of `theme.css` select on `data-testid` values. Renaming them buys nothing and breaks theming silently.

The signing pipeline does not transfer. Buzz's macOS notarization lives in the private `squareup/buzz-releases` repo (per the repo's own CLAUDE.md ecosystem table; the private repo was not accessible). Perch needs its own Developer ID, its own notarization, and its own `tauri.conf.json` updater endpoints (currently `"endpoints": []`). Budget it as new work, not as inherited work.

---

## 9. CI reconciliation

Two suites that do genuinely different jobs and should stay separate.

**Ambush CI** (`.github/workflows/ci.yml`): 12 jobs — `fmt`, `panic-contract`, `build`, `clippy`, `test`, `solver-z3`, `fixture-freshness`, `platform-contract`, `proof-surfaces`, `jetstream`, `benchmark`, `supply-chain` — invoking 14 `tools/check-*.sh` plus `verify-release-hardening.sh`. `tools/check-gates-wired.sh` structurally parses every workflow and fails if any gate script is not named by a real `run:` step (not a comment, not a `paths:` filter, not an `if: false` step).

**Buzz CI** (`.github/workflows/ci.yml`): 21 jobs, gated by a `changes` paths-filter job, plus lefthook pre-commit (five parallel fix groups with `stage_fixed`), `commit-msg` (DCO sign-off), and pre-push (`file-size-check`, clippy, `tsc --noEmit`, four parallel unit-test groups, each scoped to `git diff origin/main...HEAD`).

Perch inherits Buzz's wholesale and deletes the jobs whose subjects are gone: `mobile` (`:951`), `mobile-swift` (`:1010`), `desktop-build-macos` (`:1183`, until Perch has its own signing identity), `sprig*`, `helm-chart`, `push-gateway-helm-chart`, plus the five canary workflows. It keeps `changes`, `rust-lint`, `unit-tests`, `desktop-core`, `desktop-smoke-e2e`, `desktop-e2e-relay`, `desktop-e2e-integration*`, `backend-integration`, `relay-e2e`, `web`, `security`, `dead-token-guard`, `server-cross-compile`, `windows-rust`.

**Keeping those jobs is why `buzz-test-client` is kept.** The first draft deleted the crate and kept the jobs, which is a contradiction that would have red-lined CI on the first commit of the prune — and §14 step 1's exit criterion is a green `just ci`. Measured:

| Job | Line | Dependency on `buzz-test-client` |
|---|---:|---|
| `desktop-e2e-relay` | `:324` | Builds the nextest archive with `-p buzz-test-client` (`:381`). |
| `backend-integration` | `:601` | `needs: [changes, desktop-e2e-relay]`; consumes that archive. |
| `relay-e2e` | `:862` | Five `cargo test -p buzz-test-client` invocations (`:889-891`, `:904`). |

**One CI step edit, in the prune commit.** `relay-e2e`'s first test step (`:889`) names four binaries, three of which Perch deletes:

```diff
- cargo test -p buzz-test-client --test e2e_persona --test e2e_team_catalog \
-   --test e2e_nostr_interop --test e2e_project -- --ignored --nocapture
+ cargo test -p buzz-test-client --test e2e_nostr_interop -- --ignored --nocapture
```

`:890`, `:891` (`e2e_relay`) and `:904` (`e2e_media*`) are unchanged. The `backend-integration` archive line (`:381`) is unchanged. That is the whole cost of keeping the crate, and it buys the only independent proof the relay fork still behaves.

**What travels the other way.** Contrarian constraint C6: Ambush adopts two Buzz guards. Both must land as `tools/check-*.sh` named by a real `run:` step, or `check-gates-wired.sh` fails on the commit that adds them:

| Buzz guard | Becomes | Why Ambush wants it |
|---|---|---|
| `desktop/scripts/check-px-text.mjs` (rejects any arbitrary text-size literal — px **and** rem/em — across all of `desktop/src`) | `tools/check-console-text-scale.sh` | A 24/7 wallboard is a zoom-and-legibility surface. Hand-authored SVG axis labels are the exact thing that will regress. |
| `desktop/scripts/check-pubkey-truncation.mjs` (bans ad-hoc `pubkey.slice(0,N)`; forces the canonical `truncatePubkey`/`<PubKey>`) | `tools/check-key-truncation.sh`, **extended to Ed25519** | Ambush's `AgentId` is `swarm:ed25519:<64 hex>` (`swarm-core/src/types.rs:16`) and its voter ids are 64-hex. Truncated prefixes are grindable. The brief's C5 requires the untruncated voter id before any signature. |

06-COPY-AND-VOICE proposes a third, `tools/check-copy-banned-terms.sh`. It is not this document's to specify, but it lands under the same rule (script + real `run:` step in one commit), and §14 step 9 sequences it.

**What does not travel.** Buzz's 1000-line file-size ratchet is a differential gate whose grandfathered set is Buzz-specific (`sidebar.tsx` 1,010, `markdown.tsx` 1,905, `VideoPlayer.tsx` 2,210). Perch keeps it. Ambush does not adopt it — `swarm-runtime` is 92,596 lines across files that would need a baseline of their own, and importing a ratchet without importing its baseline is the vacuous-gate pattern this repo names ten times.

Perch's DCO requirement (`commit-msg` hook, required "DCO Check") survives the fork and applies to Perch commits. Ambush has no DCO gate; do not add one as a side effect.

---

## 10. Licensing and attribution

Both repos are Apache-2.0. Buzz: `LICENSE`, "Copyright 2026 Block, Inc.", **no `NOTICE` file at root** (verified). Ambush: `LICENSE`, "Copyright 2026 Backbay Labs", **with** a `NOTICE` file that already names `vendor/reference/` and points at `docs/VENDOR-REFERENCES.md`.

Apache-2.0 §4 obligations, concretely (this is my reading of the license, not legal advice; have counsel review before the fork is published):

- **§4(a) — deliver a copy of the License.** Perch ships `LICENSE` at root. Already satisfied by the fork.
- **§4(b) — state changes.** Perch adds `NOTICE` and a root `FORK.md` stating the fork point (upstream tag + SHA), the deletions by directory, and the two-hunk relay patch. "Prominent notices stating that You changed the files" is satisfied by a per-repo statement plus the git history; a per-file banner is not required and would be noise across 100k lines.
- **§4(c) — retain notices from the source form.** Buzz has no `NOTICE`, so there is nothing to propagate. Retain the `LICENSE` and every in-file copyright header that exists.
- **§4(d) — the derivative's own NOTICE.** Perch's `NOTICE`:

```
Perch
Copyright 2026 Backbay Labs

This product is licensed under the Apache License, Version 2.0.

This product is a derivative work of Buzz (https://github.com/block/buzz),
Copyright 2026 Block, Inc., licensed under the Apache License, Version 2.0.
Perch was forked at <tag>/<sha>. Files have been deleted, renamed and modified;
see FORK.md for the change record.

Buzz, the Buzz name and the Buzz bee mark are trademarks of Block, Inc. and are
not licensed by the Apache License. They have been removed from this work.
```

- **Ambush's `NOTICE`** gains one paragraph, because `crates/swarm-perch-bridge/src/ws/` is a **modified** copy of `block/buzz`'s `crates/buzz-ws-client`:

```
crates/swarm-perch-bridge/src/ws/ contains source copied and MODIFIED from
buzz-ws-client in Buzz (https://github.com/block/buzz) at <sha>, Copyright 2026
Block, Inc., licensed under the Apache License, Version 2.0. Modification:
four panic sites in connection.rs were rewritten to typed errors to satisfy this
workspace's unwrap_used/expect_used deny lints. See the per-file headers.
```

Each vendored file additionally carries a five-line provenance header naming the upstream path, SHA, and **whether it was modified** — for `connection.rs` that is now `yes`, with the four line numbers. This mirrors `docs/VENDOR-REFERENCES.md`'s existing per-tree provenance record, and it is the difference between a copy and a lift.

**Trademark is a separate axis from license.** Apache-2.0 §6 grants no trademark rights. The Buzz name, the bee mark, `desktop/src/shared/ui/buzz-logo`, the splash assets and the `card-texture*.png` (~3.4 MB of baked brand imagery) are removed, not restyled. Separately, `desktop/public/harness-logos/CREDITS.md` documents nominative-use-only third-party vendor marks (Cognition/Devin, xAI Grok, Cursor). Those ship with `features/agents`, which Perch mostly deletes — but the deletion must be verified, because redistributing a vendor's mark inside a differently-branded security product is a fresh legal question and the current justification ("it identifies its own vendor's harness") does not survive the rebrand.

---

## 11. Dependency delta and supply-chain impact

Ambush's `Cargo.lock` currently resolves 453 packages. `swarm-perch-bridge` adds `nostr 0.44` and `tokio-tungstenite 0.28` and their closures. It adds **no HTTP client** — decision 4 removed `reqwest` from the bridge's story, and `reqwest` is already in Ambush's graph via `swarm-ingest-runtime` regardless.

`nostr 0.44.7` declares: `base64 0.22.1`, `bech32 0.11.1`, `bip39`, `bitcoin_hashes 0.14.1`, `cbc`, `chacha20 0.9.1`, `chacha20poly1305`, `getrandom 0.2.17`, `hex`, `instant`, `scrypt`, `secp256k1 0.29.1`, `serde`, `serde_json`, `unicode-normalization`, `url`.
`tokio-tungstenite 0.28.0` declares: `futures-util`, `log`, `rustls`, `rustls-pki-types`, `tokio`, `tokio-rustls`, `tungstenite 0.28.0`, `webpki-roots 0.26.11`.

Cross-checked against Ambush's lock:

| Package | Ambush today | Added | Result |
|---|---|---|---|
| `base64` | 0.22.1 | 0.22.1 | Unifies. |
| `hex` | 0.4.3 | 0.4.x | Unifies. |
| `url` | 2.5.8 | 2.x | Unifies. |
| `getrandom` | 0.2.17, 0.3.4, 0.4.2 | 0.2.17 | Unifies. Already skipped. |
| `instant` | 0.1.13 | 0.1.13 | Unifies. **RUSTSEC-2024-0384 is already on Ambush's ignore list** (for `notify` v7). No new advisory ignore. |
| `webpki-roots` | 0.26.11 + 1.0.7 | 0.26.11 | Unifies with the existing skip. **The skip's stated reason becomes incomplete** — it names `async-nats 0.47 -> tokio-websockets 0.10` as the sole pin. Update the prose; the version pin still matches. |
| `rustls` | 0.23.40 | 0.23.x | Unifies. |
| **`chacha20`** | **0.10.1** (via `rand`) | **0.9.1** (via `nostr`) | **DUPLICATE. `[bans] multiple-versions = "deny"` → `cargo deny check bans` fails → `tools/check-supply-chain.sh` fails → the `supply-chain` CI job goes red.** |
| `secp256k1`, `bitcoin_hashes`, `bech32`, `bip39`, `scrypt`, `cbc`, `chacha20poly1305`, `unicode-normalization`, `tungstenite`, `log`, `rustls-pki-types` | absent | new | New leaves. No version conflict. Licenses (MIT / Apache-2.0 / CC0-1.0 / ISC) are inside Ambush's 12-entry allow-list — **unverified until `cargo deny check licenses` runs; verify before the first commit**. |

**The one bill item, written the way `deny.toml` demands:**

```toml
# Added <date> with the Perch bridge. `nostr 0.44` pins the chacha20 0.9 family
# for NIP-44 payload encryption; the rest of the workspace is on 0.10 via rand.
# Collapses when nostr moves to chacha20 0.10 (or when the bridge stops needing
# nostr's nip44 path). Named pinning dependency: nostr 0.44.
{ crate = "chacha20@0.9.1", reason = "nostr 0.44 (NIP-44) pins chacha20 0.9; workspace is on 0.10 via rand" },
```

That is one line, dated, with the dependency that pins it and the event that retires it — the exact shape of the existing 19 entries. It is a reviewable act, which is the point of the gate. (`unverified`: this is derived from reading both lockfiles and `deny.toml`; `cargo deny check bans` was not run against a merged graph.)

**Additional impacts:**

- **SBOM.** `tools/generate-sbom.sh` runs `cargo cyclonedx --manifest-path Cargo.toml` and emits one `.cdx.json` per crate. A 21st crate produces a 21st file automatically; the script counts what it produced and fails on zero. No change needed, but the SBOM's package count grows by ~15 and the release-artifact diff should be reviewed once.
- **`cargo audit`** reads the whole lockfile regardless of features. `tools/check-supply-chain.sh` hardcodes `--ignore RUSTSEC-2024-0384 --ignore RUSTSEC-2025-0134` and its comment requires those stay identical to `deny.toml`'s ignore list. `instant` is already covered; if `nostr`'s closure surfaces a new advisory, it must be added in **both** places or the two gates disagree.
- **Two TLS trust-anchor sets.** `deny.toml` already flags `webpki-roots` 0.26 vs 1.0 as a standing **SECURITY REVIEW ITEM**: the NATS client and the HTTP client can disagree about which CAs are trusted. The relay socket now joins the 0.26 side. This does not create the problem; it raises its stakes, and the deployment doc should say the relay connection rides the older root snapshot until `async-nats` moves.
- **`all-features = false`.** `deny.toml`'s measured limitation 2 means the `z3` feature subgraph is invisible to every check. The bridge is default-on, so it is inside the scanned graph. Do not gate the bridge behind a cargo feature — that would move it *out* of the supply-chain scan.
- **The stated infrastructure cost (brief C2).** Postgres, Redis and 40 migrations enter a product that ships two containers and a data directory. Every deployment document states this plainly, along with the fact that the relay must sit inside the operator's network boundary and never on the internet.

---

## 12. Which shells ship

| Shell | v1 | Reason |
|---|---|---|
| **Desktop (Tauri)** | **Ships** | The daemon bearer token belongs in the OS keyring, injected by a Rust command, never in a webview. A browser-hosted console turns that into a same-origin gateway design — which is the contrarian's plan, rejected. The PTY panel is also only possible here (`portable-pty`, 9 `terminal_*` commands). |
| **Web (`web/`)** | **Pruned, preserved, unbuilt** | 48 `.ts`/`.tsx` files, 4,159 LOC (the brief cites 49/4,259 — same order, counted differently; `web/` has 65 non-`node_modules` files total, so the brief likely counts `.css`). It is precedent that the design system harvests cleanly, and `buzz-relay/src/router.rs:162` already serves it via `ServeDir`. Keep the tree and the `web` CI job as a build-only smoke; add no Perch surfaces to it. Revisit if non-extractable WebCrypto ledger signing becomes the priority — that is a property a Tauri app signing in Rust cannot claim. |
| **Mobile (Flutter)** | **Deleted** | The brief closes it. `mobile/lib/shared/relay/nostr_models.dart` is the third hand-synced kind registry; marker-prefixed kind:9 means mobile degrades honestly and comes back for free later. Deleting it also removes `flutter`/`dart` from Hermit and four CI jobs. |
| **`admin-web/`** | **Delete** | Block-internal relay administration UI. `buzz-admin` (the CLI) is kept instead. |

The E2E mock bridge proves the browser path is reachable: `desktop/src/testing/e2eBridge.ts` has a "relay" mode that swaps the mock socket for a real browser WebSocket and signs genuine NIP-42 kind:22242 events (`:4188`, `:14042-14099`). That is evidence, not a commitment.

---

## 13. Testing strategy

Inherited from both, kept separate.

**From Buzz.** 162 Playwright specs and 610 `*.test.mjs` node tests. The asset that matters most is `desktop/src/testing/e2eBridge.ts` — 14,620 lines implementing the entire backend as one `switch (command)` behind Tauri's `mockIPC`. It is simultaneously the repo's largest maintenance liability (every backend change must be mirrored or 162 specs go red) and the only reason the console can be developed, screenshotted and regression-tested with no swarm running. It survives `check-file-sizes` only because `src/testing` is not one of the nine governed roots (`desktop/scripts/check-file-sizes.mjs:10-53`).

**Decision: keep it, and replace its fixtures rather than its shape.** The brief's default is explicit — develop the UI against the mock bridge with Ambush fixtures and never ship a demo implying a working gate. Concretely: an `ambushFixtures.ts` module supplying held actions, findings, deposits, leases and receipts, plus a `__PERCH_E2E_EMIT_RUNTIME_EVENT__` hook mirroring the existing `__BUZZ_E2E_EMIT_MOCK_MESSAGE__`. The four documented traps carry over verbatim: build with `pnpm build:e2e` (a plain `pnpm build` strips the bridge and every spec fails with `Cannot read properties of undefined (reading 'invoke')`, which looks exactly like a product bug); `addInitScript` before `installMockBridge`; `waitForMockLiveSubscription` before emitting; `waitForAnimations` before any screenshot.

**From Ambush.** Its testing culture is gates, not suites: 643 `#[test]` sites plus 14 self-testing bash gates. The two that constrain the bridge are `check-runtime-panic-contract.sh` (production `unwrap`/`expect`, with a per-invocation self-test) and `check-worktree-clean.sh`, which runs after the test job and fails if a test wrote a stray artifact. The bridge's disk spool must therefore respect a configured directory and never default into the repo.

### 13.1. What is actually Ed25519-signed today — and the contract test rewritten against it

**The first draft's contract test could not pass, and neither could 09's Phase-0 exit criterion 1.** Both asserted that a marker card's *"Ed25519 signature verifies against the Ed25519 chain."* Measured, for the marker card types (`03` §13 now freezes **seven** — `ambush:verdict:v1` was added when 46030/46031 was withdrawn as leg 1's carrier; it carries a real Ed25519 signature only after bill item B2o):

| Marker card | Underlying Rust type | Signature field? | Chain link? |
|---|---|---|---|
| `ambush:finding:v1` | `DetectionFinding` (`swarm-whisker/src/detector.rs:50-59`) — 7 fields | **None** | None |
| `ambush:finding:v1` (envelope form) | `SwarmFindingEnvelope` (`swarm-response/src/siem.rs:18-27`) — 8 fields | **None** | None |
| `ambush:escalation:v1` | `EscalationRecord` (`swarm-core/src/pheromone.rs:237-252`) — 6 fields | **None** | None |
| `ambush:hold:v1` | new `HeldActionStore` record (does not exist yet) | **None by default** | None |
| `ambush:receipt:v1` | `ResponseReceipt` (`swarm-response/src/lib.rs:100-116`) | **None.** Its `audit.governance.receipt` is an untyped `Option<serde_json::Value>` (`:136-142`) that *may* carry a serialized `swarm_consensus::ConsensusGovernanceReceipt` — which **is** Ed25519-signed (`swarm-consensus/src/lib.rs:382`, `:422`) | Only via that nested value |
| `ambush:rollback:v1` | `RollbackReceipt` (`swarm-response/src/rollback.rs:242-263`) | **None of its own** — carries `origin_receipt_id`, `governance_receipt_id: Option<String>` and an opaque governance attestation | ids only |
| (`AuditTrail`, the spine's own record) | `swarm-spine/src/lib.rs:114-122` — 7 fields | **None** | None |

The chain machinery the plan cites is near-dead. `build_signed_envelope` (`swarm-spine/src/envelope.rs:71`) has **exactly one non-test caller in the entire workspace** — `crates/swarm-runtime/src/approval.rs:1810`, the approval ledger. `verify_chain_link` and `ChainLinkVerdict` have **zero** consumers outside `swarm-spine`'s own module and tests (the only other mention is the re-export at `swarm-spine/src/lib.rs:61`). The two objects that *are* routinely Ed25519-signed are `PheromoneDeposit.signature` (`swarm-core/src/pheromone.rs:231-232`) — which 03 §4.1 says is never published — and `swarm-consensus`'s receipts.

Worth naming precisely, because it changes what a badge may say: the one live envelope call signs with `Keypair::from_seed(sha256("approval-ledger-envelope:{ledger_id}"))` (`approval.rs:1808-1812`, `swarm-crypto/src/signing.rs:31`). The seed is a public value, so that signature proves **chain integrity, not authorship**. Any UI that renders it must say "envelope hash chain intact," never "signed by X."

**Resolution: option (a). Add backend bill item 6b — sign the fact before it leaves the daemon.**

```rust
// Sketch, in the bridge's publish path, on the daemon side, before Nostr I/O.
// Exactly the pattern approval.rs:1810 already uses, with the daemon's own
// governance keypair rather than a derived one.
let envelope = build_signed_envelope(
    daemon_keypair,          // NOT derived from a public id
    seq.next(),              // per-issuer monotonic; the same seq the gap row uses
    prev_envelope_hash,
    fact,                    // the DetectionFinding / receipt / hold, verbatim
    now_rfc3339(),
)?;
```

This is one call per published fact, it makes `verify_chain_link` a live consumer for the first time, and it is what turns "the daemon is the record" from a slogan into something a console can check. It also converts 08's export bundle from decorative to real.

**The contract test, rewritten so it can pass:**

> Given a `RuntimeEvent` fixture, the bridge produces (i) a `kind:9` whose marker comment, JSON body and one-line human fallback parse back to the same fields, and (ii) a spine envelope over that same `fact` whose `envelope_hash` recomputes and whose Ed25519 signature verifies with `verify_envelope`, and whose `seq`/`prev_envelope_hash` satisfy `verify_chain_link` against the previous envelope from the same issuer. The Nostr secp256k1 envelope signature is asserted separately and is never accepted as a substitute.

It lives in Ambush (`crates/swarm-perch-bridge/tests/`), with the golden JSON checked into Perch as a Playwright fixture. Both sides read the same file; a drift breaks both suites.

**If item 6b is cut,** then every render law, badge, export bundle and exit criterion that says "Ed25519" must be rewritten to *"signed by the bridge's Nostr key; the daemon is the record and the verify affordance re-fetches it"* — and `GET /v1/response/holds/{id}` (bill 6a) becomes load-bearing rather than convenient, because re-fetching would be the only integrity check that exists. 09's Phase-0 exit criterion 1 must name whichever of the two was chosen. As written in the first draft it named neither, and could not pass.

---

## 14. The Monday sequence

Eleven steps. Steps 0-2 are housekeeping and are immediate, not deferred; step 3 is the gating item.

| # | Step | Repo | Depends on | Note |
|---|---|---|---|---|
| **0** | Split `AppShell.tsx` (997/1000) and `MessageRow.tsx` (998/998); lift the renderer registry out of `MessageRow` into `features/messages/ui/renderers/`. | **perch** | — | **Corrected from the first draft, which put this upstream and gated everything on it.** Do it in the fork on day one, where it is unblocked. Offer the identical refactor to `block/buzz` as a good-citizen PR with **no schedule dependency**: 1,867 commits in 90 days and 103 touches to `AppShell.tsx` alone make an external merge an unschedulable event. 09's K1 measures this in engineer-weeks, which only makes sense in the fork. |
| **1** | Fork, rename, prune. `desktop/` → `console/`, product/identifier/scheme rename, delete the 17 crates and the feature directories in §5/§6, prune the ten `buzz-test-client` specs and edit `relay-e2e:889`, delete `mobile/` and `admin-web/`. Add `NOTICE` + `FORK.md`. | perch | 0 | One large commit per deletion group, so `git log --diff-filter=D` is the change record §4(b) needs. Green `just ci` at the end or the prune is not done — which is why §9's job list and §5's crate list must agree. |
| **2** | The relay patch. Two hunks in `handlers/ingest.rs`, as `patches/0001-relay-46010-scope.patch` + a `just relay` step that applies it. Open the same change as a PR to `block/buzz`. | perch + buzz | 1 | Include the test in `buzz-test-client`: publish a 46010 without an `h` tag and assert rejection. That test is what makes it a bug fix rather than a feature, and it is the second reason the crate is kept. |
| **3** | `HeldActionStore` + `RuntimeEvent::ResponseHeld`. Persist a hold where `LiveResponse` today returns `ApprovalError::Denied` (`swarm-runtime/src/lib.rs:979-981`) and records `AuditResponseRecord::Skipped` (`:1133-1145`). | ambush | — | **Largest item; gates everything downstream.** Runs in parallel with 1-2. The human-approved path (`audit_authorize_and_execute_human_approved_instrumented`, `:1085`) is reachable today only from two demo-gated sites. |
| **3.5** | **NEW — put the human in the record.** Thread `approved_by: Option<OperatorApproval>` (operator_id, decided_at_ms, hold_id, signature) through `audit_authorize_and_execute_human_approved_instrumented` into `ResponseReceiptAudit` and the spine envelope. | ambush | 3 | Measured gap: that function takes `(&DetectionFinding, &ActionRequest, &ApprovalContext)` and **no approver** (`lib.rs:1085-1092`); `allow_human_approved_execution` is a bare `bool` that only flips the `RequireHuman` arm (`:1133-1136`); `ActionRequest` has five fields, none an operator (`swarm-policy/src/lib.rs:47-58`); `ResponseGovernanceAudit.governing_agent_id` is Tom, not the human (`swarm-response/src/lib.rs:136-142`). Without this, a granted destructive action is byte-indistinguishable in the chain from an autonomous one except that `policy.verdict` reads `require_human`, and 01/08's "who approved this" claim is false. **Until 3.5 lands, the export bundle answers only "a human was asked."** |
| **4** | `crates/swarm-perch-bridge`: vendor `buzz-ws-client` **with the four panic sites rewritten**, add `nostr`/`tokio-tungstenite`, the `chacha20@0.9.1` skip entry, the `NOTICE` paragraph. Prove `tools/check-workspace-layering.sh`, `tools/check-runtime-panic-contract.sh` and `tools/check-supply-chain.sh` stay green **before** writing any bridge logic. | ambush | — | The gate run is the first commit, not the last. If `cargo deny check licenses` rejects a new leaf, that is a decision to take before 3,000 lines exist on top of it. Half an engineer-week for the panic rewrite (§5). |
| **5** | Bridge ingress: `subscribe_runtime_events()` → disk spool → per-issuer sequence → `kind:9` marker cards + ephemeral telemetry, coalesced to 1 Hz. Hydrate from `current_{replay,incident,investigation,containment}_store()` **in-process**. Mount in `swarm_detect.rs` next to the containment router, with the same loud-on-failure logging. | ambush | 3, 4 | The contract test (§13.1) lands here, against whichever of 6b / re-fetch was chosen. |
| **6** | Console transport: `src-tauri/src/ambush/` daemon client + the eight commands over seven routes (three of which already exist); re-point `grant_approval`/`deny_approval` at the daemon; `resetCommunityState()` becomes a typed registry with an exhaustiveness check. | perch | 2 | The registry change ships in the same commit as the first Ambush singleton. Not after. |
| **7** | Ambush routes: `POST /v1/response/holds/{id}/decide` (mint the `CapabilityLease` at **decision** time — `lease_ttl_ms` is 60000), `GET /v1/response/holds[/{id}]`, `POST /v1/operator/findings/{id}/feedback`, `GET /v1/operator/pheromone/deposits`, gate `/v1/events/stream` **and drop its wildcard ACAO**. | ambush | 3 | **Feedback has a prerequisite this plan owes 03:** `providence_feedback_handler` takes a non-optional `incident_id` (`providence_handlers.rs:100`), does `current_incident_store().load_by_incident_id()` and 404s if absent (`:130-139`), and writes the measurement onto the `IncidentRecord` (`:171`) — and `build_alert_tuning_report(records: &[IncidentRecord])` (`alert_tuning.rs:85`) reads it from there. So a verdict on an *uncorrelated* finding has nowhere to land. Either the feedback route creates/attaches a single-member `IncidentRecord`, or the tuning loop does not close for the majority of findings. Decide this before writing the route. |
| **8** | Surfaces, in dependency order: `/` (The Watch + verdict row, **with the C9 counters**) → `/cases/$id` → threat-class lanes → `/leases` → `/ledger` → `/policy` → `/tuning` → `/handoff` → `/gaps` → `/watch-floor`. Each behind a `preview-features.json` flag. | perch | 5, 6, 7 | `/settings` becomes a real route before the first new surface, because `AppShell` currently swaps its whole layout on `location.pathname === "/settings"` (`AppShell.tsx:173`). The settled keymap is 04's `C`/`D`/`I` (findings) and `G`/`R` (holds); nothing in this sequence re-decides it. |
| **9** | Adopt `tools/check-console-text-scale.sh`, `tools/check-key-truncation.sh` (Ed25519-extended) and 06's `tools/check-copy-banned-terms.sh` into Ambush CI, wired into real `run:` steps. | ambush | 7 | `check-gates-wired.sh` fails on the commit that adds an unwired gate, so the workflow edit is part of the same commit. |

**The C9 instrumentation has one home: `/` (The Watch).** Median seconds page-to-verdict, measurements written per week, and the fraction of this week's tuning recommendations sourced from this week's verdicts ship **in step 8's first surface**, because `/` is the only Phase-1 surface and instrumentation added later is instrumentation never added. `/tuning` and `/handoff` restate the same three numbers read-only and link back to `/`. 09's exit criterion 6 names `/`, not `/watch` — **done**, `09` §3.3 criterion 6.

**Fallback, from the brief.** If step 3 slips more than one milestone, ship `/watch-floor` + `/ledger` + `/gaps` as v0 with the verdict queue visibly labelled *not yet wired*. Those three read the ephemeral telemetry stream, the FTS index, and a checked-in YAML catalogue respectively — none of them needs the hold store, and none of them implies a working gate.

---

## 15. Ambush surfaces Perch does not replace

Two shipped external contracts have no home in the other eight documents, and leaving them unnamed is a compatibility cost that shows up at the worst time.

| Surface | What it is | Disposition |
|---|---|---|
| `/v2/api` (6 routes: `/findings`, `/incidents`, `/evasion/coverage`, `/assets/{host_id}/posture`, `/stream/findings`, `/runtime/status` — `platform_api.rs:813-821`, nested on the daemon at `ingest/mod.rs:2573`) | The read-only platform API, bearer-authenticated, rate-limited | **Frozen at its current shape.** No new fields, no new routes, no deprecation date. It stays because Perch has exactly one dependency on it: `/tuning` reads `GET /v2/api/runtime/status` for `alert_tuning` (`:1323`), **on demand, never polled** — `platform_runtime_status_handler` loads incidents with `.recent(usize::MAX)` (`:1095`, `:1168`), so a 5-second poll from a wall screen is a self-inflicted outage. If `/tuning` ever needs a poll, that is the trigger to add a narrow `GET /v1/operator/tuning/recommendations` as a seventh bill item, not to loosen this rule. |
| `clients/python/swarm-platform-client/` (a generated `openapi-python-client` package: `client.py`, `types.py`, ~20 model modules, six API modules mirroring the routes above, plus `smoke_platform_client.py`; 53 `.py` files) | The published Python client for `/v2/api` | **Frozen, and explicitly not a Perch dependency.** It is generated by `tools/generate-platform-python-client.sh` from the OpenAPI document `tools/generate-platform-openapi.sh` emits and `tools/check-platform-openapi.sh` guards, so freezing `/v2/api`'s shape freezes the client for free and the `platform-contract` CI job already fails on drift. Perch does not import it, extend it, or route through it. If a deployment already polls `/v2/api` with this client, that polling is *its* problem and predates Perch — but the deployment doc must say the daemon serves both, and that the `.recent(usize::MAX)` cost is paid per caller. |

The rule underneath both rows: **Perch is a fourteenth surface on an existing product, not a replacement for its integration points.** Anything that already has an external consumer gets frozen, not deprecated, until someone writes down who the consumer is.

---

## 16. Changelog against the first draft

| # | Was | Is | Evidence that forced it |
|---|---|---|---|
| 1 | "the daemon (49 routes)" as one surface; bridge hydrates over `GET /v1/operator/*` | Two routers named separately (§3, §3.1); bridge hydrates in-process; the daemon's real operator surface is the 2-route containment router | `detect_http_router` (`ingest/mod.rs:2540-2575`) has zero `/v1/operator/*`; the 49 are `state.rs:293-497` under `swarmctl serve` (`core.inc:3345`); `containment.rs:29-33` says why |
| 2 | Contract test asserts "Ed25519 signature verifies against the Ed25519 chain" | §13.1 table of what is actually signed; bill item 6b (`build_signed_envelope` on the publish path) or an explicit fallback | `build_signed_envelope` has one non-test caller (`approval.rs:1810`); `verify_chain_link` has zero; `DetectionFinding`/`ResponseReceipt`/`AuditTrail`/`RollbackReceipt` carry no signature |
| 3 | `buzz-ws-client` vendored as "an unmodified copy" | Copy with four panic sites rewritten to typed errors; recorded in the provenance header and `NOTICE`; the `#[allow]` alternative named and rejected | `connection.rs:170,172,229,231` are above the `#[cfg(test)]` at `:296`; `Cargo.toml:135-137` denies both lints |
| 4 | File splits done upstream in `block/buzz`, gating everything | Done in `backbay-labs/perch` on day one; offered upstream with no dependency | 1,867 commits / 90d; `AppShell.tsx` touched 103 times in that window |
| 5 | "the absent CORS layer (verified: … any Access-Control header absent)" | `with_demo_cors` sets wildcard ACAO on every `/v1/events/stream` response; bill 5 upgraded to "gate **and** de-wildcard" | `demo.rs:361-369`, applied at `:1717` and on all four error paths; `resolve_demo_scope` (`ingest/mod.rs:636-647`) authenticates nothing |
| 6 | Presence "single-node with no `PUBLISH`" | Presence *does* publish globally; the real reason is the 180 s TTL lie window | `event.rs:844-846` comment + `publish_event(…, EventTopic::Global, …)` at `:888`; `PRESENCE_TTL_SECS = 180` (`presence.rs:16`) on a 60 s heartbeat (`lib.rs:331`) |
| 7 | "283,255 lines" across `features/`; "100-110k of 283k" retained | 254,557; "~90-100k of 254,557", plus `shared/`+`app/` = 52,903 | The per-row values sum to exactly 254,557; `desktop/src` as a whole is 322,393 |
| 8 | 11 kept / 19 deleted crates | 13 kept (194,700 LOC) / 17 deleted (140,552) = 30 | `ls crates/ \| wc -l` = 30; the old split double-counted `buzz-ws-client` and omitted `buzz-workflow` |
| 9 | `buzz-test-client` deleted, `relay-e2e` + `backend-integration` kept | Crate kept with ten specs pruned; one CI step edit at `ci.yml:889` | `ci.yml:381`, `:889-891`, `:904` — three kept jobs are implemented by the deleted crate |
| 10 | Five backend routes | Six (+ `GET /v1/response/holds[/{id}]`), plus items 3.5 and 6b | The console must be able to read the daemon at all; `audit_…_human_approved_instrumented` takes no approver |
| 11 | No mention of `clients/` or `/v2/api` | §15 freezes both | `clients/python/` is 53 `.py` files against the same six routes `/tuning` reads |
| 12 | "lane" used for both inbox categories and threat-class channels | "lane" reserved for the twelve threat-class channels; inbox categories are "queues"; CI parallel groups are "groups" | 06's own rule for "lease": two unrelated objects may not share one bare word |

**Terminology note for reviewers.** Following 06's rule, this document now uses **lane** only for the twelve standing threat-class channels. The four inbox categories are **queues**; lefthook's and CI's parallel units are **groups**. 05's hue taxonomy takes **pillar** (`--pillar-substrate`, …, after `docs/assets/pillars.svg`) and 07's transport classes take **streams**, so "the evidence lane" cannot mean a colour token and a disk spool in the same sentence.
