# 01 — The design, as it stands in one repository

**Status: the design of record for the integration, 2026-09-02.** This document is the spec
the wave-3 plans (`10-` … `14-`) implement. It is deliberately short where wave 1 and wave 2
already argue a point: it cites them and states only what changed. Where it and a cited
document disagree, `00-DECISIONS.md` has already ruled and this document follows the ruling.

Path convention: unprefixed = this repository's root (the engine); `workspace/` = the Ambush
workspace (the former chat repository).

---

## 1. What is being built, in one paragraph

The Ambush workspace — a Nostr-relay-backed team chat where humans and agents are the same kind
of participant — gains a feature area, codenamed **perch**, that turns it into the operator
console for the Ambush engine, a Rust swarm that detects, decides, acts and proves. The engine
publishes what it saw and what it held into the relay as signed cards; the console renders them
in lanes, cases and a shift-shaped verdict queue; a human's decision is a typed, signed act that
lands on a case, reaches the engine over a separate authenticated path, and becomes the next
tuning input. **The console never authorizes.** That property is guaranteed by a process
boundary (ADR 0014), and every other decision here is negotiable in a way that one is not.

The category argument is `../01-POSITIONING.md` §1; the product spine (fourteen surfaces,
seven render laws, four mechanized risks) is `../00-BRIEF.md`; the hero surface is
`../04-SURFACES-AND-UX.md` §2.1. None of that changes.

---

## 2. Repository layout after the merge (D2)

```
ambush/                              # github.com/backbay-labs/ambush
├── Cargo.toml                       # engine workspace (20 crates) — exclude = ["workspace"]
├── rust-toolchain.toml              # 1.97.1, edition 2024
├── crates/
│   ├── swarm-core … swarm-runtime-http   # the engine, unchanged in shape
│   ├── swarm-perch-wire/            # NEW  types-only: the seven cards, the eight frames, tags, HoldId
│   └── swarm-perch-bridge/          # NEW  in-process publisher: RuntimeEvent → spool → relay
├── rulesets/perch-dev.yaml (+ .sig.json)   # NEW  live-response dev profile, debug-signed
├── tools/check-perch-*.sh           # NEW  the perch gates, wired per check-gates-wired.sh
├── docker-compose.yml               # gains relay, postgres, redis beside swarm-detect
├── docs/plans/ambush-ui/            # waves 1, 2 and this one
├── .github/workflows/
│   ├── ci.yml                       # engine CI, unchanged triggers
│   └── workspace-ci.yml             # NEW  the workspace CI, re-rooted
└── workspace/                       # the Ambush workspace, own Cargo workspace + toolchain + Hermit
    ├── Cargo.toml                   # ambush-* crates; excludes desktop/src-tauri
    ├── rust-toolchain.toml          # 1.95.0, edition 2021
    ├── bin/ (Hermit), justfile, lefthook.yml
    ├── crates/ambush-relay, ambush-core, ambush-db, ambush-ws-client, ambush-sdk, …
    ├── desktop/                     # Tauri 2 + React 19
    │   ├── src/features/perch*/     # NEW  the feature area (§7)
    │   ├── src/shared/api/perch*.ts # NEW  keys, subscriptions, ephemeral store, Tauri wrappers
    │   └── src-tauri/src/commands/perch_*.rs   # NEW  the daemon client and the verdict signer
    ├── web/, mobile/, admin-web/    # unchanged; cards degrade via the human line
    ├── migrations/, schema/         # unchanged: no migration is needed (ADR 0012 Fact 1)
    └── docs/, scripts/, tests/
```

Dependency edges across the two workspaces are exactly those `00-DECISIONS.md` D2 allows:
`swarm-perch-bridge` → `workspace/crates/ambush-ws-client` (and later `ambush-sdk`) by path;
`workspace/desktop/src-tauri` → `crates/swarm-perch-wire` by path, and nothing else.

---

## 3. Processes and trust boundaries

Four processes. Nothing about their boundaries changed from `../02-ARCHITECTURE-INTEGRATION.md`
§3 and ADRs 0012, 0014, 0015; the naming did.

| Process | Binary / entry | Holds | May write |
|---|---|---|---|
| **A — the daemon** | `swarm_detect --serve`, default `127.0.0.1:9090` | the substrate, the receipt chain, the governance keyring, the containment lease map, **the hold store (B1)**; hosts **`swarm-perch-bridge` in-process** | every engine store; the relay, through the bridge only |
| **B — the ops surface** | `swarmctl serve`, `127.0.0.1:7766`, off by default | its own local stack; **not the daemon's** (ADR 0012 Fact 2) | nothing perch reads in v1 |
| **C — the relay** | `workspace/crates/ambush-relay` + Postgres + Redis, inside the operator's network boundary | the conversation, the notification index, search; **never the record** | its own tables |
| **D — the console** | the Tauri host process + the webview | the operator's secp256k1 key (keyring), the daemon bearer token (keyring, **never in the webview**, INV-22) | the relay: kind:9 messages including exactly one governance marker, `swarm:verdict:v1`; the daemon: the five allowlisted routes (INV-01) |

The engine's trusted computing base (`swarm-crypto`, `swarm-policy`, `swarm-spine`; ADR 0009)
never links the bridge, the wire crate or anything in `workspace/`. `tools/check-workspace-layering.sh`
derives that from `cargo metadata` on the commit that adds each crate; `swarm-perch-bridge` joins
`TRUST_SENSITIVE` (ADR 0015 C2) and carries the `//! ## Owns` / `//! ## Does not own` headings.

**Two identity chains, never conflated** (ADR 0016): the engine signs facts with Ed25519 under
`swarm:ed25519:<hex>` identities; the relay transports them in secp256k1-signed Nostr events
published by the bridge's derived keys. A badge names the chain and a tier; four of the seven
card types carry no engine signature until B6 and render tier 0, honestly.

---

## 4. The wire (D1 applied)

Everything in `../APPENDIX-NORMATIVE.md` §3 and `../build/13-WIRE-SCHEMAS.md` stands with the
namespace renamed (W3-1) and the rulings W3-15 … W3-21 applied.

**Durable evidence** rides `kind:9` in a lane or case channel. The body is three parts in this
order (W3-21): line 0 is exactly `<!-- swarm:<slug>:v1 -->`; line 1 is one human sentence;
then a fenced JSON block whose info string is `swarm:<slug>:v1` and whose content is a
`swarm.spine.envelope.v1` wrapping a `swarm.perch.<card>.v1` fact. Seven slugs:

| Slug | Author | Channel | Tier today |
|---|---|---|---|
| `finding` | bridge | lane | 0 |
| `escalation` | bridge | lane | 0 |
| `hold` | bridge | case | 0 |
| `verdict` | **the operator's own key**, via `perch_record_verdict` only | case | 0 |
| `receipt` | bridge | case | 0 |
| `lease` | bridge | case | 0 |
| `rollback` | bridge (operator-driven) / needs B1c for TTL-driven | case, NIP-10 reply to the lease card | 1 |

**The hold** is the one stored kind the relay learns: `kind:46010`, already defined as
`KIND_WORKFLOW_APPROVAL_REQUESTED` and queried by the needs-action feed, admitted at ingest by
three hunks in `workspace/crates/ambush-relay/src/handlers/ingest.rs` and made channel-scoped
(`../build/10-RELAY-FORK.md`, re-landed per W3-7). It carries `h` (the case channel), one `p`
per `OperatorScope::Approve` principal, `hold` and `card`; never `e` (RF-D1).

**Live telemetry** rides ephemeral `26000`–`26006`, global, aggregates only, WebSocket only
(ADR 0017). `26006`, the hold alarm, is the only live path to the queue and is fenced by a
`P_GATED_KINDS` entry in `workspace/crates/ambush-core/src/kind.rs` (registry R-1); every REQ
that can match it carries `#p` = the reader's own pubkey.

**Admission.** A card or frame renders only if its Nostr pubkey resolves to an admitted bridge
identity; everything else is counted and dropped (INV-15). The same rule gates `46010`.

**Ids.** `hold_id` matches `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`, is minted by the daemon, and is
never derived from `hunt_id` (R-3, W3-15). `case_id` **is** the case channel's UUID and is
minted by the daemon on promotion (W3-14).

**The wire crate.** `crates/swarm-perch-wire` holds the Rust types, a TypeScript mirror lives at
`workspace/desktop/src/features/perch/wire/`, sixteen golden vectors are hash-pinned, and
`tools/check-perch-wire-parity.sh` fails the build if the two sides drift
(`../build/skeleton/perch-wire/`, renamed).

---

## 5. Data flow

```
telemetry ─▶ Whisker detect ─▶ deposit ─▶ concentrate ─▶ escalate ─▶ Pounce/Tom ─▶ dispatch ─▶ seal
                 │                                                      │
                 └── RuntimeEvent broadcast (in-process, 1,024 slots) ◀─┘
                                   │
                    swarm-perch-bridge (process A)
                    recv ─▶ classify (exhaustive) ─▶ spool (disk, per-issuer seq) ─▶ 1 Hz pacer ─▶ NIP-42 WebSocket
                                   │
                              the relay (process C): stores kind:9 / 46010, fans out 26xxx
                                   │
               console (process D): 7 REQs ─▶ React Query cache (durable) / ephemeral store (26xxx)
                                   │
                        render: lane, case, The Watch, verdict pane, governance strip
                                   │
             human presses D / C / I / G+Enter / R / E
                                   │
      leg 1: perch_record_verdict signs a swarm:verdict:v1 card from DAEMON-fetched state ─▶ relay
      leg 2: perch_decide_hold / perch_finding_feedback / perch_mint_incident ─▶ POST to daemon (bearer from keyring)
                                   │
                    daemon re-derives authority, mints the capability lease at DECISION time, executes or refuses
                                   │
                    ResponseExecution / CasePromoted / ContainmentReleased events ─▶ bridge ─▶ receipt / lease / rollback cards
```

Four properties of this flow are load-bearing and each has an owner in wave 2:

- **The bridge never blocks the daemon and never reads.** Receive → classify → append-to-spool
  is the whole hot loop; network I/O drains the spool on another task; zero `REQ` or `COUNT`
  frames, ever (ADR 0015 C3, C4). Lag past the broadcast buffer is recorded as a **gap** and
  rendered as a gap row, never a silent hole.
- **The relay is never the record.** Every hold the console shows is reconciled against
  `GET /v1/response/holds` on connect, reconnect and every `26006`; a relay row with no daemon
  record renders `UNRECONCILED` (W3-18) and is excluded from export.
- **Writes are two-legged and never optimistic.** Leg 1 is the human's own signature over their
  intent, before the outcome is known; leg 2 is the decision the daemon makes from scratch. The
  UI renders `sending → recorded → acknowledged | refused_late | superseded` and offers no undo
  (INV-28, INV-33, INV-36).
- **A verdict has somewhere to live.** Feedback is incident-keyed in the engine, so promote-to-case
  mints a single-member `IncidentRecord` with the six fields ADR 0018 C3 names, and the daemon's
  `RuntimeEvent::CasePromoted` is what makes the bridge create the case channel (B1d).

---

## 6. Daemon additions, by milestone

The backend bill (`../APPENDIX-NORMATIVE.md` §5 with registry W2-9's four additions) is
unchanged in content and re-sequenced by milestone. Every route mounts in **process A** under
`require_bearer_auth` **plus** an explicit `require_operator_api_scope` (ADR 0012 clause 1 and
its negative consequence). Engine code lives in `crates/swarm-ingest-runtime/src/ingest/perch_ops/`
and `held_actions.rs`; routes and DTOs in `crates/swarm-runtime-http/src/http/perch/`.

| Milestone | Items | Why here |
|---|---|---|
| Ground | **B0** `nostr_pubkey: Option<String>` on `OperatorPrincipalConfig` | without it no hold can be `p`-tagged and reaches nobody |
| First card | **B3** `POST /v1/operator/findings/{id}/feedback` · **B3i** `POST /v1/operator/incidents` · **B3r** `GET /v1/operator/findings/reviewed` · **B1d** `RuntimeEvent::CasePromoted` | the finding path closes the tuning loop for 3.5 ew of Rust; needs no hold |
| The hold | **B1** `HeldAction` + `HeldActionStore` + sweep + `RuntimeEvent::ResponseHeld` · **B2** `POST /v1/response/holds/{id}/decide` · **B2r** the two hold reads · **B2o** `approved_by` in the receipt audit · **B2g** governance + partition re-evaluation on decide · **B5** gate `/v1/events/stream` | the product's central artifact |
| Operator-complete | **B4** `GET /v1/operator/pheromone/deposits` · **B6** signed envelopes on the publish path · **B1c** `RuntimeEvent::ContainmentReleased` · **B2g-p** partition stamps | the remaining surfaces and tier 2 |

Two deployment facts ride with The hold and are on its entry checklist, not its bill:
`runtime.containment.lease_store_path` must be set or a granted containment fails at the decide
route; `correlation.incident_store` must be file-backed with `recent_decisions_limit` raised or
the tuning evidence dies on restart (`../build/21-ADRS.md` Q1's rider).

---

## 7. The console feature area (D3 applied)

**Placement.** Six feature directories under `workspace/desktop/src/features/`, exactly as
`../build/14-CLIENT-ARCHITECTURE.md` §2.1 lays them out (`perch`, `perch-watch`,
`perch-evidence`, `perch-containment`, `perch-policy`, `perch-shift`), plus
`shared/ui/perch/` primitives and four new `shared/api/perch*.ts` siblings. Features never
import each other; cross-feature code goes in `shared/`. **Perch adds files; it never grows a
frozen one** (ADR 0011 clause 4) — `tauri.ts`, `relayClientSession.ts`, `types.ts` and
`markdown.tsx` are on the do-not-edit list in `../build/15-FILE-SPLIT-PLAN.md`.

**Gating.** A `preview-features.json` entry `perch` gates every route, sidebar entry and the
inbox remap through the existing `useFeatureEnabled` / `FeatureGate` machinery. With it off,
Ambush is unchanged. It flips on by default at The hold's exit.

**Routes.** The eleven of `../APPENDIX-NORMATIVE.md` §1 minus `/settings` (already real), added
beside the existing route manifest in `workspace/desktop/src/app/routes.ts`; `PerchView` joins
the view union instead of replacing it (W3-5). The Watch is Home's inbox with the four queues
remapped (`../04` §2.1) when the feature is on.

**The seam.** `MessageRow.tsx` (999 gate-lines) is split first; `MessageBody.tsx` gains an
eleven-line seam that calls `parseSwarmMarker` (line 0 must be the whole marker; the signer must
be admitted) and dispatches to `swarmCardRegistry` — a `satisfies Record<Marker, Presenter>`
map — or falls through to markdown untouched. The seam is the only edit to the message path.

**State.** React Query keys put the answer's owner first (`relay | daemon | local`), with
`PERCH_FRESHNESS` declaring stale-time, polling and reconnect behaviour per key; ephemerals go
to `perchEphemeralStore` read via `useSyncExternalStore` with content-equality merge. Seven
REQs, no more, through the existing `relayClient.subscribeLive`. Every module-level singleton is
a named entry in a typed `RESETTERS` registry that `resetCommunityState` iterates (INV-23).

**Daemon access.** Thirteen Tauri commands in three new files (`perch_reads.rs`,
`perch_writes.rs`, `perch_verdict.rs`); route strings are Rust constants so INV-01 is
enumerable; the bearer never crosses IPC. `perch_record_verdict` is the sole producer of a
governance marker and builds the card from daemon-fetched hold state, never from
renderer-supplied JSON. `perch_sign_gate(kind, &content)` refuses `kind:46010` and any `kind:9`
whose line 0 matches `^<!-- swarm:[a-z]+:v\d+ -->$`, and is called on the first line of every
`#[tauri::command]` that reaches `state.signing_keys()` with a `content` parameter; an
inventory test asserts the enumeration (ADR 0014 C1, W3-2).

**Keys and tokens.** The key map of `../APPENDIX-NORMATIVE.md` §2 (`A` banned; `G` arms, `Enter`
records after a 1500 ms blast-radius dwell). Perch components read only `--perch-*` tokens
(registry R-4), layered over Quiet, whose one saturated `index` value already means "an
irreversible action not yet decided" — the grant control is that value, with Night Bridge's
hinged guard (`../build/art/DECISION.md`).

**Agents.** The ACP harness already subscribes to `kind:9` in channels it is a member of, so
an Ambush persona added to a lane sees finding cards from First card onward. Agents read cards;
they never receive a `p` tag from the bridge and never hold a verdict key (`../01` §4).

---

## 8. Relay changes

Exactly what wave 2 specified, re-landed on `workspace/crates/…` (W3-7): the `46010` admission
and channel-scoping hunks with their seven unit tests and E2E binary; the `26006` constant and
`P_GATED_KINDS` entry with its tests; the `justfile` filter widening so `handlers::ingest::tests`
actually runs. Plus one client-side constant: `CHANNEL_REPAIR_KINDS` in the Tauri process grows
by `46010`, `40100` and `39005` so perch events get the lossless reconnect backfill
(`../build/14` §5.6). No migration, no schema change, no new HTTP endpoint.

---

## 9. Hardening, in place of the deletion programme (D3)

| # | Item | Invariant | Milestone |
|---|---|---|---|
| H1 | Delete animated-avatar capture and its remote script host; pin `security.csp` as a literal string with no bare `https:`/`wss:` in `connect-src` and no remote `script-src` | INV-30 | Ground |
| H2 | `perch_sign_gate` at every signing boundary, with the inventory test | INV-29 | Ground |
| H3 | `resetCommunityState` → typed exhaustive registry | INV-23 | Ground |
| H4 | `tools/check-perch-write-allowlist.sh`: the console tree's daemon-bound non-GETs are exactly five | INV-01 | First card |
| H5 | Admitted-issuer gate on every marker parse and every `26xxx` frame | INV-15 | First card |
| H6 | The six `shared/ui` components that render adversary-controlled remote content (link previews, attachments) are not mounted inside a perch surface; card bodies are `AdversaryText` end to end | INV-14 | First card |
| H7 | Fix the four panic sites in `workspace/crates/ambush-ws-client/src/connection.rs` in place and bring that crate under `tools/check-runtime-panic-contract.sh` | ADR 0015 C6 as amended (W3-6) | Ground |
| H8 | `tools/check-copy-banned-terms.sh` + the `.mjs` half over perch roots, with `Perch` added to the ban list | INV-31, W3-8 | Ground |

Everything else the deletion programme removed stays.

---

## 10. Failure modes and what the screen says

Every failure mode has a rendered state; none is a toast. The full table is
`../build/11-BRIDGE-CRATE.md` §13 (F1–F21) and `../07-REALTIME-AND-DATA.md` §5.6; the classes:

| Failure | Rendered as |
|---|---|
| Bridge lagged past the broadcast buffer, or spool evicted | a full-width **gap row** above queue 1 naming the issuer and the missing `seq` range; healed only from the daemon |
| Relay down | the last-known state with a staleness clock on the governance strip; leg 1 queues in the console's spool, leg 2 still posts |
| Daemon unreachable | verdict controls disabled with the reason; a leg-1 card already published renders **recorded, not yet acknowledged** |
| Relay row with no daemon record | `UNRECONCILED`, destructive register, excluded from export (W3-18) |
| Two consoles decide one hold | the loser receives `409`, re-reads the hold, publishes a `superseded` card; the loser's first card renders as an intent that did not execute (ADR 0014 C4) |
| Daemon refuses after a grant | `refused_late`, an outcome naming the rule, no retry (INV-28) |
| Granted containment with no lease store configured | a typed refusal on the decide route; `/leases` renders "no containment lease store configured" |
| Unadmitted signer publishes a card or frame | counted, dropped, rendered as prose at most; the count is visible (INV-15) |
| Operator not `p`-tagged (B0 unset) | the bridge refuses to publish any `46010` and logs at error; the queue header says why |
| Hold expired undecided | `hold_expired`, no receipt, no lease; handoff blocked while `expired_undecided > 0` (INV-18, INV-19) |

---

## 11. Testing

| Layer | What | Where |
|---|---|---|
| Engine unit | `HeldActionStore` state machine, `HoldId::parse`, stream classifier exhaustiveness, spool round-trip and CRC, ephemeral builders reject a `RuntimeEvent` by type, `mint_incident` field contract | `crates/swarm-perch-*/`, `crates/swarm-ingest-runtime/src/ingest/perch_ops/` |
| Engine integration | the walking skeleton's daemon half: ingest a scenario, assert a `finding` card leaves the bridge; promote, assert `CasePromoted`; feedback, assert the measurement has a real `strategy_id` and `host_id` (ADR 0018 verification) | `crates/swarm-runtime-http/tests/` |
| Relay E2E | `e2e_workflow_approval.rs` (six tests incl. the positive-control fan-out and the needs-action INNER JOIN) and `e2e_operator_alarm_pgate.rs` (eight tests) | `workspace/crates/ambush-test-client/tests/` |
| Wire parity | 311 declared fields present on both the Rust and zod sides; golden vectors reproduce their pinned hash | `tools/check-perch-wire-parity.sh` |
| Desktop unit | marker parser (whole-line, admitted-only), registry exactly seven entries, keymap registry, resetter registry, freshness table completeness | colocated `*.test.mjs`, Node's runner |
| Desktop E2E, mock | the five Playwright specs in `../build/skeleton/tests/playwright/` (verdict pane, marker admission, provenance, queue lifecycle, containment) against a delegated perch fixture module in `e2eBridge.ts` | `workspace/desktop/tests/e2e/perch-*.spec.ts` |
| Desktop E2E, relay-backed | the walking-skeleton script end to end: real daemon, real relay, real card, `E` then `D`, the tuning report moves | `docs/PERCH-DEV.md` script, run by hand at each milestone exit |
| Invariants | the 36 of `../build/16-INVARIANT-TESTS.md`, each landed with its subject | across the above |
| Gates | `check-perch-write-allowlist`, `check-perch-wire-parity`, `check-copy-banned-terms` (both halves), `check-perch-grant-affordance`, `check-perch-adversary-strings`, `check-route-tree`, plus the existing engine layering and panic-contract gates and the workspace's file-size and px-text gates | root `tools/`, `workspace/desktop/scripts/` |

Rule: a gate lands with its first subject, never ahead of it (three of the perch gates exit 1 on
a tree with no perch source, which is correct).

---

## 12. Development and deployment

- **Dev stack.** `docker-compose.yml` gains `relay`, `postgres` and `redis` beside
  `swarm-detect`; the relay auto-applies its migrations on start. A `scripts/provision-perch.sh`
  creates the twelve lane channels, the bridge identities' relay memberships and the operator's,
  and writes the lane-channel ids the demo script reads.
- **Dev ruleset.** `rulesets/perch-dev.yaml` with a debug-signed sidecar (a release daemon
  refuses it, which is correct). First card can run on the shipped detect-only profile with
  `operator_surface.enabled: true`; The hold needs the live-response profile (D4).
- **Laptop demo.** The desktop's managed-agent supervisor already ships external binaries and
  reaps process groups, so a `swarm_detect` sidecar under the same discipline is a small
  Operator-complete task, not an architecture change. Out of scope until then.
- **Packaging.** The Helm chart gains the relay trio in Operator-complete; not before.

---

## 13. What changed from waves 1 and 2, in one place

Naming (`swarm:` markers, `perch` prefix, no rendered "Perch"); one repository with the
workspace under `workspace/`; the whole workspace stays and the console is a gated feature area;
the deletion programme becomes the eight-item hardening list; the ws-client is a path dependency
fixed in place rather than vendored; the relay patches are re-landed rather than carried; the
three redirect stubs are gone; kill criteria K1, K1b and K2 are retired; and the ten integrator
rulings W3-13 … W3-22 close wave 2's internal contradictions. Everything else stands.

---

## 14. Open questions the plans assume an answer to

Listed with their defaults in `00-DECISIONS.md` §3. The two that bear on this document: D3
(confirm the whole workspace stays) and D4 (confirm detect-only for First card).
