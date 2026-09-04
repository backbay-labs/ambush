# First card — exit evidence

**Milestone:** First card (`12-PLAN-FIRST-CARD.md`). **Exit commit:** `642270647` on
`codex/ambush-fc-devstack`, rebased onto the Ground head `7549b8946`.
**Tree state at exit:** clean. **Recorded:** 2026-09-04.

Every claim names the command that produced it. A row marked *not verified* is a limitation,
not a green check. Where the plan and the code disagreed, the disagreement is recorded here and
ruled in `00-DECISIONS.md`, never resolved silently.

## What the milestone claims

One real detector finding leaves `swarm_detect` in process, crosses the bridge, is stored by the
relay, renders as a `swarm:finding:v1` card in the desktop, `E` promotes it into a case the
daemon mints, and `D` records a verdict as two separate legs. That path was exercised end to end
against a live relay; the ids are in the walking-skeleton section.

## Toolchains and services

| Component | Version |
|---|---|
| Engine Rust | 1.97.1, edition 2024 |
| Workspace Rust | 1.95.0, edition 2021 |
| Node / pnpm (Hermit) | 24.15.0 / 11.4.0 |
| Postgres for live runs | Homebrew PostgreSQL 14.19 (not the compose file's `postgres:17-alpine`) |
| Redis for live runs | Homebrew Redis 8.2.1 |
| Relay under test | `cargo build -p ambush-relay` from this tree, `ws://localhost:<port>` |
| Docker | **never exercised**: the local colima VM has filesystem I/O errors |

## Task outcomes

| Task | Evidence |
|---|---|
| 1 wire crate | 76 tests (49 unit, 17 golden, 10 human lines); `cargo metadata` asserts no `swarm-*` dependency; compiles on both 1.97.1 and 1.95.0 |
| 2 TS mirror + parity gate | `golden.test.mjs` 32/32, failing first on the missing export; parity gate 322 fields across 17 schemas; biome excluded from the golden mirror so the fix lane cannot rewrite a pinned vector |
| 3–8, 13 bridge | 64 lib + 2 wire-parity tests; write-only proven by source scan (zero REQ, zero COUNT); `rg 'todo!\(|unimplemented!\('` over `src/` finds none |
| 9 daemon mount | daemon logs `perch bridge mounted`; `swarm-perch-bridge` joins `TRUST_SENSITIVE` in the layering gate |
| 10–12 operator routes | `perch_ops` 14, route tests 14, walking skeleton 1, `swarm-runtime -p swarm-ingest-runtime -- --test-threads=1` 614 |
| 14 dev stack | twelve lane channels at their committed UUIDs with 24 memberships, idempotent across four daemon starts and recreated after a full relay-database wipe |
| 15, 20 decisions | D-FC-1 … D-FC-5 recorded in `00-DECISIONS.md` §3 under the plan's defaults |
| 16 route + surface hook | `perchViews` tests; `/cases/$caseId` behind the off-by-default `perch` feature |
| 17 parser, registry, seam | parser, adversary-text and admitted-issuer suites; the seam reads no kind |
| 18 keys, subscriptions, gaps | 28 tests across six files; five resetter entries |
| 19 Tauri client + INV-01 gate | 5 routes, 5 Rust, 20 renderer; the allowlist gate exits 1 naming a sixth POST |
| 21 `perch_record_verdict` | leg 1 built from the relay's admitted card; Ed25519 over the four-member RFC 8785 preimage |
| 22 E2E | 10 perch Playwright specs |
| 23 the verbs | the two contracts below |
| 24 copy gate | 13 negative controls, each reverted, tree byte-identical after |

## The two contracts the milestone turns on

**The legs render separately.** Both mock legs are held open and each window is read in one
synchronous DOM pass that asserts which window it caught. During `recorded` the relay leg reads
`recorded on Ambush` and the daemon leg reads `sending`, with no checkmark and no
`acknowledged` anywhere. Control: making leg 2 read `acknowledged by the daemon` during
`recorded` failed with `Received: "daemonacknowledged by the daemon"`.

**A retry re-sends leg 2 only.** With the daemon down between the legs the row holds
`daemon-unreachable`; after restoring it, `perch_record_verdict` stays at one call,
`perch_finding_feedback` reaches two, and the rendered intent event id is unchanged. Control:
making the retry re-sign leg 1 failed with a record-verdict count of 2 against an expected 1.

## The card seam is pinned from both sides

`card_bearing_kinds_match_the_renderer` (Ground) parses `formatTimelineMessages.ts` and
`MessageRow.tsx` and requires the Rust `CARD_BEARING_KINDS` to equal the kinds that reach
`MessageBody`. The second-kind spec (this milestone) emits identical golden bytes on kind 9 and
kind 40002 and requires one identical outcome. **They are two halves of one contract**: the gate
refusing eight kinds on the way in means nothing if the renderer displays only one of them, and
a renderer displaying nine means nothing if the gate guards one. Narrowing either leaves the
other true but empty. Both are load-bearing: dropping a kind from the constant fails the first
with the exact set difference; keying the seam to `message.kind === 9` fails the second with 0
cards where 1 was expected.

## Defects found by this milestone's own tests

- **The unadmitted-marker counter counted the cold-start window.** The admitted set arrives from
  the daemon after the first timeline render, so three well-formed markers were counted as
  unadmitted for one forged card — a fabricated number in the surface whose job is to be
  trustworthy. `admittedIssuersKnown()` now gates both the notice and the count, and a failed
  load leaves the set *unknown* rather than refusing on an answer the console never received.
- **`select_feedback_member` silently recorded a verdict on the wrong finding.** The shared
  resolver falls back to the first incident member, so feedback naming a non-member finding was
  recorded against another one. B3 returns 404 for that case now.
- **The copy gate's own parity comparison could exit 1 with no output**, because a `grep -v`
  chain that filters everything returns 1 under `pipefail`. An expectations file holding only its
  header was indistinguishable from a crash. Found by forcing the mismatch path.

## Known limitations

- **`docker compose up` was never exercised**, on any task, because the local Docker daemon has
  filesystem I/O errors. Every compose line was replaced by a native equivalent on a *different
  substrate* (PostgreSQL 14, not the file's 17-alpine; a `cargo build` relay, not one built from
  `workspace/Dockerfile`). `docs/PERCH-DEV.md` §0 lists each unexercised path.
- **The daemon cannot run inside the compose network as documented.** The relay binds its
  community to the connection's Host header and seeds exactly one, so a containerised daemon
  reaching `relay:3000` and a desktop reaching `localhost:3000` would not share a record. Running
  the daemon on the host is the only configuration where both see the same lanes. Measured, and
  written into both `docker-compose.yml` and `docs/PERCH-DEV.md`.
- **The desktop E2E suite runs with all six preview features enabled; production ships all six
  disabled.** `preview-features.json` gives none of them `defaultEnabled`, so a fresh user has
  workflows, projects, pulse, forum, agent-managed profiles and perch all off, while the harness
  wrote `true` for every one on each `installMockBridge` call. Part of the existing suite
  therefore asserts against a configuration no fresh user has. This predates the milestone and is
  deliberate — it is how the suite reaches gated UI — but the gap between the tested default and
  the shipped default is real and unowned. This milestone changed exactly one feature: perch is
  opt-in for E2E, because unlike the other five it changes what an already-ubiquitous element
  renders rather than adding a surface.
- **The copy gate has a bare-literal blind spot**, declared on every run: 455 string literals in
  the required roots are not scanned, because markup mode extracts only attribute values, object
  field names and JSX text. The gate reports the count per root and names which unscanned strings
  would violate a ban row; the closing line never reads as a clean sweep while the count is
  nonzero. `TIER_0_BADGE` was moved into a copy module so the mandated literal is scanned.
- **`hunt_id` is derived, not carried.** B3i requires one, but neither the finding card schema nor
  the runtime event has a hunt field, so `promoteFinding` sends `swarm:finding:{finding_id}`. The
  daemon refuses only a blank value. **If a real hunt id belongs on the card, that is a wire
  change and someone must decide it.**
- **The copy gate asserts nothing about "signed" or "verified" on a card.** Those bans are
  card-scoped, which a lexical scan cannot express; the card-scoped half is a DOM assertion in the
  provenance spec. The ban list states this limit in its own header rather than letting a green
  line imply coverage.
- The smoke suite has one stable pre-existing failure (`huddle-transcription.spec.ts:763`) that
  reproduces on the base branch, plus load-sensitive specs that pass in isolation.

## Amendments this milestone recorded

W3-31 (B3r `limit` follows the published OpenAPI: default 200, cap 500), W3-32 (39005 excluded
from the repair and channel-event sets), W3-33 (a second live-response dev profile rather than
flipping the one First card was accepted on), and the correction that the bridge identity table is
one slot per admitted agent plus two fixed slots — six for the dev profile, not the three the plan
asserted.
