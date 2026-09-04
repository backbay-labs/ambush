# 00 — The decisions of 2026-09-02, and the amendments they force

**Status: normative for wave 3.** Where this file disagrees with `../00-BRIEF.md`,
`../APPENDIX-NORMATIVE.md` or `../build/00-REGISTRY.md`, this file wins. Everything it does
not mention stands exactly as those documents ratified it. A row marked **INTEGRATOR RULING**
was decided by the integration pass because two wave-2 artifacts disagreed and no producer had
standing; every other decision was taken by the project owner on 2026-09-02.

Written against this repository at `a5f0bc43` (`main`) and the chat repository at
`727461dc4` (`rebrand/ambush`, five commits over `eed74bde2`, the pin every wave-1 and wave-2
citation uses).

---

## 0. What the plan set did not anticipate

Between 2026-08-30 and 2026-09-02 the chat application was renamed **Buzz → Ambush in place**
on the branch `rebrand/ambush` (never pushed): crates `ambush-*`, bundle identifier
`com.backbay.ambush.app`, deep-link scheme `ambush://`, environment `AMBUSH_*`, CSS variables
`--ambush-*`, the wave marker `<!-- ambush:wave:v1 -->`, themes `ambush-day` / `ambush-night`,
and the Quiet tokens `../build/art/DECISION.md` chose. Five consequences, each verified on
2026-09-02:

1. **The plan's names are inverted.** Wave 1 and 2 call the engine "Ambush" and the chat app
   "Buzz". The chat app is now Ambush too.
2. **The marker namespace collides.** The plan's `ambush:<slug>:v1` markers now share a
   namespace with the chat app's own `ambush:wave:v1`, and ADR 0014 C1's sign-gate regex would
   refuse every wave message the desktop sends.
3. **Both relay patches fail `git apply --check`** (crate paths, plus `ci.yml` and `justfile`
   context drift).
4. **The rebrand did the re-skin and none of the groundwork.** Huddle, animated avatars with
   their remote `script-src` host, the accent picker and the burst providers remain; the CSP is
   unpinned; `AppShell.tsx` / `MessageRow.tsx` / `HomeView.tsx` measure 998 / 999 / 994 gate-lines.
5. **Both repositories claim `github.com/backbay-labs/ambush`.** This repository actually lives
   there; the chat repository's remote is still `block/buzz`.

Nothing on the engine side changed after 2026-08-14: no hold store, no bridge crate, no
`nostr_pubkey` on `OperatorPrincipalConfig`, eleven `RuntimeEvent` variants.

---

## 1. Decisions

### D1 — Naming: `swarm:` markers, `perch` prefix. **DECIDED 2026-09-02.**

- Every engine-authored card marker is `<!-- swarm:<slug>:v1 -->`. The seven slugs are
  unchanged: `finding`, `escalation`, `hold`, `verdict`, `receipt`, `lease`, `rollback`.
- The fenced-JSON info string becomes `swarm:<slug>:v1`. The fact schema id becomes
  `swarm.perch.<card>.v1`. The envelope schema `swarm.spine.envelope.v1` is unchanged.
- The sign gate (ADR 0014 C1, INV-29) refuses `kind:46010` and any `kind:9` whose line 0
  matches `^<!-- swarm:[a-z]+:v\d+ -->$`. The chat app's `ambush:wave:v1` and
  `ambush:config-nudge` markers fall outside it by construction; there is no exception list.
- The feature area keeps **`perch`** as its internal codename and file prefix:
  `workspace/desktop/src/features/perch*/`, Tauri commands `perch_*`, `shared/api/perch*.ts`,
  `--perch-*` tokens, `perch-*` testids, `tools/check-perch-*.sh`, crates `swarm-perch-bridge`
  and `swarm-perch-wire`, daemon modules `perch_ops.rs` and `http/perch.rs`.
- **"Perch" never appears in a rendered string.** The product is Ambush. `Perch` joins the
  copy ban list (`../build/skeleton/tools/copy-ban-list.tsv`) as a rendered word, alongside
  `Swarm Team Six` and `clowder`. The prototypes' `┌ Perch ─` title bars are stale by this rule.

### D2 — One repository, two Cargo workspaces. **DECIDED 2026-09-02.**

- The chat repository's `rebrand/ambush` history is rewritten with
  `git filter-repo --to-subdirectory-filter workspace` and merged into this repository with
  `--allow-unrelated-histories`, **full history preserved**. This repository keeps the GitHub
  name `backbay-labs/ambush`. The `block/buzz` remote is left behind: upstream tracking ends,
  security fixes are cherry-picked by hand, and kill criterion K2 is retired as *chosen*.
- **Path prefix convention for wave 3.** An unprefixed path is this repository's root (the
  engine). `workspace/` is the former chat repository. Read wave-1 and wave-2's `BUZZ ` prefix
  as `workspace/` and their `AMB` / `AMBUSH ` prefix as root. Every wave-1/2 line number is
  stale by construction; `../build/refactor/line-ledger.mjs` re-derives the split anchors, and
  any other line cite is re-measured before it is trusted.
- Two Cargo workspaces. Root `Cargo.toml` (engine, twenty members) gains
  `exclude = ["workspace"]`. `workspace/Cargo.toml` is the chat workspace and already excludes
  `desktop/src-tauri`. Cross-workspace path dependencies are allowed in exactly these edges:
  engine crates may depend on `workspace/crates/ambush-ws-client` and
  `workspace/crates/ambush-sdk`; workspace crates (including `desktop/src-tauri`) may depend on
  `crates/swarm-perch-wire` **only**, because it is a transport-neutral wire crate with no
  dependency on any other `swarm-*` crate (W3-27). No workspace crate may link any other engine
  crate (ADR 0011 clause 4 and ADR 0014 stand: the Tauri process never links `swarm-runtime`).
- Toolchains coexist by directory: root `rust-toolchain.toml` (1.97.1, edition 2024) governs
  the engine; `workspace/rust-toolchain.toml` (1.95.0, edition 2021) governs the workspace;
  rustup resolves the nearest file. Hermit stays under `workspace/bin/` and is activated from
  `workspace/`.
- Gates. Engine gates enumerate `crates/*/src` and `tools/`; they do not see `workspace/`.
  Workspace gates run from `workspace/justfile` (`just ci`, `just check`, the file-size
  ratchet, the px-text guard). New perch gates are root `tools/check-perch-*.sh`, wired into the
  engine CI per `tools/check-gates-wired.sh`, and may read `workspace/` paths.
- CI. The chat `ci.yml` becomes root `.github/workflows/workspace-ci.yml` with a
  workflow-level `defaults.run.working-directory: workspace`, every path-filter glob, cache
  path, `hashFiles` pattern and Rust-cache `workspaces` input prefixed, and the Hermit action
  pointed at `workspace/`. **Neither workflow uses a top-level `paths:` filter**: a workflow
  skipped by path filtering leaves its required checks pending forever, whereas a job skipped by
  the existing `changes` job's `if:` reports as skipped and satisfies branch protection. So the
  engine `ci.yml` keeps its triggers unchanged for now, and giving it a `changes` job of its own
  is a Ground task once branch protection on the merged repository is decided. The other
  nineteen chat workflows stay **inert** under `workspace/.github/workflows/` (GitHub reads only
  the root directory) until each is re-rooted on demand.
- Hooks. lefthook 2.1.3 honours `LEFTHOOK_CONFIG`. `workspace/justfile`'s `hooks` recipe exports
  it and installs into the repository's `.git/hooks`; the generated dispatchers source
  `workspace/bin/.lefthookrc` by its repo-root-relative path, which prepends `workspace/bin` to
  `PATH` and exports `LEFTHOOK_CONFIG`; every lane in `workspace/lefthook.yml` declares
  `root: workspace/`, which makes lefthook run it from that directory, **and every glob and
  exclude pattern carries the `workspace/` prefix**, because patterns are matched against
  repository-relative paths regardless of `root` (measured on 2026-09-02: `crates/**` matched
  nothing, `workspace/crates/**` matched and the lane reformatted a deliberately mangled file
  from `workspace/`). Verified by `lefthook validate`, `just hooks`, a real commit with the
  sign-off lane, and the staged-file experiment above.
- Commit policy, **proposed default pending confirmation**: `git commit -s` repository-wide
  (the workspace's DCO habit) with Conventional Commits subject lines (the engine's habit).
- Attribution: `workspace/LICENSE` (Apache-2.0, block/buzz) stays in place; root `NOTICE` gains
  one line naming the workspace's origin at `block/buzz@eed74bde2`.

### D3 — The whole workspace stays; the console is a feature area. **ACCEPTED BY PROCEEDING — confirm on spec review.**

- ADR 0011's "re-skinned and cut by roughly a third" clause, `../09-ROADMAP-AND-RISKS.md` §2.3's
  deletion programme (0.3a and 0.3b), and tasks P0-01 … P0-09 are **withdrawn**. Huddle,
  projects, forum, agents process management, mobile, admin-web, personas, onboarding, the
  burst providers and the accent picker all stay.
- Three deletions survive because they are security prerequisites, not fork hygiene: **P0-10**
  (animated avatars: the only reason the CSP carries `https://cdn.jsdelivr.net/npm/@mediapipe/`
  and a `storage.googleapis.com` model fetch), **P0-14** (`resetCommunityState` as a typed
  exhaustive registry, INV-23), and **P0-23** (the CSP pin and the sign gate, INV-29 / INV-30).
- The "fourteen surfaces, closed" rule (ADR 0011 clause 1) applies **inside the perch feature
  area only**. The area ships behind a `preview-features.json` entry named `perch` until The
  hold milestone exits, and Ambush's existing surfaces are untouched by it.
- The Watch is the Home inbox with remapped queues (`../04-SURFACES-AND-UX.md` §2.1) **when
  the `perch` feature is enabled**; with it disabled, Home is the ordinary inbox. The perch
  routes `/cases/$caseId`, `/lanes/$laneId`, `/leases`, `/policy`, `/watch-floor`, `/ledger`,
  `/tuning`, `/handoff` and `/gaps` are added beside the existing routes. The three redirect
  stubs in `../build/14-CLIENT-ARCHITECTURE.md` §3 (`/channels/$id → /cases`, `/agents` and
  `/pulse → /watch-floor`) are withdrawn: those routes keep their surfaces, and a case channel
  opens at `/cases/$caseId` only when navigated as a case.
- Kill criteria: K1 and K1b are moot; K2 is retired as chosen; **K3 stands** (a third stored
  kind within two quarters means the marker bet failed); the soft product signal stands (fewer
  than five `FalsePositiveMeasurement` records per week in live use means operators do not want
  a queue).

### D4 — Runtime mode per milestone. **RECOMMENDED DEFAULT — confirm on spec review.**

- **First card** runs against `detect_only`: findings, the feedback route, incident minting and
  the reviewed-findings read all work there, and it avoids `require_durable_live_response`,
  adapter secrets and the startup attestation.
- **The hold** requires `live_response`, `runtime.containment.lease_store_path` set, a durable
  substrate, and the debug-signed `rulesets-dev/perch-dev.yaml` sidecar (P0-22). Nothing in First
  card may imply a hold exists (`../00-BRIEF.md` §10 Q1's rider, `../build/21-ADRS.md` Q1).

---

## 2. The wave-3 amendment table

Cite the row; do not restate it.

| # | Target | Was | Now |
|---|---|---|---|
| **W3-1** | `APPENDIX-NORMATIVE.md` §3; `13-WIRE-SCHEMAS.md`; `build/schemas/*`; `build/skeleton/perch-wire/**`; `build/fixtures/**`; the five prototypes | `ambush:<slug>:v1`, fact schema `ambush.perch.<card>.v1` | `swarm:<slug>:v1`, fact schema `swarm.perch.<card>.v1`. Golden vectors, `GOLDEN.sha256` and `fixtures/SHA256SUMS` are regenerated by the Ground task that applies the rename |
| **W3-2** | ADR 0014 C1; `16-INVARIANT-TESTS.md` INV-29 | `^<!-- ambush:[a-z]+:v\d+ -->$` | `^<!-- swarm:[a-z]+:v\d+ -->$` |
| **W3-3** | every `BUZZ ` path cite | `block/buzz@eed74bde2` | `workspace/…` in this repository at the merge commit; line numbers re-measured |
| **W3-4** | ADR 0011 clause 1 (fourteen closed); `09` §2.3; P0-01 … P0-09 | fork, rebrand, delete a third | withdrawn (D3); P0-10, P0-14, P0-23 kept as hardening |
| **W3-5** | `14-CLIENT-ARCHITECTURE.md` §3 redirect stubs | three redirects | withdrawn (D3) |
| **W3-6** | ADR 0015 C6 (vendor `buzz-ws-client`) | vendor, rewrite four panic sites | path dependency on `workspace/crates/ambush-ws-client`; the four panic sites at `connection.rs` are fixed **in place**; `tools/check-runtime-panic-contract.sh` gains that crate's `src` in its enumeration |
| **W3-7** | `10-RELAY-FORK.md`; `build/patches/*`; P0-16 | patch files against `buzz-*` | regenerated against `workspace/crates/ambush-relay` and `workspace/crates/ambush-core`, landed directly on the branch with their tests; offering them upstream to `block/buzz` is optional courtesy, not a dependency |
| **W3-8** | `copy-ban-list.tsv` | — | `Perch` banned as a rendered word (D1) |
| **W3-9** | `00-BRIEF.md` §9 (delete mobile); `09` §2.3 row 4 | mobile and admin-web deleted | both stay (D3); cards degrade in mobile via the human line (ADR 0013); no mobile perch surface is in scope |
| **W3-10** | `09` §8 K1, K1b, K2 | kill criteria | retired (D3, D2); K3 and the soft signal stand |
| **W3-11** | `09` §2.4, `20` §2.3 sizing | 95 / 105 engineer-weeks | re-sized per milestone in `20-ROADMAP.md`: Ground loses the ~14 ew deletion programme and gains the migration and the rename |
| **W3-12** | `02-ARCHITECTURE-INTEGRATION.md` §1–§2 (three repos, `backbay-labs/perch`, NOTICE, `docs/FORK.md`) | three repositories | one repository (D2); no fork NOTICE; attribution per D2's last bullet |
| **W3-13** · INTEGRATOR RULING | ADR 0015 C1 ("depends on `swarm-ingest-runtime`") vs `11-BRIDGE-CRATE.md` §1.3 ("deliberately NOT declared") | conflict | **`11` wins.** The bridge takes a bare `broadcast::Receiver<RuntimeEvent>` in `BridgeBuildInput` and does not depend on `swarm-ingest-runtime`. ADR 0015 C1 is amended to "depends on `swarm-core`, `swarm-runtime`, `swarm-response` and its egress" |
| **W3-14** · INTEGRATOR RULING | `12-BACKEND-BILL-API.md` §9.5 (one trigger, client-supplied `case_id`) vs ADR 0018 rev 2 / `11` §9.1 (two triggers, daemon-minted id) | conflict | **Two triggers via B1d; the daemon mints `case_id`.** `POST /v1/operator/incidents` returns `case_id`; `RuntimeEvent::CasePromoted { hunt_id, case_id, clause }` carries it; the bridge creates the channel with that id. The console supplies no id |
| **W3-15** · INTEGRATOR RULING | `hold_id`: `12` A17 (`hold_` + lowercase v4 UUID) vs `11` §8.6 parser (bare UUID only) | conflict | R-3's pattern `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$` is the contract; `12`'s 41-character format satisfies it; `11`'s `HoldId::parse` and ADR 0017 C2 are rewritten to the pattern |
| **W3-16** · INTEGRATOR RULING | verdict signing preimage: `13` §11.1 (three members) vs `12` D13 (four) | conflict | **Four members**, RFC 8785 canonical `{decided_at_ms, decision, hold_id, rationale_sha256}` (`12` D13); `13`'s PA-3 is applied to `card-swarm-verdict-v1.schema.json` and its goldens in the rename task |
| **W3-17** · INTEGRATOR RULING | learning the winner after a `409`: `13` §3.5 (from the body) vs `12` C12 (re-read) | conflict | **Re-read** `GET /v1/response/holds/{id}` (`12` C12, ADR 0014 C4); `ErrorResponse` stays `{error, message}` |
| **W3-18** · INTEGRATOR RULING | INV-35 wording: ADR 0012 clause 3 (`FORGED`) vs `16` §5.35 (`UNRECONCILED`) | conflict | **`UNRECONCILED`**; the store may simply be non-durable |
| **W3-19** · INTEGRATOR RULING | bridge write allowlist: `10` INV-RF1 (nine kinds) vs `11` §9.1 (plus 9007 and 9000) | conflict | **Eleven kinds**: 46010; kind:9 with the five bridge-authored markers; 26000–26006; 9007 and 9000 for case provisioning only. The operator key publishes exactly one kind: kind:9 `swarm:verdict:v1` |
| **W3-20** · INTEGRATOR RULING | `RECEIPT REQUIRED`: ADR 0014 C3 (enforced once B2g lands) vs `12` C15 (never on this roadmap) | conflict | **`12` C15**: never rendered as an enforced fact on this roadmap; PA-2 applied |
| **W3-21** · INTEGRATOR RULING | card body order: ADR 0013 (marker, JSON, prose) vs `13` §1.2 (marker, human line, fenced JSON) | conflict | **`13`'s order**; the schemas and goldens already follow it, and a human line on line 1 degrades better in a search snippet |
| **W3-22** · INTEGRATOR RULING | copy gate `approve`: `11` C-A4 (identifier exemption) vs `12` §5.7 (none) | conflict | **No identifier exemption**, because RF-A5 already scopes the gate to rendered literals in perch roots and an identifier is not a rendered literal |
| **W3-23** | `08` INV-30; `20` P0-23; `01-DESIGN.md` §9 H1 | the pinned CSP carries no bare `https:` / `http:` / `wss:` / `ws:` in `connect-src` and no remote `script-src` host | **narrowed under D3.** The CSP becomes a pinned literal asserted by a test, and the remote `script-src` host (`https://cdn.jsdelivr.net/npm/@mediapipe/`, animated avatars) is removed; `connect-src` keeps `https: http: wss: ws:` because the whole workspace stays and its webview fetches invites, join policy and moderation over HTTPS from `shared/api/invites.ts` and `shared/api/moderation.ts`. Narrowing `connect-src` to named relay origins is a follow-up that needs a Tauri-side proxy for those calls; until then the pin makes any widening a deliberate, reviewed edit |
| **W3-24** | `01-DESIGN.md` §9 H8; `20` P0-25 | the copy gate lands in Ground | **lands in First card**, with its first real subject: the gate refuses to pass over a tree with no Perch source (`../build/README.md`, "three of the four Perch gates exit 1 on a tree with no Perch source"). The twelve `docs/assets` SVG rewrites are engine README art deferred to Operator-complete, so a reviewed `tools/copy-scope.tsv` marks that asset scope `deferred` and the gate prints a conspicuous partial-coverage warning; Operator-complete flips it to `required` in the same commit that clears every asset violation. A missing, malformed or silently skipped scope row is a hard failure. |
| **W3-25** · INTEGRATOR RULING | hold store placement: `12` §1 / `20` (`crates/swarm-ingest-runtime/src/ingest/held_actions.rs`) vs `16`'s skeleton test (`swarm-runtime`) | conflict | **`crates/swarm-runtime/src/held_action.rs`.** The store is composition-root state like the containment lease map; the bridge takes a bare receiver (W3-13) and an `Arc<dyn HeldActionStore>` for exactly two write-backs, `mark_case_channel` and `mark_notified`, which it could not perform if the store lived in the ingest crate it does not link. Both run inside process A, so the sole-writer rule (ADR 0012) is untouched. `13-PLAN-THE-HOLD.md` Tasks 4–6 own the code |
| **W3-26** | `12` §4.7 (no `ResponseHeld` on `granted → executed / failed`) vs `13`'s hold-card schema (one terminal card per hold) | conflict | **the decide path publishes a `RuntimeEvent::ResponseHeld` on every terminal transition**, so the bridge can publish the terminal `swarm:hold:v1` card; `HeldActionView` gains `case_channel`, `notice_event_id` and `card_event_id` so leg 1 can be built from daemon state (`13-PLAN-THE-HOLD.md` Task 13, Task 21) |
| **W3-27** · INTEGRATOR RULING | D2 says `swarm-perch-wire` has no engine dependencies, but the copied skeleton and the first First-card draft declared `swarm-core`, `swarm-crypto`, `swarm-policy`, `swarm-response`, `swarm-runtime`, `swarm-spine` and `swarm-whisker` | conflict | **D2 wins.** `swarm-perch-wire` owns transport-neutral DTOs, marker grammar, tags, RFC 8785 canonical bytes, hashes and golden vectors and depends on no package whose name starts `swarm-`. Engine-domain → wire conversion and `RuntimeEvent` narrowing live in `swarm-perch-bridge`; bridge signing uses `swarm-crypto`; the Tauri process verifies the wire crate's canonical bytes with its own `ed25519-dalek`. A graph assertion plus cross-implementation canonical-byte vectors enforce the boundary. |
| **W3-28** · INTEGRATOR RULING | The hold draft put the future deposits path in `PERCH_ROUTER_PATHS` before it mounted a handler and counted seven paths at The hold exit | conflict | **the path inventory contains mounted routes only.** First card exits with three paths. The hold Task 10 adds two reads (five), Task 13 adds decide (six), and Operator-complete Task 4 adds deposits (seven). The source/inventory test asserts the exact count after each change; no future path is predeclared. |
| **W3-29** · INTEGRATOR RULING | The generated plans copied `coalesce.rs` and `leases.rs` with `todo!()` bodies, never assigned real producers for 26000–26005, and later referred to escalation and receipt card builders no task created | gap | **no stub module lands.** First card omits both future files. Operator-complete Task 8 creates `leases.rs` and the response-receipt producer it needs; Task 11 creates the durable escalation producer and its edge coalescer; Task 19 completes the global 26000–26005 reducers/publishers and the 26000 `shed` schema field before Watchfloor consumes them. Each producer has a real-relay assertion; mock frames alone cannot satisfy milestone exit. |
| **W3-30** · GROUND RULING | `11-PLAN-GROUND.md` Task 9 and its File Structure row; `12-PLAN-FIRST-CARD.md` Task 14; `13-PLAN-THE-HOLD.md` and `14-PLAN-OPERATOR-COMPLETE.md` wherever they cite the path; `01-DESIGN.md` §2 tree and its dev-ruleset bullet; `build/20-TASK-BREAKDOWN.md` P0-22 | the dev profile lands at `rulesets/perch-dev.yaml` (+ `.sig.json`) | **`rulesets-dev/perch-dev.yaml`** (+ `.sig.json`), beside the attested directory, never inside it. `rulesets/` is enumerated by the signed startup attestation: `crates/swarm-runtime/src/startup_attestation.rs` walks every `*.yaml`/`*.yml` under it and refuses any file `rulesets/attestation.json` does not cover, and that manifest is signed with the repo-owned key, which is not in the repository. A `rulesets/perch-dev.yaml` therefore fails `repo_ruleset_attestation_matches_checked_in_files` (CI `test`) and flips every daemon's ruleset attestation to failed, which blocks `live_response` outright, The hold's own dev profile included. The sibling directory keeps the attestation verifying its four files (a debug `/readyz` on the profile reports exactly that); the runtime state the daemon writes beside a config outside `rulesets/` (`rulesets-dev/data/agent-identity/`, `rulesets-dev/governance-partition-state.json`, agent keys) is git-ignored. `sign_dev_ruleset`, the debug sidecar and the release refusal are unchanged. Taken by the Ground engine executor and confirmed by the integrator on 2026-09-03; the profile landed in `9b5234eaf` and this row plus the plan rewrites in `a441929bc` (the earlier `11ae8d583` was a pre-rebase id and is not an ancestor of this branch). The integration plans' literal citations were rewritten under this row; the wave-2 `build/` documents stand as ratified and are governed by it |
| **W3-31** · INTEGRATOR RULING | `12-PLAN-FIRST-CARD.md` Task 10 (`unwrap_or(50).clamp(1, 1_000)`) vs `build/openapi/perch-operator-v1.yaml` `ReviewLimit` (values above 500 are capped) | conflict | **The published OpenAPI contract wins**: B3r's `limit` defaults to 200 and is capped at 500 (`effective_limit` in `http/perch/reviewed.rs`); the plan's handler line is superseded, the OpenAPI is unchanged. |
| **W3-32** · INTEGRATOR RULING | `11-PLAN-GROUND.md` Task 3 Step 7 extends `CHANNEL_REPAIR_KINDS` with 46010, 40100 **and 39005** | conflict with the relay | **39005 is excluded.** `ambush_core::kind::is_relay_only_kind(39005)` is true: the relay synthesizes thread summaries at query time and never stores them, and the repair filter sets neither `top_level` nor `include_summaries`, so repairing that kind could never return a row. Adding it to `CHANNEL_EVENT_KINDS` to keep the coupling test green was worse than a no-op: `relayClientSession.ts` states directly above its own filter that 39005 must ride only the window-store subscription and never reach unread tracking or cache merges, and every thread reply then appended an uncapped, never-rendered entry to the channel message cache. 40100 and 46010 stay in both sets; summaries are recovered by re-issuing the window request. |

**Rows deliberately not filed.** R-1 (26006 global, `P_GATED_KINDS` is the whole fence), R-2
(`distinct_sources` counts strategy-scoped ids), R-3, R-4 (`--perch-*`), R-5, R-6, R-7 (⌘J) all
stand unchanged. T1 (the walking skeleton runs the finding path) stands and is the First card
milestone.

---

## 3. What is still open, with the default the plans assume

| Question | Default assumed by the plans | Who decides |
|---|---|---|
| Commit policy for the merged repository | `git commit -s` + Conventional Commits | project owner |
| D3 confirmation | whole workspace stays | project owner, on spec review |
| D4 confirmation | detect-only for First card, live-response dev profile for The hold | project owner, on spec review |
| Operator verdict key (Ed25519): where the daemon learns each operator's verifying key and how the console holds the secret | **(a)** a typed `verdict_public_key_hex: Option<String>` on `OperatorPrincipalConfig` beside `nostr_pubkey`, the console minting the keypair once into the OS keyring and printing the public half for the ruleset — `13-PLAN-THE-HOLD.md` Task 2 lists (b) and (c); its Tasks 13 and 21 are written against (a) | project owner, before The hold Task 13 |
| `#watch` operations channel | not built (R-1 retired it); the watch claim (`04` §2.11) is deferred to Operator-complete | — |
| Local-directory rename `standalone/swarm-team-six` → `standalone/ambush` | not done by any plan; owner's call after the merge | project owner |
| Whether to offer the relay patches upstream to `block/buzz` | optional; not a dependency | project owner |
| Whether the first deployment runs `live_response` at all | D4's dev profile answers it for demos; production is an operator question (`21-ADRS.md` Q1) | deployment owner |
| **D-FC-1** — secp256k1 key derivation for the bridge identities | **Default the plan builds under:** `DERIVATION_DOMAIN = b"swarm.perch.bridge.nostr.v1"`; `nostr_secret[slot] = SHA-256(DOMAIN ‖ 0x00 ‖ root ‖ 0x00 ‖ colony_id ‖ 0x00 ‖ slot.label())`; the 32-byte root is read once at startup from the env var named by `perch.nostr_seed_env` (default `PERCH_BRIDGE_NOSTR_SEED`, 64 hex chars), never from a file in the repo. **Options:** (a) keep the skeleton's `ambush.perch.bridge.nostr.v1` — rejected only for namespace consistency with `swarm.perch.<card>.v1` (D1); (b) a file path under `runtime.secret_dir` via the `@secret:file-name` adapter — deferred, same code path once the adapter is wired; (c) per-agent keys minted by `FileAgentKeyStore` and converted — rejected: those are Ed25519 and the relay needs secp256k1. **Consequence:** changing the string after first provisioning rotates every bridge key and invalidates every relay membership; it is versioned (`.v1`) and never edited in place. **Dependents:** Task 7 (identity), Task 14 (`.env.perch`). | project owner, on spec review; the default ships unless overridden before Task 7 lands |
| **D-FC-2** — where the console learns the admitted-issuer set (INV-15) | **Default the plan builds under:** the daemon serves `GET /metrics/perch/identities` → `{colony_id, identities: [{slot, pubkey}]}` (public keys only, unauthenticated, on the same listener as `/metrics/perch`); the Tauri command `perch_admitted_issuers` reads it and the renderer caches it under the `daemon` query source with a five-minute stale time. The skeleton's `perchKeys.admittedIssuers` moves from the `relay` source to `daemon`. **Options:** (a) each bridge identity publishes a `kind:0` profile carrying a `swarm-agent` tag and the console trusts the relay's copy — rejected: the relay is not the record and a forged profile is one `MessagesWrite` away; (b) an operator pastes the provisioning report into Settings — kept for air-gapped consoles, Operator-complete; (c) a bearer-authenticated `/v1/operator/perch/identities` — rejected for now: public keys are public, and the metrics listener is reachable from the console's daemon URL already. **Dependents:** Tasks 17, 19. | project owner |
| **D-FC-3** — the finding-verdict card and the verdict card's `e` tag | The wave-2 `card-swarm-verdict-v1` schema is hold-only: `locator {hold_id, case_channel, hold_card_id}`, `decision {decision: grant|refuse, hold_id, …}`, and the W3-16 preimage names `hold_id`. First card records a verdict on a FINDING (`confirm|dismiss|investigate`, B3), which that shape cannot carry, and the registry is closed at seven markers (an eighth is not an option). Two documents also disagree on the `e` tag: `13` §5.1 and `verdictCardTags` emit `["e", holdCardId]`; `14` §7.3.1 publishes with `h` and no `e`. **Default the plan builds under:** (1) `locator` and `decision` gain a `subject` discriminator: `subject: "hold"` keeps every existing field; `subject: "finding"` carries `locator {finding_id, finding_card_id (hex64), case_channel, incident_id}` and `decision {decision: confirm|dismiss|investigate, finding_id, decided_at_ms, operator_id, rationale}`; the Ed25519 preimage for a finding subject is the RFC 8785 form of `{decided_at_ms, decision, finding_id, rationale_sha256}` (four members, W3-16's shape with `finding_id` in `hold_id`'s place); (2) **no `e` tag on the initial verdict card** — the finding card lives in the lane channel and the verdict in the case channel, and an `e` tag to an event in another channel would make the relay's NIP-10 thread resolver mutate a lane card's `reply_count` from a case; the join is `locator.finding_card_id` in the signed body, and `verdictCardTags` in `tags.ts` drops its `["e", …]` line. A later supersession update may carry an `e` reply to its own same-channel leg-1 verdict card, as The hold Task 27 requires; it never points across channels. **Options:** a hold-only verdict and a bare kind:9 prose message for findings — rejected: the finding verdict is the milestone's whole product and must be a card the Ledger can find; an eighth marker — rejected by the closed registry. **Dependents:** Task 21. | project owner, on spec review |
| **D-FC-4** — operator bearer, daemon URL and operator id on the console | **Default the plan builds under:** debug builds seed the keyring blob at startup from `AMBUSH_PERCH_DAEMON_URL` (default `http://127.0.0.1:9090`), `AMBUSH_PERCH_DAEMON_BEARER` and `AMBUSH_PERCH_OPERATOR_ID` (default `local-operator`, the id `rulesets-dev/perch-dev.yaml`'s principal carries) when the corresponding keyring keys `perch.daemon_url`, `perch.daemon_bearer`, `perch.operator_id` are absent; a release build reads the keyring only and renders "daemon not configured" until a Settings surface (Operator-complete) stores them. The operator Ed25519 key (`perch.operator_ed25519`) is minted on first use and never leaves the process. **Options:** a Settings form now (0.5 d of UI with no design ground yet), or a deep-link `ambush://perch/configure?…` — both deferred. **Dependents:** Tasks 19, 21. | project owner |
| **D-FC-5** — who creates the twelve lane channels | **Default the plan builds under:** the bridge, idempotently, at startup (`swarm-perch-bridge/src/alarm.rs`), from the UUIDs committed in `perch.lane_channels`; the relay answers `duplicate: channel already exists` on every later start and the bridge treats that as success. `scripts/provision-perch.sh` no longer mints lanes (Ground Task 10 step 2 is amended: it prints keys, writes `.perch-dev/`, and adds relay memberships when `AMBUSH_REQUIRE_RELAY_MEMBERSHIP=true`). **Options:** (a) the script mints lanes with random ids and a local, unsigned copy of the ruleset carries them — rejected: the signed ruleset is the only config the daemon loads, and re-signing per machine multiplies sidecars; (b) extend `ambush channels create` with `--id` — a workspace CLI change for one script; kept as the fallback if the bridge must not hold `ChannelsWrite` on lanes. **Consequence:** a fresh relay database (`docker compose down -v`) recovers its lanes on the next daemon start with no operator action. **Measured 2026-09-04** against a native Postgres/Redis/relay stack: first start created twelve channels at the committed UUIDs and twenty-four memberships (alarm owner + operator member per lane); the second and third starts left the `channels` rows, their ids and their `created_at` byte-identical and added no membership row. **Dependents:** Task 13. | project owner |
