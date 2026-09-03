# First Card Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A real `RuntimeEvent::Finding` leaves `swarm_detect --serve` in-process, crosses the bridge, is stored by the relay, renders as a `swarm:finding:v1` card in the desktop, `E` promotes it (the daemon mints an incident and a `case_id`, the bridge creates the case channel), `D` dismisses it (leg 1: a signed `swarm:verdict:v1` card; leg 2: `POST /v1/operator/findings/{finding_id}/feedback`), and the daemon's tuning report moves.

**Architecture:** Two new engine crates and one engine binary edit carry the daemon half: `swarm-perch-wire` (types, grammar, tags, goldens), `swarm-perch-bridge` (in-process `broadcast::Receiver` → disk spool → 1 Hz pacer → NIP-42 socket, plus case-channel provisioning on `RuntimeEvent::CasePromoted`), and three operator routes (`B3`, `B3i`, `B3r`) whose engine code lives in `swarm-ingest-runtime/src/ingest/perch_ops/` and whose axum handlers live in `swarm-runtime-http/src/http/perch/`. The console half is a gated feature area in the desktop: a marker parser and card registry behind the `MessageBody` seam Ground extracted, one `/cases/$caseId` route, source-first React Query keys, one lane-movement REQ, and five Tauri commands (two daemon reads, two daemon writes, one relay write) whose route strings are Rust constants. Every task ends green on the gate that governs it.

**Tech Stack:** Engine: Rust 1.97.1 / edition 2024, tokio, axum 0.8, `nostr` 0.44 (`default-features = false`), `prometheus-client` 0.23, `sha2` 0.10, `serde_json`, cargo-deny. Workspace: Rust 1.95.0 / edition 2021, Tauri 2, `reqwest` 0.13, `ed25519-dalek` 3.0.0-rc.0, `keyring` 3; React 19, TanStack Router (virtual file routes), React Query, `zod` 4.4.3, Node's built-in test runner on colocated `*.test.mjs`, Playwright against the 14.6k-line mock Tauri bridge. Dev stack: Docker Compose (relay, Postgres 17, Redis 7) beside `swarm-detect`.

**Spec:** `docs/plans/ambush-ui/integration/01-DESIGN.md` (§4, §5, §6 "First card" row, §7, §9 H4–H6 and H8, §10, §11, §12), with `00-DECISIONS.md` D1–D4 and rows W3-2, W3-6, W3-13, W3-14, W3-15, W3-16, W3-19, W3-21, W3-24, W3-27, and the wave-2 artifacts it binds to: `../build/11-BRIDGE-CRATE.md`, `../build/13-WIRE-SCHEMAS.md`, `../build/12-BACKEND-BILL-API.md` §8–§10, `../build/14-CLIENT-ARCHITECTURE.md` §4–§8, `../build/17-COMPONENT-SPECS.md` §3, §4.1, §4.12, `../build/20-TASK-BREAKDOWN.md` §8, `../build/adr/0018`.

## Global Constraints

- Engine lints: `#![forbid(unsafe_code)]` in every new crate; `clippy::unwrap_used` and `clippy::expect_used` are **denied** workspace-wide (`Cargo.toml` `[workspace.lints.clippy]`); `[profile.release] panic = "abort"`; `cargo clippy --workspace --all-targets -- -D warnings` clean; test modules that need `unwrap` carry `#[allow(clippy::unwrap_used, clippy::expect_used)]` as `crates/swarm-perch-bridge/src/spool/checksum.rs` does.
- Workspace lints: no new `unwrap()` / `expect()` in production paths, no `unsafe`, doc comments on every new public item, `cd workspace && just check` clean, `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch` green.
- TCB rule: `swarm-perch-bridge` joins `TRUST_SENSITIVE` in `tools/check-workspace-layering.sh` (three-part edit: the tuple at `:184-191`, a `FIXTURE_CRATES` row at `:618-633`, `FIXTURE_DOCUMENTED` at `:637`); its `src/lib.rs` carries the exact whole lines `//! ## Owns` and `//! ## Does not own`; no TCB crate (`swarm-crypto`, `swarm-policy`, `swarm-spine`) ever names `swarm-perch-bridge` or `swarm-perch-wire` in a manifest. `swarm-perch-wire` itself names no other `swarm-*` package: engine-domain conversion and event narrowing belong to the bridge (W3-27).
- The bridge is write-only: zero `REQ` and zero `COUNT` frames, asserted by a source-scan test; `src/receive.rs` imports only `crate::stream`, `crate::spool`, `crate::metrics` (and `swarm_runtime`, `tokio`), asserted by a source-scan test.
- Spool before any network I/O: the receive loop is `recv()` → classify → append, no `fsync` per record, no socket; `seq` is assigned per `(colony_id, issuer)` **at append**; the pacer ticks at exactly `PERCH_PUBLISH_TICK_MS = 1_000` with `MissedTickBehavior::Delay`; `created_at` is stamped at drain immediately before signing; a frame is retried **byte-identically** while `now − created_at < 900 − 120` seconds and re-stamped from the spool head after that.
- Card body (W3-21): line 0 is exactly `<!-- swarm:finding:v1 -->`, line 1 is one human sentence in the `13` §7.1 grammar, a blank line, then a fenced block whose info string is `swarm:finding:v1` holding one `swarm.spine.envelope.v1` JSON object whose `fact.schema` is `swarm.perch.finding.v1`; `CARD_CONTENT_MAX_BYTES = 192 * 1024`.
- Tag budget: `h` mandatory on every card; `t` = threat-class slug (`ThreatClass` snake_case, `custom` for a custom class); `l` = severity SCREAMING_SNAKE (`LOW|MEDIUM|HIGH|CRITICAL`); `k` = card slug; **never `p` on a card** (`TagSet::assert_publishable(9)` refuses it). An initial finding-verdict card carries no `e`; a later same-channel supersession update may reply to its own leg-1 card (D-FC-3, Task 20; The hold Task 27).
- Admitted-issuer render rule (INV-15): a card renders only when its **raw signer** (`TimelineMessage.signerPubkey`, never `pubkey`) resolves to an admitted bridge identity; an unadmitted well-formed marker renders as prose, is counted in `perch_marker_unadmitted_total`, never enters a queue, and never triggers a notification.
- Console write allowlist (INV-01): the daemon-bound non-GET surface is exactly the five `("POST", path)` tuples in `PERCH_DAEMON_WRITES`; this milestone **implements** two of them (`/v1/operator/findings/{finding_id}/feedback`, `/v1/operator/incidents`) and lists the other three; there is no generic passthrough command; the gate is `tools/check-perch-write-allowlist.sh` wired into CI in the same commit.
- The daemon bearer token, the daemon base URL and the operator Ed25519 secret live in the Tauri process's keyring blob (`SecretStore::shared(keyring_service())`, keys `perch.daemon_bearer`, `perch.daemon_url`, `perch.operator_id`, `perch.operator_ed25519`) and never appear in any value crossing IPC into the webview.
- The relay-published surface of the operator's own key is exactly `kind:9` with marker `swarm:verdict:v1`, produced only by `perch_record_verdict`; `perch_sign_gate(kind: u16, content: &str)` (Ground Task 5, `workspace/desktop/src-tauri/src/perch_sign_gate.rs`) refuses `^<!-- swarm:[a-z]+:v\d+ -->$` on line 0 and kind 46010 at every content-signing command, and a test proves it refuses exactly the line 0 `perch_record_verdict` publishes.
- Copy: no rendered "Perch", "Approve", "verified", "signed" or an `A` key on a finding card; the tier badge is the literal `secp256k1 · tier 0 · TRANSPORT-SIGNED ONLY · the daemon is the record`; verdict verbs are on `E` (promote) and `D` (dismiss) only; the copy gate (Task 24) enforces the ban list.
- Desktop text sizes are rem tokens only (`pnpm check:px-text`); perch components read `--perch-*` tokens only; new desktop code never grows a file over 1000 gate-lines (`workspace/scripts/check-file-sizes-core.mjs`) and never edits the frozen files: `shared/api/tauri.ts` (1108), `shared/api/relayClientSession.ts` (1084), `shared/api/types.ts` (1000), `shared/ui/sidebar.tsx` (1011), `shared/ui/markdown.tsx` (1904), `src-tauri/src/lib.rs` grows only by `generate_handler!` entries and stays under 1000.
- Perch adds files; the only edits to pre-existing desktop files are: `MessageBody.tsx` (the eleven-line seam), `app/routes.ts` (one route), `communities/communityScopedRegistry.ts` (registry entries), `testing/e2eBridge.ts` (the prefix guard before `default:`), `playwright.config.ts` (spec registration), `src-tauri/src/commands/mod.rs` and `src-tauri/src/lib.rs` (module and handler registration), `src-tauri/Cargo.toml` (one path dependency), `preview-features.json` is untouched (Ground Task 11 owns the entry).
- Every new `tools/check-*.sh` lands with its `.github/workflows/ci.yml` `run:` step in the same commit (`tools/check-gates-wired.sh`); engine jobs carry Ground Task 12's `needs: changes` / `if:` guard.
- Tasks 3–8 are one **atomic landing unit** even when an executor uses their commit commands as local checkpoints. The copied skeleton contains `todo!()` bodies while that stack is in progress; no such checkpoint may be pushed, reviewed, merged or left reachable from the delivered branch. Before Task 8's commit, squash/fix up the stack and prove `rg -n 'todo!\(|unimplemented!\(' crates/swarm-perch-bridge/src` has no matches. Task 13 creates `channels.rs` as complete code in one commit; Operator-complete does the same for `leases.rs` and `coalesce.rs` (W3-29).
- Commits: `git commit -s`, Conventional Commits subjects, the attribution trailers in use on this branch; never commit key material, a spool, or `.perch-dev/`.

---

## What Ground delivered, and what this plan consumes

| Ground task | Symbol or file this plan uses | Used by |
|---|---|---|
| 1 rename and re-pin | skeleton and goldens already say `swarm:` / `swarm.perch.<card>.v1` / `card-swarm-*`; `GOLDEN.sha256` re-pinned | Tasks 1, 2 |
| 2 MR-2 | `workspace/desktop/src/features/messages/ui/MessageBody.tsx` with the comment `// perch seam: see 12-PLAN-FIRST-CARD.md Task 17` in its `default:` branch | Task 17 |
| 5 H2 | `crate::perch_sign_gate::perch_sign_gate(kind: u16, content: &str) -> Result<(), String>`, `is_swarm_marker_line(line: &str) -> bool`, the inventory test | Task 21 |
| 6 H3 | `COMMUNITY_SCOPED_SINGLETONS`, `RESETTERS: Record<CommunityScopedSingleton, Resetter>`, `runResetters` in `features/communities/communityScopedRegistry.ts` | Task 18 |
| 7 H7 | `workspace/crates/ambush-ws-client` with typed errors, under the engine panic gate | Tasks 3, 7 |
| 8 B0 | `OperatorPrincipalConfig.nostr_pubkey: Option<String>`, `nostr_pubkey_bytes()` | Tasks 7, 13 |
| 9 P0-22 | `rulesets/perch-dev.yaml` (+ `.sig.json`), `crates/swarm-runtime-http/src/bin/sign_dev_ruleset.rs` | Task 14 |
| 10 P0-21 | `docker-compose.yml` with `relay`, `postgres`, `redis`; `scripts/provision-perch.sh` | Task 14 (amended: see D-FC-5) |
| 11 | `getFeature("perch")` in `workspace/preview-features.json`, off by default | Tasks 16, 17 |
| 12 | the `changes` job in `.github/workflows/ci.yml` | Tasks 2, 19, 24 |

If a symbol above is missing, stop and finish the Ground task first; this plan does not re-implement it.

## Decisions this plan records

Five values are genuinely undecided by the wave-2 set and the wave-3 rulings. Each gets a **Decision** task that writes a row into `00-DECISIONS.md` §3 with the options, a default, and the dependents blocked on it. Dependents are built under the default and carry a one-line "blocked on D-FC-n" marker in their task header.

| Id | Question | Default the plan builds under | Decision task | Blocked dependents |
|---|---|---|---|---|
| D-FC-1 | The secp256k1 derivation domain string and how the 32-byte seed reaches the daemon | `swarm.perch.bridge.nostr.v1`; env var `PERCH_BRIDGE_NOSTR_SEED` (64 hex) | Task 6 | Task 7 |
| D-FC-2 | Where the console learns the admitted-issuer set | the daemon serves it unauthenticated at `GET /metrics/perch/identities` (public keys only), read by a Tauri command | Task 15 | Tasks 17, 19 |
| D-FC-3 | The finding-verdict card's shape under `swarm:verdict:v1`, and the `e` tag | a `subject` discriminator in `locator` and `decision`; no `e` on an initial verdict, while a later supersession update may reply to its own same-channel leg-1 card | Task 20 | Task 21 |
| D-FC-4 | Operator bearer, daemon URL and operator id provisioning UX | debug builds seed the keyring from `AMBUSH_PERCH_DAEMON_URL`, `AMBUSH_PERCH_DAEMON_BEARER`, `AMBUSH_PERCH_OPERATOR_ID` at startup; a Settings surface is Operator-complete | Task 15 | Tasks 19, 21 |
| D-FC-5 | Who creates the twelve lane channels | the **bridge**, idempotently at startup, from committed UUIDs in `perch.lane_channels`; Ground Task 10's script stops minting lanes | Task 14 | Task 13 |

## File Structure

**Engine (root workspace)**

| Path | Responsibility |
|---|---|
| `crates/swarm-perch-wire/{Cargo.toml, src/lib.rs, src/marker.rs, src/envelope.rs, src/cards.rs, src/tags.rs, src/frames.rs}` | the transport-neutral wire contract in Rust: seven card bodies, the envelope, canonical bytes and hashes, the content grammar, tag builders and `HoldId`; copied from `docs/plans/ambush-ui/build/skeleton/perch-wire/rust`, stripped of engine-domain imports per W3-27, and completed |
| `crates/swarm-perch-wire/golden/*.json`, `golden/GOLDEN.sha256`, `tests/golden.rs`, `tests/human_lines.rs` | the sixteen hash-pinned vectors and the tests both languages share |
| `tools/sync-perch-golden.sh`, `tools/check-perch-wire-parity.sh` | the re-pin script and the field-set parity gate (from `skeleton/perch-wire/parity-gate.sh`) |
| `crates/swarm-core/src/config/perch.rs` | `PerchBridgeConfig`, the `perch:` block on `SwarmConfig`, every field `#[serde(default)]` |
| `crates/swarm-perch-bridge/Cargo.toml`, `src/{lib,error,stream,receive,identity,cards,pacer,publish,metrics,channels,alarm}.rs`, `src/spool/{mod,segment,checksum,cursor}.rs`, `tests/relay_live.rs` | the bridge needed by this milestone. Future `coalesce.rs` and `leases.rs` modules are not copied as stubs; Operator-complete creates each with its real producer and tests |
| `crates/swarm-runtime/src/runtime_events.rs` | `RuntimeEvent::CasePromoted` (12th variant), `RuntimeEventKind::CasePromoted`, `CasePromotionClause` |
| `crates/swarm-ingest-runtime/src/ingest/mod.rs` | `pub mod perch_ops;`, the `runtime_event_matches_scope` arm |
| `crates/swarm-ingest-runtime/src/ingest/perch_ops/{mod,reviewed,mint,feedback}.rs` | engine operations: `reviewed_findings`, `mint_incident`, `record_finding_feedback` |
| `crates/swarm-runtime-http/src/http/perch/{mod,reviewed,incidents,feedback,tests}.rs`, `src/http/mod.rs` | `perch_operator_router(config, state)` and the three handlers |
| `crates/swarm-runtime-http/src/bin/swarm_detect.rs` | the bridge spawn, the metrics-router merge, the perch-router merge, the shutdown join |
| `crates/swarm-runtime-http/tests/perch_walking_skeleton.rs` | the ADR 0018 verification test |
| `Cargo.toml`, `deny.toml`, `tools/check-workspace-layering.sh`, `.github/workflows/ci.yml` | members, duplicate-version skips with reasons, the three-part TRUST_SENSITIVE edit, the gate steps |
| `rulesets/perch-dev.yaml` (+ `.sig.json`), `docker-compose.yml`, `scripts/provision-perch.sh`, `docs/PERCH-DEV.md`, `.gitignore` | the `perch:` block, the seed env plumbing, provisioning amendments, the demo script |
| `tools/check-perch-write-allowlist.sh`, `tools/lib/perch-roots.sh`, `tools/perch-source-roots.tsv`, `tools/copy-scope.tsv`, `tools/check-copy-banned-terms.sh`, `tools/copy-ban-list.tsv`, `tools/copy-ban-allowlist.tsv`, `tools/fixtures/copy-corpus/**` | the two perch gates this milestone lands (H4, H8) |
| `docs/plans/ambush-ui/build/schemas/card-swarm-finding-v1.schema.json`, `card-swarm-verdict-v1.schema.json`, `docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml` | the `gap` block, the `evidence_truncated` placement, the verdict `subject` amendment, W3-14 applied to B3i |

**Workspace (desktop)**

| Path | Responsibility |
|---|---|
| `src/features/perch/wire/{index.ts, marker.ts, tags.ts, types.ts, zod.ts, golden.test.mjs, golden/*.json}` | the TypeScript mirror and the shared goldens |
| `src/features/perch-evidence/lib/{markerTypes.ts, parseSwarmMarker.ts, parseSwarmMarker.test.mjs, admittedIssuers.ts, admittedIssuers.test.mjs, adversaryText.ts, adversaryText.test.mjs, findingVerdictFlow.ts, verdictWriteState.ts, verdictWriteState.test.mjs, perchCaseIndex.ts}` | pure logic, testable under `node --test` |
| `src/features/perch-evidence/ui/{SwarmCardSurface.tsx, swarmCardRegistry.tsx, EvidenceCardFrame.tsx, RefusalCards.tsx, NotYetRenderedCard.tsx, cards/FindingCard.tsx, GapNotice.tsx}` | the registry, the frame and the first read-only card; Task 23 adds its verbs with their real workflow |
| `src/shared/ui/perch/{AdversaryString.tsx, WriteStateRow.tsx}` | Tier-A primitives |
| `src/shared/api/{tauriPerch.ts, perchKeys.ts, perchKeys.test.mjs, perchSubscriptions.ts, perchSubscriptions.test.mjs, perchGapStore.ts}` | Tauri wrappers, keys and freshness, the REQ manager, gap detection |
| `src/app/routes.ts`, `src/app/routes/cases.$caseId.tsx`, `src/app/perchViews.ts`, `src/app/perchViews.test.mjs` | the case route and the view derivation |
| `src/features/communities/communityScopedRegistry.ts` | four new resetter entries |
| `src/features/messages/ui/MessageBody.tsx` | the seam |
| `src/testing/perch/e2ePerchBridge.ts`, `src/testing/e2eBridge.ts` | the delegated mock module and the prefix guard |
| `tests/helpers/perchBridge.ts`, `tests/e2e/perch-marker-admission.spec.ts`, `tests/e2e/perch-finding-card.spec.ts`, `playwright.config.ts` | Playwright |
| `src-tauri/src/perch/{mod.rs, daemon_client.rs, daemon_client_tests.rs}`, `src-tauri/src/commands/{perch_reads.rs, perch_writes.rs, perch_verdict.rs}`, `src-tauri/src/commands/mod.rs`, `src-tauri/src/lib.rs`, `src-tauri/Cargo.toml` | the daemon client, the five commands, registration |
| `scripts/check-copy-banned-terms.mjs`, `package.json` (`check:copy`) | the `.mjs` half of the copy gate |

**Tests, by command**

| Command | Covers |
|---|---|
| `cargo test -p swarm-perch-wire` | grammar, tags, envelope, goldens, human lines |
| `cargo test -p swarm-perch-bridge` | config, stream, spool, receive, identity, cards, pacer, publish classification, channels; `PERCH_TEST_RELAY_URL=ws://localhost:3000 cargo test -p swarm-perch-bridge --test relay_live -- --ignored` for the live relay |
| `cargo test -p swarm-ingest-runtime perch_ops` | the three engine operations |
| `cargo test -p swarm-runtime-http perch` | the three routes and the walking-skeleton test |
| `bash tools/check-workspace-layering.sh`, `bash tools/check-runtime-panic-contract.sh`, `bash tools/check-gates-wired.sh`, `bash tools/check-perch-wire-parity.sh`, `PERCH_DESKTOP_ROOT=workspace/desktop bash tools/check-perch-write-allowlist.sh`, `PERCH_DESKTOP_ROOT=workspace/desktop bash tools/check-copy-banned-terms.sh` | gates |
| `cd workspace/desktop && node --test src/features/perch-evidence/lib/parseSwarmMarker.test.mjs` (and the other colocated `*.test.mjs`) | desktop unit |
| `cd workspace/desktop && pnpm test:e2e:smoke` | the two perch specs beside the existing smoke project |
| `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch` | the daemon client, the route table, the verdict command |
| `cd workspace && just check` | biome, px-text, pubkey-truncation, typecheck, file sizes |

---

### Task 1: `swarm-perch-wire` — envelope, `FindingCard`, tags, `HoldId`, goldens and the hash pin

**Files:**
- Create: `crates/swarm-perch-wire/Cargo.toml`, `crates/swarm-perch-wire/src/{lib,marker,envelope,cards,tags,frames}.rs` (copied from `docs/plans/ambush-ui/build/skeleton/perch-wire/rust/`, with `narrowing.rs` deliberately omitted), `crates/swarm-perch-wire/golden/` (copied from `.../skeleton/perch-wire/golden/`), `crates/swarm-perch-wire/tests/golden.rs`, `crates/swarm-perch-wire/tests/human_lines.rs`, `tools/sync-perch-golden.sh`
- Modify: `Cargo.toml` `[workspace] members` (`:3-24`, twenty members today), `docs/plans/ambush-ui/build/schemas/card-swarm-finding-v1.schema.json`
- Test: `cargo test -p swarm-perch-wire`

**Interfaces:**
- Consumes: only transport-neutral crates (`serde`, `serde_json`, `serde_json_canonicalizer`, `sha2`, `hex`, `chrono`, `thiserror`). It consumes no Rust type from the engine. `swarm-perch-bridge` converts `SwarmFindingEnvelope`, `ThreatClass`, `Severity`, `AgentRole` and `RuntimeEvent` into the wire-owned DTOs in Task 3 (W3-27).
- Produces (used by Tasks 2, 8, 21):
  - `swarm_perch_wire::marker::{CardKind, CARD_CONTENT_MAX_BYTES, ContentParts, MarkerError, build_content(kind: CardKind, human_line: &str, json: &str) -> Result<String, MarkerError>, parse_content(&str) -> Result<ContentParts<'_>, MarkerError>}`; `CardKind::{slug, marker, fence_info, fact_schema, route(&str) -> Option<CardKind>, ALL}`.
  - `swarm_perch_wire::envelope::{CardEnvelope, FactIssuer, OperatorFactIssuer, NeverARole, EnvelopeError, ENVELOPE_SCHEMA_V1}`; `CardEnvelope::seal_unsigned(kind, issuer: &str, seq: u64, prev_envelope_hash: Option<String>, issued_at: String, fact: Value) -> Result<CardEnvelope, EnvelopeError>`; `CardEnvelope::is_tier_zero(&self) -> bool`.
  - `swarm_perch_wire::cards::{Card, FindingCard, FindingLocator, EvidenceTruncated, GapBlock, GapBlockCause, HUMAN_SEP}`; `Card::human_line(&self) -> String`; `FindingCard::human_line(&self) -> String`.
  - `swarm_perch_wire::tags::{TagSet, TagError, is_opaque_hold_id, is_relay_pubkey}`; `TagSet::card(kind, channel, threat_class_slug: Option<String>, severity: Option<String>) -> TagSet`; `TagSet::assert_publishable(&self, kind: u16) -> Result<(), TagError>`; `TagSet::to_tags(&self) -> Vec<Vec<String>>`.
  - `swarm_perch_wire::{KIND_CARD = 9, KIND_HOLD_NOTICE = 46010, KIND_HOLD_ALARM = 26006, is_perch_frame_kind}`.
  - `canonical_bytes(&impl Serialize) -> Result<Vec<u8>, EnvelopeError>` and `compute_envelope_hash_hex(&Value) -> Result<String, EnvelopeError>` in `envelope.rs` using RFC 8785/JCS; `threat_class_slug(&WireThreatClass) -> &str` and `severity_label(WireSeverity) -> &'static str` in `cards.rs`.

- [ ] **Step 1: Copy the renamed skeleton into the crate.**
  ```bash
  cd /path/to/ambush
  cp -R docs/plans/ambush-ui/build/skeleton/perch-wire/rust crates/swarm-perch-wire
  cp -R docs/plans/ambush-ui/build/skeleton/perch-wire/golden crates/swarm-perch-wire/golden
  grep -rn 'ambush:finding\|ambush\.perch\.' crates/swarm-perch-wire | wc -l   # expected: 0 (Ground Task 1 renamed the skeleton)
  ls crates/swarm-perch-wire/golden | grep -c 'card-swarm-'                    # expected: 8
  rm -f crates/swarm-perch-wire/src/narrowing.rs
  grep -RniE 'swarm_(core|crypto|policy|response|runtime|spine|whisker)' crates/swarm-perch-wire/src
  # expected here: copied-skeleton hits; save the list. Step 2 must drive it to zero.
  ```
  If the first count is not 0, Ground Task 1 has not run; stop.

- [ ] **Step 2: Rewrite `Cargo.toml` to inherit from the workspace and add the member.**
  ```toml
  [package]
  name = "swarm-perch-wire"
  description = "Wire types for the operator console: seven kind:9 marker cards, the kind:46010 hold notice, and the 26000-26006 ephemeral frames"
  version.workspace = true
  edition.workspace = true
  license.workspace = true

  [dependencies]
  chrono.workspace = true
  serde.workspace = true
  serde_json.workspace = true
  thiserror.workspace = true
  serde_json_canonicalizer = "=0.3.2"
  sha2.workspace = true
  hex.workspace = true

  [lints]
  workspace = true
  ```
  In the root `Cargo.toml`, append `"crates/swarm-perch-wire",` to `members` (keep the list sorted the way it is today). The crate pins `serde_json_canonicalizer` because these bytes are a cross-process signature contract, not a presentation detail. Do not add a feature that pulls engine types back into the crate.

  Replace the copied skeleton's engine imports with wire-owned DTOs in `cards.rs` and
  `frames.rs`: `WireThreatClass` has the twelve standard snake-case variants plus
  `Custom(String)` in the same serde representation; `WireSeverity` has the four
  SCREAMING_SNAKE variants; `WireAgentRole`, `WireExecutionMode`, action, receipt,
  lease and rollback records mirror the JSON schemas field-for-field. These are
  serialized contracts, not aliases of engine domain types. Delete `pub mod narrowing`
  and every conversion impl from this crate. Task 3 owns those conversions in the bridge.

  In `envelope.rs`, replace the copied `EnvelopeError::Spine` variant and every
  `swarm_spine` call with a local `EnvelopeError::Canonical(String)` mapping.
  `canonical_bytes` delegates to `serde_json_canonicalizer::to_vec`;
  `compute_envelope_hash_hex` removes both `envelope_hash` and `signature` from an
  object copy, hashes those canonical bytes with SHA-256, and returns lowercase hex
  with the schema's `0x` prefix. `CardEnvelope.signature` remains an optional string
  field so B6 can deserialize a signed engine envelope without adding a crypto type.
  `seal_unsigned` uses only these local functions and sets it to `None`. A unit test
  uses an object whose insertion order is deliberately reversed and asserts the
  RFC-ordered bytes; Task 3 adds the engine-vs-wire differential corpus test.

- [ ] **Step 3: Write the failing human-line test.** `crates/swarm-perch-wire/tests/human_lines.rs`:
  ```rust
  #![allow(clippy::unwrap_used, clippy::expect_used)]
  use serde_json::Value;
  use swarm_perch_wire::cards::Card;

  fn fact(stem: &str) -> Value {
      let raw = std::fs::read_to_string(format!(
          "{}/golden/{stem}.json",
          env!("CARGO_MANIFEST_DIR")
      ))
      .unwrap();
      serde_json::from_str::<Value>(&raw).unwrap()["fact"].clone()
  }

  #[test]
  fn the_finding_human_line_follows_the_section_7_1_grammar() {
      let card: Card = serde_json::from_value(fact("card-swarm-finding-v1")).unwrap();
      assert_eq!(
          card.human_line(),
          "whisker-7a3f · data_exfiltration · HIGH · confidence 0.82 · host web-04 · finding f2c9a1b4"
      );
  }

  #[test]
  fn every_card_has_a_one_line_human_fallback() {
      for stem in [
          "card-swarm-finding-v1",
          "card-swarm-escalation-v1",
          "card-swarm-hold-v1",
          "card-swarm-verdict-v1",
          "card-swarm-receipt-v1",
          "card-swarm-lease-v1",
          "card-swarm-rollback-v1",
      ] {
          let card: Card = serde_json::from_value(fact(stem)).unwrap();
          let line = card.human_line();
          assert!(!line.is_empty() && !line.contains('\n'), "{stem}: {line:?}");
          assert!(line.contains(" · "), "{stem}: fields are separated by U+00B7: {line:?}");
      }
  }
  ```

- [ ] **Step 4: Run it to see it fail.**
  Run: `cargo test -p swarm-perch-wire --test human_lines`
  Expected: `panicked at ... not yet implemented: compose from issuer, finding and locator` (the skeleton's `todo!` bodies).

- [ ] **Step 5: Implement the seven human lines** in `src/cards.rs`, replacing each `todo!`. Add the two helpers near `HUMAN_SEP`:
  ```rust
  /// A wire threat class as its `t`-tag slug.
  #[must_use]
  pub fn threat_class_slug(class: &WireThreatClass) -> &'static str {
      match class {
          WireThreatClass::LateralMovement => "lateral_movement",
          WireThreatClass::DataExfiltration => "data_exfiltration",
          WireThreatClass::PrivilegeEscalation => "privilege_escalation",
          WireThreatClass::CommandAndControl => "command_and_control",
          WireThreatClass::InitialAccess => "initial_access",
          WireThreatClass::Persistence => "persistence",
          WireThreatClass::SupplyChain => "supply_chain",
          WireThreatClass::DefenseEvasion => "defense_evasion",
          WireThreatClass::CredentialAccess => "credential_access",
          WireThreatClass::Discovery => "discovery",
          WireThreatClass::Execution => "execution",
          WireThreatClass::Impact => "impact",
          WireThreatClass::Custom(_) => "custom",
      }
  }

  /// A wire severity as its `l`-tag label.
  #[must_use]
  pub fn severity_label(severity: WireSeverity) -> &'static str {
      match severity {
          WireSeverity::Low => "LOW",
          WireSeverity::Medium => "MEDIUM",
          WireSeverity::High => "HIGH",
          WireSeverity::Critical => "CRITICAL",
      }
  }

  fn iso_seconds(ms: i64) -> String {
      chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
          .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
          .unwrap_or_else(|| format!("{ms}ms"))
  }
  ```
  Then:
  ```rust
  impl FindingCard {
      fn human_line(&self) -> String {
          [
              self.issuer.swarm_agent_id.clone(),
              threat_class_slug(&self.finding.threat_class),
              severity_label(self.finding.severity).to_string(),
              format!("confidence {:.2}", self.finding.confidence),
              format!("host {}", self.locator.host_id.as_deref().unwrap_or("unknown")),
              format!("finding {}", self.locator.finding_id),
          ]
          .join(HUMAN_SEP)
      }
  }
  ```
  Escalation (three arms on `self.escalation`): crossing → `[slug, LEVEL, format!("strength {:.2}", total_strength), match source_ids { Some(ids) => format!("{} sources / {} agents", distinct_sources, agents_of(ids)), None => format!("{} sources / agents not yet resolved", distinct_sources) }, format!("mode {mode}")]` where `agents_of` drops the last `:`-segment of each id and counts distinct; mode → `["mode {from} → incident", triggering_threat_class slug or "none", reason]`; tamper → `["tamper fail-closed", format!("{} unexpected library loads", unexpected_library_count), if debugger_attached {"debugger attached"} else {"debugger not attached"}]`. Hold → `["hold {hold_id}", action_kind, SEVERITY, format!("{scope_kind} {scope_value}") from `rehearsal.blast_radius` or `"scope unresolved"`, format!("expires {}", iso_seconds(expires_at_ms))]`. Verdict → `[decision word, format!("hold {hold_id}"), format!("by {operator_id}"), iso_seconds(decided_at_ms)]`. Receipt → `[format!("receipt {}", receipt_id or "none"), action kind, status, mode, format!("trail {trail_id}")]`. Lease → `[format!("containment lease {lease_id}"), action kind, format!("issued {}", iso), format!("expires {}", iso), format!("origin receipt {origin_receipt_id}")]`. Rollback → `[format!("rollback {rollback_id}"), format!("containment lease {lease_id}"), trigger, status, format!("{k} of {n} steps reversed")]` with `k` = steps whose status is `reversed`. The field names are the wire-owned structs' (they mirror `ts/zod.ts` field for field); when an accessor does not compile, fix the accessor to the struct's name and never the grammar. Wire enums expose explicit `as_str`/`slug` methods; do not recover their spelling by importing an engine type.

- [ ] **Step 6: Add the `gap` block and pin `evidence_truncated` at the card level.** In `src/cards.rs`:
  ```rust
  /// Loss the bridge observed before this card, carried inside the same signed
  /// envelope so it cannot be lost independently of the card (11-BRIDGE-CRATE §3.6).
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  pub struct GapBlock {
      /// Why content is missing.
      pub cause: GapBlockCause,
      /// Present for `broadcast_lagged` only: the bridge never saw the events and has no seq for them.
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub count: Option<u64>,
      /// Present for the three spool causes: an exact `seq` range, inclusive.
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub from_seq: Option<u64>,
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub to_seq: Option<u64>,
      /// When the bridge first recorded the loss, daemon clock.
      pub noticed_at_ms: i64,
  }

  /// Exactly four causes. A coalesce is not a gap and never appears here.
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
  #[serde(rename_all = "snake_case")]
  pub enum GapBlockCause {
      BroadcastLagged,
      SpoolEvicted,
      SpoolTornTail,
      PublishWindowExpired,
  }
  ```
  and on `FindingCard`, after `evidence_truncated`:
  ```rust
      /// Loss observed before this card. Absent on a normal card.
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub gap: Option<GapBlock>,
  ```
  In `docs/plans/ambush-ui/build/schemas/card-swarm-finding-v1.schema.json`, add to the fact object's `properties` a `gap` object (`additionalProperties: false`, `required: [cause, noticed_at_ms]`, `cause` enum of the four snake_case values, `count`/`from_seq`/`to_seq` integers `minimum: 0`, `noticed_at_ms` integer), and confirm `evidence_truncated` is a property of the fact object, not of `fact.finding` — `SwarmFindingEnvelope` is carried by type and cannot grow a field; if the schema nests it under `finding`, move it up. Re-export `GapBlock, GapBlockCause` from `lib.rs`'s `pub use cards::{…}`.

- [ ] **Step 7: Run the crate's tests.**
  Run: `cargo test -p swarm-perch-wire`
  Expected: `human_lines` passes; `tests/golden.rs` fails only on `the_golden_corpus_matches_its_pinned_hash` if Ground's re-pin used a per-file format — the test hashes the **concatenation** of the vectors sorted by name (`golden.rs:102-117`), while Ground Task 1 step 5 wrote `shasum` output per file. Fix the pin with the script in Step 8, never by hand.

- [ ] **Step 8: The re-pin script.** `tools/sync-perch-golden.sh`:
  ```bash
  #!/usr/bin/env bash
  # Re-pins the golden corpus hash in BOTH language suites from one computation:
  # sha256 over the concatenation of every golden vector except manifest.json,
  # sorted by file name in C locale (the order tests/golden.rs and golden.test.mjs use).
  # Also mirrors the engine's golden/ into the desktop's, so the two directories
  # cannot drift. Never edit GOLDEN.sha256 by hand.
  set -euo pipefail
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  SRC="$ROOT/crates/swarm-perch-wire/golden"
  DST="$ROOT/workspace/desktop/src/features/perch/wire/golden"
  hash="$(cd "$SRC" && cat $(ls *.json | grep -v '^manifest.json$' | LC_ALL=C sort) | shasum -a 256 | cut -d' ' -f1)"
  printf '%s  (concatenated, sorted by filename)\n' "$hash" > "$SRC/GOLDEN.sha256"
  sed -i '' -E "s/^(const GOLDEN_SHA256: &str =)$/\1/; s/^    \"[0-9a-f]{64}\";$/    \"$hash\";/" "$ROOT/crates/swarm-perch-wire/tests/golden.rs"
  if [ -d "$DST" ]; then
    rm -f "$DST"/*.json "$DST/GOLDEN.sha256"
    cp "$SRC"/*.json "$SRC/GOLDEN.sha256" "$DST/"
    sed -i '' -E "s/^const GOLDEN_SHA256 = \"[0-9a-f]{64}\";$/const GOLDEN_SHA256 = \"$hash\";/" "$DST/../golden.test.mjs"
  fi
  echo "pinned $hash"
  ```
  `chmod +x tools/sync-perch-golden.sh && bash tools/sync-perch-golden.sh`, then `cargo test -p swarm-perch-wire` → all green, including `the_golden_corpus_matches_its_pinned_hash`. (`tools/check-gates-wired.sh` ignores `sync-*` names; it enumerates only `check-*` and `verify-*`.)

- [ ] **Step 9: The gates.** `cargo clippy -p swarm-perch-wire --all-targets -- -D warnings` (the test files carry the `#![allow]` line at the top; production code has no `unwrap`/`expect`); `cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; p=next(p for p in json.load(sys.stdin)["packages"] if p["name"]=="swarm-perch-wire"); bad=[d["name"] for d in p["dependencies"] if d["name"].startswith("swarm-")]; assert not bad, bad'`; `bash tools/check-runtime-panic-contract.sh`; `bash tools/check-no-include-files.sh` — if it reports `crates/swarm-perch-wire/golden/*.json` because `include_str!` reaches them, add that directory to the script's allowlist with the comment `# golden vectors: test fixtures read by include_str!, not Rust source`; `bash tools/check-workspace-layering.sh` → exit 0. Finally build the crate from both toolchain roots: `cargo +1.97.1 check -p swarm-perch-wire` and `cd workspace && cargo +1.95.0 check --manifest-path ../crates/swarm-perch-wire/Cargo.toml`.

- [ ] **Step 10: Commit.**
  ```bash
  git add Cargo.toml Cargo.lock crates/swarm-perch-wire tools/sync-perch-golden.sh docs/plans/ambush-ui/build/schemas/card-swarm-finding-v1.schema.json tools/check-no-include-files.sh
  git commit -s -m "feat(perch-wire): the wire crate — seven card bodies, grammar, tags, goldens and the hash pin"
  ```

### Task 2: The TypeScript mirror, the zod decoder, and the parity gate

**Files:**
- Create: `workspace/desktop/src/features/perch/wire/{index.ts, marker.ts, tags.ts, types.ts, zod.ts, golden.test.mjs}` (copied from `docs/plans/ambush-ui/build/skeleton/perch-wire/ts/`), `workspace/desktop/src/features/perch/wire/golden/` (mirrored by `tools/sync-perch-golden.sh`), `tools/check-perch-wire-parity.sh` (from `.../skeleton/perch-wire/parity-gate.sh`)
- Modify: `.github/workflows/ci.yml` (the gates job, after the layering step at `:151-152`)
- Test: `cd workspace/desktop && node --test src/features/perch/wire/golden.test.mjs`; `bash tools/check-perch-wire-parity.sh`

**Interfaces:**
- Produces (used by Tasks 17, 21, 22): `routeCard(content: string): CardKind | null`, `parseCardContent(content: string): CardContentParts | null`, `parseCardParts(kind: CardKind, afterMarker: string): { humanLine: string; json: string } | null`, `buildCardContent(kind, humanLine, json): string`, `CARD_MARKER`, `CARD_FENCE`, `CARD_FACT_SCHEMA`, `CARD_KINDS`, `CARD_CONTENT_MAX_BYTES` from `marker.ts`; `admitCard(json, signerPubkey, isAdmittedIssuer): { ok: true; card: Card } | { ok: false; reason: AdmissionFailure }`, `envelopeTier(card): 0 | 1 | 2`, `findingFact`, `cardEnvelope` from `zod.ts`; `Card`, `FindingCard` types from `types.ts`.

- [ ] **Step 1: Copy and mirror.**
  ```bash
  mkdir -p workspace/desktop/src/features/perch/wire
  cp docs/plans/ambush-ui/build/skeleton/perch-wire/ts/{index.ts,marker.ts,tags.ts,types.ts,zod.ts,golden.test.mjs} workspace/desktop/src/features/perch/wire/
  bash tools/sync-perch-golden.sh      # copies golden/ and rewrites the .mjs pin
  ```
  `golden.test.mjs` resolves `path.join(HERE, "golden")` (`:43-44`), so the mirrored directory is exactly where it looks.

- [ ] **Step 2: Write the failing test for `parseCardParts`.** Append to `golden.test.mjs`:
  ```js
  import { parseCardParts, parseCardContent, buildCardContent } from "./marker.ts";

  test("parseCardParts agrees with parseCardContent on every card vector", () => {
    for (const { name, raw } of cardVectors()) {
      const kind = name.replace(/^card-swarm-/, "").replace(/-v1.*$/, "");
      const body = buildCardContent(kind, `${kind} · fixture`, raw.trim());
      const whole = parseCardContent(body);
      const afterMarker = body.slice(body.indexOf("\n") + 1);
      const parts = parseCardParts(kind, afterMarker);
      assert.ok(whole && parts, name);
      assert.equal(parts.humanLine, whole.humanLine);
      assert.equal(parts.json, whole.json);
    }
  });
  ```
  (`cardVectors()` is the file's existing helper over `golden/card-*.json`; if it is named differently in the copied file, use that name.)
  Run: `cd workspace/desktop && node --test src/features/perch/wire/golden.test.mjs` → `SyntaxError: The requested module './marker.ts' does not provide an export named 'parseCardParts'`.

- [ ] **Step 3: Implement `parseCardParts` and refactor `parseCardContent` onto it** in `marker.ts`:
  ```ts
  /**
   * The two parts after line 0. Used by `parseCardContent` and by the evidence
   * registry, which already routed on line 0 and holds only the remainder.
   * Never throws.
   */
  export function parseCardParts(
    kind: CardKind,
    afterMarker: string,
  ): { readonly humanLine: string; readonly json: string } | null {
    const secondBreak = afterMarker.indexOf("\n");
    const humanLine = (
      secondBreak === -1 ? afterMarker : afterMarker.slice(0, secondBreak)
    ).trim();
    if (!humanLine) return null;
    const afterHuman = secondBreak === -1 ? "" : afterMarker.slice(secondBreak + 1);
    const fenceOpen = "```" + CARD_FENCE[kind] + "\n";
    const openAt = afterHuman.indexOf(fenceOpen);
    if (openAt === -1) return null;
    const jsonStart = openAt + fenceOpen.length;
    const closeAt = afterHuman.indexOf("\n```", jsonStart);
    if (closeAt === -1) return null;
    return { humanLine, json: afterHuman.slice(jsonStart, closeAt).trim() };
  }

  export function parseCardContent(content: string): CardContentParts | null {
    const kind = routeCard(content);
    if (!kind) return null;
    const firstBreak = content.indexOf("\n");
    if (firstBreak === -1) return null;
    const parts = parseCardParts(kind, content.slice(firstBreak + 1));
    return parts ? { kind, ...parts } : null;
  }
  ```
  Export `parseCardParts` from `index.ts` beside `parseCardContent`.

- [ ] **Step 4: Mirror Task 1's shape changes in `zod.ts`.** In `findingFact`, remove `evidence_truncated` from the nested `finding` strictObject and add at the fact level, after `finding`:
  ```ts
    evidence_truncated: z
      .strictObject({ bytes: z.number().int().nonnegative(), sha256: hexPrefixed })
      .optional(),
    gap: z
      .strictObject({
        cause: z.enum(["broadcast_lagged", "spool_evicted", "spool_torn_tail", "publish_window_expired"]),
        count: z.number().int().nonnegative().nullish(),
        from_seq: z.number().int().nonnegative().nullish(),
        to_seq: z.number().int().nonnegative().nullish(),
        noticed_at_ms: z.number().int(),
      })
      .optional(),
  ```
  and the matching `GapBlock` type in `types.ts` on `FindingCard`. Run the golden test → green (no vector carries `gap`, so admission of every vector is unchanged).

- [ ] **Step 5: The parity gate.** `cp docs/plans/ambush-ui/build/skeleton/perch-wire/parity-gate.sh tools/check-perch-wire-parity.sh`. Edit the three `resolve` calls (`:36-46`) so the in-repo layout is the first candidate: `SCHEMA_DIR` → `$ROOT/docs/plans/ambush-ui/build/schemas`, `RUST_DIR` → `$ROOT/crates/swarm-perch-wire/src`, `TS_FILE` → `$ROOT/workspace/desktop/src/features/perch/wire/zod.ts`, where `ROOT="$(cd "$HERE/.." && pwd)"`; delete the "Buzz checkout" candidates and the `PERCH_WIRE_TS` hint text at `:67`. Then:
  ```bash
  bash tools/check-perch-wire-parity.sh --self-test   # expected: the three self-test cases pass
  bash tools/check-perch-wire-parity.sh               # expected: "N fields, exit 0" — N is 311 plus the seven names Step 4 and Task 1 Step 6 added (gap, cause, count, from_seq, to_seq, noticed_at_ms; evidence_truncated already counted)
  ```
  If it reports a name missing on one side, the name is spelled differently in one of the three files; align it to the schema.

- [ ] **Step 6: Wire the gate.** In `.github/workflows/ci.yml`, immediately after the layering step (`- name: Check the trusted-computing-base layering boundary` / `run: bash tools/check-workspace-layering.sh`):
  ```yaml
        - name: Check Perch wire field-set parity
          run: bash tools/check-perch-wire-parity.sh
  ```
  `bash tools/check-gates-wired.sh` → green (the new script is named by a `run:` step). `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → ok.

- [ ] **Step 7: Desktop gates.** `cd workspace && just desktop-check && just desktop-typecheck && just file-size-check` → green (`zod.ts` is 819 lines; `types.ts` 758; both under the 1000 ratchet).

- [ ] **Step 8: Commit.**
  ```bash
  git add workspace/desktop/src/features/perch tools/check-perch-wire-parity.sh .github/workflows/ci.yml crates/swarm-perch-wire/tests/golden.rs crates/swarm-perch-wire/golden/GOLDEN.sha256
  git commit -s -m "feat(desktop): the wire mirror, the zod admission gate, and the field-set parity gate"
  ```

### Task 3: `swarm-perch-bridge` scaffold — manifest, `lib.rs`, `error.rs`, the `perch` config block, `stream.rs`

**Files:**
- Create: `crates/swarm-perch-bridge/Cargo.toml`, `crates/swarm-perch-bridge/src/{lib,error,stream,receive,identity,cards,pacer,publish,metrics}.rs`, `crates/swarm-perch-bridge/src/spool/{mod,segment,checksum}.rs` (copied from `docs/plans/ambush-ui/build/skeleton/swarm-perch-bridge/`, **without** `src/ws/`, `src/channels.rs`, `src/coalesce.rs` or `src/leases.rs`), `crates/swarm-core/src/config/perch.rs`
- Modify: `Cargo.toml` members; `deny.toml` `[[bans.skip]]`; `crates/swarm-core/src/config/{mod.rs, root.rs, validation.rs}`
- Test: `cargo test -p swarm-perch-bridge stream`; `cargo test -p swarm-perch-bridge wire_parity`; `cargo test -p swarm-core perch_config`; `cargo deny check bans`

**Interfaces:**
- Consumes: `ambush_ws_client::{NostrWsConnection, WsClientError, OkResponse, RelayMessage}` (`workspace/crates/ambush-ws-client/src/{connection,error,message}.rs`, after Ground Task 7); `swarm_runtime::runtime_events::RuntimeEvent` (11 variants today, `crates/swarm-runtime/src/runtime_events.rs:211-305`); `swarm_runtime::containment::ContainmentSweep`; `swarm_core::types::AgentId`; `swarm_core::config::OperatorPrincipalConfig` (with Ground's `nostr_pubkey`).
- Produces (used by Tasks 4–9, 13, 14):
  - `swarm_core::config::PerchBridgeConfig { enabled, relay_url, nostr_seed_env, auth_tag_env, spool_dir, spool_max_bytes, segment_bytes, publish_tick_ms, frame_max_bytes, escalation_heartbeat_ms, alarm_heartbeat_ms, alarm_burst_per_min, gap_flush_ticks, late_published_ticks, publish_window_margin_secs, case_ttl_seconds: BTreeMap<String, i32>, lane_channels: BTreeMap<String, String> }` and `SwarmConfig.perch: PerchBridgeConfig`; `PerchBridgeConfig::validate(&self) -> Result<(), ConfigValidationError>`; `PerchBridgeConfig::lane_channel(&self, class: &ThreatClass) -> Option<Uuid>`.
  - `swarm_perch_bridge::{BridgeBuildInput, PerchBridge, BridgeError, Stream}`; `BridgeBuildInput { config: PerchBridgeConfig, colony_id: String, events: Option<broadcast::Receiver<RuntimeEvent>>, admitted_identities: Vec<AgentId>, ingest_identity: AgentId, operator_principals: Vec<OperatorPrincipalConfig>, containment: Option<Arc<ContainmentSweep>>, shutdown: watch::Receiver<bool> }`; `PerchBridge::build(input) -> Result<Option<PerchBridge>, BridgeError>`; `PerchBridge::metrics_router(&self) -> axum::Router`; `PerchBridge::run(self) -> impl Future<Output = ()>`.
  - `swarm_perch_bridge::stream::{Stream, classify(&RuntimeEvent) -> Stream, redact_in_place(&mut RuntimeEvent), finding_to_wire(&SwarmFindingEnvelope) -> WireFinding, threat_class_to_wire(&ThreatClass) -> WireThreatClass, severity_to_wire(Severity) -> WireSeverity}`. These conversions live here, never in `swarm-perch-wire` (W3-27).

- [ ] **Step 1: Copy the skeleton, minus the vendored socket.**
  ```bash
  cp -R docs/plans/ambush-ui/build/skeleton/swarm-perch-bridge crates/swarm-perch-bridge
  rm -rf crates/swarm-perch-bridge/src/ws crates/swarm-perch-bridge/README.md
  rm -f crates/swarm-perch-bridge/src/channels.rs crates/swarm-perch-bridge/src/coalesce.rs crates/swarm-perch-bridge/src/leases.rs
  grep -rn 'crate::ws\|pub mod ws' crates/swarm-perch-bridge/src   # expected: lib.rs `pub mod ws;`, error.rs `crate::ws::WsClientError`, publish.rs `use crate::ws::NostrWsConnection`
  ```
  Delete `pub mod ws;` from `lib.rs`; in `error.rs` replace `crate::ws::WsClientError` with `ambush_ws_client::WsClientError`; in `publish.rs` replace `use crate::ws::NostrWsConnection;` with `use ambush_ws_client::NostrWsConnection;`.

- [ ] **Step 2: The manifest.** Replace `crates/swarm-perch-bridge/Cargo.toml`'s `[dependencies]` block with:
  ```toml
  [dependencies]
  swarm-core.workspace = true
  swarm-perch-wire = { workspace = true, default-features = false }
  swarm-response.workspace = true
  swarm-runtime.workspace = true
  axum.workspace = true
  chrono.workspace = true
  futures-util.workspace = true
  hex.workspace = true
  prometheus-client.workspace = true
  serde.workspace = true
  serde_json.workspace = true
  sha2.workspace = true
  thiserror.workspace = true
  tokio.workspace = true
  tracing.workspace = true
  uuid.workspace = true
  # W3-6: a path dependency into the second workspace, not a vendored copy.
  # The crate's `workspace = true` dependencies resolve against
  # workspace/Cargo.toml, so nostr arrives with that manifest's features.
  ambush-ws-client = { path = "../../workspace/crates/ambush-ws-client" }
  # The same nostr the ws-client resolves; features unify at the crate level.
  nostr = { version = "0.44", default-features = false, features = ["std"] }

  [dev-dependencies]
  swarm-spine.workspace = true
  tempfile = "3"
  ```
  Add `swarm-perch-wire = { path = "crates/swarm-perch-wire" }` to the root `[workspace.dependencies]` beside the other `swarm-*` entries, and `"crates/swarm-perch-bridge",` to `members`. `swarm-spine` is a bridge-only dev dependency here for the W3-27 differential test; B6 makes it a normal bridge dependency later. `tempfile` is new to the workspace as a dev-dependency only; `tools/check-supply-chain.sh` scans the resolved graph, so it is a review item in the commit message.

- [ ] **Step 3: Measure the duplicate-version surface and record every skip with its reason.**
  ```bash
  cargo build -p swarm-perch-bridge 2>&1 | tail -3
  cargo tree -p swarm-perch-bridge -i chacha20 -e normal   # the ws-client resolves nostr with nip44 from workspace/Cargo.toml; expect a hit
  cargo deny check bans 2>&1 | grep -E 'found [0-9]+ duplicate|= [a-z0-9_-]+ v' | sort -u
  ```
  For every crate cargo-deny reports twice (expected at least: `sha2`, `digest`, `block-buffer`, `crypto-common`, `tokio-tungstenite`, and `getrandom`/`rand_core` if nostr's pin differs), append to `deny.toml`'s `skip` array one entry per version **that the path dependency introduced**, in the file's own style:
  ```toml
    # --- Introduced by workspace/crates/ambush-ws-client (00-DECISIONS W3-6 path dependency) ---
    { crate = "sha2@0.11.0", reason = "ambush-ws-client -> nostr 0.44 pins the sha2 0.11 / digest 0.11 generation; the engine stays on 0.10 (ed25519-dalek 2.x)" },
  ```
  with the exact versions `cargo deny` printed. `cargo deny check bans` → clean, `unmatched-skip` warnings zero. If `cargo tree … -i chacha20` is non-empty, that is the ws-client's `nip44` feature, not this crate's; record it in the commit message and do not widen this crate's features.

- [ ] **Step 4: The `perch` config block in `swarm-core`.** Move the skeleton's `src/config.rs` to `crates/swarm-core/src/config/perch.rs` (`git mv` is not possible across the copy; `mv crates/swarm-perch-bridge/src/config.rs crates/swarm-core/src/config/perch.rs` and delete `pub mod config;` from the bridge's `lib.rs`). Edit it:
  - delete the `watch_channel` field, its doc, its `Default` line and its `validate` clause (R-1 retired `#watch`);
  - change `validate` to return `Result<(), ConfigValidationError>` using the crate's own error type (`use super::validation::ConfigValidationError;` — the `field`/`reason` constructor pattern at `validation.rs:352-376`);
  - implement `validate`:
    ```rust
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if !self.enabled {
            return Ok(());
        }
        let relay = self.relay_url.trim();
        if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
            return Err(ConfigValidationError::invalid("perch.relay_url", "must be a ws:// or wss:// URL"));
        }
        if self.spool_dir.trim().is_empty() {
            return Err(ConfigValidationError::invalid("perch.spool_dir", "must be set when perch is enabled"));
        }
        if self.publish_tick_ms == 0 || self.frame_max_bytes == 0 || self.segment_bytes == 0 || self.spool_max_bytes < self.segment_bytes {
            return Err(ConfigValidationError::invalid("perch", "tick, frame and segment sizes must be positive and spool_max_bytes >= segment_bytes"));
        }
        if !self.case_ttl_seconds.contains_key("default") {
            return Err(ConfigValidationError::invalid("perch.case_ttl_seconds", "must carry a `default` key"));
        }
        for class in swarm_core_standard_threat_class_slugs() {
            match self.lane_channels.get(class) {
                Some(value) if uuid::Uuid::parse_str(value).is_ok() => {}
                Some(_) => return Err(ConfigValidationError::invalid("perch.lane_channels", &format!("`{class}` is not a UUID"))),
                None => return Err(ConfigValidationError::invalid("perch.lane_channels", &format!("missing lane for threat class `{class}`"))),
            }
        }
        Ok(())
    }
    ```
    where `swarm_core_standard_threat_class_slugs()` is a `const [&str; 12]` in this file listing the twelve serde names of `ThreatClass` in `standard_threat_classes()` order (`lateral_movement, data_exfiltration, privilege_escalation, command_and_control, initial_access, persistence, supply_chain, defense_evasion, credential_access, discovery, execution, impact`) — `swarm-core` cannot call `swarm_runtime::escalation::standard_threat_classes()` (layering), so the list is pinned here and a `swarm-runtime` test in Step 8 asserts the two agree. Use whichever constructor `ConfigValidationError` actually exposes (`validation.rs:352-376` shows the `field:`/`reason:` shape); `uuid` is already a `swarm-core` dependency if `grep -n '^uuid' crates/swarm-core/Cargo.toml` prints a line, otherwise add `uuid.workspace = true` there (it is a workspace dependency and TCB-neutral: `TRANSPORTS` is `axum, clap, hyper, reqwest`).
  - add `pub fn lane_channel(&self, class: &swarm_core::pheromone::ThreatClass) -> Option<uuid::Uuid>` that maps the class to its slug through `serde_json::to_value` (a `Custom(_)` class yields `None`) and parses the configured value.
  - register: `pub mod perch;` and `pub use perch::*;` in `config/mod.rs`; in `root.rs` after `pub operator: OperatorSurfaceConfig,` add `#[serde(default)] pub perch: PerchBridgeConfig,`; in `validation.rs`'s `validate` (near the `self.operator.enabled` block at `:725`) add `self.perch.validate()?;`.

- [ ] **Step 5: Config tests** in `crates/swarm-core/src/config/perch.rs`:
  ```rust
  #[cfg(test)]
  #[allow(clippy::unwrap_used, clippy::expect_used)]
  mod perch_config_tests {
      use super::*;

      #[test]
      fn the_shipped_ruleset_still_loads_with_no_perch_block() {
          let cfg: PerchBridgeConfig = serde_yaml::from_str("{}").unwrap();
          assert!(!cfg.enabled);
          assert!(cfg.validate().is_ok());
      }

      #[test]
      fn an_enabled_block_needs_all_twelve_lanes() {
          let mut cfg = PerchBridgeConfig { enabled: true, relay_url: "ws://localhost:3000".into(), spool_dir: "/tmp/x".into(), ..PerchBridgeConfig::default() };
          cfg.case_ttl_seconds.insert("default".into(), 2_592_000);
          assert!(cfg.validate().is_err());
          for slug in STANDARD_THREAT_CLASS_SLUGS {
              cfg.lane_channels.insert(slug.to_string(), "154eea36-c787-4bf7-9c84-4424b0184395".into());
          }
          assert!(cfg.validate().is_ok());
          cfg.lane_channels.insert("impact".into(), "not-a-uuid".into());
          assert!(cfg.validate().is_err());
      }

      #[test]
      fn watch_channel_is_not_a_field() {
          let err = serde_yaml::from_str::<PerchBridgeConfig>("watch_channel: abc\n").unwrap_err();
          assert!(err.to_string().contains("unknown field"), "{err}");
      }
  }
  ```
  (`serde_yaml` is a workspace dependency; add it as a `swarm-core` dev-dependency if `grep serde_yaml crates/swarm-core/Cargo.toml` is empty.)
  Run: `cargo test -p swarm-core perch_config` → compile failure until Step 4 is complete, then three passes.

- [ ] **Step 6: `lib.rs`.** Keep the skeleton's doc comment and the two headings verbatim. Replace the `use` block and `BridgeBuildInput` with:
  ```rust
  #![forbid(unsafe_code)]

  pub mod cards;
  pub mod error;
  pub mod identity;
  pub mod metrics;
  pub mod pacer;
  pub mod publish;
  pub mod receive;
  pub mod spool;
  pub mod stream;

  use std::sync::Arc;

  use swarm_core::config::{OperatorPrincipalConfig, PerchBridgeConfig};
  use swarm_core::types::AgentId;
  use swarm_runtime::containment::ContainmentSweep;
  use swarm_runtime::runtime_events::RuntimeEvent;
  use tokio::sync::{broadcast, watch};

  pub use error::BridgeError;
  pub use stream::Stream;

  /// Everything `swarm_detect` hands the bridge at startup.
  pub struct BridgeBuildInput {
      pub config: PerchBridgeConfig,
      /// Namespaces every `seq`. `swarm_detect` passes `config.name`.
      pub colony_id: String,
      /// `None` means the daemon has no `RuntimeEventBroadcaster`; startup fails loudly.
      pub events: Option<broadcast::Receiver<RuntimeEvent>>,
      /// The `Vec<AgentId>` handed to `dispatcher.set_admitted_identities`, cloned before the move.
      pub admitted_identities: Vec<AgentId>,
      /// The daemon's persisted Whisker "primary" identity. Finding cards from the HTTP
      /// ingest lane carry no producer id, so this is the issuer they are attributed to.
      pub ingest_identity: AgentId,
      /// `config.operator.auth.effective_principals()`; the Approve-scoped ones with a
      /// `nostr_pubkey` are added to every case channel the bridge creates.
      pub operator_principals: Vec<OperatorPrincipalConfig>,
      /// The process's one sweep, or `None` on the shipped default.
      pub containment: Option<Arc<ContainmentSweep>>,
      pub shutdown: watch::Receiver<bool>,
  }
  ```
  Leave `PerchBridge::build`, `metrics_router` and `run` with their skeleton signatures and `todo!` bodies; Task 8 fills them. Do not declare `channels`, `coalesce` or `leases`: Task 13 creates the first with working code; Operator-complete creates the latter two with working code.

- [ ] **Step 7: `error.rs`.** Delete `WatchChannelMembership` (R-1). Change `Ws(#[from] crate::ws::WsClientError)` to `Ws(#[from] ambush_ws_client::WsClientError)`. Add:
  ```rust
      #[error("the perch bridge cannot serialise a record: {0}")]
      Encode(String),

      #[error("perch bridge shut down before the frame was acknowledged")]
      ShuttingDown,
  ```

- [ ] **Step 8: `stream.rs` — implement `redact_in_place` and write the tests.** Replace the `todo!`:
  ```rust
  pub fn redact_in_place(event: &mut RuntimeEvent) -> usize {
      match event {
          RuntimeEvent::AgentAction { details, .. } => {
              *details = serde_json::Value::Null;
              0
          }
          RuntimeEvent::TamperAlert { unexpected_library_loads, .. } => {
              let count = unexpected_library_loads.len();
              unexpected_library_loads.clear();
              count
          }
          _ => 0,
      }
  }
  ```
  (`_` is acceptable here and only here: redaction is an allow-list of fields to strip, and a new variant must default to "strip nothing" — the opposite of `classify`, whose exhaustiveness is the point. If `AgentAction.details` is not a `serde_json::Value` in `runtime_events.rs`, assign that field's `Default::default()` instead.) Return the library-load count so the receive loop can count it. Tests, in a `#[cfg(test)] mod tests` with the allow line:
  ```rust
  fn event(json: serde_json::Value) -> RuntimeEvent {
      serde_json::from_value(json).unwrap()
  }

  #[test]
  fn a_finding_is_evidence_and_a_mode_transition_is_alarm() {
      let finding = event(serde_json::json!({
          "event_type": "finding", "emitted_at_ms": 1, "host_id": "web-04",
          "finding": {"schema": "swarm_finding", "finding_id": "f1", "event_id": "e1",
                      "strategy_id": "dns_exfil_beaconing", "threat_class": "data_exfiltration",
                      "severity": "HIGH", "confidence": 0.82, "evidence": {}}
      }));
      assert_eq!(classify(&finding), Stream::Evidence);
      let mode = event(serde_json::json!({
          "event_type": "mode_transition", "emitted_at_ms": 1, "from": "normal", "to": "incident",
          "triggering_threat_class": null, "reason": "test"
      }));
      assert_eq!(classify(&mode), Stream::Alarm);
      assert!(Stream::Evidence.is_disk_spooled() && Stream::Alarm.is_disk_spooled());
      assert!(!Stream::Telemetry.is_disk_spooled() && !Stream::DroppedAtSource.is_disk_spooled());
  }

  #[test]
  fn classify_has_no_wildcard_arm() {
      // The compile-time guarantee, made greppable: a `_ =>` inside classify would
      // let a new RuntimeEvent variant land in a stream nobody chose.
      let src = include_str!("stream.rs");
      let body = src.split("pub fn classify").nth(1).unwrap().split("pub fn redact_in_place").next().unwrap();
      assert!(!body.contains("_ =>"), "classify must stay exhaustive");
  }

  #[test]
  fn redaction_strips_library_paths_and_reports_the_count() {
      let mut tamper = event(serde_json::json!({
          "event_type": "tamper_alert", "emitted_at_ms": 1, "debugger_attached": false,
          "tracer_pid": null, "unexpected_library_loads": ["/tmp/a.so", "/tmp/b.so"], "fail_closed": true
      }));
      assert_eq!(redact_in_place(&mut tamper), 2);
      assert!(matches!(tamper, RuntimeEvent::TamperAlert { ref unexpected_library_loads, .. } if unexpected_library_loads.is_empty()));
  }
  ```
  The `tamper_alert` JSON must carry every non-default field of that variant (`runtime_events.rs:249-256`); read the variant and add any field this test omits. Also add, in `crates/swarm-runtime/src/escalation.rs`'s test module, `fn standard_threat_class_slugs_match_swarm_core_config() { assert_eq!(standard_threat_classes().iter().map(|c| serde_json::to_value(c).unwrap().as_str().unwrap().to_string()).collect::<Vec<_>>(), swarm_core::config::STANDARD_THREAT_CLASS_SLUGS) }` so the pinned list in `swarm-core` cannot drift from the runtime's.

  Add the W3-27 conversion functions beside `classify`: exhaustive matches from
  `ThreatClass`, `Severity`, roles and response records into the wire-owned DTOs.
  `finding_to_wire` copies all `SwarmFindingEnvelope` fields and redacts nothing;
  redaction remains the separate step above. Add a test that constructs every standard
  threat class plus `Custom("vendor_class")`, converts each, serializes it, and asserts
  the exact schema spelling.

  Add `tests/wire_parity.rs`. For every golden envelope, remove `envelope_hash` and
  `signature`, then assert
  `swarm_perch_wire::envelope::canonical_bytes(value)` equals the canonical bytes used
  by `swarm_spine` and that both hash implementations produce the vector's
  `envelope_hash`. Include RFC 8785's number/string edge vectors already vendored by the
  spine tests. This is the differential control that permits the bridge to sign with
  `swarm-crypto` while the desktop verifies the same wire bytes independently.

- [ ] **Step 9: Run.**
  `cargo test -p swarm-perch-bridge stream` and `cargo test -p swarm-perch-bridge wire_parity` pass (the rest of the crate is `todo!` bodies, which compile). `cargo test -p swarm-runtime standard_threat_class_slugs` → passed. `cargo clippy -p swarm-perch-bridge -p swarm-core --all-targets -- -D warnings` → clean.

- [ ] **Step 10: Commit.**
  ```bash
  git add Cargo.toml Cargo.lock deny.toml crates/swarm-perch-bridge crates/swarm-core crates/swarm-runtime/src/escalation.rs
  git commit -s -m "feat(perch-bridge): crate scaffold, the perch config block, and the exhaustive stream classifier"
  ```
  This is a local checkpoint only. It and the Task 4–7 checkpoints are fixed up or
  squashed into Task 8 before the branch is shared; the atomic-unit rule above is a
  delivery gate, not optional history hygiene.

### Task 4: The spool — segments, CRC-32C, per-issuer `seq`, cursor, crash safety

**Files:**
- Modify: `crates/swarm-perch-bridge/src/spool/{mod,segment,checksum}.rs`
- Create: `crates/swarm-perch-bridge/src/spool/cursor.rs`
- Test: `cargo test -p swarm-perch-bridge spool`

**Interfaces:**
- Consumes: `crc32c(&[u8]) -> u32` (skeleton, complete); `BridgeError::{SpoolIo, SpoolBadMagic, SpoolUnknownFormat, SpoolColonyMismatch, SpoolDirInsideWorkspace, Encode}`.
- Produces (used by Tasks 5, 8, 13):
  - `spool::{Seq = u64, IssuerIdx = u8, Record { seq, emitted_at_ms, issuer, flags: RecordFlags, payload: Vec<u8> }, RecordFlags, GapCause, GapSlot}`; `Record::from_event(&RuntimeEvent, issuer: IssuerIdx) -> Result<Record, BridgeError>` (serialises with `serde_json::to_vec`, `emitted_at_ms = event.emitted_at_ms()`, `seq = 0`).
  - `trait Spool: Send { fn append(&mut self, record: Record) -> Result<Seq, BridgeError>; fn peek(&mut self, max_bytes: usize) -> Result<Vec<Record>, BridgeError>; fn commit_through(&mut self, seq: Seq) -> Result<(), BridgeError>; fn mark_gap(&mut self, cause: GapCause); fn take_gaps(&mut self) -> Vec<GapCause>; fn bytes(&self) -> u64; }`
  - `DiskSpool::open(dir: &Path, colony_id: &str, stream: Stream, segment_bytes: u64, max_bytes: u64) -> Result<DiskSpool, BridgeError>`; `MemorySpool::new()`; `SpoolSet::open(root: &Path, colony_id: &str, segment_bytes: u64, max_bytes: u64) -> Result<SpoolSet, BridgeError>`; `SpoolSet::append(&mut self, stream: Stream, record: Record) -> Result<Option<Seq>, BridgeError>` (`None` for `DroppedAtSource`); `SpoolSet::mark_gap_all_disk_spooled(&mut self, cause: GapCause)`; `SpoolSet::evidence(&mut self) -> &mut DiskSpool`; `SpoolSet::alarm(&mut self) -> &mut DiskSpool`.
  - `Seq` semantics: per `(colony_id, issuer)`, assigned at append, starting at 1, persisted in the cursor so a restart continues the run.

- [ ] **Step 1: Write the failing round-trip and crash tests** in `spool/mod.rs`'s test module (`#[cfg(test)] #[allow(clippy::unwrap_used, clippy::expect_used)] mod tests`):
  ```rust
  use super::*;
  use crate::stream::Stream;

  fn rec(issuer: IssuerIdx, payload: &[u8]) -> Record {
      Record { seq: 0, emitted_at_ms: 1_700_000_000_000, issuer, flags: RecordFlags::default(), payload: payload.to_vec() }
  }

  #[test]
  fn seq_is_assigned_at_append_per_issuer_and_survives_reopen() {
      let dir = tempfile::tempdir().unwrap();
      {
          let mut spool = DiskSpool::open(dir.path(), "colony-a", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
          assert_eq!(spool.append(rec(0, b"a")).unwrap(), 1);
          assert_eq!(spool.append(rec(1, b"b")).unwrap(), 1);
          assert_eq!(spool.append(rec(0, b"c")).unwrap(), 2);
          // dropped without seal(): the page cache is the only copy.
      }
      let mut spool = DiskSpool::open(dir.path(), "colony-a", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
      let records = spool.peek(usize::MAX).unwrap();
      assert_eq!(records.iter().map(|r| (r.issuer, r.seq)).collect::<Vec<_>>(), vec![(0, 1), (1, 1), (0, 2)]);
      assert_eq!(spool.append(rec(0, b"d")).unwrap(), 3, "seq continues across a restart");
  }

  #[test]
  fn commit_through_advances_and_peek_never_returns_committed_records() {
      let dir = tempfile::tempdir().unwrap();
      let mut spool = DiskSpool::open(dir.path(), "c", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
      for p in [b"1", b"2", b"3"] { spool.append(rec(0, p)).unwrap(); }
      spool.commit_through(2).unwrap();
      let left = spool.peek(usize::MAX).unwrap();
      assert_eq!(left.len(), 1);
      assert_eq!(left[0].payload, b"3");
  }

  #[test]
  fn a_torn_tail_is_truncated_and_recorded_as_a_gap() {
      let dir = tempfile::tempdir().unwrap();
      {
          let mut spool = DiskSpool::open(dir.path(), "c", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
          spool.append(rec(0, b"whole")).unwrap();
          spool.append(rec(0, b"torn-away")).unwrap();
          spool.seal().unwrap();
      }
      // Chop the last 4 bytes of the only segment: a crash mid-write.
      let seg = segment::list_segments(&dir.path().join("evidence")).unwrap().pop().unwrap();
      let bytes = std::fs::read(&seg).unwrap();
      std::fs::write(&seg, &bytes[..bytes.len() - 4]).unwrap();
      let mut spool = DiskSpool::open(dir.path(), "c", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
      let records = spool.peek(usize::MAX).unwrap();
      assert_eq!(records.len(), 1);
      assert_eq!(records[0].payload, b"whole");
      assert_eq!(spool.take_gaps(), vec![GapCause::SpoolTornTail { from_seq: 2, to_seq: 2 }]);
  }

  #[test]
  fn a_spool_from_another_colony_is_refused() {
      let dir = tempfile::tempdir().unwrap();
      DiskSpool::open(dir.path(), "colony-a", Stream::Evidence, 1 << 20, 8 << 20).unwrap()
          .append(rec(0, b"x")).unwrap();
      let err = DiskSpool::open(dir.path(), "colony-b", Stream::Evidence, 1 << 20, 8 << 20).unwrap_err();
      assert!(matches!(err, BridgeError::SpoolColonyMismatch { .. }), "{err}");
  }

  #[test]
  fn eviction_unlinks_the_oldest_segment_and_records_the_range() {
      let dir = tempfile::tempdir().unwrap();
      // 4 KiB segments, 8 KiB budget: the third segment evicts the first.
      let mut spool = DiskSpool::open(dir.path(), "c", Stream::Evidence, 4096, 8192).unwrap();
      let payload = vec![b'x'; 1000];
      for _ in 0..12 { spool.append(Record { payload: payload.clone(), ..rec(0, b"") }).unwrap(); }
      let gaps = spool.take_gaps();
      assert!(matches!(gaps.first(), Some(GapCause::SpoolEvicted { from_seq: 1, .. })), "{gaps:?}");
      assert!(spool.bytes() <= 8192 + 4096, "budget is enforced at segment granularity");
  }

  #[test]
  fn the_spool_root_may_not_be_inside_the_workspace() {
      let inside = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("spool-test");
      let err = SpoolSet::open(&inside, "c", 1 << 20, 8 << 20).unwrap_err();
      assert!(matches!(err, BridgeError::SpoolDirInsideWorkspace { .. }));
  }
  ```
  Add `SpoolTornTail { from_seq: Seq, to_seq: Seq }` to `GapCause` (the skeleton folds torn tails into `SpoolEvicted`; the metric label set names `spool_torn_tail` separately, so the cause is separate too), and derive `Serialize, Deserialize` on `GapCause` and `GapSlot` (the cursor persists them).

- [ ] **Step 2: Run to see them fail.**
  Run: `cargo test -p swarm-perch-bridge spool`
  Expected: compile errors (`DiskSpool` undefined, `seal` undefined) — then `not yet implemented` panics once the types exist.

- [ ] **Step 3: `segment.rs` — the codec and the scan.** Replace every `todo!` with real code. The on-disk layout is the skeleton's header comment, byte for byte (48-byte header, 26-byte record prefix). Implementation outline that the tests pin:
  ```rust
  pub struct Segment { path: PathBuf, file: std::fs::File, end: u64, pub first_seq: Seq, pub last_seq: Option<Seq> }

  impl SegmentHeader {
      pub fn encode(&self) -> [u8; HEADER_BYTES] {
          let mut out = [0u8; HEADER_BYTES];
          out[0..8].copy_from_slice(MAGIC);
          out[8..10].copy_from_slice(&self.format_version.to_le_bytes());
          out[10] = self.stream;
          out[12..20].copy_from_slice(&self.first_seq.to_le_bytes());
          out[20..28].copy_from_slice(&self.created_at_ms.to_le_bytes());
          out[28..44].copy_from_slice(&self.colony_hash);
          let crc = crate::spool::checksum::crc32c(&out[0..44]);
          out[44..48].copy_from_slice(&crc.to_le_bytes());
          out
      }
      pub fn decode(bytes: &[u8], expect_colony_hash: &[u8; 16], path: &Path) -> Result<Self, BridgeError> { /* verify length, MAGIC, version, crc, colony hash; map each failure to its BridgeError variant carrying path.display().to_string() */ }
  }

  pub fn encode_record(record: &Record) -> Vec<u8> {
      let mut body = Vec::with_capacity(RECORD_PREFIX_BYTES + record.payload.len());
      body.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
      body.extend_from_slice(&[0u8; 4]); // crc placeholder
      body.extend_from_slice(&record.seq.to_le_bytes());
      body.extend_from_slice(&record.emitted_at_ms.to_le_bytes());
      body.push(record.issuer);
      body.push(record.flags.0);
      body.extend_from_slice(&record.payload);
      let crc = crate::spool::checksum::crc32c(&body[8..]);
      body[4..8].copy_from_slice(&crc.to_le_bytes());
      body
  }

  /// `Ok(Some((record, consumed)))`, `Ok(None)` at a clean EOF, `Err(())` on a short or corrupt record.
  pub fn decode_record(bytes: &[u8]) -> Result<Option<(Record, usize)>, ()> { /* length, then crc over [8..26+len], then fields */ }
  ```
  `Segment::create` writes the header with `File::create_new` (fails if the segment exists); `Segment::open_and_scan` decodes the header, loops `decode_record` from `HEADER_BYTES`, and returns `TailVerdict::Clean` when the loop ends exactly at EOF, `TailVerdict::TornTail { last_valid_seq, truncate_at, burned: (next_seq, next_seq) }` when a decode fails **at the end** of the file (the caller truncates with `file.set_len(truncate_at)`), and `TailVerdict::Corrupt { range }` when a decode fails and valid records follow (the caller renames to `*.seg.corrupt`). `Segment::append` uses a `BufWriter`-free `write_all` on the raw `File` (one syscall, page cache only) and returns the new end offset; `seal` is `flush` + `sync_all`; `list_segments` sorts by file name (`{first_seq:020}.seg`). `bytes()` returns the cached end offset. No `unwrap`, no `expect`: every `io::Error` maps to `BridgeError::SpoolIo { path, source }`.

- [ ] **Step 4: `cursor.rs` — the committed offset and the gap slot, durable.**
  ```rust
  //! `CURSOR.json` beside the segments. Written with write-then-rename so a crash
  //! mid-write leaves the previous cursor intact. Holds the one thing that must
  //! survive a crash: the record that something did not.
  #[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
  pub struct Cursor {
      /// Highest seq the relay has acknowledged, per issuer index.
      pub committed: std::collections::BTreeMap<IssuerIdx, Seq>,
      /// Next seq to assign, per issuer index.
      pub next_seq: std::collections::BTreeMap<IssuerIdx, Seq>,
      pub gaps: GapSlot,
  }
  impl Cursor {
      pub fn load(dir: &Path) -> Result<Self, BridgeError> { /* absent file → Default */ }
      pub fn store(&self, dir: &Path) -> Result<(), BridgeError> { /* serde_json to CURSOR.json.tmp, sync, rename */ }
  }
  ```
  A record is "committed" when `record.seq <= committed[record.issuer]`. `peek` walks segments oldest-first from the first uncommitted record and returns up to `max_bytes` of payload.

- [ ] **Step 5: `mod.rs` — `DiskSpool`, `MemorySpool`, `SpoolSet`.**
  ```rust
  pub struct DiskSpool {
      dir: PathBuf,
      stream: Stream,
      colony_hash: [u8; 16],
      segment_bytes: u64,
      max_bytes: u64,
      active: Segment,
      sealed: Vec<PathBuf>,
      cursor: Cursor,
      bytes: u64,
  }
  ```
  `open` computes `colony_hash = sha256(colony_id)[..16]`, creates `dir/<stream.as_str()>/`, scans every segment (`list_segments`), applies each `TailVerdict` (truncate → `mark_gap(SpoolTornTail{..})`; corrupt → rename and `mark_gap(SpoolEvicted{..})`), refuses on `SpoolColonyMismatch`, opens the newest segment as `active` (or creates one), loads the cursor, sums bytes. `append` assigns `seq = next_seq[issuer]` (default 1), writes, bumps `next_seq`, stores the cursor **only when a segment rolls** (the seq high-water is recoverable from the segments themselves on reopen: the scan sets `next_seq[i] = max(seen)+1` before the cursor's value is trusted), rolls when `active.bytes() >= segment_bytes` (`seal`, push to `sealed`, create the next), and evicts while `bytes > max_bytes` by unlinking the oldest sealed segment and marking `SpoolEvicted { from_seq: its first_seq, to_seq: its last_seq }`. `commit_through(seq)` sets `committed[issuer of that seq]` — since `peek` returns records in file order across issuers, the pacer commits per record: change the trait signature to `commit(&mut self, issuer: IssuerIdx, seq: Seq)` and store the cursor on every commit (one small write per acknowledged frame, off the receive loop). `MemorySpool` keeps `BTreeMap<String, Record>` keyed by a caller-supplied key (the telemetry stream's last-wins slot; unused by this milestone's publisher). `SpoolSet::open` refuses a root under the workspace by canonicalising both and testing `starts_with` on the directory that holds `Cargo.toml` two levels above `CARGO_MANIFEST_DIR` at build time and on `std::env::current_dir()` at run time.

- [ ] **Step 6: Run.**
  Run: `cargo test -p swarm-perch-bridge spool`
  Expected: `seq_is_assigned_at_append_per_issuer_and_survives_reopen`, `commit_through_advances_and_peek_never_returns_committed_records` (rewritten to `commit(0, 2)`), `a_torn_tail_is_truncated_and_recorded_as_a_gap`, `a_spool_from_another_colony_is_refused`, `eviction_unlinks_the_oldest_segment_and_records_the_range`, `the_spool_root_may_not_be_inside_the_workspace`, plus the three `checksum` tests → 9 passed. `cargo clippy -p swarm-perch-bridge --all-targets -- -D warnings` clean; `bash tools/check-runtime-panic-contract.sh` clean.

- [ ] **Step 7: Commit.** `git add crates/swarm-perch-bridge/src/spool && git commit -s -m "feat(perch-bridge): the disk spool — segments, CRC-32C, per-issuer seq, durable cursor, torn-tail recovery"`

### Task 5: The receive loop, its import discipline, and the lag-to-gap path

**Files:**
- Modify: `crates/swarm-perch-bridge/src/receive.rs`, `crates/swarm-perch-bridge/src/metrics.rs` (only the two methods the loop calls)
- Test: `cargo test -p swarm-perch-bridge receive`

**Interfaces:**
- Consumes: `SpoolSet::{append, mark_gap_all_disk_spooled}`, `stream::{classify, redact_in_place}`, `Record::from_event`.
- Produces (used by Task 8): `receive::run(rx: broadcast::Receiver<RuntimeEvent>, spools: Arc<Mutex<SpoolSet>>, metrics: BridgeMetrics, issuer_of: Arc<dyn Fn(&RuntimeEvent) -> IssuerIdx + Send + Sync>, stall: Arc<AtomicU64>, shutdown: watch::Receiver<bool>) -> Result<(), BridgeError>`; `BridgeMetrics::{ingested(Stream), broadcast_lagged(u64), redacted_library_loads(usize)}` (these two-three methods are implemented now; the registry constructor is Task 8).

- [ ] **Step 1: Write the failing tests** in `receive.rs`'s test module:
  ```rust
  #[tokio::test]
  async fn a_lagged_receiver_marks_a_gap_on_every_disk_spooled_stream() {
      let dir = tempfile::tempdir().unwrap();
      let spools = Arc::new(Mutex::new(SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap()));
      let (tx, rx) = broadcast::channel::<RuntimeEvent>(4);
      let (shutdown_tx, shutdown_rx) = watch::channel(false);
      let (metrics, _registry) = BridgeMetrics::new();
      // Overrun the 4-slot buffer BEFORE the loop polls it: six sends, two lost.
      for i in 0..6 { tx.send(finding_event(i)).unwrap(); }
      let handle = tokio::spawn(run(rx, Arc::clone(&spools), metrics, Arc::new(|_| 0), Arc::new(AtomicU64::new(0)), shutdown_rx));
      tokio::time::sleep(std::time::Duration::from_millis(50)).await;
      shutdown_tx.send(true).unwrap();
      handle.await.unwrap().unwrap();
      let mut spools = spools.lock().unwrap();
      assert_eq!(spools.evidence().take_gaps(), vec![GapCause::BroadcastLagged { count: 2 }]);
      assert_eq!(spools.alarm().take_gaps(), vec![GapCause::BroadcastLagged { count: 2 }]);
      assert_eq!(spools.evidence().peek(usize::MAX).unwrap().len(), 4, "the four that survived were spooled");
  }

  #[test]
  fn the_receive_loop_imports_only_stream_spool_and_metrics() {
      let src = include_str!("receive.rs");
      for forbidden in ["crate::publish", "crate::pacer", "crate::channels", "crate::identity", "ambush_ws_client", "nostr::", "reqwest"] {
          assert!(!src.contains(forbidden), "receive.rs must not name {forbidden}");
      }
  }
  ```
  with `finding_event(i)` building a `RuntimeEvent::Finding` via `serde_json::from_value` as in Task 3's test (vary `finding_id`).

- [ ] **Step 2: Run** → compile failure (`run`'s signature differs; `BridgeMetrics::new` is `todo!`).

- [ ] **Step 3: Implement.** The loop body is the skeleton's (`biased;`, the `Lagged` arm counting and marking, the `Closed` arm), with three changes: `spools` is `Arc<Mutex<SpoolSet>>` locked per event (`std::sync::Mutex`, held for the append only — the pacer holds it for a peek or a commit, never across an await); `issuer_of(&event)` supplies the `IssuerIdx` (this milestone maps every event to index 0, the ingest identity; the table lives in Task 7); and the debug-only stall hook before `recv()`:
  ```rust
  #[cfg(debug_assertions)]
  {
      let ms = stall.swap(0, std::sync::atomic::Ordering::AcqRel);
      if ms > 0 {
          tracing::warn!(module = module_path!(), ms, "perch bridge receive loop stalled on request (test hook)");
          tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
      }
  }
  ```
  In `metrics.rs`, give `BridgeMetrics` real fields for `ingested: Family<StreamLabel, Counter>`, `broadcast_lagged: Counter<u64>`, `redacted_library_loads: Counter<u64>` and implement the three methods; leave the rest of `new()` for Task 8 but make it return a registry with these three registered so this task's test compiles (the seven appendix names are asserted in Task 8).

- [ ] **Step 4: Run** → 2 passed. Clippy and the panic gate clean.
- [ ] **Step 5: Commit.** `git commit -s -am "feat(perch-bridge): the receive loop — recv, classify, append, and a lag becomes a counted gap"`

### Task 6: Decision D-FC-1 — the derivation domain string and how the seed reaches the daemon

**Files:**
- Modify: `docs/plans/ambush-ui/integration/00-DECISIONS.md` (§3 table)

**Interfaces:**
- Produces: the row below, and the values Task 7 compiles in: `DERIVATION_DOMAIN`, `PerchBridgeConfig.nostr_seed_env`'s default.

- [ ] **Step 1: Record the decision** by appending to the §3 table in `00-DECISIONS.md`:
  ```markdown
  | **D-FC-1** — secp256k1 key derivation for the bridge identities | **Default the plan builds under:** `DERIVATION_DOMAIN = b"swarm.perch.bridge.nostr.v1"`; `nostr_secret[slot] = SHA-256(DOMAIN ‖ 0x00 ‖ root ‖ 0x00 ‖ colony_id ‖ 0x00 ‖ slot.label())`; the 32-byte root is read once at startup from the env var named by `perch.nostr_seed_env` (default `PERCH_BRIDGE_NOSTR_SEED`, 64 hex chars), never from a file in the repo. **Options:** (a) keep the skeleton's `ambush.perch.bridge.nostr.v1` — rejected only for namespace consistency with `swarm.perch.<card>.v1` (D1); (b) a file path under `runtime.secret_dir` via the `@secret:file-name` adapter — deferred, same code path once the adapter is wired; (c) per-agent keys minted by `FileAgentKeyStore` and converted — rejected: those are Ed25519 and the relay needs secp256k1. **Consequence:** changing the string after first provisioning rotates every bridge key and invalidates every relay membership; it is versioned (`.v1`) and never edited in place. **Dependents:** Task 7 (identity), Task 14 (`.env.perch`). | project owner, on spec review; the default ships unless overridden before Task 7 lands |
  ```
- [ ] **Step 2: Commit.** `git add docs/plans/ambush-ui/integration/00-DECISIONS.md && git commit -s -m "docs(decisions): D-FC-1 bridge key derivation domain and seed provisioning"`

### Task 7: Identity derivation, NIP-42 over the path-dependency ws-client, and one published event

> Blocked on D-FC-1 (Task 6); built under its default.

**Files:**
- Modify: `crates/swarm-perch-bridge/src/identity.rs`
- Create: `crates/swarm-perch-bridge/tests/relay_live.rs`
- Test: `cargo test -p swarm-perch-bridge identity`; `PERCH_TEST_RELAY_URL=ws://localhost:3000 cargo test -p swarm-perch-bridge --test relay_live -- --ignored --nocapture`

**Interfaces:**
- Consumes: `NostrWsConnection::connect_authenticated(url: &str, keys: &Keys, auth_tag: Option<&Tag>) -> Result<Self, WsClientError>` and `send_event(Event) -> Result<OkResponse, WsClientError>` (`workspace/crates/ambush-ws-client/src/connection.rs:37-45, :96-101`); `OperatorPrincipalConfig::{scopes, nostr_pubkey}`; `swarm_core::config::SecretString::{new, expose_secret}`.
- Produces (used by Tasks 8, 13, 14):
  - `identity::{DERIVATION_DOMAIN, Slot, Identity { slot, keys: nostr::Keys, auth_tag: Option<nostr::Tag> }, IdentityTable}`; `IdentityTable::build(seed: &SecretString, colony_id: &str, admitted: &[AgentId], ingest: &AgentId, auth_tag: Option<Tag>) -> Result<IdentityTable, BridgeError>`; `IdentityTable::get(&self, idx: IssuerIdx) -> Option<&Identity>`; `IdentityTable::index_of(&self, slot: &Slot) -> Option<IssuerIdx>`; `IdentityTable::alarm(&self) -> IssuerIdx`; `IdentityTable::ingest(&self) -> IssuerIdx`; `IdentityTable::provisioning_report(&self) -> String`; `IdentityTable::public_identities(&self) -> Vec<(String, String)>` (label, hex pubkey — what `GET /metrics/perch/identities` serves under D-FC-2);
  - `identity::normalize_p_tag(&str) -> Result<String, BridgeError>` (skeleton, complete); `identity::approve_scoped_operator_pubkeys(&[OperatorPrincipalConfig]) -> Result<Vec<String>, BridgeError>`;
  - `identity::seed_from_env(var: &str) -> Result<SecretString, BridgeError>` (64 hex → 32 bytes, else `MissingNostrSeed`).

- [ ] **Step 1: Failing unit tests** in `identity.rs`:
  ```rust
  #[test]
  fn derivation_is_deterministic_and_slot_separated() {
      let seed = SecretString::new("11".repeat(32));
      let a = AgentId("swarm:ed25519:aa".to_string());
      let t1 = IdentityTable::build(&seed, "colony", &[a.clone()], &a, None).unwrap();
      let t2 = IdentityTable::build(&seed, "colony", &[a.clone()], &a, None).unwrap();
      assert_eq!(t1.get(t1.alarm()).unwrap().keys.public_key(), t2.get(t2.alarm()).unwrap().keys.public_key());
      assert_ne!(t1.get(t1.alarm()).unwrap().keys.public_key(), t1.get(t1.ingest()).unwrap().keys.public_key());
      let other = IdentityTable::build(&seed, "other-colony", &[a.clone()], &a, None).unwrap();
      assert_ne!(t1.get(t1.alarm()).unwrap().keys.public_key(), other.get(other.alarm()).unwrap().keys.public_key());
  }

  #[test]
  fn a_short_seed_is_refused_by_name() {
      let err = seed_from_raw("PERCH_TEST_SEED_SHORT", Some("abcd")).unwrap_err();
      assert!(matches!(err, BridgeError::MissingNostrSeed { ref env } if env == "PERCH_TEST_SEED_SHORT"));
  }

  #[test]
  fn approve_scoped_pubkeys_come_only_from_principals_with_a_key() {
      let with = OperatorPrincipalConfig { operator_id: "a".into(), token_env: "T".into(), token_expires_at_ms: None, scopes: vec![OperatorScope::Approve], nostr_pubkey: Some("C0FFEE".repeat(10) + "c0ff") };
      let read_only = OperatorPrincipalConfig { scopes: vec![OperatorScope::Read], nostr_pubkey: Some("a".repeat(64)), ..with.clone() };
      let keyless = OperatorPrincipalConfig { nostr_pubkey: None, ..with.clone() };
      let keys = approve_scoped_operator_pubkeys(&[with.clone(), read_only, keyless]).unwrap();
      assert_eq!(keys, vec!["c0ffee".repeat(10) + "c0ff"], "lowercased, Approve only");
      assert!(matches!(approve_scoped_operator_pubkeys(&[]).unwrap_err(), BridgeError::HoldUndeliverable));
  }
  ```
  `seed_from_raw(var, raw: Option<&str>)` is a private pure helper; `seed_from_env` passes
  `std::env::var(var).ok().as_deref()` to it. This tests missing/invalid/short/valid inputs with
  no process-global mutation and introduces no new `unsafe` merely because older tests contain it.

- [ ] **Step 2: Run** `cargo test -p swarm-perch-bridge identity` → compile failure.

- [ ] **Step 3: Implement.**
  ```rust
  pub const DERIVATION_DOMAIN: &[u8] = b"swarm.perch.bridge.nostr.v1";

  pub fn seed_from_env(var: &str) -> Result<SecretString, BridgeError> {
      let raw = std::env::var(var).ok();
      seed_from_raw(var, raw.as_deref())
  }

  fn seed_from_raw(var: &str, raw: Option<&str>) -> Result<SecretString, BridgeError> {
      let trimmed = raw.unwrap_or_default().trim();
      let bytes = hex::decode(trimmed).unwrap_or_default();
      if bytes.len() != 32 {
          return Err(BridgeError::MissingNostrSeed { env: var.to_string() });
      }
      Ok(SecretString::new(trimmed.to_string()))
  }

  fn derive_keys(seed: &SecretString, colony_id: &str, label: &str) -> Result<nostr::Keys, BridgeError> {
      use sha2::{Digest, Sha256};
      let root = hex::decode(seed.expose_secret()).map_err(|e| BridgeError::InvalidConfig { reason: format!("seed is not hex: {e}") })?;
      let mut hasher = Sha256::new();
      for part in [DERIVATION_DOMAIN, &[0u8][..], &root, &[0u8][..], colony_id.as_bytes(), &[0u8][..], label.as_bytes()] {
          hasher.update(part);
      }
      let digest = hasher.finalize();
      let secret = nostr::SecretKey::from_slice(&digest)
          .map_err(|e| BridgeError::InvalidConfig { reason: format!("derived scalar rejected for `{label}`: {e}") })?;
      Ok(nostr::Keys::new(secret))
  }
  ```
  `IdentityTable` holds `Vec<Identity>` in slot order: index 0 = `Slot::Agent(ingest.clone())`, then one `Slot::Agent(id)` per admitted identity not equal to the ingest id, then `Slot::Telemetry`, then `Slot::Alarm` (so `alarm()` is the last index and `ingest()` is 0; `IssuerIdx` is a `u8`, and `build` refuses more than 254 slots with `InvalidConfig`). `provisioning_report` prints one line per slot: `{label}  npub={hex}  scopes={MessagesWrite|MessagesWrite,ChannelsWrite,AdminChannels}` and `build` logs it at `info` plus one `warn` per slot when `auth_tag` is `None` ("no NIP-OA owner attestation; this identity is on the 60/min human tier"). `approve_scoped_operator_pubkeys` filters `scopes.contains(&OperatorScope::Approve)`, maps `nostr_pubkey`, `normalize_p_tag`s each, and returns `HoldUndeliverable` when empty.

- [ ] **Step 4: Run** → 3 passed.

- [ ] **Step 5: The live test** — `crates/swarm-perch-bridge/tests/relay_live.rs`, `#[ignore]`d so `cargo test` needs no relay, gated on an env var so CI's engine lanes never touch the network:
  ```rust
  #![allow(clippy::unwrap_used, clippy::expect_used)]
  //! Requires a running relay (docker compose up -d postgres redis relay) and
  //! PERCH_TEST_RELAY_URL. Publishes ONE kind:9 card into the lateral_movement lane
  //! and asserts the relay's OK. Run with `-- --ignored`.
  use swarm_core::config::SecretString;
  use swarm_core::types::AgentId;
  use swarm_perch_bridge::identity::IdentityTable;
  use swarm_perch_wire::marker::{build_content, CardKind};
  use swarm_perch_wire::tags::TagSet;

  #[tokio::test]
  #[ignore = "needs PERCH_TEST_RELAY_URL and a live relay"]
  async fn one_signed_card_is_accepted_by_a_live_relay() {
      let url = std::env::var("PERCH_TEST_RELAY_URL").expect("PERCH_TEST_RELAY_URL");
      let lane = std::env::var("PERCH_TEST_LANE_CHANNEL").unwrap_or_else(|_| "154eea36-c787-4bf7-9c84-4424b0184395".into());
      let ingest = AgentId("swarm:ed25519:".to_string() + &"ab".repeat(32));
      let table = IdentityTable::build(&SecretString::new("42".repeat(32)), "relay-live", &[], &ingest, None).unwrap();
      let identity = table.get(table.ingest()).unwrap();
      let mut conn = ambush_ws_client::NostrWsConnection::connect_authenticated(&url, &identity.keys, None).await.unwrap();
      let content = build_content(CardKind::Finding, "relay-live · lateral_movement · LOW · confidence 0.10 · host unknown · finding live-1", "{\"schema\":\"swarm.spine.envelope.v1\"}").unwrap();
      let tags = TagSet::card(CardKind::Finding, lane.clone(), Some("lateral_movement".into()), Some("LOW".into()));
      tags.assert_publishable(9).unwrap();
      let nostr_tags = tags.to_tags().into_iter().map(|t| nostr::Tag::parse(t).unwrap()).collect::<Vec<_>>();
      let event = nostr::EventBuilder::new(nostr::Kind::Custom(9), content).tags(nostr_tags).sign_with_keys(&identity.keys).unwrap();
      let ok = conn.send_event(event).await.unwrap();
      assert!(ok.accepted, "relay said: {}", ok.message);
  }
  ```
  Before running it the lane must exist on the relay (Task 14's bridge startup creates it; until then create one by hand with `AMBUSH_PRIVATE_KEY=<any hex> workspace/target/release/ambush channels create --name lateral-movement --type stream --visibility open` and export its id as `PERCH_TEST_LANE_CHANNEL`). Expected: `test one_signed_card_is_accepted_by_a_live_relay ... ok`; a `restricted:` message in the assertion names the relay's actual refusal (membership, scope) and is the provisioning fact Task 14 must satisfy.

- [ ] **Step 6: Commit.** `git add crates/swarm-perch-bridge && git commit -s -m "feat(perch-bridge): derived secp256k1 identities, NIP-42 over ambush-ws-client, one live published card"`

### Task 8: Finding cards, the 1 Hz pacer, the publisher, and the metrics registry

**Files:**
- Modify: `crates/swarm-perch-bridge/src/{cards,pacer,publish,metrics,lib}.rs`
- Test: `cargo test -p swarm-perch-bridge pacer`; `cargo test -p swarm-perch-bridge metrics`; `cargo test -p swarm-perch-bridge publish`

**Interfaces:**
- Consumes: Task 1's `FindingCard`, `CardEnvelope::seal_unsigned`, `build_content`, `TagSet`, `threat_class_slug`, `severity_label`; Task 4's `SpoolSet`; Task 7's `IdentityTable`; `PerchBridgeConfig::lane_channel`.
- Produces (used by Tasks 9, 13, 14, 21):
  - `cards::{CardBody { kind: CardKind, channel: Uuid, content: String, tags: Vec<Vec<String>>, covers: (IssuerIdx, Seq) }, build_finding_card(record: &Record, event: &RuntimeEvent, issuer: &Identity, colony_id: &str, config: &PerchBridgeConfig, seq_chain: &mut SeqChain, gaps: &[GapCause], now_ms: i64) -> Result<Option<CardBody>, BridgeError>}`; `SeqChain { prev_envelope_hash: Option<String> }` per issuer (`prev_envelope_hash` chains envelopes; `seq` is the spool's).
  - `pacer::{Frame { identity: IssuerIdx, channel: Option<Uuid>, signed: nostr::Event, event_id: String, covers: (IssuerIdx, Seq), created_at_secs: i64 }, Pacer, PERCH_PUBLISH_TICK_MS, PERCH_FRAME_MAX_BYTES, PERCH_GAP_FLUSH_TICKS, PERCH_LATE_PUBLISHED_TICKS, PERCH_PUBLISH_WINDOW_MARGIN_SECS}`; `trait FramePublisher: Send { fn publish(&mut self, frame: &Frame) -> impl Future<Output = Result<OkOutcome, BridgeError>> + Send; }`; `Pacer::new(spools, identities, config, colony_id, metrics, publisher: P) -> Pacer<P>`; `Pacer::tick(&mut self, now_ms: i64) -> Result<usize, BridgeError>` (frames acknowledged this tick); `Pacer::run(self, shutdown) -> impl Future`.
  - `publish::{ConnectionSupervisor, OkOutcome, RetryDecision, PERCH_ALARM_BURST_PER_MIN, bridge_issues_no_req_frames, backoff_for}`; `ConnectionSupervisor::new(relay_url: String, identity: Identity) -> Self`; `impl FramePublisher for ConnectionSupervisor`; `ConnectionSupervisor::classify_ok(accepted, message) -> OkOutcome` (skeleton, complete).
  - `metrics::{BridgeMetrics, router(registry, identities, stall) -> axum::Router}`; `BridgeMetrics::new() -> (Self, Arc<Mutex<Registry>>)`.

- [ ] **Step 1: Failing tests.** In `cards.rs`:
  ```rust
  #[test]
  fn a_finding_record_becomes_a_three_part_card_with_the_lane_tags() {
      let (identity, config) = fixture();     // Identity for the ingest slot; config with twelve lanes, colony "c"
      let event = finding_event("f2c9a1b4", "data_exfiltration", "HIGH");
      let record = Record { seq: 41, ..Record::from_event(&event, 0).unwrap() };
      let mut chain = SeqChain::default();
      let body = build_finding_card(&record, &event, &identity, "c", &config, &mut chain, &[], 1_700_000_005_000).unwrap().unwrap();
      assert_eq!(body.content.lines().next(), Some("<!-- swarm:finding:v1 -->"));
      assert!(body.content.lines().nth(1).unwrap().contains("data_exfiltration · HIGH · confidence"));
      let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
      let envelope: swarm_perch_wire::CardEnvelope = serde_json::from_str(parts.json).unwrap();
      assert_eq!(envelope.seq, 41);
      assert!(envelope.is_tier_zero());
      assert_eq!(envelope.fact["schema"], "swarm.perch.finding.v1");
      assert_eq!(envelope.fact["locator"]["lane_channel"], config.lane_channels["data_exfiltration"]);
      assert_eq!(envelope.fact["issuer"]["swarm_agent_id"], identity.slot.label());
      assert_eq!(body.tags, vec![
          vec!["h".to_string(), config.lane_channels["data_exfiltration"].clone()],
          vec!["t".to_string(), "data_exfiltration".to_string()],
          vec!["l".to_string(), "HIGH".to_string()],
          vec!["k".to_string(), "finding".to_string()],
      ]);
      assert_eq!(chain.prev_envelope_hash.as_deref(), Some(envelope.envelope_hash.as_str()));
  }

  #[test]
  fn a_pending_gap_rides_inside_the_next_card() {
      let (identity, config) = fixture();
      let event = finding_event("f1", "execution", "LOW");
      let record = Record::from_event(&event, 0).unwrap();
      let gaps = vec![GapCause::BroadcastLagged { count: 7 }];
      let body = build_finding_card(&record, &event, &identity, "c", &config, &mut SeqChain::default(), &gaps, 1).unwrap().unwrap();
      let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
      let fact: serde_json::Value = serde_json::from_str::<serde_json::Value>(parts.json).unwrap()["fact"].clone();
      assert_eq!(fact["gap"]["cause"], "broadcast_lagged");
      assert_eq!(fact["gap"]["count"], 7);
      assert!(fact["gap"].get("from_seq").is_none(), "a lag has no seq range, ever");
  }

  #[test]
  fn oversized_evidence_is_replaced_by_a_byte_count_and_a_hash() {
      let (identity, config) = fixture();
      let mut event = finding_event("big", "impact", "CRITICAL");
      if let RuntimeEvent::Finding { finding, .. } = &mut event { finding.evidence = serde_json::json!({ "blob": "x".repeat(CARD_CONTENT_MAX_BYTES) }); }
      let record = Record::from_event(&event, 0).unwrap();
      let body = build_finding_card(&record, &event, &identity, "c", &config, &mut SeqChain::default(), &[], 1).unwrap().unwrap();
      assert!(body.content.len() <= CARD_CONTENT_MAX_BYTES);
      let parts = swarm_perch_wire::marker::parse_content(&body.content).unwrap();
      let fact: serde_json::Value = serde_json::from_str::<serde_json::Value>(parts.json).unwrap()["fact"].clone();
      assert_eq!(fact["finding"]["evidence"], serde_json::Value::Null);
      assert!(fact["evidence_truncated"]["bytes"].as_u64().unwrap() > CARD_CONTENT_MAX_BYTES as u64);
      assert!(fact["evidence_truncated"]["sha256"].as_str().unwrap().starts_with("0x"));
  }

  #[test]
  fn a_non_finding_evidence_record_builds_no_card() {
      let (identity, config) = fixture();
      let event: RuntimeEvent = serde_json::from_value(serde_json::json!({
          "event_type": "escalation", "emitted_at_ms": 1, "threat_class": "execution", "level": "alert",
          "total_strength": 2.5, "distinct_sources": 2, "peak_confidence": 0.9, "mode_changed": false, "current_mode": "alert"
      })).unwrap();
      let record = Record::from_event(&event, 0).unwrap();
      assert!(build_finding_card(&record, &event, &identity, "c", &config, &mut SeqChain::default(), &[], 1).unwrap().is_none());
  }
  ```
  In `pacer.rs`, a recording publisher and the tick contract:
  ```rust
  struct Recording { frames: Vec<Frame>, answer: OkOutcome }
  impl FramePublisher for Recording {
      async fn publish(&mut self, frame: &Frame) -> Result<OkOutcome, BridgeError> { self.frames.push(frame.clone()); Ok(self.answer.clone()) }
  }

  #[tokio::test]
  async fn one_tick_publishes_one_card_per_identity_and_commits_only_on_ok() {
      let (spools, identities, config, metrics) = harness();
      for i in 0..3 { spools.lock().unwrap().append(Stream::Evidence, Record::from_event(&finding_event(&format!("f{i}"), "execution", "LOW"), 0).unwrap()).unwrap(); }
      let mut pacer = Pacer::new(Arc::clone(&spools), identities, config, "c".into(), metrics, Recording { frames: vec![], answer: OkOutcome::Accepted });
      assert_eq!(pacer.tick(1_700_000_000_000).unwrap(), 1);
      assert_eq!(pacer.tick(1_700_000_001_000).unwrap(), 1);
      assert_eq!(pacer.tick(1_700_000_002_000).unwrap(), 1);
      assert_eq!(pacer.tick(1_700_000_003_000).unwrap(), 0, "nothing left");
      assert!(spools.lock().unwrap().evidence().peek(usize::MAX).unwrap().is_empty());
      let frames = &pacer.publisher().frames;
      assert_eq!(frames.len(), 3);
      assert_eq!(frames[0].signed.kind.as_u16(), 9);
      assert_eq!(frames[0].signed.content.lines().next(), Some("<!-- swarm:finding:v1 -->"));
      // created_at is the drain instant, not the domain instant.
      assert_eq!(frames[0].created_at_secs, 1_700_000_000);
  }

  #[tokio::test]
  async fn a_rejected_frame_is_not_committed_and_a_lag_gap_flushes_on_the_next_card() {
      let (spools, identities, config, metrics) = harness();
      spools.lock().unwrap().append(Stream::Evidence, Record::from_event(&finding_event("f0", "execution", "LOW"), 0).unwrap()).unwrap();
      let mut pacer = Pacer::new(Arc::clone(&spools), identities, config, "c".into(), metrics, Recording { frames: vec![], answer: OkOutcome::Rejected { message: "blocked".into() } });
      assert_eq!(pacer.tick(1_700_000_000_000).unwrap(), 0);
      assert_eq!(spools.lock().unwrap().evidence().peek(usize::MAX).unwrap().len(), 1, "still at the head");
      spools.lock().unwrap().mark_gap_all_disk_spooled(GapCause::BroadcastLagged { count: 3 });
      pacer.publisher_mut().answer = OkOutcome::Accepted;
      assert_eq!(pacer.tick(1_700_000_001_000).unwrap(), 1);
      let content = &pacer.publisher().frames.last().unwrap().signed.content;
      assert!(content.contains("\"gap\":{\"cause\":\"broadcast_lagged\",\"count\":3"));
  }
  ```
  In `metrics.rs`:
  ```rust
  #[test]
  fn the_seven_appendix_names_encode_exactly_once_without_a_double_total() {
      let (_m, registry) = BridgeMetrics::new();
      let mut out = String::new();
      prometheus_client::encoding::text::encode(&mut out, &registry.lock().unwrap()).unwrap();
      for name in ["perch_bridge_broadcast_lagged_total", "perch_bridge_spool_bytes", "perch_bridge_dropped_events_total", "perch_bridge_alarm_spool_full_total", "perch_bridge_publish_latency_seconds", "perch_bridge_admission_rejections_total", "perch_bridge_late_published_seconds"] {
          assert_eq!(out.matches(&format!("# HELP {name} ")).count(), 1, "{name}");
      }
      assert!(!out.contains("_total_total"));
  }
  ```
  In `publish.rs`:
  ```rust
  #[test]
  fn the_bridge_never_sends_a_req_or_count_frame() {
      assert!(bridge_issues_no_req_frames());
      // `channels.rs` does not exist until Task 13. That task adds it to this array
      // in the same commit that creates the completed module.
      for file in [include_str!("publish.rs"), include_str!("pacer.rs"), include_str!("lib.rs")] {
          assert!(!file.contains("\"REQ\"") && !file.contains("\"COUNT\""));
      }
  }

  #[test]
  fn retry_is_byte_identical_inside_the_window_and_restamps_after_it() {
      let frame = frame_created_at(1_700_000_000);
      assert_eq!(retry_decision(&frame, 1_700_000_000 + 779), RetryDecision::ResendIdentical);
      assert_eq!(retry_decision(&frame, 1_700_000_000 + 780), RetryDecision::RestampFromSpool);
  }
  ```

- [ ] **Step 2: Run** → compile failures across the four files.

- [ ] **Step 3: Implement `cards.rs`.** Replace the skeleton's `Marker` enum with `swarm_perch_wire::CardKind` (one source of markers), delete `issuer_block`/`hold_card`/`attach_loss_blocks` (the wire types carry the fields), and write:
  ```rust
  #[derive(Debug, Default)]
  pub struct SeqChain { pub prev_envelope_hash: Option<String> }

  pub fn build_finding_card(record: &Record, event: &RuntimeEvent, issuer: &Identity, colony_id: &str, config: &PerchBridgeConfig, chain: &mut SeqChain, gaps: &[GapCause], now_ms: i64) -> Result<Option<CardBody>, BridgeError> {
      let RuntimeEvent::Finding { emitted_at_ms, host_id, finding } = event else { return Ok(None); };
      let Some(lane) = config.lane_channel(&finding.threat_class) else {
          return Err(BridgeError::MissingLaneChannel { threat_class: threat_class_slug(&finding.threat_class) });
      };
      let mut card = FindingCard {
          issuer: FactIssuer { swarm_agent_id: issuer.slot.label().to_string(), role: Some(AgentRole::Whisker), nostr_pubkey: Some(issuer.keys.public_key().to_hex()) },
          emitted_at_ms: *emitted_at_ms,
          locator: FindingLocator { finding_id: finding.finding_id.clone(), event_id: finding.event_id.clone(), strategy_id: finding.strategy_id.clone(), host_id: host_id.clone(), lane_channel: lane.to_string() },
          finding: finding.clone(),
          evidence_truncated: None,
          gap: gaps.first().map(|g| gap_block(g, now_ms)),
      };
      let seal = |card: &FindingCard| -> Result<String, BridgeError> {
          let fact = serde_json::to_value(Card::Finding(card.clone()))?;
          let envelope = CardEnvelope::seal_unsigned(CardKind::Finding, &spine_issuer(issuer), record.seq, chain.prev_envelope_hash.clone(), issued_at_secs(now_ms), fact)
              .map_err(|e| BridgeError::Encode(e.to_string()))?;
          Ok(serde_json::to_string(&envelope)?)
      };
      let mut json = seal(&card)?;
      if json.len() + 256 > CARD_CONTENT_MAX_BYTES {
          let evidence = serde_json::to_vec(&card.finding.evidence)?;
          card.evidence_truncated = Some(EvidenceTruncated { bytes: evidence.len(), sha256: format!("0x{}", hex::encode(sha2::Sha256::digest(&evidence))) });
          card.finding.evidence = serde_json::Value::Null;
          json = seal(&card)?;
      }
      let human = Card::Finding(card.clone()).human_line();
      let content = build_content(CardKind::Finding, &human, &json).map_err(|e| BridgeError::Encode(e.to_string()))?;
      let tags = TagSet::card(CardKind::Finding, lane.to_string(), Some(threat_class_slug(&finding.threat_class)), Some(severity_label(finding.severity).to_string()));
      tags.assert_publishable(swarm_perch_wire::KIND_CARD).map_err(|e| BridgeError::Encode(e.to_string()))?;
      // The chain advances only when the caller acknowledges the frame; return the hash beside the body.
      let envelope_hash = serde_json::from_str::<serde_json::Value>(&json)?["envelope_hash"].as_str().unwrap_or_default().to_string();
      chain.prev_envelope_hash = Some(envelope_hash);
      Ok(Some(CardBody { kind: CardKind::Finding, channel: lane, content, tags: tags.to_tags(), covers: (record.issuer, record.seq) }))
  }
  ```
  with `spine_issuer(identity) = format!("swarm:ed25519:{}", identity.keys.public_key().to_hex())` (the envelope's `issuer` must match `^swarm:ed25519:[0-9a-f]{64}$`, the form `verify_chain_link` parses; the bridge's secp256k1 key is 32 bytes of hex like an Ed25519 key, and `13` §… names the publishing identity, not the producing agent, as the envelope issuer), `issued_at_secs(ms)` = RFC 3339 seconds `Z`, and `gap_block` mapping `BroadcastLagged{count}` → `count`, the three spool causes → `from_seq/to_seq`. `Record::from_event` already carries the redacted event; the pacer deserialises `record.payload` back into a `RuntimeEvent` to hand here (one `serde_json::from_slice`, off the receive loop). The `chain` note: the test asserts `prev_envelope_hash` after a build; the pacer resets it to the previous value when a frame is not acknowledged (keep `let before = chain.clone()` around the build).

- [ ] **Step 4: Implement `pacer.rs`.** `Pacer<P: FramePublisher>` holds `spools: Arc<Mutex<SpoolSet>>`, `identities: Arc<IdentityTable>`, `config`, `colony_id`, `metrics`, `publisher: P`, `chains: BTreeMap<IssuerIdx, SeqChain>`, `inflight: Option<Frame>` (a frame awaiting a byte-identical retry). `tick(now_ms)`:
  1. If `inflight` is `Some`, apply `retry_decision(&frame, now_ms / 1000)`: `ResendIdentical` → publish again; `RestampFromSpool` → drop it, count `dropped_events{stream=evidence,cause=publish_window_expired}`, `mark_gap(PublishWindowExpired{from_seq,to_seq})` on the evidence spool, continue.
  2. Lock the spool, `peek(PERCH_FRAME_MAX_BYTES)`, take the **first** record only (one finding = one card = one frame; front-run packing degenerates to one record per tick for single-fact cards), `take_gaps()`, unlock.
  3. Deserialise the event; if `build_finding_card` returns `Ok(None)`, `commit(issuer, seq)` immediately, count `bridge_skipped_unpublished{stream="evidence"}` (a card type this milestone does not publish; the record's meaning is not lost — it stays in the daemon's own stores), return `0`.
  4. Stamp: `created_at_secs = now_ms / 1000`; sign with `identities.get(record.issuer)`'s keys: `EventBuilder::new(Kind::Custom(9), body.content).tags(nostr_tags).custom_created_at(Timestamp::from(created_at_secs as u64)).sign_with_keys(&keys)`; observe `late_published_seconds = created_at_secs - record.emitted_at_ms/1000` when it exceeds `PERCH_LATE_PUBLISHED_TICKS`.
  5. `publisher.publish(&frame).await`: `Accepted` → `commit(issuer, seq)`, `source_events_published{evidence}.inc()`, observe `publish_latency_seconds`; `Rejected{message}` → `admission_rejections{reason}`, restore the chain, keep the record at the head (the next tick retries with a fresh stamp — a rejection is not a timeout); `Err(BridgeError::Ws(WsClientError::Timeout))` → keep the signed frame in `inflight`; other `Err` → restore the chain, count, keep at the head.
  `run(self, shutdown)` is the skeleton's `interval` with `MissedTickBehavior::Delay` and a `biased` select over `shutdown.changed()` and `interval.tick()`, calling `tick(now_ms())` and logging (never propagating) a per-tick error. `pack_front_run`/`flush_gap_only_card` are deleted with a comment naming this milestone's one-record-per-frame rule and the gap-carriage rule (a gap rides the next card; a gap-only card needs an array-payload schema `13` does not have — recorded in the exit criteria as a limitation).

- [ ] **Step 5: Implement `publish.rs`.** `ConnectionSupervisor { relay_url, identity, conn: Option<NostrWsConnection>, attempt: u32 }`; `connect()` → `NostrWsConnection::connect_authenticated(&relay_url, &identity.keys, identity.auth_tag.as_ref())` with `backoff_for(attempt, &OkOutcome::Rejected{..})` sleeps between attempts (exponential from 500 ms, capped at 30 s, jittered by `attempt % 7 * 100` ms); `impl FramePublisher`: ensure connected, `conn.send_event(frame.signed.clone()).await` → `Ok(ok)` → `classify_ok(ok.accepted, &ok.message)`; `Err(WsClientError::Timeout)` → `Err(BridgeError::Ws(..))` (the pacer keeps the frame); any other `Err` → drop `conn` (reconnect next tick) and return `Err`. `retry_decision(frame, now_secs)`: `ResendIdentical` iff `now_secs - frame.created_at_secs < 900 - PERCH_PUBLISH_WINDOW_MARGIN_SECS`. `parse_retry_hint`: parse the integer after `retry in ` and before `s`, clamp to 300. `backoff_for`: `AdmissionUnavailable` doubles the base; `ClockSkew` returns `Duration::MAX`'s practical stand-in `Duration::from_secs(3600)` and logs at `error` once.

- [ ] **Step 6: Implement `metrics.rs`.** Complete `new()`: keep the skeleton's registrations, add `bridge_ingested`, `bridge_source_events_published`, `bridge_coalesced`, `bridge_case_channel_conflict`, `bridge_case_channels_created`, `bridge_skipped_unpublished` (`Family<StreamLabel, Counter>`), `bridge_redacted_library_loads` (`Counter`), `bridge_spool_torn_tail`, `bridge_spool_corrupt`, `bridge_connection_state` (`Family<IdentityLabel, Gauge>`), `bridge_hold_undeliverable`, `bridge_lease_store_absent`, `bridge_unknown_action_kind` (counters); return `(Self { … }, Arc::new(Mutex::new(registry)))`. `router(registry, identities: Arc<IdentityTable>, stall: Arc<AtomicU64>)`:
  ```rust
  Router::new()
      .route("/metrics/perch", get(move || encode_registry(Arc::clone(&registry))))
      .route("/metrics/perch/healthz", get(|| async { "ok" }))
      // D-FC-2 default: public keys only, unauthenticated, the admitted-issuer set the console reads.
      .route("/metrics/perch/identities", get(move || identities_json(Arc::clone(&identities))))
      .route("/metrics/perch/test/stall", post(move |Json(body): Json<StallRequest>| stall_handler(Arc::clone(&stall), body)))
  ```
  where the stall route's handler is `#[cfg(debug_assertions)]` and a release build registers `POST /metrics/perch/test/stall` → `404` (route absent). `encode_registry` sets `content-type: application/openmetrics-text; version=1.0.0; charset=utf-8` (`ingest/health.rs:693-695`'s value). `identities_json` returns `{"colony_id": …, "identities": [{"slot": label, "pubkey": hex}]}`.

- [ ] **Step 7: `lib.rs` — `build`, `metrics_router`, `run`.** `build`: return `Ok(None)` when `!config.enabled`; `events.ok_or(BridgeError::NoBroadcaster)?`; `seed_from_env(&config.nostr_seed_env)?`; `IdentityTable::build(...)`; `SpoolSet::open(Path::new(&config.spool_dir), &colony_id, config.segment_bytes, config.spool_max_bytes)?`; `approve_scoped_operator_pubkeys(&operator_principals)` — on `HoldUndeliverable`, log at `warn` ("no Approve principal carries a nostr_pubkey; case channels will be created with the bridge as their only member") and continue with an empty list (First card promotes findings; a hold is Operator-complete); assemble `PerchBridge { receive: (rx, …), pacer, metrics, registry, identities, stall }`. `run`: spawn `receive::run` and the evidence `Pacer::run` with a `ConnectionSupervisor` for the ingest identity; `select!` on those two handles and `shutdown`; on shutdown `seal()` both disk spools. `metrics_router` delegates to `metrics::router`. Task 13 creates `channels.rs`/`alarm.rs`, opens `CaseRouting`, and extends this composition root with the third task only when that code exists.

- [ ] **Step 8: Run and close the atomic-unit gate.** `cargo test -p swarm-perch-bridge` → every test in `cards`, `pacer`, `publish`, `metrics`, `spool`, `stream`, `identity`, `receive` passes. `cargo clippy -p swarm-perch-bridge --all-targets -- -D warnings` clean; `bash tools/check-runtime-panic-contract.sh` clean. `rg -n 'todo!\(|unimplemented!\(' crates/swarm-perch-bridge/src` → no matches. Fix up or squash the Task 3–7 local checkpoints so no reachable commit in the branch contains the copied stub bodies; inspect with `git log -S'todo!(' --oneline -- crates/swarm-perch-bridge/src` before sharing the branch.

- [ ] **Step 9: Commit.** `git add crates/swarm-perch-bridge && git commit -s -m "feat(perch-bridge): finding cards, the 1 Hz pacer with created_at at drain, the OK classifier, and the perch metrics registry"`

### Task 9: Mount the bridge in `swarm_detect`, join `TRUST_SENSITIVE`, keep every gate green

**Files:**
- Modify: `crates/swarm-runtime-http/src/bin/swarm_detect.rs` (imports `:17-31`; the `admitted_identities` move at `:963`; after the containment sweep `:1022-1075`; the router merge block `:1113-1143`; the shutdown join near `await_background_task` `:623-637`), `crates/swarm-runtime-http/Cargo.toml` (`swarm-perch-bridge.workspace = true`), `Cargo.toml` `[workspace.dependencies]` (`swarm-perch-bridge = { path = "crates/swarm-perch-bridge" }`), `tools/check-workspace-layering.sh` (`:184-191`, `:618-633`, `:637`)
- Test: `cargo build -p swarm-runtime-http`; `bash tools/check-workspace-layering.sh`; `bash tools/check-runtime-panic-contract.sh`; a debug run against the dev stack

**Interfaces:**
- Consumes: Task 3's `BridgeBuildInput`, Task 8's `PerchBridge::{build, metrics_router, run}`; `IngestState::subscribe_runtime_events(&self) -> Option<broadcast::Receiver<RuntimeEvent>>` (`ingest/mod.rs:1875`); `ingest_identity: PersistedAgentIdentity { id: AgentId, signing_key }` (`swarm_detect.rs:733`, `agent_identity.rs:95-98`).
- Produces: the log line `perch bridge mounted` at `info` (and `perch bridge NOT mounted` at `error` on a build failure); the bridge task handle joined at shutdown.

- [ ] **Step 1: The layering gate first, on a throwaway edit,** so the fixture failure mode is seen once: add only the tuple entry and run `bash tools/check-workspace-layering.sh` → expected `Vacuity("policy names crates that are not workspace members…")` from the fixture at `:289-294` (exit 1). Then make the three-part edit: `"swarm-perch-bridge",` in `TRUST_SENSITIVE`; the `FIXTURE_CRATES` row `swarm-perch-bridge|swarm-core swarm-runtime swarm-response` (the fixture models declared edges; `swarm-perch-wire` and the ws-client are not fixture crates and need no row); `swarm-perch-bridge` appended to `FIXTURE_DOCUMENTED`. Run again → exit 0, and the real scan reports RULE 5 satisfied for the new crate (the two headings are exact whole lines in `lib.rs`).

- [ ] **Step 2: Wire the spawn.** In `swarm_detect.rs`:
  - imports: `use swarm_perch_bridge::{BridgeBuildInput, PerchBridge};`
  - immediately before `dispatcher.set_admitted_identities(admitted_identities);` (`:963`): `let perch_admitted = admitted_identities.clone();`
  - after the containment-sweep handle block (`:1061-1075`) and before `let listener = …` (`:1100`):
    ```rust
    // The perch bridge: the daemon's only writer of daemon-sourced facts to the relay.
    // A misconfigured bridge must not silently ship a daemon that publishes nothing:
    // `build` fails loudly on a missing seed, a spool inside the workspace, a missing
    // lane, or a daemon with no event broadcaster.
    let mut perch_bridge_handle = None;
    let mut perch_metrics_router = None;
    match PerchBridge::build(BridgeBuildInput {
        config: config.perch.clone(),
        colony_id: config.name.clone(),
        events: state.subscribe_runtime_events(),
        admitted_identities: perch_admitted,
        ingest_identity: ingest_identity.id.clone(),
        operator_principals: config.operator.auth.effective_principals(),
        containment: containment_sweep.clone(),
        shutdown: shutdown_rx.clone(),
    }) {
        Ok(Some(bridge)) => {
            perch_metrics_router = Some(bridge.metrics_router());
            tracing::info!(module = module_path!(), relay = %config.perch.relay_url, "perch bridge mounted");
            perch_bridge_handle = Some(tokio::spawn(bridge.run()));
        }
        Ok(None) => tracing::info!(module = module_path!(), "perch bridge disabled in config"),
        Err(error) => {
            tracing::error!(module = module_path!(), reason = %error, "perch bridge NOT mounted; no evidence will reach the relay");
            return Err(std::io::Error::other(error.to_string()));
        }
    }
    ```
    (`config.perch.enabled` true with a build error is a startup failure by design — the daemon must not run believing it publishes.) If `containment_sweep` is not `Clone` at that point, pass `containment_sweep.as_ref().map(Arc::clone)`.
  - in the router block, after the containment merge's `match` closes: `if let Some(perch_router) = perch_metrics_router { router = router.merge(perch_router); }`
  - at shutdown, beside the other `await_background_task` calls: `if let Some(handle) = perch_bridge_handle.take() { await_background_task("perch bridge", handle, GRACEFUL_SHUTDOWN_TIMEOUT_SECS).await; }` using that helper's actual signature at `:623-637`.

- [ ] **Step 3: Build and gate.** `cargo build -p swarm-runtime-http` → ok. `cargo clippy --workspace --all-targets -- -D warnings` → clean. `bash tools/check-workspace-layering.sh` → exit 0. `bash tools/check-runtime-panic-contract.sh` → exit 0. `bash tools/check-supply-chain.sh` → the skips from Task 3 cover every duplicate.

- [ ] **Step 4: Runtime proof (needs Task 14's config; do it then, but record the expectation now):** `PERCH_BRIDGE_NOSTR_SEED=<64 hex> cargo run -p swarm-runtime-http --bin swarm_detect -- --config rulesets/perch-dev.yaml --serve --bind 127.0.0.1:9090` logs `perch bridge mounted` and `curl -sf http://127.0.0.1:9090/metrics/perch | grep -c perch_bridge_` prints a number ≥ 7; unsetting the seed makes the daemon exit non-zero with `environment variable \`PERCH_BRIDGE_NOSTR_SEED\` is unset or shorter than 32 bytes`.

- [ ] **Step 5: Commit.** `git add Cargo.toml Cargo.lock crates/swarm-runtime-http tools/check-workspace-layering.sh && git commit -s -m "feat(swarm-detect): mount the perch bridge beside the containment router; bridge joins TRUST_SENSITIVE"`

### Task 10: B3r — `GET /v1/operator/findings/reviewed`, the honest window

**Files:**
- Create: `crates/swarm-ingest-runtime/src/ingest/perch_ops/mod.rs`, `crates/swarm-ingest-runtime/src/ingest/perch_ops/reviewed.rs`, `crates/swarm-runtime-http/src/http/perch/mod.rs`, `crates/swarm-runtime-http/src/http/perch/reviewed.rs`, `crates/swarm-runtime-http/src/http/perch/tests.rs`
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs` (`:1-5` module list: add `pub mod perch_ops;`), `crates/swarm-runtime-http/src/http/mod.rs` (`pub mod perch;` and `pub use perch::perch_operator_router;`), `crates/swarm-runtime-http/src/http/auth.rs` (test-only in-memory bearer constructor; production remains env-backed), `crates/swarm-runtime-http/src/bin/swarm_detect.rs` (the router block)
- Test: `cargo test -p swarm-ingest-runtime perch_ops::reviewed`; `cargo test -p swarm-runtime-http perch::tests::reviewed`

**Interfaces:**
- Consumes: `IngestState::current_incident_store(&self) -> ConfiguredIncidentStore` (`ingest/mod.rs:2051`); `IncidentStore::recent(limit) -> Result<Vec<IncidentRecord>, IncidentStoreError>` (`swarm-spine/src/incident.rs:335`); `IncidentRecord.false_positive_measurements: Vec<FalsePositiveMeasurement>` (`:208-243`); `config.audit.recent_decisions_limit`; `config.correlation.incident_store` (`Memory` vs file-backed); `OperatorAuthState::from_config`, `HttpRateLimiter::new`, `OperatorRequestGuardState`, `require_bearer_auth`, `require_supported_operator_api_schema_version`, `require_operator_api_scope` (all `pub(super)` under `http/`, reachable from `http::perch`); `OperatorApiError::{bad_request, unauthorized, forbidden, not_found, internal}` (`http/error.rs`).
- Produces (used by Tasks 12, 14, 19):
  - `swarm_ingest_runtime::perch_ops::reviewed::{ReviewedFinding { finding_id, reviewed_at_ms, action: ProvidenceFeedbackAction, analyst_id, false_positive, incident_id, strategy_id, host_id: Option<String> }, ReviewedFindingsResponse { schema_version: u32, observed_at_ms: i64, reviewed: Vec<ReviewedFinding>, window_incident_count: usize, window_is_truncated: bool, window_oldest_incident_at_ms: Option<i64>, store_durable: bool }, reviewed_findings(state: &IngestState, since_ms: Option<i64>, limit: usize, now_ms: i64) -> Result<ReviewedFindingsResponse, PerchOpsError>}`; `perch_ops::PerchOpsError { NotFound(String), BadRequest(String), Internal(String) }` with `From<IncidentStoreError>`.
  - `swarm_runtime_http::http::perch_operator_router(config: &SwarmConfig, state: IngestState) -> Result<Router, OperatorHttpError>` mounting the one B3r route behind bearer + schema-version middleware; Tasks 11 and 12 grow the same router to two and then three mounted paths, never placeholder handlers. Each handler checks its scope (`Read` for B3r, `Approve` for B3 and B3i).

- [ ] **Step 1: Failing engine test** in `perch_ops/reviewed.rs`'s test module (the crate's `ingest/tests.rs` builds `IngestState::from_config("inline", test_config(strategy))`; reuse `super::super::tests::test_config` if it is `pub(crate)`, otherwise copy the config literal into a `perch_ops/test_support.rs`):
  ```rust
  #[test]
  fn reviewed_findings_flatten_measurements_and_report_the_window() {
      let state = IngestState::from_config("inline", test_config("suspicious_process_tree")).unwrap();
      let store = state.current_incident_store();
      let mut incident = perch_incident("hunt-1", "f-1", 1_000);      // a CorrelatedIncident with one member, see Task 11's helper
      incident.upsert_false_positive_measurement(FalsePositiveMeasurement {
          finding_id: "f-1".into(), hunt_id: "hunt-1".into(), strategy_id: "suspicious_process_tree".into(),
          host_id: Some("host-ops-1".into()), feedback_id: "perch-feedback:f-1:aa".into(), reviewed_at_ms: 5_000,
          analyst_id: "ops".into(), action: ProvidenceFeedbackAction::Dismiss, reason: None, soar_lineage: None, false_positive: true,
      });
      store.persist(&incident).unwrap();
      let out = reviewed_findings(&state, None, 50, 9_000).unwrap();
      assert_eq!(out.reviewed.len(), 1);
      assert_eq!(out.reviewed[0].strategy_id, "suspicious_process_tree");
      assert_eq!(out.reviewed[0].host_id.as_deref(), Some("host-ops-1"));
      assert_eq!(out.window_incident_count, 1);
      assert!(!out.window_is_truncated);
      assert_eq!(out.window_oldest_incident_at_ms, Some(1_000));
      assert!(!out.store_durable, "the test config's incident store is Memory");
      let none = reviewed_findings(&state, Some(6_000), 50, 9_000).unwrap();
      assert!(none.reviewed.is_empty(), "since_ms filters on reviewed_at_ms");
  }
  ```

- [ ] **Step 2: Run** `cargo test -p swarm-ingest-runtime perch_ops` → module not found.

- [ ] **Step 3: Implement `perch_ops/mod.rs`** with `pub mod reviewed;` and
  `PerchOpsError`; Tasks 11 and 12 add `mint` and `feedback` only when their real modules land.
  Then implement `reviewed.rs`:
  ```rust
  pub fn reviewed_findings(state: &IngestState, since_ms: Option<i64>, limit: usize, now_ms: i64) -> Result<ReviewedFindingsResponse, PerchOpsError> {
      let config = state.current_config();       // the accessor that returns the live SwarmConfig; if IngestState exposes it under another name (grep `pub fn current_config\|pub fn config(` in ingest/mod.rs), use that
      let window = limit.max(config.audit.recent_decisions_limit);
      let records = state.current_incident_store().recent(window)?;
      let window_incident_count = records.len();
      let window_is_truncated = window_incident_count >= window;
      let window_oldest_incident_at_ms = records.iter().map(|r| r.created_at_ms).min();
      let mut reviewed: Vec<ReviewedFinding> = records.iter().flat_map(|record| {
          record.false_positive_measurements.iter().map(move |m| ReviewedFinding {
              finding_id: m.finding_id.clone(), reviewed_at_ms: m.reviewed_at_ms, action: m.action, analyst_id: m.analyst_id.clone(),
              false_positive: m.false_positive, incident_id: record.incident_id.clone(), strategy_id: m.strategy_id.clone(), host_id: m.host_id.clone(),
          })
      }).filter(|r| since_ms.is_none_or(|s| r.reviewed_at_ms >= s)).collect();
      reviewed.sort_by(|a, b| b.reviewed_at_ms.cmp(&a.reviewed_at_ms).then(a.finding_id.cmp(&b.finding_id)));
      reviewed.truncate(limit);
      Ok(ReviewedFindingsResponse { schema_version: 1, observed_at_ms: now_ms, reviewed, window_incident_count, window_is_truncated, window_oldest_incident_at_ms,
          store_durable: !matches!(config.correlation.incident_store, swarm_core::config::BundleStoreConfig::Memory) })
  }
  ```
  `IncidentRecord`'s timestamp field is `created_at_ms` per `incident.rs:208-243`; if it is named differently there, use the record's name. The `since_ms` order is the one `upsert_false_positive_measurement` imposes (`incident.rs:189-204`): `reviewed_at_ms DESC, finding_id ASC`.

- [ ] **Step 4: The router and the handler.** `http/perch/mod.rs`:
  ```rust
  //! First-card operator routes, grown only with implemented handlers and mounted on the
  //! daemon's own listener beside `containment_operator_router`. Every route: bearer +
  //! schema-version middleware, then an explicit scope check in the handler (ADR 0012 clause 1).
  mod reviewed;
  #[cfg(test)]
  mod tests;

  use super::auth::{OperatorAuthState, require_bearer_auth, require_supported_operator_api_schema_version};
  use super::state::{OperatorHttpError, OperatorRequestGuardState};
  use axum::{Router, middleware, routing::get};
  use swarm_core::config::SwarmConfig;
  use swarm_core::http_rate_limit::HttpRateLimiter;
  use swarm_ingest_runtime::IngestState;

  #[derive(Clone)]
  pub(super) struct PerchHttpState { pub(super) ingest: IngestState }

  /// The paths this router declares, for the disjointness test against the other operator router.
  pub const PERCH_ROUTER_PATHS: [&str; 1] = [
      "/v1/operator/findings/reviewed",
  ];

  pub fn perch_operator_router(config: &SwarmConfig, ingest: IngestState) -> Result<Router, OperatorHttpError> {
      let auth = OperatorAuthState::from_config(config)?;
      Ok(perch_operator_router_with_auth(config, ingest, auth))
  }

  fn perch_operator_router_with_auth(config: &SwarmConfig, ingest: IngestState, auth: OperatorAuthState) -> Router {
      let rate_limiter = HttpRateLimiter::new("operator-perch", config.operator.rate_limit.clone());
      Router::new()
          .route(PERCH_ROUTER_PATHS[0], get(reviewed::reviewed_findings_handler))
          .with_state(PerchHttpState { ingest })
          .layer(middleware::from_fn_with_state(OperatorRequestGuardState { auth, rate_limiter }, require_bearer_auth))
          .layer(middleware::from_fn(require_supported_operator_api_schema_version))
  }
  ```
  Do not create `feedback.rs`, `incidents.rs`, their module declarations or their path entries in
  this task. W3-28's rule applies from the first route: the inventory describes mounted handlers,
  never the future. `reviewed.rs`:
  ```rust
  pub(super) async fn reviewed_findings_handler(
      Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
      State(state): State<PerchHttpState>,
      Query(query): Query<ReviewedQuery>,
  ) -> Result<Json<ReviewedFindingsResponse>, OperatorApiError> {
      require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
      let limit = query.limit.unwrap_or(50).clamp(1, 1_000);
      reviewed_findings(&state.ingest, query.since_ms, limit, now_ms()).map(Json).map_err(map_perch_error)
  }
  ```
  with `#[derive(Deserialize)] pub(super) struct ReviewedQuery { since_ms: Option<i64>, limit: Option<usize> }` and `map_perch_error: PerchOpsError → OperatorApiError` (`NotFound → not_found`, `BadRequest → bad_request`, `Internal → internal`) in `perch/mod.rs`. Mount in `swarm_detect.rs`, inside the `Some(sweep) if config.operator.enabled` arm's success path and also when there is no containment sweep — i.e. as its own `if config.operator.enabled { match perch_operator_router(&config, state.clone()) { Ok(r) => { tracing::info!(module = module_path!(), "perch operator routes mounted"); router = router.merge(r); } Err(e) => tracing::error!(module = module_path!(), reason = %e, "perch operator routes NOT mounted") } }` placed right after the containment block. The log string `perch operator routes mounted` is the one `docs/PERCH-DEV.md` step 4 greps for.

- [ ] **Step 5: Route tests** in `http/perch/tests.rs`, following `http/tests.rs`'s
  `operator_config()` and `oneshot` shape (`:940-960`) without copying its process-global
  `unsafe set_var` pattern. In `http/auth.rs`, add `#[cfg(test)]
  OperatorAuthState::for_test(operator_id, scopes, token)`: its configured principal carries an
  in-memory `Zeroizing<String>` token that `authenticate` reads before the env-backed path. The
  field and branch are compiled only for unit tests; `from_config` and production token rotation
  remain byte-for-byte env-backed. Add `#[cfg(test)] perch_operator_router_for_test(config,
  ingest, auth)` in `perch/mod.rs`; it delegates to `perch_operator_router_with_auth`.
  ```rust
  fn app() -> (Router, IngestState) {
      let config = super::super::tests::operator_config();
      let state = IngestState::from_config("inline", config.clone()).unwrap();
      let auth = OperatorAuthState::for_test("local-operator", vec![OperatorScope::Read, OperatorScope::Approve], "secret-token");
      (perch_operator_router_for_test(&config, state.clone(), auth), state)
  }

  #[tokio::test]
  async fn reviewed_requires_a_bearer_and_answers_the_window() {
      let (app, _state) = app();
      let unauthorized = app.clone().oneshot(Request::builder().uri("/v1/operator/findings/reviewed").body(Body::empty()).unwrap()).await.unwrap();
      assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
      let ok = app.oneshot(Request::builder().uri("/v1/operator/findings/reviewed?limit=10")
          .header(AUTHORIZATION, "Bearer secret-token").header("x-swarm-schema-version", "1").body(Body::empty()).unwrap()).await.unwrap();
      assert_eq!(ok.status(), StatusCode::OK);
      let body: serde_json::Value = serde_json::from_slice(&to_bytes(ok.into_body(), usize::MAX).await.unwrap()).unwrap();
      assert_eq!(body["window_incident_count"], 0);
      assert_eq!(body["store_durable"], false);
      assert!(body["reviewed"].as_array().unwrap().is_empty());
  }

  #[test]
  fn perch_paths_are_disjoint_from_the_containment_router() {
      assert_eq!(PERCH_ROUTER_PATHS.len(), 1);
      for path in PERCH_ROUTER_PATHS {
          assert!(!path.starts_with("/v1/operator/containment"), "{path}");
      }
  }
  ```
  If `operator_config` is private to `http/tests.rs`, make it `pub(super)` there (a one-word change).

- [ ] **Step 6: Run** `cargo test -p swarm-runtime-http perch` → 2 passed; `cargo test -p swarm-ingest-runtime perch_ops` → 1 passed. Clippy clean.
- [ ] **Step 7: Commit.** `git add crates/swarm-ingest-runtime crates/swarm-runtime-http && git commit -s -m "feat(operator): B3r GET /v1/operator/findings/reviewed with an honest evidence window"`

### Task 11: B3i — `POST /v1/operator/incidents` mints the incident **and the `case_id`**, publishes `RuntimeEvent::CasePromoted`

**Files:**
- Modify: `crates/swarm-runtime/src/runtime_events.rs` (`RuntimeEventKind` `:125-139`, `as_str` `:142-156`, `parse` `:158-173`, `RuntimeEvent` `:211-305`, `emitted_at_ms` `:308-322`, `kind` `:324-338`), `crates/swarm-ingest-runtime/src/ingest/mod.rs` (`runtime_event_matches_scope` last arm `:766-768`), `crates/swarm-ingest-runtime/src/ingest/perch_ops/mod.rs`, `crates/swarm-runtime-http/src/http/perch/mod.rs` (add the second mounted path), `docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml` (`IncidentMintRequest`, `IncidentMintResponse`)
- Create: `crates/swarm-ingest-runtime/src/ingest/perch_ops/mint.rs`, `crates/swarm-runtime-http/src/http/perch/incidents.rs`, `crates/swarm-runtime-http/tests/perch_walking_skeleton.rs`
- Test: `cargo test -p swarm-runtime runtime_events`; `cargo test -p swarm-ingest-runtime perch_ops::mint`; `cargo test -p swarm-runtime-http perch`

**Interfaces:**
- Consumes: `CorrelatedIncident` (20 fields, 9 without defaults: `incident_id, summary, created_at_ms, window_start_ms, window_end_ms, correlation_keys, related_receipt_ids, included_members, rejected_members`; `incident.rs:136-170`), `IncidentMemberDecision { investigation_id, hunt_id, finding_id, reason, shared_keys, evidence_links, confidence_score }` (`:101-110`), `IncidentStore::{persist, load_by_incident_id, recent}`, `IngestState::publish_runtime_event(&self, RuntimeEvent)` (`ingest/mod.rs:1913`).
- Produces (used by Tasks 12, 13, 19, 23):
  - `RuntimeEvent::CasePromoted { emitted_at_ms: i64, hunt_id: String, case_id: String, clause: CasePromotionClause, incident_id: String, finding_id: String, threat_class: ThreatClass, severity: Severity, summary: String }`; `RuntimeEventKind::CasePromoted` (`"case_promoted"`); `#[serde(rename_all = "snake_case")] pub enum CasePromotionClause { HeldAction, CorrelatedIncident, Manual }` with `as_str()`.
  - `perch_ops::mint::{IncidentMintRequest { finding_id, hunt_id, event_id, strategy_id, threat_class: ThreatClass, severity: Severity, created_at_ms: i64, summary, host_id: Option<String>, correlation_keys: Vec<String> }` (`#[serde(deny_unknown_fields)]`; **no `case_id`** — W3-14), `IncidentMintResponse { schema_version: u32, incident_id, case_id: String, created: bool, degraded: Vec<String>, record: IncidentRecord }`, `mint_incident(state: &IngestState, request: IncidentMintRequest, now_ms: i64) -> Result<IncidentMintResponse, PerchOpsError>`, `PERCH_CASE_INCIDENT_PREFIX = "incident:perch-case:"`}`.

- [ ] **Step 1: The runtime event first — failing test** in `runtime_events.rs`'s test module:
  ```rust
  #[test]
  fn case_promoted_round_trips_and_is_the_twelfth_kind() {
      let event = RuntimeEvent::CasePromoted { emitted_at_ms: 7, hunt_id: "hunt-1".into(), case_id: "9499a6e2-8872-453b-80d9-dafc6fc7fc69".into(), clause: CasePromotionClause::Manual,
          incident_id: "incident:perch-case:9499a6e2-8872-453b-80d9-dafc6fc7fc69".into(), finding_id: "f-1".into(), threat_class: ThreatClass::Execution, severity: Severity::High, summary: "promoted".into() };
      let json = serde_json::to_value(&event).unwrap();
      assert_eq!(json["event_type"], "case_promoted");
      assert_eq!(json["clause"], "manual");
      assert_eq!(event.kind(), RuntimeEventKind::CasePromoted);
      assert_eq!(event.emitted_at_ms(), 7);
      assert_eq!(RuntimeEventKind::parse("case_promoted"), Some(RuntimeEventKind::CasePromoted));
      assert_eq!(RuntimeEventKind::CasePromoted.as_str(), "case_promoted");
  }
  ```
  Run `cargo test -p swarm-runtime case_promoted` → compile failure. Add the variant to all six sites (the enum member, `as_str`, `parse`, the `RuntimeEvent` variant after `ModeTransition`, the `emitted_at_ms` arm, the `kind` arm) and the `CasePromotionClause` enum. Then `cargo build --workspace` names every exhaustive `match` that now fails: `runtime_event_matches_scope` (`ingest/mod.rs:766-768` — add `| RuntimeEvent::CasePromoted { .. }` to the arm that returns `false`, so a promotion never reaches the unauthenticated Providence context stream) and `swarm_perch_bridge::stream::classify` (add `RuntimeEvent::CasePromoted { .. } => Stream::Alarm` in the Alarm block, with the skeleton's comment). Any other site the compiler names gets the arm that preserves its current behaviour for a non-finding event, with a one-line comment. Run the test → passed.

- [ ] **Step 2: Failing mint tests** in `perch_ops/mint.rs`:
  ```rust
  fn request(finding: &str, host: Option<&str>) -> IncidentMintRequest {
      IncidentMintRequest { finding_id: finding.into(), hunt_id: "hunt-evt-1".into(), event_id: "hunt-evt-1".into(), strategy_id: "suspicious_process_tree".into(),
          threat_class: ThreatClass::Execution, severity: Severity::High, created_at_ms: 1_700_000_000_000, summary: "Office-spawned encoded PowerShell".into(),
          host_id: host.map(str::to_string), correlation_keys: vec![] }
  }

  #[test]
  fn a_mint_satisfies_the_feedback_target_contract_and_emits_case_promoted() {
      let state = IngestState::from_config("inline", test_config("suspicious_process_tree")).unwrap();
      let mut rx = state.subscribe_runtime_events().unwrap();
      let out = mint_incident(&state, request("f-1", Some("host-ops-1")), 1_700_000_001_000).unwrap();
      assert!(out.created);
      assert!(out.incident_id.starts_with(PERCH_CASE_INCIDENT_PREFIX));
      assert_eq!(out.incident_id, format!("{PERCH_CASE_INCIDENT_PREFIX}{}", out.case_id));
      assert!(uuid::Uuid::parse_str(&out.case_id).is_ok());
      assert!(out.degraded.is_empty());
      let lookup = state.current_incident_store().load_by_incident_id(&out.incident_id).unwrap().unwrap();
      let target = swarm_runtime::providence::resolve_feedback_target(&lookup, Some("f-1")).unwrap();
      assert_eq!(target.strategy_id.as_deref(), Some("suspicious_process_tree"));
      assert_eq!(target.host_id.as_deref(), Some("host-ops-1"));
      assert_eq!(target.threat_class, ThreatClass::Execution);
      match rx.try_recv().unwrap() {
          RuntimeEvent::CasePromoted { case_id, clause, incident_id, .. } => { assert_eq!(case_id, out.case_id); assert_eq!(clause, CasePromotionClause::Manual); assert_eq!(incident_id, out.incident_id); }
          other => panic!("expected CasePromoted, got {other:?}"),
      }
  }

  #[test]
  fn a_second_mint_for_the_same_finding_replays_and_emits_nothing() {
      let state = IngestState::from_config("inline", test_config("suspicious_process_tree")).unwrap();
      let first = mint_incident(&state, request("f-1", Some("h")), 1).unwrap();
      let mut rx = state.subscribe_runtime_events().unwrap();
      let second = mint_incident(&state, request("f-1", Some("h")), 2).unwrap();
      assert!(!second.created);
      assert_eq!(second.case_id, first.case_id);
      assert!(rx.try_recv().is_err(), "a replay must not re-promote");
  }

  #[test]
  fn an_empty_strategy_id_is_refused_and_a_missing_host_is_named_as_degraded() {
      let state = IngestState::from_config("inline", test_config("suspicious_process_tree")).unwrap();
      let mut bad = request("f-2", Some("h")); bad.strategy_id = "  ".into();
      assert!(matches!(mint_incident(&state, bad, 1).unwrap_err(), PerchOpsError::BadRequest(_)));
      let out = mint_incident(&state, request("f-3", None), 1).unwrap();
      assert_eq!(out.degraded, vec!["host_exclusion_unreachable".to_string()]);
  }

  #[test]
  fn the_minted_id_cannot_collide_with_the_correlation_engines_scheme() {
      // correlation.rs:211 mints `incident:{hunt_id}:{created_at_ms}`; the second segment
      // here is the literal `perch-case`, and a hunt id containing a colon is sanitized.
      assert!(!"incident:perch-case:x".starts_with("incident:hunt"));
      let id = format!("{PERCH_CASE_INCIDENT_PREFIX}{}", uuid::Uuid::nil());
      assert_eq!(id.split(':').nth(1), Some("perch-case"));
  }
  ```

- [ ] **Step 3: Run** → compile failure. **Implement `mint.rs`:**
  ```rust
  pub const PERCH_CASE_INCIDENT_PREFIX: &str = "incident:perch-case:";

  pub fn mint_incident(state: &IngestState, request: IncidentMintRequest, now_ms: i64) -> Result<IncidentMintResponse, PerchOpsError> {
      if request.strategy_id.trim().is_empty() {
          return Err(PerchOpsError::BadRequest("strategy_id must be non-empty; `unknown` would collapse the tuning bucket".into()));
      }
      for (name, value) in [("finding_id", &request.finding_id), ("hunt_id", &request.hunt_id), ("event_id", &request.event_id)] {
          if value.trim().is_empty() { return Err(PerchOpsError::BadRequest(format!("{name} must be non-empty"))); }
      }
      let store = state.current_incident_store();
      // Idempotency on the finding: the console supplies no case_id (W3-14), so a replay is
      // "an incident this route already minted for this finding". The scan is bounded by the
      // same window B3r reads.
      let window = state.current_config().audit.recent_decisions_limit.max(200);
      if let Some(existing) = store.recent(window)?.into_iter().find(|r| r.incident_id.starts_with(PERCH_CASE_INCIDENT_PREFIX) && r.trigger_finding_id.as_deref() == Some(request.finding_id.as_str())) {
          let case_id = existing.incident_id[PERCH_CASE_INCIDENT_PREFIX.len()..].to_string();
          let degraded = degraded_for(&existing.correlation_keys);
          return Ok(IncidentMintResponse { schema_version: 1, incident_id: existing.incident_id.clone(), case_id, created: false, degraded, record: existing });
      }
      let case_id = uuid::Uuid::new_v4().to_string();
      let incident_id = format!("{PERCH_CASE_INCIDENT_PREFIX}{case_id}");
      let mut correlation_keys = request.correlation_keys.clone();
      if let Some(host) = request.host_id.as_deref().filter(|h| !h.trim().is_empty()) {
          correlation_keys.push(format!("host:{host}"));
      }
      let member = IncidentMemberDecision {
          investigation_id: format!("perch-promotion:{}", super::super::sanitize_id(&request.finding_id)),
          hunt_id: request.hunt_id.clone(), finding_id: request.finding_id.clone(),
          reason: "promoted by operator".into(), shared_keys: correlation_keys.clone(), evidence_links: vec![], confidence_score: 1.0,
      };
      let incident = CorrelatedIncident {
          incident_id: incident_id.clone(), summary: request.summary.clone(), created_at_ms: request.created_at_ms,
          window_start_ms: request.created_at_ms, window_end_ms: request.created_at_ms, correlation_keys: correlation_keys.clone(),
          related_receipt_ids: vec![], included_members: vec![member], rejected_members: vec![], graph_dimensions: vec![], confidence_score: 1.0,
          trigger_event_id: Some(request.event_id.clone()), trigger_finding_id: Some(request.finding_id.clone()), trigger_strategy_id: Some(request.strategy_id.trim().to_string()),
          threat_class: Some(request.threat_class.clone()), severity: Some(request.severity), external_references: vec![], providence_reconciliation: None,
          providence_callback_audit_entries: vec![], feedback_audit_entries: vec![], false_positive_measurements: vec![],
      };
      let record = store.persist(&incident)?;
      // The event goes out AFTER the record commits: the bridge creates the channel the record already names.
      state.publish_runtime_event(RuntimeEvent::CasePromoted {
          emitted_at_ms: now_ms, hunt_id: request.hunt_id, case_id: case_id.clone(), clause: CasePromotionClause::Manual,
          incident_id: incident_id.clone(), finding_id: request.finding_id, threat_class: request.threat_class, severity: request.severity, summary: request.summary,
      });
      Ok(IncidentMintResponse { schema_version: 1, incident_id, case_id, created: true, degraded: degraded_for(&correlation_keys), record })
  }

  fn degraded_for(keys: &[String]) -> Vec<String> {
      if keys.iter().any(|k| k.starts_with("host:")) { vec![] } else { vec!["host_exclusion_unreachable".to_string()] }
  }
  ```
  `sanitize_id` is private in `ingest/mod.rs` (`:556`); make it `pub(crate)` (one-word change). `PerchOpsError: From<IncidentStoreError>` maps to `Internal`. If `CorrelatedIncident` has a field this literal omits, the compiler names it; give it its `Default`.

- [ ] **Step 4: The handler** in `http/perch/incidents.rs`:
  ```rust
  pub(super) async fn mint_incident_handler(
      Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
      State(state): State<PerchHttpState>,
      body: Result<Json<IncidentMintRequest>, JsonRejection>,
  ) -> Result<Json<IncidentMintResponse>, OperatorApiError> {
      require_operator_api_scope(&principal, OperatorScope::Approve, "approve")?;
      let Json(request) = body.map_err(|e| OperatorApiError::bad_request(e.body_text()))?;
      mint_incident(&state.ingest, request, now_ms()).map(Json).map_err(map_perch_error)
  }
  ```
  In `http/perch/mod.rs`, add `mod incidents;`, import `post`, append
  `"/v1/operator/incidents"` to `PERCH_ROUTER_PATHS`, change its exact length from one to two,
  and mount `post(incidents::mint_incident_handler)` at the new index. Extend the source/inventory
  assertion to two. The path and handler land together (W3-28).
  Route test in `http/perch/tests.rs`: POST with the bearer and a full body → 200, `created: true`, `case_id` parses as a UUID; POST with `{"case_id": "…"}` added → 400 (`deny_unknown_fields`); POST without `Approve` (add a `read-only` principal to the config the way `http/tests.rs:3528` does) → 403.

- [ ] **Step 5: The ADR 0018 verification test** — `crates/swarm-runtime-http/tests/perch_walking_skeleton.rs` (an integration test so it sees only the public API; it drives the engine functions directly and reads the same store the platform status route reads):
  ```rust
  #![allow(clippy::unwrap_used, clippy::expect_used)]
  //! ADR 0018 "Verification": promote a finding, dismiss it, and assert the measurement is
  //! attributable — strategy_id is not "unknown" and host_id is Some. Asserting only that a
  //! measurement exists would pass with a useless one.
  use swarm_ingest_runtime::perch_ops::{feedback::{record_finding_feedback, FindingFeedbackRequest}, mint::{mint_incident, IncidentMintRequest}};
  // …test_config as in http/tests.rs's operator_config(), copied into this file…

  #[test]
  fn a_promoted_then_dismissed_finding_leaves_an_attributable_measurement() {
      let state = IngestState::from_config("inline", operator_config()).unwrap();
      let minted = mint_incident(&state, IncidentMintRequest { /* host_id: Some("host-ops-1"), strategy_id: "suspicious_process_tree", … */ }, 1).unwrap();
      let fed = record_finding_feedback(&state, "local-operator", "f-1", FindingFeedbackRequest { action: ProvidenceFeedbackAction::Dismiss, incident_id: minted.incident_id.clone(), verdict_event_id: "ab".repeat(32), reason: Some("looked like the backup job".into()) }, 2).unwrap();
      assert!(fed.false_positive);
      assert_eq!(fed.analyst_id, "local-operator");
      let record = state.current_incident_store().load_by_incident_id(&minted.incident_id).unwrap().unwrap().record;
      let m = &record.false_positive_measurements[0];
      assert_ne!(m.strategy_id, "unknown");
      assert_eq!(m.host_id.as_deref(), Some("host-ops-1"));
      assert_eq!(m.analyst_id, "local-operator");
      assert!(m.feedback_id.starts_with("perch-feedback:f-1:"));
  }
  ```
  (It compiles after Task 12; write it now, run it then.)

- [ ] **Step 6: Amend the OpenAPI source of truth** (`docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml`): remove `case_id` from `IncidentMintRequest.required` and `.properties`, replace its description with one sentence pointing at W3-14; add `case_id: { type: string, format: uuid, description: "Minted by the daemon (00-DECISIONS W3-14). The case channel's UUID; the bridge creates the channel from RuntimeEvent::CasePromoted." }` to `IncidentMintResponse.properties` and `required`; change the path description's "IDEMPOTENT ON `case_id`" paragraph to "IDEMPOTENT ON `finding_id`: a second mint for a finding this route already promoted returns 200 with `created: false` and the original `case_id`". The generator and gate (`12` §14, P1-13) are not on this milestone; the YAML is the reviewable contract.

- [ ] **Step 7: Run** `cargo test -p swarm-runtime case_promoted && cargo test -p swarm-ingest-runtime perch_ops && cargo test -p swarm-runtime-http perch` → green except the walking-skeleton test (blocked on Task 12). `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **Step 8: Commit.** `git add -A crates docs/plans/ambush-ui/build/openapi && git commit -s -m "feat(operator): B3i POST /v1/operator/incidents mints the incident and the case_id; RuntimeEvent::CasePromoted (B1d)"`

### Task 12: B3 — `POST /v1/operator/findings/{finding_id}/feedback`, `analyst_id` from the principal

**Files:**
- Create: `crates/swarm-ingest-runtime/src/ingest/perch_ops/feedback.rs`, `crates/swarm-runtime-http/src/http/perch/feedback.rs`
- Modify: `crates/swarm-runtime-http/src/http/perch/mod.rs` (add the third mounted path), `crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs` (visibility only: `apply_providence_feedback` and `enrich_feedback_target` are already `pub(crate)`; `ProvidenceFeedbackError` may need `pub(crate)`)
- Test: `cargo test -p swarm-ingest-runtime perch_ops::feedback`; `cargo test -p swarm-runtime-http perch`; `cargo test -p swarm-runtime-http --test perch_walking_skeleton`

**Interfaces:**
- Consumes: `apply_providence_feedback(state, &SwarmProvidenceFeedbackRequest, &ProvidenceFeedbackTarget, feedback_id: &str, recorded_at_ms) -> Result<ProvidenceFeedbackApplicationResult { outcome: Value, evidence }, ProvidenceFeedbackError>` (`providence_handlers.rs:294-300`), `enrich_feedback_target` (`:456-471`), `false_positive_measurement` (`:473-495`), `resolve_feedback_target` (`providence.rs:799-836`), `AnalystFeedbackAuditEntry` (`incident.rs:23-42`), `CorrelatedIncident::upsert_false_positive_measurement`.
- Produces (used by Tasks 19, 23): `perch_ops::feedback::{FindingFeedbackRequest { action: ProvidenceFeedbackAction, incident_id: String, verdict_event_id: String, reason: Option<String> }` (`#[serde(deny_unknown_fields)]`), `FindingFeedbackResponse { schema_version: u32, feedback_id, action, incident_id, finding_id, analyst_id, false_positive: bool, replayed: bool, outcome: Value }`, `record_finding_feedback(state: &IngestState, operator_id: &str, finding_id: &str, request: FindingFeedbackRequest, now_ms: i64) -> Result<FindingFeedbackResponse, PerchOpsError>`}`; the `request_signature` convention `operator-bearer:{operator_id}` (C7).

- [ ] **Step 1: Failing tests** in `feedback.rs`:
  ```rust
  #[test]
  fn feedback_takes_analyst_id_from_the_caller_and_is_idempotent_on_the_verdict_event() {
      let state = IngestState::from_config("inline", test_config("suspicious_process_tree")).unwrap();
      let minted = mint_incident(&state, request_for("f-1", Some("host-ops-1")), 1).unwrap();
      let req = FindingFeedbackRequest { action: ProvidenceFeedbackAction::Dismiss, incident_id: minted.incident_id.clone(), verdict_event_id: "cd".repeat(32), reason: None };
      let first = record_finding_feedback(&state, "ops-alice", "f-1", req.clone(), 10).unwrap();
      assert_eq!(first.analyst_id, "ops-alice");
      assert_eq!(first.feedback_id, format!("perch-feedback:f-1:{}", "cd".repeat(32)));
      assert!(first.false_positive && !first.replayed);
      let second = record_finding_feedback(&state, "ops-alice", "f-1", req, 11).unwrap();
      assert!(second.replayed);
      let record = state.current_incident_store().load_by_incident_id(&minted.incident_id).unwrap().unwrap().record;
      assert_eq!(record.feedback_audit_entries.len(), 1, "an append guarded by the deterministic id");
      assert_eq!(record.feedback_audit_entries[0].request_signature, "operator-bearer:ops-alice");
      assert_eq!(record.false_positive_measurements.len(), 1);
  }

  #[test]
  fn confirm_and_investigate_move_the_denominator_without_a_false_positive() {
      let state = IngestState::from_config("inline", test_config("suspicious_process_tree")).unwrap();
      let minted = mint_incident(&state, request_for("f-2", Some("h")), 1).unwrap();
      for (action, verdict) in [(ProvidenceFeedbackAction::Confirm, "01"), (ProvidenceFeedbackAction::Investigate, "02")] {
          let out = record_finding_feedback(&state, "ops", "f-2", FindingFeedbackRequest { action, incident_id: minted.incident_id.clone(), verdict_event_id: verdict.repeat(32), reason: None }, 5).unwrap();
          assert!(!out.false_positive);
      }
      let record = state.current_incident_store().load_by_incident_id(&minted.incident_id).unwrap().unwrap().record;
      assert_eq!(record.false_positive_measurements.len(), 1, "upsert replaces by finding_id");
      assert_eq!(record.feedback_audit_entries.len(), 2);
  }

  #[test]
  fn feedback_on_an_unknown_incident_or_finding_is_the_not_yet_correlated_wall() {
      let state = IngestState::from_config("inline", test_config("suspicious_process_tree")).unwrap();
      let missing = record_finding_feedback(&state, "ops", "f-9", FindingFeedbackRequest { action: ProvidenceFeedbackAction::Dismiss, incident_id: "incident:perch-case:nope".into(), verdict_event_id: "ee".repeat(32), reason: None }, 1);
      assert!(matches!(missing, Err(PerchOpsError::NotFound(_))));
      let minted = mint_incident(&state, request_for("f-3", Some("h")), 1).unwrap();
      let wrong_member = record_finding_feedback(&state, "ops", "f-not-a-member", FindingFeedbackRequest { action: ProvidenceFeedbackAction::Dismiss, incident_id: minted.incident_id, verdict_event_id: "ff".repeat(32), reason: None }, 1);
      assert!(matches!(wrong_member, Err(PerchOpsError::NotFound(_))));
  }
  ```

- [ ] **Step 2: Run** → compile failure. **Implement** (the seven steps of `providence_feedback_handler`, `providence_handlers.rs:119-192`, with the three changes `12` §8 names):
  ```rust
  pub fn record_finding_feedback(state: &IngestState, operator_id: &str, finding_id: &str, request: FindingFeedbackRequest, now_ms: i64) -> Result<FindingFeedbackResponse, PerchOpsError> {
      if request.verdict_event_id.len() != 64 || !request.verdict_event_id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
          return Err(PerchOpsError::BadRequest("verdict_event_id must be 64 lowercase hex".into()));
      }
      let store = state.current_incident_store();
      let lookup = store.load_by_incident_id(&request.incident_id)?
          .ok_or_else(|| PerchOpsError::NotFound(format!("incident `{}` was not found", request.incident_id)))?;
      let target = resolve_feedback_target(&lookup, Some(finding_id)).map_err(PerchOpsError::NotFound)?;
      let target = enrich_feedback_target(state, &lookup, &target).map_err(|e| PerchOpsError::Internal(e.to_string()))?;
      let feedback_id = format!("perch-feedback:{}:{}", super::super::sanitize_id(finding_id), request.verdict_event_id);
      let mut incident = lookup.incident.clone();
      if let Some(existing) = incident.feedback_audit_entries.iter().find(|e| e.feedback_id == feedback_id) {
          return Ok(response(&feedback_id, &request, &target, operator_id, true, existing.outcome.clone()));
      }
      // The webhook's request type, with analyst_id set from the PRINCIPAL (C5/C6). The body
      // type cannot carry one: FindingFeedbackRequest is deny_unknown_fields.
      let providence_request = SwarmProvidenceFeedbackRequest { action: request.action, incident_id: request.incident_id.clone(), finding_id: Some(finding_id.to_string()), analyst_id: operator_id.to_string(), reason: request.reason.clone() };
      let applied = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(apply_providence_feedback(state, &providence_request, &target, &feedback_id, now_ms)))
          .map_err(|e| PerchOpsError::Internal(e.to_string()))?;
      incident.feedback_audit_entries.push(AnalystFeedbackAuditEntry {
          feedback_id: feedback_id.clone(), received_at_ms: now_ms, action: request.action, analyst_id: operator_id.to_string(), incident_id: request.incident_id.clone(),
          finding_id: Some(target.finding_id.clone()), reason: request.reason.clone(), request_signature: format!("operator-bearer:{operator_id}"),
          evidence: Some(applied.evidence), soar_lineage: None, payload: serde_json::to_value(&request)?, outcome: applied.outcome.clone(),
      });
      incident.upsert_false_positive_measurement(false_positive_measurement(&providence_request, &target, &feedback_id, now_ms));
      store.persist(&incident)?;
      Ok(response(&feedback_id, &request, &target, operator_id, false, applied.outcome))
  }
  ```
  `apply_providence_feedback` is `async`; make `record_finding_feedback` `async` instead of blocking (the handler is async; the tests become `#[tokio::test]`), and drop the `block_in_place` line — that is the intended shape; the sketch shows the call for clarity. `response(..)` fills `false_positive: matches!(action, Dismiss)`. If `ProvidenceFeedbackError` is private, add `pub(crate)` to it; nothing about the webhook path changes.

- [ ] **Step 3: The handler** in `http/perch/feedback.rs`, mirroring Task 11's, with `RoutePath(finding_id): RoutePath<String>`, the `Approve` scope, and `principal.operator_id.as_ref()` as the analyst. In `http/perch/mod.rs`, add `mod feedback;`, insert `"/v1/operator/findings/{finding_id}/feedback"` between reviewed and incidents in `PERCH_ROUTER_PATHS`, change the exact length from two to three, mount `post(feedback::finding_feedback_handler)`, and extend the source/inventory assertion to three. Route tests: 200 with the audit entry's `analyst_id` equal to the config's `operator_id` (`local-operator` in `operator_config()`); a body carrying `"analyst_id": "mallory"` → 400; an unknown incident → 404 with `error: "not_found"`.

- [ ] **Step 4: Run** `cargo test -p swarm-ingest-runtime perch_ops && cargo test -p swarm-runtime-http perch && cargo test -p swarm-runtime-http --test perch_walking_skeleton` → all green, including Task 11's ADR 0018 test. Clippy clean.
- [ ] **Step 5: Commit.** `git add -A crates && git commit -s -m "feat(operator): B3 finding feedback with analyst_id from the authenticated principal and a deterministic feedback_id"`

### Task 13: The bridge creates the case channel on `CasePromoted` — and the twelve lanes at startup

> Blocked on D-FC-5 (Task 14 records it); built under its default.

**Files:**
- Create: `crates/swarm-perch-bridge/src/channels.rs` (begin from the reviewed skeleton, then replace every `todo!()` before commit)
- Modify: `crates/swarm-perch-bridge/src/{lib,stream}.rs`
- Create: `crates/swarm-perch-bridge/src/alarm.rs`
- Modify: `crates/swarm-perch-bridge/tests/relay_live.rs`
- Test: `cargo test -p swarm-perch-bridge channels`; `cargo test -p swarm-perch-bridge alarm`; the live test

**Interfaces:**
- Consumes: Task 11's `RuntimeEvent::CasePromoted`; Task 7's `IdentityTable::alarm()`, `approve_scoped_operator_pubkeys`; Task 8's `ConnectionSupervisor`, `OkOutcome`; `PerchBridgeConfig::{case_ttl_seconds, lane_channels}`; the relay's kind 9007 tags `h`, `name`, `visibility` (`open|private`), `channel_type` (`stream|forum`), `ttl` (seconds) and kind 9000 tags `h`, `p` (the shapes `workspace/crates/ambush-sdk/src/builders.rs:685-712` and `:576-592` emit; the relay validates `name` and `visibility` at `ambush-relay/src/handlers/ingest.rs:2793-2830`); `classify_ok`'s `ChannelAlreadyExists` arm (the relay's `duplicate: channel already exists`).
- Produces (used by Tasks 14, 22):
  - `channels::{CasePromotionTrigger, PromotionClause, PublishStep::{CreateChannel { channel: Uuid, name: String, visibility: &'static str, ttl_seconds: Option<i32> }, AddMember { channel: Uuid, pubkey: String }, PublishHold{..}, PublishAlarm{..}}, HoldId, CaseRouting}`; `CaseRouting::open(sidecar: &Path) -> Result<Self, BridgeError>`; `CaseRouting::ensure_case_channel(&mut self, trigger: &CasePromotionTrigger, operators: &[String], ttl_seconds: i32) -> Result<(Uuid, Vec<PublishStep>), BridgeError>`; `channels::lane_channel_steps(config: &PerchBridgeConfig, operators: &[String]) -> Vec<PublishStep>`; `channels::step_to_event(step: &PublishStep, keys: &nostr::Keys, created_at_secs: u64) -> Result<nostr::Event, BridgeError>`.
  - `alarm::run(spools, identities, config, operators, routing, supervisor, metrics, shutdown)`: drains the alarm spool one record per second, publishes `CasePromoted` steps, commits on success, and publishes the lane steps once at startup.
  - the log lines `case channel created` (`info`, with `case_id`, `hunt_id`, `clause`) and `lane channels ensured` (`info`, count).

- [ ] **Step 1: Copy only `channels.rs`, declare `pub mod channels;` in `lib.rs`, then write the failing unit tests** in `channels.rs`. Do not copy either future module alongside it:
  ```bash
  cp docs/plans/ambush-ui/build/skeleton/swarm-perch-bridge/src/channels.rs crates/swarm-perch-bridge/src/channels.rs
  ```
  ```rust
  #[test]
  fn a_manual_promotion_plans_create_plus_one_add_per_operator_and_is_idempotent() {
      let dir = tempfile::tempdir().unwrap();
      let mut routing = CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
      let case = uuid::Uuid::parse_str("9499a6e2-8872-453b-80d9-dafc6fc7fc69").unwrap();
      let trigger = CasePromotionTrigger::Promoted { hunt_id: "hunt-evt-1".into(), case_id: case, clause: PromotionClause::Manual };
      let ops = vec!["a".repeat(64), "b".repeat(64)];
      let (channel, steps) = routing.ensure_case_channel(&trigger, &ops, 2_592_000).unwrap();
      assert_eq!(channel, case);
      assert!(matches!(&steps[0], PublishStep::CreateChannel { channel, name, visibility: "private", ttl_seconds: Some(2_592_000) } if *channel == case && name == "case-9499a6e2"));
      assert_eq!(steps.len(), 3);
      // Replay: same hunt, same case → no steps. Different case → conflict, never a second channel.
      assert!(routing.ensure_case_channel(&trigger, &ops, 1).unwrap().1.is_empty());
      let other = CasePromotionTrigger::Promoted { hunt_id: "hunt-evt-1".into(), case_id: uuid::Uuid::new_v4(), clause: PromotionClause::Manual };
      assert!(matches!(routing.ensure_case_channel(&other, &ops, 1), Err(BridgeError::CaseChannelConflict { .. })));
      // Durable across reopen.
      let reopened = CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
      assert_eq!(reopened.case_for_hunt("hunt-evt-1"), Some(case));
  }

  #[test]
  fn lane_steps_cover_all_twelve_lanes_open_with_no_ttl() {
      let config = twelve_lane_config();
      let steps = lane_channel_steps(&config, &["c".repeat(64)]);
      let creates = steps.iter().filter(|s| matches!(s, PublishStep::CreateChannel { visibility: "open", ttl_seconds: None, .. })).count();
      let adds = steps.iter().filter(|s| matches!(s, PublishStep::AddMember { .. })).count();
      assert_eq!((creates, adds), (12, 12));
      assert!(steps.iter().any(|s| matches!(s, PublishStep::CreateChannel { name, .. } if name == "lane-lateral-movement")));
  }

  #[test]
  fn steps_become_the_relay_events_the_sdk_would_build() {
      let keys = nostr::Keys::generate();
      let case = uuid::Uuid::nil();
      let create = step_to_event(&PublishStep::CreateChannel { channel: case, name: "case-00000000".into(), visibility: "private", ttl_seconds: Some(60) }, &keys, 1_700_000_000).unwrap();
      assert_eq!(create.kind.as_u16(), 9007);
      let tags: Vec<Vec<String>> = create.tags.iter().map(|t| t.clone().to_vec()).collect();
      assert_eq!(tags, vec![vec!["h".into(), case.to_string()], vec!["name".into(), "case-00000000".into()], vec!["visibility".into(), "private".into()], vec!["channel_type".into(), "stream".into()], vec!["ttl".into(), "60".into()]]);
      let add = step_to_event(&PublishStep::AddMember { channel: case, pubkey: "A".repeat(64) }, &keys, 1_700_000_000).unwrap();
      assert_eq!(add.kind.as_u16(), 9000);
      assert_eq!(add.tags.iter().nth(1).map(|t| t.clone().to_vec()), Some(vec!["p".to_string(), "a".repeat(64)]));
  }

  #[test]
  fn a_hold_id_with_a_colon_is_refused() {
      assert!(HoldId::parse("hold:hunt-evt-1:1773738882600").is_err());
      assert!(HoldId::parse("27799e23-ab25-4659-b381-3de47ea7ca4d").is_ok());
  }
  ```

- [ ] **Step 2: Run** → compile failure. **Implement `channels.rs`.** Keep the skeleton's docs. `CaseRouting { path: PathBuf, hunts: BTreeMap<String, Uuid>, receipts: BTreeMap<String, String> }` persisted as JSON with write-then-rename (the same helper as the cursor; move it to `spool/cursor.rs` as `pub(crate) fn write_atomic(path, bytes)`). `ensure_case_channel`: look up `hunt_id`; `Held` on a routed hunt → `(existing, vec![])`; `Held` unrouted → mint `Uuid::new_v4()`; `Promoted` on a routed hunt → equal id → `(id, vec![])`, different → `CaseChannelConflict { hunt_id, existing, incoming }`; `Promoted` unrouted → adopt; on a new entry persist and return `CreateChannel { channel, name: format!("case-{}", &channel.to_string()[..8]), visibility: "private", ttl_seconds: Some(ttl_seconds) }` followed by one `AddMember` per operator. `lane_channel_steps`: for each `(slug, uuid)` in `config.lane_channels` (BTreeMap order): `CreateChannel { channel, name: format!("lane-{}", slug.replace('_', "-")), visibility: "open", ttl_seconds: None }` then one `AddMember` per operator. `step_to_event`: build tags as the test pins (lowercase the `p` value; `normalize_p_tag` it first and return `MalformedPTag` on failure), `EventBuilder::new(Kind::Custom(9007|9000), "").tags(tags).custom_created_at(Timestamp::from(created_at_secs)).sign_with_keys(keys)` mapped to `BridgeError::Encode`. `HoldId::parse` uses the already-decided R-3/W3-15 opaque pattern `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`; any colon is refused. The hold milestone pins this again with its full boundary corpus rather than replacing a placeholder.

  In `publish.rs`'s `the_bridge_never_sends_a_req_or_count_frame`, add
  `include_str!("channels.rs")` to the scanned file array now that the file exists.
  Run `rg -n 'todo!\(|unimplemented!\(' crates/swarm-perch-bridge/src/channels.rs`
  and require no matches before proceeding.

- [ ] **Step 3: `alarm.rs`.** The drainer runs on the alarm identity's `ConnectionSupervisor` and the same 1 Hz cadence as the pacer (a promotion is not a hold; it does not bypass the tick):
  ```rust
  pub async fn run<P: FramePublisher>(spools: Arc<Mutex<SpoolSet>>, identities: Arc<IdentityTable>, config: PerchBridgeConfig, operators: Vec<String>, mut routing: CaseRouting, mut publisher: P, metrics: BridgeMetrics, mut shutdown: watch::Receiver<bool>) -> Result<(), BridgeError> {
      // Startup: the twelve lanes, idempotently. A duplicate is success.
      let keys = identities.get(identities.alarm()).ok_or(BridgeError::InvalidConfig { reason: "no alarm identity".into() })?.keys.clone();
      for step in channels::lane_channel_steps(&config, &operators) {
          publish_step(&mut publisher, &step, &keys, &metrics).await?;
      }
      tracing::info!(module = module_path!(), lanes = config.lane_channels.len(), "lane channels ensured");
      let mut interval = tokio::time::interval(Duration::from_millis(config.publish_tick_ms));
      interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
      loop {
          tokio::select! {
              biased;
              changed = shutdown.changed() => { if changed.is_err() || *shutdown.borrow() { return Ok(()); } }
              _ = interval.tick() => {
                  let Some(record) = spools.lock().map_err(|_| BridgeError::Encode("spool mutex poisoned".into()))?.alarm().peek(PERCH_FRAME_MAX_BYTES)?.into_iter().next() else { continue };
                  let event: RuntimeEvent = serde_json::from_slice(&record.payload)?;
                  match event {
                      RuntimeEvent::CasePromoted { hunt_id, case_id, clause, threat_class, .. } => {
                          let case = uuid::Uuid::parse_str(&case_id).map_err(|_| BridgeError::InvalidConfig { reason: format!("daemon minted a non-uuid case_id {case_id}") })?;
                          let ttl = config.case_ttl_seconds.get(&threat_class_slug(&threat_class)).or(config.case_ttl_seconds.get("default")).copied().unwrap_or(2_592_000);
                          let trigger = CasePromotionTrigger::Promoted { hunt_id: hunt_id.clone(), case_id: case, clause: clause.into() };
                          match routing.ensure_case_channel(&trigger, &operators, ttl) {
                              Ok((_, steps)) => {
                                  let mut all_ok = true;
                                  for step in &steps { if let Err(e) = publish_step(&mut publisher, step, &keys, &metrics).await { all_ok = false; tracing::warn!(module = module_path!(), reason = %e, "case channel step failed; retrying next tick"); break; } }
                                  if all_ok {
                                      metrics.case_channel_created(clause.as_str());
                                      tracing::info!(module = module_path!(), %case_id, %hunt_id, clause = clause.as_str(), "case channel created");
                                      spools.lock().map_err(|_| BridgeError::Encode("spool mutex poisoned".into()))?.alarm().commit(record.issuer, record.seq)?;
                                  }
                              }
                              Err(BridgeError::CaseChannelConflict { .. }) => { metrics.case_channel_conflict(); spools.lock().map_err(|_| BridgeError::Encode("spool mutex poisoned".into()))?.alarm().commit(record.issuer, record.seq)?; }
                              Err(e) => return Err(e),
                          }
                      }
                      _ => {
                          // ModeTransition / TamperAlert: alarm-class facts this milestone does not publish.
                          metrics.skipped_unpublished(Stream::Alarm);
                          spools.lock().map_err(|_| BridgeError::Encode("spool mutex poisoned".into()))?.alarm().commit(record.issuer, record.seq)?;
                      }
                  }
              }
          }
      }
  }
  ```
  `publish_step` signs with `step_to_event(step, keys, now_secs)`, wraps in a `Frame`, calls `publisher.publish`, and treats `Accepted | ChannelAlreadyExists` as `Ok(())`, `NotAChannelMember | Rejected{..} | RateLimited{..} | AdmissionUnavailable | RelayForkAbsent | ClockSkew` as `Err(BridgeError::RelayRejected { message })` after counting `admission_rejections{reason}`. `From<CasePromotionClause> for PromotionClause` maps the three names. In `lib.rs::run`, spawn `alarm::run` beside the pacer with `ConnectionSupervisor::new(relay_url, alarm identity)`. Wire `metrics.case_channel_created(clause)`, `case_channel_conflict()`, `skipped_unpublished(stream)` onto `BridgeMetrics`.

- [ ] **Step 4: Live test extension** in `tests/relay_live.rs` (`#[ignore]`d):
  ```rust
  #[tokio::test]
  #[ignore = "needs PERCH_TEST_RELAY_URL and a live relay"]
  async fn a_case_channel_is_created_and_the_operator_is_a_member() {
      let url = std::env::var("PERCH_TEST_RELAY_URL").unwrap();
      let ingest = AgentId("swarm:ed25519:".to_string() + &"ab".repeat(32));
      let table = IdentityTable::build(&SecretString::new("42".repeat(32)), "relay-live", &[], &ingest, None).unwrap();
      let alarm = table.get(table.alarm()).unwrap();
      let operator = nostr::Keys::generate();
      let case = uuid::Uuid::new_v4();
      let steps = vec![
          PublishStep::CreateChannel { channel: case, name: format!("case-{}", &case.to_string()[..8]), visibility: "private", ttl_seconds: Some(3600) },
          PublishStep::AddMember { channel: case, pubkey: operator.public_key().to_hex() },
      ];
      let mut conn = ambush_ws_client::NostrWsConnection::connect_authenticated(&url, &alarm.keys, None).await.unwrap();
      for step in &steps {
          let ok = conn.send_event(step_to_event(step, &alarm.keys, now_secs()).unwrap()).await.unwrap();
          assert!(ok.accepted || ok.message.starts_with("duplicate: channel already exists"), "{}", ok.message);
      }
      // The TEST reads; the bridge never does. The operator's own socket sees the channel metadata.
      let mut reader = ambush_ws_client::NostrWsConnection::connect_authenticated(&url, &operator, None).await.unwrap();
      reader.send_raw(&serde_json::json!(["REQ", "case-check", {"kinds": [39000], "#d": [case.to_string()], "limit": 1}])).await.unwrap();
      let mut saw_metadata = false;
      for _ in 0..10 {
          match reader.next_event(std::time::Duration::from_secs(5)).await.unwrap() {
              ambush_ws_client::RelayMessage::Event { event, .. } if event.kind.as_u16() == 39000 => { saw_metadata = true; break; }
              ambush_ws_client::RelayMessage::Eose { .. } => break,
              _ => {}
          }
      }
      assert!(saw_metadata, "kind:39000 for the case channel must reach a member");
  }
  ```
  (`RelayMessage`'s variant names are in `workspace/crates/ambush-ws-client/src/message.rs:8-50`; use its spelling.) Expected on the dev stack: passes; a `restricted:` message names the scope the alarm identity lacks and is a provisioning fact for Task 14.

- [ ] **Step 5: Run** the unit tests → 4 passed; clippy and the panic gate clean.
- [ ] **Step 6: Commit.** `git add crates/swarm-perch-bridge && git commit -s -m "feat(perch-bridge): case channels on CasePromoted and the twelve lanes at startup, first-write-wins routing"`

### Task 14: Dev stack — the `perch` block, the seed, provisioning amendments, and `docs/PERCH-DEV.md`

> Records D-FC-5 (the bridge creates lanes) and amends Ground Task 10.

**Files:**
- Modify: `rulesets/perch-dev.yaml` (+ re-sign `rulesets/perch-dev.yaml.sig.json`), `docker-compose.yml` (`swarm-detect` env), `scripts/provision-perch.sh`, `.gitignore`, `docs/plans/ambush-ui/integration/00-DECISIONS.md` (D-FC-5 row), `docs/plans/ambush-ui/integration/11-PLAN-GROUND.md` (Task 10 step 2 note)
- Create: `docs/PERCH-DEV.md`, `.env.perch.example`
- Test: the daemon starts against the compose stack and `curl http://127.0.0.1:9090/metrics/perch/identities` lists three identities; twelve lanes exist on the relay

**Interfaces:**
- Consumes: Ground Task 9's ruleset and signer; Ground Task 10's compose services and script; Task 9's mount; Task 13's lane creation.
- Produces (used by Task 25): a runnable `docs/PERCH-DEV.md`; `.perch-dev/operator.nsec` (git-ignored) and `.perch-dev/identities.json`.

- [ ] **Step 1: Record D-FC-5** in `00-DECISIONS.md` §3:
  ```markdown
  | **D-FC-5** — who creates the twelve lane channels | **Default the plan builds under:** the bridge, idempotently, at startup (`swarm-perch-bridge/src/alarm.rs`), from the UUIDs committed in `perch.lane_channels`; the relay answers `duplicate: channel already exists` on every later start and the bridge treats that as success. `scripts/provision-perch.sh` no longer mints lanes (Ground Task 10 step 2 is amended: it prints keys, writes `.perch-dev/`, and adds relay memberships when `AMBUSH_REQUIRE_RELAY_MEMBERSHIP=true`). **Options:** (a) the script mints lanes with random ids and a local, unsigned copy of the ruleset carries them — rejected: the signed ruleset is the only config the daemon loads, and re-signing per machine multiplies sidecars; (b) extend `ambush channels create` with `--id` — a workspace CLI change for one script; kept as the fallback if the bridge must not hold `ChannelsWrite` on lanes. **Consequence:** a fresh relay database (`docker compose down -v`) recovers its lanes on the next daemon start with no operator action. **Dependents:** Task 13. | project owner |
  ```
  and in `11-PLAN-GROUND.md` Task 10 step 2 append: `(Amended by 12-PLAN-FIRST-CARD.md D-FC-5: the lanes are created by the bridge; this script only prints the dev operator key and writes .perch-dev/.)`.

- [ ] **Step 2: The `perch` block.** Append to `rulesets/perch-dev.yaml` (after `operator_surface:`):
  ```yaml
  perch:
    enabled: true
    relay_url: "ws://127.0.0.1:3000"
    nostr_seed_env: PERCH_BRIDGE_NOSTR_SEED
    # MUST resolve outside the repository (tools/check-worktree-clean.sh sweeps with find).
    spool_dir: "/tmp/ambush-perch-dev/spool"
    case_ttl_seconds:
      default: 2592000
    # Twelve standing lanes, one per standard threat class, created by the bridge at startup (D-FC-5).
    lane_channels:
      lateral_movement: "154eea36-c787-4bf7-9c84-4424b0184395"
      data_exfiltration: "c4c31b06-02a7-46c3-a0cb-8dba1f220be1"
      privilege_escalation: "bef7e4d9-3f8c-46f4-96a0-1e3bb88e741d"
      command_and_control: "56c17d5c-aeb3-48c8-b05a-088bc53b43f3"
      initial_access: "f0255b44-3e2f-4e6d-a55f-64eeeaf79c70"
      persistence: "955ef466-1b4f-4369-8e26-09494de7c9ff"
      supply_chain: "3c6fdb45-c783-47ba-b59e-3bd5e7eae750"
      defense_evasion: "ebf7c500-6bcb-4916-8a6e-d5db7cb18ea3"
      credential_access: "6c461f1b-688e-470b-8301-6547f35dc07c"
      discovery: "884aa52b-8ef7-47ef-919b-31b3606067ee"
      execution: "a30249d7-446b-4135-8e9f-8704a5a052b1"
      impact: "7e8f562f-5484-4e5f-9140-d071d7c4b60c"
  ```
  Keep `runtime.mode: detect_only` (D4) and Ground's `operator_surface.enabled: true`, `correlation.enabled: true`, file-backed incident store, `recent_decisions_limit: 200`. Re-sign: `cargo run -p swarm-runtime-http --bin sign_dev_ruleset -- rulesets/perch-dev.yaml && cargo run -p swarm-runtime-http --bin swarmctl -- validate --config rulesets/perch-dev.yaml` → valid. Commit the sidecar.

- [ ] **Step 3: The seed.** `.env.perch.example`:
  ```bash
  # Copy to .env.perch (git-ignored) and fill in. 32 bytes of hex; generate with:
  #   python3 -c 'import secrets; print(secrets.token_hex(32))'
  PERCH_BRIDGE_NOSTR_SEED=
  # The operator surface bearer the console and curl send (rulesets/perch-dev.yaml operator_surface.auth.token_env).
  SWARM_OPERATOR_TOKEN=dev-token-not-a-secret
  SWARM_PLATFORM_API_TOKEN=dev-platform-token
  ```
  Add to `.gitignore`: `.env.perch`, `.perch-dev/`. In `docker-compose.yml`, add `env_file: [.env.perch]` to `swarm-detect` and a `PERCH_BRIDGE_NOSTR_SEED: ${PERCH_BRIDGE_NOSTR_SEED}` line under its `environment:` (compose interpolates from the shell for the laptop-run daemon too). `tools/check-no-committed-keys.sh` must stay green: the example file carries an empty value, and a test (`tools/check-no-committed-keys.sh` itself, run in Step 6) proves it.

- [ ] **Step 4: Provisioning amendments** in `scripts/provision-perch.sh` (Ground's script; keep its key generation and its `.perch-dev/` output):
  - remove the twelve `ambush channels create` calls (D-FC-5) and the `lane-channels.json` writer;
  - keep printing the dev operator pubkey; also write the private key to `.perch-dev/operator.nsec` with `chmod 600` and print `import .perch-dev/operator.nsec into the desktop (onboarding → restore an existing identity)`;
  - after the daemon has started once, fetch the bridge identities: `curl -sf http://127.0.0.1:9090/metrics/perch/identities > .perch-dev/identities.json`;
  - when `AMBUSH_REQUIRE_RELAY_MEMBERSHIP=true` in `workspace/.env`, run `(cd workspace && cargo run -p ambush-admin -- add-member --pubkey <hex> --role member)` for each pubkey in `identities.json` and for the operator pubkey; the dev default (`workspace/.env.example` leaves the variable unset, `ambush-relay/src/config.rs:670`) is an open relay and the loop is skipped with a printed note.

- [ ] **Step 5: `docs/PERCH-DEV.md`** — the demo script, transcribed from `20-TASK-BREAKDOWN.md` §8.3 with every correction this milestone forces:
  ````markdown
  # PERCH-DEV — the First-card walking skeleton, end to end

  DEBUG BUILD ONLY: `rulesets/perch-dev.yaml` is signed with the in-repo debug key and a `--release` daemon refuses it (correct: production signs its own).

  ```bash
  #!/usr/bin/env bash
  set -euo pipefail
  cd "$(git rev-parse --show-toplevel)"
  set -a; . ./.env.perch; set +a            # PERCH_BRIDGE_NOSTR_SEED, SWARM_OPERATOR_TOKEN, SWARM_PLATFORM_API_TOKEN

  # 1. Sign the dev ruleset (idempotent; the sidecar is committed and this must leave the tree clean).
  cargo run -p swarm-runtime-http --bin sign_dev_ruleset -- rulesets/perch-dev.yaml
  test -z "$(git status --porcelain rulesets/)"

  # 2. The relay stack.
  docker compose up -d postgres redis relay
  curl -sf -H 'Accept: application/nostr+json' http://localhost:3000 | head -c 200; echo

  # 3. Keys: the dev operator identity and the bridge identities.
  bash scripts/provision-perch.sh                       # writes .perch-dev/operator.nsec and prints the operator pubkey

  # 4. The daemon, detect-only, with the operator surface and the bridge.
  cargo run -p swarm-runtime-http --bin swarm_detect -- --config rulesets/perch-dev.yaml --serve --bind 127.0.0.1:9090 > .perch-dev/daemon.log 2>&1 &
  DAEMON=$!; sleep 6
  curl -sf http://127.0.0.1:9090/readyz
  grep -q 'perch bridge mounted' .perch-dev/daemon.log
  grep -q 'perch operator routes mounted' .perch-dev/daemon.log     # only the new router prints this; demo mode never does
  grep -q 'lane channels ensured' .perch-dev/daemon.log
  curl -sf http://127.0.0.1:9090/metrics/perch/identities > .perch-dev/identities.json
  INGEST_PUBKEY=$(python3 -c 'import json;print([i for i in json.load(open(".perch-dev/identities.json"))["identities"] if i["slot"].startswith("swarm:")][0]["pubkey"])')

  # 5. Real telemetry through the real pipeline (not /v1/demo/replay).
  python3 - <<'PY' > .perch-dev/events.json
  import json, yaml, pathlib
  doc = yaml.safe_load(pathlib.Path("scenarios/office-dropper-correlation.yaml").read_text())
  print(json.dumps([step["event"] for step in doc["input"]["events"]]))
  PY
  curl -sf -X POST http://127.0.0.1:9090/v1/ingest/events -H 'content-type: application/json' --data @.perch-dev/events.json | python3 -c 'import json,sys;print([r["status"] for r in json.load(sys.stdin)])'

  # 6. The card crossed the seam — read from the RELAY, out of process, before the app opens. Budget: two seconds.
  LANE=$(python3 -c 'import yaml;print(yaml.safe_load(open("rulesets/perch-dev.yaml"))["perch"]["lane_channels"]["execution"])')
  sleep 2
  PERCH_TEST_RELAY_URL=ws://localhost:3000 PERCH_TEST_LANE_CHANNEL="$LANE" PERCH_TEST_EXPECT_AUTHOR="$INGEST_PUBKEY" \
    cargo test -p swarm-perch-bridge --test relay_live -- --ignored lane_carries_a_finding_card_from_the_ingest_identity
  ```

  Step 6 is a Rust test rather than a `curl` because `POST /query` needs a NIP-98 header and the bridge's own key must not be used to read (it never reads). The test opens a socket with a throwaway key, `REQ`s `{"kinds":[9], "#h":[LANE], "authors":[INGEST_PUBKEY], "limit": 20}`, and asserts at least one event whose line 0 is exactly `<!-- swarm:finding:v1 -->`.

  7. Open the desktop (`cd workspace && just desktop-dev`, or the Tauri app), restore the identity from `.perch-dev/operator.nsec`, add the community `ws://localhost:3000`, enable Settings → Experiments → "Operator console", and open `#lane-execution`: the finding renders as a card badged `secp256k1 · tier 0 · TRANSPORT-SIGNED ONLY · the daemon is the record`. Press `E` → the case opens (`/cases/<case_id>`; "opening the case" until the bridge's `case channel created` line appears in the daemon log). Press `D` → the write-state row goes `sending → recorded → acknowledged`.

  8. Assert the verdict moved the report — run this BEFORE step 7 too and diff, so a pre-existing measurement cannot be mistaken for the verdict's:
  ```bash
  curl -sf http://127.0.0.1:9090/v2/api/runtime/status -H "Authorization: Bearer $SWARM_PLATFORM_API_TOKEN" -H 'x-swarm-schema-version: 1' \
    | python3 -c 'import json,sys;d=json.load(sys.stdin)["data"][0];print(json.dumps({"reviewed":d["false_positive_tracking"],"recommendations":d["alert_tuning"]["recommendations"]},indent=1))' > .perch-dev/status-after.json
  diff .perch-dev/status-before.json .perch-dev/status-after.json || true
  ```
  Thresholds (`alert_tuning.rs:6-15`): host 2 reviewed / 2 FP / 0.75; detector threshold 4 / 2 / 0.50; rule 3 / 2 / 0.34. One Dismiss moves `reviewed_findings` and `false_positive_findings`; a recommendation needs two Dismisses on the same host.

  9. The relay dies for a minute; nothing is lost.
  ```bash
  docker compose stop relay; sleep 60; docker compose start relay
  curl -sf -X POST http://127.0.0.1:9090/v1/ingest/events -H 'content-type: application/json' --data @.perch-dev/events.json > /dev/null
  PERCH_TEST_RELAY_URL=ws://localhost:3000 PERCH_TEST_LANE_CHANNEL="$LANE" PERCH_TEST_EXPECT_AUTHOR="$INGEST_PUBKEY" \
    cargo test -p swarm-perch-bridge --test relay_live -- --ignored the_lane_seq_run_is_contiguous
  ```

  10. A gap renders as a gap.
  ```bash
  curl -sf -X POST http://127.0.0.1:9090/metrics/perch/test/stall -H 'content-type: application/json' -d '{"ms": 3000}'
  for i in $(seq 1 40); do curl -sf -X POST http://127.0.0.1:9090/v1/ingest/events -H 'content-type: application/json' --data @.perch-dev/events.json > /dev/null; done
  ```
  More than 1,024 runtime events accumulate during the stall (each ingest publishes `Ingest`, `Finding`, and the 10 Hz concentration snapshots keep coming). The next finding card carries `gap.cause = "broadcast_lagged"` with a COUNT and no range, and the desktop renders the gap notice above that card.
  ````
  Add the two named live tests to `tests/relay_live.rs`: `lane_carries_a_finding_card_from_the_ingest_identity` (REQ as described; assert line 0) and `the_lane_seq_run_is_contiguous` (REQ `limit: 500`, parse every card's envelope `seq` for `PERCH_TEST_EXPECT_AUTHOR`, sort, assert `windows(2)` differ by exactly 1 and the count is ≥ 4).

- [ ] **Step 6: Run the stack once, end to end through step 6.** Expected: every `grep -q` succeeds; the `lane_carries_a_finding_card…` test passes within the two-second sleep. `bash tools/check-no-committed-keys.sh` → green; `bash tools/check-worktree-clean.sh "perch dev"` → green (the spool is under `/tmp`).
- [ ] **Step 7: Commit.** `git add rulesets docker-compose.yml scripts/provision-perch.sh .gitignore .env.perch.example docs/PERCH-DEV.md docs/plans/ambush-ui/integration crates/swarm-perch-bridge/tests && git commit -s -m "feat(dev): perch block, seed plumbing, bridge-created lanes, and the PERCH-DEV walking-skeleton script"`

### Task 15: Decisions D-FC-2 and D-FC-4 — the admitted-issuer source; bearer, URL and operator id provisioning

**Files:**
- Modify: `docs/plans/ambush-ui/integration/00-DECISIONS.md` (§3 table)

- [ ] **Step 1: Record both rows.**
  ```markdown
  | **D-FC-2** — where the console learns the admitted-issuer set (INV-15) | **Default the plan builds under:** the daemon serves `GET /metrics/perch/identities` → `{colony_id, identities: [{slot, pubkey}]}` (public keys only, unauthenticated, on the same listener as `/metrics/perch`); the Tauri command `perch_admitted_issuers` reads it and the renderer caches it under the `daemon` query source with a five-minute stale time. The skeleton's `perchKeys.admittedIssuers` moves from the `relay` source to `daemon`. **Options:** (a) each bridge identity publishes a `kind:0` profile carrying a `swarm-agent` tag and the console trusts the relay's copy — rejected: the relay is not the record and a forged profile is one `MessagesWrite` away; (b) an operator pastes the provisioning report into Settings — kept for air-gapped consoles, Operator-complete; (c) a bearer-authenticated `/v1/operator/perch/identities` — rejected for now: public keys are public, and the metrics listener is reachable from the console's daemon URL already. **Dependents:** Tasks 17, 19. | project owner |
  | **D-FC-4** — operator bearer, daemon URL and operator id on the console | **Default the plan builds under:** debug builds seed the keyring blob at startup from `AMBUSH_PERCH_DAEMON_URL` (default `http://127.0.0.1:9090`), `AMBUSH_PERCH_DAEMON_BEARER` and `AMBUSH_PERCH_OPERATOR_ID` (default `local-operator`, the id `rulesets/perch-dev.yaml`'s principal carries) when the corresponding keyring keys `perch.daemon_url`, `perch.daemon_bearer`, `perch.operator_id` are absent; a release build reads the keyring only and renders "daemon not configured" until a Settings surface (Operator-complete) stores them. The operator Ed25519 key (`perch.operator_ed25519`) is minted on first use and never leaves the process. **Options:** a Settings form now (0.5 d of UI with no design ground yet), or a deep-link `ambush://perch/configure?…` — both deferred. **Dependents:** Tasks 19, 21. | project owner |
  ```
- [ ] **Step 2: Commit.** `git commit -s -am "docs(decisions): D-FC-2 admitted-issuer source and D-FC-4 console provisioning defaults"`

### Task 16: The `/cases/$caseId` route, the surface hook, and the feature gate in use

**Files:**
- Create: `workspace/desktop/src/app/routes/cases.$caseId.tsx`, `workspace/desktop/src/app/perchViews.ts`, `workspace/desktop/src/app/perchViews.test.mjs`, `workspace/desktop/src/features/perch-evidence/ui/SwarmCardSurface.tsx`
- Modify: `workspace/desktop/src/app/routes.ts` (one `route(...)` line)
- Test: `cd workspace/desktop && node --test src/app/perchViews.test.mjs`; `cd workspace && just desktop-typecheck`

**Interfaces:**
- Consumes: `createFileRoute` / `Navigate` from `@tanstack/react-router`; `useFeatureEnabled`, `usePreviewFeatureWarning` (`shared/features/useFeatureEnabled.ts`); `ChannelRouteScreen` (`app/routes/ChannelRouteScreen.tsx`, props `autoSendDraftKey, channelId, searchHighlight, selectedPostId, targetMessageId, targetReplyId, targetThreadRootId`); `useChannelsQuery` (`features/channels/hooks`); `ViewLoadingFallback`.
- Produces (used by Tasks 17, 22, 23):
  - `derivePerchShellRoute(pathname: string): { selectedView: "case" | "other"; selectedCaseId: string | null }`.
  - `SwarmCardSurfaceProvider({ surface, caseChannelId, children })` and `useSwarmCardSurface(): SwarmCardSurface` where `type SwarmCardSurface = { enabled: boolean; surface: "case" | "lane" | "other"; caseChannelId: string | null }`. Without a provider the hook derives `surface` from the router location (`/cases/` → `case`, `/channels/` → `lane`, else `other`) and `enabled` from `useFeatureEnabled("perch")`, so the seam works in lane channels with no provider and `MessageRow`'s parents are untouched.
  - the `data-testid`s `perch-case-opening`, `perch-case-not-found`, `perch-case-timeline` (the wrapper around the channel screen).

- [ ] **Step 1: Failing test** `perchViews.test.mjs`:
  ```js
  import test from "node:test"; import assert from "node:assert/strict";
  import { derivePerchShellRoute } from "./perchViews.ts";
  test("a case path selects the case and carries its id", () => {
    assert.deepEqual(derivePerchShellRoute("/cases/9499a6e2-8872-453b-80d9-dafc6fc7fc69"), { selectedView: "case", selectedCaseId: "9499a6e2-8872-453b-80d9-dafc6fc7fc69" });
    assert.deepEqual(derivePerchShellRoute("/channels/abc"), { selectedView: "other", selectedCaseId: null });
    assert.deepEqual(derivePerchShellRoute("/cases/"), { selectedView: "case", selectedCaseId: null });
  });
  ```
  Run → module not found. Implement `perchViews.ts` with the skeleton's `segment()` helper and a two-member view (the full eleven-view union is Operator-complete's).

- [ ] **Step 2: The surface hook.** `SwarmCardSurface.tsx`:
  ```tsx
  import * as React from "react";
  import { useLocation } from "@tanstack/react-router";
  import { useFeatureEnabled } from "@/shared/features/useFeatureEnabled";
  import { derivePerchShellRoute } from "@/app/perchViews";

  export type SwarmCardSurface = { enabled: boolean; surface: "case" | "lane" | "other"; caseChannelId: string | null };
  const Ctx = React.createContext<Omit<SwarmCardSurface, "enabled"> | null>(null);

  export function SwarmCardSurfaceProvider({ surface, caseChannelId, children }: { surface: "case" | "lane"; caseChannelId: string | null; children: React.ReactNode }) {
    const value = React.useMemo(() => ({ surface, caseChannelId }), [surface, caseChannelId]);
    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
  }

  export function useSwarmCardSurface(): SwarmCardSurface {
    const enabled = useFeatureEnabled("perch");
    const provided = React.useContext(Ctx);
    const pathname = useLocation({ select: (l) => l.pathname });
    return React.useMemo(() => {
      if (provided) return { enabled, ...provided };
      const route = derivePerchShellRoute(pathname);
      if (route.selectedView === "case") return { enabled, surface: "case", caseChannelId: route.selectedCaseId };
      return { enabled, surface: pathname.startsWith("/channels/") ? "lane" : "other", caseChannelId: null };
    }, [enabled, provided, pathname]);
  }
  ```
  (`useMemo` keeps the object reference-stable per input so `MessageBody`'s memoised parents are not defeated — `CLAUDE.md` gotcha 6.)

- [ ] **Step 3: The route.** `routes.ts`: add `route("/cases/$caseId", "cases.$caseId.tsx"),` after the `/channels/$channelId` line. `cases.$caseId.tsx`:
  ```tsx
  import * as React from "react";
  import { createFileRoute, Navigate } from "@tanstack/react-router";
  import { useChannelsQuery } from "@/features/channels/hooks";
  import { SwarmCardSurfaceProvider } from "@/features/perch-evidence/ui/SwarmCardSurface";
  import { useFeatureEnabled, usePreviewFeatureWarning } from "@/shared/features/useFeatureEnabled";
  import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

  const ChannelRouteScreen = React.lazy(async () => ({ default: (await import("./ChannelRouteScreen")).ChannelRouteScreen }));
  const CASE_OPEN_TIMEOUT_MS = 60_000;

  export const Route = createFileRoute("/cases/$caseId")({ component: CaseRouteComponent });

  function CaseRouteComponent() {
    const { caseId } = Route.useParams();
    const enabled = useFeatureEnabled("perch");
    usePreviewFeatureWarning("perch");
    if (!enabled) return <Navigate to="/channels/$channelId" params={{ channelId: caseId }} />;
    return (
      <SwarmCardSurfaceProvider surface="case" caseChannelId={caseId}>
        <CaseOpening caseId={caseId}>
          <div data-testid="perch-case-timeline" className="contents">
            <React.Suspense fallback={<ViewLoadingFallback includeHeader kind="channel" />}>
              <ChannelRouteScreen autoSendDraftKey={null} channelId={caseId} searchHighlight={null} selectedPostId={null} targetMessageId={null} targetReplyId={null} targetThreadRootId={null} />
            </React.Suspense>
          </div>
        </CaseOpening>
      </SwarmCardSurfaceProvider>
    );
  }

  function CaseOpening({ caseId, children }: { caseId: string; children: React.ReactNode }) {
    const channels = useChannelsQuery();
    const known = (channels.data ?? []).some((c) => c.id === caseId);
    const [startedAt] = React.useState(() => Date.now());
    const [timedOut, setTimedOut] = React.useState(false);
    React.useEffect(() => {
      if (known) return;
      const id = window.setInterval(() => {
        void channels.refetch();
        if (Date.now() - startedAt > CASE_OPEN_TIMEOUT_MS) setTimedOut(true);
      }, 1_000);
      return () => window.clearInterval(id);
    }, [known, startedAt, channels.refetch]);
    if (known) return children;
    if (timedOut) return <p data-testid="perch-case-not-found" className="p-4 text-sm text-[var(--perch-foreground-muted)]">The daemon promoted this finding, but no case channel arrived in 60 seconds. The bridge creates it; check the daemon log for "case channel created".</p>;
    return <p data-testid="perch-case-opening" role="status" className="p-4 text-sm text-[var(--perch-foreground-muted)]">Opening the case. The bridge is creating its channel.</p>;
  }
  ```
  `useChannelsQuery`'s result shape is the one `ChannelRouteScreen.tsx` already destructures; depend on `channels.refetch` (stable) and never on the result object (gotcha 6). If the `--perch-foreground-muted` token does not exist yet in `workspace/desktop/src/index.css`, add the four tokens Task 17 needs (`--perch-card`, `--perch-border-strong`, `--perch-foreground`, `--perch-foreground-muted`) with the values `19-TOKENS.md` gives, in the same `:root` block that defines the Quiet tokens.

- [ ] **Step 4: Regenerate the route tree and gate.** `cd workspace/desktop && pnpm build:e2e` (the vite plugin regenerates `src/app/routeTree.gen.ts`; commit it), then `cd workspace && just desktop-check && just desktop-typecheck && just file-size-check && (cd desktop && node --test src/app/perchViews.test.mjs)` → green.
- [ ] **Step 5: Commit.** `git add workspace/desktop/src/app workspace/desktop/src/features/perch-evidence && git commit -s -m "feat(desktop): /cases/\$caseId behind the perch feature, and the swarm card surface hook"`

### Task 17: The marker parser, the card registry, the frame, the finding card, and the `MessageBody` seam

> Blocked on D-FC-2 (Task 15) for the admitted-issuer source; built under its default.

**Files:**
- Create: `workspace/desktop/src/features/perch-evidence/lib/{markerTypes.ts, parseSwarmMarker.ts, parseSwarmMarker.test.mjs, admittedIssuers.ts, admittedIssuers.test.mjs, adversaryText.ts, adversaryText.test.mjs}`, `workspace/desktop/src/features/perch-evidence/ui/{swarmCardRegistry.tsx, EvidenceCardFrame.tsx, RefusalCards.tsx, NotYetRenderedCard.tsx, GapNotice.tsx, UnadmittedMarkerNotice.tsx, cards/FindingCard.tsx}`, `workspace/desktop/src/shared/ui/perch/AdversaryString.tsx`
- Modify: `workspace/desktop/src/features/messages/ui/MessageBody.tsx` (the seam comment line only), `workspace/desktop/src/index.css` (the `--perch-*` tokens, if Task 16 did not add them)
- Test: `cd workspace/desktop && node --test src/features/perch-evidence/lib/parseSwarmMarker.test.mjs src/features/perch-evidence/lib/admittedIssuers.test.mjs src/features/perch-evidence/lib/adversaryText.test.mjs`; `cd workspace && just check`

**Interfaces:**
- Consumes: Task 2's `parseCardParts`, `admitCard`, `envelopeTier`, `Card`/`FindingCard` types; Task 16's `useSwarmCardSurface`; `TimelineMessage { id, body, tags, signerPubkey, pubkey, … }` (`features/messages/types.ts:14-41`); `getChannelIdFromTags` (`features/messages/lib/threading.ts:12`); Task 19's `perchAdmittedIssuers()` wrapper (until it lands, `admittedIssuers.ts` is fed by tests and by the E2E fixture).
- Produces (used by Tasks 22, 23):
  - `lib/markerTypes.ts`: `SwarmMarkerKind`, `SWARM_MARKER_KINDS`, `SWARM_MARKER_VERSION = 1`, `swarmMarkerComment(kind)`, `SwarmMarkerCard { kind, version, rawBody, issuerPubkey, channelTag, eventId }`, `SwarmMarkerParse` (five statuses: `not-a-marker | unadmitted-issuer | unknown-kind | unsupported-version | ok`), `SwarmCardContext { surface, caseChannelId, searchQuery, density }`, `SwarmCardDecoder<T> = (card: SwarmMarkerCard) => SwarmCardDecodeResult<T>`, `SwarmCardEntry { pillar, homeSurface, render }`, `PerchPillar`.
  - `lib/parseSwarmMarker.ts`: `parseSwarmMarker({ content, signerPubkey, channelTag, eventId, isAdmittedIssuer }): SwarmMarkerParse`.
  - `lib/admittedIssuers.ts`: `setAdmittedIssuers(pubkeys: readonly string[], lanes: Readonly<Record<string, string>>)`, `isAdmittedIssuer(pubkey: string): boolean` (module-level, reference-stable), `useAdmittedIssuerPredicate(): (pubkey: string) => boolean`, `perchLaneChannelIds(): readonly string[]`, `countUnadmittedMarker(eventId: string)`, `readPerchCounter(name: "perch_marker_unadmitted_total"): number`, `subscribePerchCounters(listener)`, `resetPerchAdmittedIssuers()`, `ensureAdmittedIssuersLoaded(loader: () => Promise<{ issuers: string[]; lanes: Record<string, string> }>)`.
  - `lib/adversaryText.ts`: `escapeAdversaryText(value: string): ReadonlyArray<{ kind: "text"; text: string } | { kind: "escaped"; codepoint: string; glyph: string }>`; `ADVERSARY_CAP = 512`.
  - `ui/swarmCardRegistry.tsx`: `defineSwarmCard`, `SWARM_CARD_REGISTRY satisfies Record<SwarmMarkerKind, SwarmCardEntry>`, `SwarmEvidenceCard({ parsed, ctx })`.
  - `ui/EvidenceCardFrame.tsx`: `EvidenceCardFrame({ kind, pillar, eventId, issuerPubkey, tier, gap, children })` with `data-testid="perch-evidence-frame"`, the tier badge, and the `TIER_0_BADGE = "secp256k1 · tier 0 · TRANSPORT-SIGNED ONLY · the daemon is the record"` constant.
  - `ui/cards/FindingCard.tsx`: `findingCardEntry`, a read-only `FindingCardPresenter`, `data-testid="perch-evidence-finding"`; Task 23 creates and mounts the action component atomically with its real workflow.
  - `shared/ui/perch/AdversaryString.tsx`: `AdversaryString({ value, field, cap, layout, className })`, `data-perch-role="adversary-string"`, `data-testid="perch-adversary-string"`, escaped glyphs carry `data-testid="perch-escaped-codepoint"` and `title="U+202E RIGHT-TO-LEFT OVERRIDE"` (the codepoint name from a fixed table; unknown codepoints get `title="U+XXXX"`).
  - The seam in `MessageBody.tsx` (eleven lines, below).

- [ ] **Step 1: Failing parser tests** `parseSwarmMarker.test.mjs`:
  ```js
  import test from "node:test"; import assert from "node:assert/strict";
  import { parseSwarmMarker } from "./parseSwarmMarker.ts";
  const ADMITTED = "207176338a897b2379564322033e86ed7197600499ba348e6c6c898b8139b586";
  const admit = (pk) => pk === ADMITTED;
  const parse = (content, signerPubkey = ADMITTED) => parseSwarmMarker({ content, signerPubkey, channelTag: "h1", eventId: "e1", isAdmittedIssuer: admit });

  test("the marker fires only when it is the whole of line 0 (trimEnd, never trimStart)", () => {
    assert.equal(parse("<!-- swarm:finding:v1 -->\nx").status, "ok");
    assert.equal(parse("<!-- swarm:finding:v1 -->\r\nx").status, "ok");
    assert.equal(parse(" <!-- swarm:finding:v1 -->\nx").status, "not-a-marker");
    assert.equal(parse("<!-- swarm:finding:v1 --> hello\nx").status, "not-a-marker");
    assert.equal(parse("hello\n<!-- swarm:finding:v1 -->").status, "not-a-marker");
    assert.equal(parse("<!-- ambush:wave:v1 -->\nx").status, "not-a-marker");
  });

  test("an unadmitted signer is reported with its slug, never as a card", () => {
    const r = parse("<!-- swarm:hold:v1 -->\nx", "684949a3287973d209a80c63057ff9e099ede5996b18288936db5e318fafbde5");
    assert.deepEqual(r, { status: "unadmitted-issuer", slug: "hold", issuerPubkey: "684949a3287973d209a80c63057ff9e099ede5996b18288936db5e318fafbde5" });
    assert.equal(parse("<!-- swarm:hold:v1 -->\nx", undefined).status, "unadmitted-issuer");
    assert.equal(parse("<!-- swarm:hold:v1 -->\nx", "NOT-HEX").status, "unadmitted-issuer");
  });

  test("unknown kinds and other versions are named refusals, and rawBody is byte-exact", () => {
    assert.equal(parse("<!-- swarm:teapot:v1 -->\n{}").status, "unknown-kind");
    const v2 = parse("<!-- swarm:hold:v2 -->\n  body  \n");
    assert.equal(v2.status, "unsupported-version");
    assert.equal(v2.card.rawBody, "  body  \n");
    const ok = parse("<!-- swarm:finding:v1 -->\nline1\n\n```swarm:finding:v1\n{}\n```");
    assert.equal(ok.card.issuerPubkey, ADMITTED);
    assert.equal(ok.card.channelTag, "h1");
  });

  test("the parser and the Rust sign gate agree on line 0", () => {
    // Pairs taken from perch_sign_gate.rs's tests (Ground Task 5): what the gate refuses, this parses; what it signs, this ignores.
    for (const line of ["<!-- swarm:verdict:v1 -->", "<!-- swarm:finding:v1 -->", "<!-- swarm:hold:v12 -->   "]) assert.notEqual(parse(`${line}\n{}`).status, "not-a-marker", line);
    for (const line of ["<!-- ambush:wave:v1 -->", "hello <!-- swarm:verdict:v1 -->", " <!-- swarm:verdict:v1 -->"]) assert.equal(parse(`${line}\n{}`).status, "not-a-marker", line);
  });
  ```
  Run → module not found. Implement `markerTypes.ts` and `parseSwarmMarker.ts` from `17` §3.3–3.4 with `ambush` → `swarm` and `MARKER_RE = /^<!--\s+swarm:([a-z][a-z-]*):v(\d{1,3})\s+-->$/` (accepting the same interior whitespace Ground's `is_swarm_marker_line` accepts); the decoder signature takes the whole `SwarmMarkerCard` (it needs `issuerPubkey` for `admitCard`) — a deliberate one-argument widening of `17` §3.3's `(rawBody)`.

- [ ] **Step 2: Admitted issuers and counters** — failing test `admittedIssuers.test.mjs`:
  ```js
  test("the predicate is reference-stable across set updates and false when empty", () => {
    const before = isAdmittedIssuer;
    assert.equal(isAdmittedIssuer("ab".repeat(32)), false);
    setAdmittedIssuers(["AB".repeat(32)], { execution: "a30249d7-446b-4135-8e9f-8704a5a052b1" });
    assert.equal(isAdmittedIssuer("ab".repeat(32)), true, "lowercased on set");
    assert.equal(before, isAdmittedIssuer);
    assert.deepEqual(perchLaneChannelIds(), ["a30249d7-446b-4135-8e9f-8704a5a052b1"]);
    countUnadmittedMarker("e1"); countUnadmittedMarker("e1"); countUnadmittedMarker("e2");
    assert.equal(readPerchCounter("perch_marker_unadmitted_total"), 2, "one count per event id");
    resetPerchAdmittedIssuers();
    assert.equal(isAdmittedIssuer("ab".repeat(32)), false);
    assert.equal(readPerchCounter("perch_marker_unadmitted_total"), 0);
  });
  ```
  Implement with module-level `let admitted = new Set<string>()`, `let lanes: Record<string, string> = {}`, `const countedEvents = new Set<string>()`, `let unadmittedTotal = 0`, a listener set plus `emit()`, `useAdmittedIssuerPredicate()` = `useSyncExternalStore(subscribe, () => version, () => 0)` followed by `return isAdmittedIssuer` (the function identity never changes; the version bump re-renders subscribers), and `ensureAdmittedIssuersLoaded(loader)` that calls `loader()` at most once per five minutes (module-level `loadedAt`) and applies the result through `setAdmittedIssuers`; a failed load keeps the previous set and logs with `console.warn`. Export `resetPerchAdmittedIssuers` for Task 18's registry.

- [ ] **Step 3: `adversaryText.ts`** — failing test (escape sequences, never literal invisible characters, so the test file stays readable):
  ```js
  test("control, bidi and zero-width codepoints become named glyphs; a newline too", () => {
    const parts = escapeAdversaryText("isolate\u202Ehost\u200B\nsecond");
    const escaped = parts.filter((p) => p.kind === "escaped");
    assert.deepEqual(escaped.map((p) => p.codepoint), ["U+202E", "U+200B", "U+000A"]);
    assert.equal(parts.filter((p) => p.kind === "text").map((p) => p.text).join(""), "isolatehostsecond");
  });
  ```
  Implement: iterate `for (const ch of value)` (code points); a code point is escaped when it is in `U+0000–U+001F`, `U+007F–U+009F`, `U+200B–U+200F`, `U+202A–U+202E`, `U+2066–U+2069`, or is `U+FEFF`; `codepoint = "U+" + hex.toUpperCase().padStart(4, "0")`; `glyph` is `"␀" + code` for C0 controls (the Control Pictures block: U+240A renders newline as a visible symbol), `"␣"` for the zero-width class, `"⇄"` for the bidi classes, `"␀"` otherwise; adjacent text runs are merged. A `CODEPOINT_NAMES` table maps `U+202E → RIGHT-TO-LEFT OVERRIDE`, `U+200B → ZERO WIDTH SPACE`, `U+000A → LINE FEED`, `U+FEFF → ZERO WIDTH NO-BREAK SPACE`, `U+202A–U+202D`, `U+2066–U+2069` by their Unicode names; the rest render the codepoint alone.

- [ ] **Step 4: Components.** `AdversaryString.tsx` per `17` §4.1: a plain text node per part, `font-mono whitespace-pre-wrap break-all text-sm`, wrapped in typographic quotes that belong to the component, inside a 1px rail labelled `ADVERSARY-CONTROLLED` (`text-eyebrow` if that token exists in `tailwind.config.js`, else `text-2xs uppercase tracking-wide`), `aria-label={`${field}, adversary-controlled value`}`, a cap of `cap ?? 512` graphemes via `new Intl.Segmenter(undefined, { granularity: "grapheme" })` with `<button type="button" data-testid="perch-adversary-string-expand">show all {n} characters</button>`, the literal `EMPTY` token for an empty value, and `· CONTAINS ESCAPED CHARACTERS` appended to the rail label when any part is escaped. Tokens: `--perch-surface-raised`, `--perch-border-strong`, `--perch-foreground`, `--perch-foreground-muted`. Refuses `children` (not in its props type).
  `EvidenceCardFrame.tsx`: `<article data-testid="perch-evidence-frame" data-perch-role="evidence-card" data-perch-pillar={pillar} role="status" className="rounded border-l-4 …">` with a header row (eyebrow `kind.toUpperCase()`, except `lease` → `CONTAINMENT LEASE`), the badge `<span data-testid="perch-tier-badge">{TIER_0_BADGE}</span>` when `tier === 0`, `<GapNotice gap={gap} />` when `gap` is set, then `children`, then a footer `event {eventId.slice(0, 8)} · signer {issuerPubkey.slice(0, 8)}` in `text-2xs`. Never the words "verified", "signed" or "Perch" (Task 24's gate reads this file).
  `GapNotice.tsx`: `<p data-testid="perch-gap-notice" role="status">` — for `broadcast_lagged`: `{count} events were lost before the bridge saw them (the runtime's broadcast lagged). Nothing between the previous card and this one can be recovered from the relay; the daemon holds its own record.`; for the three spool causes: `Cards {from_seq}–{to_seq} from this issuer were {evicted from | torn from | expired in} the bridge spool and cannot be delivered.`
  `RefusalCards.tsx`: the four components of `17` §3.6 with their `data-testid`s (`perch-evidence-undecodable`, `perch-evidence-unknown-kind`, `perch-evidence-unsupported-version`, `perch-evidence-misplaced`), each `role="status"` without `aria-live`; `MisplacedCard` with `reason="channel-mismatch"` additionally renders `<span data-testid="perch-channel-mismatch-notice">tagged for channel {card.channelTag}</span>`. `UnsupportedVersionCard`'s copy contains the literal `this console reads version 1`.
  `NotYetRenderedCard.tsx`: `data-testid="perch-evidence-not-yet-rendered"`, copy `This console does not yet render {kind} cards. The daemon holds the record.` — the presenter for the six kinds this milestone does not render, so the registry stays exhaustive and honest.
  `UnadmittedMarkerNotice.tsx`: `<p data-testid="perch-unadmitted-marker-notice" className="text-2xs …">This message carries a {slug} card marker from a signer this console does not admit. It is shown as text and counted.</p>`, with `useEffect(() => countUnadmittedMarker(eventId), [eventId])`. (`17` §3.6 says the unadmitted case renders "nothing of its own"; the skeleton spec `perch-marker-admission.spec.ts` test 02 asserts a visible notice. The notice is one line of text beside the prose, not a card, and is what the spec asserts.)
  `swarmCardRegistry.tsx`: `defineSwarmCard` (from `17` §3.3, decoder takes the card), then
  ```tsx
  export const SWARM_CARD_REGISTRY = {
    finding: findingCardEntry,
    escalation: notYetRendered("escalation", "authority", ["case", "lane"]),
    hold: notYetRendered("hold", "authority", ["case"]),
    verdict: notYetRendered("verdict", "authority", ["case"]),
    receipt: notYetRendered("receipt", "evidence", ["case"]),
    lease: notYetRendered("lease", "evidence", ["case"]),
    rollback: notYetRendered("rollback", "evidence", ["case"]),
  } satisfies Record<SwarmMarkerKind, SwarmCardEntry>;

  export function SwarmEvidenceCard({ parsed, ctx }: { parsed: Exclude<SwarmMarkerParse, { status: "not-a-marker" } | { status: "unadmitted-issuer" }>; ctx: SwarmCardContext }) {
    if (parsed.status === "unknown-kind") return <UnknownMarkerCard slug={parsed.slug} version={parsed.version} card={parsed.card} />;
    if (parsed.status === "unsupported-version") return <UnsupportedVersionCard kind={parsed.kind} version={parsed.version} card={parsed.card} />;
    const { card } = parsed;
    const entry = SWARM_CARD_REGISTRY[card.kind];
    if (!entry.homeSurface.includes(ctx.surface)) return <MisplacedCard card={card} surface={ctx.surface} />;
    if (ctx.surface === "case" && card.channelTag !== ctx.caseChannelId) return <MisplacedCard card={card} surface={ctx.surface} reason="channel-mismatch" />;
    return entry.render({ card, ctx });
  }
  ```
  with `notYetRendered(kind, pillar, homeSurface)` returning an entry whose `render` is `<NotYetRenderedCard kind={kind} card={card} />`. The `finding` entry's `homeSurface` is `["case", "lane"]`.
  `cards/FindingCard.tsx`: decoder = `parseCardParts("finding", card.rawBody)` → `admitCard(parts.json, card.issuerPubkey, isAdmittedIssuer)` → `fact.schema === "swarm.perch.finding.v1"`, else `{ ok: false, reason }`; presenter renders inside `<EvidenceCardFrame kind="finding" pillar="substrate" tier={envelopeTier(payload)} gap={fact.gap} eventId={card.eventId} issuerPubkey={card.issuerPubkey}>` a definition list: agent (`fact.issuer.swarm_agent_id`), threat class (`t` slug, or `custom: <name>` for `{custom}`), severity (`fact.finding.severity`), confidence (`confidence 0.82` — two decimals and the word), host (`<AdversaryString field="host" value={fact.locator.host_id ?? "unknown"} layout="inline" />`), finding id, strategy, event id, evidence (`<AdversaryString field="evidence" value={JSON.stringify(fact.finding.evidence)} layout="block" />`, or the sentence `evidence omitted: {bytes} bytes, sha256 {sha256}` when `evidence_truncated` is set). The card is deliberately read-only until Task 23; do not create an empty action component or a stub callback. `data-testid="perch-evidence-finding"` on the presenter's root.

- [ ] **Step 5: The seam.** In `MessageBody.tsx`, at the top of the component body (hooks, before any early return):
  ```tsx
  const swarmSurface = useSwarmCardSurface();
  const isAdmittedIssuer = useAdmittedIssuerPredicate();
  const swarmParse = React.useMemo(
    () => swarmSurface.enabled
      ? parseSwarmMarker({ content: message.body, signerPubkey: message.signerPubkey, channelTag: getChannelIdFromTags(message.tags ?? []), eventId: message.id, isAdmittedIssuer })
      : NOT_A_SWARM_MARKER,
    [swarmSurface.enabled, message.body, message.signerPubkey, message.tags, message.id, isAdmittedIssuer],
  );
  const swarmCtx = React.useMemo<SwarmCardContext>(
    () => ({ surface: swarmSurface.surface, caseChannelId: swarmSurface.caseChannelId, searchQuery: searchQuery ?? "", density: "comfortable" }),
    [swarmSurface.surface, swarmSurface.caseChannelId, searchQuery],
  );
  ```
  and, replacing the seam comment inside the `default:` branch, **before** `parseWaveMessageContent`:
  ```tsx
  if (swarmParse.status === "ok" || swarmParse.status === "unknown-kind" || swarmParse.status === "unsupported-version") {
    return <SwarmEvidenceCard parsed={swarmParse} ctx={swarmCtx} />;
  }
  const unadmittedNotice = swarmParse.status === "unadmitted-issuer" ? <UnadmittedMarkerNotice slug={swarmParse.slug} eventId={message.id} /> : null;
  ```
  and prepend `{unadmittedNotice}` to the prose branch's returned element (`<>{unadmittedNotice}<VideoReviewCommentMarkdown …/></>`). `NOT_A_SWARM_MARKER` is a module-level `Object.freeze({ status: "not-a-marker" } as const)`. `MessageBody` gains no props; `MessageRow`'s comparator is untouched. Ground's `MessageBody.test.mjs` (the wave marker still renders) keeps passing because `ambush:wave:v1` is `not-a-marker`.

- [ ] **Step 6: Gates.** `cd workspace/desktop && node --test "src/features/perch-evidence/**/*.test.mjs"` → green; `cd workspace && just check && just desktop-typecheck && just desktop-test && just file-size-check` → green (`pnpm check:px-text` flags any `text-[…px]`; use `text-sm`, `text-2xs`, `text-3xs` only).
- [ ] **Step 7: Commit.** `git add workspace/desktop/src && git commit -s -m "feat(desktop): swarm marker parser, the seven-entry card registry, the finding card, and the MessageBody seam"`

### Task 18: Query keys, the seven-REQ manager (one lane-movement REQ for twelve lanes), gap tracking, the write-state store, and the resetter entries

**Files:**
- Create: `workspace/desktop/src/shared/api/{perchKeys.ts, perchKeys.test.mjs, perchSubscriptions.ts, perchSubscriptions.test.mjs, perchGapStore.ts, perchLaneMovement.ts}`, `workspace/desktop/src/features/perch-evidence/lib/{verdictWriteState.ts, verdictWriteState.test.mjs, perchCaseIndex.ts}`
- Modify: `workspace/desktop/src/features/communities/communityScopedRegistry.ts` (five entries) and its test, `workspace/desktop/src/features/perch-evidence/ui/SwarmCardSurface.tsx` (the subscription mount), `crates/swarm-perch-bridge/src/metrics.rs` (`lanes` in the identities JSON)
- Test: `cd workspace/desktop && node --test src/shared/api/perchKeys.test.mjs src/shared/api/perchSubscriptions.test.mjs src/features/perch-evidence/lib/verdictWriteState.test.mjs src/features/communities/communityScopedRegistry.test.mjs`

**Interfaces:**
- Consumes: `relayClient.subscribeLive(filter, onEvent, onReady?, readinessTimeoutMs?)` (`shared/api/relayClientSession.ts:410-417`); `CHANNEL_EVENT_KINDS`, `KIND_CHANNEL_THREAD_SUMMARY = 39005` (`shared/constants/kinds.ts:100`, `:21`); `queryClient` (`shared/api/queryClient.ts`); `channelMessagesKey(channelId)` (`features/messages/lib/messageQueryKeys.ts:3`); `useIdentityQuery` (`shared/api/hooks`); Ground Task 6's `COMMUNITY_SCOPED_SINGLETONS` / `RESETTERS`.
- Produces (used by Tasks 22, 23):
  - `perchKeys` (skeleton verbatim, with `admittedIssuers: () => key("daemon", "admitted-issuers")` per D-FC-2), `PERCH_FRESHNESS`, `PERCH_NO_RETRY`, `isRelayDependentQuery`, `isDaemonDependentQuery`.
  - `buildPerchSubscriptions(ctx)`, `syncPerchSubscriptions(specs)`, `setPerchEventSink(sink)`, `resetPerchSubscriptions()`, `observeIssuerSeq(issuer, seq, nowMs)`, `perchOpenGaps()`, `closePerchGap(issuer, expectedSeq)`, `resetPerchSeqTracking()`, `perchCaseLiveKinds()`, `PERCH_CASE_REPAIR_KINDS`, `assertPerchRepairKindsCovered`, `perchSteadyStateReqFrames(specs)`.
  - `perchGapStore.ts`: `usePerchOpenGaps(): readonly PerchSeqGap[]` (`useSyncExternalStore`, content-equal snapshot).
  - `perchLaneMovement.ts`: `usePerchSubscriptionsMount()` (refcounted; the first mount calls `syncPerchSubscriptions(buildPerchSubscriptions({...}))`, the last unmount `syncPerchSubscriptions([])`) and the sink that, for `lane-movement` events, parses the envelope's `seq` and `issuer`, calls `observeIssuerSeq`, and invalidates `channelMessagesKey(h)`.
  - `verdictWriteState.ts`: `type VerdictWriteState = { phase: "idle" } | { phase: "sending" } | { phase: "recorded"; atMs: number } | { phase: "acknowledged"; atMs: number; feedbackId: string } | { phase: "daemon-unreachable"; reason: string } | { phase: "not-yet-correlated" } | { phase: "failed"; reason: string }`; `getVerdictWriteState(findingId)`, `setVerdictWriteState(findingId, state)`, `useVerdictWriteState(findingId)`, `resetPerchWriteStates()`.
  - `perchCaseIndex.ts`: `rememberCase(findingId, { caseId, incidentId })`, `caseFor(findingId)`, `useCaseFor(findingId)`, `resetPerchCaseIndex()`.
  - registry entries `perchSubscriptions`, `perchSeqTracking`, `perchAdmittedIssuers`, `perchWriteStates`, `perchCaseIndex`.

- [ ] **Step 1: Copy and correct.** `cp docs/plans/ambush-ui/build/skeleton/desktop/src/shared/api/{perchKeys.ts,perchSubscriptions.ts} workspace/desktop/src/shared/api/` (if the skeleton's desktop tree is laid out differently, `find docs/plans/ambush-ui/build/skeleton -name perchKeys.ts` locates it). In `perchKeys.ts` change `admittedIssuers` to the `daemon` source and its `why` to name D-FC-2. In `perchSubscriptions.ts`: replace the two `_PLACEHOLDER` constants with `import { CHANNEL_EVENT_KINDS, KIND_CHANNEL_THREAD_SUMMARY } from "@/shared/constants/kinds";` and `Array.from(new Set([...CHANNEL_EVENT_KINDS, KIND_CHANNEL_THREAD_SUMMARY, 46010, 40100]))`; the `watch-alarm`, `watch-snoozes`, `watch-named-you`, `case-activity` and `telemetry` specs stay declared (this milestone passes `telemetryWanted: false` and `activeCaseIds: []`; the alarm REQ is harmless on the dev relay after Ground Task 3 and is the queue's live path later).

- [ ] **Step 2: Failing tests.** `perchKeys.test.mjs`:
  ```js
  test("every key names its source first and has a freshness row", () => {
    for (const [name, factory] of Object.entries(perchKeys)) {
      const k = factory("x", 0);
      assert.ok(["relay", "daemon", "local"].includes(k[0]), `${name}: ${k[0]}`);
      assert.ok(name in PERCH_FRESHNESS, `${name} has no freshness row`);
    }
    assert.equal(perchKeys.admittedIssuers()[0], "daemon");
    assert.ok(isDaemonDependentQuery({ queryKey: perchKeys.reviewedFindings(0) }));
    assert.ok(!isRelayDependentQuery({ queryKey: perchKeys.reviewedFindings(0) }));
  });
  ```
  `perchSubscriptions.test.mjs` (`buildPerchSubscriptions` and the seq functions are pure; `relayClient` is never touched):
  ```js
  test("twelve lanes ride ONE REQ, and the steady state is at most seven", () => {
    const lanes = Array.from({ length: 12 }, (_, i) => `lane-${i}`);
    const specs = buildPerchSubscriptions({ myPubkey: "a".repeat(64), laneChannelIds: lanes, activeCaseIds: [], openCaseId: null, telemetryWanted: false, nowSecs: 1 });
    const lane = specs.find((s) => s.id === "lane-movement");
    assert.deepEqual(lane.filter, { kinds: [9], "#h": lanes, limit: 1 });
    assert.ok(perchSteadyStateReqFrames(specs) <= 7);
    assert.equal(specs.find((s) => s.id === "watch-alarm").priority, true);
  });
  test("a forward seq jump opens a gap; a late or duplicate seq does not", () => {
    resetPerchSeqTracking();
    assert.equal(observeIssuerSeq("i", 1, 0), null);
    assert.equal(observeIssuerSeq("i", 2, 0), null);
    assert.equal(observeIssuerSeq("i", 2, 0), null);
    assert.equal(observeIssuerSeq("i", 1, 0), null);
    const gap = observeIssuerSeq("i", 5, 99);
    assert.deepEqual(gap, { issuer: "i", expectedSeq: 3, receivedSeq: 5, missing: 2, firstNoticedAtMs: 99 });
    assert.equal(perchOpenGaps().length, 1);
    closePerchGap("i", 3);
    assert.equal(perchOpenGaps().length, 0);
  });
  ```
  `verdictWriteState.test.mjs`:
  ```js
  test("write state is per finding, observable, and resets", () => {
    setVerdictWriteState("f1", { phase: "sending" });
    setVerdictWriteState("f1", { phase: "recorded", atMs: 5 });
    assert.deepEqual(getVerdictWriteState("f1"), { phase: "recorded", atMs: 5 });
    assert.deepEqual(getVerdictWriteState("f2"), { phase: "idle" });
    resetPerchWriteStates();
    assert.deepEqual(getVerdictWriteState("f1"), { phase: "idle" });
  });
  ```
  and in Ground's `communityScopedRegistry.test.mjs` add: `assert.ok(["perchSubscriptions", "perchSeqTracking", "perchAdmittedIssuers", "perchWriteStates", "perchCaseIndex"].every((k) => COMMUNITY_SCOPED_SINGLETONS.includes(k)))`.

- [ ] **Step 3: Implement** the three small stores (`perchGapStore.ts` wraps `perchOpenGaps()` in a versioned `useSyncExternalStore` with a listener that `perchSubscriptions.ts` calls after every `observeIssuerSeq`/`closePerchGap`; `verdictWriteState.ts` and `perchCaseIndex.ts` are `Map`-backed with the same listener pattern and a frozen `IDLE` constant so `getVerdictWriteState` returns a stable object for unknown ids), `perchLaneMovement.ts` (the sink parses `event.content` with `parseCardContent` → `JSON.parse(parts.json)` inside `try/catch` → `observeIssuerSeq(envelope.issuer, envelope.seq, Date.now())`, then `queryClient.invalidateQueries({ queryKey: channelMessagesKey(getChannelIdFromTags(event.tags)) })`; `usePerchSubscriptionsMount` reads `myPubkey` from `useIdentityQuery()` and the lanes from `perchLaneChannelIds()`, and re-syncs when either changes), and the five registry entries (each `() => reset…()`; `perchSubscriptions` is `async`, which `runResetters` awaits). Call `usePerchSubscriptionsMount()` inside `useSwarmCardSurface` when `enabled` (the refcount makes many callers one REQ set). Extend Task 8's `/metrics/perch/identities` JSON with `"lanes": { "<slug>": "<uuid>" }` from `config.lane_channels` (one field on the bridge side; Task 19's Tauri read passes it through).

- [ ] **Step 4: Run** the four test files → green; `cd workspace && just check && just desktop-typecheck && just file-size-check` → green (`perchSubscriptions.ts` is about 660 lines).
- [ ] **Step 5: Commit.** `git add workspace/desktop/src crates/swarm-perch-bridge/src/metrics.rs && git commit -s -m "feat(desktop): source-first query keys, the seven-REQ manager with one lane-movement REQ, seq gap tracking, and the perch resetters"`

### Task 19: Tauri — the daemon client, two reads, two writes, the keyring bearer, and the write-allowlist gate

> Blocked on D-FC-2 and D-FC-4 (Task 15); built under their defaults.

**Files:**
- Create: `workspace/desktop/src-tauri/src/perch/mod.rs`, `workspace/desktop/src-tauri/src/perch/daemon_client.rs`, `workspace/desktop/src-tauri/src/perch/daemon_client_tests.rs`, `workspace/desktop/src-tauri/src/commands/perch_reads.rs`, `workspace/desktop/src-tauri/src/commands/perch_writes.rs`, `workspace/desktop/src/shared/api/tauriPerch.ts`, `tools/check-perch-write-allowlist.sh`, `tools/lib/perch-roots.sh`, `tools/perch-source-roots.tsv`
- Modify: `workspace/desktop/src-tauri/src/lib.rs` (`pub mod perch;`, the keyring seeding in `.setup`, the handler entries), `workspace/desktop/src-tauri/src/commands/mod.rs` (`mod perch_reads; mod perch_writes;` and `pub use perch_reads::*; pub use perch_writes::*;`), `workspace/desktop/src-tauri/Cargo.toml` (`swarm-perch-wire = { path = "../../../crates/swarm-perch-wire", default-features = false }`), `.github/workflows/ci.yml`, `workspace/desktop/src/testing/e2eBridge.ts` (see Task 22 — the two commands must be mocked in the same commit or every smoke spec fails at mount)
- Test: `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch`; `PERCH_DESKTOP_ROOT=$PWD/workspace/desktop bash tools/check-perch-write-allowlist.sh`

**Interfaces:**
- Consumes: `AppState { http_client: reqwest::Client, … }` (`app_state.rs:19-24`); `SecretStore::shared(keyring_service())` with `load(key) -> Result<Option<String>, String>` and `store(key, value) -> Result<(), String>` (`secret_store.rs:242, :549, :729`; `keyring_service()` in `app_state_keyring.rs`); Task 10's `ReviewedFindingsResponse` JSON; Task 11's `IncidentMintRequest`/`IncidentMintResponse`; Task 12's `FindingFeedbackRequest`/`FindingFeedbackResponse`; Task 18's `/metrics/perch/identities` JSON.
- Produces (used by Tasks 21, 22, 23):
  - `perch::daemon_client::{PERCH_DAEMON_WRITES: [(&str, &str); 5], PERCH_DAEMON_URL_KEY = "perch.daemon_url", PERCH_DAEMON_BEARER_KEY = "perch.daemon_bearer", PERCH_OPERATOR_ID_KEY = "perch.operator_id", DaemonRoute { template: &'static str, path: String }, route(template: &'static str, params: &[(&str, &str)]) -> Result<DaemonRoute, String>, DaemonResponse { status: u16, body: serde_json::Value }, perch_daemon_get(state, route) -> Result<DaemonResponse, String>, perch_daemon_post(state, route, body: serde_json::Value) -> Result<DaemonResponse, String>, daemon_url(state) -> Result<String, String>, daemon_bearer() -> Result<String, String>, operator_id() -> Result<String, String>, seed_daemon_settings_from_env_in_debug()}`.
  - `#[tauri::command] perch_reviewed_findings(since_ms: Option<i64>, limit: Option<usize>, state) -> Result<Value, String>`; `#[tauri::command] perch_admitted_issuers(state) -> Result<PerchAdmittedIssuers { issuers: Vec<String>, lanes: BTreeMap<String, String>, colony_id: String }, String>`.
  - `#[tauri::command] perch_finding_feedback(finding_id: String, incident_id: String, action: String, verdict_event_id: String, reason: Option<String>, state) -> Result<Value, String>`; `#[tauri::command] perch_mint_incident(input: MintIncidentInput, state) -> Result<Value, String>` where `MintIncidentInput` (camelCase) mirrors Task 11's request minus nothing (`findingId, huntId, eventId, strategyId, threatClass: Value, severity, createdAtMs, summary, hostId, correlationKeys`).
  - `tauriPerch.ts`: `perchReviewedFindings(sinceMs, limit)`, `perchAdmittedIssuers()`, `perchFindingFeedback({ findingId, incidentId, action, verdictEventId, reason })`, `perchMintIncident(input)`, `perchRecordVerdict(input)` (Task 21's command; declared here so `PERCH_TAURI_COMMANDS` is complete), and the three arrays `PERCH_READ_COMMANDS = ["perch_reviewed_findings", "perch_admitted_issuers"]`, `PERCH_RELAY_WRITE_COMMANDS = ["perch_record_verdict"]`, `PERCH_DAEMON_WRITE_COMMANDS = ["perch_finding_feedback", "perch_mint_incident"]`, `PERCH_TAURI_COMMANDS`.

- [ ] **Step 1: The gate first, so its Phase-0 arm is seen once.** `cp docs/plans/ambush-ui/build/skeleton/tools/check-perch-write-allowlist.sh tools/ && mkdir -p tools/lib && cp docs/plans/ambush-ui/build/skeleton/tools/lib/perch-roots.sh tools/lib/ && cp docs/plans/ambush-ui/build/skeleton/tools/perch-source-roots.tsv tools/`. Run `PERCH_DESKTOP_ROOT=$PWD/workspace/desktop bash tools/check-perch-write-allowlist.sh` → the fixture passes, and the real scan **fails**: the manifest says `src/features/perch-evidence` is `absent` but Task 17 created it. Flip the manifest rows for every directory that now exists to `required` (`src/features/perch`, `src/features/perch-evidence`, `src/shared/ui/perch`, and after Step 3 `src-tauri/src/perch`), keeping the other rows `absent`; run again → `write-allowlist gate: no Perch Rust file exists yet…` exit 0 (the Phase-0 arm) until Step 3, then the real assertion.

- [ ] **Step 2: Failing Rust tests** `perch/daemon_client_tests.rs` (registered with `#[cfg(test)] #[path = "daemon_client_tests.rs"] mod tests;` at the bottom of `daemon_client.rs`):
  ```rust
  #[test]
  fn the_write_table_is_exactly_the_five_inv_01_routes() {
      let mut got: Vec<String> = PERCH_DAEMON_WRITES.iter().map(|(m, p)| format!("{m} {p}")).collect();
      got.sort();
      assert_eq!(got, vec![
          "POST /v1/operator/containment/leases/{lease_id}/release",
          "POST /v1/operator/findings/{finding_id}/feedback",
          "POST /v1/operator/incidents",
          "POST /v1/operator/review/sessions",
          "POST /v1/response/holds/{hold_id}/decide",
      ]);
  }

  #[test]
  fn route_substitution_encodes_and_refuses_a_slash() {
      let r = route("/v1/operator/findings/{finding_id}/feedback", &[("finding_id", "f 1")]).unwrap();
      assert_eq!(r.path, "/v1/operator/findings/f%201/feedback");
      assert_eq!(r.template, "/v1/operator/findings/{finding_id}/feedback");
      assert!(route("/v1/operator/findings/{finding_id}/feedback", &[("finding_id", "../../admin")]).is_err());
      assert!(route("/v1/operator/findings/{finding_id}/feedback", &[]).is_err(), "an unsubstituted placeholder is an error");
  }

  #[tokio::test]
  async fn an_unlisted_write_is_refused_before_any_socket_opens() {
      // The base URL is unroutable; if the allowlist check ran AFTER the request, the error would be a connect error.
      let state = crate::app_state::AppState::for_tests();      // the constructor the existing command tests use; grep `fn for_tests\|fn test_state` in app_state.rs and use that name
      crate::secret_store::SecretStore::shared(crate::app_state_keyring::keyring_service()).store(PERCH_DAEMON_URL_KEY, "http://192.0.2.1:9").unwrap();
      let r = DaemonRoute { template: "/v1/operator/anything", path: "/v1/operator/anything".into() };
      let err = perch_daemon_post(&state, &r, serde_json::json!({})).await.unwrap_err();
      assert!(err.contains("not on the INV-01 allowlist"), "{err}");
  }
  ```
  If `AppState` has no test constructor, build the minimal one the other `commands/*_tests.rs` files use (search `AppState {` in `src-tauri/src/**/*tests*.rs`) and, for the keyring, use the `#[cfg(not(feature = "system-keyring"))]` fallback the store already has under test.

- [ ] **Step 3: Implement `perch/daemon_client.rs`.**
  ```rust
  //! The console's ONLY path to the daemon. One dispatch function consults the INV-01 table;
  //! every command names a route constant; nothing here accepts a path from the renderer.
  pub const PERCH_DAEMON_WRITES: [(&str, &str); 5] = [
      ("POST", "/v1/response/holds/{hold_id}/decide"),
      ("POST", "/v1/operator/findings/{finding_id}/feedback"),
      ("POST", "/v1/operator/incidents"),
      ("POST", "/v1/operator/containment/leases/{lease_id}/release"),
      ("POST", "/v1/operator/review/sessions"),
  ];
  pub const PERCH_DAEMON_URL_KEY: &str = "perch.daemon_url";
  pub const PERCH_DAEMON_BEARER_KEY: &str = "perch.daemon_bearer";
  pub const PERCH_OPERATOR_ID_KEY: &str = "perch.operator_id";
  const SCHEMA_VERSION_HEADER: (&str, &str) = ("x-swarm-schema-version", "1");

  pub struct DaemonRoute { pub template: &'static str, pub path: String }
  pub struct DaemonResponse { pub status: u16, pub body: serde_json::Value }

  pub fn route(template: &'static str, params: &[(&str, &str)]) -> Result<DaemonRoute, String> {
      let mut path = template.to_string();
      for (name, value) in params {
          if value.is_empty() || value.contains('/') { return Err(format!("route parameter `{name}` is empty or contains a slash")); }
          let encoded: String = url_encode(value);
          path = path.replace(&format!("{{{name}}}"), &encoded);
      }
      if path.contains('{') { return Err(format!("route `{template}` has an unsubstituted parameter")); }
      Ok(DaemonRoute { template, path })
  }

  async fn perch_daemon_request(state: &AppState, method: reqwest::Method, route: &DaemonRoute, body: Option<serde_json::Value>) -> Result<DaemonResponse, String> {
      if method != reqwest::Method::GET && !PERCH_DAEMON_WRITES.iter().any(|(m, t)| *m == method.as_str() && *t == route.template) {
          return Err(format!("{} {} is not on the INV-01 allowlist", method, route.template));
      }
      let url = format!("{}{}", daemon_url(state)?.trim_end_matches('/'), route.path);
      let mut request = state.http_client.request(method, &url).bearer_auth(daemon_bearer()?).header(SCHEMA_VERSION_HEADER.0, SCHEMA_VERSION_HEADER.1);
      if let Some(body) = body { request = request.json(&body); }
      let response = request.send().await.map_err(|e| format!("daemon unreachable: {e}"))?;
      let status = response.status().as_u16();
      let body = response.json::<serde_json::Value>().await.unwrap_or(serde_json::Value::Null);
      Ok(DaemonResponse { status, body })
  }
  pub async fn perch_daemon_get(state: &AppState, route: &DaemonRoute) -> Result<DaemonResponse, String> { perch_daemon_request(state, reqwest::Method::GET, route, None).await }
  pub async fn perch_daemon_post(state: &AppState, route: &DaemonRoute, body: serde_json::Value) -> Result<DaemonResponse, String> { perch_daemon_request(state, reqwest::Method::POST, route, Some(body)).await }
  ```
  Keep each `perch_daemon_get`/`perch_daemon_post` body on one line: the gate's W2 filter (`check-perch-write-allowlist.sh:199-204`) drops lines that contain `perch_daemon_request`, and a rustfmt split would put `Method::POST` alone on a line. Add `#[rustfmt::skip]` on the two wrappers. `url_encode` is a 12-line percent-encoder over the unreserved set (no new crate). `daemon_url` returns the keyring value or `Err("daemon not configured")`; `daemon_bearer` and `operator_id` the same. `seed_daemon_settings_from_env_in_debug()`:
  ```rust
  pub fn seed_daemon_settings_from_env_in_debug() {
      if !cfg!(debug_assertions) { return; }
      let store = crate::secret_store::SecretStore::shared(crate::app_state_keyring::keyring_service());
      for (key, var, default) in [(PERCH_DAEMON_URL_KEY, "AMBUSH_PERCH_DAEMON_URL", Some("http://127.0.0.1:9090")), (PERCH_DAEMON_BEARER_KEY, "AMBUSH_PERCH_DAEMON_BEARER", None), (PERCH_OPERATOR_ID_KEY, "AMBUSH_PERCH_OPERATOR_ID", Some("local-operator"))] {
          if matches!(store.load(key), Ok(Some(_))) { continue; }
          if let Some(value) = std::env::var(var).ok().filter(|v| !v.is_empty()).or_else(|| default.map(str::to_string)) {
              if let Err(e) = store.store(key, &value) { tracing::warn!(key, "perch: could not seed keyring: {e}"); }
          }
      }
  }
  ```
  called from `lib.rs`'s `.setup` closure immediately before its closing `Ok(())` (the line above `.invoke_handler(` at `lib.rs:519`). `perch/mod.rs`: `pub mod daemon_client;`.

- [ ] **Step 4: The commands.** `perch_reads.rs`:
  ```rust
  const ROUTE_REVIEWED: &str = "/v1/operator/findings/reviewed";
  const ROUTE_IDENTITIES: &str = "/metrics/perch/identities";

  #[tauri::command]
  pub async fn perch_reviewed_findings(since_ms: Option<i64>, limit: Option<usize>, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
      let mut path = ROUTE_REVIEWED.to_string();
      let query: Vec<String> = [since_ms.map(|s| format!("since_ms={s}")), limit.map(|l| format!("limit={l}"))].into_iter().flatten().collect();
      if !query.is_empty() { path.push('?'); path.push_str(&query.join("&")); }
      let r = perch_daemon_get(&state, &DaemonRoute { template: ROUTE_REVIEWED, path }).await?;
      if r.status != 200 { return Err(format!("daemon answered {}: {}", r.status, r.body["message"].as_str().unwrap_or(""))); }
      Ok(r.body)
  }

  #[tauri::command]
  pub async fn perch_admitted_issuers(state: State<'_, AppState>) -> Result<PerchAdmittedIssuers, String> {
      // Unauthenticated on the daemon side (D-FC-2): public keys and lane ids only. Sent without a bearer.
      let url = format!("{}{}", daemon_url(&state)?.trim_end_matches('/'), ROUTE_IDENTITIES);
      let body: serde_json::Value = state.http_client.get(&url).send().await.map_err(|e| format!("daemon unreachable: {e}"))?.json().await.map_err(|e| e.to_string())?;
      Ok(PerchAdmittedIssuers {
          colony_id: body["colony_id"].as_str().unwrap_or_default().to_string(),
          issuers: body["identities"].as_array().map(|a| a.iter().filter_map(|i| i["pubkey"].as_str().map(|s| s.to_ascii_lowercase())).collect()).unwrap_or_default(),
          lanes: serde_json::from_value(body["lanes"].clone()).unwrap_or_default(),
      })
  }
  ```
  `perch_writes.rs` keeps the skeleton's header comment (updated to name `PERCH_DAEMON_WRITES` in `perch/daemon_client.rs` as the table) and implements the two commands:
  ```rust
  const ROUTE_FINDING_FEEDBACK: &str = "/v1/operator/findings/{finding_id}/feedback";
  const ROUTE_MINT_INCIDENT: &str = "/v1/operator/incidents";

  #[tauri::command]
  pub async fn perch_finding_feedback(finding_id: String, incident_id: String, action: String, verdict_event_id: String, reason: Option<String>, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
      if !matches!(action.as_str(), "confirm" | "dismiss" | "investigate") { return Err(format!("unknown finding action `{action}`")); }
      let r = perch_daemon_post(&state, &route(ROUTE_FINDING_FEEDBACK, &[("finding_id", &finding_id)])?, serde_json::json!({ "action": action, "incident_id": incident_id, "verdict_event_id": verdict_event_id, "reason": reason })).await?;
      match r.status { 200 => Ok(r.body), 404 => Err(format!("not-yet-correlated: {}", r.body["message"].as_str().unwrap_or(""))), s => Err(format!("daemon answered {s}: {}", r.body["message"].as_str().unwrap_or(""))) }
  }

  #[tauri::command]
  pub async fn perch_mint_incident(input: MintIncidentInput, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
      let body = serde_json::json!({ "finding_id": input.finding_id, "hunt_id": input.hunt_id, "event_id": input.event_id, "strategy_id": input.strategy_id, "threat_class": input.threat_class, "severity": input.severity, "created_at_ms": input.created_at_ms, "summary": input.summary, "host_id": input.host_id, "correlation_keys": input.correlation_keys });
      let r = perch_daemon_post(&state, &route(ROUTE_MINT_INCIDENT, &[])?, body).await?;
      if r.status != 200 { return Err(format!("daemon answered {}: {}", r.status, r.body["message"].as_str().unwrap_or(""))); }
      Ok(r.body)
  }
  ```
  Neither command takes a `content` parameter, so Ground's inventory test does not require the sign gate here (they sign nothing). Register `perch_reads::perch_reviewed_findings, perch_reads::perch_admitted_issuers, perch_writes::perch_finding_feedback, perch_writes::perch_mint_incident` in `generate_handler!` (`lib.rs` stays under 1000 gate-lines: it is 939 today and gains five entries across this task and Task 21). `tauriPerch.ts` is the skeleton trimmed to the five wrappers above, with `perchMintIncident`'s input type mirroring `MintIncidentInput` in camelCase and `perchFindingFeedback` returning `FindingFeedbackResponse`'s shape.

- [ ] **Step 5: Wire the gate** into `.github/workflows/ci.yml`, in the engine gates job after the parity step:
  ```yaml
        - name: Check the Perch write allowlist (INV-01)
          env:
            PERCH_DESKTOP_ROOT: ${{ github.workspace }}/workspace/desktop
          run: bash tools/check-perch-write-allowlist.sh
  ```
  (No `actions/checkout` of another repository: the console tree is in this repository now; the snippet's `block/buzz` checkout step is not copied.) `bash tools/check-gates-wired.sh` → green.

- [ ] **Step 6: Run.** `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch` → 3 passed. `PERCH_DESKTOP_ROOT=$PWD/workspace/desktop bash tools/check-perch-write-allowlist.sh` → `write-allowlist gate clean: 5 routes, 3 Rust file(s), N renderer file(s)`. `cd workspace && just check && just desktop-typecheck` → green. **Build the desktop crate with the transport-neutral wire dependency under the workspace toolchain**: `cargo +1.95.0 build --manifest-path workspace/desktop/src-tauri/Cargo.toml`. Failure is a stop condition: fix the wire crate's dependency or MSRV defect without adding an engine dependency and without creating a second wire implementation (W3-27).
- [ ] **Step 7: Commit.** `git add workspace/desktop tools .github/workflows/ci.yml && git commit -s -m "feat(desktop): the perch daemon client behind a five-route table, two reads, two writes, and the INV-01 gate"`

### Task 20: Decision D-FC-3 — the finding-verdict card under `swarm:verdict:v1`, and the `e` tag

**Files:**
- Modify: `docs/plans/ambush-ui/integration/00-DECISIONS.md` (§3), `docs/plans/ambush-ui/build/schemas/card-swarm-verdict-v1.schema.json`, `crates/swarm-perch-wire/src/cards.rs` (`VerdictCard`), `workspace/desktop/src/features/perch/wire/{zod.ts, types.ts, tags.ts}`, `crates/swarm-perch-wire/golden/card-swarm-verdict-v1-finding.json` (new vector), `tools/sync-perch-golden.sh` (re-pin)
- Test: `cargo test -p swarm-perch-wire`; `node --test workspace/desktop/src/features/perch/wire/golden.test.mjs`; `bash tools/check-perch-wire-parity.sh`

- [ ] **Step 1: Record the decision.**
  ```markdown
  | **D-FC-3** — the finding-verdict card and the verdict card's `e` tag | The wave-2 `card-swarm-verdict-v1` schema is hold-only: `locator {hold_id, case_channel, hold_card_id}`, `decision {decision: grant|refuse, hold_id, …}`, and the W3-16 preimage names `hold_id`. First card records a verdict on a FINDING (`confirm|dismiss|investigate`, B3), which that shape cannot carry, and the registry is closed at seven markers (an eighth is not an option). Two documents also disagree on the `e` tag: `13` §5.1 and `verdictCardTags` emit `["e", holdCardId]`; `14` §7.3.1 publishes with `h` and no `e`. **Default the plan builds under:** (1) `locator` and `decision` gain a `subject` discriminator: `subject: "hold"` keeps every existing field; `subject: "finding"` carries `locator {finding_id, finding_card_id (hex64), case_channel, incident_id}` and `decision {decision: confirm|dismiss|investigate, finding_id, decided_at_ms, operator_id, rationale}`; the Ed25519 preimage for a finding subject is the RFC 8785 form of `{decided_at_ms, decision, finding_id, rationale_sha256}` (four members, W3-16's shape with `finding_id` in `hold_id`'s place); (2) **no `e` tag on the initial verdict card** — the finding card lives in the lane channel and the verdict in the case channel, and an `e` tag to an event in another channel would make the relay's NIP-10 thread resolver mutate a lane card's `reply_count` from a case; the join is `locator.finding_card_id` in the signed body, and `verdictCardTags` in `tags.ts` drops its `["e", …]` line. A later supersession update may carry an `e` reply to its own same-channel leg-1 verdict card, as The hold Task 27 requires; it never points across channels. **Options:** a hold-only verdict and a bare kind:9 prose message for findings — rejected: the finding verdict is the milestone's whole product and must be a card the Ledger can find; an eighth marker — rejected by the closed registry. **Dependents:** Task 21. | project owner, on spec review |
  ```
- [ ] **Step 2: Apply it to the wire.** In the schema, wrap the existing `locator`/`decision` shapes in a `oneOf` on `subject` and add the finding branch; in `cards.rs`, `VerdictCard.locator: VerdictLocator` and `VerdictCard.decision: VerdictDecision` become `#[serde(tag = "subject", rename_all = "snake_case")] pub enum VerdictLocator { Hold { hold_id, case_channel, hold_card_id }, Finding { finding_id, finding_card_id, case_channel, incident_id } }` and the matching `VerdictDecision` enum (`decision` inner field typed `VerdictWord { Grant, Refuse }` for holds and `FindingVerdictWord { Confirm, Dismiss, Investigate }` for findings; serde `rename_all = "snake_case"`); `human_line` gains the finding arm `{confirm|dismiss|investigate} · finding {finding_id} · by {operator_id} · {ISO}`; `zod.ts`'s `verdictFact` becomes a `z.discriminatedUnion("subject", …)` inside `locator` and `decision` (mirror the Rust field names exactly); `tags.ts`'s `verdictCardTags` drops the `e` line and its test. Add the golden vector `card-swarm-verdict-v1-finding.json` (copy `card-swarm-verdict-v1.json`, switch both blocks to the finding subject, `issued_at` `2026-03-17T09:21:00Z`, recompute `envelope_hash` with `fixtures/validate.mjs`'s helper as Ground Task 1 step 5 did), add it to `tests/golden.rs`'s `VECTORS` and to `the_registry_is_seven_cards_one_stored_kind_and_seven_frames` (nine card vectors, still seven schemas), run `bash tools/sync-perch-golden.sh`, then the three test commands → green.
- [ ] **Step 3: Commit.** `git add -A docs/plans/ambush-ui crates/swarm-perch-wire workspace/desktop/src/features/perch/wire tools && git commit -s -m "docs(decisions): D-FC-3 finding-verdict subject on swarm:verdict:v1, no e tag; wire and goldens updated"`

### Task 21: `perch_record_verdict` — leg 1 for a finding verdict, built from the relay's admitted card, signed twice

> Blocked on D-FC-3 (Task 20) and D-FC-4 (Task 15); built under their defaults.

**Files:**
- Create: `workspace/desktop/src-tauri/src/commands/perch_verdict.rs`
- Modify: `workspace/desktop/src-tauri/src/commands/mod.rs`, `workspace/desktop/src-tauri/src/lib.rs` (one handler entry), `workspace/desktop/src/shared/api/tauriPerch.ts` (the wrapper's input type)
- Test: `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_verdict`

**Interfaces:**
- Consumes: `crate::relay::query_relay(&AppState, &[serde_json::Value]) -> Result<Vec<nostr::Event>, String>` (`relay.rs:360`); `crate::relay::submit::submit_signed_event_at_with_keys(&Event, &AppState, api_base_url, &Keys) -> Result<SubmitEventResponse, String>` (`relay/submit.rs:16`) and `crate::relay::relay_api_base_url_with_override(&AppState)` (`relay.rs:63`); `state.signing_keys()` (`app_state.rs:278-291`); `crate::perch_sign_gate::perch_sign_gate` (Ground Task 5); Task 19's `perch_admitted_issuers` logic (factor its fetch into `perch::daemon_client::fetch_admitted_issuers(&AppState)`), keyring keys `perch.operator_id`, `perch.operator_ed25519`; `swarm_perch_wire::{envelope::canonical_bytes, marker::{parse_content, build_content, CardKind}, tags::TagSet, KIND_CARD}`; `ed25519_dalek::SigningKey` (3.0.0-rc.0), `sha2::Sha256` (0.11) — both already desktop dependencies.
- Produces (used by Tasks 22, 23): `#[tauri::command] perch_record_verdict(input: RecordVerdictInput, state) -> Result<RecordVerdictOutput, String>` with
  ```rust
  #[derive(Deserialize)] #[serde(rename_all = "camelCase")]
  pub struct RecordVerdictInput { pub finding_card_id: String, pub case_channel: String, pub incident_id: String, pub decision: FindingVerdictWord, pub rationale: Option<String> }
  #[derive(Serialize)]
  pub struct RecordVerdictOutput { pub nostr_intent_event_id: String, pub decided_at_ms: i64, pub signature: DetachedSignature, pub finding_id: String }
  pub const PERCH_RELAY_PUBLISHED_KINDS: [u32; 1] = [9];
  pub const PERCH_RELAY_PUBLISHED_MARKERS: [&str; 1] = ["swarm:verdict:v1"];
  const OPERATOR_ED25519_SECRET_KEY: &str = "perch.operator_ed25519";
  pub fn verdict_preimage(decided_at_ms: i64, decision: &str, finding_id: &str, rationale: Option<&str>) -> Vec<u8>
  ```

- [ ] **Step 1: Failing tests** in `perch_verdict.rs`:
  ```rust
  #[test]
  fn the_operator_key_publishes_exactly_one_kind_and_one_marker() {
      assert_eq!(PERCH_RELAY_PUBLISHED_KINDS, [9]);
      assert_eq!(PERCH_RELAY_PUBLISHED_MARKERS, ["swarm:verdict:v1"]);
  }

  #[test]
  fn the_generic_signer_refuses_what_this_command_publishes() {
      assert!(crate::perch_sign_gate::perch_sign_gate(9, "<!-- swarm:verdict:v1 -->\nx").is_err());
  }

  #[test]
  fn this_files_daemon_reads_are_not_writes() {
      // The command reads the relay and the identities endpoint; it POSTs nothing to the daemon.
      assert!(!crate::perch::daemon_client::PERCH_DAEMON_WRITES.iter().any(|(_, p)| p.contains("verdict")));
  }

  #[test]
  fn the_preimage_is_rfc_8785_canonical_with_four_members() {
      let empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      assert_eq!(
          String::from_utf8(verdict_preimage(1_773_738_979_000, "dismiss", "f2c9a1b4", None)).unwrap(),
          format!("{{\"decided_at_ms\":1773738979000,\"decision\":\"dismiss\",\"finding_id\":\"f2c9a1b4\",\"rationale_sha256\":\"{empty_sha}\"}}")
      );
      let with = String::from_utf8(verdict_preimage(1, "confirm", "f", Some("backup job"))).unwrap();
      assert!(with.contains("\"rationale_sha256\":\"") && !with.contains("backup job"));
  }
  ```
  Run `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_verdict` → compile failure.

- [ ] **Step 2: Implement.** Order of operations, each step load-bearing:
  1. Validate locally: `finding_card_id` is 64 lowercase hex; `case_channel` parses as a UUID; `incident_id` starts with `incident:perch-case:`.
  2. `let issuers = fetch_admitted_issuers(&state).await?;` then `query_relay(&state, &[json!({"ids": [finding_card_id], "kinds": [9], "limit": 1})])` → exactly one event, else `Err("finding card not found on the relay")`; refuse unless `issuers.contains(&event.pubkey.to_hex())` (`"finding card signer is not an admitted bridge identity"`) and `event.content.lines().next() == Some("<!-- swarm:finding:v1 -->")`; `parse_content(&event.content)` → `serde_json::from_str::<serde_json::Value>(parts.json)` → `fact` with `fact["schema"] == "swarm.perch.finding.v1"`; take `finding_id = fact["locator"]["finding_id"]`, `lane_channel`, `strategy_id`, `host_id` from THAT body — the renderer supplied only ids, the decision and the rationale.
  3. `decided_at_ms = now_ms()` from this process's clock.
  4. The operator Ed25519 key: `SecretStore::shared(keyring_service()).load(OPERATOR_ED25519_SECRET_KEY)?` → hex → `SigningKey::from_bytes`; when absent, `SigningKey::generate(&mut OsRng)`, store its hex, log at `info` `perch: minted the operator Ed25519 key`. `signature = DetachedSignature { algorithm: "ed25519", key_id: operator_id()?, public_key_hex: hex(verifying_key), signature_hex: hex(sign(preimage)) }` over `verdict_preimage(decided_at_ms, decision.as_str(), &finding_id, rationale.as_deref())`, where the preimage is `swarm_perch_wire::canonical_bytes(&serde_json::json!({ "decided_at_ms": …, "decision": …, "finding_id": …, "rationale_sha256": hex(sha256(rationale_bytes)) }))?`. Ordinary `serde_json::to_vec` is not the signature contract; W3-27 makes the shared JCS function authoritative.
  5. The fact: `{ "schema": "swarm.perch.verdict.v1", "issuer": { "swarm_agent_id": operator_id, "role": null, "nostr_pubkey": state.signing_keys()?.public_key().to_hex() }, "emitted_at_ms": decided_at_ms, "locator": { "subject": "finding", "finding_id", "finding_card_id", "case_channel", "incident_id" }, "decision": { "subject": "finding", "decision", "finding_id", "decided_at_ms", "operator_id", "rationale" }, "signature": signature, "leg2": { "state": "sending", "receipt_id": null, "refusal_check": null, "superseded_by": null, "superseded_at_ms": null } }`; the envelope: `{ "schema": "swarm.spine.envelope.v1", "issuer": format!("swarm:ed25519:{}", public_key_hex), "seq": 1, "prev_envelope_hash": null, "issued_at": <RFC 3339 seconds Z>, "capability_token": null, "fact": …, "envelope_hash": "0x" + hex(sha256(canonical unsigned envelope)) }` (the console has no chain; every operator card is `seq: 1` with no predecessor, tier 0 like every other card today). The human line: `{decision} · finding {finding_id} · by {operator_id} · {ISO}`. `content = build_content(CardKind::Verdict, &human, &json)?`.
  6. `tags = TagSet::card(CardKind::Verdict, case_channel, None, None)`; `tags.assert_publishable(KIND_CARD)?` (no `p`, no `e`); `EventBuilder::new(Kind::Custom(9), content).tags(nostr_tags).sign_with_keys(&state.signing_keys()?)`; `submit_signed_event_at_with_keys(&event, &state, &relay_api_base_url_with_override(&state), &keys).await?` (the funnel's egress guard runs; Ground's `perch_sign_gate` is not called here — this is the one sanctioned producer, and the inventory test scans commands with a `content` parameter, which this command does not have).
  7. Return `RecordVerdictOutput { nostr_intent_event_id: event.id.to_hex(), decided_at_ms, signature, finding_id }`.
  Register `perch_verdict::perch_record_verdict` in `generate_handler!` and `mod perch_verdict; pub use perch_verdict::*;` in `commands/mod.rs`. `tauriPerch.ts`: `perchRecordVerdict({ findingCardId, caseChannel, incidentId, decision: "confirm" | "dismiss" | "investigate", rationale })`.

- [ ] **Step 3: Run** → 4 passed; `cargo clippy --manifest-path workspace/desktop/src-tauri/Cargo.toml -- -D warnings` clean; Ground's inventory test still green (`cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_sign_gate`).
- [ ] **Step 4: Commit.** `git add workspace/desktop && git commit -s -m "feat(desktop): perch_record_verdict — leg 1 for a finding verdict, built from the admitted relay card, Ed25519 over the four-member preimage"`

### Task 22: E2E — the delegated fixture, marker admission, and the finding card

**Files:**
- Create: `workspace/desktop/src/testing/perch/e2ePerchBridge.ts`, `workspace/desktop/src/testing/perch/e2ePerchBridge.test.mjs`
- Modify: `workspace/desktop/src/testing/e2eBridge.ts` (one prefix guard before `default:`)
- Create: `workspace/desktop/tests/helpers/perchBridge.ts`, `workspace/desktop/tests/e2e/perch-marker-admission.spec.ts`, `workspace/desktop/tests/e2e/perch-finding-card.spec.ts`
- Modify: `workspace/desktop/tests/helpers/features.ts`, `workspace/desktop/tests/helpers/bridge.ts`, `workspace/desktop/playwright.config.ts`
- Test: the node test above and the two Playwright specs

**Interfaces:**
- Consumes: `PERCH_TAURI_COMMANDS` from Task 19; `installMockBridge`, `waitForMockLiveSubscription`, `waitForAnimations`; `__AMBUSH_E2E_EMIT_MOCK_MESSAGE__`; Tasks 2 and 17's goldens, parser and admitted-issuer rule.
- Produces (extended by The hold Task 22): `handlePerchMockCommand(command, payload)`, `seedPerchFixture(fixture)`, `installPerchControlSeams(seams)`; `installPerchBridge(page, fixture?)`; constants `PERCH_CASE_CHANNEL`, `PERCH_LANE_CHANNEL`, `PERCH_ADMITTED_ISSUER`, `PERCH_NOW_MS`; the `window.__AMBUSH_E2E_PERCH__` fixture seam.

- [ ] **Step 1: Write a failing delegated-module test.** The test imports
  `PERCH_TAURI_COMMANDS` and asserts that every First-card command has an explicit handler;
  `perch_reviewed_findings` returns the fixture's typed response,
  `perch_admitted_issuers` returns only public ids and lane UUIDs,
  `perch_mint_incident` returns a stable `incident_id`/`case_id` on replay, and
  `perch_finding_feedback` records exactly one feedback row keyed by
  `(finding_id, verdict_event_id)`. Run:
  ```bash
  cd workspace/desktop
  node --import ./test-loader.mjs --experimental-strip-types --test src/testing/perch/e2ePerchBridge.test.mjs
  ```
  Expected: module not found.

- [ ] **Step 2: Add the single mock boundary.** Move the new module under
  `src/testing/perch/`; it owns the fixture state and every `perch_*` command arm. In
  `e2eBridge.ts`, immediately before the unsupported-command `default:`, add only:
  ```ts
  if (command.startsWith("perch_")) {
    return handlePerchMockCommand(command, payload);
  }
  ```
  The module exports a closed `HANDLED_COMMANDS` set and throws at import when
  `PERCH_TAURI_COMMANDS` has a member it does not handle. It does not fork channel,
  message, subscription or Nostr-event behavior; those stay in `e2eBridge.ts`.

- [ ] **Step 3: Add the Playwright helper.** `installPerchBridge(page, fixture?, options?)` calls
  `page.addInitScript` to seed the fixture and enable only the `perch` preview feature,
  then calls `installMockBridge(page, undefined, { ...options, enableFeatures: ["perch"] })`;
  that order is mandatory because React reads both on mount. Perch specs call this helper once
  and never call `installMockBridge` a second time. `tests/helpers/features.ts` declares `perch`
  opt-in, so the existing smoke suite does not silently switch Home. The helper emits a
  signed-looking event through
  `__AMBUSH_E2E_EMIT_MOCK_MESSAGE__` only after
  `waitForMockLiveSubscription(page, channelName)` resolves; it never reaches into React.

- [ ] **Step 4: Marker-admission spec.** In one lane channel, exercise four distinct
  messages and scope each assertion to its event id:
  1. exact `swarm:finding:v1`, admitted raw signer, valid golden → one
     `perch-evidence-finding` and no ordinary Markdown body;
  2. same bytes from an unadmitted raw signer → ordinary prose plus the unadmitted notice,
     no card, counter increments once;
  3. admitted signer with a malformed fence/schema → `perch-card-refusal`, no action
     controls;
  4. `ambush:wave:v1` → the inherited wave renderer, proving the two namespaces do not
     collide.
  Assert the delegated/proxied signer field is ignored in favor of `signerPubkey`.

- [ ] **Step 5: Finding-card spec.** Render the golden finding and assert the human facts,
  adversary-controlled host/evidence rails, `secp256k1 · tier 0 · TRANSPORT-SIGNED ONLY ·
  the daemon is the record`, and that no action controls exist before Task 23 lands the workflow.
  Plant U+202E and U+200B in the host and assert
  both visible codepoint labels.
  Use `locator.screenshot()` only when a screenshot is needed; call
  `waitForAnimations(page)` first.

- [ ] **Step 6: Run and protect the old product.** Kill a stale preview server on port
  4173, then run `cd workspace/desktop && pnpm test:e2e:smoke`; the two new specs and every
  existing smoke spec pass from `pnpm build:e2e`. Run the node test and
  `cd workspace && just desktop-check && just file-size-check`.

- [ ] **Step 7: Commit.**
  ```bash
  git add workspace/desktop/src/testing workspace/desktop/tests workspace/desktop/playwright.config.ts
  git commit -s -m "test(desktop): delegate perch mock commands and exercise finding-card admission"
  ```

### Task 23: `E` promotes; `D` records and delivers the finding verdict

> Blocked on D-FC-2, D-FC-3 and D-FC-4; built under their defaults.

**Files:**
- Create: `workspace/desktop/src/features/perch-evidence/lib/findingVerdictFlow.ts`, `findingVerdictFlow.test.mjs`, `workspace/desktop/src/features/perch-evidence/ui/cards/FindingCardActions.tsx`
- Modify: `workspace/desktop/src/features/perch-evidence/lib/verdictWriteState.ts`, `verdictWriteState.test.mjs`, `perchCaseIndex.ts`
- Modify: `workspace/desktop/src/features/perch-evidence/ui/cards/FindingCard.tsx` (mount the real action component)
- Create: `workspace/desktop/src/shared/ui/perch/WriteStateRow.tsx`
- Modify: `workspace/desktop/tests/e2e/perch-finding-card.spec.ts`
- Test: node tests, Tauri verdict tests, Playwright

**Interfaces:**
- Consumes: `perchMintIncident`, `perchRecordVerdict`, `perchFindingFeedback`;
  `rememberCase`/`caseFor`; React Query's stable `mutateAsync` methods; the admitted card
  fact, never renderer-supplied copies of its identifiers.
- Produces: `promoteFinding(card) -> Promise<CaseRef>`;
  `recordFindingVerdict(card, "confirm" | "dismiss" | "investigate", rationale?)`;
  `retryFindingFeedback(findingId)`; `pendingFindingVerdicts()` and
  `resetFindingVerdictFlow()`; `<WriteStateRow>` with the literal phases
  `sending`, `recorded on Ambush`, `acknowledged by the daemon`,
  `daemon unreachable — the Ambush record remains`, `not yet correlated`, `failed`.

- [ ] **Step 1: Write the state-machine tests first.** With fake functions, assert:
  promotion calls `perchMintIncident` once, remembers the daemon-minted ids and never
  publishes a verdict; dismissal before promotion returns `not-yet-correlated` and calls
  neither leg; after promotion, leg 1 resolves before leg 2 starts; a leg-1 failure calls
  no daemon route; a leg-2 network failure retains the exact intent id/signature in the
  pending map; retry calls leg 2 only and never re-signs or republishes. A 404 from B3 maps
  to `not-yet-correlated`; every other typed daemon refusal remains visible as `failed`.

- [ ] **Step 2: Close the asynchronous channel race in Task 21.** Before
  `perch_record_verdict` publishes into the daemon-minted case UUID, poll the relay for at
  most five seconds using explicit filters: kind 39000 with `#d = case_channel`, and kind
  39002 with `#d = case_channel` and `#p = current Nostr pubkey`. Sleep 100 ms between
  attempts. Only after both are visible may it submit kind 9. Exhaustion returns the stable
  error prefix `case-channel-pending:`; it does not create the channel, publish elsewhere,
  or call the daemon. Add paused-time unit tests for success, timeout and cancellation.

- [ ] **Step 3: Implement the flow.** `promoteFinding` builds the B3i request from the
  admitted card's fact, stores the returned `case_id`/`incident_id`, invalidates the case
  and reviewed-finding keys, and navigates to `/cases/$caseId`. `recordFindingVerdict`
  requires that stored pair, sets `sending`, calls leg 1, sets `recorded`, stores the exact
  leg-2 input, then calls B3. Only the daemon response advances to `acknowledged`; neither
  an optimistic mutation nor a relay OK changes tuning data. On success invalidate
  `reviewedFindings` and `operatorStatus`, not `deposits` (the daemon owns the suppression
  calculation). Register `resetFindingVerdictFlow` in `COMMUNITY_SCOPED_SINGLETONS` and
  `RESETTERS` in the same edit.

- [ ] **Step 4: Implement the controls.** The action group renders neutral controls
  `E Promote`, `C Confirm`, `D Dismiss`, `I Investigate`. Before promotion C/D/I stay
  present but disabled with `Promote this finding to a case first`; after promotion they
  enable. E is one meaning only. While the group has keyboard focus, non-repeating bare
  E/C/D/I dispatch the same callbacks; input, textarea, contenteditable, modifier keys and
  an active dialog suppress them. `D` first expands a rationale row and the second D or
  its explicit record control commits—never one destructive keystroke. Every pending or
  terminal phase renders through `WriteStateRow`; no checkmark stands for both legs.

- [ ] **Step 5: Exercise the complete mock workflow.** Extend the finding-card spec:
  focus the action group, press E, assert one B3i request and navigation to the exact
  daemon-minted case UUID; return to the admitted finding, press D twice, assert the mock
  log order `perch_record_verdict` then `perch_finding_feedback`, and assert
  `sending → recorded → acknowledged`. Repeat with leg 2 offline and assert the record
  stays visible; restore it, click Retry, and assert the original intent event id is reused
  with no second relay event.

- [ ] **Step 6: Run and commit.**
  ```bash
  cd workspace/desktop
  node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-evidence/lib/findingVerdictFlow.test.mjs src/features/perch-evidence/lib/verdictWriteState.test.mjs
  pnpm test:e2e:smoke -- perch-finding-card.spec.ts
  cd ..
  cargo test --manifest-path desktop/src-tauri/Cargo.toml perch_verdict
  just check
  git add desktop
  git commit -s -m "feat(desktop): promote findings and complete the two-legged dismissal flow"
  ```

### Task 24: The copy gate, the real walking skeleton, and milestone exit

**Files:**
- Create: `tools/lib/perch-roots.sh`, `tools/perch-source-roots.tsv`, `tools/copy-scope.tsv`, `tools/check-copy-banned-terms.sh`, `tools/copy-ban-list.tsv`, `tools/copy-ban-allowlist.tsv`, `tools/fixtures/copy-corpus/**`
- Create: `workspace/desktop/scripts/check-copy-banned-terms.mjs`
- Modify: `workspace/desktop/package.json` (`check:copy` in `check`), `.github/workflows/ci.yml`
- Create: `docs/plans/ambush-ui/integration/evidence/first-card.md`
- Test: shell and Node negative controls, all milestone gates, live stack

- [ ] **Step 1: Land the gate with its first real subject.** Copy the shell gate, roots,
  TSVs, parity corpus and desktop `.mjs` from `build/skeleton/`, then apply W3-24 rather than
  retaining the skeleton's obsolete "assets always required" assumption. Resolve the desktop
  root to `$ROOT/workspace/desktop` by default; retain `PERCH_DESKTOP_ROOT` for self-tests.
  `tools/copy-scope.tsv` contains exactly one reviewed row,
  `docs/assets<TAB>deferred<TAB>W3-24: rewrite and require in Operator-complete Task 20`.
  The shell gate accepts only `deferred` or `required`: `deferred` skips the asset extraction
  but prints `PARTIAL COVERAGE: docs/assets deferred by W3-24`; `required` demands at least one
  SVG and scans all of them. A missing row, a second row, an unknown status, or a deferred row
  with no reason exits 1. Keep a manifest override for the gate's own fixtures only. Wire the
  shell gate into the engine `gates` job and `check:copy` into the desktop `check` script in the
  same commit. `perch-source-roots.tsv` marks every root created by Tasks 16–18 as `required`;
  a required root that is missing, an `absent` root that has landed, and an unlisted discovered
  Perch root all fail.

- [ ] **Step 2: Prove the gate is not decorative.** Run both implementations over the
  shared corpus and compare the exact `(file, row-id)` set. Then mutate, one at a time:
  an `Approve this hold` rendered literal, a `key: "A", verb: "confirm"` binding, a
  quorum fraction, and a missing `features/perch-evidence` root; each must exit 1 for the
  intended row. Restore each mutation with the working tree byte-identical. A clean
  synthetic desktop tree with no Perch source must warn rather than claim product coverage.
  Add asset-scope mutations too: a missing or malformed `copy-scope.tsv` fails; a temporary
  `required` fixture containing `Approve this hold` fails the asset half; the committed
  `deferred` row emits the exact partial-coverage warning. The real tree must scan the required
  desktop roots and say that those roots are clean while naming `docs/assets` as deferred—never
  `copy gate clean` without that qualification. The twelve SVG rewrites and the atomic
  `deferred` → `required` flip remain Operator-complete Task 20 (W3-24).

- [ ] **Step 3: Run the local acceptance sweep.** From the root:
  ```bash
  cargo test -p swarm-perch-wire
  cargo test -p swarm-perch-bridge
  cargo test -p swarm-ingest-runtime perch_ops
  cargo test -p swarm-runtime-http perch
  bash tools/check-perch-wire-parity.sh
  PERCH_DESKTOP_ROOT=$PWD/workspace/desktop bash tools/check-perch-write-allowlist.sh
  PERCH_DESKTOP_ROOT=$PWD/workspace/desktop bash tools/check-copy-banned-terms.sh
  bash tools/check-workspace-layering.sh
  bash tools/check-gates-wired.sh
  ```
  Then, under `workspace/` with Hermit active, run `just check`, the desktop Tauri
  perch tests and `pnpm test:e2e:smoke`. No focused green run substitutes for this sweep.

- [ ] **Step 4: Exercise the real path.** Start the pinned Postgres, Redis, relay and
  detect-only daemon from `docs/PERCH-DEV.md`; start the actual Tauri desktop, not a plain
  browser. Inject one finding through the documented detector fixture. Record in
  `evidence/first-card.md`: commit SHA, toolchain versions, service image digests, community
  id, finding event id, relay card event id, case UUID, verdict event id, feedback id, and
  tuning counters before/after. Demonstrate: bridge identity authenticates; the relay
  stores the finding card; the real desktop admits and renders it; E creates the daemon
  incident and bridge-owned case; D publishes leg 1 then B3 records leg 2; the tuning
  report changes. Stop if any id cannot be joined across those records.

- [ ] **Step 5: Negative live control.** Replay the same marker under an unadmitted key
  and show it remains prose and never enters the action flow. Stop the daemon after leg 1,
  show `recorded on Ambush` without an acknowledgement, restart it, retry leg 2 and prove
  the same verdict event id is used. This is runtime evidence; a green mock spec does not
  replace it.

- [ ] **Step 6: Commit the gate and evidence.**
  ```bash
  git add tools workspace/desktop/scripts workspace/desktop/package.json .github/workflows/ci.yml docs/plans/ambush-ui/integration/evidence/first-card.md
  git commit -s -m "test(perch): enforce copy and record the First-card acceptance chain"
  ```

## Self-Review

**Spec coverage.** Tasks 1–9 build the transport-neutral wire, the bridge, durable spool,
NIP-42 publisher and composition root. Tasks 10–15 supply B3r, B3i, B3 and the five owner
decisions. Tasks 16–23 build and exercise the first user-visible card, its case, and both
write legs. Task 24 supplies H8 and the real workflow evidence. The hold store, 46010 row,
26006 alarm, grant/refuse and The Watch remain exclusively in The hold.

**Layering.** W3-27 resolves the only architectural contradiction found during recovery:
`swarm-perch-wire` has no internal engine dependency, conversions and signing stay in the
bridge, and Tauri verifies the shared canonical bytes with its own crypto dependency. The
graph assertion and differential corpus test make that a gate, not prose.

**Failure semantics.** Network input is admitted by raw signer and exact marker; the spool
precedes network I/O; a case-channel race is bounded and explicit; leg 1 and leg 2 have
separate rendered states; retry never republishes leg 1. No task claims a hold exists in
detect-only mode.

**Placeholder scan.** Search this plan for `TBD`, `TODO`, `implement later`, `fill in`,
`add error handling`, `add validation`, `handle edge cases`, `write tests for` and
`similar to Task`: none is permitted. `todo!` / `unimplemented!` may appear in this plan
only when a task explicitly names copied code it replaces or a zero-match gate that
prevents that code from reaching a shareable commit.

## Exit criteria

1. `swarm-perch-wire` compiles under Rust 1.97.1 and 1.95.0, has no dependency whose package
   name starts `swarm-`, and matches the TypeScript field set and the engine's canonical
   bytes on every golden and RFC vector.
2. One real `RuntimeEvent::Finding` is disk-spooled before socket I/O, published at no more
   than 1 Hz, accepted by NIP-42, stored as kind 9 with exactly `h/t/l/k`, and rendered only
   for an admitted raw signer.
3. Restarting after an append, a torn tail, a relay refusal or an expired publish window
   neither reorders acknowledged records nor hides the gap; retry inside the window is
   byte-identical.
4. E on the real card causes B3i to mint one incident and case UUID; the bridge creates that
   private case and adds the operator before the verdict command publishes into it.
5. D before promotion is visibly disabled. After promotion, D produces exactly one
   `swarm:verdict:v1` leg-1 event and one B3 feedback record; the daemon's tuning report
   changes only after leg 2.
6. With the daemon down after leg 1, the UI says the Ambush record exists and does not imply
   acknowledgement; retry uses the original event id and detached signature.
7. An unadmitted marker, malformed payload, cross-channel `e` tag, forbidden generic signer
   and out-of-allowlist daemon write all fail closed under a named test or gate.
8. With `perch` disabled, Home and the existing smoke suite are unchanged. With it enabled,
   the case route and finding card use rem text tokens and stay below the 1000-line gate.
9. The full engine/workspace gate sweep is green and `evidence/first-card.md` joins the live
   detector, bridge, relay, desktop, incident, verdict, feedback and tuning ids at one commit.
   The copy gate reports the required Perch product roots clean and explicitly reports the
   W3-24 `docs/assets` deferral; it does not claim complete asset coverage before Task 20.

## Sizing

Engineer-days, one engineer-week = five days. The Rust path is mostly serial; desktop work
can begin at Task 16 once Tasks 1–2 and the admitted-issuer decision are stable.

| Task | Days | Note |
|---|---:|---|
| 1 Wire crate | 4 | transport-neutral rewrite, JCS, goldens, dual-toolchain boundary |
| 2 TypeScript mirror | 3 | zod and parity gate |
| 3 Bridge scaffold | 3 | config, conversions, differential canonical test |
| 4 Durable spool | 5 | crash and corruption cases |
| 5 Receive loop | 2 | lag and redaction |
| 6 D-FC-1 | 0.5 | decision filing |
| 7 Identity + NIP-42 | 4 | derivation, reconnect, live test |
| 8 Cards + pacer | 5 | retry window, metrics, gaps |
| 9 Composition root | 2 | shutdown and layering |
| 10 B3r | 3 | reviewed-findings projection |
| 11 B3i | 4 | incident/case mint and event |
| 12 B3 | 3 | feedback and tuning |
| 13 Case/lane provisioning | 4 | first-write-wins routing |
| 14 Dev stack + D-FC-5 | 2.5 | runnable detect-only profile |
| 15 D-FC-2 + D-FC-4 | 0.5 | decision filing |
| 16 Case route + flag | 2 | feature boundary |
| 17 Parser + card | 4 | adversary text and admission |
| 18 Queries + resetters | 3 | seven-REQ budget and gap state |
| 19 Tauri client | 4 | five-route table and INV-01 gate |
| 20 D-FC-3 | 1 | schema decision and new golden |
| 21 Verdict command | 4 | dual signatures and channel readiness |
| 22 E2E boundary | 3 | delegated mock and two specs |
| 23 Promote + dismiss flow | 4 | two-legged state machine and retry |
| 24 Gate + milestone exit | 4 | negative controls and live evidence |
| **Total** | **74.5 days** | **14.9 engineer-weeks**; roughly 10.7 ew Rust/integration, 3.8 ew desktop, 0.4 ew decisions |

This is larger than the wave-2 walking-skeleton estimate because it now prices the repository
boundary, durable spool recovery, daemon-minted case-channel race, delegated E2E seam and a real
end-to-end acceptance run instead of treating them as ambient integration work.
