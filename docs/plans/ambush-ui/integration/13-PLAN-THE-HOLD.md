# The Hold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a `PolicyVerdict::RequireHuman` durable in the daemon, deliver it to one human as a `kind:46010` queue row plus a `26006` alarm, and turn that human's signed decision into a daemon-arbitrated grant or refusal whose capability lease is minted at the decision instant.

**Architecture:** The daemon (`swarm_detect --serve`, process A) gains a hold store, a decide route and two hold reads under `require_bearer_auth` plus an explicit scope check; `swarm-perch-bridge` (in-process in A) turns `RuntimeEvent::ResponseHeld` into a case channel, a `swarm:hold:v1` card, a `46010` notice and a `26006` alarm; the console (process D) renders The Watch's HOLDS queue reconciled against `GET /v1/response/holds`, and records a decision as two legs — a `swarm:verdict:v1` card signed by the operator's own keys, then `POST /v1/response/holds/{hold_id}/decide` from the Tauri host with a bearer that never crosses IPC. The console never authorizes; the daemon re-derives policy and governance from scratch (ADR 0014).

**Tech Stack:** Engine: Rust 1.97.1 / edition 2024, axum 0.8, serde, `uuid` v4, tokio, `swarm-crypto` (Ed25519 + RFC 8785 canonical JSON). Workspace: Rust 1.95.0 / edition 2021, `ambush-relay` + Postgres + Redis, `ambush-ws-client` (NIP-42), Tauri 2 host (`nostr` 0.44, `reqwest` 0.13, `ed25519-dalek` 3.0.0-rc.0, `sha2` 0.11). Desktop: React 19, Vite, Tailwind (rem tokens only), TanStack Query + Router, `node:test`, Playwright.

**Spec:** docs/plans/ambush-ui/integration/01-DESIGN.md (plus the wave-2 documents it cites: `build/12-BACKEND-BILL-API.md`, `build/11-BRIDGE-CRATE.md`, `build/13-WIRE-SCHEMAS.md`, `build/14-CLIENT-ARCHITECTURE.md`, `build/17-COMPONENT-SPECS.md`, `build/16-INVARIANT-TESTS.md`, `build/20-TASK-BREAKDOWN.md`), read under `00-DECISIONS.md`'s rulings.

Path convention (D2): an unprefixed path is the engine root; `workspace/` is the Ambush workspace. Every line number below was re-measured on 2026-09-02 against this repository at `integrate/workspace`; the wave-2 numbers are stale by construction.

---

## Global Constraints

- **Engine lints.** `clippy::unwrap_used` and `clippy::expect_used` are denied in production code; test modules opt out with `#![allow(clippy::unwrap_used, clippy::expect_used)]` exactly as `crates/swarm-runtime-http/src/http/tests.rs:1` does. No `unsafe`. Release profile is `panic = "abort"`. Every new `pub` item carries a doc comment.
- **TCB rule (ADR 0009, ADR 0015 C2, D2).** `swarm-crypto`, `swarm-policy`, `swarm-spine` (and the other `TRUST_SENSITIVE` crates at `tools/check-workspace-layering.sh:184-191`) never link `swarm-perch-bridge`, `swarm-perch-wire` or anything under `workspace/`. Cross-workspace edges are exactly: `swarm-perch-bridge → workspace/crates/ambush-ws-client`; `workspace/desktop/src-tauri → crates/swarm-perch-wire` with `default-features = false` and nothing else.
- **Sign gate (ADR 0014 C1, INV-29, W3-2).** `perch_sign_gate(kind, &content)` refuses `kind:46010` and any `kind:9` whose line 0 (`trimEnd`, never `trimStart`) matches `^<!-- swarm:[a-z]+:v\d+ -->$`. It runs on the first line of every `#[tauri::command]` that reaches `state.signing_keys()` with a `content` parameter. `perch_record_verdict` is the sole producer of a governance marker.
- **Marker names (D1, W3-1).** Line 0 is exactly `<!-- swarm:hold:v1 -->` / `<!-- swarm:verdict:v1 -->`; fence info string `swarm:hold:v1` / `swarm:verdict:v1`; fact schema `swarm.perch.hold.v1` / `swarm.perch.verdict.v1`; the 26006 frame schema `swarm.perch.frame.hold_alarm.v1`; envelope `swarm.spine.envelope.v1` unchanged. Card body order (W3-21): marker line, one human line, blank line, fenced JSON.
- **`hold_id` (R-3, W3-15).** Matches `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`; B1 mints `hold_` + a lowercase RFC 4122 v4 UUID (41 characters); never derived from `hunt_id`; never contains a colon.
- **Leases (W2-15).** `policy.lease_ttl_ms` is `60_000` and the capability lease is minted from the store's compare-and-set instant, never from hold time and never from the request body's `decided_at_ms`. The containment lease is a different object (`runtime.containment.lease_ttl_ms`, default `900_000`) and is never labelled bare "lease".
- **Hold constants.** `PERCH_HOLD_TTL_MS = 3_600_000` (per threat class overridable); `decide_stall_ms = 60_000`; `sweep_interval_ms = 5_000`; `governance_receipt_max_age_ms = 86_400_000`; `PERCH_QUEUE_DEPTH_ALARM = 12`; grant dwell `1500` ms.
- **`46010` tags (RF-D1, W2-6).** Exactly one `h` (the case channel UUID), one `p` per principal holding `OperatorScope::Approve` (at least one), exactly one `hold`, at most one `card`; **never `e`**, never `t`/`l`/`k`. Content is one human line, no marker, no JSON.
- **`26006` (R-1, W2-3).** Global, no `h` tag, one `p` per Approve principal, listed in `P_GATED_KINDS`; every REQ that can match it carries `#p` = the reader's own pubkey on every filter; payload is exactly `{hold_id, action_kind, severity, case_channel, expires_at_ms}` plus the frame header. Never coalesced, never shed, bypasses the pacer.
- **Console write allowlist (INV-01).** The console process issues exactly five non-GET requests to a daemon: `POST /v1/response/holds/{hold_id}/decide`, `POST /v1/operator/findings/{finding_id}/feedback`, `POST /v1/operator/incidents`, `POST /v1/operator/containment/leases/{lease_id}/release`, `POST /v1/operator/review/sessions`. Route strings are Rust `const`s; there is no generic passthrough command. The bearer never crosses IPC (INV-22).
- **Desktop text sizing.** Only rem tokens (`text-sm`, `text-xs`, `text-2xs`, `text-3xs`, `text-message`); no `text-[Npx]` and no arbitrary rem literals; `pnpm check:px-text` fails otherwise. Perch components read only `--perch-*` tokens (R-4).
- **File size.** Hard ceiling 1000 gate-lines per file in `workspace/desktop/src/{app,features,shared/api,shared/ui,...}` and `src-tauri/src` (`workspace/desktop/scripts/check-file-sizes.mjs:8-55`); split, never bump. Frozen files (`tauri.ts` 1107, `relayClientSession.ts` 1083, `types.ts` 999, `MessageRow.tsx`) are read, never edited.
- **Commits.** `git commit -s` on every commit, Conventional Commits subject (`feat(scope): …`, `test(scope): …`, `fix(scope): …`, `docs(scope): …`); engine changes under a `swarm-*` scope, workspace changes under `ambush-*`/`desktop`/`relay` scopes.
- **Copy.** No rendered `Perch`, no rendered `Approve`/`Approved`, no verdict control bound to `a`/`A`, no `Deny` as an operator label, no bare "lease", no shield or lock glyph, no `Everything looks good`/`All clear`/`no data` (APPENDIX §7, W3-8). `refuse` is the operator's word; `deny` is the policy's; `veto` is governance's.
- **Two legs, never optimistic (INV-33, INV-28).** Every governance write renders `sending → recorded → acknowledged | refused_late | superseded | daemon_unreachable` as distinct states with no undo; a late refusal is an outcome, never an error.

---

## Entry checklist

Everything below is owed by `10-PLAN-MIGRATION.md`, `11-PLAN-GROUND.md` and `12-PLAN-FIRST-CARD.md`. A worker starting Task 3 verifies each line first; a missing line is a blocker on that earlier plan, not work for this one.

- [ ] `rulesets-dev/perch-dev.yaml` + `.sig.json` exist with `runtime.mode: live_response`, `require_durable_live_response: true`, `pheromone.backend.kind: local_journal`, `runtime.containment.lease_store_path: data/perch-dev/containment-leases`, `correlation.enabled: true` with a `local_files` incident store, `audit.recent_decisions_limit: 200`, `operator_surface.enabled: true` and one principal carrying `nostr_pubkey` (P0-22, P0-26, D4). A debug `swarm_detect --config rulesets-dev/perch-dev.yaml --serve` logs `operator containment release routes mounted`.
- [ ] `OperatorPrincipalConfig` has `nostr_pubkey: Option<String>` (B0) at `crates/swarm-core/src/config/operator.rs:115-129`.
- [ ] `crates/swarm-perch-wire` exists (P1-26) with `marker.rs`, `tags.rs` (`is_opaque_hold_id`, `TagSet::assert_publishable`), `cards.rs` and `frames.rs` renamed to `swarm:` markers, and its default feature set links no engine crate.
- [ ] `crates/swarm-perch-bridge` exists (P0-17 … P0-19) with `receive.rs`, `spool/`, `pacer.rs`, `identity.rs` (`normalize_p_tag`, `approve_scoped_operator_pubkeys`), `publish.rs`, `channels.rs` (with `ensure_case_channel`'s `Promoted` arm from B1d), and publishes `swarm:finding:v1` end to end.
- [ ] `RuntimeEvent::CasePromoted` (B1d) exists, so `RuntimeEvent` has twelve variants and `runtime_event_matches_scope` at `crates/swarm-ingest-runtime/src/ingest/mod.rs:698-770` already carries a `CasePromoted => false` arm.
- [ ] The relay patches are re-landed on `workspace/crates/ambush-relay` and `workspace/crates/ambush-core` (W3-7): `46010` in `required_scope_for_kind` and `requires_h_channel_scope` (`workspace/crates/ambush-relay/src/handlers/ingest.rs:704-733` today), `KIND_OPERATOR_ALARM_FRAME = 26006` in `P_GATED_KINDS` (`workspace/crates/ambush-core/src/kind.rs:159-169` today), and the two E2E binaries `e2e_workflow_approval.rs` and `e2e_operator_alarm_pgate.rs` under `workspace/crates/ambush-test-client/tests/`.
- [ ] `perch_sign_gate` is wired at `sign_event` (`workspace/desktop/src-tauri/src/commands/identity.rs:108-135`), `send_channel_message` (`commands/messages.rs:409`) and the egress boundaries, with the inventory test (H2).
- [ ] `resetCommunityState` calls the typed `runResetters` registry (H3) and `workspace/desktop/src/features/communities/communityScopedRegistry.ts` exists with `COMMUNITY_SCOPED_SINGLETONS` and `RESETTERS`.
- [ ] The E2E delegated module `workspace/desktop/src/testing/perch/e2ePerchBridge.ts` exists and the `if (command.startsWith("perch_"))` guard sits before `default:` at `workspace/desktop/src/testing/e2eBridge.ts:14605` (P0-20).
- [ ] `commands/perch_writes.rs` exists with `perch_finding_feedback` and `perch_mint_incident`, `PERCH_WRITE_ROUTES` is `[&str; 5]`, and `tools/check-perch-write-allowlist.sh` is wired (H4). `commands/perch_reads.rs` may or may not exist; Task 19 creates or extends it.
- [ ] `workspace/desktop/src/features/perch-evidence/` has `parseSwarmMarker`, the `swarmCardRegistry` `satisfies Record<…>` map with a `finding` entry, `EvidenceCardFrame`, `RefusalCards` and the `MessageBody` seam (P1-17), and `features/perch-watch/` exists with First card's findings queue and its three verbs.
- [ ] `docker-compose.yml` brings up `relay`, `postgres`, `redis` beside `swarm-detect`, and `scripts/provision-perch.sh` provisions the bridge identities with `MessagesWrite`, `ChannelsWrite` and `AdminChannels` (P0-21).
- [ ] Two deployment facts from `01-DESIGN.md` §6 hold on the dev profile: `runtime.containment.lease_store_path` is set, and `correlation.incident_store` is file-backed.

---

## File Structure

### Engine (unprefixed = repository root)

| Path | Responsibility |
|---|---|
| `crates/swarm-core/src/config/runtime.rs` (modify) | `ResponseHoldSettings` block on `RuntimeSettings.response`; six `#[serde(default)]` keys |
| `crates/swarm-core/src/config/defaults.rs` (modify) | the six default fns |
| `crates/swarm-core/src/config/validation.rs` (modify) | fail-closed validation of the block, beside the containment rules at `:352-378` |
| `crates/swarm-core/src/config/operator.rs` (modify, blocked on Task 2) | `verdict_public_key_hex: Option<String>` on `OperatorPrincipalConfig` |
| `crates/swarm-core/src/types.rs` (modify) | `OperatorApproval` (B2o) |
| `crates/swarm-runtime/src/held_action.rs` (create) | `HeldAction`, `HoldState`, `HoldRationale`, `HoldDecisionRecord`, `HoldRefusal`, `HoldOutcome`, `GovernanceClearance`, `mint_hold_id`, `HeldActionStore` trait, `DecisionClaim`, `MemoryHeldActionStore`, `FileHeldActionStore`, `ConfiguredHeldActionStore`, `HeldActionStoreHealth` |
| `crates/swarm-runtime/src/held_action_tests.rs` (create) | the store's unit tests, `#[path]`-included so `held_action.rs` stays readable |
| `crates/swarm-runtime/src/hold_sweep.rs` (create) | `HoldSweep`: `expire_due` + `fail_stalled_decisions`, `run_until_shutdown` |
| `crates/swarm-runtime/src/runtime_events.rs` (modify) | the six `ResponseHeld` edits |
| `crates/swarm-runtime/src/governance_gate.rs` (create) | `reauthorize`, `GovernanceClearance` bounds, the moved dispatcher functions (B2g) |
| `crates/swarm-runtime/src/dispatcher.rs` (modify) | the two gate sites call `governance_gate` |
| `crates/swarm-runtime/src/lib.rs` (modify) | `pub mod held_action; pub mod hold_sweep; pub mod governance_gate;` and the `approved_by` fourth parameter (B2o) |
| `crates/swarm-response/src/lib.rs` (modify) | `ResponseReceiptAudit.approved_by`, `with_operator_approval` |
| `crates/swarm-ingest-runtime/src/ingest/mod.rs` (modify) | `route_request` intercept, `hold_store` on `IngestState`, `current_hold_store`, `current_governance_authority`, `operator_binds_voter_id`, the `ResponseHeld` scope arm, `resolve_demo_scope` token mandatory (B5) |
| `crates/swarm-ingest-runtime/src/ingest/perch_ops/mod.rs` (modify) | re-exports `holds` |
| `crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs` (create) | `HoldCapture::capture_hold`, `decide_hold`, `list_holds`, `get_hold`, the view builders, `HoldDecisionError` |
| `crates/swarm-ingest-runtime/src/ingest/demo.rs` (modify) | `with_demo_cors` dropped from the stream response (B5); the two human-approved call sites gain `None` |
| `crates/swarm-runtime-http/src/http/perch/mod.rs` (modify) | `perch_operator_router` gains two hold reads in Task 10 and decide in Task 13; `PERCH_ROUTER_PATHS` grows from three to six (W3-28) |
| `crates/swarm-runtime-http/src/http/perch/holds.rs` (create) | `HeldActionView`, `HoldListResponse`, `HoldDetailResponse`, `HoldDecisionRequest`, `HoldDecisionResponse`, the three handlers, the 409 taxonomy |
| `crates/swarm-runtime-http/src/http/review.rs` (modify) | `review_session_create_handler` takes `Extension(principal)` (B5) |
| `crates/swarm-runtime-http/src/bin/swarm_detect.rs` (modify) | build the hold store from config, `with_hold_store`, spawn `HoldSweep`, boot `warn!` for Approve-without-Read |
| `crates/swarm-perch-wire/src/verdict.rs` (create) | `DecisionPreimage`, `decision_preimage_bytes`, `rationale_sha256_hex` — the one implementation of the four-member preimage both legs use |
| `crates/swarm-perch-bridge/src/channels.rs` (modify) | `HoldId::parse` rewritten to the R-3 pattern (W3-15); `Held` arm of `ensure_case_channel`; `PublishHold`, `PublishAlarm` steps |
| `crates/swarm-perch-bridge/src/cards.rs` (modify) | `hold_card(&HeldAction, …)`, `HoldAlarm` (five keys) |
| `crates/swarm-perch-bridge/src/holds.rs` (create) | the hold publisher: reads the record from the store handle, plans the sequence, reports `mark_case_channel` / `mark_notified` back |
| `crates/swarm-perch-bridge/src/stream.rs` (modify) | `ResponseHeld => Stream::Alarm` |
| `crates/swarm-perch-bridge/src/lib.rs` (modify) | `BridgeBuildInput.hold_store`, `BridgeBuildInput.approve_pubkeys` |
| `tools/check-no-unrouted-authorize.sh` (create) | C4: `authorize_and_execute` has no non-test caller; a stale allowlist entry also fails |
| `.github/workflows/ci.yml` (modify) | the `run:` step for the new gate |
| `docs/PERCH-DEV.md` (modify) | the hold half of the demo script |
| `docs/plans/ambush-ui/integration/00-DECISIONS.md` (modify) | §3 rows written by Tasks 1 and 2 |

### Relay and workspace crates (`workspace/`)

| Path | Responsibility |
|---|---|
| `workspace/crates/ambush-test-client/tests/e2e_workflow_approval.rs` (verify, run) | six landed tests, exercised end to end against a live stack |
| `workspace/crates/ambush-test-client/tests/e2e_operator_alarm_pgate.rs` (verify, run) | the eight landed tests; tests 5–8 are documentation of the design not taken (R-1) |
| `workspace/crates/ambush-test-client/tests/e2e_perch_hold_path.rs` (create) | one test that publishes 9007 → 9000 → kind:9 hold card → 46010 → 26006 with the bridge's identities and asserts the needs-action join and the p-gated alarm |
| `workspace/desktop/src-tauri/src/commands/channel_reconnect_repair.rs` (modify) | `CHANNEL_REPAIR_KINDS` from 15 to 18 (`+46010, +40100, +39005`) |

### Desktop (`workspace/desktop/`)

| Path | Responsibility |
|---|---|
| `src-tauri/src/perch/mod.rs`, `src-tauri/src/perch/client.rs`, `src-tauri/src/perch/client_tests.rs` (create) | the daemon HTTP client: bearer from the keyring, `PERCH_DAEMON_WRITES` allowlist, `redact_for_ipc` |
| `src-tauri/src/commands/perch_reads.rs` (create or extend) | `perch_list_holds`, `perch_get_hold` |
| `src-tauri/src/commands/perch_writes.rs` (modify) | `perch_decide_hold` filled in; the 409 mapping |
| `src-tauri/src/commands/perch_verdict.rs` (create) | `perch_record_verdict`, `perch_operator_identity`; the operator Ed25519 secret in the keyring |
| `src-tauri/src/commands/mod.rs`, `src-tauri/src/lib.rs` (modify) | `mod` + `pub use` + `generate_handler![]` entries |
| `src-tauri/Cargo.toml` (modify) | `swarm-perch-wire = { path = "../../../crates/swarm-perch-wire", default-features = false }` |
| `src/testing/perch/e2ePerchBridge.ts` (modify) | hold fixtures, `perch_list_holds`/`perch_get_hold`/`perch_decide_hold`/`perch_record_verdict` arms, `__AMBUSH_E2E_PERCH_CONTROL__` |
| `src/testing/perch/perchDemoFixture.json` (verify) | the vendored canonical fixture |
| `src/testing/e2eBridge.ts` (modify, four lines) | `26006` in the mock `P_GATED_KINDS`, `installPerchControlSeams(emitMockGlobalEvent)` |
| `src/shared/api/tauriPerch.ts` (modify) | `perchListHolds`, `perchGetHold`, `perchRecordVerdict`, `perchDecideHold` typed wrappers |
| `src/shared/api/perchKeys.ts` (modify) | `holds`, `hold`, `needsAction`, `reconcileDivergences` rows |
| `src/shared/api/perchSubscriptions.ts` (modify) | `watch-alarm` and `case-activity` specs; `PERCH_CASE_REPAIR_KINDS` assertion |
| `src/shared/api/perchEphemeralStore.ts` (modify) | the `26006` arm, `drainPerchAlarms` |
| `src/shared/api/perchHoldAlarm.ts` (create) | `useHoldAlarmRefetch`: alarm → invalidate `holds` |
| `src/features/perch/lib/perchKeymapRegistry.ts` + `.test.mjs` (create from the skeleton) | the row keymap as data |
| `src/features/perch/usePerchKeymap.ts` (create) | one bubble-phase listener, `event.repeat` ignored, escape surface |
| `src/features/perch/lib/keymapArmingState.ts` (create) | `G` arming state, reset on `hold_id` change; registered resetter |
| `src/features/perch-watch/lib/holdRows.ts` (create) | `PerchHoldRow` shapes, `reconcileHoldQueue` reducer, counters |
| `src/features/perch-watch/lib/holdRows.test.mjs` (create) | the reducer's table test |
| `src/features/perch-watch/lib/watchQueues.ts` (create) | the four queue ids and labels; `queueForFeedItem` |
| `src/features/perch-watch/useHoldQueue.ts` (create) | daemon list + relay notices + admitted set → rows |
| `src/features/perch-watch/ui/WatchScreen.tsx` (modify) | four queues + the detail pane |
| `src/features/perch-watch/ui/WatchQueueSection.tsx`, `VerdictQueueRow.tsx` (create) | queue section and the three-line row |
| `src/features/perch-watch/ui/VerdictPane.tsx`, `VerdictSlot.tsx`, `GrantControl.tsx`, `RefuseControl.tsx` (create) | the Verdict Row for a hold subject |
| `src/features/perch-watch/lib/verdictSlots.ts` (create) | `VERDICT_SLOT_ORDER`, per-slot content builders for all fifteen action kinds |
| `src/features/perch-watch/lib/verdictSlots.test.mjs` (create) | the fifteen-variant snapshot |
| `src/features/perch-watch/lib/verdictWrite.ts` + `.test.mjs` (create) | the two-legged write reducer |
| `src/features/perch-watch/useVerdictWrite.ts` (create) | drives leg 1 → leg 2, publishes `superseded` |
| `src/features/perch-watch/lib/isTheDecision.ts` + `.test.mjs` (create) | the signature-keyed reconciliation predicate (C13, C16) |
| `src/features/perch-evidence/ui/cards/HoldCard.tsx`, `VerdictCard.tsx` (create) | the two case-timeline presenters this milestone needs |
| `src/shared/ui/perch/HoldTtlClock.tsx`, `WriteStateRow.tsx` (create) | Tier B primitives |
| `src/app/routes/index.tsx` (modify) | the `perch` flag seam: `WatchScreen` or `HomeScreen` |
| `../preview-features.json` (modify) | the `perch` entry |
| `tests/helpers/perchBridge.ts` (extend First card's helper with the skeleton hold fixtures) | fixture builders, `installPerchBridge`, `emitPerchHoldAlarm`, `advancePerchClock` |
| `tests/helpers/features.ts` (modify) | `E2E_OPT_IN_FEATURES = ["perch"]` |
| `tests/e2e/perch-verdict-pane.spec.ts`, `perch-queue-lifecycle.spec.ts`, `perch-concurrent-decision.spec.ts`, `watch-queues.spec.ts`, `two-legged-write.spec.ts`, `grant-two-stroke.spec.ts` (create) | the Playwright coverage; registered in `playwright.config.ts` `smoke` |

---

## Task 1: Decision: confirm D4 — The hold runs on the live-response dev profile

**Files:**
- Modify: `docs/plans/ambush-ui/integration/00-DECISIONS.md` (§3 row "D4 confirmation")

**Interfaces:**
- Consumes: `00-DECISIONS.md` D4 ("RECOMMENDED DEFAULT — confirm on spec review"); `20-TASK-BREAKDOWN.md` §1.3 (no hold can exist under `detect_only`: `crates/swarm-runtime/src/lib.rs:1133-1146` skips `RequireHuman` only when `self.mode == RuntimeMode::LiveResponse`).
- Produces: a recorded decision every later task's runtime assumption depends on. Tasks 8, 9, 13, 18 and 28 are **blocked** on this row until it reads "confirmed".

- [ ] **Step 1: Record the question and the options in `00-DECISIONS.md` §3.**

Replace the existing row `D4 confirmation | detect-only for First card, live-response dev profile for The hold | project owner, on spec review` with the block:

```markdown
| D4 confirmation (The hold) | **Options:** (a) The hold runs on `rulesets-dev/perch-dev.yaml` with `runtime.mode: live_response`, a `local_journal` substrate, a file-backed containment lease store and a file-backed incident store, debug-signed, refused by a release build — the plans' default; (b) The hold runs on `detect_only` with a test-only interception of the dry-run path — rejected by the plans because `lib.rs:1133-1146` never produces a `Skipped` RequireHuman in `detect_only`, so no hold can exist; (c) a production-signed live-response ruleset from day one — a deployment question, not a milestone one (`21-ADRS.md` Q1). **Default: (a).** Status: ☐ confirmed by the project owner on ____-__-__. | project owner, on spec review |
```

- [ ] **Step 2: Commit.**

```bash
git add docs/plans/ambush-ui/integration/00-DECISIONS.md
git commit -s -m "docs(decisions): record the D4 confirmation row for The hold"
```

- [ ] **Step 3: Owner confirms.** The project owner ticks the box and dates the row. Until then, Tasks 8, 9, 13, 18 and 28 carry "blocked on Task 1" and a worker who reaches one of them stops and reports.

---

## Task 2: Decision: where the operator's verdict signing key lives and how the daemon binds it

**Files:**
- Modify: `docs/plans/ambush-ui/integration/00-DECISIONS.md` (§3 new row "Operator verdict key")

**Interfaces:**
- Consumes: `12-BACKEND-BILL-API.md` §4.3 step 3 (`state.operator_binds_voter_id(operator_id, &voter_id)`, listed as PROPOSED with no data source in §17.1); `14-CLIENT-ARCHITECTURE.md` §7.3.1 ("Provisioning is not designed here"); ADR 0014 Follow-On Work ("the provisioning question is open"); `crates/swarm-core/src/config/operator.rs:115-129` (`OperatorPrincipalConfig` is `deny_unknown_fields`); `crates/swarm-runtime/src/approval.rs:1783-1785` (`voter_id_from_public_key` formats `swarm:ed25519:{hex}`).
- Produces: a recorded decision. Task 13 Step 9 (voter binding) and Task 21 Steps 3–4 (the console's key) are **blocked** on it.

- [ ] **Step 1: Add the row to `00-DECISIONS.md` §3.**

```markdown
| Operator verdict key (Ed25519) — where the daemon learns each operator's verifying key, and how the console gets the matching secret | **Options:** (a) a typed field `verdict_public_key_hex: Option<String>` on `OperatorPrincipalConfig` (64 lowercase hex, validated at load); the console mints an Ed25519 keypair on first use, stores the 32-byte seed under `perch.operator_ed25519` in the OS keyring (`SecretStore::shared(keyring_service())`, `secret_store.rs:729`), and shows `public_key_hex` for the operator to paste into the daemon's principal entry; `operator_binds_voter_id` compares `voter_id == format!("swarm:ed25519:{verdict_public_key_hex}")`. (b) derive both sides from the bearer token with `Ed25519Signer::from_secret_material(token)` (`crates/swarm-crypto/src/lib.rs:57-70`) — zero config, but the signature then proves only possession of the bearer and the two authorities collapse into one; rejected by ADR 0014's two-authority argument. (c) a trust-on-first-use registration route — a sixth console write, which INV-01 forbids. **Default assumed by this plan: (a).** Status: ☐ decided by the project owner on ____-__-__. | project owner |
```

- [ ] **Step 2: Commit.**

```bash
git add docs/plans/ambush-ui/integration/00-DECISIONS.md
git commit -s -m "docs(decisions): record the operator verdict key provisioning question"
```

- [ ] **Step 3: On decision (a), unblock.** Task 13 Step 9 and Task 21 Steps 3–4 are written against (a). On (b) or (c) those steps are rewritten before they are executed; a worker reaching them with the row undecided stops and reports.

---

## Task 3: B1 config — `ResponseHoldSettings` on `runtime.response`

**Files:**
- Modify: `crates/swarm-core/src/config/runtime.rs` (after `ContainmentSettings`, currently `:66-103`)
- Modify: `crates/swarm-core/src/config/defaults.rs`
- Modify: `crates/swarm-core/src/config/validation.rs` (beside the containment rules at `:352-378`)
- Test: `crates/swarm-core/src/config/tests.rs`

**Interfaces:**
- Consumes: `RuntimeSettings` (`runtime.rs:5-63`, `#[serde(deny_unknown_fields)]`), `ConfigValidationError::InvalidField { field, reason }`.
- Produces:
  ```rust
  pub struct ResponseHoldSettings {
      pub hold_store_path: Option<String>,
      pub hold_ttl_ms: u64,                                  // 3_600_000
      pub hold_ttl_ms_by_threat_class: BTreeMap<String, u64>, // keyed by threat-class slug
      pub sweep_interval_ms: u64,                            // 5_000
      pub decide_stall_ms: u64,                              // 60_000
      pub governance_receipt_max_age_ms: u64,                // 86_400_000
  }
  impl ResponseHoldSettings { pub fn hold_ttl_ms_for(&self, threat_class_slug: &str) -> u64 }
  ```
  and `RuntimeSettings.response: ResponseHoldSettings` (`#[serde(default)]`).

The map is keyed by the threat-class **slug** rather than `ThreatClass` because `ThreatClass::Custom(String)` is a newtype variant (`crates/swarm-core/src/pheromone.rs:16-31`) and serde map keys must be strings; the slug is the same string `threat_class_slug` already renders.

- [ ] **Step 1: Write the failing round-trip test.**

Append to `crates/swarm-core/src/config/tests.rs`:

```rust
#[test]
fn response_hold_settings_default_and_round_trip() {
    let yaml = r#"
hold_store_path: data/perch-dev/holds
hold_ttl_ms: 1800000
hold_ttl_ms_by_threat_class:
  lateral_movement: 900000
"#;
    let settings: ResponseHoldSettings = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(settings.hold_store_path.as_deref(), Some("data/perch-dev/holds"));
    assert_eq!(settings.hold_ttl_ms, 1_800_000);
    assert_eq!(settings.hold_ttl_ms_for("lateral_movement"), 900_000);
    assert_eq!(settings.hold_ttl_ms_for("execution"), 1_800_000);
    assert_eq!(settings.sweep_interval_ms, 5_000);
    assert_eq!(settings.decide_stall_ms, 60_000);
    assert_eq!(settings.governance_receipt_max_age_ms, 86_400_000);

    let defaults = ResponseHoldSettings::default();
    assert_eq!(defaults.hold_store_path, None);
    assert_eq!(defaults.hold_ttl_ms, 3_600_000);
}

#[test]
fn response_hold_settings_reject_an_empty_store_path_and_a_zero_ttl() {
    let mut config = test_config();
    config.runtime.response.hold_store_path = Some("   ".to_string());
    let error = config.validate().unwrap_err();
    assert!(matches!(
        error,
        ConfigValidationError::InvalidField { field: "runtime.response.hold_store_path", .. }
    ));

    let mut config = test_config();
    config.runtime.response.hold_ttl_ms = 0;
    let error = config.validate().unwrap_err();
    assert!(matches!(
        error,
        ConfigValidationError::InvalidField { field: "runtime.response.hold_ttl_ms", .. }
    ));
}
```

(`test_config()` is the existing fixture in that file; if it is named differently, use the name the file already uses for a valid `SwarmConfig`.)

- [ ] **Step 2: Run it and watch it fail to compile.**

```bash
cargo test -p swarm-core response_hold_settings
```

Expected: `error[E0412]: cannot find type ResponseHoldSettings`.

- [ ] **Step 3: Add the block.**

In `crates/swarm-core/src/config/defaults.rs`:

```rust
/// APPENDIX-NORMATIVE.md §6: PERCH_HOLD_TTL_MS, sixty minutes.
pub(super) const fn default_hold_ttl_ms() -> u64 {
    3_600_000
}

/// Same cadence as the containment sweep spawned in `swarm_detect`.
pub(super) const fn default_hold_sweep_interval_ms() -> u64 {
    5_000
}

/// Equals `policy.lease_ttl_ms`: past this instant the capability lease a
/// stalled decision would have carried is dead anyway.
pub(super) const fn default_decide_stall_ms() -> u64 {
    60_000
}

/// One day. The upper bound (`issued_at_ms <= held_at_ms`) is the load-bearing half.
pub(super) const fn default_governance_receipt_max_age_ms() -> u64 {
    86_400_000
}
```

In `crates/swarm-core/src/config/runtime.rs`, add the field to `RuntimeSettings` after `containment`:

```rust
    /// Durability, TTL and sweep cadence for holds (B1).
    #[serde(default)]
    pub response: ResponseHoldSettings,
```

and the type after `ContainmentSettings`:

```rust
/// Where held destructive actions are recorded, how long they stay decidable,
/// and how often the sweep runs.
///
/// Every field is `#[serde(default)]` for the reason `ContainmentSettings`
/// gives: `rulesets/default.yaml` is digest-signed and cannot take a new key,
/// so the shipped ruleset keeps loading and a deployment adds the block to its
/// own config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHoldSettings {
    /// `None` keeps holds in memory only, which means a restart FORGETS every
    /// open hold: the action is not taken, no expiry record is published, and
    /// the operator's queue silently loses rows. Same failure shape, same
    /// wording, as `ContainmentSettings.lease_store_path`.
    #[serde(default)]
    pub hold_store_path: Option<String>,
    /// How long a hold stays decidable. `PERCH_HOLD_TTL_MS`, default 3,600,000.
    #[serde(default = "default_hold_ttl_ms")]
    pub hold_ttl_ms: u64,
    /// Per-threat-class overrides, keyed by the threat-class slug
    /// (`lateral_movement`, …). Keyed by slug and not by `ThreatClass` because
    /// `ThreatClass::Custom(String)` is a newtype variant and a serde map key
    /// must be a string.
    #[serde(default)]
    pub hold_ttl_ms_by_threat_class: BTreeMap<String, u64>,
    /// How often `HoldSweep` runs. Default 5,000.
    #[serde(default = "default_hold_sweep_interval_ms")]
    pub sweep_interval_ms: u64,
    /// A `deciding` claim older than this is resolved to `failed` by the sweep.
    /// Default 60,000, equal to `policy.lease_ttl_ms`.
    #[serde(default = "default_decide_stall_ms")]
    pub decide_stall_ms: u64,
    /// A governance receipt older than this at decision time is refused as
    /// `governance.receipt_stale`. Default 86,400,000.
    #[serde(default = "default_governance_receipt_max_age_ms")]
    pub governance_receipt_max_age_ms: u64,
}

impl ResponseHoldSettings {
    /// The TTL for one threat class: the override when present, else the default.
    pub fn hold_ttl_ms_for(&self, threat_class_slug: &str) -> u64 {
        self.hold_ttl_ms_by_threat_class
            .get(threat_class_slug)
            .copied()
            .unwrap_or(self.hold_ttl_ms)
    }
}

impl Default for ResponseHoldSettings {
    fn default() -> Self {
        Self {
            hold_store_path: None,
            hold_ttl_ms: default_hold_ttl_ms(),
            hold_ttl_ms_by_threat_class: BTreeMap::new(),
            sweep_interval_ms: default_hold_sweep_interval_ms(),
            decide_stall_ms: default_decide_stall_ms(),
            governance_receipt_max_age_ms: default_governance_receipt_max_age_ms(),
        }
    }
}
```

In `crates/swarm-core/src/config/validation.rs`, immediately after the `lease_store_path` rule (`:366-378`):

```rust
        if self.runtime.response.hold_ttl_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.response.hold_ttl_ms",
                reason: "must be greater than zero; a hold with no bound is never expired"
                    .to_string(),
            });
        }
        if self.runtime.response.sweep_interval_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.response.sweep_interval_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.runtime.response.decide_stall_ms == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.response.decide_stall_ms",
                reason: "must be greater than zero; a decision that can stall forever is a \
                         trap"
                    .to_string(),
            });
        }
        if self
            .runtime
            .response
            .hold_store_path
            .as_ref()
            .is_some_and(|path| path.trim().is_empty())
        {
            return Err(ConfigValidationError::InvalidField {
                field: "runtime.response.hold_store_path",
                reason: "must not be empty when set; omit the key for in-memory holds".to_string(),
            });
        }
        for (slug, ttl) in &self.runtime.response.hold_ttl_ms_by_threat_class {
            if *ttl == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "runtime.response.hold_ttl_ms_by_threat_class",
                    reason: format!("override for `{slug}` must be greater than zero"),
                });
            }
        }
```

- [ ] **Step 4: Run the tests.**

```bash
cargo test -p swarm-core response_hold_settings
cargo test -p swarm-core config::
```

Expected: both new tests pass; every existing config test still passes (the block defaults on every fixture that does not set it, and `rulesets/default.yaml` still loads because it does not set it).

- [ ] **Step 5: Add the block to the dev ruleset and re-sign it.**

Append to `rulesets-dev/perch-dev.yaml` under `runtime:`:

```yaml
  response:
    hold_store_path: data/perch-dev/holds
```

Then `cargo run --bin sign_dev_ruleset -- rulesets-dev/perch-dev.yaml` (P0-22's binary) and confirm `git status --porcelain rulesets/` shows both the YAML and the sidecar modified, nothing else.

- [ ] **Step 6: Commit.**

```bash
git add crates/swarm-core rulesets-dev/perch-dev.yaml rulesets-dev/perch-dev.yaml.sig.json
git commit -s -m "feat(swarm-core): add runtime.response hold settings"
```

---

## Task 4: B1 record — `HeldAction`, its state enum and its decision record

**Files:**
- Create: `crates/swarm-runtime/src/held_action.rs`
- Create: `crates/swarm-runtime/src/held_action_tests.rs`
- Modify: `crates/swarm-runtime/src/lib.rs` (`pub mod held_action;` inserted between `pub mod evolution_status;` at `:133` and `pub mod http;` at `:134`)

**Interfaces:**
- Consumes: `swarm_policy::{ActionRequest, PolicyDecision}` (`crates/swarm-policy/src/lib.rs:47-82`), `swarm_core::types::{ResponseRehearsalPreview, Severity}`, `swarm_core::pheromone::{PheromoneConcentration, ThreatClass}`, `crate::escalation::EscalationLevel` (re-exported through `runtime_events`), `swarm_crypto::DetachedSignature`, `swarm_whisker::DetectionFinding`, `uuid::Uuid`.
- Produces (all `pub`, all `Serialize + Deserialize`):
  ```rust
  pub enum HoldState { Created, Notified, Armed, Deciding, Granted, Refused, Expired, Executed, Failed }
  pub enum HoldDecision { Grant, Refuse }
  pub enum HoldOutcome { GrantedExecuted, GrantedSimulated, GrantedFailed, RefusedByOperator, RefusedLate, GuardRejected }
  pub enum GovernanceClearance { NotRequired, PartitionAuthorized, ReceiptSignatureOk, ReceiptSubjectBound }
  pub struct HoldRefusal { pub rule: String, pub reason: String }
  pub struct HoldRationale { rule_name, reason, threat_class: ThreatClass, severity: Severity, request_carried_fields: Vec<String>, concentration_at_hold: Option<PheromoneConcentration>, escalation_level: Option<EscalationLevel>, governance_receipt_present: bool }
  pub struct HoldDecisionRecord { decision, operator_id, voter_id, rationale_sha256: Option<String>, hold_notice_published: bool, governance_clearance, decided_at_ms, nostr_intent_event_id, signature: Option<DetachedSignature>, rationale: Option<String>, outcome, dispatched: bool, receipt_id: Option<String>, audit_trail_id: Option<String>, refusal: Option<HoldRefusal> }
  pub struct HeldAction { hold_id, state, action_request, detection, policy_decision, rehearsal: Option<ResponseRehearsalPreview>, rationale, held_at_ms, expires_at_ms, audit_trail_id: Option<String>, case_channel: Option<String>, notified_at_ms: Option<i64>, notice_event_id: Option<String>, card_event_id: Option<String>, decision: Option<HoldDecisionRecord>, deciding_intent_event_id: Option<String>, cas_instant_ms: Option<i64>, prior_state: Option<HoldState> }
  pub fn mint_hold_id() -> String                       // "hold_" + lowercase v4 UUID
  pub fn is_opaque_hold_id(value: &str) -> bool         // the R-3 pattern
  impl HeldAction { pub fn is_open(&self) -> bool; pub fn is_terminal(&self) -> bool; pub fn assert_decidable(&self, now_ms: i64) -> Result<(), NotDecidable>; pub fn leases_a_containment(&self) -> bool }
  ```

`case_channel`, `notice_event_id` and `card_event_id` are additions to `12` §3.2's record: `perch_record_verdict` builds the leg-1 card's `locator.case_channel` from daemon-fetched state (`14` §7.3.1), and the record is the only place the bridge can report the channel it created for a `Held` trigger back to the daemon (`11` §9.1.4 mints the case UUID in the bridge). The HTTP `HeldActionView` exposes them (Task 10).

- [ ] **Step 1: Write the failing tests.**

`crates/swarm-runtime/src/held_action_tests.rs`:

```rust
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
use swarm_policy::{ActionRequest, PolicyDecision, PolicyVerdict};

pub(super) const T0: i64 = 1_773_739_200_000;

pub(super) fn fixture_request(action: ResponseAction) -> ActionRequest {
    ActionRequest {
        hunt_id: HuntId("hunt-evt-1".to_string()),
        requested_by: AgentId::from_public_key_hex(&"18".repeat(32)),
        action,
        severity: Severity::Critical,
        evidence: serde_json::json!({ "escalation": { "threat_class": "execution", "level": "alert" } }),
    }
}

pub(super) fn fixture_hold(action: ResponseAction, held_at_ms: i64) -> HeldAction {
    let request = fixture_request(action);
    let detection = crate::detection::routed_detection_for_test(&request);
    HeldAction::new(
        mint_hold_id(),
        request,
        detection,
        PolicyDecision {
            verdict: PolicyVerdict::RequireHuman,
            rule_name: "static.human_gate".to_string(),
            reason: "authorized but held for human approval".to_string(),
        },
        None,
        held_at_ms,
        held_at_ms + 3_600_000,
        Some("trail-1".to_string()),
    )
}

#[test]
fn a_minted_hold_id_matches_the_wire_pattern_and_is_v4() {
    let id = mint_hold_id();
    assert_eq!(id.len(), 41);
    assert!(id.starts_with("hold_"));
    assert!(is_opaque_hold_id(&id));
    assert!(!id.contains(':'));
    let uuid = &id["hold_".len()..];
    assert_eq!(uuid.as_bytes()[14], b'4');
    assert!(matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
}

#[test]
fn the_pattern_refuses_the_derived_colon_form() {
    assert!(!is_opaque_hold_id("hold:hunt-evt-1:1773739200000"));
    assert!(!is_opaque_hold_id("short"));
    assert!(!is_opaque_hold_id("_leading-underscore"));
    assert!(is_opaque_hold_id("h_a07aeacf"));
}

#[test]
fn the_record_serializes_in_verdict_pane_order() {
    let hold = fixture_hold(
        ResponseAction::IsolateHost { host_id: "host-ops-1".to_string() },
        T0,
    );
    let value = serde_json::to_value(&hold).unwrap();
    let keys: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
    // ACTION -> BLAST RADIUS -> IF YOU UNDO -> WHY WE ARE ASKING -> WHAT GRANTING OPENS
    // rides as: action_request -> rehearsal -> (inverse is derived) -> rationale -> expires_at_ms.
    let position = |name: &str| keys.iter().position(|k| *k == name).unwrap();
    assert!(position("action_request") < position("rehearsal"));
    assert!(position("rehearsal") < position("policy_decision"));
    assert!(position("policy_decision") < position("rationale"));
    assert!(position("rationale") < position("expires_at_ms"));
    assert!(position("hold_id") == 0 && position("state") == 1);
}

#[test]
fn only_the_four_containment_actions_lease_a_containment() {
    let leased = [
        ResponseAction::QuarantineFile { host_id: "h".into(), file_path: "/tmp/x".into() },
        ResponseAction::SuspendProcess { host_id: "h".into(), process_name: "p".into() },
        ResponseAction::IsolateHost { host_id: "h".into() },
        ResponseAction::TerminateUserSession { host_id: "h".into(), session_id: "s".into() },
    ];
    for action in leased {
        assert!(fixture_hold(action, T0).leases_a_containment());
    }
    assert!(!fixture_hold(ResponseAction::BlockEgress { target: "203.0.113.10".into() }, T0)
        .leases_a_containment());
    assert!(!fixture_hold(ResponseAction::KillProcess { host_id: "h".into(), process_name: "p".into() }, T0)
        .leases_a_containment());
}

#[test]
fn decidable_is_created_notified_or_armed_and_not_expired() {
    let mut hold = fixture_hold(ResponseAction::IsolateHost { host_id: "h".into() }, T0);
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    hold.state = HoldState::Notified;
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    hold.state = HoldState::Armed;
    assert!(hold.assert_decidable(T0 + 1).is_ok());
    assert_eq!(
        hold.assert_decidable(T0 + 3_600_000).unwrap_err(),
        NotDecidable::Expired
    );
    hold.state = HoldState::Deciding;
    assert_eq!(hold.assert_decidable(T0 + 1).unwrap_err(), NotDecidable::Deciding);
    hold.state = HoldState::Refused;
    assert_eq!(hold.assert_decidable(T0 + 1).unwrap_err(), NotDecidable::Terminal);
}
```

`crate::detection::routed_detection_for_test` does not exist; this task adds it as a `#[cfg(test)]`-only re-export of the same derivation `routed_detection_from_request` performs in `crates/swarm-ingest-runtime/src/ingest/mod.rs:1008-1040`, kept in `swarm-runtime` so the store tests need no ingest crate. Step 3 writes it.

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-runtime held_action
```

Expected: `error[E0583]: file not found for module held_action`.

- [ ] **Step 3: Write the record.**

`crates/swarm-runtime/src/held_action.rs`:

```rust
//! One `PolicyVerdict::RequireHuman` made durable (bill item B1).
//!
//! The record lives in `swarm-runtime` rather than `swarm-ingest-runtime`
//! because two consumers need the trait and neither may link the ingest crate:
//! the perch bridge (W3-13: it takes a bare receiver and holds a store handle
//! for the in-process `mark_*` callbacks `12-BACKEND-BILL-API.md` §3.2 names),
//! and `swarm_detect`, which builds the store from config beside the
//! containment store. The interception point stays in the ingest crate
//! (`perch_ops::holds::HoldCapture`).
//!
//! # State machine
//!
//! `created -> notified -> armed -> deciding -> {granted, refused}`,
//! `granted -> {executed, failed, refused}`, and `{created, notified, armed}
//! -> expired` on the sweep. `deciding` is never absorbing: `abandon_decision`
//! returns it to `prior_state`, and `fail_stalled_decisions` moves it to
//! `failed` after `decide_stall_ms`. `created` IS decidable — `notified` is a
//! fact about the queue card, not about the hold.

use std::collections::BTreeMap;
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};
use swarm_core::pheromone::{PheromoneConcentration, ThreatClass};
use swarm_core::types::{ResponseRehearsalPreview, Severity};
use swarm_crypto::DetachedSignature;
use swarm_policy::{ActionRequest, PolicyDecision};
use swarm_whisker::DetectionFinding;

use crate::runtime_events::EscalationLevel;

/// The nine hold states. Transitions are in the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldState {
    Created,
    Notified,
    Armed,
    Deciding,
    Granted,
    Refused,
    Expired,
    Executed,
    Failed,
}

impl HoldState {
    /// `created`, `notified` or `armed`.
    pub fn is_open(self) -> bool {
        matches!(self, Self::Created | Self::Notified | Self::Armed)
    }

    /// `granted`, `refused`, `expired`, `executed` or `failed`.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Granted | Self::Refused | Self::Expired | Self::Executed | Self::Failed
        )
    }

    /// The wire string, matching `#[serde(rename_all = "snake_case")]`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Notified => "notified",
            Self::Armed => "armed",
            Self::Deciding => "deciding",
            Self::Granted => "granted",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Executed => "executed",
            Self::Failed => "failed",
        }
    }
}

/// `grant` / `refuse`. Never `deny`: `refuse` is the operator's word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldDecision {
    Grant,
    Refuse,
}

impl HoldDecision {
    /// The wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Refuse => "refuse",
        }
    }
}

/// What actually happened after a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldOutcome {
    GrantedExecuted,
    GrantedSimulated,
    GrantedFailed,
    RefusedByOperator,
    RefusedLate,
    GuardRejected,
}

/// Which governance checks ran at decision time. No variant is named
/// `Verified`, because nothing this bill can build establishes that a
/// receipt's signer is a governor (`12-BACKEND-BILL-API.md` §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceClearance {
    NotRequired,
    PartitionAuthorized,
    ReceiptSignatureOk,
    ReceiptSubjectBound,
}

/// Why a grant did not become an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldRefusal {
    /// One of the fifteen rules `12-BACKEND-BILL-API.md` §4.6 enumerates.
    pub rule: String,
    /// The verbatim reason from the refusing layer.
    pub reason: String,
}

/// The differentiating context render law 1 needs and `PolicyDecision`
/// cannot give: every hold today carries `static.human_gate` and the same
/// reason string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldRationale {
    pub rule_name: String,
    pub reason: String,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    /// Always contains at least `severity` and `threat_class`: both are set by
    /// the requesting agent and read back by `ConfigurableApprovalGate`.
    pub request_carried_fields: Vec<String>,
    pub concentration_at_hold: Option<PheromoneConcentration>,
    pub escalation_level: Option<EscalationLevel>,
    /// Whether `evidence["governance_receipt"]` was present at hold time. Not
    /// a verification result.
    pub governance_receipt_present: bool,
}

/// The stored outcome of a decision. Written once, replayed byte-identically
/// to any retry carrying the same `nostr_intent_event_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoldDecisionRecord {
    pub decision: HoldDecision,
    /// From `AuthenticatedOperatorPrincipal.operator_id`, never from the body.
    pub operator_id: String,
    /// `swarm:ed25519:{public_key_hex}`, derived from the signature's own key.
    pub voter_id: String,
    /// The digest inside the signature preimage, or `None` when there was none.
    pub rationale_sha256: Option<String>,
    /// Whether the hold had reached `notified` at the compare-and-set.
    pub hold_notice_published: bool,
    pub governance_clearance: GovernanceClearance,
    /// The compare-and-set instant. Both leases are minted from it.
    pub decided_at_ms: i64,
    /// The leg-1 card id. The idempotency key and an UNSIGNED pointer.
    pub nostr_intent_event_id: String,
    pub signature: Option<DetachedSignature>,
    pub rationale: Option<String>,
    pub outcome: HoldOutcome,
    /// Whether the runtime attempted the response at all.
    pub dispatched: bool,
    pub receipt_id: Option<String>,
    pub audit_trail_id: Option<String>,
    pub refusal: Option<HoldRefusal>,
}

/// One held destructive action. Field order IS the verdict pane's render
/// order and a test asserts it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeldAction {
    /// `hold_` + lowercase v4 UUID; see [`mint_hold_id`].
    pub hold_id: String,
    pub state: HoldState,
    /// ACTION. Persisted verbatim: `AuditTrail` does not carry it.
    pub action_request: ActionRequest,
    /// BLAST RADIUS. `None` when no preview could be built; the card renders
    /// an explicit absence.
    pub rehearsal: Option<ResponseRehearsalPreview>,
    pub detection: DetectionFinding,
    pub policy_decision: PolicyDecision,
    /// WHY WE ARE ASKING.
    pub rationale: HoldRationale,
    pub held_at_ms: i64,
    /// WHAT GRANTING OPENS is computed from this and the configured TTLs.
    pub expires_at_ms: i64,
    /// The runtime's own `AuditTrail.trail_id` for the `Skipped` trail.
    pub audit_trail_id: Option<String>,
    /// The case channel the bridge created (or reused) for this hold's hunt.
    /// `None` until the bridge reports it; a hold is decidable without one,
    /// but leg 1 has nowhere to be published until it exists.
    pub case_channel: Option<String>,
    /// When the relay accepted the `kind:46010` notice. Informational.
    pub notified_at_ms: Option<i64>,
    /// The `46010` event id, once accepted.
    pub notice_event_id: Option<String>,
    /// The `swarm:hold:v1` card's event id, once accepted.
    pub card_event_id: Option<String>,
    /// Set exactly once, by `complete_decision`.
    pub decision: Option<HoldDecisionRecord>,
    /// The `nostr_intent_event_id` that won the compare-and-set.
    pub deciding_intent_event_id: Option<String>,
    /// The instant the compare-and-set succeeded.
    pub cas_instant_ms: Option<i64>,
    /// The state the compare-and-set moved out of.
    pub prior_state: Option<HoldState>,
}

/// Why a hold cannot be decided right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotDecidable {
    /// `now_ms >= expires_at_ms`, or the state is already `expired`.
    Expired,
    /// Another decision holds the claim.
    Deciding,
    /// The hold is in a terminal state.
    Terminal,
}

/// `hold_` plus a lowercase RFC 4122 v4 UUID: 41 characters, purely random,
/// no timestamp, no `hunt_id`. Satisfies the R-3 pattern.
pub fn mint_hold_id() -> String {
    format!("hold_{}", uuid::Uuid::new_v4().hyphenated())
}

/// The R-3 wire pattern `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`, hand-written so
/// no regex engine sits under a safety assert.
pub fn is_opaque_hold_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (8..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
}

impl HeldAction {
    /// A fresh `created` hold.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hold_id: String,
        action_request: ActionRequest,
        detection: DetectionFinding,
        policy_decision: PolicyDecision,
        rehearsal: Option<ResponseRehearsalPreview>,
        held_at_ms: i64,
        expires_at_ms: i64,
        audit_trail_id: Option<String>,
    ) -> Self {
        let rationale = HoldRationale::derive(&action_request, &policy_decision);
        Self {
            hold_id,
            state: HoldState::Created,
            action_request,
            rehearsal,
            detection,
            policy_decision,
            rationale,
            held_at_ms,
            expires_at_ms,
            audit_trail_id,
            case_channel: None,
            notified_at_ms: None,
            notice_event_id: None,
            card_event_id: None,
            decision: None,
            deciding_intent_event_id: None,
            cas_instant_ms: None,
            prior_state: None,
        }
    }

    /// `created`, `notified` or `armed`.
    pub fn is_open(&self) -> bool {
        self.state.is_open()
    }

    /// Any of the five terminal states.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Whether `is_containment_action` matches: true for exactly four of the
    /// twelve destructive kinds, so the card knows whether to render a
    /// pending containment-lease slot at all.
    pub fn leases_a_containment(&self) -> bool {
        crate::containment::is_containment_action(&self.action_request.action)
    }

    /// Read-only decidability check. Mutates nothing.
    pub fn assert_decidable(&self, now_ms: i64) -> Result<(), NotDecidable> {
        match self.state {
            HoldState::Deciding => Err(NotDecidable::Deciding),
            HoldState::Expired => Err(NotDecidable::Expired),
            state if state.is_terminal() => Err(NotDecidable::Terminal),
            _ if now_ms >= self.expires_at_ms => Err(NotDecidable::Expired),
            _ => Ok(()),
        }
    }
}

impl HoldRationale {
    /// Built at hold time from the request's own evidence. `severity` and
    /// `threat_class` are always request-carried.
    pub fn derive(request: &ActionRequest, decision: &PolicyDecision) -> Self {
        let escalation = request.evidence.get("escalation");
        let threat_class = escalation
            .and_then(|value| value.get("threat_class"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or(ThreatClass::Execution);
        let escalation_level = escalation
            .and_then(|value| value.get("level"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        let concentration_at_hold = escalation
            .and_then(|value| value.get("concentration"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
        Self {
            rule_name: decision.rule_name.clone(),
            reason: decision.reason.clone(),
            threat_class,
            severity: request.severity,
            request_carried_fields: vec!["severity".to_string(), "threat_class".to_string()],
            concentration_at_hold,
            escalation_level,
            governance_receipt_present: request.evidence.get("governance_receipt").is_some(),
        }
    }
}

#[cfg(test)]
#[path = "held_action_tests.rs"]
mod tests;
```

The store types (`HeldActionStore`, `DecisionClaim`, `MemoryHeldActionStore`, `FileHeldActionStore`) are appended to this file by Tasks 5 and 6; the `use std::…` lines above are for them. Add to `crates/swarm-runtime/src/detection/mod.rs`:

```rust
/// Test-only mirror of the ingest crate's `routed_detection_from_request`, so
/// the hold store's tests can build a `DetectionFinding` without linking the
/// ingest crate.
#[cfg(test)]
pub fn routed_detection_for_test(request: &swarm_policy::ActionRequest) -> swarm_whisker::DetectionFinding {
    swarm_whisker::DetectionFinding {
        finding_id: format!("finding:{}", request.hunt_id.0),
        event_id: request.hunt_id.0.clone(),
        strategy_id: "test".to_string(),
        threat_class: swarm_core::pheromone::ThreatClass::Execution,
        severity: request.severity,
        confidence: 1.0,
        evidence: request.evidence.clone(),
    }
}
```

(Match the seven field names of `DetectionFinding` at `crates/swarm-whisker/src/detector.rs:50-59`; if a field there is named differently, use that name.)

In `crates/swarm-runtime/src/lib.rs`, insert `pub mod held_action;` after `pub mod evolution_status;` (`:133`).

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-runtime held_action
```

Expected: 5 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-runtime
git commit -s -m "feat(swarm-runtime): add the HeldAction record and hold state machine types"
```

---

## Task 5: B1 store — `HeldActionStore`, `MemoryHeldActionStore` and the `DecisionClaim` guard

**Files:**
- Modify: `crates/swarm-runtime/src/held_action.rs`
- Modify: `crates/swarm-runtime/src/held_action_tests.rs`

**Interfaces:**
- Produces:
  ```rust
  pub enum HeldActionStoreError { NotFound { hold_id: String }, NotDecidable { hold_id: String, current: Box<HeldAction> }, Duplicate { hold_id: String }, Io { path: String, source: std::io::Error }, Corrupt { path: String, reason: String }, Poisoned }
  pub struct HeldActionStoreHealth { pub durable: bool, pub backend: String, pub open_holds: usize, pub deciding_stalled: usize }
  pub trait HeldActionStore: Send + Sync {
      fn create(&self, hold: HeldAction) -> Result<(), HeldActionStoreError>;
      fn get(&self, hold_id: &str) -> Result<Option<HeldAction>, HeldActionStoreError>;
      fn list(&self, include_terminal: bool, limit: usize) -> Result<Vec<HeldAction>, HeldActionStoreError>;
      fn mark_case_channel(&self, hold_id: &str, case_channel: &str) -> Result<(), HeldActionStoreError>;
      fn mark_notified(&self, hold_id: &str, at_ms: i64, notice_event_id: &str, card_event_id: Option<&str>) -> Result<(), HeldActionStoreError>;
      fn mark_armed(&self, hold_id: &str, at_ms: i64) -> Result<(), HeldActionStoreError>;
      fn begin_decision(&self, hold_id: &str, intent_event_id: &str, cas_instant_ms: i64) -> Result<HeldAction, HeldActionStoreError>;
      fn abandon_decision(&self, hold_id: &str, intent_event_id: &str) -> Result<(), HeldActionStoreError>;
      fn complete_decision(&self, hold_id: &str, decision: HoldDecisionRecord, state: HoldState) -> Result<(), HeldActionStoreError>;
      fn expire_due(&self, now_ms: i64) -> Result<Vec<HeldAction>, HeldActionStoreError>;
      fn fail_stalled_decisions(&self, now_ms: i64, stall_ms: u64) -> Result<Vec<HeldAction>, HeldActionStoreError>;
      fn health(&self, now_ms: i64, stall_ms: u64) -> Result<HeldActionStoreHealth, HeldActionStoreError>;
  }
  pub struct DecisionClaim<'a> { … }   // Drop => abandon unless disarmed
  impl<'a> DecisionClaim<'a> { pub fn begin(store: &'a dyn HeldActionStore, hold_id: &str, intent_event_id: &str, cas_instant_ms: i64) -> Result<Self, HeldActionStoreError>; pub fn claimed(&self) -> &HeldAction; pub fn complete(self, decision: HoldDecisionRecord, state: HoldState) -> Result<(), HeldActionStoreError> }
  pub struct MemoryHeldActionStore { … }  // RwLock<BTreeMap<String, HeldAction>>
  ```

- [ ] **Step 1: Write the failing state-machine tests.**

Append to `held_action_tests.rs`:

```rust
use swarm_core::types::ResponseAction;

fn memory_store_with_hold(state: HoldState) -> (MemoryHeldActionStore, String) {
    let store = MemoryHeldActionStore::default();
    let mut hold = fixture_hold(ResponseAction::IsolateHost { host_id: "host-ops-1".into() }, T0);
    hold.state = state;
    if state == HoldState::Notified {
        hold.notified_at_ms = Some(T0 + 10);
    }
    let id = hold.hold_id.clone();
    store.create(hold).unwrap();
    (store, id)
}

fn refused_record(intent: &str) -> HoldDecisionRecord {
    HoldDecisionRecord {
        decision: HoldDecision::Refuse,
        operator_id: "perch-dev-operator".into(),
        voter_id: format!("swarm:ed25519:{}", "ab".repeat(32)),
        rationale_sha256: None,
        hold_notice_published: false,
        governance_clearance: GovernanceClearance::NotRequired,
        decided_at_ms: T0 + 100,
        nostr_intent_event_id: intent.to_string(),
        signature: None,
        rationale: None,
        outcome: HoldOutcome::RefusedByOperator,
        dispatched: false,
        receipt_id: None,
        audit_trail_id: None,
        refusal: None,
    }
}

const INTENT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INTENT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn created_is_decidable_and_the_cas_records_the_prior_state() {
    let (store, id) = memory_store_with_hold(HoldState::Created);
    let claimed = store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
    assert_eq!(claimed.state, HoldState::Deciding);
    assert_eq!(claimed.prior_state, Some(HoldState::Created));
    assert_eq!(claimed.deciding_intent_event_id.as_deref(), Some(INTENT_A));
    assert_eq!(claimed.cas_instant_ms, Some(T0 + 100));
}

#[test]
fn a_second_decision_on_a_deciding_hold_is_refused_with_the_current_record() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
    let error = store.begin_decision(&id, INTENT_B, T0 + 101).unwrap_err();
    match error {
        HeldActionStoreError::NotDecidable { current, .. } => {
            assert_eq!(current.state, HoldState::Deciding);
            assert_eq!(current.deciding_intent_event_id.as_deref(), Some(INTENT_A));
        }
        other => panic!("expected NotDecidable, got {other:?}"),
    }
}

#[test]
fn the_cas_rechecks_expiry_inside_the_lock() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    let error = store.begin_decision(&id, INTENT_A, T0 + 3_600_000).unwrap_err();
    assert!(matches!(error, HeldActionStoreError::NotDecidable { .. }));
    assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Notified);
}

#[test]
fn abandon_restores_the_prior_state_and_is_idempotent() {
    let (store, id) = memory_store_with_hold(HoldState::Armed);
    store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
    store.abandon_decision(&id, INTENT_A).unwrap();
    let hold = store.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Armed);
    assert_eq!(hold.deciding_intent_event_id, None);
    assert_eq!(hold.prior_state, None);
    // Abandoning again, or with the wrong id, is a no-op and not an error.
    store.abandon_decision(&id, INTENT_A).unwrap();
    store.abandon_decision(&id, INTENT_B).unwrap();
    assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Armed);
}

#[test]
fn every_pre_dispatch_refusal_leaves_the_hold_decidable() {
    // The Drop guard is the load-bearing half: every early return between the
    // CAS and complete_decision abandons, including ones nobody has written.
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    fn early_return(store: &dyn HeldActionStore, id: &str) -> Result<(), HeldActionStoreError> {
        let claim = DecisionClaim::begin(store, id, INTENT_A, T0 + 100)?;
        let _ = claim.claimed();
        Err(HeldActionStoreError::Poisoned) // an injected pre-dispatch failure
    }
    let _ = early_return(&store, &id);
    assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Notified, "the guard parked the hold in deciding");
}

#[test]
fn complete_disarms_the_guard_and_writes_the_terminal_record() {
    let (store, id) = memory_store_with_hold(HoldState::Notified);
    let claim = DecisionClaim::begin(&store, &id, INTENT_A, T0 + 100).unwrap();
    claim.complete(refused_record(INTENT_A), HoldState::Refused).unwrap();
    let hold = store.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Refused);
    assert_eq!(hold.decision.as_ref().unwrap().nostr_intent_event_id, INTENT_A);
    assert_eq!(hold.deciding_intent_event_id.as_deref(), Some(INTENT_A));
    assert_eq!(hold.prior_state, None);
    // A retry on a terminal hold with the same id sees the stored record.
    let error = store.begin_decision(&id, INTENT_A, T0 + 200).unwrap_err();
    assert!(matches!(error, HeldActionStoreError::NotDecidable { .. }));
}

#[test]
fn list_is_sorted_by_expiry_then_id_and_hides_terminal_by_default() {
    let store = MemoryHeldActionStore::default();
    let mut late = fixture_hold(ResponseAction::BlockEgress { target: "a".into() }, T0 + 5);
    late.hold_id = "hold_zzzzzzzz-0000-4000-8000-000000000000".into();
    let mut early = fixture_hold(ResponseAction::BlockEgress { target: "b".into() }, T0);
    early.hold_id = "hold_aaaaaaaa-0000-4000-8000-000000000000".into();
    let mut done = fixture_hold(ResponseAction::BlockEgress { target: "c".into() }, T0);
    done.hold_id = "hold_bbbbbbbb-0000-4000-8000-000000000000".into();
    done.state = HoldState::Refused;
    for hold in [late.clone(), early.clone(), done.clone()] {
        store.create(hold).unwrap();
    }
    let open: Vec<String> = store.list(false, 10).unwrap().into_iter().map(|h| h.hold_id).collect();
    assert_eq!(open, vec![early.hold_id.clone(), late.hold_id.clone()]);
    assert_eq!(store.list(true, 10).unwrap().len(), 3);
    assert_eq!(store.list(true, 1).unwrap().len(), 1);
}

#[test]
fn mark_case_channel_and_mark_notified_move_created_to_notified() {
    let (store, id) = memory_store_with_hold(HoldState::Created);
    store.mark_case_channel(&id, "27799e23-ab25-4659-b381-3de47ea7ca4d").unwrap();
    assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Created);
    store.mark_notified(&id, T0 + 50, &"cd".repeat(32), Some(&"ef".repeat(32))).unwrap();
    let hold = store.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Notified);
    assert_eq!(hold.notified_at_ms, Some(T0 + 50));
    assert_eq!(hold.case_channel.as_deref(), Some("27799e23-ab25-4659-b381-3de47ea7ca4d"));
    assert_eq!(hold.notice_event_id.as_deref(), Some("cd".repeat(32).as_str()));
}
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-runtime held_action
```

Expected: `error[E0433]: failed to resolve: use of undeclared type MemoryHeldActionStore` (and the trait).

- [ ] **Step 3: Implement the trait, the memory store and the guard.**

Append to `crates/swarm-runtime/src/held_action.rs`:

```rust
/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum HeldActionStoreError {
    #[error("no hold `{hold_id}`")]
    NotFound { hold_id: String },
    /// Carries the CURRENT record so the route can tell a replay from a
    /// conflict without a second read.
    #[error("hold `{hold_id}` is not decidable in state {}", current.state.as_str())]
    NotDecidable { hold_id: String, current: Box<HeldAction> },
    #[error("hold `{hold_id}` already exists")]
    Duplicate { hold_id: String },
    #[error("hold store io error at {path}: {source}")]
    Io { path: String, #[source] source: std::io::Error },
    #[error("hold store document {path} is corrupt: {reason}")]
    Corrupt { path: String, reason: String },
    #[error("hold store lock poisoned")]
    Poisoned,
}

/// What a list response says about the backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldActionStoreHealth {
    /// FALSE for the in-memory backend: a restart forgets every open hold.
    pub durable: bool,
    pub backend: String,
    pub open_holds: usize,
    /// Holds in `deciding` older than `stall_ms`.
    pub deciding_stalled: usize,
}

/// Durable home for holds. `begin_decision` is a compare-and-set, not a write.
pub trait HeldActionStore: Send + Sync {
    /// Insert a `created` hold. `Duplicate` on an existing id.
    fn create(&self, hold: HeldAction) -> Result<(), HeldActionStoreError>;
    /// One hold, any state.
    fn get(&self, hold_id: &str) -> Result<Option<HeldAction>, HeldActionStoreError>;
    /// Sorted `(expires_at_ms, hold_id)`. `include_terminal` adds decided and
    /// expired holds.
    fn list(&self, include_terminal: bool, limit: usize)
        -> Result<Vec<HeldAction>, HeldActionStoreError>;
    /// The bridge reports the case channel it created or reused. Any open
    /// state; informational.
    fn mark_case_channel(&self, hold_id: &str, case_channel: &str)
        -> Result<(), HeldActionStoreError>;
    /// The bridge reports that the relay accepted the `46010` notice.
    /// `created -> notified`; a no-op on any other state. Gates nothing.
    fn mark_notified(
        &self,
        hold_id: &str,
        at_ms: i64,
        notice_event_id: &str,
        card_event_id: Option<&str>,
    ) -> Result<(), HeldActionStoreError>;
    /// Client-reported arming. `notified -> armed`; a no-op otherwise.
    fn mark_armed(&self, hold_id: &str, at_ms: i64) -> Result<(), HeldActionStoreError>;
    /// `created|notified|armed -> deciding`, atomically, re-checking expiry
    /// inside the lock. Returns the claimed record; `NotDecidable` carries the
    /// current record for every other state.
    fn begin_decision(
        &self,
        hold_id: &str,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<HeldAction, HeldActionStoreError>;
    /// `deciding -> prior_state`. The only non-terminal exit. Idempotent: a
    /// hold that is not `deciding`, or that is deciding under another id, is
    /// left alone and this is NOT an error.
    fn abandon_decision(&self, hold_id: &str, intent_event_id: &str)
        -> Result<(), HeldActionStoreError>;
    /// `deciding -> terminal`, with the outcome. Keeps `deciding_intent_event_id`
    /// so a 409'd console can learn the winner; clears `prior_state`.
    fn complete_decision(
        &self,
        hold_id: &str,
        decision: HoldDecisionRecord,
        state: HoldState,
    ) -> Result<(), HeldActionStoreError>;
    /// `created|notified|armed -> expired` for everything past `now_ms`.
    fn expire_due(&self, now_ms: i64) -> Result<Vec<HeldAction>, HeldActionStoreError>;
    /// `deciding -> failed` for every claim older than `stall_ms`, with the
    /// honest unknown-outcome refusal.
    fn fail_stalled_decisions(
        &self,
        now_ms: i64,
        stall_ms: u64,
    ) -> Result<Vec<HeldAction>, HeldActionStoreError>;
    /// Backend facts for the list response.
    fn health(&self, now_ms: i64, stall_ms: u64)
        -> Result<HeldActionStoreHealth, HeldActionStoreError>;
}

/// The refusal a stalled decision is resolved with. One string, rendered
/// verbatim, because neither the daemon nor the operator can know more.
pub const STALLED_DECISION_REASON: &str = "the decision stalled; whether the action ran is unknown";

fn stalled_refusal() -> HoldRefusal {
    HoldRefusal {
        rule: "runtime.capability_lease_expired".to_string(),
        reason: STALLED_DECISION_REASON.to_string(),
    }
}

/// Pure transition logic shared by both backends, applied under the backend's
/// own lock. Every method mutates in place and reports what it did.
mod transitions {
    use super::*;

    pub fn begin(
        hold: &mut HeldAction,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<(), ()> {
        if hold.assert_decidable(cas_instant_ms).is_err() {
            return Err(());
        }
        hold.prior_state = Some(hold.state);
        hold.state = HoldState::Deciding;
        hold.deciding_intent_event_id = Some(intent_event_id.to_string());
        hold.cas_instant_ms = Some(cas_instant_ms);
        Ok(())
    }

    pub fn abandon(hold: &mut HeldAction, intent_event_id: &str) -> bool {
        if hold.state != HoldState::Deciding
            || hold.deciding_intent_event_id.as_deref() != Some(intent_event_id)
        {
            return false;
        }
        hold.state = hold.prior_state.take().unwrap_or(HoldState::Created);
        hold.deciding_intent_event_id = None;
        hold.cas_instant_ms = None;
        true
    }

    pub fn complete(hold: &mut HeldAction, decision: HoldDecisionRecord, state: HoldState) {
        hold.state = state;
        hold.decision = Some(decision);
        hold.prior_state = None;
    }

    pub fn expire(hold: &mut HeldAction, now_ms: i64) -> bool {
        if hold.state.is_open() && now_ms >= hold.expires_at_ms {
            hold.state = HoldState::Expired;
            return true;
        }
        false
    }

    pub fn fail_stalled(hold: &mut HeldAction, now_ms: i64, stall_ms: u64) -> bool {
        let stalled = hold.state == HoldState::Deciding
            && hold
                .cas_instant_ms
                .is_some_and(|cas| now_ms.saturating_sub(cas) >= stall_ms as i64);
        if !stalled {
            return false;
        }
        let intent = hold.deciding_intent_event_id.clone().unwrap_or_default();
        hold.decision = Some(HoldDecisionRecord {
            decision: HoldDecision::Grant,
            operator_id: String::new(),
            voter_id: String::new(),
            rationale_sha256: None,
            hold_notice_published: hold.notified_at_ms.is_some(),
            governance_clearance: GovernanceClearance::NotRequired,
            decided_at_ms: hold.cas_instant_ms.unwrap_or(now_ms),
            nostr_intent_event_id: intent,
            signature: None,
            rationale: None,
            outcome: HoldOutcome::GrantedFailed,
            dispatched: false,
            receipt_id: None,
            audit_trail_id: None,
            refusal: Some(stalled_refusal()),
        });
        hold.state = HoldState::Failed;
        hold.prior_state = None;
        true
    }

    pub fn is_stalled(hold: &HeldAction, now_ms: i64, stall_ms: u64) -> bool {
        hold.state == HoldState::Deciding
            && hold
                .cas_instant_ms
                .is_some_and(|cas| now_ms.saturating_sub(cas) >= stall_ms as i64)
    }

    pub fn sort_key(hold: &HeldAction) -> (i64, String) {
        (hold.expires_at_ms, hold.hold_id.clone())
    }
}

/// In-memory backend. `durable: false`.
#[derive(Debug, Default)]
pub struct MemoryHeldActionStore {
    holds: RwLock<BTreeMap<String, HeldAction>>,
}

impl MemoryHeldActionStore {
    fn read(&self) -> Result<std::sync::RwLockReadGuard<'_, BTreeMap<String, HeldAction>>, HeldActionStoreError> {
        self.holds.read().map_err(|_| HeldActionStoreError::Poisoned)
    }

    fn write(&self) -> Result<std::sync::RwLockWriteGuard<'_, BTreeMap<String, HeldAction>>, HeldActionStoreError> {
        self.holds.write().map_err(|_| HeldActionStoreError::Poisoned)
    }

    fn with_hold<T>(
        &self,
        hold_id: &str,
        apply: impl FnOnce(&mut HeldAction) -> T,
    ) -> Result<T, HeldActionStoreError> {
        let mut holds = self.write()?;
        let hold = holds.get_mut(hold_id).ok_or_else(|| HeldActionStoreError::NotFound {
            hold_id: hold_id.to_string(),
        })?;
        Ok(apply(hold))
    }
}

impl HeldActionStore for MemoryHeldActionStore {
    fn create(&self, hold: HeldAction) -> Result<(), HeldActionStoreError> {
        let mut holds = self.write()?;
        if holds.contains_key(&hold.hold_id) {
            return Err(HeldActionStoreError::Duplicate { hold_id: hold.hold_id });
        }
        holds.insert(hold.hold_id.clone(), hold);
        Ok(())
    }

    fn get(&self, hold_id: &str) -> Result<Option<HeldAction>, HeldActionStoreError> {
        Ok(self.read()?.get(hold_id).cloned())
    }

    fn list(&self, include_terminal: bool, limit: usize) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds: Vec<HeldAction> = self
            .read()?
            .values()
            .filter(|hold| include_terminal || !hold.is_terminal())
            .cloned()
            .collect();
        holds.sort_by_key(transitions::sort_key);
        holds.truncate(limit);
        Ok(holds)
    }

    fn mark_case_channel(&self, hold_id: &str, case_channel: &str) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| hold.case_channel = Some(case_channel.to_string()))
    }

    fn mark_notified(
        &self,
        hold_id: &str,
        at_ms: i64,
        notice_event_id: &str,
        card_event_id: Option<&str>,
    ) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| {
            hold.notified_at_ms = Some(at_ms);
            hold.notice_event_id = Some(notice_event_id.to_string());
            hold.card_event_id = card_event_id.map(str::to_string);
            if hold.state == HoldState::Created {
                hold.state = HoldState::Notified;
            }
        })
    }

    fn mark_armed(&self, hold_id: &str, _at_ms: i64) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| {
            if hold.state == HoldState::Notified {
                hold.state = HoldState::Armed;
            }
        })
    }

    fn begin_decision(
        &self,
        hold_id: &str,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<HeldAction, HeldActionStoreError> {
        let mut holds = self.write()?;
        let hold = holds.get_mut(hold_id).ok_or_else(|| HeldActionStoreError::NotFound {
            hold_id: hold_id.to_string(),
        })?;
        match transitions::begin(hold, intent_event_id, cas_instant_ms) {
            Ok(()) => Ok(hold.clone()),
            Err(()) => Err(HeldActionStoreError::NotDecidable {
                hold_id: hold_id.to_string(),
                current: Box::new(hold.clone()),
            }),
        }
    }

    fn abandon_decision(&self, hold_id: &str, intent_event_id: &str) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| {
            transitions::abandon(hold, intent_event_id);
        })
    }

    fn complete_decision(
        &self,
        hold_id: &str,
        decision: HoldDecisionRecord,
        state: HoldState,
    ) -> Result<(), HeldActionStoreError> {
        self.with_hold(hold_id, |hold| transitions::complete(hold, decision, state))
    }

    fn expire_due(&self, now_ms: i64) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds = self.write()?;
        let mut expired = Vec::new();
        for hold in holds.values_mut() {
            if transitions::expire(hold, now_ms) {
                expired.push(hold.clone());
            }
        }
        Ok(expired)
    }

    fn fail_stalled_decisions(&self, now_ms: i64, stall_ms: u64) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds = self.write()?;
        let mut failed = Vec::new();
        for hold in holds.values_mut() {
            if transitions::fail_stalled(hold, now_ms, stall_ms) {
                failed.push(hold.clone());
            }
        }
        Ok(failed)
    }

    fn health(&self, now_ms: i64, stall_ms: u64) -> Result<HeldActionStoreHealth, HeldActionStoreError> {
        let holds = self.read()?;
        Ok(HeldActionStoreHealth {
            durable: false,
            backend: "memory".to_string(),
            open_holds: holds.values().filter(|hold| hold.is_open()).count(),
            deciding_stalled: holds
                .values()
                .filter(|hold| transitions::is_stalled(hold, now_ms, stall_ms))
                .count(),
        })
    }
}

/// The claim a decide call holds between the compare-and-set and the outcome
/// write. `Drop` abandons unless `complete` disarmed it, so every early return
/// — including ones nobody has written yet — leaves the hold decidable.
pub struct DecisionClaim<'a> {
    store: &'a dyn HeldActionStore,
    hold_id: String,
    intent_event_id: String,
    claimed: HeldAction,
    armed: bool,
}

impl<'a> DecisionClaim<'a> {
    /// The compare-and-set. `Err(NotDecidable)` carries the current record.
    pub fn begin(
        store: &'a dyn HeldActionStore,
        hold_id: &str,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<Self, HeldActionStoreError> {
        let claimed = store.begin_decision(hold_id, intent_event_id, cas_instant_ms)?;
        Ok(Self {
            store,
            hold_id: hold_id.to_string(),
            intent_event_id: intent_event_id.to_string(),
            claimed,
            armed: true,
        })
    }

    /// The record as it was at the compare-and-set.
    pub fn claimed(&self) -> &HeldAction {
        &self.claimed
    }

    /// The ONLY terminal exit from `deciding`. Disarms the guard first, so a
    /// store fault on the terminal write is reported and not followed by an
    /// abandon that would erase the fault.
    pub fn complete(
        mut self,
        decision: HoldDecisionRecord,
        state: HoldState,
    ) -> Result<(), HeldActionStoreError> {
        self.armed = false;
        self.store.complete_decision(&self.hold_id, decision, state)
    }
}

impl Drop for DecisionClaim<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Err(error) = self.store.abandon_decision(&self.hold_id, &self.intent_event_id) {
            tracing::error!(
                module = module_path!(),
                hold_id = %self.hold_id,
                reason = %error,
                "abandon_decision failed; the hold may be parked in deciding until the sweep resolves it"
            );
        }
    }
}
```

Add `thiserror.workspace = true` to `crates/swarm-runtime/Cargo.toml` `[dependencies]` if it is not already there (it is a workspace dependency at root `Cargo.toml:100`).

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-runtime held_action
```

Expected: 13 passed. Then `cargo clippy -p swarm-runtime --all-targets -- -D warnings` clean (the `unwrap_or(HoldState::Created)` in `abandon` is a defensive default on a state the invariant guarantees is `Some`; no `unwrap()`).

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-runtime
git commit -s -m "feat(swarm-runtime): add HeldActionStore, the memory backend and the DecisionClaim guard"
```

---

## Task 6: B1 durability — `FileHeldActionStore`, `ConfiguredHeldActionStore`, restart recovery

**Files:**
- Modify: `crates/swarm-runtime/src/held_action.rs`
- Modify: `crates/swarm-runtime/src/held_action_tests.rs`

**Interfaces:**
- Consumes: `swarm_core::config::ResponseHoldSettings` (Task 3).
- Produces:
  ```rust
  pub struct FileHeldActionStore { … }      // one JSON document per hold, temp-then-rename, std::sync::Mutex
  impl FileHeldActionStore { pub fn open(directory: impl AsRef<Path>) -> Result<Self, HeldActionStoreError> }
  pub enum ConfiguredHeldActionStore { Memory(MemoryHeldActionStore), LocalFiles(FileHeldActionStore) }
  impl ConfiguredHeldActionStore { pub fn from_settings(settings: &ResponseHoldSettings, config_dir: &Path) -> Result<Self, HeldActionStoreError> }
  impl HeldActionStore for ConfiguredHeldActionStore   // delegates
  ```

- [ ] **Step 1: Write the failing restart tests.**

Append to `held_action_tests.rs`:

```rust
fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "held-action-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_file_store_recovers_an_open_hold_after_a_restart() {
    let dir = temp_dir("restart");
    let id = {
        let store = FileHeldActionStore::open(&dir).unwrap();
        let hold = fixture_hold(ResponseAction::IsolateHost { host_id: "host-ops-1".into() }, T0);
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        store.mark_notified(&id, T0 + 5, &"cd".repeat(32), None).unwrap();
        id
    };
    let reopened = FileHeldActionStore::open(&dir).unwrap();
    let hold = reopened.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Notified);
    assert!(reopened.health(T0, 60_000).unwrap().durable);
    assert_eq!(reopened.health(T0, 60_000).unwrap().backend, "local_files");
}

#[test]
fn a_deciding_hold_is_reloaded_as_deciding_and_resolved_by_the_sweep_not_by_a_guess() {
    let dir = temp_dir("deciding");
    let id = {
        let store = FileHeldActionStore::open(&dir).unwrap();
        let hold = fixture_hold(ResponseAction::IsolateHost { host_id: "host-ops-1".into() }, T0);
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        store.begin_decision(&id, INTENT_A, T0 + 100).unwrap();
        id
    };
    let reopened = FileHeldActionStore::open(&dir).unwrap();
    assert_eq!(reopened.get(&id).unwrap().unwrap().state, HoldState::Deciding);
    assert!(reopened.fail_stalled_decisions(T0 + 100 + 59_999, 60_000).unwrap().is_empty());
    let failed = reopened.fail_stalled_decisions(T0 + 100 + 60_000, 60_000).unwrap();
    assert_eq!(failed.len(), 1);
    let hold = reopened.get(&id).unwrap().unwrap();
    assert_eq!(hold.state, HoldState::Failed);
    let refusal = hold.decision.unwrap().refusal.unwrap();
    assert_eq!(refusal.rule, "runtime.capability_lease_expired");
    assert!(refusal.reason.contains("whether the action ran is unknown"));
}

#[test]
fn a_torn_document_is_reported_as_corrupt_not_skipped() {
    let dir = temp_dir("torn");
    std::fs::write(dir.join("hold_torn.json"), b"{\"hold_id\": \"hold_torn").unwrap();
    let error = FileHeldActionStore::open(&dir).unwrap_err();
    assert!(matches!(error, HeldActionStoreError::Corrupt { .. }));
}

#[test]
fn configured_store_is_memory_when_no_path_is_set() {
    let settings = ResponseHoldSettings::default();
    let store = ConfiguredHeldActionStore::from_settings(&settings, std::path::Path::new(".")).unwrap();
    assert!(!store.health(T0, 60_000).unwrap().durable);
}
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-runtime held_action
```

Expected: `cannot find type FileHeldActionStore`.

- [ ] **Step 3: Implement the file backend.**

Append to `held_action.rs`:

```rust
use std::path::{Path, PathBuf};
use swarm_core::config::ResponseHoldSettings;

/// One JSON document per hold under `runtime.response.hold_store_path`,
/// written temp-then-rename under a `std::sync::Mutex`. The in-memory map is
/// the read cache; every mutation writes through before the lock is released.
#[derive(Debug)]
pub struct FileHeldActionStore {
    directory: PathBuf,
    holds: Mutex<BTreeMap<String, HeldAction>>,
}

impl FileHeldActionStore {
    /// Load every `*.json` document in `directory`, creating it if absent. A
    /// document that does not parse is `Corrupt`, never skipped: a skipped
    /// hold is a destructive action nobody is shown.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, HeldActionStoreError> {
        let directory = directory.as_ref().to_path_buf();
        std::fs::create_dir_all(&directory).map_err(|source| HeldActionStoreError::Io {
            path: directory.display().to_string(),
            source,
        })?;
        let mut holds = BTreeMap::new();
        let entries = std::fs::read_dir(&directory).map_err(|source| HeldActionStoreError::Io {
            path: directory.display().to_string(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| HeldActionStoreError::Io {
                path: directory.display().to_string(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|source| HeldActionStoreError::Io {
                path: path.display().to_string(),
                source,
            })?;
            let hold: HeldAction =
                serde_json::from_slice(&bytes).map_err(|error| HeldActionStoreError::Corrupt {
                    path: path.display().to_string(),
                    reason: error.to_string(),
                })?;
            holds.insert(hold.hold_id.clone(), hold);
        }
        Ok(Self {
            directory,
            holds: Mutex::new(holds),
        })
    }

    fn document_path(&self, hold_id: &str) -> PathBuf {
        self.directory.join(format!("{hold_id}.json"))
    }

    fn persist(&self, hold: &HeldAction) -> Result<(), HeldActionStoreError> {
        let path = self.document_path(&hold.hold_id);
        let temp = self.directory.join(format!("{}.json.tmp", hold.hold_id));
        let bytes = serde_json::to_vec_pretty(hold).map_err(|error| HeldActionStoreError::Corrupt {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        std::fs::write(&temp, bytes).map_err(|source| HeldActionStoreError::Io {
            path: temp.display().to_string(),
            source,
        })?;
        std::fs::rename(&temp, &path).map_err(|source| HeldActionStoreError::Io {
            path: path.display().to_string(),
            source,
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, HeldAction>>, HeldActionStoreError> {
        self.holds.lock().map_err(|_| HeldActionStoreError::Poisoned)
    }

    fn mutate(
        &self,
        hold_id: &str,
        apply: impl FnOnce(&mut HeldAction),
    ) -> Result<(), HeldActionStoreError> {
        let mut holds = self.lock()?;
        let hold = holds.get_mut(hold_id).ok_or_else(|| HeldActionStoreError::NotFound {
            hold_id: hold_id.to_string(),
        })?;
        apply(hold);
        self.persist(hold)
    }
}

impl HeldActionStore for FileHeldActionStore {
    fn create(&self, hold: HeldAction) -> Result<(), HeldActionStoreError> {
        let mut holds = self.lock()?;
        if holds.contains_key(&hold.hold_id) {
            return Err(HeldActionStoreError::Duplicate { hold_id: hold.hold_id });
        }
        self.persist(&hold)?;
        holds.insert(hold.hold_id.clone(), hold);
        Ok(())
    }

    fn get(&self, hold_id: &str) -> Result<Option<HeldAction>, HeldActionStoreError> {
        Ok(self.lock()?.get(hold_id).cloned())
    }

    fn list(&self, include_terminal: bool, limit: usize) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds: Vec<HeldAction> = self
            .lock()?
            .values()
            .filter(|hold| include_terminal || !hold.is_terminal())
            .cloned()
            .collect();
        holds.sort_by_key(transitions::sort_key);
        holds.truncate(limit);
        Ok(holds)
    }

    fn mark_case_channel(&self, hold_id: &str, case_channel: &str) -> Result<(), HeldActionStoreError> {
        self.mutate(hold_id, |hold| hold.case_channel = Some(case_channel.to_string()))
    }

    fn mark_notified(
        &self,
        hold_id: &str,
        at_ms: i64,
        notice_event_id: &str,
        card_event_id: Option<&str>,
    ) -> Result<(), HeldActionStoreError> {
        self.mutate(hold_id, |hold| {
            hold.notified_at_ms = Some(at_ms);
            hold.notice_event_id = Some(notice_event_id.to_string());
            hold.card_event_id = card_event_id.map(str::to_string);
            if hold.state == HoldState::Created {
                hold.state = HoldState::Notified;
            }
        })
    }

    fn mark_armed(&self, hold_id: &str, _at_ms: i64) -> Result<(), HeldActionStoreError> {
        self.mutate(hold_id, |hold| {
            if hold.state == HoldState::Notified {
                hold.state = HoldState::Armed;
            }
        })
    }

    fn begin_decision(
        &self,
        hold_id: &str,
        intent_event_id: &str,
        cas_instant_ms: i64,
    ) -> Result<HeldAction, HeldActionStoreError> {
        let mut holds = self.lock()?;
        let hold = holds.get_mut(hold_id).ok_or_else(|| HeldActionStoreError::NotFound {
            hold_id: hold_id.to_string(),
        })?;
        if transitions::begin(hold, intent_event_id, cas_instant_ms).is_err() {
            return Err(HeldActionStoreError::NotDecidable {
                hold_id: hold_id.to_string(),
                current: Box::new(hold.clone()),
            });
        }
        self.persist(hold)?;
        Ok(hold.clone())
    }

    fn abandon_decision(&self, hold_id: &str, intent_event_id: &str) -> Result<(), HeldActionStoreError> {
        let mut holds = self.lock()?;
        let Some(hold) = holds.get_mut(hold_id) else {
            return Ok(());
        };
        if transitions::abandon(hold, intent_event_id) {
            self.persist(hold)?;
        }
        Ok(())
    }

    fn complete_decision(
        &self,
        hold_id: &str,
        decision: HoldDecisionRecord,
        state: HoldState,
    ) -> Result<(), HeldActionStoreError> {
        self.mutate(hold_id, |hold| transitions::complete(hold, decision, state))
    }

    fn expire_due(&self, now_ms: i64) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds = self.lock()?;
        let mut expired = Vec::new();
        for hold in holds.values_mut() {
            if transitions::expire(hold, now_ms) {
                self.persist(hold)?;
                expired.push(hold.clone());
            }
        }
        Ok(expired)
    }

    fn fail_stalled_decisions(&self, now_ms: i64, stall_ms: u64) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        let mut holds = self.lock()?;
        let mut failed = Vec::new();
        for hold in holds.values_mut() {
            if transitions::fail_stalled(hold, now_ms, stall_ms) {
                self.persist(hold)?;
                failed.push(hold.clone());
            }
        }
        Ok(failed)
    }

    fn health(&self, now_ms: i64, stall_ms: u64) -> Result<HeldActionStoreHealth, HeldActionStoreError> {
        let holds = self.lock()?;
        Ok(HeldActionStoreHealth {
            durable: true,
            backend: "local_files".to_string(),
            open_holds: holds.values().filter(|hold| hold.is_open()).count(),
            deciding_stalled: holds
                .values()
                .filter(|hold| transitions::is_stalled(hold, now_ms, stall_ms))
                .count(),
        })
    }
}

/// The backend `runtime.response.hold_store_path` selects.
#[derive(Debug)]
pub enum ConfiguredHeldActionStore {
    Memory(MemoryHeldActionStore),
    LocalFiles(FileHeldActionStore),
}

impl ConfiguredHeldActionStore {
    /// `None` path => memory (and a restart forgets every open hold). A
    /// relative path resolves against `config_dir`, matching how the
    /// containment store resolves `lease_store_path`.
    pub fn from_settings(
        settings: &ResponseHoldSettings,
        config_dir: &Path,
    ) -> Result<Self, HeldActionStoreError> {
        match settings.hold_store_path.as_deref() {
            None => Ok(Self::Memory(MemoryHeldActionStore::default())),
            Some(path) => {
                let resolved = if Path::new(path).is_absolute() {
                    PathBuf::from(path)
                } else {
                    config_dir.join(path)
                };
                Ok(Self::LocalFiles(FileHeldActionStore::open(resolved)?))
            }
        }
    }
}

macro_rules! delegate_store {
    ($self:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            ConfiguredHeldActionStore::Memory(store) => store.$method($($arg),*),
            ConfiguredHeldActionStore::LocalFiles(store) => store.$method($($arg),*),
        }
    };
}

impl HeldActionStore for ConfiguredHeldActionStore {
    fn create(&self, hold: HeldAction) -> Result<(), HeldActionStoreError> {
        delegate_store!(self, create, hold)
    }
    fn get(&self, hold_id: &str) -> Result<Option<HeldAction>, HeldActionStoreError> {
        delegate_store!(self, get, hold_id)
    }
    fn list(&self, include_terminal: bool, limit: usize) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        delegate_store!(self, list, include_terminal, limit)
    }
    fn mark_case_channel(&self, hold_id: &str, case_channel: &str) -> Result<(), HeldActionStoreError> {
        delegate_store!(self, mark_case_channel, hold_id, case_channel)
    }
    fn mark_notified(&self, hold_id: &str, at_ms: i64, notice_event_id: &str, card_event_id: Option<&str>) -> Result<(), HeldActionStoreError> {
        delegate_store!(self, mark_notified, hold_id, at_ms, notice_event_id, card_event_id)
    }
    fn mark_armed(&self, hold_id: &str, at_ms: i64) -> Result<(), HeldActionStoreError> {
        delegate_store!(self, mark_armed, hold_id, at_ms)
    }
    fn begin_decision(&self, hold_id: &str, intent_event_id: &str, cas_instant_ms: i64) -> Result<HeldAction, HeldActionStoreError> {
        delegate_store!(self, begin_decision, hold_id, intent_event_id, cas_instant_ms)
    }
    fn abandon_decision(&self, hold_id: &str, intent_event_id: &str) -> Result<(), HeldActionStoreError> {
        delegate_store!(self, abandon_decision, hold_id, intent_event_id)
    }
    fn complete_decision(&self, hold_id: &str, decision: HoldDecisionRecord, state: HoldState) -> Result<(), HeldActionStoreError> {
        delegate_store!(self, complete_decision, hold_id, decision, state)
    }
    fn expire_due(&self, now_ms: i64) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        delegate_store!(self, expire_due, now_ms)
    }
    fn fail_stalled_decisions(&self, now_ms: i64, stall_ms: u64) -> Result<Vec<HeldAction>, HeldActionStoreError> {
        delegate_store!(self, fail_stalled_decisions, now_ms, stall_ms)
    }
    fn health(&self, now_ms: i64, stall_ms: u64) -> Result<HeldActionStoreHealth, HeldActionStoreError> {
        delegate_store!(self, health, now_ms, stall_ms)
    }
}
```

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-runtime held_action
```

Expected: 17 passed. Also run `bash tools/check-runtime-panic-contract.sh` (the crate is in its enumeration) — expected exit 0.

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-runtime
git commit -s -m "feat(swarm-runtime): add the file-backed hold store and restart recovery"
```

---

## Task 7: B1 event — `RuntimeEvent::ResponseHeld` and its scope arm

**Files:**
- Modify: `crates/swarm-runtime/src/runtime_events.rs` (`RuntimeEventKind` `:127-139`, `as_str` `:142-156`, `parse` `:158-173`, `RuntimeEvent` `:211-305`, `emitted_at_ms` `:308-322`, `kind` `:324-338`)
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs` (`runtime_event_matches_scope` `:698-770`, last arm `:766-768`)
- Modify: `crates/swarm-perch-bridge/src/stream.rs` (`classify`)
- Test: `crates/swarm-runtime/src/runtime_events.rs` `mod tests`; `crates/swarm-ingest-runtime/src/ingest/tests.rs`

**Interfaces:**
- Produces:
  ```rust
  RuntimeEvent::ResponseHeld {
      emitted_at_ms: i64,
      hold_id: String,
      hunt_id: String,          // for the daemon's own consumers; the bridge drops it from the 26006 frame
      action_kind: String,
      severity: Severity,
      expires_at_ms: i64,
      state: HoldState,
  }
  RuntimeEventKind::ResponseHeld  // "response_held"
  ```
  Seven fields and no more (12 §3.6). The arm in `runtime_event_matches_scope` returns `false`, grouped with `TamperAlert`.

- [ ] **Step 1: Write the failing tests.**

In `crates/swarm-runtime/src/runtime_events.rs`'s existing `mod tests`:

```rust
    #[test]
    fn response_held_round_trips_through_kind_parse_and_serde() {
        assert_eq!(RuntimeEventKind::parse("response_held"), Some(RuntimeEventKind::ResponseHeld));
        assert_eq!(RuntimeEventKind::ResponseHeld.as_str(), "response_held");
        let event = RuntimeEvent::ResponseHeld {
            emitted_at_ms: 1_773_739_200_000,
            hold_id: "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13".to_string(),
            hunt_id: "hunt-evt-1".to_string(),
            action_kind: "isolate_host".to_string(),
            severity: swarm_core::types::Severity::Critical,
            expires_at_ms: 1_773_742_800_000,
            state: crate::held_action::HoldState::Created,
        };
        assert_eq!(event.kind(), RuntimeEventKind::ResponseHeld);
        assert_eq!(event.emitted_at_ms(), 1_773_739_200_000);
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["event_type"], "response_held");
        assert_eq!(value["state"], "created");
        assert_eq!(value.as_object().unwrap().len(), 8, "seven fields plus the tag, and no more");
        let back: RuntimeEvent = serde_json::from_value(value).unwrap();
        assert_eq!(back.kind(), RuntimeEventKind::ResponseHeld);
    }
```

In `crates/swarm-ingest-runtime/src/ingest/tests.rs`, beside the existing scope tests (search for `runtime_event_matches_scope`):

```rust
#[test]
fn a_hold_alarm_never_matches_any_stream_scope_including_the_anonymous_empty_one() {
    let held = RuntimeEvent::ResponseHeld {
        emitted_at_ms: 1,
        hold_id: "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13".into(),
        hunt_id: "hunt-evt-1".into(),
        action_kind: "isolate_host".into(),
        severity: Severity::Critical,
        expires_at_ms: 2,
        state: swarm_runtime::held_action::HoldState::Created,
    };
    // The empty scope is what an anonymous reader gets until B5 lands; it
    // short-circuits `true` for every other variant.
    assert!(!super::runtime_event_matches_scope(&held, &ProvidenceContextScope::default()));
    let scoped = ProvidenceContextScope {
        hunt_id: Some("hunt-evt-1".into()),
        ..ProvidenceContextScope::default()
    };
    assert!(!super::runtime_event_matches_scope(&held, &scoped));
}
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-runtime runtime_events::tests::response_held
cargo test -p swarm-ingest-runtime a_hold_alarm_never_matches
```

Expected: `no variant named ResponseHeld`.

- [ ] **Step 3: Make the seven edits.**

`runtime_events.rs`:

```rust
// RuntimeEventKind: add after ModeTransition (and after CasePromoted if B1d ordered it there)
    ResponseHeld,

// as_str
            Self::ResponseHeld => "response_held",

// parse
            "response_held" => Some(Self::ResponseHeld),

// RuntimeEvent, after ModeTransition { .. }:
    /// A destructive action held for a human (bill item B1). Seven fields and
    /// no more: the bridge maps this onto the community-global `26006` frame
    /// and drops `hunt_id`, which is a join key into detection data.
    ResponseHeld {
        emitted_at_ms: i64,
        hold_id: String,
        hunt_id: String,
        action_kind: String,
        severity: Severity,
        expires_at_ms: i64,
        state: crate::held_action::HoldState,
    },

// emitted_at_ms
            | Self::ResponseHeld { emitted_at_ms, .. }

// kind
            Self::ResponseHeld { .. } => RuntimeEventKind::ResponseHeld,
```

with `use swarm_core::types::Severity;` added to the file's imports. In `ingest/mod.rs`, extend the last arm of `runtime_event_matches_scope`:

```rust
        RuntimeEvent::EvolutionStatus { .. }
        | RuntimeEvent::AgentHealth { .. }
        | RuntimeEvent::TamperAlert { .. }
        // B1. Grouped with TamperAlert deliberately: a hold names a destructive
        // action pending against a named host. Until B5 makes the token
        // mandatory an empty scope is an ANONYMOUS reader, and the
        // short-circuit at the top of this function would hand it every hold.
        | RuntimeEvent::ResponseHeld { .. } => false,
```

and move the `scope.is_empty()` short-circuit **below** a first `match` on `ResponseHeld` (and `CasePromoted`, which B1d already returns `false` for) so the empty-scope path cannot reach the short-circuit for those two variants:

```rust
fn runtime_event_matches_scope(event: &RuntimeEvent, scope: &ProvidenceContextScope) -> bool {
    // These two never reach the stream, scoped or not. Checked BEFORE the
    // empty-scope short-circuit on purpose.
    if matches!(event, RuntimeEvent::ResponseHeld { .. } | RuntimeEvent::CasePromoted { .. }) {
        return false;
    }
    if scope.is_empty() {
        return true;
    }
    match event {
        // … unchanged arms …
    }
}
```

In `crates/swarm-perch-bridge/src/stream.rs`, `classify` gains `RuntimeEvent::ResponseHeld { .. } => Stream::Alarm,`. (The crate's `classify_is_exhaustive` test fails to compile until this arm exists, which is the point.)

- [ ] **Step 4: Run the whole affected set.**

```bash
cargo test -p swarm-runtime runtime_events
cargo test -p swarm-ingest-runtime ingest::tests
cargo test -p swarm-perch-bridge classify
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all green; `runtime_event_matches_scope` is exhaustive with no `_` arm, so a missing arm anywhere else is a compile error, not a runtime surprise.

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-runtime crates/swarm-ingest-runtime crates/swarm-perch-bridge
git commit -s -m "feat(swarm-runtime): add RuntimeEvent::ResponseHeld and fence it from the event stream"
```

---

## Task 8: B1 intercept — `capture_hold` at the router, the store on `IngestState`, and the other door fenced

> Blocked on Task 1 (the dev profile is the only place a hold can be produced).

**Files:**
- Create: `crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs`
- Modify: `crates/swarm-ingest-runtime/src/ingest/perch_ops/mod.rs` (`pub mod holds;`)
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs` (`IngestRuntimeRequestResponseRouter` `:117-150`; `IngestState` `:1352-1380`; `from_config_with_signing_key` `:1403-…`; `current_request_response_router` `:1818`)
- Modify: `crates/swarm-runtime-http/src/bin/swarm_detect.rs` (build the store after the containment sweep block ending at `:1075`)
- Create: `tools/check-no-unrouted-authorize.sh`
- Modify: `.github/workflows/ci.yml` (a `run:` step beside `check-visibility-baseline.sh` at `:104`)
- Test: `crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs` `mod tests`; `crates/swarm-ingest-runtime/src/ingest/tests.rs`

**Interfaces:**
- Consumes: `AuditTrail { trail_id, policy: PolicyRecord { verdict, rule_name, reason }, response: AuditResponseRecord::Skipped { reason }, … }` (`crates/swarm-spine/src/lib.rs:105-122`), `SwarmService::rehearsal_preview` (`crates/swarm-runtime/src/service/runtime_service.rs:861-868`), `RuntimeEventBroadcaster::publish`.
- Produces:
  ```rust
  pub struct HoldCapture { store: Arc<dyn HeldActionStore>, events: Option<RuntimeEventBroadcaster>, settings: ResponseHoldSettings }
  impl HoldCapture {
      pub fn new(store, events, settings) -> Self;
      /// Runs AFTER audit_authorize_and_execute returns. Captures iff verdict == RequireHuman && response is Skipped.
      pub fn capture_hold(&self, request: &ActionRequest, detection: &DetectionFinding, audit: &AuditTrail, rehearsal: Option<ResponseRehearsalPreview>, now_ms: i64) -> Option<HeldAction>;
  }
  impl IngestState {
      pub fn with_hold_store(self, store: Arc<dyn HeldActionStore>) -> Self;
      pub fn current_hold_store(&self) -> Option<Arc<dyn HeldActionStore>>;
      pub fn current_hold_settings(&self) -> ResponseHoldSettings;
  }
  ```

- [ ] **Step 1: Write the failing four-producer test.**

`crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs` (tests at the bottom; the module body is Step 3):

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, PolicyVerdict};
    use swarm_runtime::held_action::{HoldState, MemoryHeldActionStore};
    use swarm_runtime::runtime_events::RuntimeEventBroadcaster;
    use swarm_spine::{AuditResponseRecord, AuditTrail, PolicyRecord};

    const T0: i64 = 1_773_739_200_000;

    fn request() -> ActionRequest {
        ActionRequest {
            hunt_id: HuntId("hunt-evt-1".into()),
            requested_by: AgentId::from_public_key_hex(&"18".repeat(32)),
            action: ResponseAction::IsolateHost { host_id: "host-ops-1".into() },
            severity: Severity::Critical,
            evidence: serde_json::json!({ "escalation": { "threat_class": "execution" } }),
        }
    }

    fn trail(verdict: PolicyVerdict, response: AuditResponseRecord) -> AuditTrail {
        let request = request();
        AuditTrail {
            trail_id: "trail-1".into(),
            hunt_id: request.hunt_id.0.clone(),
            related_receipt_ids: vec![],
            detection: crate::ingest::routed_detection_from_request(&request),
            policy: PolicyRecord {
                verdict,
                rule_name: "static.human_gate".into(),
                reason: "authorized but held for human approval".into(),
            },
            response,
            created_at_ms: T0,
        }
    }

    fn capture() -> (HoldCapture, Arc<MemoryHeldActionStore>, tokio::sync::broadcast::Receiver<RuntimeEvent>) {
        let store = Arc::new(MemoryHeldActionStore::default());
        let events = RuntimeEventBroadcaster::new(16);
        let rx = events.subscribe();
        let capture = HoldCapture::new(
            store.clone(),
            Some(events),
            swarm_core::config::ResponseHoldSettings::default(),
        );
        (capture, store, rx)
    }

    #[test]
    fn exactly_one_of_the_four_skipped_producers_becomes_a_hold() {
        let skipped = || AuditResponseRecord::Skipped { reason: "r".into() };
        let cases = [
            ("deny", trail(PolicyVerdict::Deny, skipped()), false),
            ("require_human", trail(PolicyVerdict::RequireHuman, skipped()), true),
            (
                "containment_refused",
                trail(PolicyVerdict::Allow, AuditResponseRecord::Skipped { reason: "no containment lease store is configured".into() }),
                false,
            ),
            (
                "guard",
                trail(PolicyVerdict::Allow, AuditResponseRecord::GuardRejected { guard_name: "g".into(), reason: "r".into() }),
                false,
            ),
        ];
        for (label, audit, expect_hold) in cases {
            let (capture, store, mut rx) = capture();
            let request = request();
            let detection = crate::ingest::routed_detection_from_request(&request);
            let captured = capture.capture_hold(&request, &detection, &audit, None, T0);
            assert_eq!(captured.is_some(), expect_hold, "{label}");
            assert_eq!(store.list(true, 10).unwrap().len(), usize::from(expect_hold), "{label}");
            if expect_hold {
                let hold = captured.unwrap();
                assert_eq!(hold.state, HoldState::Created);
                assert_eq!(hold.expires_at_ms, T0 + 3_600_000);
                assert_eq!(hold.audit_trail_id.as_deref(), Some("trail-1"));
                assert_eq!(hold.rationale.threat_class, swarm_core::pheromone::ThreatClass::Execution);
                match rx.try_recv().unwrap() {
                    RuntimeEvent::ResponseHeld { hold_id, state, action_kind, .. } => {
                        assert_eq!(hold_id, hold.hold_id);
                        assert_eq!(state, HoldState::Created);
                        assert_eq!(action_kind, "isolate_host");
                    }
                    other => panic!("expected ResponseHeld, got {other:?}"),
                }
            } else {
                assert!(rx.try_recv().is_err(), "{label} published an event");
            }
        }
    }

    #[test]
    fn the_ttl_honours_the_threat_class_override() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut settings = swarm_core::config::ResponseHoldSettings::default();
        settings.hold_ttl_ms_by_threat_class.insert("execution".into(), 900_000);
        let capture = HoldCapture::new(store, None, settings);
        let request = request();
        let detection = crate::ingest::routed_detection_from_request(&request);
        let audit = trail(PolicyVerdict::RequireHuman, AuditResponseRecord::Skipped { reason: "r".into() });
        let hold = capture.capture_hold(&request, &detection, &audit, None, T0).unwrap();
        assert_eq!(hold.expires_at_ms, T0 + 900_000);
    }
}
```

`routed_detection_from_request` is private today (`ingest/mod.rs:1008`); make it `pub(crate)`.

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-ingest-runtime perch_ops::holds
```

Expected: `cannot find type HoldCapture`.

- [ ] **Step 3: Implement `HoldCapture` and wire the router.**

Top of `perch_ops/holds.rs`:

```rust
//! B1's interception point, and (Tasks 10 and 13) the hold reads and the decide engine.
//!
//! Owns: turning a `RequireHuman` audit trail into a durable `HeldAction`, and
//! publishing `RuntimeEvent::ResponseHeld`.
//!
//! Does not own: the store (`swarm_runtime::held_action`), the routes
//! (`swarm_runtime_http::http::perch::holds`), or any authorization decision.

use std::sync::Arc;

use swarm_core::config::ResponseHoldSettings;
use swarm_core::pheromone::threat_class_slug;
use swarm_core::types::ResponseRehearsalPreview;
use swarm_policy::{ActionRequest, PolicyDecision, PolicyVerdict};
use swarm_runtime::held_action::{HeldAction, HeldActionStore, HoldState, mint_hold_id};
use swarm_runtime::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster};
use swarm_spine::{AuditResponseRecord, AuditTrail};
use swarm_whisker::DetectionFinding;

/// Everything `route_request` needs to make a hold durable after the runtime
/// has returned its `Skipped` trail.
#[derive(Clone)]
pub struct HoldCapture {
    store: Arc<dyn HeldActionStore>,
    events: Option<RuntimeEventBroadcaster>,
    settings: ResponseHoldSettings,
}

impl HoldCapture {
    /// Bundle the daemon's one store, its broadcaster and the hold settings.
    pub fn new(
        store: Arc<dyn HeldActionStore>,
        events: Option<RuntimeEventBroadcaster>,
        settings: ResponseHoldSettings,
    ) -> Self {
        Self { store, events, settings }
    }

    /// The store handle, for the reads and the decide engine.
    pub fn store(&self) -> &Arc<dyn HeldActionStore> {
        &self.store
    }

    /// The configured settings.
    pub fn settings(&self) -> &ResponseHoldSettings {
        &self.settings
    }

    /// Capture iff BOTH clauses hold: `verdict == RequireHuman` AND
    /// `response == Skipped`. `Skipped` alone has four producers (Deny,
    /// RequireHuman-in-live, containment-refused, the guard path) and matching
    /// it alone would turn denied actions into holds an operator could grant.
    pub fn capture_hold(
        &self,
        request: &ActionRequest,
        detection: &DetectionFinding,
        audit: &AuditTrail,
        rehearsal: Option<ResponseRehearsalPreview>,
        now_ms: i64,
    ) -> Option<HeldAction> {
        if !matches!(audit.policy.verdict, PolicyVerdict::RequireHuman)
            || !matches!(audit.response, AuditResponseRecord::Skipped { .. })
        {
            return None;
        }
        let decision = PolicyDecision {
            verdict: audit.policy.verdict,
            rule_name: audit.policy.rule_name.clone(),
            reason: audit.policy.reason.clone(),
        };
        let slug = request
            .evidence
            .get("escalation")
            .and_then(|value| value.get("threat_class"))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .map(|class| threat_class_slug(&class))
            .unwrap_or_else(|| "execution".to_string());
        let ttl_ms = self.settings.hold_ttl_ms_for(&slug) as i64;
        let hold = HeldAction::new(
            mint_hold_id(),
            request.clone(),
            detection.clone(),
            decision,
            rehearsal,
            now_ms,
            now_ms.saturating_add(ttl_ms),
            Some(audit.trail_id.clone()),
        );
        if let Err(error) = self.store.create(hold.clone()) {
            tracing::error!(
                module = module_path!(),
                hold_id = %hold.hold_id,
                reason = %error,
                "hold could not be stored; the action was NOT taken and is NOT queued"
            );
            return None;
        }
        self.publish_state(&hold, HoldState::Created, now_ms);
        Some(hold)
    }

    /// One `ResponseHeld` per state change. Called by capture and by the sweep.
    pub fn publish_state(&self, hold: &HeldAction, state: HoldState, now_ms: i64) {
        if let Some(events) = &self.events {
            events.publish(RuntimeEvent::ResponseHeld {
                emitted_at_ms: now_ms,
                hold_id: hold.hold_id.clone(),
                hunt_id: hold.action_request.hunt_id.0.clone(),
                action_kind: hold.action_request.action.kind().to_string(),
                severity: hold.action_request.severity,
                expires_at_ms: hold.expires_at_ms,
                state,
            });
        }
    }
}
```

(`threat_class_slug` exists in `swarm-core`'s pheromone module or `swarm-runtime`'s escalation module; use whichever is `pub` — `grep -rn 'pub fn threat_class_slug' crates/` — and import from there.)

In `ingest/mod.rs`, give the router the capture:

```rust
struct IngestRuntimeRequestResponseRouter {
    runtime: Arc<ArcSwap<IngestRequestRuntime>>,
    hold_capture: Option<Arc<perch_ops::holds::HoldCapture>>,
    stack: Arc<ArcSwap<IngestRuntimeStack>>,
}

#[async_trait]
impl RequestResponseRouter for IngestRuntimeRequestResponseRouter {
    async fn route_request(
        &self,
        request: ActionRequest,
    ) -> Result<swarm_spine::AuditTrail, RuntimeError> {
        let runtime = self.runtime.load_full();
        let context = approval_context_now(runtime.mode() == RuntimeMode::LiveResponse);
        let detection = routed_detection_from_request(&request);
        let audit = runtime
            .audit_authorize_and_execute(&detection, &request, &context)
            .await?;
        // B1. Post-hoc on the returned trail, the same pattern
        // `process_demo_replay_step` uses (`:1272-1278`). Both match clauses are
        // inside `capture_hold`.
        if let Some(capture) = &self.hold_capture {
            let rehearsal = self
                .stack
                .load_full()
                .service
                .rehearsal_preview(&request, &format!("hold:{}", request.hunt_id.0), context.now_ms)
                .ok();
            capture.capture_hold(&request, &detection, &audit, rehearsal, context.now_ms);
        }
        Ok(audit)
    }
    // route_governance_veto unchanged
}
```

Add to `IngestState`: field `hold_capture: Option<Arc<perch_ops::holds::HoldCapture>>` (initialised `None` in `from_config_with_signing_key`), and:

```rust
    /// Attach the daemon's one hold store (B1). Called once by `swarm_detect`
    /// after the store is built from `runtime.response`, before the router is
    /// handed to the dispatcher.
    pub fn with_hold_store(mut self, store: Arc<dyn HeldActionStore>) -> Self {
        let settings = self.current_hold_settings();
        self.hold_capture = Some(Arc::new(perch_ops::holds::HoldCapture::new(
            store,
            self.runtime_events.clone(),
            settings,
        )));
        self
    }

    /// The hold store, if one was attached.
    pub fn current_hold_store(&self) -> Option<Arc<dyn HeldActionStore>> {
        self.hold_capture.as_ref().map(|capture| Arc::clone(capture.store()))
    }

    /// The hold capture bundle, for the sweep and the decide engine.
    pub fn current_hold_capture(&self) -> Option<Arc<perch_ops::holds::HoldCapture>> {
        self.hold_capture.clone()
    }

    /// `runtime.response` from the current config.
    pub fn current_hold_settings(&self) -> ResponseHoldSettings {
        self.stack.load_full().service.config.runtime.response.clone()
    }
```

and make `current_request_response_router` (`:1818`) construct the router with `hold_capture: self.hold_capture.clone()` and `stack: Arc::clone(&self.stack)`. Because `with_hold_store` must run **before** `with_runtime_events`'s consumers read the router, order the builder calls in `swarm_detect` as: `with_runtime_events(...)` (`:752`) → `with_hold_store(...)` → the dispatcher wiring. Concretely, in `crates/swarm-runtime-http/src/bin/swarm_detect.rs` immediately before the containment-sweep block (`:1020`):

```rust
        // B1. The daemon's ONE hold store, built from `runtime.response` the way
        // the containment store is built from `runtime.containment`. A relative
        // path resolves against the config file's directory.
        let hold_settings = state.current_hold_settings();
        let hold_store: Arc<dyn swarm_runtime::held_action::HeldActionStore> = Arc::new(
            swarm_runtime::held_action::ConfiguredHeldActionStore::from_settings(
                &hold_settings,
                config_dir,
            )?,
        );
        if hold_settings.hold_store_path.is_none() {
            tracing::warn!(
                module = module_path!(),
                "runtime.response.hold_store_path is unset; holds are in memory and a restart forgets every open hold"
            );
        }
        let state = state.with_hold_store(Arc::clone(&hold_store));
```

`config_dir` is the directory `:188` derives from `config_path`; if the binding at `:1020` is a different name, use that name. `with_hold_store` returns a new `IngestState`; every later `state.clone()` (the sweep, `serve_state` at `:1101`) therefore sees the store. The dispatcher receives its router through `state.current_request_response_router()`; verify with `grep -n current_request_response_router crates/swarm-runtime-http/src/bin/swarm_detect.rs` that the call sits after this insertion, and move the insertion up if it does not.

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-ingest-runtime perch_ops::holds
cargo test -p swarm-ingest-runtime
cargo build --bin swarm_detect
```

Expected: the two new tests pass; the crate's suite is unchanged; the binary builds.

- [ ] **Step 5: Write the failing gate fixture for the other door (C4).**

`tools/check-no-unrouted-authorize.sh`:

```bash
#!/usr/bin/env bash
#
# B1 commitment C4. `SwarmRuntime::authorize_and_execute`
# (crates/swarm-runtime/src/lib.rs, the non-audit variant) returns
# `ApprovalError::Denied` on RequireHuman instead of an AuditTrail, so a
# RequireHuman reaching it is NOT captured as a hold. It has no production
# caller today. This gate keeps it that way: the first caller must move the
# interception in-runtime (12-BACKEND-BILL-API.md §3.5 option (a)).
#
# Shape: check-visibility-baseline.sh's. An allowlist of KNOWN call sites,
# and a STALE entry also fails, so the list cannot rot into a no-op.
set -euo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Known non-test call sites, as `<path>:<count>`. Today: none.
ALLOWLIST=()

# --- self-test on a fixture, so an empty scan cannot pass vacuously ---------
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/crates/x/src"
printf 'fn a() { runtime.authorize_and_execute(&r, &c).await }\n' > "$fixture/crates/x/src/lib.rs"
if ! grep -rn --include='*.rs' -E '\.authorize_and_execute\(' "$fixture/crates" >/dev/null; then
  echo "check-no-unrouted-authorize: FIXTURE FAILED — the needle does not match a planted call" >&2
  exit 2
fi

# --- the real scan ----------------------------------------------------------
# Exclude test modules and files: `#[cfg(test)]` bodies are approximated by
# excluding files whose path contains `tests` and lines after a `mod tests`
# marker in lib.rs is handled by the allowlist form below.
mapfile -t hits < <(grep -rn --include='*.rs' -E '\.authorize_and_execute\(' crates \
  | grep -v -E '(/tests?/|_tests\.rs|/tests\.rs)' \
  | grep -v -E 'audit_authorize_and_execute' \
  | grep -v -E 'crates/swarm-runtime/src/lib\.rs:[0-9]+:\s*pub async fn authorize_and_execute' || true)

# lib.rs's own `#[cfg(test)] mod tests` calls the function; those lines sit after the marker.
test_start="$(grep -n '^#\[cfg(test)\]' crates/swarm-runtime/src/lib.rs | head -1 | cut -d: -f1 || true)"
filtered=()
for hit in "${hits[@]:-}"; do
  [ -n "$hit" ] || continue
  file="${hit%%:*}"; rest="${hit#*:}"; line="${rest%%:*}"
  if [ "$file" = "crates/swarm-runtime/src/lib.rs" ] && [ -n "$test_start" ] && [ "$line" -ge "$test_start" ]; then
    continue
  fi
  filtered+=("$hit")
done

status=0
for hit in "${filtered[@]:-}"; do
  [ -n "$hit" ] || continue
  echo "check-no-unrouted-authorize: UNROUTED CALLER: $hit" >&2
  echo "  A RequireHuman reaching authorize_and_execute is refused, not held. Route through" >&2
  echo "  IngestRuntimeRequestResponseRouter::route_request, or move the intercept in-runtime." >&2
  status=1
done
for entry in "${ALLOWLIST[@]:-}"; do
  [ -n "$entry" ] || continue
  path="${entry%%:*}"
  if ! printf '%s\n' "${filtered[@]:-}" | grep -q "^${path}:"; then
    echo "check-no-unrouted-authorize: STALE ALLOWLIST ENTRY: $entry (no such caller any more)" >&2
    status=1
  fi
done
if [ "$status" -eq 0 ]; then
  echo "check-no-unrouted-authorize: clean (0 non-test callers of authorize_and_execute)"
fi
exit "$status"
```

`chmod +x tools/check-no-unrouted-authorize.sh`. Then add to `.github/workflows/ci.yml`, immediately after the `Check visibility baseline` step at `:103-104`:

```yaml
      # B1 commitment C4: `authorize_and_execute` has no non-test caller, so a
      # RequireHuman can only reach the runtime through the routed path that
      # captures it as a hold.
      - name: Check no unrouted authorize_and_execute caller
        run: bash tools/check-no-unrouted-authorize.sh
```

- [ ] **Step 6: Run the gates.**

```bash
bash tools/check-no-unrouted-authorize.sh
bash tools/check-gates-wired.sh
```

Expected: `clean (0 non-test callers …)`, and `check-gates-wired.sh` exits 0 (the new script is named by a real `run:` step in the same commit).

- [ ] **Step 7: Commit.**

```bash
git add crates/swarm-ingest-runtime crates/swarm-runtime-http tools/check-no-unrouted-authorize.sh .github/workflows/ci.yml
git commit -s -m "feat(swarm-ingest-runtime): capture RequireHuman as a durable hold at the router"
```

---

## Task 9: B1 sweep — `HoldSweep` expires holds and resolves stalled decisions on a running daemon

> Blocked on Task 1.

**Files:**
- Create: `crates/swarm-runtime/src/hold_sweep.rs`
- Modify: `crates/swarm-runtime/src/lib.rs` (`pub mod hold_sweep;` after `pub mod held_action;`)
- Modify: `crates/swarm-runtime-http/src/bin/swarm_detect.rs` (spawn beside the containment sweep, `:1061-1075`)
- Test: `crates/swarm-runtime/src/hold_sweep.rs` `mod tests`

**Interfaces:**
- Consumes: `HeldActionStore::{expire_due, fail_stalled_decisions}`, `RuntimeEventBroadcaster`, `tokio::sync::watch::Receiver<bool>`, `tokio::time::MissedTickBehavior::Skip` (the containment sweep's shape at `crates/swarm-runtime/src/containment.rs:621-640`).
- Produces:
  ```rust
  pub struct HoldSweep { store: Arc<dyn HeldActionStore>, events: Option<RuntimeEventBroadcaster>, decide_stall_ms: u64 }
  pub struct HoldSweepReport { pub expired: Vec<String>, pub stalled: Vec<String>, pub failures: Vec<String> }
  impl HoldSweep {
      pub fn new(store, events, decide_stall_ms) -> Self;
      pub fn tick(&self, now_ms: i64) -> HoldSweepReport;   // expire_due then fail_stalled_decisions; one ResponseHeld per row
      pub async fn run_until_shutdown(&self, interval_ms: u64, shutdown: watch::Receiver<bool>);
  }
  ```

- [ ] **Step 1: Write the failing tests.**

`crates/swarm-runtime/src/hold_sweep.rs` tests (module body in Step 3):

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::held_action::{HoldState, MemoryHeldActionStore};
    use crate::held_action::tests::{fixture_hold, T0};
    use crate::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster};
    use swarm_core::types::ResponseAction;

    fn sweep_with(state: HoldState) -> (HoldSweep, Arc<MemoryHeldActionStore>, tokio::sync::broadcast::Receiver<RuntimeEvent>, String) {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut hold = fixture_hold(ResponseAction::IsolateHost { host_id: "h".into() }, T0);
        hold.state = state;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        if state == HoldState::Deciding {
            // Put it into deciding through the real CAS so cas_instant_ms is set.
            let mut reset = store.get(&id).unwrap().unwrap();
            reset.state = HoldState::Notified;
            store.complete_decision(&id, reset.decision.clone().unwrap_or_else(|| unreachable!()), HoldState::Notified).ok();
        }
        let events = RuntimeEventBroadcaster::new(16);
        let rx = events.subscribe();
        (HoldSweep::new(store.clone(), Some(events), 60_000), store, rx, id)
    }

    #[test]
    fn a_hold_is_expired_at_its_ttl_not_before_and_the_record_is_published() {
        let (sweep, store, mut rx, id) = sweep_with(HoldState::Notified);
        assert!(sweep.tick(T0 + 3_600_000 - 1).expired.is_empty());
        assert_eq!(store.get(&id).unwrap().unwrap().state, HoldState::Notified);
        let report = sweep.tick(T0 + 3_600_000);
        assert_eq!(report.expired, vec![id.clone()]);
        let hold = store.get(&id).unwrap().unwrap();
        assert_eq!(hold.state, HoldState::Expired);
        assert!(hold.decision.is_none(), "expiry takes no action and writes no decision");
        match rx.try_recv().unwrap() {
            RuntimeEvent::ResponseHeld { state, hold_id, .. } => {
                assert_eq!(state, HoldState::Expired);
                assert_eq!(hold_id, id);
            }
            other => panic!("{other:?}"),
        }
        // Still listed, so /handoff can count it (INV-19).
        assert_eq!(store.list(true, 10).unwrap().len(), 1);
        assert!(store.list(false, 10).unwrap().is_empty());
    }

    #[test]
    fn the_sweep_resolves_a_stalled_decision_without_a_restart() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let hold = fixture_hold(ResponseAction::IsolateHost { host_id: "h".into() }, T0);
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        store.begin_decision(&id, &"aa".repeat(32), T0 + 100).unwrap();
        let events = RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let sweep = HoldSweep::new(store.clone(), Some(events), 60_000);

        assert!(sweep.tick(T0 + 100 + 59_999).stalled.is_empty());
        let report = sweep.tick(T0 + 100 + 60_000);
        assert_eq!(report.stalled, vec![id.clone()]);
        let hold = store.get(&id).unwrap().unwrap();
        assert_eq!(hold.state, HoldState::Failed);
        assert!(hold.decision.unwrap().refusal.unwrap().reason.contains("whether the action ran is unknown"));
        match rx.try_recv().unwrap() {
            RuntimeEvent::ResponseHeld { state, .. } => assert_eq!(state, HoldState::Failed),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn run_until_shutdown_stops_on_the_watch_flag() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let sweep = HoldSweep::new(store, None, 60_000);
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(async move { sweep.run_until_shutdown(1, rx).await });
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), handle).await.unwrap().unwrap();
    }
}
```

Make `held_action_tests.rs`'s `fixture_hold` and `T0` `pub(crate)` (they already are `pub(super)`; change to `pub(crate)`) and add `pub(crate) mod tests;` visibility on the `#[path]` module in `held_action.rs` so `hold_sweep` can reuse them.

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-runtime hold_sweep
```

Expected: `file not found for module hold_sweep`.

- [ ] **Step 3: Implement the sweep.**

`crates/swarm-runtime/src/hold_sweep.rs`:

```rust
//! Expire holds past their TTL and resolve stalled decisions, on a running
//! daemon — not only after a restart. Same loop shape as `ContainmentSweep`.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::held_action::{HeldAction, HeldActionStore, HoldState};
use crate::runtime_events::{RuntimeEvent, RuntimeEventBroadcaster, now_ms};

/// One tick's outcome.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HoldSweepReport {
    /// Holds moved `created|notified|armed -> expired`. No action was taken.
    pub expired: Vec<String>,
    /// Holds moved `deciding -> failed` with the unknown-outcome refusal.
    pub stalled: Vec<String>,
    /// Store errors, one string each. The sweep never panics.
    pub failures: Vec<String>,
}

/// The sweep. Reads the clock once per tick.
pub struct HoldSweep {
    store: Arc<dyn HeldActionStore>,
    events: Option<RuntimeEventBroadcaster>,
    decide_stall_ms: u64,
}

impl HoldSweep {
    /// Bundle the daemon's one store and broadcaster with `runtime.response.decide_stall_ms`.
    pub fn new(
        store: Arc<dyn HeldActionStore>,
        events: Option<RuntimeEventBroadcaster>,
        decide_stall_ms: u64,
    ) -> Self {
        Self { store, events, decide_stall_ms }
    }

    fn publish(&self, hold: &HeldAction, state: HoldState, at_ms: i64) {
        if let Some(events) = &self.events {
            events.publish(RuntimeEvent::ResponseHeld {
                emitted_at_ms: at_ms,
                hold_id: hold.hold_id.clone(),
                hunt_id: hold.action_request.hunt_id.0.clone(),
                action_kind: hold.action_request.action.kind().to_string(),
                severity: hold.action_request.severity,
                expires_at_ms: hold.expires_at_ms,
                state,
            });
        }
    }

    /// Expiry first, then stall resolution. Every row either method returns
    /// is published as its own `ResponseHeld`, so the bridge can publish the
    /// terminal card without polling.
    pub fn tick(&self, now_ms: i64) -> HoldSweepReport {
        let mut report = HoldSweepReport::default();
        match self.store.expire_due(now_ms) {
            Ok(expired) => {
                for hold in expired {
                    self.publish(&hold, HoldState::Expired, now_ms);
                    report.expired.push(hold.hold_id);
                }
            }
            Err(error) => report.failures.push(format!("expire_due: {error}")),
        }
        match self.store.fail_stalled_decisions(now_ms, self.decide_stall_ms) {
            Ok(stalled) => {
                for hold in stalled {
                    tracing::error!(
                        module = module_path!(),
                        hold_id = %hold.hold_id,
                        "decision stalled past decide_stall_ms; resolved to failed with an unknown outcome"
                    );
                    self.publish(&hold, HoldState::Failed, now_ms);
                    report.stalled.push(hold.hold_id);
                }
            }
            Err(error) => report.failures.push(format!("fail_stalled_decisions: {error}")),
        }
        report
    }

    /// Tick every `interval_ms` until the shutdown flag flips. Missed ticks
    /// are skipped, never bursted.
    pub async fn run_until_shutdown(&self, interval_ms: u64, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms.max(1)));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    if *shutdown.borrow() {
                        break;
                    }
                    let report = self.tick(now_ms());
                    if !report.expired.is_empty() || !report.stalled.is_empty() || !report.failures.is_empty() {
                        tracing::info!(
                            module = module_path!(),
                            expired = report.expired.len(),
                            stalled = report.stalled.len(),
                            failures = report.failures.len(),
                            "hold sweep tick"
                        );
                    }
                }
            }
        }
    }
}
```

In `swarm_detect.rs`, after the containment-sweep spawn (`:1075`):

```rust
        let mut hold_sweep_handle = Some({
            let sweep = swarm_runtime::hold_sweep::HoldSweep::new(
                Arc::clone(&hold_store),
                Some(runtime_events.clone()),
                hold_settings.decide_stall_ms,
            );
            let sweep_shutdown = shutdown_rx.clone();
            let interval_ms = hold_settings.sweep_interval_ms;
            tracing::info!(
                module = module_path!(),
                interval_ms,
                hold_ttl_ms = hold_settings.hold_ttl_ms,
                decide_stall_ms = hold_settings.decide_stall_ms,
                "hold sweep started"
            );
            tokio::spawn(async move { sweep.run_until_shutdown(interval_ms, sweep_shutdown).await })
        });
```

and add `await_background_task("hold_sweep", hold_sweep_handle.take())` to the shutdown arms the same way `containment_sweep_handle` is awaited (search `containment_sweep_handle` in the file; mirror each site). `runtime_events` is the broadcaster bound at `:726`; if it was moved into a builder before this point, clone it at `:726` first.

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-runtime hold_sweep
cargo build --bin swarm_detect
```

Expected: 3 passed; builds.

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-runtime crates/swarm-runtime-http
git commit -s -m "feat(swarm-runtime): sweep expired holds and stalled decisions on a running daemon"
```

---

## Task 10: B2r — the two hold reads, the perch router, and the reconciliation authority

**Files:**
- Create: `crates/swarm-runtime-http/src/http/perch/holds.rs`
- Modify: `crates/swarm-runtime-http/src/http/perch/mod.rs` (First card's router; the three hold routes join it)
- Modify: `crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs` (`list_holds`, `get_hold`, `HoldReadError`)
- Modify: `crates/swarm-runtime-http/src/bin/swarm_detect.rs` (the boot `warn!` for Approve-without-Read)
- Test: `crates/swarm-runtime-http/src/http/perch/holds.rs` `mod tests`

**Interfaces:**
- Consumes: `require_bearer_auth`, `require_operator_api_scope` (`http/auth.rs:154-166`), `OperatorApiError` (`http/error.rs:16-100`), `CURRENT_OPERATOR_API_SCHEMA_VERSION`, `ContainmentLeaseView`'s two-fact shape (`http/containment.rs:72-88`), `resolve_inverse` (`crates/swarm-response/src/rollback.rs:151-192`).
- Produces (all `Serialize`, mirroring `build/openapi/perch-operator-v1.yaml` `HeldActionView`/`HoldListResponse`/`HoldDetailResponse` plus the three record additions):
  ```rust
  pub struct InverseResolution { pub step_kind: String, pub verdict: InverseVerdict, pub reason: Option<String> }
  pub enum InverseVerdict { Executable, Irreversible, Unmapped }
  pub struct HeldActionView { hold_id, state, notified_at_ms, deciding_intent_event_id, case_channel, notice_event_id, card_event_id, action_kind, severity, held_at_ms, expires_at_ms, remaining_ms, expired, action_request, policy_decision, rationale, leases_a_containment, rehearsal, inverse_resolution: Vec<InverseResolution>, decision }
  pub struct HoldListResponse { schema_version, observed_at_ms, holds: Vec<HeldActionView>, open_count, truncated, deciding_stalled_count, store_durable }
  pub struct HoldDetailResponse { schema_version, observed_at_ms, hold: HeldActionView }
  pub struct HoldListQuery { now_ms: Option<i64>, include_terminal: Option<bool>, limit: Option<usize> }
  // perch_ops::holds
  pub fn list_holds(state: &IngestState, include_terminal: bool, limit: usize, now_ms: i64) -> Result<HoldListing, HoldReadError>
  pub fn get_hold(state: &IngestState, hold_id: &str, now_ms: i64) -> Result<Option<HeldAction>, HoldReadError>
  pub struct HoldListing { pub holds: Vec<HeldAction>, pub open_count: usize, pub truncated: bool, pub health: HeldActionStoreHealth }
  pub enum HoldReadError { NoHoldStore, Store(HeldActionStoreError) }
  pub const PERCH_ROUTER_PATHS: [&str; 5] // three First-card paths plus the two reads; Task 13 makes six
  ```
  `GET /v1/response/holds` sorts `(expires_at_ms, hold_id)` ascending; both routes check `OperatorScope::Read`; `now_ms` is a query parameter ("absent means now").

- [ ] **Step 1: Write the failing route tests.**

`crates/swarm-runtime-http/src/http/perch/holds.rs` tail:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use std::sync::Arc;
    use swarm_core::config::OperatorScope;
    use swarm_core::types::ResponseAction;
    use swarm_runtime::held_action::{HeldActionStore, HoldState, MemoryHeldActionStore};
    use tower::ServiceExt;

    const T0: i64 = 1_773_739_200_000;

    fn seeded_state(holds: &[(HoldState, i64, &str)]) -> (swarm_ingest_runtime::ingest::IngestState, Arc<MemoryHeldActionStore>) {
        let store = Arc::new(MemoryHeldActionStore::default());
        for (state, held_at, id) in holds {
            let mut hold = swarm_runtime::held_action::tests::fixture_hold(
                ResponseAction::IsolateHost { host_id: "host-ops-1".into() },
                *held_at,
            );
            hold.hold_id = (*id).to_string();
            hold.state = *state;
            store.create(hold).unwrap();
        }
        let state = crate::http::tests::perch_test_state().with_hold_store(store.clone());
        (state, store)
    }

    async fn get(app: axum::Router, uri: &str, token: &str) -> (StatusCode, Value) {
        let response = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() };
        (status, value)
    }

    fn app_with_scopes(
        state: swarm_ingest_runtime::ingest::IngestState,
        scopes: Vec<OperatorScope>,
        token: &str,
    ) -> axum::Router {
        let config = crate::http::tests::operator_config();
        let auth = crate::http::auth::OperatorAuthState::for_test(
            "perch-dev-operator",
            scopes,
            token,
        );
        crate::http::perch::perch_operator_router_for_test(&config, state, auth)
    }

    #[tokio::test]
    async fn the_list_is_sorted_by_expiry_then_id_and_carries_the_honesty_fields() {
        let (state, _store) = seeded_state(&[
            (HoldState::Notified, T0 + 5, "hold_zzzzzzzz-0000-4000-8000-000000000000"),
            (HoldState::Created, T0, "hold_aaaaaaaa-0000-4000-8000-000000000000"),
            (HoldState::Refused, T0, "hold_bbbbbbbb-0000-4000-8000-000000000000"),
        ]);
        let app = app_with_scopes(state, vec![OperatorScope::Read, OperatorScope::Approve], "secret-token");
        let (status, body) = get(app, &format!("/v1/response/holds?now_ms={}", T0 + 1), "secret-token").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["observed_at_ms"], T0 + 1);
        assert_eq!(body["store_durable"], false);
        assert_eq!(body["open_count"], 2);
        assert_eq!(body["deciding_stalled_count"], 0);
        let ids: Vec<&str> = body["holds"].as_array().unwrap().iter().map(|h| h["hold_id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["hold_aaaaaaaa-0000-4000-8000-000000000000", "hold_zzzzzzzz-0000-4000-8000-000000000000"]);
        assert_eq!(body["holds"][0]["remaining_ms"], 3_600_000 - 1);
        assert_eq!(body["holds"][0]["expired"], false);
        assert_eq!(body["holds"][0]["leases_a_containment"], true);
        assert_eq!(body["holds"][0]["case_channel"], Value::Null);
    }

    #[tokio::test]
    async fn detail_derives_two_clock_facts_and_the_inverse_resolution() {
        let (state, _store) = seeded_state(&[(HoldState::Notified, T0, "hold_aaaaaaaa-0000-4000-8000-000000000000")]);
        let app = app_with_scopes(state, vec![OperatorScope::Read, OperatorScope::Approve], "secret-token");
        let (status, body) = get(
            app,
            &format!("/v1/response/holds/hold_aaaaaaaa-0000-4000-8000-000000000000?now_ms={}", T0 + 3_600_000 + 1),
            "secret-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["hold"]["remaining_ms"], 0);
        assert_eq!(body["hold"]["expired"], true);
        // Derived, not served: the resolution names the function.
        assert!(body["hold"]["inverse_resolution"].is_array());
    }

    #[tokio::test]
    async fn reads_require_the_read_scope_and_an_unknown_id_is_404() {
        let (state, _store) = seeded_state(&[]);
        let app = app_with_scopes(state, vec![OperatorScope::Approve], "approve-only-token");
        let (status, body) = get(app.clone(), "/v1/response/holds", "approve-only-token").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "forbidden");
        let (state, _store) = seeded_state(&[]);
        let app = app_with_scopes(state, vec![OperatorScope::Read, OperatorScope::Approve], "secret-token");
        let (status, body) = get(app, "/v1/response/holds/hold_neverexisted-0000-4000-8000-000000000000", "secret-token").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");
    }

    #[tokio::test]
    async fn no_hold_store_is_503_never_an_empty_list() {
        let state = crate::http::tests::perch_test_state();
        let app = app_with_scopes(state, vec![OperatorScope::Read, OperatorScope::Approve], "secret-token");
        let (status, body) = get(app, "/v1/response/holds", "secret-token").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "internal_error");
        assert!(body["message"].as_str().unwrap().contains("hold store"));
    }

    #[test]
    fn perch_router_paths_are_disjoint_from_the_local_operator_surface() {
        let perch: std::collections::BTreeSet<&str> = crate::http::perch::PERCH_ROUTER_PATHS.into_iter().collect();
        let local: std::collections::BTreeSet<&str> = crate::http::state::LOCAL_OPERATOR_SURFACE_PATHS.into_iter().collect();
        assert!(!perch.is_empty() && !local.is_empty(), "empty path set: the collector is broken");
        let overlap: Vec<_> = perch.intersection(&local).collect();
        assert!(overlap.is_empty(), "same path on two ports: {overlap:?}");
        assert_eq!(perch.len(), 5);
    }
}
```

`crate::http::tests::perch_test_state()` is a `pub(crate)` helper in `http/tests.rs`; First card also makes the existing `operator_config()` visible to the `perch` test subtree. Every route test constructs its bearer through First card's test-only `OperatorAuthState::for_test` and `perch_operator_router_for_test`; it must not set process-global environment variables. `LOCAL_OPERATOR_SURFACE_PATHS` is a `pub(crate) const [&str; 49]` added to `http/state.rs` listing the 49 `.route(` paths verbatim; the router at `:294-…` is rewritten to iterate nothing — it keeps its literal `.route(` calls and a second test in `state.rs` asserts `LOCAL_OPERATOR_SURFACE_PATHS.len() == 49` and that every entry appears as a `.route("<path>"` literal in the file (`include_str!("state.rs")`), so the array cannot drift from the router.

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-runtime-http http::perch::holds
```

Expected: `cannot find function perch_operator_router` or missing `holds` module.

- [ ] **Step 3: Implement the reads.**

`perch_ops/holds.rs` additions:

```rust
use swarm_runtime::held_action::{HeldActionStoreError, HeldActionStoreHealth};

/// Why a hold read failed.
#[derive(Debug, thiserror::Error)]
pub enum HoldReadError {
    #[error("no hold store is attached to this daemon")]
    NoHoldStore,
    #[error(transparent)]
    Store(#[from] HeldActionStoreError),
}

/// A page of holds plus the facts the list response must carry.
pub struct HoldListing {
    pub holds: Vec<HeldAction>,
    pub open_count: usize,
    pub truncated: bool,
    pub health: HeldActionStoreHealth,
}

/// `GET /v1/response/holds`'s engine half. Sorted `(expires_at_ms, hold_id)`.
pub fn list_holds(
    state: &crate::ingest::IngestState,
    include_terminal: bool,
    limit: usize,
    now_ms: i64,
) -> Result<HoldListing, HoldReadError> {
    let capture = state.current_hold_capture().ok_or(HoldReadError::NoHoldStore)?;
    let store = capture.store();
    let all = store.list(include_terminal, usize::MAX)?;
    let open_count = all.iter().filter(|hold| hold.is_open()).count();
    let truncated = all.len() > limit;
    let mut holds = all;
    holds.truncate(limit);
    let health = store.health(now_ms, capture.settings().decide_stall_ms)?;
    Ok(HoldListing { holds, open_count, truncated, health })
}

/// `GET /v1/response/holds/{hold_id}`'s engine half.
pub fn get_hold(
    state: &crate::ingest::IngestState,
    hold_id: &str,
) -> Result<Option<HeldAction>, HoldReadError> {
    let capture = state.current_hold_capture().ok_or(HoldReadError::NoHoldStore)?;
    Ok(capture.store().get(hold_id)?)
}
```

`crates/swarm-runtime-http/src/http/perch/holds.rs`:

```rust
//! The three hold routes (B2r + B2). Owns the DTOs, the scope checks and the
//! status codes; does not own holding, deciding or reading (those are
//! `perch_ops::holds`).

use axum::Json;
use axum::extract::{Extension, Path as RoutePath, Query, State};
use serde::{Deserialize, Serialize};
use swarm_core::config::OperatorScope;
use swarm_core::types::{ResponseRehearsalPreview, Severity};
use swarm_ingest_runtime::control::CURRENT_OPERATOR_API_SCHEMA_VERSION;
use swarm_ingest_runtime::ingest::perch_ops::holds::{HoldReadError, get_hold, list_holds};
use swarm_policy::{ActionRequest, PolicyDecision};
use swarm_response::rollback::{InverseGap, resolve_inverse};
use swarm_runtime::held_action::{HeldAction, HoldDecisionRecord, HoldRationale, HoldState};

use super::PerchHttpState;
use crate::http::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use crate::http::error::OperatorApiError;
use crate::http::helpers::now_ms;

/// Per rollback step, what `resolve_inverse` said. DERIVED, not served.
#[derive(Debug, Clone, Serialize)]
pub struct InverseResolution {
    pub step_kind: String,
    pub verdict: InverseVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Render law 4: the console names the producing function.
    pub derived_by: &'static str,
}

/// `executable | irreversible | unmapped`.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InverseVerdict {
    Executable,
    Irreversible,
    Unmapped,
}

/// One hold as an operator reads it. `remaining_ms` and `expired` are TWO
/// facts, for the reason `ContainmentLeaseView` carries both.
#[derive(Debug, Clone, Serialize)]
pub struct HeldActionView {
    pub hold_id: String,
    pub state: HoldState,
    pub notified_at_ms: Option<i64>,
    pub deciding_intent_event_id: Option<String>,
    pub case_channel: Option<String>,
    pub notice_event_id: Option<String>,
    pub card_event_id: Option<String>,
    pub action_kind: String,
    pub severity: Severity,
    pub held_at_ms: i64,
    pub expires_at_ms: i64,
    /// Saturates at zero.
    pub remaining_ms: i64,
    pub expired: bool,
    pub action_request: ActionRequest,
    pub policy_decision: PolicyDecision,
    pub rationale: HoldRationale,
    pub leases_a_containment: bool,
    pub rehearsal: Option<ResponseRehearsalPreview>,
    pub inverse_resolution: Vec<InverseResolution>,
    pub decision: Option<HoldDecisionRecord>,
}

impl HeldActionView {
    /// Build the view against a stated instant.
    pub fn from_hold(hold: HeldAction, observed_at_ms: i64) -> Self {
        let remaining_ms = (hold.expires_at_ms - observed_at_ms).max(0);
        let expired = hold.state == HoldState::Expired || observed_at_ms >= hold.expires_at_ms;
        let inverse_resolution = hold
            .rehearsal
            .as_ref()
            .map(|preview| {
                preview
                    .rollback
                    .steps
                    .iter()
                    .map(|step| match resolve_inverse(&hold.action_request.action, step) {
                        Ok(_) => InverseResolution {
                            step_kind: format!("{:?}", step.kind),
                            verdict: InverseVerdict::Executable,
                            reason: None,
                            derived_by: "swarm_response::rollback::resolve_inverse",
                        },
                        Err(InverseGap::Irreversible { reason }) => InverseResolution {
                            step_kind: format!("{:?}", step.kind),
                            verdict: InverseVerdict::Irreversible,
                            reason: Some(reason.to_string()),
                            derived_by: "swarm_response::rollback::resolve_inverse",
                        },
                        Err(_) => InverseResolution {
                            step_kind: format!("{:?}", step.kind),
                            verdict: InverseVerdict::Unmapped,
                            reason: None,
                            derived_by: "swarm_response::rollback::resolve_inverse",
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            hold_id: hold.hold_id,
            state: hold.state,
            notified_at_ms: hold.notified_at_ms,
            deciding_intent_event_id: hold.deciding_intent_event_id,
            case_channel: hold.case_channel,
            notice_event_id: hold.notice_event_id,
            card_event_id: hold.card_event_id,
            action_kind: hold.action_request.action.kind().to_string(),
            severity: hold.action_request.severity,
            held_at_ms: hold.held_at_ms,
            expires_at_ms: hold.expires_at_ms,
            remaining_ms,
            expired,
            leases_a_containment: swarm_runtime::containment::is_containment_action(&hold.action_request.action),
            action_request: hold.action_request,
            policy_decision: hold.policy_decision,
            rationale: hold.rationale,
            rehearsal: hold.rehearsal,
            inverse_resolution,
            decision: hold.decision,
        }
    }
}

/// `GET /v1/response/holds`.
#[derive(Debug, Clone, Serialize)]
pub struct HoldListResponse {
    pub schema_version: u32,
    pub observed_at_ms: i64,
    pub holds: Vec<HeldActionView>,
    pub open_count: usize,
    pub truncated: bool,
    pub deciding_stalled_count: usize,
    pub store_durable: bool,
}

/// `GET /v1/response/holds/{hold_id}`.
#[derive(Debug, Clone, Serialize)]
pub struct HoldDetailResponse {
    pub schema_version: u32,
    pub observed_at_ms: i64,
    pub hold: HeldActionView,
}

/// Query of the list route. `now_ms` absent means now.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldListQuery {
    pub now_ms: Option<i64>,
    pub include_terminal: Option<bool>,
    pub limit: Option<usize>,
}

/// Query of the detail route.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldDetailQuery {
    pub now_ms: Option<i64>,
}

fn map_read_error(error: HoldReadError) -> OperatorApiError {
    match error {
        HoldReadError::NoHoldStore => OperatorApiError::service_unavailable(
            "no hold store is attached to this daemon; set runtime.response.hold_store_path or start with the hold-capable profile",
        ),
        HoldReadError::Store(error) => OperatorApiError::internal(error.to_string()),
    }
}

pub(super) async fn hold_list_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    Query(query): Query<HoldListQuery>,
) -> Result<Json<HoldListResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
    let observed_at_ms = query.now_ms.unwrap_or_else(now_ms);
    let listing = list_holds(
        &state.ingest,
        query.include_terminal.unwrap_or(false),
        query.limit.unwrap_or(200).clamp(1, 1_000),
        observed_at_ms,
    )
    .map_err(map_read_error)?;
    Ok(Json(HoldListResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        observed_at_ms,
        holds: listing
            .holds
            .into_iter()
            .map(|hold| HeldActionView::from_hold(hold, observed_at_ms))
            .collect(),
        open_count: listing.open_count,
        truncated: listing.truncated,
        deciding_stalled_count: listing.health.deciding_stalled,
        store_durable: listing.health.durable,
    }))
}

pub(super) async fn hold_detail_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    RoutePath(hold_id): RoutePath<String>,
    Query(query): Query<HoldDetailQuery>,
) -> Result<Json<HoldDetailResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
    let observed_at_ms = query.now_ms.unwrap_or_else(now_ms);
    let hold = get_hold(&state.ingest, &hold_id)
        .map_err(map_read_error)?
        .ok_or_else(|| OperatorApiError::not_found(format!("no hold `{hold_id}`")))?;
    Ok(Json(HoldDetailResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        observed_at_ms,
        hold: HeldActionView::from_hold(hold, observed_at_ms),
    }))
}
```

Add to `http/error.rs`, beside `internal`:

```rust
    /// 503 with the `internal_error` slug: the daemon is up and the feature is
    /// not configured. Never "no holds".
    pub(super) fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "internal_error",
            message: message.into(),
            retry_after_seconds: None,
        }
    }
```

In `http/perch/mod.rs`, extend the router First card built:

```rust
pub mod holds;

/// Every path this router declares, so the disjointness test has a set to
/// compare and a route cannot be added without being counted.
pub const PERCH_ROUTER_PATHS: [&str; 5] = [
    "/v1/response/holds",
    "/v1/response/holds/{hold_id}",
    "/v1/operator/findings/reviewed",
    "/v1/operator/findings/{finding_id}/feedback",
    "/v1/operator/incidents",
];
```

and the three `.route(` calls:

```rust
        .route(PERCH_ROUTER_PATHS[0], get(holds::hold_list_handler))
        .route(PERCH_ROUTER_PATHS[1], get(holds::hold_detail_handler))
```

(`hold_decide_handler` is Task 13. That task inserts the decide path as element 2, mounts the
third `.route(`, and changes the exact count from five to six. Do not predeclare either the decide
path or Operator-complete's deposits path before their handlers exist; W3-28.)

Boot warning in `swarm_detect.rs`, where `config.operator.enabled` is first read (`:1115`):

```rust
        for principal in config.operator.auth.effective_principals() {
            if principal.scopes.contains(&swarm_core::config::OperatorScope::Approve)
                && !principal.scopes.contains(&swarm_core::config::OperatorScope::Read)
            {
                tracing::warn!(
                    module = module_path!(),
                    operator_id = %principal.operator_id,
                    "principal holds `approve` without `read`; the hold reads will answer 403 for it"
                );
            }
        }
```

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-runtime-http http::perch
cargo test -p swarm-runtime-http http::state::local_operator_surface_paths
```

Expected: the five tests pass (the disjointness test asserts five here and Task 13 flips it to six).

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-runtime-http crates/swarm-ingest-runtime
git commit -s -m "feat(swarm-runtime-http): add the two hold reads as the reconciliation authority"
```

---

## Task 11: B2o — `OperatorApproval` on the receipt

**Files:**
- Modify: `crates/swarm-core/src/types.rs` (`OperatorApproval`)
- Modify: `crates/swarm-response/src/lib.rs` (`ResponseReceiptAudit` `:118-125`; do **not** touch `:6` and `:19`, the `//! ## Owns` / `//! ## Does not own` lines RULE 5 reads)
- Modify: `crates/swarm-runtime/src/lib.rs` (`audit_authorize_and_execute_human_approved_instrumented` `:1085-1095`, `_internal` `:1097-1105`, the two `with_policy_audit` sites at `:1208-1216` and `:1253-1258`)
- Modify: `crates/swarm-ingest-runtime/src/ingest/demo.rs` (`:725`, `:1369`: pass `None`)
- Test: `crates/swarm-response/src/lib.rs` tests; `crates/swarm-runtime/src/lib.rs` tests

**Interfaces:**
- Produces:
  ```rust
  // swarm-core
  pub struct OperatorApproval { pub operator_id: String, pub voter_id: String, pub hold_id: String, pub decided_at_ms: i64, pub signature: DetachedSignature, pub rationale: Option<String>, pub rationale_sha256: Option<String>, pub nostr_intent_event_id: Option<String> }
  // swarm-response
  pub struct ResponseReceiptAudit { pub policy: Option<ResponsePolicyAudit>, pub governance: Option<ResponseGovernanceAudit>, pub approved_by: Option<OperatorApproval> }
  impl ResponseReceipt { pub fn with_operator_approval(self, approval: OperatorApproval) -> Self }
  // swarm-runtime
  pub async fn audit_authorize_and_execute_human_approved_instrumented(&self, detection, request, context, approved_by: Option<OperatorApproval>) -> Result<RuntimeExecutionReport, RuntimeError>
  ```

- [ ] **Step 1: Write the failing tests.**

In `crates/swarm-response/src/lib.rs`'s `mod tests`:

```rust
    #[test]
    fn a_receipt_carries_who_approved_it_and_serializes_the_field() {
        let receipt = ResponseReceipt {
            receipt_id: "r-1".into(),
            action: "isolate_host".into(),
            mode: ExecutionMode::Enforced,
            status: ResponseStatus::Executed,
            summary: "isolated".into(),
            details: serde_json::json!({}),
            audit: ResponseReceiptAudit::default(),
        }
        .with_operator_approval(swarm_core::types::OperatorApproval {
            operator_id: "perch-dev-operator".into(),
            voter_id: format!("swarm:ed25519:{}", "ab".repeat(32)),
            hold_id: "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13".into(),
            decided_at_ms: 1,
            signature: swarm_crypto::DetachedSignature {
                algorithm: "ed25519".into(),
                key_id: "k".into(),
                public_key_hex: "ab".repeat(32),
                signature_hex: "cd".repeat(64),
            },
            rationale: Some("two detectors agree".into()),
            rationale_sha256: Some("ef".repeat(32)),
            nostr_intent_event_id: Some("01".repeat(32)),
        });
        let value = serde_json::to_value(&receipt).unwrap();
        assert_eq!(value["audit"]["approved_by"]["operator_id"], "perch-dev-operator");
        assert_eq!(value["audit"]["approved_by"]["voter_id"], format!("swarm:ed25519:{}", "ab".repeat(32)));
        let back: ResponseReceipt = serde_json::from_value(value).unwrap();
        assert!(back.audit.approved_by.is_some());
        // A receipt written before B2o still deserializes.
        let legacy: ResponseReceiptAudit = serde_json::from_str(r#"{"policy":null}"#).unwrap();
        assert!(legacy.approved_by.is_none());
    }
```

In `crates/swarm-runtime/src/lib.rs`'s `mod tests`, beside `human_approved_live_runtime_executes_human_gated_action` (`:1681`), a copy of that test named `human_approved_execution_records_the_operator_on_the_receipt` which passes `Some(approval)` and asserts `report.audit.response` is `Success(receipt)` with `receipt.audit.approved_by.unwrap().hold_id == "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13"`.

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-response a_receipt_carries_who_approved
cargo test -p swarm-runtime human_approved_execution_records
```

Expected: `no method named with_operator_approval`; `this function takes 3 arguments but 4 were supplied`.

- [ ] **Step 3: Implement.**

`crates/swarm-core/src/types.rs` (after `ResponseRehearsalPreview`):

```rust
/// Who decided, on the Ed25519 chain. Attached to `ResponseReceiptAudit.approved_by`
/// (bill item B2o). Lives in `swarm-core` because `swarm-response` is trust-sensitive
/// and `swarm-core` is already inside its allowed closure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorApproval {
    pub operator_id: String,
    /// `swarm:ed25519:{public_key_hex}` — derived from the signature and bound
    /// to the authenticated principal. This, not `operator_id`, says a key signed.
    pub voter_id: String,
    pub hold_id: String,
    pub decided_at_ms: i64,
    pub signature: swarm_crypto::DetachedSignature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    /// SHA-256 of `rationale`'s UTF-8 bytes; a member of the signature preimage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale_sha256: Option<String>,
    /// A secp256k1 Nostr event id, OUTSIDE the Ed25519 preimage by construction.
    /// Recorded for cross-chain reconstruction only; never rendered as verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nostr_intent_event_id: Option<String>,
}
```

`crates/swarm-response/src/lib.rs`:

```rust
/// Runtime-owned audit metadata attached to successful response receipts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseReceiptAudit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ResponsePolicyAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance: Option<ResponseGovernanceAudit>,
    /// The human who granted a held action (B2o). `None` on the autonomous path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<swarm_core::types::OperatorApproval>,
}

impl ResponseReceipt {
    /// Attach the operator who granted the hold. Mirrors `with_policy_audit`.
    pub fn with_operator_approval(mut self, approval: swarm_core::types::OperatorApproval) -> Self {
        self.audit.approved_by = Some(approval);
        self
    }
}
```

`crates/swarm-runtime/src/lib.rs`:

```rust
    /// Execute a previously human-approved request through the normal runtime lane.
    ///
    /// `approved_by` is threaded onto the receipt (B2o) so a granted destructive
    /// action is distinguishable in the chain from an autonomous one.
    pub async fn audit_authorize_and_execute_human_approved_instrumented(
        &self,
        detection: &DetectionFinding,
        request: &ActionRequest,
        context: &ApprovalContext,
        approved_by: Option<swarm_core::types::OperatorApproval>,
    ) -> Result<RuntimeExecutionReport, RuntimeError> {
        self.audit_authorize_and_execute_instrumented_internal(
            detection, request, context, true, None, approved_by,
        )
        .await
    }
```

`_internal` gains `approved_by: Option<swarm_core::types::OperatorApproval>` as its sixth parameter (the other two callers pass `None`), and at both `with_policy_audit` sites (`:1208-1216` success, `:1253-1258` failure) the receipt is built as:

```rust
                                            let receipt = receipt.with_policy_audit(
                                                decision.verdict,
                                                decision.rule_name.clone(),
                                                decision.reason.clone(),
                                            );
                                            let receipt = match approved_by.clone() {
                                                Some(approval) => receipt.with_operator_approval(approval),
                                                None => receipt,
                                            };
                                            let receipt = Self::decorate_receipt_with_governance(
                                                receipt,
                                                request,
                                                "consensus approved response action",
                                            );
```

In `demo.rs:725` and `:1369` add the fourth argument `None`.

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-response
cargo test -p swarm-runtime human_approved
cargo test -p swarm-ingest-runtime
bash tools/check-workspace-layering.sh
```

Expected: green; RULE 5 still finds `//! ## Owns` and `//! ## Does not own` at `crates/swarm-response/src/lib.rs:6,19`; RULE 3 baseline unchanged (no new transport dependency reached the TCB closure).

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-core crates/swarm-response crates/swarm-runtime crates/swarm-ingest-runtime
git commit -s -m "feat(swarm-response): record the approving operator on human-granted receipts"
```

---

## Task 12: B2g — `swarm_runtime::governance_gate`, the moved checks and the four added ones

**Files:**
- Create: `crates/swarm-runtime/src/governance_gate.rs`
- Modify: `crates/swarm-runtime/src/lib.rs` (`pub mod governance_gate;` after `pub mod evolution_status;`)
- Modify: `crates/swarm-runtime/src/dispatcher.rs` (`:560-587` and `:671`: call the module; delete `:1276-1310`)
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs` (`current_governance_authority` accessor)
- Test: `crates/swarm-runtime/src/governance_gate.rs` `mod tests`

**Interfaces:**
- Consumes: `swarm_consensus::{ConsensusGovernanceReceipt, GovernanceReceiptDecision}` (`crates/swarm-consensus/src/lib.rs:353-448`), `GovernanceAuthority::authorize_partition_request` (`crates/swarm-policy/src/governance.rs:159-163`), `GovernanceClearance` (Task 4).
- Produces:
  ```rust
  pub fn response_action_requires_governance_receipt(action: &ResponseAction) -> bool   // moved
  pub fn missing_governance_receipt_reason(request: &ActionRequest) -> Option<String> // moved verbatim; the autonomous path's G0
  pub struct GovernanceReceiptBounds { pub subject_captured_at_ms: i64, pub max_age_ms: u64 }
  pub struct GovernanceRefusal { pub rule: &'static str, pub reason: String }
  pub fn reauthorize(authority: Option<&Arc<dyn GovernanceAuthority>>, request: &ActionRequest, now_ms: i64, bounds: GovernanceReceiptBounds) -> Result<GovernanceClearance, GovernanceRefusal>
  ```
  The autonomous path keeps calling `missing_governance_receipt_reason` (byte-identical behaviour after the move); `reauthorize` is what the decide path calls and what adds G1–G3. Making the dispatcher itself stricter is argued separately in the PR body; this task does **not** change the dispatcher's gate semantics.

- [ ] **Step 1: Write the six falsifiable tests.**

`governance_gate.rs` tests (module body in Step 3):

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use swarm_consensus::{ConsensusCommit, ConsensusCommittee, ConsensusGovernanceReceipt, ConsensusProposal, GovernanceReceiptDecision};
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_crypto::{canonical_json_bytes, sha256_hex};
    use swarm_policy::ActionRequest;

    const HELD_AT: i64 = 1_773_739_200_000;

    fn receipt(decision: GovernanceReceiptDecision, issued_at_ms: i64, threshold: usize, signer_in_committee: bool) -> serde_json::Value {
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let issued_by = AgentId::from_verifying_key(&signing_key.verifying_key());
        let member = if signer_in_committee { issued_by.clone() } else { AgentId::new("tom", "other") };
        let committee = ConsensusCommittee::new(vec![member], threshold).unwrap();
        let proposal_payload = json!({ "decision": decision });
        let commit = ConsensusCommit {
            height: 1,
            round: 0,
            committee_id: committee.committee_id().to_string(),
            proposal: ConsensusProposal {
                proposal_id: sha256_hex(&canonical_json_bytes(&proposal_payload).unwrap()),
                payload: proposal_payload,
            },
            prevote_tally: 1,
            precommit_tally: 1,
            commit_hash: "commit".to_string(),
        };
        serde_json::to_value(
            ConsensusGovernanceReceipt::issue(&commit, "prev", &committee, decision, issued_by, &signing_key, issued_at_ms).unwrap(),
        )
        .unwrap()
    }

    fn request_with(receipt: Option<serde_json::Value>) -> ActionRequest {
        let mut evidence = json!({ "escalation": { "threat_class": "execution" } });
        if let Some(receipt) = receipt {
            evidence["governance_receipt"] = receipt;
        }
        ActionRequest {
            hunt_id: HuntId("hunt-evt-1".into()),
            requested_by: AgentId::from_public_key_hex(&"18".repeat(32)),
            action: ResponseAction::IsolateHost { host_id: "host-ops-1".into() },
            severity: Severity::Critical,
            evidence,
        }
    }

    fn bounds() -> GovernanceReceiptBounds {
        GovernanceReceiptBounds { subject_captured_at_ms: HELD_AT, max_age_ms: 86_400_000 }
    }

    #[test]
    fn a_veto_receipt_is_refused() {
        let request = request_with(Some(receipt(GovernanceReceiptDecision::Veto, HELD_AT - 1, 1, true)));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_veto");
    }

    #[test]
    fn a_receipt_issued_after_the_hold_is_refused() {
        let request = request_with(Some(receipt(GovernanceReceiptDecision::Approve, HELD_AT + 1, 1, true)));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_stale");
    }

    #[test]
    fn a_receipt_older_than_max_age_is_refused() {
        let request = request_with(Some(receipt(GovernanceReceiptDecision::Approve, HELD_AT - 86_400_001, 1, true)));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_stale");
    }

    #[test]
    fn a_receipt_whose_signer_is_not_in_its_own_committee_is_refused() {
        let request = request_with(Some(receipt(GovernanceReceiptDecision::Approve, HELD_AT - 1, 1, false)));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_committee_inconsistent");
    }

    #[test]
    fn a_zero_threshold_receipt_is_refused() {
        let request = request_with(Some(receipt(GovernanceReceiptDecision::Approve, HELD_AT - 1, 0, true)));
        let refusal = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.receipt_committee_inconsistent");
    }

    #[test]
    fn a_self_signed_one_member_approve_receipt_is_accepted_and_clears_only_to_receipt_signature_ok() {
        // Asserts a LIMITATION. Strengthening the gate must fail this test and
        // force the console's limit sentence to change in the same commit.
        let request = request_with(Some(receipt(GovernanceReceiptDecision::Approve, HELD_AT - 1, 1, true)));
        let clearance = reauthorize(None, &request, HELD_AT + 10, bounds()).unwrap();
        assert_eq!(clearance, GovernanceClearance::ReceiptSignatureOk);
        assert_ne!(clearance, GovernanceClearance::ReceiptSubjectBound);
    }

    #[test]
    fn a_missing_receipt_on_a_gated_action_is_refused_and_a_non_gated_action_needs_none() {
        let refusal = reauthorize(None, &request_with(None), HELD_AT, bounds()).unwrap_err();
        assert_eq!(refusal.rule, "governance.missing_receipt");
        let mut scan = request_with(None);
        scan.action = ResponseAction::TriggerEdrScan { host_id: "h".into(), scan_profile: "quick".into() };
        assert_eq!(reauthorize(None, &scan, HELD_AT, bounds()).unwrap(), GovernanceClearance::NotRequired);
    }
}
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-runtime governance_gate
```

Expected: `file not found for module governance_gate`.

- [ ] **Step 3: Write the module and rewire the dispatcher.**

`crates/swarm-runtime/src/governance_gate.rs`:

```rust
//! The pre-routing governance gate, as one public module, so the autonomous
//! path (`dispatcher.rs`) and the human path (`perch_ops::holds::decide_hold`)
//! cannot drift (bill item B2g).
//!
//! `ConsensusGovernanceReceipt::verify()` checks a signature and that
//! `issued_by` derives from the signing key. IT DOES NOT CHECK THAT THE SIGNER
//! IS A GOVERNOR, and it cannot from here (the governor keys live inside the
//! concrete governance agent's state). So `GovernanceClearance` is named for
//! what ran, and no variant of it is called `Verified`.

use std::sync::Arc;

use swarm_consensus::{ConsensusGovernanceReceipt, GovernanceReceiptDecision};
use swarm_core::types::ResponseAction;
use swarm_policy::ActionRequest;
use swarm_policy::governance::GovernanceAuthority;

pub use crate::held_action::GovernanceClearance;

/// The twelve response actions that require a governance receipt. Moved from
/// `dispatcher.rs` (was `:1276-1292`); the count of copies stays at four.
pub fn response_action_requires_governance_receipt(action: &ResponseAction) -> bool {
    matches!(
        action,
        ResponseAction::BlockEgress { .. }
            | ResponseAction::IsolateHost { .. }
            | ResponseAction::RevokeCredential { .. }
            | ResponseAction::SinkholeDns { .. }
            | ResponseAction::TerminateUserSession { .. }
            | ResponseAction::InjectFirewallRule { .. }
            | ResponseAction::QuarantineFile { .. }
            | ResponseAction::KillProcess { .. }
            | ResponseAction::SuspendProcess { .. }
            | ResponseAction::DisableUserAccount { .. }
            | ResponseAction::ForcePasswordReset { .. }
            | ResponseAction::RemoveScheduledTask { .. }
    )
}

/// `Some(reason)` when the request cannot proceed on receipt grounds. Verbatim
/// move of the dispatcher's G0 so the autonomous path is byte-identical.
pub fn missing_governance_receipt_reason(request: &ActionRequest) -> Option<String> {
    if !response_action_requires_governance_receipt(&request.action) {
        return None;
    }
    let Some(receipt_value) = request.evidence.get("governance_receipt").cloned() else {
        return Some("missing governance receipt".to_string());
    };
    let receipt: ConsensusGovernanceReceipt = match serde_json::from_value(receipt_value) {
        Ok(receipt) => receipt,
        Err(error) => return Some(format!("invalid governance receipt: {error}")),
    };
    receipt
        .verify()
        .map(|_| ())
        .map_err(|error| format!("invalid governance receipt signature: {error}"))
        .err()
}

/// Freshness window for a receipt, from `runtime.response`.
#[derive(Debug, Clone, Copy)]
pub struct GovernanceReceiptBounds {
    /// The hold's `held_at_ms`. A receipt issued AFTER this was minted to order.
    pub subject_captured_at_ms: i64,
    /// Older than this is `receipt_stale`.
    pub max_age_ms: u64,
}

/// A typed refusal. `rule` is one of the `governance.*` rows of
/// `12-BACKEND-BILL-API.md` §4.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceRefusal {
    pub rule: &'static str,
    pub reason: String,
}

fn refusal(rule: &'static str, reason: impl Into<String>) -> GovernanceRefusal {
    GovernanceRefusal { rule, reason: reason.into() }
}

/// The whole pre-routing gate as one call. Partition authorization first
/// (which SKIPS the receipt check, exactly as the dispatcher's
/// `!partition_authorized &&` does), then G0 + G1 + G2 + G3. G4 needs the
/// producer-side change B2g-s and is unreachable until it lands.
pub fn reauthorize(
    authority: Option<&Arc<dyn GovernanceAuthority>>,
    request: &ActionRequest,
    now_ms: i64,
    bounds: GovernanceReceiptBounds,
) -> Result<GovernanceClearance, GovernanceRefusal> {
    if let Some(authority) = authority {
        match authority.authorize_partition_request(request, now_ms) {
            Ok(true) => return Ok(GovernanceClearance::PartitionAuthorized),
            Ok(false) => {}
            Err(reason) => return Err(refusal("governance.partition_rejected", reason)),
        }
    }
    if !response_action_requires_governance_receipt(&request.action) {
        return Ok(GovernanceClearance::NotRequired);
    }
    // G0 — the shipped gate.
    let Some(receipt_value) = request.evidence.get("governance_receipt").cloned() else {
        return Err(refusal("governance.missing_receipt", "missing governance receipt"));
    };
    let receipt: ConsensusGovernanceReceipt = serde_json::from_value(receipt_value)
        .map_err(|error| refusal("governance.invalid_receipt", format!("invalid governance receipt: {error}")))?;
    receipt
        .verify()
        .map_err(|error| refusal("governance.invalid_receipt", format!("invalid governance receipt signature: {error}")))?;
    let payload = &receipt.payload;
    // G1 — the field verify() never reads.
    if payload.decision != GovernanceReceiptDecision::Approve {
        return Err(refusal("governance.receipt_veto", "the attested decision is a veto"));
    }
    // G2 — freshness, both bounds.
    if payload.issued_at_ms > bounds.subject_captured_at_ms {
        return Err(refusal(
            "governance.receipt_stale",
            format!("receipt issued at {} after the action was held at {}", payload.issued_at_ms, bounds.subject_captured_at_ms),
        ));
    }
    if now_ms.saturating_sub(payload.issued_at_ms) > bounds.max_age_ms as i64 {
        return Err(refusal(
            "governance.receipt_stale",
            format!("receipt issued at {} is older than {} ms", payload.issued_at_ms, bounds.max_age_ms),
        ));
    }
    // G3 — self-consistency, not authority.
    if payload.threshold == 0 {
        return Err(refusal("governance.receipt_committee_inconsistent", "threshold is zero"));
    }
    if !payload.committee_members.contains(&payload.issued_by) {
        return Err(refusal("governance.receipt_committee_inconsistent", "issued_by is not a committee member"));
    }
    if payload.prevote_tally < payload.threshold || payload.precommit_tally < payload.threshold {
        return Err(refusal("governance.receipt_committee_inconsistent", "a tally is below the threshold"));
    }
    // G4 is unreachable until B2g-s writes evidence["governance_proposal"].
    Ok(GovernanceClearance::ReceiptSignatureOk)
}
```

In `dispatcher.rs`, replace the two private free functions at `:1276-1310` with `use crate::governance_gate::missing_governance_receipt_reason;` (both call sites at `:576` and `:671` keep their exact shape and semantics). `authorize_partition_request` at `:1014` stays private and unchanged. Then verify:

```bash
STS_VISIBILITY_HEAD_REV= bash tools/check-visibility-baseline.sh
```

Expected: exit 0 — the two functions were private (no visibility keyword) at the baseline, so `governance_gate.rs fn missing_governance_receipt_reason` is a new key, not a widened one.

In `ingest/mod.rs`, beside `current_governance_status` (`:1847`):

```rust
    /// The governance authority the dispatcher holds, for the decide path's
    /// partition re-evaluation (B2g).
    pub fn current_governance_authority(&self) -> Option<Arc<dyn GovernanceAuthority>> {
        self.governance_policy.clone()
    }
```

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-runtime governance_gate
cargo test -p swarm-runtime --test dispatch_integration
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: 7 gate tests pass; `dispatch_integration` unchanged (the autonomous path is byte-identical).

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-runtime crates/swarm-ingest-runtime
git commit -s -m "feat(swarm-runtime): lift the governance gate into a shared module with veto, freshness and committee checks"
```

---

## Task 13: B2 — `POST /v1/response/holds/{hold_id}/decide`

> Blocked on Task 1 for runtime behaviour; Step 9 is blocked on Task 2.

**Files:**
- Create: `crates/swarm-perch-wire/src/verdict.rs` (`pub mod verdict;` in `crates/swarm-perch-wire/src/lib.rs`)
- Modify: `crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs` (`decide_hold`, `HoldDecisionError`, `HoldDecisionOutcome`)
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs` (`operator_binds_voter_id`)
- Modify: `crates/swarm-runtime-http/src/http/perch/holds.rs` (`HoldDecisionRequest`, `HoldDecisionResponse`, `hold_decide_handler`, the 409 taxonomy)
- Modify: `crates/swarm-runtime-http/src/http/error.rs` (`conflict` constructor with an optional `Retry-After`, `unprocessable`)
- Modify: `crates/swarm-core/src/config/operator.rs` (Task 2 option (a): `verdict_public_key_hex: Option<String>` on `OperatorPrincipalConfig`, validated 64 lowercase hex)
- Test: `crates/swarm-perch-wire/src/verdict.rs` tests; `perch_ops/holds.rs` tests; `http/perch/holds.rs` tests

**Interfaces:**
- Consumes: `DecisionClaim` (Task 5), `governance_gate::reauthorize` (Task 12), `audit_authorize_and_execute_human_approved_instrumented(…, Some(approval))` (Task 11), `swarm_crypto::{canonical_json_bytes, sha256_hex, verify_detached_signature, DetachedSignature}` (`crates/swarm-crypto/src/lib.rs:50-150`), `demo_approval_resume_handler`'s prototype (`crates/swarm-ingest-runtime/src/ingest/demo.rs:1279-1425`: `ApprovalContext` with the decision instant, the human-approved call, `RuntimeEvent::ResponseExecution` publish, `correlate_hunt`).
- Produces:
  ```rust
  // swarm-perch-wire (default features; serde + serde_json only)
  pub struct DecisionPreimage<'a> { pub decided_at_ms: i64, pub decision: &'a str, pub hold_id: &'a str, pub rationale_sha256: Option<&'a str> }
  pub fn decision_preimage_bytes(decided_at_ms: i64, decision: &str, hold_id: &str, rationale_sha256: Option<&str>) -> Vec<u8>
  pub fn rationale_sha256_hex(rationale: Option<&str>) -> Option<String>
  // perch_ops::holds
  pub struct HoldDecisionInput { pub decision: HoldDecision, pub decided_at_ms: i64, pub nostr_intent_event_id: String, pub signature: DetachedSignature, pub rationale: Option<String>, pub armed_at_ms: Option<i64> }
  pub enum HoldDecisionError { NoHoldStore, NotFound, InvalidSignature(String), VoterMismatch { operator_id: String, voter_id: String }, Expired, DecisionInFlight, AlreadyDeciding, AlreadyDecided, Store(HeldActionStoreError), Runtime(String) }
  pub struct HoldDecisionOutcome { pub hold: HeldAction, pub replayed: bool, pub receipt: Option<ResponseReceipt>, pub capability_lease: Option<CapabilityLease>, pub containment_lease_id: Option<String> }
  pub async fn decide_hold(state: &IngestState, hold_id: &str, operator_id: &str, input: HoldDecisionInput, now_ms: i64) -> Result<HoldDecisionOutcome, HoldDecisionError>
  ```
  Status codes: 200 (`HoldDecisionResponse`, read `decision.outcome`/`dispatched`), 400 (bad body, unknown field, bad `nostr_intent_event_id`), 401, 403 (no `Approve`, or voter mismatch), 404, 409 (`hold_already_decided`; `decision_in_flight` + `Retry-After: 1`; `hold_already_deciding` + `Retry-After: 1`; `hold_expired`), 422 (`bad_request` slug: signature or digest mismatch, nothing written), 503 (no store).

- [ ] **Step 1: Write the failing preimage tests (wire crate).**

`crates/swarm-perch-wire/src/verdict.rs` tests:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_preimage_is_exactly_the_rfc_8785_form_of_four_sorted_members() {
        let bytes = decision_preimage_bytes(
            1_773_738_979_000,
            "grant",
            "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13",
            Some("f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"),
        );
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            r#"{"decided_at_ms":1773738979000,"decision":"grant","hold_id":"hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13","rationale_sha256":"f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"}"#
        );
        let none = decision_preimage_bytes(1, "refuse", "h_a07aeacf", None);
        assert_eq!(std::str::from_utf8(&none).unwrap(), r#"{"decided_at_ms":1,"decision":"refuse","hold_id":"h_a07aeacf","rationale_sha256":null}"#);
    }

    #[test]
    fn the_rationale_digest_is_lowercase_sha256_of_the_utf8_bytes_or_none() {
        assert_eq!(rationale_sha256_hex(None), None);
        assert_eq!(
            rationale_sha256_hex(Some("hello")).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-perch-wire verdict
```

Expected: `file not found for module verdict`.

- [ ] **Step 3: Write the wire module.**

`crates/swarm-perch-wire/src/verdict.rs`:

```rust
//! The four-member decision preimage both legs sign and verify (W3-16).
//!
//! RFC 8785 canonical JSON of `{decided_at_ms, decision, hold_id,
//! rationale_sha256}`. With these value types (an integer, two ASCII tokens
//! and a hex digest or null) canonical form is exactly: keys in lexicographic
//! order, no whitespace, the integer as plain digits, `null` for an absent
//! digest — which is what `serde_json::to_vec` emits for a struct whose fields
//! are declared in sorted order. `hold_id` is constrained to
//! `[A-Za-z0-9_-]` so no escaping can differ between implementations. The
//! engine side asserts byte equality against `swarm_crypto::canonical_json_bytes`.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Field order IS the canonical order. Do not reorder.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionPreimage<'a> {
    pub decided_at_ms: i64,
    pub decision: &'a str,
    pub hold_id: &'a str,
    pub rationale_sha256: Option<&'a str>,
}

/// The exact bytes the operator signs and the daemon verifies.
pub fn decision_preimage_bytes(
    decided_at_ms: i64,
    decision: &str,
    hold_id: &str,
    rationale_sha256: Option<&str>,
) -> Vec<u8> {
    // Serializing a struct of primitives cannot fail; the fallback keeps the
    // crate free of `unwrap`/`expect` in production code.
    serde_json::to_vec(&DecisionPreimage { decided_at_ms, decision, hold_id, rationale_sha256 })
        .unwrap_or_default()
}

/// Lowercase hex SHA-256 of the rationale's UTF-8 bytes, or `None` when the
/// operator wrote none.
pub fn rationale_sha256_hex(rationale: Option<&str>) -> Option<String> {
    rationale.map(|text| {
        let digest = Sha256::digest(text.as_bytes());
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    })
}
```

Add `sha2 = { workspace = true }` to `crates/swarm-perch-wire/Cargo.toml` under the default feature set (it is already a workspace dependency, `Cargo.toml:84`); `sha2` links no engine crate so D2's rule holds.

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-perch-wire verdict
```

Expected: 2 passed.

- [ ] **Step 5: Write the failing engine tests.**

Append to `perch_ops/holds.rs`'s `mod tests`:

```rust
    use swarm_crypto::{Ed25519Signer, canonical_json_bytes};
    use swarm_perch_wire::verdict::{decision_preimage_bytes, rationale_sha256_hex};

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_secret_material("perch-dev-operator-verdict-seed")
    }

    fn input(decision: HoldDecision, hold_id: &str, rationale: Option<&str>, intent: &str) -> HoldDecisionInput {
        let digest = rationale_sha256_hex(rationale);
        let bytes = decision_preimage_bytes(T0 + 100, decision.as_str(), hold_id, digest.as_deref());
        HoldDecisionInput {
            decision,
            decided_at_ms: T0 + 100,
            nostr_intent_event_id: intent.to_string(),
            signature: signer().sign(&bytes),
            rationale: rationale.map(str::to_string),
            armed_at_ms: Some(T0 + 90),
        }
    }

    fn state_with_hold(state: HoldState) -> (crate::ingest::IngestState, String) {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut hold = swarm_runtime::held_action::tests::fixture_hold(
            ResponseAction::IsolateHost { host_id: "host-ops-1".into() },
            T0,
        );
        hold.state = state;
        let id = hold.hold_id.clone();
        store.create(hold).unwrap();
        let state = crate::ingest::tests::test_ingest_state_live_response()
            .with_hold_store(store)
            .with_verdict_key_for_test("perch-dev-operator", signer().public_key_hex());
        (state, id)
    }

    #[test]
    fn the_engine_preimage_equals_the_wire_preimage_byte_for_byte() {
        let engine = canonical_json_bytes(&serde_json::json!({
            "hold_id": "h_a07aeacf", "decision": "grant", "decided_at_ms": 5, "rationale_sha256": null
        }))
        .unwrap();
        let wire = decision_preimage_bytes(5, "grant", "h_a07aeacf", None);
        assert_eq!(engine, wire);
    }

    #[tokio::test]
    async fn a_bad_signature_is_422_and_writes_nothing() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let mut bad = input(HoldDecision::Refuse, &id, None, &"aa".repeat(32));
        bad.signature.signature_hex = "00".repeat(64);
        let error = decide_hold(&state, &id, "perch-dev-operator", bad, T0 + 100).await.unwrap_err();
        assert!(matches!(error, HoldDecisionError::InvalidSignature(_)));
        assert_eq!(state.current_hold_store().unwrap().get(&id).unwrap().unwrap().state, HoldState::Notified);
    }

    #[tokio::test]
    async fn a_substituted_rationale_is_422() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let mut swapped = input(HoldDecision::Refuse, &id, Some("original"), &"aa".repeat(32));
        swapped.rationale = Some("substituted".into());
        let error = decide_hold(&state, &id, "perch-dev-operator", swapped, T0 + 100).await.unwrap_err();
        assert!(matches!(error, HoldDecisionError::InvalidSignature(_)));
    }

    #[tokio::test]
    async fn a_voter_that_does_not_bind_to_the_principal_is_403() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let error = decide_hold(&state, &id, "someone-else", input(HoldDecision::Refuse, &id, None, &"aa".repeat(32)), T0 + 100)
            .await
            .unwrap_err();
        assert!(matches!(error, HoldDecisionError::VoterMismatch { .. }));
    }

    #[tokio::test]
    async fn refuse_short_circuits_on_a_created_hold_and_records_the_notice_state() {
        let (state, id) = state_with_hold(HoldState::Created);
        let outcome = decide_hold(&state, &id, "perch-dev-operator", input(HoldDecision::Refuse, &id, Some("not now"), &"aa".repeat(32)), T0 + 100)
            .await
            .unwrap();
        assert!(!outcome.replayed);
        assert_eq!(outcome.hold.state, HoldState::Refused);
        let record = outcome.hold.decision.unwrap();
        assert_eq!(record.outcome, HoldOutcome::RefusedByOperator);
        assert!(!record.dispatched);
        assert!(!record.hold_notice_published);
        assert_eq!(record.decided_at_ms, T0 + 100, "the CAS instant, not the body's clock");
        assert_eq!(record.rationale_sha256, rationale_sha256_hex(Some("not now")));
        assert!(record.audit_trail_id.is_none(), "the runtime is never entered on refuse");
    }

    #[tokio::test]
    async fn a_replay_returns_the_stored_record_and_a_different_id_is_409() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let first = input(HoldDecision::Refuse, &id, None, &"aa".repeat(32));
        decide_hold(&state, &id, "perch-dev-operator", first.clone(), T0 + 100).await.unwrap();
        let replay = decide_hold(&state, &id, "perch-dev-operator", first, T0 + 200).await.unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.hold.decision.unwrap().decided_at_ms, T0 + 100);
        let other = decide_hold(&state, &id, "perch-dev-operator", input(HoldDecision::Grant, &id, None, &"bb".repeat(32)), T0 + 300)
            .await
            .unwrap_err();
        assert!(matches!(other, HoldDecisionError::AlreadyDecided));
    }

    #[tokio::test]
    async fn an_expired_hold_is_a_typed_hold_expired() {
        let (state, id) = state_with_hold(HoldState::Notified);
        let error = decide_hold(&state, &id, "perch-dev-operator", input(HoldDecision::Grant, &id, None, &"aa".repeat(32)), T0 + 3_600_000)
            .await
            .unwrap_err();
        assert!(matches!(error, HoldDecisionError::Expired));
    }

    #[tokio::test]
    async fn a_grant_on_isolate_host_with_no_lease_store_is_refused_late_with_a_typed_rule() {
        // The shipped default. `prepare_containment` returns ContainmentRefused
        // and the runtime records Skipped; the decide route names the rule.
        let (state, id) = state_with_hold(HoldState::Notified);
        let outcome = decide_hold(&state, &id, "perch-dev-operator", input(HoldDecision::Grant, &id, Some("isolate"), &"aa".repeat(32)), T0 + 100)
            .await
            .unwrap();
        let record = outcome.hold.decision.unwrap();
        assert_eq!(record.outcome, HoldOutcome::RefusedLate);
        assert_eq!(record.refusal.unwrap().rule, "runtime.containment_refused");
        assert!(record.audit_trail_id.is_some(), "the runtime WAS entered and wrote a trail");
        assert!(outcome.capability_lease.is_some(), "the lease was minted at the decision instant");
        let lease = outcome.capability_lease.unwrap();
        assert_eq!(lease.expires_at_ms, T0 + 100 + 60_000);
    }

    #[tokio::test]
    async fn a_grant_on_a_non_containment_action_executes_and_names_the_operator_on_the_receipt() {
        let (state, id) = state_with_hold_action(HoldState::Notified, ResponseAction::BlockEgress { target: "203.0.113.10".into() });
        let outcome = decide_hold(&state, &id, "perch-dev-operator", input(HoldDecision::Grant, &id, None, &"aa".repeat(32)), T0 + 100)
            .await
            .unwrap();
        let record = outcome.hold.decision.clone().unwrap();
        assert!(matches!(record.outcome, HoldOutcome::GrantedExecuted | HoldOutcome::GrantedSimulated));
        assert!(record.dispatched);
        assert_eq!(record.governance_clearance, GovernanceClearance::ReceiptSignatureOk);
        let receipt = outcome.receipt.unwrap();
        assert_eq!(receipt.audit.approved_by.unwrap().hold_id, id);
    }
```

`state_with_hold_action` is `state_with_hold` with the action as a parameter (refactor `state_with_hold` to call it); the block-egress case needs `evidence["governance_receipt"]` — build it with the `receipt(Approve, T0 - 1, 1, true)` helper from Task 12's tests (move that helper into `crates/swarm-runtime/src/governance_gate.rs` as `pub(crate) fn sample_receipt_for_test` behind `#[cfg(any(test, feature = "test-fixtures"))]`, and enable `test-fixtures` for `swarm-ingest-runtime`'s dev-dependency on `swarm-runtime`). `test_ingest_state_live_response()` is `test_ingest_state()` (`ingest/tests.rs:690-692`) with `runtime.mode = LiveResponse`, `response_adapter` the dry-run adapter, and a permissive policy rule for `execution` mirroring `permissive_policy_rules()` in `http/tests.rs:80-93`; `with_verdict_key_for_test` is a `#[cfg(test)]` builder that inserts one principal `{operator_id, verdict_public_key_hex}` into the config template's `operator.auth.principals`.

- [ ] **Step 6: Run and watch it fail.**

```bash
cargo test -p swarm-ingest-runtime perch_ops::holds
```

Expected: `cannot find function decide_hold`.

- [ ] **Step 7: Add the error and outcome types and the `conflict` constructors.**

`http/error.rs`:

```rust
    /// 409 with one of the four decide slugs; `Retry-After: 1` when the
    /// conflict will resolve on its own.
    pub(super) fn conflict(error: &'static str, message: impl Into<String>, retry_after_seconds: Option<u64>) -> Self {
        Self { status: StatusCode::CONFLICT, error, message: message.into(), retry_after_seconds }
    }

    /// 422 with the `bad_request` slug: the body parsed and the signature did
    /// not verify. Nothing was written.
    pub(super) fn unprocessable(message: impl Into<String>) -> Self {
        Self { status: StatusCode::UNPROCESSABLE_ENTITY, error: "bad_request", message: message.into(), retry_after_seconds: None }
    }
```

`perch_ops/holds.rs`:

```rust
use swarm_crypto::{DetachedSignature, canonical_json_bytes, verify_detached_signature};
use swarm_perch_wire::verdict::rationale_sha256_hex;
use swarm_policy::{ApprovalContext, CapabilityLease};
use swarm_response::ResponseReceipt;
use swarm_runtime::governance_gate::{GovernanceReceiptBounds, reauthorize};
use swarm_runtime::held_action::{
    DecisionClaim, GovernanceClearance, HeldActionStoreError, HoldDecision, HoldDecisionRecord,
    HoldOutcome, HoldRefusal, NotDecidable,
};
use swarm_core::config::RuntimeMode;
use swarm_core::types::OperatorApproval;

/// The decide body after the route's own validation.
#[derive(Debug, Clone)]
pub struct HoldDecisionInput {
    pub decision: HoldDecision,
    pub decided_at_ms: i64,
    pub nostr_intent_event_id: String,
    pub signature: DetachedSignature,
    pub rationale: Option<String>,
    pub armed_at_ms: Option<i64>,
}

/// Every way a decision can be refused before it becomes a record.
#[derive(Debug, thiserror::Error)]
pub enum HoldDecisionError {
    #[error("no hold store is attached to this daemon")]
    NoHoldStore,
    #[error("no such hold")]
    NotFound,
    /// 422. Nothing was written.
    #[error("signature did not verify: {0}")]
    InvalidSignature(String),
    /// 403. Nothing was written.
    #[error("voter `{voter_id}` does not bind to operator `{operator_id}`")]
    VoterMismatch { operator_id: String, voter_id: String },
    #[error("hold expired")]
    Expired,
    /// 409, same intent id, still deciding.
    #[error("this decision is still in flight")]
    DecisionInFlight,
    /// 409, another intent id holds the claim.
    #[error("another decision holds the claim")]
    AlreadyDeciding,
    /// 409, terminal under another intent id.
    #[error("the hold was already decided by another intent")]
    AlreadyDecided,
    #[error(transparent)]
    Store(#[from] HeldActionStoreError),
    /// A transport or store fault after the CAS. The guard abandoned the claim.
    #[error("runtime error: {0}")]
    Runtime(String),
}

/// What the route returns on 200.
pub struct HoldDecisionOutcome {
    pub hold: HeldAction,
    pub replayed: bool,
    pub receipt: Option<ResponseReceipt>,
    pub capability_lease: Option<CapabilityLease>,
    pub containment_lease_id: Option<String>,
}

/// Signature payload, serialized through `canonical_json_bytes` so key order
/// is the canonical one; the wire crate's `decision_preimage_bytes` produces
/// identical bytes (asserted in this module's tests).
#[derive(serde::Serialize)]
struct DecisionSignaturePayload<'a> {
    decided_at_ms: i64,
    decision: &'a str,
    hold_id: &'a str,
    rationale_sha256: Option<&'a str>,
}

fn voter_id_from_public_key(public_key_hex: &str) -> String {
    format!("swarm:ed25519:{public_key_hex}")
}
```

- [ ] **Step 8: Write `decide_hold` steps 1–8.**

```rust
/// The daemon re-derives authority from scratch. Steps, in order, each
/// naming the mechanism: read (no write) → verify the signature (no write) →
/// bind the voter (no write) → compare-and-set (the point of no return, held
/// by a `Drop` guard) → refuse short-circuit → governance → policy + execute
/// with the lease minted from the CAS instant → commit, then publish.
pub async fn decide_hold(
    state: &crate::ingest::IngestState,
    hold_id: &str,
    operator_id: &str,
    input: HoldDecisionInput,
    now_ms: i64,
) -> Result<HoldDecisionOutcome, HoldDecisionError> {
    let capture = state.current_hold_capture().ok_or(HoldDecisionError::NoHoldStore)?;
    let store = capture.store();

    // 2. READ. Nothing is mutated in steps 2-3.
    let hold = store.get(hold_id)?.ok_or(HoldDecisionError::NotFound)?;
    if let Some(record) = &hold.decision {
        if record.nostr_intent_event_id == input.nostr_intent_event_id {
            return Ok(HoldDecisionOutcome { hold, replayed: true, receipt: None, capability_lease: None, containment_lease_id: None });
        }
    }
    match hold.assert_decidable(now_ms) {
        Ok(()) => {}
        Err(NotDecidable::Expired) => return Err(HoldDecisionError::Expired),
        Err(NotDecidable::Deciding) => {
            return Err(if hold.deciding_intent_event_id.as_deref() == Some(input.nostr_intent_event_id.as_str()) {
                HoldDecisionError::DecisionInFlight
            } else {
                HoldDecisionError::AlreadyDeciding
            });
        }
        Err(NotDecidable::Terminal) => return Err(HoldDecisionError::AlreadyDecided),
    }

    // 3. SIGNATURE, BEFORE ANY WRITE. Then the voter binding.
    let rationale_sha256 = rationale_sha256_hex(input.rationale.as_deref());
    let payload = canonical_json_bytes(&DecisionSignaturePayload {
        decided_at_ms: input.decided_at_ms,
        decision: input.decision.as_str(),
        hold_id,
        rationale_sha256: rationale_sha256.as_deref(),
    })
    .map_err(|error| HoldDecisionError::Runtime(error.to_string()))?;
    verify_detached_signature(&payload, &input.signature)
        .map_err(|error| HoldDecisionError::InvalidSignature(error.to_string()))?;
    let voter_id = voter_id_from_public_key(&input.signature.public_key_hex);
    if !state.operator_binds_voter_id(operator_id, &voter_id) {
        return Err(HoldDecisionError::VoterMismatch { operator_id: operator_id.to_string(), voter_id });
    }

    // 4. COMPARE-AND-SET, by a guard. Expiry and state are re-checked inside.
    let claim = match DecisionClaim::begin(store.as_ref(), hold_id, &input.nostr_intent_event_id, now_ms) {
        Ok(claim) => claim,
        Err(HeldActionStoreError::NotDecidable { current, .. }) => {
            return Err(classify_conflict(&current, &input.nostr_intent_event_id, now_ms));
        }
        Err(error) => return Err(error.into()),
    };
    let claimed = claim.claimed().clone();
    let hold_notice_published = claimed.prior_state != Some(HoldState::Created);
    let base_record = |outcome: HoldOutcome, clearance: GovernanceClearance| HoldDecisionRecord {
        decision: input.decision,
        operator_id: operator_id.to_string(),
        voter_id: voter_id.clone(),
        rationale_sha256: rationale_sha256.clone(),
        hold_notice_published,
        governance_clearance: clearance,
        decided_at_ms: now_ms,
        nostr_intent_event_id: input.nostr_intent_event_id.clone(),
        signature: Some(input.signature.clone()),
        rationale: input.rationale.clone(),
        outcome,
        dispatched: false,
        receipt_id: None,
        audit_trail_id: None,
        refusal: None,
    };

    // 5. REFUSE short-circuits. Nothing about governance, policy or telemetry
    //    is consulted: Refuse is the exit and must survive every degraded state.
    if input.decision == HoldDecision::Refuse {
        let record = base_record(HoldOutcome::RefusedByOperator, GovernanceClearance::NotRequired);
        claim.complete(record, HoldState::Refused)?;
        capture.publish_state(&claimed, HoldState::Refused, now_ms);
        let hold = store.get(hold_id)?.ok_or(HoldDecisionError::NotFound)?;
        return Ok(HoldDecisionOutcome { hold, replayed: false, receipt: None, capability_lease: None, containment_lease_id: None });
    }

    // 6. GOVERNANCE (B2g). A typed refusal is terminal; an internal error is
    //    not (the guard abandons on `?`).
    let bounds = GovernanceReceiptBounds {
        subject_captured_at_ms: claimed.held_at_ms,
        max_age_ms: capture.settings().governance_receipt_max_age_ms,
    };
    let authority = state.current_governance_authority();
    let clearance = match reauthorize(authority.as_ref(), &claimed.action_request, now_ms, bounds) {
        Ok(clearance) => clearance,
        Err(refusal) => {
            let mut record = base_record(HoldOutcome::RefusedLate, GovernanceClearance::NotRequired);
            record.refusal = Some(HoldRefusal { rule: refusal.rule.to_string(), reason: refusal.reason });
            claim.complete(record, HoldState::Refused)?;
            capture.publish_state(&claimed, HoldState::Refused, now_ms);
            let hold = store.get(hold_id)?.ok_or(HoldDecisionError::NotFound)?;
            return Ok(HoldDecisionOutcome { hold, replayed: false, receipt: None, capability_lease: None, containment_lease_id: None });
        }
    };

    // 7. POLICY + EXECUTION. `now_ms` here is the CAS instant, so `issue_lease`
    //    mints the capability lease from the decision, never from hold time.
    let context = ApprovalContext {
        live_mode: state.current_runtime_mode() == RuntimeMode::LiveResponse,
        receipt_chain: vec![claimed.hold_id.clone()],
        correlation_id: Some(claimed.hold_id.clone()),
        now_ms,
    };
    let approval = OperatorApproval {
        operator_id: operator_id.to_string(),
        voter_id: voter_id.clone(),
        hold_id: claimed.hold_id.clone(),
        decided_at_ms: now_ms,
        signature: input.signature.clone(),
        rationale: input.rationale.clone(),
        rationale_sha256: rationale_sha256.clone(),
        nostr_intent_event_id: Some(input.nostr_intent_event_id.clone()),
    };
    let runtime = state.request_runtime.load_full();
    let execution = runtime
        .audit_authorize_and_execute_human_approved_instrumented(
            &claimed.detection,
            &claimed.action_request,
            &context,
            Some(approval),
        )
        .await
        .map_err(|error| HoldDecisionError::Runtime(error.to_string()))?;

    // 8. COMMIT the outcome, then publish. Store first.
    let audit = execution.audit.clone();
    let (receipt_id, response_error) = crate::ingest::response_receipt_details(&audit);
    let (outcome, state_after, refusal, receipt) = classify_execution(&audit, &execution);
    let mut record = base_record(outcome, clearance);
    record.dispatched = execution.response_attempted;
    record.receipt_id = receipt_id.clone();
    record.audit_trail_id = Some(audit.trail_id.clone());
    record.refusal = refusal;
    claim.complete(record, state_after)?;
    capture.publish_state(&claimed, state_after, now_ms);
    state.publish_runtime_event(RuntimeEvent::ResponseExecution {
        emitted_at_ms: now_ms,
        agent_id: claimed.action_request.requested_by.to_string(),
        hunt_id: audit.hunt_id.clone(),
        action_kind: claimed.action_request.action.kind().to_string(),
        response_kind: audit.response_kind().to_string(),
        policy_verdict: audit.policy.verdict,
        rule_name: audit.policy.rule_name.clone(),
        reason: audit.policy.reason.clone(),
        receipt_id,
        governing_agent_id: None,
        error: response_error,
    });
    if let Ok(Some(outcome)) = state.stack.load_full().correlate_hunt(&claimed.action_request.hunt_id.0) {
        tracing::info!(module = module_path!(), hold_id, incident = %outcome.incident.incident_id, "hold decision correlated");
    }
    let capability_lease = runtime.policy().issue_lease(&claimed.action_request, &context).ok();
    let containment_lease_id = receipt
        .as_ref()
        .and_then(|receipt| receipt.details.get("containment_lease_id").and_then(|v| v.as_str()).map(str::to_string));
    let hold = store.get(hold_id)?.ok_or(HoldDecisionError::NotFound)?;
    Ok(HoldDecisionOutcome { hold, replayed: false, receipt, capability_lease, containment_lease_id })
}

fn classify_conflict(current: &HeldAction, intent: &str, _now_ms: i64) -> HoldDecisionError {
    match current.state {
        HoldState::Deciding if current.deciding_intent_event_id.as_deref() == Some(intent) => HoldDecisionError::DecisionInFlight,
        HoldState::Deciding => HoldDecisionError::AlreadyDeciding,
        HoldState::Expired => HoldDecisionError::Expired,
        _ => HoldDecisionError::AlreadyDecided,
    }
}

/// Map the runtime's trail onto a hold outcome. Every late refusal is a
/// typed rule, never an error.
fn classify_execution(
    audit: &AuditTrail,
    execution: &swarm_runtime::RuntimeExecutionReport,
) -> (HoldOutcome, HoldState, Option<HoldRefusal>, Option<ResponseReceipt>) {
    match &audit.response {
        AuditResponseRecord::Success(receipt) => {
            let outcome = if receipt.mode == swarm_response::ExecutionMode::DryRun {
                HoldOutcome::GrantedSimulated
            } else {
                HoldOutcome::GrantedExecuted
            };
            (outcome, HoldState::Executed, None, Some(receipt.clone()))
        }
        AuditResponseRecord::Failure(failure) => {
            let lease_expired = failure.details.get("status").and_then(|v| v.as_str()) == Some("lease_expired");
            if lease_expired {
                (
                    HoldOutcome::RefusedLate,
                    HoldState::Refused,
                    Some(HoldRefusal { rule: "runtime.capability_lease_expired".into(), reason: failure.message.clone() }),
                    None,
                )
            } else {
                (HoldOutcome::GrantedFailed, HoldState::Failed, None, None)
            }
        }
        AuditResponseRecord::Skipped { reason } => {
            let rule = if reason.contains("containment") {
                "runtime.containment_refused"
            } else if audit.policy.rule_name.starts_with("policy.") || audit.policy.rule_name.starts_with("static.") {
                match audit.policy.rule_name.as_str() {
                    "static.minimum_severity" => "policy.minimum_severity",
                    "static.scope_rate_limit" => "policy.scope_rate_limit",
                    "configurable.time_window" => "policy.time_window",
                    "configurable.fail_closed.empty_ruleset" => "policy.empty_ruleset",
                    _ => "policy.denied",
                }
            } else {
                "policy.denied"
            };
            let _ = execution;
            (HoldOutcome::RefusedLate, HoldState::Refused, Some(HoldRefusal { rule: rule.into(), reason: reason.clone() }), None)
        }
        AuditResponseRecord::GuardRejected { guard_name, reason } => (
            HoldOutcome::GuardRejected,
            HoldState::Refused,
            Some(HoldRefusal { rule: "runtime.guard_rejected".into(), reason: format!("{guard_name}: {reason}") }),
            None,
        ),
    }
}
```

`runtime.policy()` is the gate accessor on `SwarmRuntime` (`grep -n 'pub fn policy' crates/swarm-runtime/src/lib.rs`); if it is absent, add `pub fn policy(&self) -> &P { &self.policy }` beside `mode()` at `:627`. `crate::ingest::response_receipt_details` already exists (used by `demo.rs:1391`). The rule-name mapping table above is the one place `12` §4.6's fifteen rule strings are produced from the runtime's own `rule_name`s; the four `static.*`/`configurable.*` literals come from `crates/swarm-policy/src/static_gate.rs:274-299` and `configurable_gate.rs:136-158` — read them once while implementing and adjust the literal keys to the exact strings those files emit.

- [ ] **Step 9: Voter binding (blocked on Task 2, written against option (a)).**

`crates/swarm-core/src/config/operator.rs`, on `OperatorPrincipalConfig`:

```rust
    /// The Ed25519 verifying key whose signature the decide route binds to this
    /// principal (`swarm:ed25519:{hex}`). 64 lowercase hex characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_public_key_hex: Option<String>,
```

with validation beside the `nostr_pubkey` rule B0 added (64 lowercase hex or `InvalidField { field: "operator_surface.auth.principals.verdict_public_key_hex" }`). In `ingest/mod.rs`:

```rust
    /// Whether `voter_id` (`swarm:ed25519:{hex}`) is the verdict key configured
    /// for `operator_id`. A principal with no `verdict_public_key_hex` binds to
    /// nothing, so every decide from it is 403 — a named, fail-closed state.
    pub fn operator_binds_voter_id(&self, operator_id: &str, voter_id: &str) -> bool {
        self.config_template
            .load_full()
            .operator
            .auth
            .effective_principals()
            .iter()
            .any(|principal| {
                principal.operator_id == operator_id
                    && principal
                        .verdict_public_key_hex
                        .as_deref()
                        .is_some_and(|hex| format!("swarm:ed25519:{hex}") == voter_id)
            })
    }
```

and the `#[cfg(test)] with_verdict_key_for_test(self, operator_id, hex)` builder that pushes a principal onto the template.

- [ ] **Step 10: The route.**

`http/perch/holds.rs`:

```rust
/// Body of `POST /v1/response/holds/{hold_id}/decide`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoldDecisionRequest {
    pub decision: HoldDecision,
    pub decided_at_ms: i64,
    /// 64 lowercase hex. The idempotency key and an unsigned pointer.
    pub nostr_intent_event_id: String,
    pub signature: swarm_crypto::DetachedSignature,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub armed_at_ms: Option<i64>,
}

/// Response. The caller reads `decision.outcome` and `decision.dispatched`,
/// never the status code, to learn what happened to the world.
#[derive(Debug, Clone, Serialize)]
pub struct HoldDecisionResponse {
    pub schema_version: u32,
    pub hold_id: String,
    pub state: HoldState,
    pub decision: HoldDecisionRecord,
    pub replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<swarm_response::ResponseReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_trail_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containment_lease_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_lease: Option<swarm_policy::CapabilityLease>,
}

fn is_hex64_lower(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) async fn hold_decide_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    RoutePath(hold_id): RoutePath<String>,
    Json(request): Json<HoldDecisionRequest>,
) -> Result<Json<HoldDecisionResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Approve, "approve")?;
    if hold_id.trim().is_empty() || !swarm_runtime::held_action::is_opaque_hold_id(&hold_id) {
        return Err(OperatorApiError::bad_request("hold_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$"));
    }
    if !is_hex64_lower(&request.nostr_intent_event_id) {
        return Err(OperatorApiError::bad_request("nostr_intent_event_id must be 64 lowercase hex characters"));
    }
    if request.rationale.as_ref().is_some_and(|text| text.len() > 4096) {
        return Err(OperatorApiError::bad_request("rationale exceeds 4096 bytes"));
    }
    let input = HoldDecisionInput {
        decision: request.decision,
        decided_at_ms: request.decided_at_ms,
        nostr_intent_event_id: request.nostr_intent_event_id,
        signature: request.signature,
        rationale: request.rationale,
        armed_at_ms: request.armed_at_ms,
    };
    let outcome = decide_hold(&state.ingest, &hold_id, principal.operator_id.as_ref(), input, now_ms())
        .await
        .map_err(|error| match error {
            HoldDecisionError::NoHoldStore => OperatorApiError::service_unavailable("no hold store is attached to this daemon"),
            HoldDecisionError::NotFound => OperatorApiError::not_found(format!("no hold `{hold_id}`")),
            HoldDecisionError::InvalidSignature(reason) => OperatorApiError::unprocessable(reason),
            HoldDecisionError::VoterMismatch { operator_id, voter_id } => {
                OperatorApiError::forbidden(format!("signature key `{voter_id}` does not bind to operator `{operator_id}`"))
            }
            HoldDecisionError::Expired => OperatorApiError::conflict("hold_expired", "the hold expired; the action was never taken", None),
            HoldDecisionError::DecisionInFlight => OperatorApiError::conflict("decision_in_flight", "this decision is still being applied", Some(1)),
            HoldDecisionError::AlreadyDeciding => OperatorApiError::conflict("hold_already_deciding", "another decision holds the claim; re-read the hold", Some(1)),
            HoldDecisionError::AlreadyDecided => OperatorApiError::conflict("hold_already_decided", "the hold was decided under another intent; re-read the hold", None),
            HoldDecisionError::Store(error) => OperatorApiError::internal(error.to_string()),
            HoldDecisionError::Runtime(reason) => OperatorApiError::internal(reason),
        })?;
    let decision = outcome
        .hold
        .decision
        .clone()
        .ok_or_else(|| OperatorApiError::internal("decided hold carries no decision record"))?;
    Ok(Json(HoldDecisionResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        hold_id: outcome.hold.hold_id.clone(),
        state: outcome.hold.state,
        audit_trail_id: decision.audit_trail_id.clone(),
        decision,
        replayed: outcome.replayed,
        receipt: outcome.receipt,
        containment_lease_id: outcome.containment_lease_id,
        capability_lease: outcome.capability_lease,
    }))
}
```

Then insert `"/v1/response/holds/{hold_id}/decide"` as `PERCH_ROUTER_PATHS[2]`, add the third
`.route(PERCH_ROUTER_PATHS[2], post(holds::hold_decide_handler))` in `perch/mod.rs`, and flip the
disjointness assertion from five to six (W3-28). Route tests in `holds.rs`'s `mod tests`: a 403
with no `Approve`; a 422 with a flipped signature byte asserting `body["error"] == "bad_request"`
and the hold still `notified`; a 409 `decision_in_flight` with `Retry-After: 1` produced by seeding
a `deciding` hold with the same intent id; a 200 refuse whose body has `replayed: false`,
`decision.outcome == "refused_by_operator"`, `decision.dispatched == false`; the same body
re-posted returning `replayed: true` byte-identical `decision`.

- [ ] **Step 11: Run.**

```bash
cargo test -p swarm-ingest-runtime perch_ops::holds
cargo test -p swarm-runtime-http http::perch
cargo clippy --workspace --all-targets -- -D warnings
bash tools/check-runtime-panic-contract.sh
```

Expected: all green.

- [ ] **Step 12: Commit.**

```bash
git add crates/swarm-perch-wire crates/swarm-ingest-runtime crates/swarm-runtime-http crates/swarm-core crates/swarm-runtime
git commit -s -m "feat(swarm-runtime-http): add the decide route with signature-first ordering and a guarded compare-and-set"
```

---

## Task 14: B5 — the event stream's token becomes mandatory, its wildcard ACAO goes, the review POST gains a scope check

**Files:**
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs` (`resolve_demo_scope` `:636-652`)
- Modify: `crates/swarm-ingest-runtime/src/ingest/demo.rs` (`runtime_events_handler` `:1644-1718`; `with_demo_cors` `:361-369`)
- Modify: `crates/swarm-runtime-http/src/http/review.rs` (`review_session_create_handler` `:204-221`)
- Modify: `crates/swarm-core/src/config/defaults.rs` (`default_operator_context_token_env` `:239-241`)
- Test: `crates/swarm-ingest-runtime/src/ingest/tests.rs`; `crates/swarm-runtime-http/src/http/tests.rs`

**Interfaces:**
- Consumes: `resolve_demo_scope(operator, query) -> Result<ProvidenceContextScope, IngestRequestError>`, `verify_providence_context_token`, `require_operator_review_scope` (`http/auth.rs:168-180`).
- Produces: `resolve_demo_scope` returns `Err(IngestRequestError::ProvidenceContextToken { reason: "context_token is required" })` when the token is absent or empty; the stream response carries no `Access-Control-Allow-Origin`; `review_session_create_handler(Extension(principal), State, Form)` calls `require_operator_review_scope(&principal, OperatorScope::Approve, "approve")`; `operator.auth.context_token_env` defaults to `SWARM_OPERATOR_CONTEXT_TOKEN` and `docs/CONFIGURATION.md` says so.

- [ ] **Step 1: Write the failing tests.**

`ingest/tests.rs`:

```rust
#[tokio::test]
async fn the_event_stream_refuses_an_anonymous_reader_and_serves_a_token_bearing_one() {
    let app = detect_http_router(test_ingest_state_with_context_token("stream-secret"));
    let anonymous = app
        .clone()
        .oneshot(Request::builder().uri("/v1/events/stream").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert!(anonymous.headers().get("access-control-allow-origin").is_none());

    let token = mint_providence_context_token_for_test("stream-secret", ProvidenceContextScope::default());
    let scoped = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/events/stream?context_token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scoped.status(), StatusCode::OK);
    assert!(scoped.headers().get("access-control-allow-origin").is_none());
}
```

`http/tests.rs`, in the review section: a `POST /v1/operator/review/sessions` with a bearer whose principal holds `{Read}` only → 403 rendered as the review layout (`text/html`), and with `{Approve}` → 303 redirect (the existing behaviour).

- [ ] **Step 2: Run and watch them fail.**

```bash
cargo test -p swarm-ingest-runtime the_event_stream_refuses
cargo test -p swarm-runtime-http review_session_create
```

Expected: the anonymous request answers 200 today; the read-only principal creates a session today.

- [ ] **Step 3: Implement.**

`resolve_demo_scope`:

```rust
fn resolve_demo_scope(
    operator: &OperatorSurfaceConfig,
    query: &DemoScopeQuery,
) -> Result<ProvidenceContextScope, IngestRequestError> {
    let requested_scope = query.raw_scope();
    // B5. The token is MANDATORY. The previous arm returned the requested scope
    // unverified when the token was absent, which combined with the empty-scope
    // short-circuit in `runtime_event_matches_scope` to hand an ANONYMOUS reader
    // more than a scoped one.
    let Some(raw_token) = query.context_token.as_deref().filter(|value| !value.is_empty()) else {
        return Err(IngestRequestError::ProvidenceContextToken {
            reason: "context_token is required".to_string(),
        });
    };
    let secret_material = operator_secret_material(operator)?;
    let claims = verify_providence_context_token(&secret_material, raw_token, now_ms())
        .map_err(|reason| IngestRequestError::ProvidenceContextToken { reason })?;
    merge_context_scope(claims.scope, requested_scope)
}
```

In `runtime_events_handler`, replace every `with_demo_cors(...)` wrapper with a new `with_no_store(...)` that sets only `Cache-Control: no-store`:

```rust
pub(super) fn with_no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
```

The other 25 `with_demo_cors` sites on `/v1/demo/*` stay (they are `demo_mode_enabled()`-gated and out of this bill's scope; `12` §12.2 names them so they are not forgotten — record that in the PR body). `review_session_create_handler`:

```rust
pub(super) async fn review_session_create_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<OperatorHttpState>,
    Form(form): Form<ReviewSessionCreateForm>,
) -> Result<Redirect, OperatorReviewError> {
    require_operator_review_scope(&principal, OperatorScope::Approve, "approve")?;
    let service = review_workbench_service(&state)?;
    // … unchanged …
}
```

`defaults.rs`:

```rust
pub(super) fn default_operator_context_token_env() -> String {
    "SWARM_OPERATOR_CONTEXT_TOKEN".to_string()
}
```

with a `docs/CONFIGURATION.md` paragraph: the stream token and the operator bearer were one env var; a deployment that relied on that sets `operator_surface.auth.context_token_env: SWARM_OPERATOR_TOKEN` explicitly. `rulesets-dev/perch-dev.yaml` sets it to `SWARM_OPERATOR_CONTEXT_TOKEN` and `docs/PERCH-DEV.md` exports it.

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-ingest-runtime
cargo test -p swarm-runtime-http
```

Expected: green; the existing stream tests that relied on an anonymous read are updated to pass a token in the same commit (they are the tests this task exists to change).

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-ingest-runtime crates/swarm-runtime-http crates/swarm-core docs/CONFIGURATION.md rulesets-dev/perch-dev.yaml rulesets-dev/perch-dev.yaml.sig.json
git commit -s -m "fix(swarm-ingest-runtime): require the context token on the event stream and scope the review session POST"
```

---

## Task 15: Bridge — `HoldId` per R-3, the hold card body, the `46010` tag set, and `ensure_case_channel`'s `Held` arm

**Files:**
- Modify: `crates/swarm-perch-bridge/src/channels.rs` (`HoldId::parse`, `ensure_case_channel` `Held` arm, `PublishStep::{PublishHold, PublishAlarm}`)
- Modify: `crates/swarm-perch-bridge/src/cards.rs` (`hold_card`, `HoldAlarm`)
- Modify: `crates/swarm-perch-bridge/src/lib.rs` (`BridgeBuildInput.hold_store`, `BridgeBuildInput.approve_pubkeys`)
- Test: `crates/swarm-perch-bridge/src/channels.rs` and `cards.rs` `mod tests` (T-18, T-20 amended, T-21 amended per R-1)

**Interfaces:**
- Consumes: `swarm_runtime::held_action::{HeldAction, HeldActionStore, HoldState, is_opaque_hold_id}`, `swarm_perch_wire::marker::CardKind::Hold`, `swarm_perch_wire::tags::{TagSet, TagError}`, `swarm_perch_wire::cards::HoldCard` (renamed to `swarm:` by P1-26), `crate::identity::normalize_p_tag`.
- Produces:
  ```rust
  impl HoldId { pub fn parse(raw: &str) -> Result<Self, BridgeError> }   // the R-3 pattern; colon => MalformedHoldId
  pub enum PublishStep { CreateCaseChannel {..}, AddOperator {..}, PublishHoldCard { channel: Uuid, hold_id: HoldId, reply_to: Option<String> }, PublishHoldNotice { channel: Uuid, hold_id: HoldId, card_event_id: Option<String> }, PublishAlarm { hold_id: HoldId } }
  pub fn hold_card(hold: &HeldAction, case_channel: &str, finding_card_id: Option<&str>, issuer: &IssuerBlock, seq: u64, prev_envelope_hash: Option<&str>, issued_at: &str) -> CardBody
  pub struct HoldAlarm { pub hold_id: String, pub action_kind: String, pub severity: String, pub case_channel: String, pub expires_at_ms: i64 }
  pub struct BridgeBuildInput { …, pub hold_store: Option<Arc<dyn HeldActionStore>>, pub approve_pubkeys: Vec<String> }
  ```
  `PublishAlarm` carries no `watch_channel` (R-1: the frame is global and the `#watch` layer is retracted); `perch.watch_channel` is deleted from `config.rs` in this task.

- [ ] **Step 1: Write the failing tests.**

`channels.rs` tests:

```rust
    #[test]
    fn hold_id_shape_is_asserted_to_the_r3_pattern() {
        for ok in ["hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13", "h_a07aeacf", "abcdefgh"] {
            assert!(HoldId::parse(ok).is_ok(), "{ok}");
        }
        for bad in ["hold:01K3QJ7ZV9M2R4TX8N6B0DWCA5", "hold:hunt-evt-1:1773739200000", "short", "", "_x1234567", &"a".repeat(65)] {
            assert!(matches!(HoldId::parse(bad), Err(BridgeError::MalformedHoldId { .. })), "{bad:?}");
        }
    }

    #[test]
    fn a_held_trigger_on_an_unrouted_hunt_plans_create_then_operators_and_mints_the_case() {
        let dir = tempfile::tempdir().unwrap();
        let mut routing = CaseRouting::open(&dir.path().join("routing.json")).unwrap();
        let trigger = CasePromotionTrigger::Held { hunt_id: "hunt-evt-1".into(), hold_id: "h_a07aeacf".into() };
        let operators = vec!["68".repeat(32), "69".repeat(32)];
        let (case, steps) = routing.ensure_case_channel(&trigger, &operators, 2_592_000).unwrap();
        assert!(matches!(steps[0], PublishStep::CreateCaseChannel { channel, ttl_seconds: 2_592_000, .. } if channel == case));
        assert_eq!(steps.iter().filter(|s| matches!(s, PublishStep::AddOperator { .. })).count(), 2);
        assert_eq!(steps.len(), 3, "the caller appends PublishHoldCard/PublishHoldNotice/PublishAlarm itself");
        // Idempotent: the same hunt routes to the same channel with no create steps.
        let (again, more) = routing.ensure_case_channel(&trigger, &operators, 2_592_000).unwrap();
        assert_eq!(again, case);
        assert!(more.is_empty());
        // Durable across a reopen.
        drop(routing);
        let reopened = CaseRouting::open(&dir.path().join("routing.json")).unwrap();
        assert_eq!(reopened.case_for_hunt("hunt-evt-1"), Some(case));
    }
```

`cards.rs` tests:

```rust
    #[test]
    fn the_hold_card_body_is_three_parts_in_the_ruled_order_and_names_no_signature() {
        let hold = swarm_runtime::held_action::tests::fixture_hold(
            swarm_core::types::ResponseAction::IsolateHost { host_id: "host-ops-1".into() },
            1_773_738_882_600,
        );
        let body = hold_card(&hold, "27799e23-ab25-4659-b381-3de47ea7ca4d", None, &test_issuer(), 3, None, "2026-03-17T09:14:42Z");
        let mut lines = body.content.split('\n');
        assert_eq!(lines.next(), Some("<!-- swarm:hold:v1 -->"));
        let human = lines.next().unwrap();
        assert!(human.starts_with(&format!("hold {} · isolate_host · CRITICAL · host host-ops-1 · expires ", hold.hold_id)), "{human}");
        assert_eq!(lines.next(), Some(""));
        assert_eq!(lines.next(), Some("```swarm:hold:v1"));
        let json: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(json["schema"], "swarm.spine.envelope.v1");
        assert_eq!(json["fact"]["schema"], "swarm.perch.hold.v1");
        assert_eq!(json["fact"]["locator"]["case_channel"], "27799e23-ab25-4659-b381-3de47ea7ca4d");
        assert_eq!(json["fact"]["hold"]["leases_a_containment"], true);
        assert!(json.get("signature").is_none());
        assert!(!body.content.contains("signed_by") && !body.content.contains("verified"));
        assert_eq!(body.tags.h.as_deref(), Some("27799e23-ab25-4659-b381-3de47ea7ca4d"));
        assert!(body.tags.p.is_empty(), "a kind:9 card never carries p");
    }

    #[test]
    fn the_notice_carries_exactly_the_four_tag_names_and_the_alarm_exactly_five_keys() {
        let notice = hold_notice_tags("27799e23-ab25-4659-b381-3de47ea7ca4d", &["68".repeat(32)], "h_a07aeacf", Some(&"b9".repeat(32)));
        notice.assert_publishable(46010).unwrap();
        assert!(notice.e.is_none() && notice.t.is_none() && notice.l.is_none() && notice.k.is_none());
        assert_eq!(notice.p.len(), 1);
        let alarm = serde_json::to_value(HoldAlarm {
            hold_id: "h_a07aeacf".into(), action_kind: "isolate_host".into(), severity: "CRITICAL".into(),
            case_channel: "27799e23-ab25-4659-b381-3de47ea7ca4d".into(), expires_at_ms: 1_773_742_482_600,
        }).unwrap();
        let mut keys: Vec<&str> = alarm.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["action_kind", "case_channel", "expires_at_ms", "hold_id", "severity"]);
        let alarm_tags = hold_alarm_tags(&["68".repeat(32)]);
        assert!(alarm_tags.h.is_none(), "26006 is global (R-1)");
        alarm_tags.assert_publishable(26006).unwrap();
        assert!(matches!(hold_alarm_tags(&[]).assert_publishable(26006), Err(TagError::NoRecipients(26006))));
    }
```

- [ ] **Step 2: Run and watch them fail.**

```bash
cargo test -p swarm-perch-bridge hold_id_shape
cargo test -p swarm-perch-bridge a_held_trigger
cargo test -p swarm-perch-bridge the_hold_card_body
```

Expected: the R-3 `HoldId` and `Held` routing regression tests already pass from First
card; `hold_card` has only the finding-era shape and `hold_notice_tags` does not exist,
so the card/tag tests fail to compile. A regression failure in either of the first two
commands is a First-card defect and must be repaired there, not accepted as this task's
red phase.

- [ ] **Step 3: Implement.**

`channels.rs`: retain First card's complete R-3 parser (shown here as the contract this
task re-verifies; it is not a stub replacement):

```rust
impl HoldId {
    /// The R-3 wire pattern `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$` (W3-15). A colon
    /// anywhere is a hard refusal: that is the derived `hold:{hunt_id}:{ms}`
    /// form, and this id rides the community-global `26006` frame.
    pub fn parse(raw: &str) -> Result<Self, BridgeError> {
        if swarm_runtime::held_action::is_opaque_hold_id(raw) {
            Ok(Self(raw.to_string()))
        } else {
            Err(BridgeError::MalformedHoldId { value: raw.to_string() })
        }
    }
}
```

Keep First card's `ensure_case_channel` implementation and `hunts` persistence map.
This task extends its `Held` regression corpus and renames `CreateChannel` / `AddMember`
to `CreateCaseChannel` / `AddOperator` consistently if those hold-specific names are
preferred; it must not introduce a second `by_hunt` representation or rewrite the
already-durable routing algorithm.

`PublishStep` gains the following hold variants (there are no copied skeleton variants
left after First card's atomic-unit gate):

```rust
    /// kind:9 `swarm:hold:v1` into the case channel. First, so the notice can
    /// point at it. `reply_to` is the open card's id on a terminal card.
    PublishHoldCard { channel: Uuid, hold_id: HoldId, reply_to: Option<String> },
    /// kind:46010, `h` + `p` per Approve principal + `hold` + `card`. Second.
    PublishHoldNotice { channel: Uuid, hold_id: HoldId, card_event_id: Option<String> },
    /// ephemeral 26006, GLOBAL, `p` per Approve principal, no `h` (R-1). Last,
    /// and it bypasses the pacer.
    PublishAlarm { hold_id: HoldId },
```

`cards.rs`:

```rust
/// The `swarm:hold:v1` body: marker, one human line, blank line, fenced
/// envelope. Field order inside `fact.hold` IS the verdict pane's order
/// because `HeldAction` serializes in that order.
pub fn hold_card(
    hold: &HeldAction,
    case_channel: &str,
    finding_card_id: Option<&str>,
    issuer: &IssuerBlock,
    seq: u64,
    prev_envelope_hash: Option<&str>,
    issued_at: &str,
) -> CardBody {
    let scope = scope_of(&hold.action_request.action);
    let expires = rfc3339_ms(hold.expires_at_ms);
    let human = format!(
        "hold {} · {} · {} · {} {} · expires {}",
        hold.hold_id,
        hold.action_request.action.kind(),
        severity_screaming(hold.action_request.severity),
        scope.0,
        scope.1,
        expires
    );
    let fact = serde_json::json!({
        "schema": "swarm.perch.hold.v1",
        "issuer": issuer.as_value(),
        "emitted_at_ms": hold.held_at_ms,
        "locator": {
            "hold_id": hold.hold_id,
            "case_channel": case_channel,
            "hunt_id": hold.action_request.hunt_id.0,
            "finding_card_id": finding_card_id,
        },
        "hold": hold_view_from_record(hold),
    });
    let envelope = crate::envelope::unsigned_envelope(issuer, seq, prev_envelope_hash, issued_at, fact);
    CardBody {
        content: format!(
            "<!-- swarm:hold:v1 -->\n{human}\n\n```swarm:hold:v1\n{}\n```",
            envelope
        ),
        tags: TagSet::card(CardKind::Hold, case_channel, Some(threat_class_slug(&hold.rationale.threat_class)), Some(severity_screaming(hold.action_request.severity).to_string())),
    }
}

/// The `46010` tag set. Exactly `h`, `p`×N, `hold`, `card`. `assert_publishable`
/// refuses `e`/`t`/`l`/`k`, a missing `hold`, and zero recipients.
pub fn hold_notice_tags(case_channel: &str, approve_pubkeys: &[String], hold_id: &str, card_event_id: Option<&str>) -> TagSet {
    TagSet {
        h: Some(case_channel.to_string()),
        p: approve_pubkeys.to_vec(),
        hold: Some(hold_id.to_string()),
        card: card_event_id.map(str::to_string),
        ..TagSet::default()
    }
}

/// The `26006` tag set: `p` per Approve principal and NOTHING else (R-1).
pub fn hold_alarm_tags(approve_pubkeys: &[String]) -> TagSet {
    TagSet { p: approve_pubkeys.to_vec(), ..TagSet::default() }
}

/// The `46010` content line: the same human line the card carries, verbatim.
pub fn hold_notice_content(card: &CardBody) -> String {
    card.content.lines().nth(1).unwrap_or_default().to_string()
}
```

`crate::cards::hold_view_from_record(&HeldAction) -> serde_json::Value` is a bridge-owned adapter that projects the engine record onto the neutral `HeldActionView` shape minus the two clock fields (`remaining_ms`, `expired` are never on a card). Implement it here as `serde_json::to_value(hold)` with `notified_at_ms`, `deciding_intent_event_id`, `cas_instant_ms`, `prior_state`, `case_channel`, `notice_event_id`, `card_event_id` removed and `leases_a_containment: hold.leases_a_containment()` and `inverse_resolution: []` added. It must not move into `swarm-perch-wire`: accepting `HeldAction` there would violate W3-27's zero-engine-dependency boundary. `TagSet::assert_publishable(46010)` already refuses `ExtraNoticeTag`, `MissingHoldTag`, `NoRecipients`, `ThreadedHoldNotice`; extend it so `assert_publishable(26006)` refuses `ScopedHoldAlarm` when `h` is set and `NoRecipients(26006)` when `p` is empty (P1-26 shipped both variants; this step only confirms the two branches exist).

`lib.rs` — `BridgeBuildInput` gains:

```rust
    /// The daemon's ONE hold store. Read only in the publish task (never in
    /// `receive.rs`) to build the hold card body from the record, and written
    /// through `mark_case_channel` / `mark_notified` once the relay OKs the
    /// 9007 and the 46010. `None` on a daemon with no `runtime.response`
    /// block; the bridge then refuses every `ResponseHeld` (F18-shaped).
    pub hold_store: Option<Arc<dyn swarm_runtime::held_action::HeldActionStore>>,
    /// Lowercase 64-hex Nostr pubkeys of every principal holding
    /// `OperatorScope::Approve` with a `nostr_pubkey` (B0). Empty means every
    /// hold is undeliverable and the bridge says so (F18).
    pub approve_pubkeys: Vec<String>,
```

and `swarm_detect.rs`'s build site passes `hold_store: Some(Arc::clone(&hold_store))` and `approve_pubkeys: swarm_perch_bridge::identity::approve_scoped_operator_pubkeys(&config.operator.auth)` (P0-19's helper). Delete `watch_channel` from `config.rs` and `PerchBridgeConfig::validate`.

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-perch-bridge
```

Expected: green, including T-16 (`no_signature_field_in_any_card_body`) over the new hold body.

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-perch-bridge crates/swarm-perch-wire crates/swarm-runtime-http
git commit -s -m "feat(swarm-perch-bridge): assemble the hold card, the 46010 notice and the case-channel steps for a held action"
```

---

## Task 16: Bridge — `ResponseHeld` drives the case channel, the card, the notice and the daemon callbacks

**Files:**
- Create: `crates/swarm-perch-bridge/src/holds.rs`
- Modify: `crates/swarm-perch-bridge/src/lib.rs` (`pub mod holds;`, wire the publisher into `run()`)
- Modify: `crates/swarm-perch-bridge/src/publish.rs` (`ConnectionSupervisor::submit_steps`)
- Test: `crates/swarm-perch-bridge/src/holds.rs` `mod tests`

**Interfaces:**
- Consumes: `Stream::Alarm` records from the spool (Task 7 classified `ResponseHeld` there), `CaseRouting::ensure_case_channel` (Task 15), `HeldActionStore::{get, mark_case_channel, mark_notified}`, `ConnectionSupervisor::classify_ok` (`duplicate: channel already exists` is success, F14).
- Produces:
  ```rust
  pub struct HoldPublisher { routing: CaseRouting, store: Option<Arc<dyn HeldActionStore>>, approve_pubkeys: Vec<String>, case_ttl_seconds: i32, issuer: IssuerBlock, metrics: BridgeMetrics }
  pub enum HoldPlan { Steps(Vec<PublishStep>), Undeliverable { hold_id: String, reason: &'static str } }
  impl HoldPublisher {
      pub fn plan(&mut self, event: &RuntimeEvent) -> Result<HoldPlan, BridgeError>;   // ResponseHeld{created} => create+operators+card+notice+alarm; terminal states => reply card only
      pub fn on_ok(&self, step: &PublishStep, event_id: &str, now_ms: i64);             // mark_case_channel after 9007, mark_notified after 46010
  }
  ```
  Publish order for a `created` hold: `9007` → `9000`×N → kind:9 card → `46010` (with `card` = the card's id) → `26006`. A terminal `ResponseHeld` (`refused`, `executed`, `failed`, `expired`) publishes exactly one terminal card as a NIP-10 reply to the open card and nothing else. `state: notified` is never published by the daemon (it is the bridge's own callback).

- [ ] **Step 1: Write the failing tests.**

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_runtime::held_action::{HeldActionStore, HoldState, MemoryHeldActionStore};
    use swarm_runtime::runtime_events::RuntimeEvent;

    fn held_event(hold: &swarm_runtime::held_action::HeldAction, state: HoldState) -> RuntimeEvent {
        RuntimeEvent::ResponseHeld {
            emitted_at_ms: hold.held_at_ms,
            hold_id: hold.hold_id.clone(),
            hunt_id: hold.action_request.hunt_id.0.clone(),
            action_kind: hold.action_request.action.kind().to_string(),
            severity: hold.action_request.severity,
            expires_at_ms: hold.expires_at_ms,
            state,
        }
    }

    fn publisher(store: Option<Arc<MemoryHeldActionStore>>, operators: Vec<String>) -> HoldPublisher {
        let dir = tempfile::tempdir().unwrap();
        HoldPublisher::new(
            CaseRouting::open(&dir.path().join("routing.json")).unwrap(),
            store.map(|s| s as Arc<dyn HeldActionStore>),
            operators,
            2_592_000,
            test_issuer(),
            BridgeMetrics::for_test(),
        )
    }

    #[test]
    fn a_created_hold_plans_the_five_step_sequence_in_order() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let hold = swarm_runtime::held_action::tests::fixture_hold(
            swarm_core::types::ResponseAction::IsolateHost { host_id: "host-ops-1".into() },
            1_773_738_882_600,
        );
        store.create(hold.clone()).unwrap();
        let mut publisher = publisher(Some(store.clone()), vec!["68".repeat(32)]);
        let HoldPlan::Steps(steps) = publisher.plan(&held_event(&hold, HoldState::Created)).unwrap() else { panic!("undeliverable") };
        let kinds: Vec<&str> = steps.iter().map(PublishStep::label).collect();
        assert_eq!(kinds, ["create_case_channel", "add_operator", "publish_hold_card", "publish_hold_notice", "publish_alarm"]);
        // The 9007 OK reports the channel; the 46010 OK reports notified.
        let PublishStep::CreateCaseChannel { channel, .. } = &steps[0] else { unreachable!() };
        publisher.on_ok(&steps[0], &"01".repeat(32), 1);
        assert_eq!(store.get(&hold.hold_id).unwrap().unwrap().case_channel.as_deref(), Some(channel.to_string().as_str()));
        publisher.on_ok(&steps[3], &"02".repeat(32), 2);
        let after = store.get(&hold.hold_id).unwrap().unwrap();
        assert_eq!(after.state, HoldState::Notified);
        assert_eq!(after.notice_event_id.as_deref(), Some("02".repeat(32).as_str()));
    }

    #[test]
    fn no_approve_pubkey_means_undeliverable_and_nothing_is_built() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let hold = swarm_runtime::held_action::tests::fixture_hold(
            swarm_core::types::ResponseAction::IsolateHost { host_id: "h".into() }, 1);
        store.create(hold.clone()).unwrap();
        let mut publisher = publisher(Some(store), vec![]);
        assert!(matches!(publisher.plan(&held_event(&hold, HoldState::Created)).unwrap(), HoldPlan::Undeliverable { reason: "no_operator_pubkey", .. }));
    }

    #[test]
    fn a_terminal_state_plans_exactly_one_reply_card() {
        let store = Arc::new(MemoryHeldActionStore::default());
        let mut hold = swarm_runtime::held_action::tests::fixture_hold(
            swarm_core::types::ResponseAction::IsolateHost { host_id: "h".into() }, 1);
        hold.state = HoldState::Refused;
        hold.card_event_id = Some("03".repeat(32));
        hold.case_channel = Some(uuid::Uuid::new_v4().to_string());
        store.create(hold.clone()).unwrap();
        let mut publisher = publisher(Some(store), vec!["68".repeat(32)]);
        let HoldPlan::Steps(steps) = publisher.plan(&held_event(&hold, HoldState::Refused)).unwrap() else { panic!() };
        assert_eq!(steps.len(), 1);
        assert!(matches!(&steps[0], PublishStep::PublishHoldCard { reply_to: Some(id), .. } if id == &"03".repeat(32)));
    }
}
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cargo test -p swarm-perch-bridge holds::
```

Expected: `file not found for module holds`.

- [ ] **Step 3: Implement the publisher and wire it.**

`crates/swarm-perch-bridge/src/holds.rs`:

```rust
//! The hold path: `RuntimeEvent::ResponseHeld` -> case channel -> card ->
//! `46010` -> `26006`, and the two in-process callbacks that tell the daemon
//! what the relay accepted. Runs in the PUBLISH task, never in `receive.rs`.

use std::sync::Arc;

use swarm_runtime::held_action::{HeldAction, HeldActionStore, HoldState};
use swarm_runtime::runtime_events::RuntimeEvent;
use uuid::Uuid;

use crate::cards::IssuerBlock;
use crate::channels::{CasePromotionTrigger, CaseRouting, HoldId, PublishStep};
use crate::error::BridgeError;
use crate::metrics::BridgeMetrics;

/// What one `ResponseHeld` becomes.
#[derive(Debug)]
pub enum HoldPlan {
    Steps(Vec<PublishStep>),
    /// Nothing is built. The reason is one of `no_operator_pubkey`,
    /// `no_hold_store`, `hold_not_found`.
    Undeliverable { hold_id: String, reason: &'static str },
}

/// Plans and acknowledges the hold sequence.
pub struct HoldPublisher {
    routing: CaseRouting,
    store: Option<Arc<dyn HeldActionStore>>,
    approve_pubkeys: Vec<String>,
    case_ttl_seconds: i32,
    issuer: IssuerBlock,
    metrics: BridgeMetrics,
}

impl HoldPublisher {
    /// Bundle the routing sidecar, the store handle and the Approve set.
    pub fn new(
        routing: CaseRouting,
        store: Option<Arc<dyn HeldActionStore>>,
        approve_pubkeys: Vec<String>,
        case_ttl_seconds: i32,
        issuer: IssuerBlock,
        metrics: BridgeMetrics,
    ) -> Self {
        Self { routing, store, approve_pubkeys, case_ttl_seconds, issuer, metrics }
    }

    /// The record behind a `ResponseHeld`, read from the daemon's store.
    fn record(&self, hold_id: &str) -> Result<Option<HeldAction>, BridgeError> {
        let Some(store) = &self.store else { return Ok(None) };
        store
            .get(hold_id)
            .map_err(|error| BridgeError::InvalidConfig { reason: format!("hold store read failed: {error}") })
    }

    /// Plan the sequence for one event. Only `ResponseHeld` is planned; any
    /// other variant returns an empty step list.
    pub fn plan(&mut self, event: &RuntimeEvent) -> Result<HoldPlan, BridgeError> {
        let RuntimeEvent::ResponseHeld { hold_id, hunt_id, state, .. } = event else {
            return Ok(HoldPlan::Steps(Vec::new()));
        };
        let hold_id = HoldId::parse(hold_id)?;
        if self.store.is_none() {
            self.metrics.hold_undeliverable("no_hold_store");
            return Ok(HoldPlan::Undeliverable { hold_id: hold_id.as_str().to_string(), reason: "no_hold_store" });
        }
        let Some(record) = self.record(hold_id.as_str())? else {
            self.metrics.hold_undeliverable("hold_not_found");
            return Ok(HoldPlan::Undeliverable { hold_id: hold_id.as_str().to_string(), reason: "hold_not_found" });
        };
        match state {
            HoldState::Created => {
                if self.approve_pubkeys.is_empty() {
                    // F18. A hold with no `p` tag reaches nobody; refusing is the
                    // honest failure and the queue header names the config key.
                    self.metrics.hold_undeliverable("no_operator_pubkey");
                    tracing::error!(module = module_path!(), hold_id = %hold_id.as_str(),
                        "no operator principal carries nostr_pubkey; refusing to publish a 46010 nobody is p-tagged on");
                    return Ok(HoldPlan::Undeliverable { hold_id: hold_id.as_str().to_string(), reason: "no_operator_pubkey" });
                }
                let trigger = CasePromotionTrigger::Held { hunt_id: hunt_id.clone(), hold_id: hold_id.as_str().to_string() };
                let (case, mut steps) = self.routing.ensure_case_channel(&trigger, &self.approve_pubkeys, self.case_ttl_seconds)?;
                steps.push(PublishStep::PublishHoldCard { channel: case, hold_id: hold_id.clone(), reply_to: None });
                steps.push(PublishStep::PublishHoldNotice { channel: case, hold_id: hold_id.clone(), card_event_id: None });
                steps.push(PublishStep::PublishAlarm { hold_id });
                Ok(HoldPlan::Steps(steps))
            }
            HoldState::Notified | HoldState::Armed | HoldState::Deciding => Ok(HoldPlan::Steps(Vec::new())),
            HoldState::Granted | HoldState::Refused | HoldState::Expired | HoldState::Executed | HoldState::Failed => {
                let Some(case) = record.case_channel.as_deref().and_then(|c| Uuid::parse_str(c).ok())
                    .or_else(|| self.routing.case_for_hunt(hunt_id)) else {
                    self.metrics.hold_undeliverable("no_case_channel");
                    return Ok(HoldPlan::Undeliverable { hold_id: hold_id.as_str().to_string(), reason: "no_case_channel" });
                };
                Ok(HoldPlan::Steps(vec![PublishStep::PublishHoldCard {
                    channel: case,
                    hold_id,
                    reply_to: record.card_event_id.clone(),
                }]))
            }
        }
    }

    /// Called by the publish task after the relay OKs a step (a `duplicate:
    /// channel already exists` OK counts). Writes the two callbacks through
    /// the store handle; failures are logged, never retried, because the relay
    /// already accepted the event and a replay would duplicate nothing.
    pub fn on_ok(&self, step: &PublishStep, event_id: &str, now_ms: i64) {
        let Some(store) = &self.store else { return };
        let result = match step {
            PublishStep::CreateCaseChannel { channel, .. } => {
                // Every hold routed to this channel learns it. The routing map
                // is keyed on hunt, so look the holds up through the store.
                store.list(false, usize::MAX).map(|holds| {
                    for hold in holds.iter().filter(|h| self.routing.case_for_hunt(&h.action_request.hunt_id.0) == Some(*channel)) {
                        let _ = store.mark_case_channel(&hold.hold_id, &channel.to_string());
                    }
                })
            }
            PublishStep::PublishHoldNotice { hold_id, card_event_id, .. } => {
                store.mark_notified(hold_id.as_str(), now_ms, event_id, card_event_id.as_deref())
            }
            _ => Ok(()),
        };
        if let Err(error) = result {
            tracing::error!(module = module_path!(), reason = %error, "hold callback failed; the daemon record is behind the relay");
        }
    }

    /// The issuer block for cards built from this publisher.
    pub fn issuer(&self) -> &IssuerBlock {
        &self.issuer
    }

    /// The Approve set, for the notice and alarm tag builders.
    pub fn approve_pubkeys(&self) -> &[String] {
        &self.approve_pubkeys
    }
}
```

`PublishStep::label()` returns the snake-case names the test asserts. In `publish.rs`, the drain of the `Alarm` stream calls `HoldPublisher::plan` for each `ResponseHeld` record, submits the steps in order through `ConnectionSupervisor::submit` on the `perch-alarm` identity (the card built with `cards::hold_card` from the store record at submit time, the notice with `hold_notice_tags` and `card_event_id` = the card's returned id, the alarm through the pacer bypass of Task 17), and calls `on_ok` after each accepted OK. The five steps are one spool record, so a crash between them replays the whole sequence; steps 1–2 are idempotent by construction and step 3's replay is deduplicated by event id because the card bytes are identical inside the publish window (`11` §10.4). `BridgeMetrics` gains `hold_undeliverable(reason: &'static str)` (`perch_bridge_hold_undeliverable_total{reason}`) and `for_test()`.

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-perch-bridge
cargo clippy -p swarm-perch-bridge --all-targets -- -D warnings
bash tools/check-workspace-layering.sh
```

Expected: green; `receive.rs` still imports only `stream`, `spool`, `metrics` (the module-boundary test T-1's neighbour asserts it).

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-perch-bridge
git commit -s -m "feat(swarm-perch-bridge): publish the case channel, hold card and notice for a held action and report back to the daemon"
```

---

## Task 17: Bridge — the `26006` alarm frame bypasses the pacer

**Files:**
- Modify: `crates/swarm-perch-bridge/src/cards.rs` (the frame body with the header)
- Modify: `crates/swarm-perch-bridge/src/pacer.rs` / `publish.rs` (the alarm lane)
- Test: `crates/swarm-perch-bridge/src/cards.rs` and `publish.rs` `mod tests` (T-15, T-21 amended)

**Interfaces:**
- Consumes: `swarm_perch_wire::frames::{FrameHeader, HoldAlarm}` (schema `swarm.perch.frame.hold_alarm.v1`), `PerchBridgeConfig.alarm_burst_per_min` (40).
- Produces:
  ```rust
  pub fn hold_alarm_frame(hold: &HeldAction, case_channel: &str, issuer: &str, seq: u64, emitted_at_ms: i64) -> serde_json::Value  // {schema, kind: 26006, issuer, emitted_at_ms, seq, hold_id, action_kind, severity, case_channel, expires_at_ms}
  impl ConnectionSupervisor { pub async fn submit_alarm(&mut self, event: nostr::Event) -> Result<(), BridgeError> }  // outside the 1 Hz tick, bounded by alarm_burst_per_min
  ```

- [ ] **Step 1: Write the failing tests.**

```rust
    #[test]
    fn the_alarm_frame_is_global_carries_p_only_and_exactly_the_ten_keys() {
        let hold = swarm_runtime::held_action::tests::fixture_hold(
            swarm_core::types::ResponseAction::IsolateHost { host_id: "host-ops-1".into() }, 1_773_738_882_600);
        let frame = hold_alarm_frame(&hold, "27799e23-ab25-4659-b381-3de47ea7ca4d", "swarm:ed25519:5fa3", 8, 1_773_738_882_610);
        let mut keys: Vec<&str> = frame.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["action_kind", "case_channel", "emitted_at_ms", "expires_at_ms", "hold_id", "issuer", "kind", "schema", "seq", "severity"]);
        assert_eq!(frame["schema"], "swarm.perch.frame.hold_alarm.v1");
        assert_eq!(frame["kind"], 26006);
        assert!(frame.get("hunt_id").is_none(), "hunt_id never rides the global frame");
        assert_eq!(frame["severity"], "CRITICAL");
    }

    #[tokio::test]
    async fn alarms_are_never_shed_while_evidence_is() {
        // T-15: fill the evidence spool to eviction while alarms flow; assert
        // zero alarm drops and that evidence shed instead.
        let harness = FakeRelayHarness::new().await;
        harness.fill_evidence_to_eviction(2_000).await;
        for i in 0..10 {
            harness.emit_alarm(i).await;
        }
        let snapshot = harness.metrics_snapshot();
        assert_eq!(snapshot.dropped("alarm"), 0);
        assert!(snapshot.dropped("evidence") > 0);
        assert_eq!(harness.relay_received_kind(26006).await, 10);
    }
```

`FakeRelayHarness` is the in-crate fake relay P0-18/P0-19 shipped for T-9 (`bridge_issues_no_req_frames`); extend it with `fill_evidence_to_eviction`, `emit_alarm` and `relay_received_kind`.

- [ ] **Step 2: Run and watch them fail.**

```bash
cargo test -p swarm-perch-bridge the_alarm_frame_is_global
cargo test -p swarm-perch-bridge alarms_are_never_shed
```

Expected: `cannot find function hold_alarm_frame`; the harness lacks the helpers.

- [ ] **Step 3: Implement.**

```rust
/// The `26006` body. Ten keys: the five-key frame header plus the five
/// payload keys `APPENDIX-NORMATIVE.md` §3 names. Built from a narrow struct
/// so no `RuntimeEvent` field can leak through a derive.
pub fn hold_alarm_frame(hold: &HeldAction, case_channel: &str, issuer: &str, seq: u64, emitted_at_ms: i64) -> serde_json::Value {
    let payload = HoldAlarm {
        hold_id: hold.hold_id.clone(),
        action_kind: hold.action_request.action.kind().to_string(),
        severity: severity_screaming(hold.action_request.severity).to_string(),
        case_channel: case_channel.to_string(),
        expires_at_ms: hold.expires_at_ms,
    };
    let mut value = serde_json::json!({
        "schema": "swarm.perch.frame.hold_alarm.v1",
        "kind": 26006,
        "issuer": issuer,
        "emitted_at_ms": emitted_at_ms,
        "seq": seq,
    });
    if let (Some(object), Ok(serde_json::Value::Object(fields))) = (value.as_object_mut(), serde_json::to_value(&payload)) {
        object.extend(fields);
    }
    value
}
```

In `publish.rs`, `submit_alarm` sends the signed ephemeral on the `perch-alarm` identity's socket immediately (no tick wait), guarded by a sliding one-minute window counter of `alarm_burst_per_min` (40); past the cap the alarm is queued for the next pacer tick and `perch_bridge_alarm_deferred_total` increments — deferred, never dropped. The alarm stream's spool never evicts: on `spool_max_bytes` the append refuses with `BridgeError::AlarmSpoolFull`, logs at `error` and increments `perch_bridge_alarm_spool_full_total` (F6), while the evidence spool sheds oldest-first exactly as P0-18 built it.

- [ ] **Step 4: Run.**

```bash
cargo test -p swarm-perch-bridge
```

Expected: green including T-9 (still zero `REQ`/`COUNT` frames) and T-11 (metric names).

- [ ] **Step 5: Commit.**

```bash
git add crates/swarm-perch-bridge
git commit -s -m "feat(swarm-perch-bridge): publish the global 26006 hold alarm outside the pacer, never shed"
```

---

## Task 18: Relay verification — the landed patches exercised end to end, plus the reconnect backfill constant

> Blocked on Task 1 (the live stack needs the dev profile to produce a hold).

**Files:**
- Create: `workspace/crates/ambush-test-client/tests/e2e_perch_hold_path.rs`
- Modify: `workspace/desktop/src-tauri/src/commands/channel_reconnect_repair.rs` (`CHANNEL_REPAIR_KINDS` `:6-8` and `repair_filter_is_fixed_and_keyset_scoped`)
- Verify: `workspace/crates/ambush-test-client/tests/e2e_workflow_approval.rs`, `e2e_operator_alarm_pgate.rs`

**Interfaces:**
- Consumes: `AmbushTestClient::{connect, send_event, subscribe, collect_until_eose, recv_event}` (`workspace/crates/ambush-test-client/src/lib.rs:90-212`), `nostr::{EventBuilder, Keys, Kind, Tag}`, the relay's `POST /query`.
- Produces: one E2E that proves the whole hold sequence is accepted by the re-landed relay in the order the bridge publishes it, and the desktop's paged reconnect repair fetches `46010`, `40100` and `39005`.

- [ ] **Step 1: Run the fourteen landed tests against a live stack.**

```bash
cd workspace && docker compose up -d relay postgres redis
RELAY_URL=ws://localhost:3001 cargo test -p ambush-test-client --test e2e_workflow_approval -- --ignored --nocapture
RELAY_URL=ws://localhost:3001 cargo test -p ambush-test-client --test e2e_operator_alarm_pgate -- --ignored --nocapture
```

Expected: 6 passed; 8 passed (tests 5–8 of the second binary assert the `h`-tag design that R-1 retracted; they pass because the relay code path they exercise still exists, and their module doc says they document the design not taken. Do not delete them).

- [ ] **Step 2: Write the failing hold-path E2E.**

`workspace/crates/ambush-test-client/tests/e2e_perch_hold_path.rs`:

```rust
//! The bridge's hold sequence, end to end, against a live relay:
//! 9007 -> 9000 -> kind:9 `swarm:hold:v1` -> 46010 -> 26006.
//!
//! RELAY_URL=ws://localhost:3001 cargo test -p ambush-test-client --test e2e_perch_hold_path -- --ignored --nocapture

use std::time::Duration;

use ambush_test_client::{AmbushTestClient, RelayMessage};
use nostr::{EventBuilder, Filter, Keys, Kind, Tag};

fn relay_url() -> String {
    std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:3001".to_string())
}

const HOLD_CARD: &str = "<!-- swarm:hold:v1 -->\nhold h_e2e00001 · isolate_host · CRITICAL · host host-ops-1 · expires 2026-03-17T10:14:42Z\n\n```swarm:hold:v1\n{\"schema\":\"swarm.spine.envelope.v1\",\"issuer\":\"swarm:ed25519:00\",\"seq\":1,\"prev_envelope_hash\":null,\"issued_at\":\"2026-03-17T09:14:42Z\",\"capability_token\":null,\"fact\":{\"schema\":\"swarm.perch.hold.v1\"},\"envelope_hash\":\"0x00\"}\n```";

#[tokio::test]
#[ignore]
async fn the_hold_sequence_is_accepted_in_publish_order_and_reaches_only_the_named_operator() {
    let bridge = Keys::generate();
    let operator_a = Keys::generate();
    let operator_b = Keys::generate();
    let case = uuid::Uuid::new_v4().to_string();

    let mut bridge_conn = AmbushTestClient::connect(&relay_url(), &bridge).await.unwrap();
    // 1. kind:9007 create-group with a client-supplied UUID and a ttl tag.
    let create = EventBuilder::new(Kind::Custom(9007), "")
        .tags([Tag::parse(["h", &case]).unwrap(), Tag::parse(["name", "case-e2e"]).unwrap(), Tag::parse(["visibility", "private"]).unwrap(), Tag::parse(["ttl", "2592000"]).unwrap()])
        .sign_with_keys(&bridge).unwrap();
    assert!(bridge_conn.send_event(create).await.unwrap().accepted);
    // 2. kind:9000 put-user for operator A only.
    let put_user = EventBuilder::new(Kind::Custom(9000), "")
        .tags([Tag::parse(["h", &case]).unwrap(), Tag::parse(["p", &operator_a.public_key().to_hex(), "member"]).unwrap()])
        .sign_with_keys(&bridge).unwrap();
    assert!(bridge_conn.send_event(put_user).await.unwrap().accepted);
    // 3. the kind:9 card.
    let card = EventBuilder::new(Kind::Custom(9), HOLD_CARD)
        .tags([Tag::parse(["h", &case]).unwrap(), Tag::parse(["k", "hold"]).unwrap()])
        .sign_with_keys(&bridge).unwrap();
    let card_id = card.id.to_hex();
    assert!(bridge_conn.send_event(card).await.unwrap().accepted);
    // 4. the 46010 notice: h, p, hold, card. Never e.
    let notice = EventBuilder::new(Kind::Custom(46010), "hold h_e2e00001 · isolate_host · CRITICAL · host host-ops-1 · expires 2026-03-17T10:14:42Z")
        .tags([
            Tag::parse(["h", &case]).unwrap(),
            Tag::parse(["p", &operator_a.public_key().to_hex()]).unwrap(),
            Tag::parse(["hold", "h_e2e00001"]).unwrap(),
            Tag::parse(["card", &card_id]).unwrap(),
        ])
        .sign_with_keys(&bridge).unwrap();
    assert!(bridge_conn.send_event(notice).await.unwrap().accepted);

    // Operator A: the needs-action query joins the mention row; B sees nothing.
    let http = reqwest::Client::new();
    let query = |pubkey: &Keys| {
        http.post(format!("{}/query", relay_url().replace("ws://", "http://")))
            .header("X-Pubkey", pubkey.public_key().to_hex())
            .json(&serde_json::json!([{ "kinds": [46010], "#p": [pubkey.public_key().to_hex()], "limit": 20 }]))
            .send()
    };
    let for_a: Vec<serde_json::Value> = query(&operator_a).await.unwrap().json().await.unwrap();
    assert_eq!(for_a.len(), 1);
    assert_eq!(for_a[0]["tags"].as_array().unwrap().iter().filter(|t| t[0] == "e").count(), 0);
    let for_b: Vec<serde_json::Value> = query(&operator_b).await.unwrap().json().await.unwrap();
    assert!(for_b.is_empty());

    // 5. the 26006 alarm, GLOBAL, p = A only. A's self-#p REQ receives it;
    //    B's self-#p REQ does not; a #p-less REQ is CLOSED.
    let mut a_conn = AmbushTestClient::connect(&relay_url(), &operator_a).await.unwrap();
    let mut b_conn = AmbushTestClient::connect(&relay_url(), &operator_b).await.unwrap();
    let mut anon = AmbushTestClient::connect(&relay_url(), &Keys::generate()).await.unwrap();
    a_conn.subscribe("alarm-a", vec![Filter::new().kind(Kind::Custom(26006)).custom_tag(nostr::SingleLetterTag::lowercase(nostr::Alphabet::P), [operator_a.public_key().to_hex()])]).await.unwrap();
    b_conn.subscribe("alarm-b", vec![Filter::new().kind(Kind::Custom(26006)).custom_tag(nostr::SingleLetterTag::lowercase(nostr::Alphabet::P), [operator_b.public_key().to_hex()])]).await.unwrap();
    anon.subscribe("alarm-anon", vec![Filter::new().kind(Kind::Custom(26006))]).await.unwrap();
    match anon.recv_event(Duration::from_secs(5)).await.unwrap() {
        RelayMessage::Closed { message, .. } => assert!(message.contains("p-gated")),
        other => panic!("expected CLOSED, got {other:?}"),
    }
    let alarm = EventBuilder::new(Kind::Custom(26006), r#"{"schema":"swarm.perch.frame.hold_alarm.v1","kind":26006,"issuer":"swarm:ed25519:00","emitted_at_ms":1,"seq":1,"hold_id":"h_e2e00001","action_kind":"isolate_host","severity":"CRITICAL","case_channel":"x","expires_at_ms":2}"#)
        .tags([Tag::parse(["p", &operator_a.public_key().to_hex()]).unwrap()])
        .sign_with_keys(&bridge).unwrap();
    assert!(bridge_conn.send_event(alarm).await.unwrap().accepted);
    match a_conn.recv_event(Duration::from_secs(5)).await.unwrap() {
        RelayMessage::Event { event, .. } => assert_eq!(event.kind, Kind::Custom(26006)),
        other => panic!("A expected the alarm, got {other:?}"),
    }
    assert!(b_conn.recv_event(Duration::from_secs(2)).await.is_err(), "B received an alarm it was not named on");
}
```

- [ ] **Step 3: Run it.**

```bash
cd workspace && RELAY_URL=ws://localhost:3001 cargo test -p ambush-test-client --test e2e_perch_hold_path -- --ignored --nocapture
```

Expected: passes against the re-landed relay. If step 4's `send_event` answers `restricted: unknown event kind`, the `46010` arm in `required_scope_for_kind` did not land (W3-7); stop and report against `11-PLAN-GROUND.md`.

- [ ] **Step 4: Extend the reconnect repair constant.**

`workspace/desktop/src-tauri/src/commands/channel_reconnect_repair.rs:6-8`:

```rust
const CHANNEL_REPAIR_KINDS: [u32; 18] = [
    5, 7, 9, 9005, 40001, 40002, 40003, 40008, 40099, 45001, 45003, 48100, 48101, 48102, 48103,
    // Perch (14 §5.3): the forked hold notice, the case canvas, the relay-signed
    // thread summary. Without these the keyset backfill after a long disconnect
    // fetches Ambush's fifteen kinds and silently drops a hold notice.
    46010, 40100, 39005,
];
```

and update the literal in `repair_filter_is_fixed_and_keyset_scoped` (`:74-96`) to the eighteen. Add a test in the same file asserting the three Perch kinds are members.

- [ ] **Step 5: Run and commit.**

```bash
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml channel_reconnect_repair
git add crates/ambush-test-client/tests/e2e_perch_hold_path.rs desktop/src-tauri/src/commands/channel_reconnect_repair.rs
git commit -s -m "test(relay): exercise the perch hold sequence end to end and widen the reconnect repair kinds"
```

Add the `--test e2e_perch_hold_path` invocation beside the two existing E2E lines in `.github/workflows/workspace-ci.yml` (the re-rooted chat CI).

---

## Task 19: Tauri — the daemon client and the two hold reads

**Files:**
- Create: `workspace/desktop/src-tauri/src/perch/mod.rs`, `perch/client.rs`, `perch/client_tests.rs`
- Create or extend: `workspace/desktop/src-tauri/src/commands/perch_reads.rs`
- Modify: `workspace/desktop/src-tauri/src/lib.rs` (`mod perch;`, two `generate_handler![]` entries), `commands/mod.rs` (`mod perch_reads; pub use perch_reads::*;`)
- Modify: `workspace/desktop/src-tauri/Cargo.toml` (`swarm-perch-wire = { path = "../../../crates/swarm-perch-wire", default-features = false }`)

**Interfaces:**
- Consumes: `SecretStore::shared(keyring_service())` with `load(key) -> Result<Option<String>, String>` (`secret_store.rs:549`) and `store(key, value)` (`:729`); `reqwest 0.13`; `AppState`.
- Produces:
  ```rust
  // perch/client.rs
  pub const DAEMON_BEARER_KEY: &str = "perch.daemon_bearer";       // keyring
  pub const DAEMON_BASE_URL_KEY: &str = "perch.daemon_base_url";   // keyring; env AMBUSH_PERCH_DAEMON_URL / AMBUSH_PERCH_DAEMON_TOKEN are the dev fallback
  pub enum PerchMethod { Get, Post }
  pub const PERCH_DAEMON_WRITES: [(PerchMethod, &str); 5]
  pub enum PerchClientError { NotOnWriteAllowlist { method: PerchMethod, template: String }, NotConfigured, Transport(String), Status { status: u16, error: String, message: String, retry_after: Option<u64> } }
  pub async fn perch_daemon_request(method: PerchMethod, template: &str, params: &[(&str, &str)], body: Option<serde_json::Value>, base_url: &str, token: &str) -> Result<(u16, serde_json::Value), PerchClientError>
  pub fn redact_for_ipc(message: &str, token: &str) -> String
  pub async fn daemon_credentials(state: &AppState) -> Result<(String, String), PerchClientError>   // (base_url, token); never returned across IPC
  // commands/perch_reads.rs
  #[tauri::command] pub async fn perch_list_holds(state) -> Result<serde_json::Value, String>     // GET /v1/response/holds?include_terminal=true
  #[tauri::command] pub async fn perch_get_hold(hold_id: String, state) -> Result<serde_json::Value, String>
  #[tauri::command] pub async fn perch_configure_daemon(base_url: String, bearer: String, state) -> Result<(), String>   // writes the two keyring keys; not daemon-bound
  ```
  Every error string crossing IPC passes through `redact_for_ipc`. Every request carries `Authorization: Bearer …` and `x-swarm-schema-version: 1`.

- [ ] **Step 1: Write the failing tests** — `perch/client_tests.rs` is the skeleton `tests/rust/buzz/perch_daemon_client_tests.rs` verbatim, with its `perch_daemon_request(method, path, body, base_url, token)` calls adjusted to `(method, template, &[], body, base_url, token)`; plus:

```rust
#[test]
fn a_template_param_is_substituted_and_a_traversal_in_a_param_is_refused() {
    let path = super::render_template("/v1/response/holds/{hold_id}/decide", &[("hold_id", "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13")]).unwrap();
    assert_eq!(path, "/v1/response/holds/hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13/decide");
    assert!(super::render_template("/v1/response/holds/{hold_id}/decide", &[("hold_id", "../../operator/control/mode")]).is_err());
}

#[test]
fn credentials_never_appear_in_a_get_result() {
    // The reads return the daemon body verbatim; the body cannot contain the
    // bearer because the daemon never echoes it — asserted structurally: the
    // typed return of every perch_* command is serde_json::Value or a struct
    // with no String field named `token`/`bearer`.
    let source = include_str!("../commands/perch_reads.rs");
    assert!(!source.contains("token:") && !source.contains("bearer:"), "a read command returns credential-shaped fields");
}
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml perch::client
```

Expected: `unresolved import perch`.

- [ ] **Step 3: Implement the client.**

`perch/client.rs`:

```rust
//! The console's ONLY path to the daemon. One dispatcher; every non-GET
//! template is checked against `PERCH_DAEMON_WRITES` before a socket opens
//! (INV-01); the bearer is read from the keyring here and never returned
//! (INV-22); every error string that can reach the webview is redacted.

use serde_json::Value;

use crate::app_state::AppState;
use crate::app_state_keyring::keyring_service;
use crate::secret_store::SecretStore;

pub const DAEMON_BEARER_KEY: &str = "perch.daemon_bearer";
pub const DAEMON_BASE_URL_KEY: &str = "perch.daemon_base_url";
const SCHEMA_VERSION_HEADER: &str = "x-swarm-schema-version";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerchMethod {
    Get,
    Post,
}

/// INV-01's closed set. Written out again in `client_tests.rs` on purpose.
pub const PERCH_DAEMON_WRITES: [(PerchMethod, &str); 5] = [
    (PerchMethod::Post, "/v1/response/holds/{hold_id}/decide"),
    (PerchMethod::Post, "/v1/operator/findings/{finding_id}/feedback"),
    (PerchMethod::Post, "/v1/operator/incidents"),
    (PerchMethod::Post, "/v1/operator/containment/leases/{lease_id}/release"),
    (PerchMethod::Post, "/v1/operator/review/sessions"),
];

#[derive(Debug)]
pub enum PerchClientError {
    NotOnWriteAllowlist { method: PerchMethod, template: String },
    NotConfigured,
    Transport(String),
    Status { status: u16, error: String, message: String, retry_after: Option<u64> },
}

impl std::fmt::Display for PerchClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotOnWriteAllowlist { method, template } => write!(f, "refused: {method:?} {template} is not on the console write allowlist"),
            Self::NotConfigured => write!(f, "the daemon is not configured: set the base URL and bearer in Settings, or AMBUSH_PERCH_DAEMON_URL / AMBUSH_PERCH_DAEMON_TOKEN in development"),
            Self::Transport(reason) => write!(f, "daemon unreachable: {reason}"),
            Self::Status { status, error, message, .. } => write!(f, "daemon answered {status} {error}: {message}"),
        }
    }
}

/// Substitute `{name}` segments. A value containing `/`, `..`, `?` or `#` is
/// refused, so a param cannot smuggle a path.
pub fn render_template(template: &str, params: &[(&str, &str)]) -> Result<String, PerchClientError> {
    let mut path = template.to_string();
    for (name, value) in params {
        if value.is_empty() || value.contains('/') || value.contains("..") || value.contains('?') || value.contains('#') {
            return Err(PerchClientError::NotOnWriteAllowlist { method: PerchMethod::Post, template: template.to_string() });
        }
        path = path.replace(&format!("{{{name}}}"), value);
    }
    if path.contains('{') {
        return Err(PerchClientError::Transport(format!("template {template} has an unfilled parameter")));
    }
    Ok(path)
}

/// Strip anything bearer-shaped, whether or not it is this process's token.
pub fn redact_for_ipc(message: &str, token: &str) -> String {
    let mut out = if token.is_empty() { message.to_string() } else { message.replace(token, "[redacted]") };
    // `bearer <token>` / `token=<token>` / `TOKEN=<token>` / a JSON "presented" field.
    for pattern in ["bearer ", "token=", "TOKEN=", "\"presented\":\""] {
        let mut cursor = 0;
        while let Some(start) = out[cursor..].to_ascii_lowercase().find(&pattern.to_ascii_lowercase()) {
            let value_start = cursor + start + pattern.len();
            let value_end = out[value_start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == ')' || c == ',')
                .map_or(out.len(), |i| value_start + i);
            if value_end > value_start && &out[value_start..value_end] != "[redacted]" {
                out.replace_range(value_start..value_end, "[redacted]");
            }
            cursor = value_start;
        }
    }
    out
}

/// The base URL and bearer, keyring first, dev env second. Never crosses IPC.
pub async fn daemon_credentials(_state: &AppState) -> Result<(String, String), PerchClientError> {
    let store = SecretStore::shared(keyring_service());
    let base_url = store.load(DAEMON_BASE_URL_KEY).ok().flatten().or_else(|| std::env::var("AMBUSH_PERCH_DAEMON_URL").ok());
    let token = store.load(DAEMON_BEARER_KEY).ok().flatten().or_else(|| std::env::var("AMBUSH_PERCH_DAEMON_TOKEN").ok());
    match (base_url, token) {
        (Some(base_url), Some(token)) if !base_url.trim().is_empty() && !token.trim().is_empty() => {
            Ok((base_url.trim_end_matches('/').to_string(), token))
        }
        _ => Err(PerchClientError::NotConfigured),
    }
}

/// One request. Returns `(status, body)`; a non-2xx is `Status` with the
/// daemon's `{error, message}` and `Retry-After` when present.
pub async fn perch_daemon_request(
    method: PerchMethod,
    template: &str,
    params: &[(&str, &str)],
    body: Option<Value>,
    base_url: &str,
    token: &str,
) -> Result<(u16, Value), PerchClientError> {
    if method != PerchMethod::Get && !PERCH_DAEMON_WRITES.iter().any(|(m, t)| *m == method && *t == template) {
        return Err(PerchClientError::NotOnWriteAllowlist { method, template: template.to_string() });
    }
    let path = render_template(template, params)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| PerchClientError::Transport(redact_for_ipc(&e.to_string(), token)))?;
    let url = format!("{base_url}{path}");
    let request = match method {
        PerchMethod::Get => client.get(&url),
        PerchMethod::Post => client.post(&url).json(&body.unwrap_or(Value::Null)),
    }
    .bearer_auth(token)
    .header(SCHEMA_VERSION_HEADER, "1");
    let response = request.send().await.map_err(|e| PerchClientError::Transport(redact_for_ipc(&e.to_string(), token)))?;
    let status = response.status().as_u16();
    let retry_after = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
    let value: Value = response.json().await.unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        return Ok((status, value));
    }
    Err(PerchClientError::Status {
        status,
        error: value["error"].as_str().unwrap_or("unknown").to_string(),
        message: redact_for_ipc(value["message"].as_str().unwrap_or(""), token),
        retry_after,
    })
}
```

`commands/perch_reads.rs`:

```rust
use tauri::State;

use crate::app_state::AppState;
use crate::perch::client::{PerchMethod, daemon_credentials, perch_daemon_request, redact_for_ipc};

const ROUTE_LIST_HOLDS: &str = "/v1/response/holds";
const ROUTE_GET_HOLD: &str = "/v1/response/holds/{hold_id}";

fn ipc_error(error: crate::perch::client::PerchClientError, token: &str) -> String {
    redact_for_ipc(&error.to_string(), token)
}

/// B2r. The queue's authority. Returns the daemon body verbatim.
#[tauri::command]
pub async fn perch_list_holds(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let (base_url, token) = daemon_credentials(&state).await.map_err(|e| e.to_string())?;
    perch_daemon_request(PerchMethod::Get, ROUTE_LIST_HOLDS, &[], None, &format!("{base_url}?include_terminal=true"), &token)
        .await
        .map(|(_, body)| body)
        .map_err(|e| ipc_error(e, &token))
}

/// B2r. One hold, for the verdict pane and for leg 1's card body.
#[tauri::command]
pub async fn perch_get_hold(hold_id: String, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    if !swarm_perch_wire::tags::is_opaque_hold_id(&hold_id) {
        return Err("hold_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$".to_string());
    }
    let (base_url, token) = daemon_credentials(&state).await.map_err(|e| e.to_string())?;
    perch_daemon_request(PerchMethod::Get, ROUTE_GET_HOLD, &[("hold_id", &hold_id)], None, &base_url, &token)
        .await
        .map(|(_, body)| body)
        .map_err(|e| ipc_error(e, &token))
}

/// Writes the daemon base URL and bearer into the keyring. Not daemon-bound.
#[tauri::command]
pub async fn perch_configure_daemon(base_url: String, bearer: String, _state: State<'_, AppState>) -> Result<(), String> {
    let store = crate::secret_store::SecretStore::shared(crate::app_state_keyring::keyring_service());
    store.store(crate::perch::client::DAEMON_BASE_URL_KEY, base_url.trim())?;
    store.store(crate::perch::client::DAEMON_BEARER_KEY, bearer.trim())
}
```

(The `include_terminal` query is appended to the base URL rather than the template so the template set stays exact; a cleaner `query: &[(&str, &str)]` parameter on `perch_daemon_request` is acceptable if added in the same commit with a test.)

- [ ] **Step 4: Run.**

```bash
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml perch
cd workspace && cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
```

Expected: green; `egress_guard_tests::events_url_inventory_is_fully_guarded` unchanged (the client never constructs a relay `/events` URL).

- [ ] **Step 5: Commit.**

```bash
cd workspace && git add desktop/src-tauri
git commit -s -m "feat(desktop): add the perch daemon client with the write allowlist and the two hold reads"
```

---

## Task 20: Tauri — `perch_decide_hold` (leg 2) and its 409 mapping

**Files:**
- Modify: `workspace/desktop/src-tauri/src/commands/perch_writes.rs` (fill `perch_decide_hold`; keep `PERCH_WRITE_ROUTES` at five)
- Modify: `workspace/desktop/src-tauri/src/lib.rs` (`generate_handler![]` entry)
- Test: `perch_writes.rs` `mod tests`

**Interfaces:**
- Consumes: `DecideHoldInput` and `DecideOutcome`/`DecideOutcomeKind` exactly as `build/skeleton/desktop/src-tauri/src/commands/perch_writes.rs` declares them; `perch_daemon_request`; `perch_get_hold`'s route for the 409 re-read (a GET, not on the allowlist).
- Produces: `perch_decide_hold(input, state) -> Result<DecideOutcome, String>` with the mapping: 200 → `Dispatched | RefusedLate | RefusedLateGovernance` from `decision.outcome`/`decision.refusal.rule`; 409 `decision_in_flight` → one retry after `Retry-After`, then `Sending`-still surfaced as `Err("decision_in_flight")`; 409 `hold_already_deciding` / `hold_already_decided` → re-read `GET /v1/response/holds/{hold_id}`, `Superseded { superseded_by: deciding_intent_event_id }` (W3-17); 409 `hold_expired` → `Expired`; 404 → `UnknownHold`.

- [ ] **Step 1: Write the failing tests** (the skeleton's three plus):

```rust
    #[test]
    fn a_409_with_another_intent_id_maps_to_superseded_after_a_re_read() {
        let body = serde_json::json!({ "hold": { "deciding_intent_event_id": "aa".repeat(32), "state": "refused", "decision": { "decision": "refuse", "decided_at_ms": 5 } } });
        let outcome = map_conflict("hold_already_decided", &"bb".repeat(32), &body);
        assert!(matches!(outcome.outcome, DecideOutcomeKind::Superseded));
        assert_eq!(outcome.superseded_by.as_deref(), Some("aa".repeat(32).as_str()));
    }

    #[test]
    fn a_200_refused_late_maps_the_rule_and_reason_verbatim() {
        let body = serde_json::json!({ "hold_id": "h_a07aeacf", "state": "refused", "replayed": false, "decision": {
            "outcome": "refused_late", "dispatched": false, "decided_at_ms": 7,
            "refusal": { "rule": "runtime.containment_refused", "reason": "no containment lease store is configured" } } });
        let outcome = map_success(&body);
        assert!(matches!(outcome.outcome, DecideOutcomeKind::RefusedLate));
        assert_eq!(outcome.reason.as_deref(), Some("no containment lease store is configured"));
        assert_eq!(outcome.rule.as_deref(), Some("runtime.containment_refused"));
        let governance = serde_json::json!({ "hold_id": "h", "state": "refused", "replayed": false, "decision": { "outcome": "refused_late", "dispatched": false, "decided_at_ms": 7, "refusal": { "rule": "governance.receipt_veto", "reason": "veto" } } });
        assert!(matches!(map_success(&governance).outcome, DecideOutcomeKind::RefusedLateGovernance));
    }
```

(`DecideOutcome` gains `pub rule: Option<String>` so the pane can quote the rule name separately from the reason.)

- [ ] **Step 2: Run and watch it fail.**

```bash
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml perch_writes
```

Expected: `cannot find function map_conflict`.

- [ ] **Step 3: Implement.**

```rust
fn map_success(body: &serde_json::Value) -> DecideOutcome {
    let decision = &body["decision"];
    let rule = decision["refusal"]["rule"].as_str().map(str::to_string);
    let reason = decision["refusal"]["reason"].as_str().map(str::to_string);
    let outcome = match decision["outcome"].as_str().unwrap_or("") {
        "granted_executed" | "granted_simulated" => DecideOutcomeKind::Dispatched,
        "granted_failed" => DecideOutcomeKind::RefusedLate,
        "refused_by_operator" => DecideOutcomeKind::Dispatched,
        _ if rule.as_deref().is_some_and(|r| r.starts_with("governance.")) => DecideOutcomeKind::RefusedLateGovernance,
        _ => DecideOutcomeKind::RefusedLate,
    };
    DecideOutcome {
        outcome,
        rule,
        reason,
        receipt_id: decision["receipt_id"].as_str().map(str::to_string),
        decided_at_ms: decision["decided_at_ms"].as_i64().unwrap_or_default(),
        superseded_by: None,
        replayed: body["replayed"].as_bool().unwrap_or(false),
    }
}

fn map_conflict(error: &str, own_intent: &str, re_read: &serde_json::Value) -> DecideOutcome {
    let winner = re_read["hold"]["deciding_intent_event_id"].as_str().unwrap_or_default().to_string();
    let superseded = matches!(error, "hold_already_deciding" | "hold_already_decided") && winner != own_intent;
    DecideOutcome {
        outcome: if superseded { DecideOutcomeKind::Superseded } else if error == "hold_expired" { DecideOutcomeKind::Expired } else { DecideOutcomeKind::UnknownHold },
        rule: Some(error.to_string()),
        reason: re_read["hold"]["decision"]["decision"].as_str().map(|d| format!("another operator's {d} was recorded first")),
        receipt_id: None,
        decided_at_ms: re_read["hold"]["decision"]["decided_at_ms"].as_i64().unwrap_or_default(),
        superseded_by: if superseded { Some(winner) } else { None },
        replayed: false,
    }
}

#[tauri::command]
pub async fn perch_decide_hold(input: DecideHoldInput, state: State<'_, AppState>) -> Result<DecideOutcome, String> {
    if !swarm_perch_wire::tags::is_opaque_hold_id(&input.hold_id) {
        return Err("hold_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$".to_string());
    }
    let (base_url, token) = daemon_credentials(&state).await.map_err(|e| e.to_string())?;
    let body = serde_json::json!({
        "decision": input.decision,
        "decided_at_ms": input.decided_at_ms,
        "nostr_intent_event_id": input.nostr_intent_event_id,
        "signature": input.signature,
        "rationale": input.rationale,
        "armed_at_ms": input.armed_at_ms,
    });
    let mut attempts = 0;
    loop {
        attempts += 1;
        match perch_daemon_request(PerchMethod::Post, ROUTE_DECIDE_HOLD, &[("hold_id", &input.hold_id)], Some(body.clone()), &base_url, &token).await {
            Ok((_, body)) => return Ok(map_success(&body)),
            Err(PerchClientError::Status { status: 409, error, retry_after, .. }) => {
                if error == "decision_in_flight" && attempts < 2 {
                    tokio::time::sleep(std::time::Duration::from_secs(retry_after.unwrap_or(1))).await;
                    continue;
                }
                if error == "decision_in_flight" {
                    return Err("decision_in_flight".to_string());
                }
                let (_, re_read) = perch_daemon_request(PerchMethod::Get, "/v1/response/holds/{hold_id}", &[("hold_id", &input.hold_id)], None, &base_url, &token)
                    .await
                    .map_err(|e| redact_for_ipc(&e.to_string(), &token))?;
                return Ok(map_conflict(&error, &input.nostr_intent_event_id, &re_read));
            }
            Err(PerchClientError::Status { status: 404, .. }) => {
                return Ok(DecideOutcome { outcome: DecideOutcomeKind::UnknownHold, rule: Some("not_found".into()), reason: None, receipt_id: None, decided_at_ms: input.decided_at_ms, superseded_by: None, replayed: false });
            }
            Err(error) => return Err(redact_for_ipc(&error.to_string(), &token)),
        }
    }
}
```

(A 422 or 403 reaches the renderer as `Err(String)` — those are client bugs, not outcomes, and the write machine renders them as `daemon_refused_request` with the redacted message.)

- [ ] **Step 4: Run and commit.**

```bash
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml perch_writes && bash ../tools/check-perch-write-allowlist.sh
git add desktop/src-tauri && git commit -s -m "feat(desktop): implement perch_decide_hold with the 409 re-read and typed outcomes"
```

---

## Task 21: Tauri — `perch_record_verdict` (leg 1) and the operator's Ed25519 key

> Steps 3–4 are blocked on Task 2 (written against option (a)).

**Files:**
- Create: `workspace/desktop/src-tauri/src/commands/perch_verdict.rs`
- Modify: `workspace/desktop/src-tauri/src/lib.rs`, `commands/mod.rs`
- Test: `perch_verdict.rs` `mod tests`; `perch_marker_guard_tests.rs` (the H2 builder test, un-gated now that the module exists)

**Interfaces:**
- Consumes: `state.signing_keys()` (`app_state.rs:278-291`, the Nostr secp256k1 identity), `SecretStore::{load, store}`, `ed25519-dalek 3.0.0-rc.0` (`SigningKey::from_bytes`, `Signer::sign`, `VerifyingKey::to_bytes`), `sha2 0.11`, `swarm_perch_wire::verdict::{decision_preimage_bytes, rationale_sha256_hex}`, `crate::relay::submit::submit_event_at_created_at` (the funnel `send_channel_message` lands in, `relay/submit.rs:97`; it already runs `perch_marker_guard` — this command's card must pass through a **second** funnel, `submit_governance_event`, that is the one caller allowed to bypass the marker guard and is asserted by the inventory test).
- Produces:
  ```rust
  pub const OPERATOR_ED25519_SECRET_KEY: &str = "perch.operator_ed25519";   // 64-hex seed in the keyring
  pub const PERCH_RELAY_PUBLISHED_KINDS: [u32; 1] = [9];
  pub const PERCH_RELAY_PUBLISHED_MARKERS: [&str; 1] = ["swarm:verdict:v1"];
  #[tauri::command] pub async fn perch_operator_identity(state) -> Result<OperatorIdentityOutput, String>   // { public_key_hex, key_id } — mints on first call
  #[tauri::command] pub async fn perch_record_verdict(input: RecordVerdictInput, state) -> Result<RecordVerdictOutput, String>
  pub fn build_verdict_card(hold: &serde_json::Value, case_channel: &str, decision: VerdictDecision, decided_at_ms: i64, rationale: Option<&str>, operator_id: &str, nostr_pubkey: &str, signature: &DetachedSignature) -> String   // the three-part body
  ```
  `DetachedSignature.key_id` is `sha256(public_key_bytes)` as lowercase hex — `swarm_crypto::verify_detached_signature` (`crates/swarm-crypto/src/lib.rs:130-150`) refuses any other `key_id`, and the wire schema's example `key_id: "perch-operator-1"` would fail verification (flagged in the summary).

- [ ] **Step 1: Write the failing tests.**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn hold_fixture() -> serde_json::Value {
        serde_json::json!({ "hold": {
            "hold_id": "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13", "state": "notified",
            "case_channel": "27799e23-ab25-4659-b381-3de47ea7ca4d", "card_event_id": "b9".repeat(32),
            "action_kind": "isolate_host", "severity": "CRITICAL", "expires_at_ms": 1_773_742_482_600,
            "action_request": { "action": { "type": "isolate_host", "host_id": "host-ops-1" } },
            "rehearsal": null, "remaining_ms": 1000, "expired": false
        } })
    }

    #[test]
    fn the_operator_key_publishes_exactly_one_kind_and_one_marker() {
        assert_eq!(PERCH_RELAY_PUBLISHED_KINDS, [9]);
        assert_eq!(PERCH_RELAY_PUBLISHED_MARKERS, ["swarm:verdict:v1"]);
    }

    #[test]
    fn the_signature_verifies_under_swarm_crypto_rules_and_key_id_is_sha256_of_the_pubkey() {
        let seed = [7u8; 32];
        let signature = sign_decision(&seed, 5, VerdictDecision::Grant, "h_a07aeacf", None);
        assert_eq!(signature.algorithm, "ed25519");
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let expected_key_id = sha256_hex_of(&key.verifying_key().to_bytes());
        assert_eq!(signature.key_id, expected_key_id);
        assert_eq!(signature.public_key_hex, hex::encode(key.verifying_key().to_bytes()));
        let preimage = swarm_perch_wire::verdict::decision_preimage_bytes(5, "grant", "h_a07aeacf", None);
        let sig = ed25519_dalek::Signature::from_slice(&hex::decode(&signature.signature_hex).unwrap()).unwrap();
        key.verifying_key().verify_strict(&preimage, &sig).unwrap();
    }

    #[test]
    fn the_card_body_is_three_parts_and_the_generic_signer_refuses_it() {
        let signature = sign_decision(&[7u8; 32], 1_773_738_979_000, VerdictDecision::Grant, "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13", Some("two detectors agree"));
        let body = build_verdict_card(&hold_fixture()["hold"], "27799e23-ab25-4659-b381-3de47ea7ca4d", VerdictDecision::Grant, 1_773_738_979_000, Some("two detectors agree"), "perch-dev-operator", &"68".repeat(32), &signature);
        let lines: Vec<&str> = body.split('\n').collect();
        assert_eq!(lines[0], "<!-- swarm:verdict:v1 -->");
        assert!(lines[1].starts_with("verdict grant · hold hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13 · isolate_host · by perch-dev-operator"));
        assert_eq!(lines[2], "");
        assert_eq!(lines[3], "```swarm:verdict:v1");
        let json: serde_json::Value = serde_json::from_str(lines[4]).unwrap();
        assert_eq!(json["fact"]["schema"], "swarm.perch.verdict.v1");
        assert_eq!(json["fact"]["decision"]["decision"], "grant");
        assert_eq!(json["fact"]["locator"]["hold_card_id"], "b9".repeat(32));
        assert_eq!(json["fact"]["leg2"]["state"], "sending");
        assert_eq!(json["fact"]["signature"]["signature_hex"], signature.signature_hex);
        assert!(crate::perch_marker_guard::perch_sign_gate(9, &body).is_err(), "sign_event must refuse what perch_record_verdict publishes");
    }

    #[test]
    fn a_hold_that_is_not_decidable_or_has_no_case_channel_is_refused_locally() {
        let mut expired = hold_fixture();
        expired["hold"]["expired"] = serde_json::Value::Bool(true);
        assert!(matches!(assert_decidable(&expired["hold"]), Err(reason) if reason.contains("expired")));
        let mut no_channel = hold_fixture();
        no_channel["hold"]["case_channel"] = serde_json::Value::Null;
        assert!(matches!(assert_decidable(&no_channel["hold"]), Err(reason) if reason.contains("case channel")));
    }
}
```

- [ ] **Step 2: Run and watch them fail.**

```bash
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml perch_verdict
```

Expected: `unresolved import perch_verdict`.

- [ ] **Step 3: The key (Task 2 option (a)).**

```rust
pub const OPERATOR_ED25519_SECRET_KEY: &str = "perch.operator_ed25519";

fn sha256_hex_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Load the operator's Ed25519 seed from the keyring, minting one on first use.
/// The seed never leaves this function's callers; only the public half crosses IPC.
fn operator_seed() -> Result<[u8; 32], String> {
    let store = crate::secret_store::SecretStore::shared(crate::app_state_keyring::keyring_service());
    if let Some(hex_seed) = store.load(OPERATOR_ED25519_SECRET_KEY)? {
        let bytes = hex::decode(hex_seed.trim()).map_err(|e| format!("operator key is corrupt: {e}"))?;
        return bytes.try_into().map_err(|_| "operator key is not 32 bytes".to_string());
    }
    if let Ok(dev_seed) = std::env::var("AMBUSH_PERCH_OPERATOR_SEED") {
        let bytes = hex::decode(dev_seed.trim()).map_err(|e| format!("AMBUSH_PERCH_OPERATOR_SEED is not hex: {e}"))?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| "AMBUSH_PERCH_OPERATOR_SEED is not 32 bytes".to_string())?;
        store.store(OPERATOR_ED25519_SECRET_KEY, &hex::encode(seed))?;
        return Ok(seed);
    }
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    store.store(OPERATOR_ED25519_SECRET_KEY, &hex::encode(seed))?;
    Ok(seed)
}

/// Sign the four-member preimage. `key_id` is sha256(pubkey), which is what
/// `swarm_crypto::verify_detached_signature` checks.
fn sign_decision(seed: &[u8; 32], decided_at_ms: i64, decision: VerdictDecision, hold_id: &str, rationale: Option<&str>) -> DetachedSignature {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    let digest = swarm_perch_wire::verdict::rationale_sha256_hex(rationale);
    let preimage = swarm_perch_wire::verdict::decision_preimage_bytes(decided_at_ms, decision.as_str(), hold_id, digest.as_deref());
    let public = key.verifying_key().to_bytes();
    DetachedSignature {
        algorithm: "ed25519".to_string(),
        key_id: sha256_hex_of(&public),
        public_key_hex: hex::encode(public),
        signature_hex: hex::encode(key.sign(&preimage).to_bytes()),
    }
}

#[derive(Debug, Serialize)]
pub struct OperatorIdentityOutput {
    pub public_key_hex: String,
    pub key_id: String,
}

/// The public half, for the operator to paste into the daemon's principal entry.
#[tauri::command]
pub async fn perch_operator_identity(_state: State<'_, AppState>) -> Result<OperatorIdentityOutput, String> {
    let seed = operator_seed()?;
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    Ok(OperatorIdentityOutput { public_key_hex: hex::encode(public), key_id: sha256_hex_of(&public) })
}
```

- [ ] **Step 4: The command.**

```rust
fn assert_decidable(hold: &serde_json::Value) -> Result<(String, String), String> {
    if hold["expired"].as_bool().unwrap_or(true) {
        return Err("this hold has expired; the daemon will refuse it and no card is published".to_string());
    }
    match hold["state"].as_str().unwrap_or("") {
        "created" | "notified" | "armed" => {}
        state => return Err(format!("this hold is `{state}` and cannot be decided")),
    }
    let case_channel = hold["case_channel"].as_str().filter(|c| !c.is_empty())
        .ok_or_else(|| "this hold has no case channel yet; the bridge has not filed it, so there is nowhere to publish the intent card".to_string())?;
    let hold_id = hold["hold_id"].as_str().ok_or_else(|| "hold record carries no hold_id".to_string())?;
    Ok((hold_id.to_string(), case_channel.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub fn build_verdict_card(hold: &serde_json::Value, case_channel: &str, decision: VerdictDecision, decided_at_ms: i64, rationale: Option<&str>, operator_id: &str, nostr_pubkey: &str, signature: &DetachedSignature) -> String {
    let hold_id = hold["hold_id"].as_str().unwrap_or_default();
    let action_kind = hold["action_kind"].as_str().unwrap_or_default();
    let human = format!("verdict {} · hold {hold_id} · {action_kind} · by {operator_id}", decision.as_str());
    let fact = serde_json::json!({
        "schema": "swarm.perch.verdict.v1",
        "issuer": { "swarm_agent_id": operator_id, "role": null, "nostr_pubkey": nostr_pubkey },
        "emitted_at_ms": decided_at_ms,
        "locator": { "hold_id": hold_id, "case_channel": case_channel, "hold_card_id": hold["card_event_id"] },
        "decision": { "decision": decision.as_str(), "hold_id": hold_id, "decided_at_ms": decided_at_ms, "operator_id": operator_id, "rationale": rationale },
        "signature": signature,
        "leg2": { "state": "sending", "receipt_id": null, "refusal_check": null, "superseded_by": null, "superseded_at_ms": null }
    });
    let envelope = serde_json::json!({
        "schema": "swarm.spine.envelope.v1",
        "issuer": format!("swarm:ed25519:{}", signature.public_key_hex),
        "seq": 1, "prev_envelope_hash": null,
        "issued_at": chrono::DateTime::from_timestamp_millis(decided_at_ms).map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default(),
        "capability_token": null,
        "fact": fact,
        "envelope_hash": swarm_perch_wire::envelope::keyless_envelope_hash(&fact),
    });
    format!("<!-- swarm:verdict:v1 -->\n{human}\n\n```swarm:verdict:v1\n{envelope}\n```")
}

/// Leg 1. GET the hold; refuse locally unless decidable; stamp the clock; sign
/// the preimage with the operator's Ed25519 key; build the card from the
/// daemon's answer; sign the kind:9 with the Nostr identity; publish with `h`
/// and no `e`; return exactly three values. Never calls the decide route.
#[tauri::command]
pub async fn perch_record_verdict(input: RecordVerdictInput, state: State<'_, AppState>) -> Result<RecordVerdictOutput, String> {
    if !swarm_perch_wire::tags::is_opaque_hold_id(&input.hold_id) {
        return Err("hold_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$".to_string());
    }
    let (base_url, token) = crate::perch::client::daemon_credentials(&state).await.map_err(|e| e.to_string())?;
    let (_, detail) = crate::perch::client::perch_daemon_request(crate::perch::client::PerchMethod::Get, ROUTE_GET_HOLD, &[("hold_id", &input.hold_id)], None, &base_url, &token)
        .await
        .map_err(|e| crate::perch::client::redact_for_ipc(&e.to_string(), &token))?;
    let hold = &detail["hold"];
    let (hold_id, case_channel) = assert_decidable(hold)?;
    let decided_at_ms = chrono::Utc::now().timestamp_millis();
    let seed = operator_seed()?;
    let signature = sign_decision(&seed, decided_at_ms, input.decision, &hold_id, input.rationale.as_deref());
    let keys = state.signing_keys()?;
    let operator_id = std::env::var("AMBUSH_PERCH_OPERATOR_ID").unwrap_or_else(|_| "operator".to_string());
    let content = build_verdict_card(hold, &case_channel, input.decision, decided_at_ms, input.rationale.as_deref(), &operator_id, &keys.public_key().to_hex(), &signature);
    let tags = vec![vec!["h".to_string(), case_channel.clone()], vec!["k".to_string(), "verdict".to_string()]];
    let event_id = crate::relay::submit::submit_governance_event(&state, 9, &content, tags, &keys).await?;
    Ok(RecordVerdictOutput { nostr_intent_event_id: event_id, decided_at_ms, signature })
}
```

`submit_governance_event` is a new function in `relay/submit.rs` beside `submit_event_at_created_at` (`:97`): it builds the event with `EventBuilder::new(Kind::Custom(kind), content).tags(...)`, signs with `keys`, runs `egress_guard::assert_no_key_backup_bytes` (boundary 1) and **does not** run `perch_marker_guard`; the inventory test `perch_marker_guard_call_sites_match_egress_guard` gains `relay/submit.rs::submit_governance_event` as its one declared exemption, with `PERCH_RELAY_PUBLISHED_MARKERS` asserted to be its only content producer (a test that greps the file for callers of `submit_governance_event` and finds exactly `perch_verdict.rs` twice — leg 1 and Task 27's `superseded` update). `AMBUSH_PERCH_OPERATOR_ID` is a dev convenience; the daemon derives the real operator id from the bearer and the card's `operator_id` is display only. `swarm_perch_wire::envelope::keyless_envelope_hash` is P1-26's `compute_envelope_hash_hex` mirror.

- [ ] **Step 5: Run.**

```bash
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml perch_verdict
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml perch_marker_guard
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml egress_guard
```

Expected: green; the H2 inventory test now compiles its builder half (the skeleton's `#[cfg(feature = "perch-writes")]` gate is removed).

- [ ] **Step 6: Commit.**

```bash
cd workspace && git add desktop/src-tauri
git commit -s -m "feat(desktop): add perch_record_verdict, the leg-1 card built from daemon-fetched hold state"
```

---

## Task 22: E2E — the delegated perch module learns holds, decisions and the alarm control seam

**Files:**
- Modify: `workspace/desktop/src/testing/perch/e2ePerchBridge.ts`
- Modify: `workspace/desktop/src/testing/e2eBridge.ts` (four lines: `26006` in `P_GATED_KINDS` at `:5324-5330`; `installPerchControlSeams({ emitGlobalEvent: emitMockGlobalEvent, emitChannelEvent: emitMockLiveEvent })` beside the `startsWith("perch_")` guard)
- Modify: `workspace/desktop/tests/helpers/perchBridge.ts` (extend First card's helper from `build/skeleton/tests/playwright/helpers/perchBridge.ts`, `__BUZZ_E2E_*` → `__AMBUSH_E2E_*`; retain its one-call install contract)
- Modify: `workspace/desktop/tests/helpers/features.ts`, `tests/helpers/bridge.ts` (`seedPreviewFeaturesEnabled` skips `E2E_OPT_IN_FEATURES` unless the spec passes `enableFeatures`)
- Test: `workspace/desktop/src/testing/perch/e2ePerchBridge.test.mjs`

**Interfaces:**
- Consumes: `emitMockGlobalEvent(event)` (`e2eBridge.ts:4805-4820`, delivers to every subscription whose kinds match), `emitMockLiveEvent(channelId, event)` (`:4777`), `isPGatedFilterAuthorized` (`:5340`), `PERCH_TAURI_COMMANDS` from `tauriPerch.ts`.
- Produces:
  ```ts
  export function handlePerchMockCommand(command: string, payload: unknown): Promise<unknown>;
  export function installPerchControlSeams(seams: { emitGlobalEvent: (event: RelayEvent) => void; emitChannelEvent: (channelId: string, event: RelayEvent) => void }): void;
  // window.__AMBUSH_E2E_PERCH__ (fixture) and window.__AMBUSH_E2E_PERCH_CONTROL__ = { emitEphemeral(frame), advanceClock(ms) }
  ```
  Mock answers: `perch_list_holds` → `HoldListResponse` from the fixture with `remaining_ms`/`expired` computed against the frozen clock; `perch_get_hold` → `HoldDetailResponse` or a thrown `daemon answered 404 not_found: no hold`; `perch_record_verdict` → `{nostr_intent_event_id, decided_at_ms, signature}` and a kind:9 `swarm:verdict:v1` event delivered into the case channel through `emitChannelEvent`; `perch_decide_hold` → the fixture's `decide[hold_id]` outcome after `delay_ms`; `perch_operator_identity` → a fixed pubkey.

- [ ] **Step 1: Write the failing node test.**

`e2ePerchBridge.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { handlePerchMockCommand, installPerchControlSeams, seedPerchFixture } from "./e2ePerchBridge.ts";

const HOLD = { hold_id: "h_a07aeacf", action_kind: "isolate_host", severity: "CRITICAL", case_channel: "27799e23-ab25-4659-b381-3de47ea7ca4d", held_at_ms: 1_773_738_882_600, expires_at_ms: 1_773_742_482_600, state: "notified", containment_lease_id: null, every_step_reversible: true, rationale: { rule_name: "static.human_gate", reason: "authorized but held for human approval" }, partition_state_at_hold: "healthy" };

test("perch_list_holds derives the two clock facts from the frozen clock", async () => {
  seedPerchFixture({ holds: [HOLD], containments: [], decide: {}, relayOnlyHoldIds: [], storeDurable: false, admittedIssuers: [], nowMs: 1_773_739_200_000 });
  const body = await handlePerchMockCommand("perch_list_holds", null);
  assert.equal(body.holds[0].remaining_ms, 1_773_742_482_600 - 1_773_739_200_000);
  assert.equal(body.holds[0].expired, false);
  assert.equal(body.store_durable, false);
  assert.equal(body.open_count, 1);
  globalThis.window.__AMBUSH_E2E_PERCH_CONTROL__.advanceClock(3_600_000);
  const later = await handlePerchMockCommand("perch_list_holds", null);
  assert.equal(later.holds[0].expired, true);
  assert.equal(later.holds[0].state, "expired");
});

test("perch_decide_hold answers the fixture outcome and superseded carries the winner", async () => {
  seedPerchFixture({ holds: [HOLD], containments: [], decide: { h_a07aeacf: { outcome: "superseded", rule: "hold_already_decided", reason: "another operator's decision was recorded first", receipt_id: null, superseded_by: "aa".repeat(32) } }, relayOnlyHoldIds: [], storeDurable: false, admittedIssuers: [], nowMs: 1 });
  const outcome = await handlePerchMockCommand("perch_decide_hold", { input: { holdId: "h_a07aeacf", decision: "grant", rationale: null, decidedAtMs: 1, nostrIntentEventId: "bb".repeat(32), signature: { algorithm: "ed25519", key_id: "k", public_key_hex: "cc".repeat(32), signature_hex: "dd".repeat(64) }, armedAtMs: null } });
  assert.equal(outcome.outcome, "superseded");
  assert.equal(outcome.superseded_by, "aa".repeat(32));
});

test("every perch command has a handler", async () => {
  const { PERCH_TAURI_COMMANDS } = await import("../../shared/api/tauriPerch.ts");
  for (const command of PERCH_TAURI_COMMANDS) {
    await assert.doesNotReject(handlePerchMockCommand(command, {}), `no handler for ${command}`);
  }
});

test("emitEphemeral delivers a 26006 through the global seam with the issuer as pubkey", () => {
  const delivered = [];
  installPerchControlSeams({ emitGlobalEvent: (event) => delivered.push(event), emitChannelEvent: () => {} });
  globalThis.window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral({ kind: 26006, pubkey: "20".repeat(32), payload: { hold_id: "h_a07aeacf" } });
  assert.equal(delivered.length, 1);
  assert.equal(delivered[0].kind, 26006);
  assert.equal(delivered[0].pubkey, "20".repeat(32));
  assert.equal(JSON.parse(delivered[0].content).hold_id, "h_a07aeacf");
});
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/testing/perch/e2ePerchBridge.test.mjs
```

Expected: `seedPerchFixture is not exported` (First card shipped the module with the finding arms only).

- [ ] **Step 3: Implement the arms.**

Append to `e2ePerchBridge.ts`:

```ts
import type { RelayEvent } from "@/shared/api/types";
import { PERCH_TAURI_COMMANDS } from "@/shared/api/tauriPerch";

type PerchFixture = import("../../../tests/helpers/perchBridge").PerchFixture;

let fixture: PerchFixture = defaultFixtureFromDemo();
let clockOffsetMs = 0;
const decidedIntentIds = new Map<string, string>();
let seams: { emitGlobalEvent: (event: RelayEvent) => void; emitChannelEvent: (channelId: string, event: RelayEvent) => void } | null = null;

export function seedPerchFixture(next: PerchFixture): void {
  fixture = next;
  clockOffsetMs = 0;
  decidedIntentIds.clear();
}

function nowMs(): number {
  return fixture.nowMs + clockOffsetMs;
}

function holdView(hold: PerchFixture["holds"][number]) {
  const now = nowMs();
  const expired = hold.state === "expired" || now >= hold.expires_at_ms;
  return {
    hold_id: hold.hold_id,
    state: expired && (hold.state === "notified" || hold.state === "created" || hold.state === "armed") ? "expired" : hold.state,
    notified_at_ms: hold.state === "created" ? null : hold.held_at_ms + 10,
    deciding_intent_event_id: decidedIntentIds.get(hold.hold_id) ?? null,
    case_channel: hold.case_channel,
    notice_event_id: "02".repeat(32),
    card_event_id: "b9".repeat(32),
    action_kind: hold.action_kind,
    severity: hold.severity,
    held_at_ms: hold.held_at_ms,
    expires_at_ms: hold.expires_at_ms,
    remaining_ms: Math.max(0, hold.expires_at_ms - now),
    expired,
    action_request: { hunt_id: "hunt-evt-1", requested_by: "swarm:ed25519:" + "18".repeat(32), action: actionFor(hold.action_kind), severity: hold.severity, evidence: { escalation: { threat_class: "execution" } } },
    policy_decision: { verdict: "require_human", rule_name: hold.rationale.rule_name, reason: hold.rationale.reason },
    rationale: { ...hold.rationale, threat_class: "execution", severity: hold.severity, request_carried_fields: ["severity", "threat_class"], concentration_at_hold: null, escalation_level: "alert", governance_receipt_present: false },
    leases_a_containment: hold.containment_lease_id !== null,
    rehearsal: hold.containment_lease_id ? rehearsalFor(hold.action_kind) : null,
    inverse_resolution: hold.containment_lease_id ? [{ step_kind: "RestoreHostConnectivity", verdict: hold.every_step_reversible ? "executable" : "irreversible", reason: hold.every_step_reversible ? null : "a terminated session cannot be resumed; the principal can only establish a fresh session", derived_by: "swarm_response::rollback::resolve_inverse" }] : [],
    decision: null,
  };
}

export async function handlePerchMockCommand(command: string, payload: unknown): Promise<unknown> {
  const args = (payload ?? {}) as Record<string, unknown>;
  switch (command) {
    case "perch_list_holds": {
      const holds = fixture.holds.map(holdView);
      return { schema_version: 1, observed_at_ms: nowMs(), holds, open_count: holds.filter((h) => ["created", "notified", "armed"].includes(h.state)).length, truncated: false, deciding_stalled_count: 0, store_durable: fixture.storeDurable };
    }
    case "perch_get_hold": {
      const hold = fixture.holds.find((h) => h.hold_id === args.holdId);
      if (!hold) throw new Error(`daemon answered 404 not_found: no hold \`${String(args.holdId)}\``);
      return { schema_version: 1, observed_at_ms: nowMs(), hold: holdView(hold) };
    }
    case "perch_operator_identity":
      return { public_key_hex: "bc".repeat(32), key_id: "ef".repeat(32) };
    case "perch_record_verdict": {
      const input = args.input as { holdId: string; decision: "grant" | "refuse"; rationale: string | null };
      const hold = fixture.holds.find((h) => h.hold_id === input.holdId);
      if (!hold) throw new Error("daemon answered 404 not_found");
      const eventId = randomHex64();
      const content = `<!-- swarm:verdict:v1 -->\nverdict ${input.decision} · hold ${hold.hold_id} · ${hold.action_kind} · by operator\n\n\`\`\`swarm:verdict:v1\n${JSON.stringify({ schema: "swarm.spine.envelope.v1", fact: { schema: "swarm.perch.verdict.v1", locator: { hold_id: hold.hold_id, case_channel: hold.case_channel, hold_card_id: "b9".repeat(32) }, decision: { decision: input.decision, hold_id: hold.hold_id, decided_at_ms: nowMs(), operator_id: "operator", rationale: input.rationale }, signature: { algorithm: "ed25519", key_id: "ef".repeat(32), public_key_hex: "bc".repeat(32), signature_hex: "dd".repeat(64) }, leg2: { state: "sending", receipt_id: null, refusal_check: null, superseded_by: null, superseded_at_ms: null } } })}\n\`\`\``;
      seams?.emitChannelEvent(hold.case_channel, { id: eventId, pubkey: "68".repeat(32), created_at: Math.floor(nowMs() / 1000), kind: 9, tags: [["h", hold.case_channel], ["k", "verdict"]], content, sig: "00".repeat(64) });
      return { nostr_intent_event_id: eventId, decided_at_ms: nowMs(), signature: { algorithm: "ed25519", key_id: "ef".repeat(32), public_key_hex: "bc".repeat(32), signature_hex: "dd".repeat(64) } };
    }
    case "perch_decide_hold": {
      const input = args.input as { holdId: string; nostrIntentEventId: string };
      const scripted = fixture.decide[input.holdId];
      if (scripted?.delay_ms) await new Promise((r) => setTimeout(r, scripted.delay_ms));
      const outcome = scripted ?? { outcome: "dispatched", rule: null, reason: null, receipt_id: "receipt-mock", superseded_by: null };
      decidedIntentIds.set(input.holdId, outcome.outcome === "superseded" ? (outcome.superseded_by ?? "") : input.nostrIntentEventId);
      return { outcome: outcome.outcome, rule: outcome.rule, reason: outcome.reason, receipt_id: outcome.receipt_id, decided_at_ms: nowMs(), superseded_by: outcome.superseded_by ?? null, replayed: false };
    }
    default:
      return handleFirstCardPerchCommand(command, payload); // the finding arms First card shipped
  }
}

export function installPerchControlSeams(next: NonNullable<typeof seams>): void {
  seams = next;
  (window as unknown as { __AMBUSH_E2E_PERCH_CONTROL__: unknown }).__AMBUSH_E2E_PERCH_CONTROL__ = {
    emitEphemeral(frame: { kind: number; pubkey: string; payload: unknown }) {
      next.emitGlobalEvent({ id: randomHex64(), pubkey: frame.pubkey, created_at: Math.floor(nowMs() / 1000), kind: frame.kind, tags: [["p", "68".repeat(32)]], content: JSON.stringify(frame.payload), sig: "00".repeat(64) });
    },
    advanceClock(deltaMs: number) {
      clockOffsetMs += deltaMs;
      window.dispatchEvent(new CustomEvent("ambush:e2e-perch-clock"));
    },
  };
}

const missing = PERCH_TAURI_COMMANDS.filter((c) => !HANDLED_COMMANDS.has(c));
if (missing.length > 0) throw new Error(`e2ePerchBridge has no handler for: ${missing.join(", ")}`);
```

(`HANDLED_COMMANDS` is a `Set` listing every `case` label; `randomHex64`, `actionFor`, `rehearsalFor`, `defaultFixtureFromDemo` are small local helpers, the last reading `perchDemoFixture.json`.) In `e2eBridge.ts`: add `26006` to the `P_GATED_KINDS` `Set` (`:5324`), and next to the `startsWith("perch_")` guard call `installPerchControlSeams({ emitGlobalEvent: emitMockGlobalEvent, emitChannelEvent: emitMockLiveEvent })` once during install. The fixture seam: at module load, `seedPerchFixture((window as any).__AMBUSH_E2E_PERCH__ ?? defaultFixtureFromDemo())`. In `tests/helpers/features.ts` keep `E2E_OPT_IN_FEATURES = ["perch"]`; in `bridge.ts`, `seedPreviewFeaturesEnabled` keeps ordinary specs off unless `options.enableFeatures` names it. Extend `installPerchBridge` to pass that option internally. Existing specs keep calling `installMockBridge`; perch specs call only `installPerchBridge`.

- [ ] **Step 4: Run.**

```bash
cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/testing/perch/e2ePerchBridge.test.mjs
cd workspace/desktop && pnpm test:e2e:smoke -- badge.spec.ts channels.spec.ts
```

Expected: 4 node tests pass; two existing smoke specs unchanged (the guard has no ordering constraint and `perch` is not seeded for them).

- [ ] **Step 5: Commit.**

```bash
cd workspace && git add desktop/src/testing desktop/tests/helpers
git commit -s -m "test(desktop): teach the perch e2e module holds, decisions and the alarm control seam"
```

(`preview-features.json` is not edited here: Ground Task 11 already registered `perch`, off by
default. This task changes only how tests opt into that existing entry.)

---

## Task 23: Desktop shared modules — hold keys, the alarm subscription, the ephemeral arm, the Tauri wrappers

**Files:**
- Modify: `workspace/desktop/src/shared/api/tauriPerch.ts` (`perchListHolds`, `perchGetHold`, `perchRecordVerdict`, `perchDecideHold`, `perchOperatorIdentity`, typed `PerchHeldActionView`)
- Modify: `workspace/desktop/src/shared/api/perchKeys.ts` (`holds`, `hold`, `needsAction`, `reconcileDivergences` rows — present in the skeleton; this task verifies them and adds nothing)
- Modify: `workspace/desktop/src/shared/api/perchSubscriptions.ts` (`watch-alarm`, `case-activity` specs live; `PERCH_CASE_REPAIR_KINDS` assertion wired to `get_channel_reconnect_repair_kinds`)
- Modify: `workspace/desktop/src/shared/api/perchEphemeralStore.ts` (the `26006` arm and `drainPerchAlarms` — present in the skeleton; verified)
- Create: `workspace/desktop/src/shared/api/perchHoldAlarm.ts` (`useHoldAlarmRefetch`)
- Modify: `workspace/desktop/src/features/communities/communityScopedRegistry.ts` (the `perchEphemeralStore`, `perchSubscriptions`, `holdListMirror`, `reconcileDivergenceCounter`, `verdictSpool`, `keymapArmingState`, `escapeSurfaceLease` resetters point at real functions)
- Test: `workspace/desktop/src/shared/api/perchHoldAlarm.test.mjs`, `perchEphemeralStore.test.mjs`

**Interfaces:**
- Consumes: `invokeTauri` (`shared/api/tauri.ts:296-309`), `relayClient.subscribeLive(filter, onEvent)` (`relayClientSession.ts:410-417`), `useSyncExternalStore`, `QueryClient.invalidateQueries`.
- Produces:
  ```ts
  export type PerchHeldActionView = { readonly hold_id: string; readonly state: "created"|"notified"|"armed"|"deciding"|"granted"|"refused"|"expired"|"executed"|"failed"; readonly notified_at_ms: number | null; readonly deciding_intent_event_id: string | null; readonly case_channel: string | null; readonly card_event_id: string | null; readonly action_kind: string; readonly severity: "LOW"|"MEDIUM"|"HIGH"|"CRITICAL"; readonly held_at_ms: number; readonly expires_at_ms: number; readonly remaining_ms: number; readonly expired: boolean; readonly action_request: { readonly action: Record<string, unknown> & { type: string }; readonly severity: string; readonly evidence: Record<string, unknown> }; readonly policy_decision: { readonly rule_name: string; readonly reason: string }; readonly rationale: { readonly rule_name: string; readonly reason: string; readonly threat_class: string; readonly severity: string; readonly request_carried_fields: readonly string[] }; readonly leases_a_containment: boolean; readonly rehearsal: { readonly blast_radius: { readonly scope_kind: string; readonly scope_value: string; readonly impact: string; readonly max_affected_scopes: number; readonly affected_capabilities: readonly string[]; readonly summary: string } } | null; readonly inverse_resolution: ReadonlyArray<{ readonly step_kind: string; readonly verdict: "executable"|"irreversible"|"unmapped"; readonly reason: string | null; readonly derived_by: string }>; readonly decision: PerchHoldDecisionRecord | null };
  export type PerchHoldListResponse = { readonly holds: readonly PerchHeldActionView[]; readonly open_count: number; readonly deciding_stalled_count: number; readonly store_durable: boolean; readonly observed_at_ms: number };
  export function perchListHolds(): Promise<PerchHoldListResponse>;
  export function perchGetHold(holdId: string): Promise<{ readonly hold: PerchHeldActionView; readonly observed_at_ms: number }>;
  export function useHoldAlarmRefetch(): void;   // 26006 in the ephemeral store → drain → invalidate perchKeys.holds()
  ```

- [ ] **Step 1: Write the failing tests.**

`perchHoldAlarm.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { applyPerchEphemeralFrame, drainPerchAlarms, perchUnadmittedFrameCount, resetPerchEphemeralStore, setPerchAdmittedIssuers } from "./perchEphemeralStore.ts";
import { holdIdsToRefetch } from "./perchHoldAlarm.ts";

const ADMITTED = "20".repeat(32);

test("a 26006 from an admitted issuer is queued and drained into one refetch", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED]));
  assert.equal(applyPerchEphemeralFrame({ kind: 26006, pubkey: ADMITTED, receivedAtMs: 1, body: { hold_id: "h_a07aeacf" } }), true);
  assert.equal(applyPerchEphemeralFrame({ kind: 26006, pubkey: ADMITTED, receivedAtMs: 2, body: { hold_id: "h_a07aeacf" } }), true);
  const ids = holdIdsToRefetch(drainPerchAlarms());
  assert.deepEqual([...ids], ["h_a07aeacf"], "two alarms for one hold collapse into one re-read");
  assert.equal(drainPerchAlarms().length, 0);
});

test("a 26006 from an unadmitted issuer is counted and dropped", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED]));
  assert.equal(applyPerchEphemeralFrame({ kind: 26006, pubkey: "68".repeat(32), receivedAtMs: 1, body: { hold_id: "h_1c28ae79" } }), false);
  assert.equal(perchUnadmittedFrameCount(), 1);
  assert.equal(drainPerchAlarms().length, 0);
});
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/shared/api/perchHoldAlarm.test.mjs
```

Expected: `ERR_MODULE_NOT_FOUND` on `./perchHoldAlarm.ts`.

- [ ] **Step 3: Implement.**

`perchHoldAlarm.ts`:

```ts
import * as React from "react";
import { useQueryClient } from "@tanstack/react-query";

import { perchKeys } from "./perchKeys";
import { drainPerchAlarms, getPerchEphemeralSnapshot, subscribePerchEphemeral } from "./perchEphemeralStore";

/** Distinct hold ids named by a batch of drained alarms. Order preserved. */
export function holdIdsToRefetch(alarms: readonly Readonly<Record<string, unknown>>[]): ReadonlySet<string> {
  const ids = new Set<string>();
  for (const alarm of alarms) {
    const id = alarm.hold_id;
    if (typeof id === "string" && id.length > 0) ids.add(id);
  }
  return ids;
}

/**
 * The alarm is a nudge with no authority: every drained 26006 invalidates the
 * daemon hold list, and a row appears only if `GET /v1/response/holds`
 * confirms it. Mount once, at The Watch.
 */
export function useHoldAlarmRefetch(): void {
  const queryClient = useQueryClient();
  const alarms = React.useSyncExternalStore(subscribePerchEphemeral, () => getPerchEphemeralSnapshot().alarms);
  React.useEffect(() => {
    if (alarms.length === 0) return;
    const drained = drainPerchAlarms();
    if (holdIdsToRefetch(drained).size === 0) return;
    void queryClient.invalidateQueries({ queryKey: perchKeys.holds() });
  }, [alarms, queryClient]);
}
```

`tauriPerch.ts` gains the typed view above and:

```ts
export function perchListHolds() {
  return invokeTauri<PerchHoldListResponse>("perch_list_holds");
}
export function perchGetHold(holdId: string) {
  return invokeTauri<{ readonly hold: PerchHeldActionView; readonly observed_at_ms: number }>("perch_get_hold", { holdId });
}
export function perchOperatorIdentity() {
  return invokeTauri<{ readonly public_key_hex: string; readonly key_id: string }>("perch_operator_identity");
}
```

with `perchRecordVerdict` and `perchDecideHold` as the skeleton declares them (`PerchDecideOutcome` gains `readonly rule: string | null` and `readonly replayed: boolean`). `PERCH_READ_COMMANDS` gains `perch_operator_identity` and `PERCH_TAURI_COMMANDS` is re-derived. In `perchSubscriptions.ts`, `syncPerchSubscriptions` is exported and `resetPerchSubscriptions()` disposes every open REQ; `perchCaseLiveKinds()` replaces its placeholders with the real `CHANNEL_EVENT_KINDS` and `KIND_CHANNEL_THREAD_SUMMARY` imports. Every `perch*` module's `reset*` export is bound in `features/communities/communityScopedRegistry.ts`'s `RESETTERS`, and its id is present in `COMMUNITY_SCOPED_SINGLETONS`; `pnpm test` runs `communityScopedRegistry.test.mjs` with `PERCH_FEATURES_ROOT` unset (the sweep finds the real tree).

- [ ] **Step 4: Run.**

```bash
cd workspace/desktop && pnpm test && pnpm typecheck && pnpm check
```

Expected: green, including `perchResetterRegistry.test.mjs` sweeping `src/features/perch*` with zero unregistered singletons and `check:px-text` clean.

- [ ] **Step 5: Commit.**

```bash
cd workspace && git add desktop/src
git commit -s -m "feat(desktop): add the hold keys, the alarm-driven refetch and the typed hold wrappers"
```

---

## Task 24: The Watch — the `perch` flag, the four queues, and the reconciled HOLDS queue

**Files:**
- Verify: `workspace/preview-features.json` (`perch` already exists with `defaultEnabled` omitted = off; Ground Task 11)
- Modify: `workspace/desktop/src/app/routes/index.tsx` (the seam)
- Create: `workspace/desktop/src/features/perch-watch/lib/watchQueues.ts`, `lib/holdRows.ts`, `lib/holdRows.test.mjs`, `useHoldQueue.ts`
- Create: `workspace/desktop/src/features/perch-watch/ui/WatchQueueSection.tsx`, `ui/VerdictQueueRow.tsx`
- Modify: `workspace/desktop/src/features/perch-watch/ui/WatchScreen.tsx` (First card's single-queue screen becomes the four-queue two-pane)
- Create: `workspace/desktop/src/shared/ui/perch/HoldTtlClock.tsx`
- Create: `workspace/desktop/tests/e2e/watch-queues.spec.ts`, `tests/e2e/perch-queue-lifecycle.spec.ts` (from the skeleton, tests 01, 03a–03c, 07; 02, 04-lifecycle-INV-32, 05, 06 land with their surfaces)
- Modify: `workspace/desktop/playwright.config.ts` (`smoke` `testMatch` gains the two specs)

**Interfaces:**
- Consumes: `useFeatureEnabled("perch")` (`shared/features/useFeatureEnabled.ts`), `useHomeFeedQuery` shape (`["home-feed"]`, `HomeFeedResponse` with `feed.mentions|needsAction|activity|agentActivity` of `FeedItem { id, kind, pubkey, content, createdAt, channelId, tags, category }`, `shared/api/types.ts:206-240`) read through a new `shared/api/perchRelayFeed.ts` wrapper over `invokeTauri("get_feed")` so no perch feature imports `features/home`; `perchKeys`, `PERCH_FRESHNESS`, `perchListHolds`, `useHoldAlarmRefetch`, `useRelayConnection()` (`shared/api/useRelayConnection.ts:22`), the admitted-issuer set (`perchKeys.admittedIssuers()`, First card).
- Produces:
  ```ts
  export type PerchQueueId = "holds" | "named-you" | "findings" | "case-activity";
  export const PERCH_QUEUE_LABELS: Record<PerchQueueId, string> = { holds: "Holds", "named-you": "Named you", findings: "Findings to review", "case-activity": "Case activity" };
  export type PerchHoldRow =
    | { kind: "hold"; hold: PerchHeldActionView; noticed: boolean; register: "ordinary" }
    | { kind: "unreconciled"; holdId: string; noticeEventId: string; register: "ordinary" | "destructive"; reason: string }
    | { kind: "expired"; hold: PerchHeldActionView };
  export type HoldQueueReconciliation = { rows: PerchHoldRow[]; divergences: number; unadmittedFrames: number; openCount: number; storeDurable: boolean; queueDepthAlarm: boolean };
  export function reconcileHoldQueue(input: { daemon: PerchHoldListResponse | null; relayNotices: readonly FeedItem[]; admitted: ReadonlySet<string>; nowMs: number }): HoldQueueReconciliation;
  export function useHoldQueue(): { data: HoldQueueReconciliation | null; status: "loading" | "ready" | "daemon-unreachable" | "not-configured"; error: string | null; reconciled: boolean };
  ```
  Rows sort age-first (oldest `held_at_ms` first). `queueDepthAlarm` is `openCount >= 12`.

- [ ] **Step 1: Write the failing reducer test.**

`holdRows.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { reconcileHoldQueue } from "./holdRows.ts";

const BRIDGE = "20".repeat(32);
const NOW = 1_773_739_200_000;
const hold = (id, extra = {}) => ({ hold_id: id, state: "notified", notified_at_ms: NOW - 100, deciding_intent_event_id: null, case_channel: "27799e23-ab25-4659-b381-3de47ea7ca4d", card_event_id: null, action_kind: "isolate_host", severity: "CRITICAL", held_at_ms: NOW - 1000, expires_at_ms: NOW + 3_600_000, remaining_ms: 3_600_000, expired: false, action_request: { action: { type: "isolate_host", host_id: "h" }, severity: "CRITICAL", evidence: {} }, policy_decision: { rule_name: "static.human_gate", reason: "r" }, rationale: { rule_name: "static.human_gate", reason: "r", threat_class: "execution", severity: "CRITICAL", request_carried_fields: ["severity", "threat_class"] }, leases_a_containment: true, rehearsal: null, inverse_resolution: [], decision: null, ...extra });
const notice = (holdId, pubkey = BRIDGE) => ({ id: "0".repeat(64), kind: 46010, pubkey, content: `hold ${holdId} · isolate_host · CRITICAL · host h · expires x`, createdAt: 1, channelId: "27799e23-ab25-4659-b381-3de47ea7ca4d", channelName: "case", tags: [["h", "27799e23-ab25-4659-b381-3de47ea7ca4d"], ["p", "68".repeat(32)], ["hold", holdId]], category: "needs_action" });

test("a daemon hold with a relay notice is one ordinary row and no divergence", () => {
  const out = reconcileHoldQueue({ daemon: { holds: [hold("h_a07aeacf")], open_count: 1, deciding_stalled_count: 0, store_durable: false, observed_at_ms: NOW }, relayNotices: [notice("h_a07aeacf")], admitted: new Set([BRIDGE]), nowMs: NOW });
  assert.equal(out.rows.length, 1);
  assert.equal(out.rows[0].kind, "hold");
  assert.equal(out.divergences, 0);
});

test("a relay notice with no daemon record renders UNRECONCILED, keyed on store durability", () => {
  const nonDurable = reconcileHoldQueue({ daemon: { holds: [], open_count: 0, deciding_stalled_count: 0, store_durable: false, observed_at_ms: NOW }, relayNotices: [notice("h_1c28ae79")], admitted: new Set([BRIDGE]), nowMs: NOW });
  assert.equal(nonDurable.rows[0].kind, "unreconciled");
  assert.equal(nonDurable.rows[0].register, "ordinary");
  assert.match(nonDurable.rows[0].reason, /store_durable/);
  assert.equal(nonDurable.divergences, 1);
  const durable = reconcileHoldQueue({ daemon: { holds: [], open_count: 0, deciding_stalled_count: 0, store_durable: true, observed_at_ms: NOW }, relayNotices: [notice("h_1c28ae79")], admitted: new Set([BRIDGE]), nowMs: NOW });
  assert.equal(durable.rows[0].register, "destructive");
  assert.match(durable.rows[0].reason, /durable hold store and no record/);
});

test("an unadmitted notice renders nothing of its own and increments a separate counter", () => {
  const out = reconcileHoldQueue({ daemon: { holds: [], open_count: 0, deciding_stalled_count: 0, store_durable: false, observed_at_ms: NOW }, relayNotices: [notice("h_1c28ae79", "68".repeat(32))], admitted: new Set([BRIDGE]), nowMs: NOW });
  assert.equal(out.rows.length, 0);
  assert.equal(out.divergences, 0);
  assert.equal(out.unadmittedFrames, 1);
});

test("an expired hold stays in the queue as an expired row, oldest first, and 12 open holds trip the alarm", () => {
  const holds = Array.from({ length: 12 }, (_, i) => hold(`h_open${String(i).padStart(4, "0")}`, { held_at_ms: NOW - i }));
  holds.push(hold("h_expired01", { state: "expired", expired: true, remaining_ms: 0, held_at_ms: NOW - 99_999 }));
  const out = reconcileHoldQueue({ daemon: { holds, open_count: 12, deciding_stalled_count: 0, store_durable: true, observed_at_ms: NOW }, relayNotices: [], admitted: new Set([BRIDGE]), nowMs: NOW });
  assert.equal(out.rows[0].kind, "expired");
  assert.equal(out.rows.length, 13);
  assert.equal(out.queueDepthAlarm, true);
});
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-watch/lib/holdRows.test.mjs
```

Expected: `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the reducer, the hook and the queue components.**

`holdRows.ts`:

```ts
import type { FeedItem } from "@/shared/api/types";
import type { PerchHeldActionView, PerchHoldListResponse } from "@/shared/api/tauriPerch";

/** APPENDIX-NORMATIVE.md §6. */
export const PERCH_QUEUE_DEPTH_ALARM = 12;

export type PerchHoldRow =
  | { kind: "hold"; hold: PerchHeldActionView; noticed: boolean; register: "ordinary" }
  | { kind: "unreconciled"; holdId: string; noticeEventId: string; register: "ordinary" | "destructive"; reason: string }
  | { kind: "expired"; hold: PerchHeldActionView };

export type HoldQueueReconciliation = {
  rows: PerchHoldRow[];
  divergences: number;
  unadmittedFrames: number;
  openCount: number;
  storeDurable: boolean;
  queueDepthAlarm: boolean;
};

function holdTag(item: FeedItem): string | null {
  const tag = item.tags.find((t) => t[0] === "hold");
  return tag?.[1] ?? null;
}

/**
 * Layer 3 of the hold path: the daemon list is the authority, the relay
 * notices are the delivery record, and the three divergence cases render
 * rather than resolve silently. INV-35's split: UNRECONCILED in the ordinary
 * register on a non-durable store, in the destructive register on a durable
 * one; an unadmitted issuer renders nothing and is counted apart.
 */
export function reconcileHoldQueue(input: {
  daemon: PerchHoldListResponse | null;
  relayNotices: readonly FeedItem[];
  admitted: ReadonlySet<string>;
  nowMs: number;
}): HoldQueueReconciliation {
  const { daemon, relayNotices, admitted, nowMs } = input;
  const rows: PerchHoldRow[] = [];
  let unadmittedFrames = 0;
  let divergences = 0;
  const noticedIds = new Set<string>();
  const admittedNotices: FeedItem[] = [];
  for (const item of relayNotices) {
    if (item.kind !== 46010) continue;
    if (!admitted.has(item.pubkey.toLowerCase())) {
      unadmittedFrames += 1;
      continue;
    }
    const id = holdTag(item);
    if (!id) continue;
    noticedIds.add(id);
    admittedNotices.push(item);
  }
  const daemonIds = new Set<string>();
  for (const hold of daemon?.holds ?? []) {
    daemonIds.add(hold.hold_id);
    const expired = hold.state === "expired" || hold.expired || nowMs >= hold.expires_at_ms;
    if (expired) {
      rows.push({ kind: "expired", hold });
    } else if (hold.state === "created" || hold.state === "notified" || hold.state === "armed" || hold.state === "deciding") {
      rows.push({ kind: "hold", hold, noticed: noticedIds.has(hold.hold_id) || hold.notified_at_ms !== null, register: "ordinary" });
    }
  }
  const storeDurable = daemon?.store_durable ?? false;
  for (const item of admittedNotices) {
    const id = holdTag(item);
    if (!id || daemonIds.has(id)) continue;
    divergences += 1;
    rows.push(
      storeDurable
        ? { kind: "unreconciled", holdId: id, noticeEventId: item.id, register: "destructive", reason: "the daemon has a durable hold store and no record of this hold" }
        : { kind: "unreconciled", holdId: id, noticeEventId: item.id, register: "ordinary", reason: "no daemon record: store_durable is false, so a restart forgot every open hold" },
    );
  }
  rows.sort((a, b) => rowAge(a) - rowAge(b));
  const openCount = daemon?.open_count ?? 0;
  return { rows, divergences, unadmittedFrames, openCount, storeDurable, queueDepthAlarm: openCount >= PERCH_QUEUE_DEPTH_ALARM };
}

function rowAge(row: PerchHoldRow): number {
  return row.kind === "unreconciled" ? Number.MAX_SAFE_INTEGER : row.hold.held_at_ms;
}
```

`useHoldQueue.ts`:

```ts
import * as React from "react";
import { useQuery } from "@tanstack/react-query";

import { PERCH_FRESHNESS, PERCH_NO_RETRY, perchKeys } from "@/shared/api/perchKeys";
import { useHoldAlarmRefetch } from "@/shared/api/perchHoldAlarm";
import { usePerchRelayFeed } from "@/shared/api/perchRelayFeed";
import { perchListHolds } from "@/shared/api/tauriPerch";
import { useRelayConnection } from "@/shared/api/useRelayConnection";
import { usePerchAdmittedIssuers } from "@/shared/api/perchAdmission";
import { useQueryClient } from "@tanstack/react-query";

import { reconcileHoldQueue, type HoldQueueReconciliation } from "./lib/holdRows";

let divergenceCounter = 0;
/** Rendered as `data-perch-counter="perch_queue_reconcile_divergences_total"`. */
export function readReconcileDivergenceCounter(): number {
  return divergenceCounter;
}
export function resetReconcileDivergenceCounter(): void {
  divergenceCounter = 0;
}

export function useHoldQueue() {
  useHoldAlarmRefetch();
  const queryClient = useQueryClient();
  const connection = useRelayConnection();
  const admitted = usePerchAdmittedIssuers();
  const feed = usePerchRelayFeed();
  const holds = useQuery({
    queryKey: perchKeys.holds(),
    queryFn: perchListHolds,
    staleTime: PERCH_FRESHNESS.holds.staleTime,
    ...PERCH_NO_RETRY,
  });
  // Re-read the daemon on every relay reconnect edge (14 §5.6 step 3).
  const previous = React.useRef(connection);
  React.useEffect(() => {
    if (previous.current !== "connected" && connection === "connected") {
      void queryClient.invalidateQueries({ queryKey: perchKeys.holds() });
    }
    previous.current = connection;
  }, [connection, queryClient]);

  const data = React.useMemo(() => {
    if (!holds.data) return null;
    const out = reconcileHoldQueue({ daemon: holds.data, relayNotices: feed.data?.feed.needsAction ?? [], admitted, nowMs: Date.now() });
    divergenceCounter += out.divergences;
    return out;
  }, [holds.data, feed.data, admitted]);

  const status: "loading" | "ready" | "daemon-unreachable" | "not-configured" = holds.isPending
    ? "loading"
    : holds.error
      ? String(holds.error).includes("not configured") ? "not-configured" : "daemon-unreachable"
      : "ready";
  return { data, status, error: holds.error ? String(holds.error) : null, reconciled: status === "ready" && !feed.isPending };
}
```

(`usePerchAdmittedIssuers` and `usePerchRelayFeed` are two ten-line hooks in `shared/api/`: the first reads `perchKeys.admittedIssuers()` — First card owns the query — and returns a stable `ReadonlySet`; the second is `useQuery({ queryKey: perchKeys.needsAction(), queryFn: () => invokeTauri<HomeFeedResponse>("get_feed", { since: 0 }) })`.)

`WatchQueueSection.tsx` and `VerdictQueueRow.tsx` follow `17` §6.2 — three lines per row, `text-sm` line 1, `text-xs` lines 2–3, `data-testid="perch-queue-row-${holdId}"`, `data-perch-hold-state`, `data-perch-register`, the header count `data-testid="perch-queue-count-${queue}"` rendering `count unavailable` (never `0`) when the daemon is unreachable, `data-perch-role="empty-state"` with `data-perch-empty-kind="governing-number"` for an empty HOLDS queue ("No held actions. N destructive actions ran without a hold in this window — see /policy") and `hideWhenEmpty` for NAMED YOU. `HoldTtlClock.tsx` renders `remaining_ms` and `expired` as two separate elements with `data-testid="perch-hold-ttl"`, states `live | under-5m | expired`. `WatchScreen.tsx` composes: a full-width `StreamGapRow` slot above queue 1 (First card's gap detector), four `WatchQueueSection`s, the `data-perch-queue-reconciled` attribute set from `useHoldQueue().reconciled`, three `data-perch-counter` nodes (`perch_queue_reconcile_divergences_total`, `perch_frame_unadmitted_total`, `perch_queue_open_count`), and the detail pane switching on the selected row (`VerdictPane` from Task 25 for holds; First card's finding pane otherwise). The queue header for an undeliverable state reads `no operator is configured to receive holds — set nostr_pubkey on the approve principal` when the daemon list is non-empty and no notice has ever arrived.

`routes/index.tsx`:

```tsx
import { useFeatureEnabled } from "@/shared/features";
import { WatchScreen } from "@/features/perch-watch/ui/WatchScreen";
// …
function HomeRouteComponent() {
  const perchEnabled = useFeatureEnabled("perch");
  // … existing hooks unchanged …
  if (perchEnabled) {
    return <WatchScreen currentPubkey={identityQuery.data?.pubkey} onOpenCase={(caseId) => void goCase(caseId)} />;
  }
  return <HomeScreen … />;
}
```

(`goCase` is First card's navigation callback to `/cases/$caseId`.) Assert Ground Task 11's
`workspace/preview-features.json` entry still names `perch`, targets desktop and omits
`defaultEnabled`; do not add a duplicate entry. Task 28 owns the one later change to this row.

- [ ] **Step 4: Write the Playwright coverage.**

`tests/e2e/watch-queues.spec.ts`:

```ts
import { expect, test } from "@playwright/test";
import { waitForAnimations } from "../helpers/animations";
import { PERCH_HOLD_A, PERCH_HOLD_B, installPerchBridge, perchFixture, perchHold, waitForPerchQueue } from "../helpers/perchBridge";

test("the four queues render with their ratified labels and holds sort oldest first", async ({ page }) => {
  const older = perchHold({ hold_id: PERCH_HOLD_A, held_at_ms: 1_773_738_882_600 });
  const newer = perchHold({ hold_id: PERCH_HOLD_B, action_kind: "block_egress", held_at_ms: 1_773_738_900_000, containment_lease_id: null });
  await installPerchBridge(page, perchFixture({ holds: [newer, older] }));
  await page.goto("/");
  await waitForPerchQueue(page);
  await waitForAnimations(page);
  for (const label of ["Holds", "Findings to review", "Case activity"]) {
    await expect(page.getByRole("heading", { name: label })).toBeVisible();
  }
  await expect(page.getByRole("heading", { name: "Named you" })).toHaveCount(0); // absent, not zero, in a solo deployment
  const rows = page.locator('[data-testid^="perch-queue-row-"]');
  await expect(rows.nth(0)).toHaveAttribute("data-testid", `perch-queue-row-${PERCH_HOLD_A}`);
  await expect(page.getByTestId("perch-queue-count-holds")).toHaveText("2");
  await expect(page.getByTestId(`perch-queue-row-${PERCH_HOLD_B}`).getByTestId("perch-pending-containment-lease")).toHaveCount(0);
});

test("with the daemon unreachable the count is unavailable, never zero, and the selection does not jump", async ({ page }) => {
  await installPerchBridge(page, perchFixture({ holds: [perchHold()], daemonUnreachable: true }));
  await page.goto("/");
  await expect(page.getByTestId("perch-queue-count-holds")).toContainText("count unavailable");
  await expect(page.getByTestId("perch-queue-holds")).not.toContainText(/all clear|no data|caught up/i);
});
```

(`daemonUnreachable: true` makes the mock module throw `daemon unreachable: connection refused` from `perch_list_holds`.) `perch-queue-lifecycle.spec.ts` is the skeleton file with `installPerchBridge(page, fixture)`, `__BUZZ_E2E_*` → `__AMBUSH_E2E_*`, and only tests 01, 03a, 03b, 03c and 07 registered now; the other four are added by the tasks that land their surfaces (02 with `/handoff` in Operator-complete, INV-32's rendered half in Task 26, 05 and 06 with the lane list and empty states First card owns).

- [ ] **Step 5: Run.**

```bash
cd workspace/desktop && pnpm test && pnpm typecheck && pnpm check && pnpm check:file-sizes
cd workspace/desktop && pnpm test:e2e:smoke -- watch-queues.spec.ts perch-queue-lifecycle.spec.ts
cd workspace/desktop && pnpm test:e2e:smoke -- badge.spec.ts  # an existing home-adjacent spec still passes with the flag off
```

Expected: green. Hash the lifecycle screenshots if any are captured (`shasum -a 256 test-results/**/*.png` — every hash unique).

- [ ] **Step 6: Commit.**

```bash
cd workspace && git add desktop/src desktop/tests desktop/playwright.config.ts
git commit -s -m "feat(desktop): remap Home into The Watch behind the perch flag with a reconciled holds queue"
```

---

## Task 25: The Verdict Row — `VerdictPane`, `VerdictSlot`, `WriteStateRow`, fixed order across fifteen action kinds

**Files:**
- Create: `workspace/desktop/src/features/perch-watch/lib/verdictSlots.ts`, `lib/verdictSlots.test.mjs`
- Create: `workspace/desktop/src/features/perch-watch/ui/VerdictPane.tsx`, `ui/VerdictSlot.tsx`
- Create: `workspace/desktop/src/shared/ui/perch/WriteStateRow.tsx`
- Create: `workspace/desktop/src/features/perch-evidence/ui/cards/HoldCard.tsx`, `cards/VerdictCard.tsx` (registry entries `hold` and `verdict`)
- Create: `workspace/desktop/tests/e2e/perch-verdict-pane.spec.ts` (skeleton tests 01, 02, 06, 07; 03–05 land in Task 26/27)

**Interfaces:**
- Consumes: `PerchHeldActionView`, `AdversaryString` (First card, H6), `EyebrowLabel`, `SeverityChip` (First card's Tier B), `acquireEscapeSurface` (`shared/hooks/escapeSurfaces.ts:27-33`).
- Produces:
  ```ts
  export const VERDICT_SLOT_ORDER = ["action", "blast-radius", "if-you-undo", "why-we-are-asking", "what-granting-opens"] as const;
  export type VerdictSlotId = (typeof VERDICT_SLOT_ORDER)[number];
  export type VerdictSlotContent = { kind: "present"; lines: readonly VerdictLine[] } | { kind: "absent"; copy: string };
  export type VerdictLine = { label: string | null; value: string; adversary: boolean; provenance?: "request-carried" | "runtime" | "derived" };
  export function buildVerdictSlots(hold: PerchHeldActionView, leaseTtls: { capabilityLeaseTtlMs: number; containmentLeaseTtlMs: number }): Record<VerdictSlotId, VerdictSlotContent>;
  export type VerdictWriteState = { phase: "idle" } | { phase: "sending" } | { phase: "recorded"; atMs: number } | { phase: "daemon-dispatched"; atMs: number; receiptId: string | null } | { phase: "daemon-refused"; ruleName: string; reason: string } | { phase: "refused-late"; ruleName: string; reason: string } | { phase: "refused-late-governance"; reason: string } | { phase: "daemon-unreachable"; reason: string } | { phase: "superseded"; winningIntentEventId: string; winningDecision: "grant" | "refuse"; decidedAtMs: number };
  ```
  `VerdictPane` maps `VERDICT_SLOT_ORDER` and renders a `VerdictSlot` per id whether or not content exists — there is no branch that can omit one. An unleased destructive action renders no `perch-pending-containment-lease` node at all. WHY WE ARE ASKING renders the daemon's `rationale.reason` through `<code>` fed from data (never a literal), so the copy gate's `approve` row is never seen by the extractor.

- [ ] **Step 1: Write the failing fifteen-variant test.**

`verdictSlots.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { VERDICT_SLOT_ORDER, buildVerdictSlots } from "./verdictSlots.ts";

const ACTIONS = [
  ["block_egress", { target: "203.0.113.10" }, false],
  ["isolate_host", { host_id: "h" }, true],
  ["revoke_credential", { credential_id: "c" }, false],
  ["sinkhole_dns", { domain: "d" }, false],
  ["terminate_user_session", { host_id: "h", session_id: "s" }, true],
  ["trigger_edr_scan", { host_id: "h", scan_profile: "quick" }, false],
  ["inject_firewall_rule", { host_id: "h", rule_name: "r", direction: "in", cidr: "10.0.0.0/8", port: null }, false],
  ["quarantine_file", { host_id: "h", file_path: "/tmp/x" }, true],
  ["kill_process", { host_id: "h", process_name: "p" }, false],
  ["suspend_process", { host_id: "h", process_name: "p" }, true],
  ["disable_user_account", { user_id: "u" }, false],
  ["force_password_reset", { user_id: "u" }, false],
  ["remove_scheduled_task", { host_id: "h", task_name: "t" }, false],
  ["deploy_decoy", { decoy_type: "honeytoken", target_zone: "z" }, false],
  ["escalate", { summary: "s", urgency: "HIGH" }, false],
];

const hold = (kind, fields, leased) => ({ hold_id: "h_a07aeacf", state: "notified", notified_at_ms: 1, deciding_intent_event_id: null, case_channel: "c", card_event_id: null, action_kind: kind, severity: "CRITICAL", held_at_ms: 1, expires_at_ms: 2, remaining_ms: 1, expired: false, action_request: { action: { type: kind, ...fields }, severity: "CRITICAL", evidence: { escalation: { threat_class: "execution" } } }, policy_decision: { rule_name: "static.human_gate", reason: "authorized but held for human approval" }, rationale: { rule_name: "static.human_gate", reason: "authorized but held for human approval", threat_class: "execution", severity: "CRITICAL", request_carried_fields: ["severity", "threat_class"] }, leases_a_containment: leased, rehearsal: null, inverse_resolution: [], decision: null });

for (const [kind, fields, leased] of ACTIONS) {
  test(`${kind}: five slots, fixed order, none empty`, () => {
    const slots = buildVerdictSlots(hold(kind, fields, leased), { capabilityLeaseTtlMs: 60_000, containmentLeaseTtlMs: 900_000 });
    assert.deepEqual(Object.keys(slots), [...VERDICT_SLOT_ORDER]);
    for (const id of VERDICT_SLOT_ORDER) {
      const slot = slots[id];
      if (slot.kind === "present") assert.ok(slot.lines.length > 0, `${kind} ${id} has no lines`);
      else assert.ok(slot.copy.length > 0, `${kind} ${id} has no absence copy`);
    }
    // The ACTION slot names every typed field through the adversary path.
    const action = slots.action;
    assert.equal(action.kind, "present");
    for (const field of Object.keys(fields)) assert.ok(action.lines.some((l) => l.label === field && l.adversary), `${kind} lacks ${field}`);
    // No rehearsal => BLAST RADIUS is an explicit absence, never collapsed.
    assert.equal(slots["blast-radius"].kind, "absent");
    assert.match(slots["blast-radius"].copy, /NO REHEARSAL/);
    // WHY WE ARE ASKING marks the request-carried selector fields.
    const why = slots["why-we-are-asking"];
    assert.equal(why.kind, "present");
    assert.ok(why.lines.some((l) => l.provenance === "request-carried" && l.label === "threat_class"));
    // WHAT GRANTING OPENS names the capability lease and, only when leased, the containment lease.
    const opens = slots["what-granting-opens"];
    assert.equal(opens.kind, "present");
    assert.ok(opens.lines.some((l) => l.value.includes("60 s")));
    assert.equal(opens.lines.some((l) => l.value.includes("15 min")), leased);
  });
}
```

- [ ] **Step 2: Run and watch it fail.**

```bash
cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-watch/lib/verdictSlots.test.mjs
```

Expected: `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the slot builder and the components.**

`verdictSlots.ts`:

```ts
import type { PerchHeldActionView } from "@/shared/api/tauriPerch";

export const VERDICT_SLOT_ORDER = ["action", "blast-radius", "if-you-undo", "why-we-are-asking", "what-granting-opens"] as const;
export type VerdictSlotId = (typeof VERDICT_SLOT_ORDER)[number];

export const VERDICT_SLOT_LABELS: Record<VerdictSlotId, string> = {
  action: "ACTION",
  "blast-radius": "BLAST RADIUS",
  "if-you-undo": "IF YOU UNDO",
  "why-we-are-asking": "WHY WE ARE ASKING",
  "what-granting-opens": "WHAT GRANTING OPENS",
};

export type VerdictLine = { label: string | null; value: string; adversary: boolean; provenance?: "request-carried" | "runtime" | "derived" };
export type VerdictSlotContent = { kind: "present"; lines: readonly VerdictLine[] } | { kind: "absent"; copy: string };

function formatMs(ms: number): string {
  return ms >= 60_000 && ms % 60_000 === 0 ? `${ms / 60_000} min` : `${Math.round(ms / 1000)} s`;
}

export function buildVerdictSlots(
  hold: PerchHeldActionView,
  leaseTtls: { capabilityLeaseTtlMs: number; containmentLeaseTtlMs: number },
): Record<VerdictSlotId, VerdictSlotContent> {
  const { type, ...fields } = hold.action_request.action;
  const action: VerdictSlotContent = {
    kind: "present",
    lines: [
      { label: null, value: type, adversary: false },
      ...Object.entries(fields).map(([label, value]) => ({ label, value: value === null || value === undefined ? "—" : String(value), adversary: true })),
    ],
  };
  const radius = hold.rehearsal?.blast_radius;
  const blastRadius: VerdictSlotContent = radius
    ? {
        kind: "present",
        lines: [
          { label: "impact", value: radius.impact, adversary: false, provenance: "runtime" },
          { label: "scope", value: `${radius.scope_kind}: ${radius.scope_value}`, adversary: true, provenance: "runtime" },
          { label: "max affected scopes", value: String(radius.max_affected_scopes), adversary: false, provenance: "runtime" },
          { label: "capabilities", value: radius.affected_capabilities.join(", ") || "—", adversary: false, provenance: "runtime" },
          { label: null, value: "served by the runtime's rehearsal preview", adversary: false, provenance: "runtime" },
        ],
      }
    : { kind: "absent", copy: "NO REHEARSAL — the runtime did not derive a blast radius for this request" };
  const ifYouUndo: VerdictSlotContent =
    hold.inverse_resolution.length > 0
      ? {
          kind: "present",
          lines: hold.inverse_resolution.map((step) => ({
            label: step.step_kind,
            value: step.verdict === "executable" ? "executable inverse" : step.verdict === "irreversible" ? `irreversible — ${step.reason ?? ""}` : "unmapped — no inverse is defined for this step",
            adversary: false,
            provenance: "derived",
          })),
        }
      : { kind: "absent", copy: hold.leases_a_containment ? "no rollback plan was derived for this containment" : "no executable inverse — this action is not a containment and has no inverse plan" };
  const whyWeAreAsking: VerdictSlotContent = {
    kind: "present",
    lines: [
      { label: "rule", value: hold.rationale.rule_name, adversary: false, provenance: "runtime" },
      { label: "reason", value: hold.rationale.reason, adversary: true, provenance: "runtime" },
      { label: "threat_class", value: hold.rationale.threat_class, adversary: false, provenance: "request-carried" },
      { label: "severity", value: hold.rationale.severity, adversary: false, provenance: "request-carried" },
      { label: null, value: "receipt-required on the autonomous path — a decide re-runs the governance gate; nothing checks that a receipt's signer is a governor", adversary: false, provenance: "runtime" },
    ],
  };
  const opens: VerdictLine[] = [
    { label: "capability lease", value: `minted at your decision, not now · ${formatMs(leaseTtls.capabilityLeaseTtlMs)}`, adversary: false, provenance: "runtime" },
  ];
  if (hold.leases_a_containment) {
    opens.push({ label: "containment lease", value: `then a containment lease on the lease board · ${formatMs(leaseTtls.containmentLeaseTtlMs)}`, adversary: false, provenance: "runtime" });
  }
  return { action, "blast-radius": blastRadius, "if-you-undo": ifYouUndo, "why-we-are-asking": whyWeAreAsking, "what-granting-opens": { kind: "present", lines: opens } };
}
```

`VerdictSlot.tsx`:

```tsx
import * as React from "react";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";
import { EyebrowLabel } from "@/shared/ui/perch/EyebrowLabel";
import type { VerdictSlotContent, VerdictSlotId } from "../lib/verdictSlots";

export function VerdictSlot({ id, label, content, onFullyVisible }: { id: VerdictSlotId; label: string; content: VerdictSlotContent; onFullyVisible?: () => void }) {
  const lastChild = React.useRef<HTMLDivElement | null>(null);
  React.useEffect(() => {
    if (!onFullyVisible || !lastChild.current) return;
    const observer = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.intersectionRatio >= 1)) onFullyVisible();
    }, { threshold: 1.0 });
    observer.observe(lastChild.current);
    return () => observer.disconnect();
  }, [onFullyVisible]);
  return (
    <section data-testid={`perch-verdict-slot-${id}`} data-perch-role="verdict-slot" data-perch-slot={id} className="border-l-[2.5px] border-[var(--perch-pillar-authority-mark)] pl-3 py-2">
      <EyebrowLabel>{label}</EyebrowLabel>
      {content.kind === "absent" ? (
        <p className="text-sm text-[var(--perch-foreground-muted)]" data-perch-absence="">{content.copy}</p>
      ) : (
        content.lines.map((line, index) => (
          <div key={`${line.label ?? "value"}-${index}`} ref={index === content.lines.length - 1 ? lastChild : undefined} className="grid grid-cols-[minmax(6rem,auto)_1fr] gap-x-3 text-sm" data-perch-provenance={line.provenance ?? undefined}>
            <span className="text-xs text-[var(--perch-foreground-muted)] font-mono">{line.label ?? ""}</span>
            {line.adversary ? <AdversaryString value={line.value} /> : <code className="font-mono">{line.value}</code>}
          </div>
        ))
      )}
    </section>
  );
}
```

`VerdictPane.tsx` renders `<section data-testid="perch-verdict-pane" tabIndex={-1} aria-labelledby="perch-verdict-action">` with the five slots mapped in order, `onBlastRadiusRead` wired to the `blast-radius` slot's `onFullyVisible`, the `HoldTtlClock`, `data-testid="perch-pending-containment-lease"` rendered only when `hold.leases_a_containment`, the `perch-undo-affordance` button enabled iff every `inverse_resolution` entry is `executable` (its disabled text quoting the first irreversible reason), the expired state (`perch-verdict-pane-expired`, action bar replaced by "this hold expired at <time> · no action was taken"), the `WriteStateRow`, and the refusal legend (`perch-refusal-legend-open` → a list whose governance row carries `data-perch-reachable="true"` now that Task 12 landed, with the middle-row limit sentence from `12` §5.7). It acquires an escape surface on mount and releases it on unmount, and moves focus to itself on `hold_id` change. `WriteStateRow.tsx` renders each phase with `data-testid="perch-write-state-${phase}"`, `data-perch-decision-state` (`sending | recorded | acknowledged | refused_late | superseded | unreachable`), `role="status"` except `daemon-refused`/`refused-late` which are `role="alert"`, and for `superseded` the sentence "Another operator's decision was the one that ran: <verb> at <time>. Your decision is recorded on this case and did not run." with `data-testid="perch-write-state-superseded-winner"` on the id node. `HoldCard.tsx` and `VerdictCard.tsx` are registry presenters (`swarmCardRegistry.hold`, `.verdict`) rendering the human line, the five-slot summary (hold) or the decision + `leg2.state` (verdict), each carrying `ProvenanceRows` naming `secp256k1 · tier 0` and, for the verdict card, `Ed25519 · tier 1 (leg-1 signature; not verified against the daemon here)`.

- [ ] **Step 4: The Playwright spec.** `perch-verdict-pane.spec.ts` from the skeleton with tests 01 (fifteen variants), 02, 06 and 07 (07's expectation flips to `data-perch-reachable="true"` and the middle-row sentence, because B2g is built), `enableFeatures: ["perch"]`, and `__AMBUSH_E2E_*` seams.

- [ ] **Step 5: Run.**

```bash
cd workspace/desktop && pnpm test && pnpm typecheck && pnpm check && pnpm check:file-sizes
cd workspace/desktop && pnpm test:e2e:smoke -- perch-verdict-pane.spec.ts
bash tools/check-copy-banned-terms.sh
```

Expected: 15 node snapshots pass; the spec's registered tests pass; the copy gate finds no `Approve`, no `Perch`, no bare `lease` label (the eyebrow reads `capability lease` / `containment lease`).

- [ ] **Step 6: Commit.**

```bash
cd workspace && git add desktop/src desktop/tests
git commit -s -m "feat(desktop): render the Verdict Row with five fixed slots across all fifteen action kinds"
```

---

## Task 26: The keymap registry, `usePerchKeymap`, and the two-stroke grant control

**Files:**
- Create: `workspace/desktop/src/features/perch/lib/perchKeymapRegistry.ts`, `lib/perchKeymapRegistry.test.mjs` (from the skeleton, verbatim)
- Create: `workspace/desktop/src/features/perch/lib/keymapArmingState.ts`, `features/perch/usePerchKeymap.ts`
- Create: `workspace/desktop/src/features/perch-watch/ui/GrantControl.tsx`, `ui/RefuseControl.tsx`
- Create: `workspace/desktop/src/features/perch-watch/lib/grantDwell.ts`, `lib/grantDwell.test.mjs`
- Modify: `workspace/desktop/src/shared/ui/button.tsx` (a `verdict` variant with no `bg-primary` path)
- Create: `workspace/desktop/tests/e2e/grant-two-stroke.spec.ts` (+ skeleton verdict-pane tests 03 and 04 registered)

**Interfaces:**
- Consumes: `PERCH_BINDINGS` (the skeleton's data), `useAppShellKeyboardShortcuts.ts:57-64`'s `event.repeat` house rule, `acquireEscapeSurface`, `buttonVariants` (`shared/ui/button.tsx:10-33`).
- Produces:
  ```ts
  export function usePerchKeymap(handlers: { rowType: PerchRowType | null; onVerb: (verb: PerchVerdictVerb) => void; onMove: (delta: 1 | -1) => void; onOpen: () => void; onPromote: () => void; onSnooze: () => void; onMarkDone: () => void; onMarkUnread: () => void }): void;
  export type DwellState = { accruedMs: number; visible: boolean; lastTickMs: number | null; holdId: string };
  export function dwellReducer(state: DwellState, event: { type: "visible" | "hidden"; atMs: number } | { type: "tick"; atMs: number } | { type: "reset"; holdId: string }): DwellState;
  export const GRANT_DWELL_MS = 1500;
  export function armGrant(holdId: string): void; export function isGrantArmed(holdId: string): boolean; export function resetKeymapArmingState(): void;
  ```
  `G` arms (ignored on `event.repeat`); `Enter` or a click records, disabled until `accruedMs >= 1500` **while BLAST RADIUS was fully visible** (accrual freezes, never resets, when it is hidden); arming resets on `hold_id` change; `R` refuses in one keypress; `D` is never offered on a hold; the control renders `null` when the selection cardinality is not 1; its label is exactly `Record my decision and send it to the daemon`.

- [ ] **Step 1: Write the failing tests.**

`grantDwell.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { GRANT_DWELL_MS, dwellReducer, dwellComplete } from "./grantDwell.ts";

const start = { accruedMs: 0, visible: false, lastTickMs: null, holdId: "h_a" };

test("time accrues only while the blast radius is fully visible and freezes when it is not", () => {
  let s = dwellReducer(start, { type: "visible", atMs: 0 });
  s = dwellReducer(s, { type: "tick", atMs: 800 });
  assert.equal(s.accruedMs, 800);
  s = dwellReducer(s, { type: "hidden", atMs: 800 });
  s = dwellReducer(s, { type: "tick", atMs: 2_800 });
  assert.equal(s.accruedMs, 800, "frozen, not reset, and nothing accrued while hidden");
  assert.equal(dwellComplete(s), false);
  s = dwellReducer(s, { type: "visible", atMs: 2_800 });
  s = dwellReducer(s, { type: "tick", atMs: 3_500 });
  assert.equal(s.accruedMs, 1500);
  assert.equal(dwellComplete(s), true);
});

test("two seconds spent not looking never completes the gate", () => {
  let s = dwellReducer(start, { type: "tick", atMs: 2_000 });
  assert.equal(s.accruedMs, 0);
  assert.equal(dwellComplete(s), false);
});

test("a hold_id change resets the accrual", () => {
  let s = dwellReducer(dwellReducer(start, { type: "visible", atMs: 0 }), { type: "tick", atMs: GRANT_DWELL_MS });
  assert.equal(dwellComplete(s), true);
  s = dwellReducer(s, { type: "reset", holdId: "h_b" });
  assert.equal(s.accruedMs, 0);
  assert.equal(s.holdId, "h_b");
});
```

Plus the skeleton's `perchKeymapRegistry.test.mjs` (8 tests) and, in `keymapArmingState.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { armGrant, isGrantArmed, noteHoldSelected, resetKeymapArmingState } from "./keymapArmingState.ts";

test("arming is per hold and resets on selection change and on community reset", () => {
  armGrant("h_a");
  assert.equal(isGrantArmed("h_a"), true);
  noteHoldSelected("h_b");
  assert.equal(isGrantArmed("h_a"), false);
  armGrant("h_b");
  resetKeymapArmingState();
  assert.equal(isGrantArmed("h_b"), false);
});
```

- [ ] **Step 2: Run and watch them fail.**

```bash
cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test "src/features/perch/lib/*.test.mjs" "src/features/perch-watch/lib/grantDwell.test.mjs"
```

Expected: `ERR_MODULE_NOT_FOUND` on the three modules.

- [ ] **Step 3: Implement.**

`grantDwell.ts`:

```ts
/** APPENDIX-NORMATIVE.md §2, the strict reading (16 §5.11). */
export const GRANT_DWELL_MS = 1500;

export type DwellState = { accruedMs: number; visible: boolean; lastTickMs: number | null; holdId: string };
export type DwellEvent = { type: "visible" | "hidden"; atMs: number } | { type: "tick"; atMs: number } | { type: "reset"; holdId: string };

export function dwellReducer(state: DwellState, event: DwellEvent): DwellState {
  switch (event.type) {
    case "reset":
      return { accruedMs: 0, visible: false, lastTickMs: null, holdId: event.holdId };
    case "visible":
      return { ...state, visible: true, lastTickMs: event.atMs };
    case "hidden":
      return { ...state, visible: false, lastTickMs: null };
    case "tick": {
      if (!state.visible || state.lastTickMs === null) return { ...state, lastTickMs: state.visible ? event.atMs : null };
      const delta = Math.max(0, event.atMs - state.lastTickMs);
      return { ...state, accruedMs: Math.min(GRANT_DWELL_MS, state.accruedMs + delta), lastTickMs: event.atMs };
    }
  }
}

export function dwellComplete(state: DwellState): boolean {
  return state.accruedMs >= GRANT_DWELL_MS;
}

export function dwellPercent(state: DwellState): number {
  return Math.floor((state.accruedMs / GRANT_DWELL_MS) * 100);
}
```

`keymapArmingState.ts`:

```ts
// Module-level on purpose: arming must survive a row re-render and must reset
// on hold_id change and on community switch (INV-11; registered resetter).
let armedHoldId: string | null = null;
let selectedHoldId: string | null = null;

export function armGrant(holdId: string): void {
  armedHoldId = holdId;
}
export function disarmGrant(): void {
  armedHoldId = null;
}
export function isGrantArmed(holdId: string): boolean {
  return armedHoldId === holdId;
}
export function noteHoldSelected(holdId: string | null): void {
  if (holdId !== selectedHoldId) armedHoldId = null;
  selectedHoldId = holdId;
}
export function resetKeymapArmingState(): void {
  armedHoldId = null;
  selectedHoldId = null;
}
```

`usePerchKeymap.ts` registers one bubble-phase `keydown` listener on `window` that returns early on `event.repeat`, `event.defaultPrevented`, a primary modifier, or an editable target; maps `event.key` through `PERCH_BINDINGS` filtered by `rowType` (a binding whose `disabledOn` includes the row type is a no-op) and dispatches `onVerb`/`onMove`/`onOpen`/`onPromote`/`onSnooze`/`onMarkDone`/`onMarkUnread`; `Escape` is deliberately not in `PERCH_BINDINGS` and the hook never handles it — the pane's `acquireEscapeSurface` is what stops `useMarkAsReadShortcuts` from marking read. `GrantControl.tsx`:

```tsx
export function GrantControl({ holdId, dwell, selectionCount, writeState, onRecord, disabledReason }: GrantControlProps) {
  const [armed, setArmed] = React.useState(() => isGrantArmed(holdId));
  React.useEffect(() => { noteHoldSelected(holdId); setArmed(isGrantArmed(holdId)); }, [holdId]);
  React.useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.repeat || event.defaultPrevented || hasPrimaryShortcutModifier(event) || event.altKey) return;
      if (event.key === "g" || event.key === "G") { armGrant(holdId); setArmed(true); event.preventDefault(); return; }
      if (event.key === "Enter" && isGrantArmed(holdId) && dwellComplete(dwell) && writeState.phase === "idle") { event.preventDefault(); onRecord(); }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [holdId, dwell, writeState.phase, onRecord]);
  if (selectionCount !== 1 || writeState.phase === "superseded") return null;
  const blocked = !dwellComplete(dwell) ? (dwell.accruedMs === 0 && !dwell.visible ? "read the blast radius first" : `keep the blast radius in view · ${dwellPercent(dwell)}%`) : disabledReason;
  const disabled = Boolean(blocked) || writeState.phase !== "idle";
  return (
    <div data-perch-role="grant" className="flex items-center gap-3">
      {armed ? <span data-testid="perch-grant-armed" className="text-2xs uppercase tracking-wide">armed — press Enter to record</span> : null}
      <Button type="button" variant="verdict" aria-disabled={disabled} aria-describedby="perch-grant-reason" onClick={() => { if (!disabled) onRecord(); }} data-testid="perch-grant-record">
        Record my decision and send it to the daemon
      </Button>
      <span id="perch-grant-reason" data-testid="perch-grant-dwell" className="text-xs text-[var(--perch-foreground-muted)]">{blocked ?? `${dwellPercent(dwell)}%`}</span>
    </div>
  );
}
```

`button.tsx` gains `verdict: "border border-[var(--perch-border-strong)] bg-[var(--perch-card)] text-[var(--perch-foreground)] hover:bg-[var(--perch-card-hover)]"` in the `variant` map — no `bg-primary` anywhere on that path. The pane's `VerdictSlot` for `blast-radius` feeds `dwellReducer` `visible`/`hidden` from its `IntersectionObserver`, and a 100 ms `setInterval` plus a `getBoundingClientRect` sample feeds `tick` (the second mechanism `16` §5.11 requires, so a fast scroll cannot carry the sentinel past the observer). `RefuseControl.tsx` is a `variant="verdict"` button labelled `Refuse` bound to `R` through `usePerchKeymap`'s `onVerb("refuse")`, one keypress, no dialog.

- [ ] **Step 4: Playwright.** `grant-two-stroke.spec.ts` asserts a single `G` records nothing, a held `G` (`repeat: true`) does not arm, the dwell gate freezes while the blast radius is scrolled out (the skeleton's test 04 verbatim), and `R` publishes leg 1 and posts leg 2 without a dialog; register skeleton tests 03 and 04 in `perch-verdict-pane.spec.ts`.

- [ ] **Step 5: Run.**

```bash
cd workspace/desktop && pnpm test && pnpm typecheck && pnpm check
cd workspace/desktop && pnpm test:e2e:smoke -- grant-two-stroke.spec.ts perch-verdict-pane.spec.ts
bash tools/check-perch-grant-affordance.sh
bash tools/check-copy-banned-terms.sh
```

Expected: green; R2/R3 of the grant gate find `.repeat`, `IntersectionObserver` and `1500` in exactly one file; R4/R7 find no `variant="default"` or `bg-primary` under `data-perch-role="grant"`; the keymap pass finds no `key: "A"`.

- [ ] **Step 6: Commit.**

```bash
cd workspace && git add desktop/src desktop/tests
git commit -s -m "feat(desktop): add the perch keymap and the dwell-gated two-stroke grant control"
```

---

## Task 27: The two-legged write, the `superseded` update card, and the signature-keyed reconciliation rule

**Files:**
- Create: `workspace/desktop/src/features/perch-watch/lib/verdictWrite.ts`, `lib/verdictWrite.test.mjs`, `useVerdictWrite.ts`
- Create: `workspace/desktop/src/features/perch-watch/lib/isTheDecision.ts`, `lib/isTheDecision.test.mjs`
- Modify: `workspace/desktop/src-tauri/src/commands/perch_verdict.rs` (`perch_publish_verdict_update` — the `superseded` reply card; the second caller of `submit_governance_event`)
- Modify: `workspace/desktop/src/shared/api/tauriPerch.ts` (`perchPublishVerdictUpdate`; `PERCH_RELAY_WRITE_COMMANDS` becomes two)
- Modify: `workspace/desktop/src/features/perch-evidence/ui/cards/VerdictCard.tsx` (renders "not the decision" from the predicate)
- Create: `workspace/desktop/tests/e2e/two-legged-write.spec.ts`, `tests/e2e/perch-concurrent-decision.spec.ts` (+ skeleton verdict-pane test 05, lifecycle test 04-INV-36 registered)

**Interfaces:**
- Consumes: `perchRecordVerdict`, `perchDecideHold`, `perchGetHold`, `VerdictWriteState` (Task 25).
- Produces:
  ```ts
  export type VerdictWriteEvent = { type: "start" } | { type: "leg1-ok"; atMs: number; intentEventId: string } | { type: "leg1-failed"; reason: string } | { type: "leg2-ok"; outcome: PerchDecideOutcome } | { type: "leg2-unreachable"; reason: string } | { type: "leg2-rejected"; reason: string };
  export function verdictWriteReducer(state: VerdictWriteState, event: VerdictWriteEvent): VerdictWriteState;
  export function useVerdictWrite(holdId: string): { state: VerdictWriteState; record: (decision: "grant" | "refuse", rationale: string | null, armedAtMs: number | null) => Promise<void> };
  export function isTheDecision(card: { holdId: string; signatureHex: string }, record: { hold_id: string; decision: { signature: { signature_hex: string } | null } | null } | null): "decision" | "not-the-decision" | "unresolved";
  // Tauri
  #[tauri::command] pub async fn perch_publish_verdict_update(input: VerdictUpdateInput { hold_id, own_intent_event_id, superseded_by, superseded_at_ms }, state) -> Result<{ nostr_intent_event_id: String }, String>
  ```
  `record` runs leg 1 then leg 2, never optimistically; on `superseded` it publishes the update card (a NIP-10 reply to its own leg-1 card carrying `leg2.state: "superseded"`, `superseded_by`, `superseded_at_ms`) and never retries or re-signs. The predicate joins on `signature_hex` (C13/C16), never on the event id; with no daemon record it is `unresolved`, never a guess.

- [ ] **Step 1: Write the failing tests.**

`verdictWrite.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { verdictWriteReducer } from "./verdictWrite.ts";

const idle = { phase: "idle" };

test("the four terminal states are reached only through recorded, never optimistically", () => {
  let s = verdictWriteReducer(idle, { type: "start" });
  assert.equal(s.phase, "sending");
  s = verdictWriteReducer(s, { type: "leg1-ok", atMs: 5, intentEventId: "aa".repeat(32) });
  assert.equal(s.phase, "recorded");
  const dispatched = verdictWriteReducer(s, { type: "leg2-ok", outcome: { outcome: "dispatched", rule: null, reason: null, receipt_id: "r-1", decided_at_ms: 6, superseded_by: null, replayed: false } });
  assert.equal(dispatched.phase, "daemon-dispatched");
  const late = verdictWriteReducer(s, { type: "leg2-ok", outcome: { outcome: "refused_late", rule: "runtime.containment_refused", reason: "no containment lease store is configured", receipt_id: null, decided_at_ms: 6, superseded_by: null, replayed: false } });
  assert.deepEqual(late, { phase: "refused-late", ruleName: "runtime.containment_refused", reason: "no containment lease store is configured" });
  const governance = verdictWriteReducer(s, { type: "leg2-ok", outcome: { outcome: "refused_late_governance", rule: "governance.receipt_veto", reason: "the attested decision is a veto", receipt_id: null, decided_at_ms: 6, superseded_by: null, replayed: false } });
  assert.equal(governance.phase, "refused-late-governance");
  const unreachable = verdictWriteReducer(s, { type: "leg2-unreachable", reason: "daemon unreachable: connection refused" });
  assert.equal(unreachable.phase, "daemon-unreachable");
  const superseded = verdictWriteReducer(s, { type: "leg2-ok", outcome: { outcome: "superseded", rule: "hold_already_decided", reason: "another operator's grant was recorded first", receipt_id: null, decided_at_ms: 7, superseded_by: "bb".repeat(32), replayed: false } });
  assert.equal(superseded.phase, "superseded");
  assert.equal(superseded.winningIntentEventId, "bb".repeat(32));
  assert.equal(superseded.winningDecision, "grant");
});

test("a leg-2 outcome cannot arrive before leg 1 was recorded", () => {
  const s = verdictWriteReducer({ phase: "sending" }, { type: "leg2-ok", outcome: { outcome: "dispatched", rule: null, reason: null, receipt_id: null, decided_at_ms: 1, superseded_by: null, replayed: false } });
  assert.equal(s.phase, "sending", "ignored: there is no intent record to acknowledge");
});
```

`isTheDecision.test.mjs`:

```js
import assert from "node:assert/strict";
import test from "node:test";
import { isTheDecision } from "./isTheDecision.ts";

const sig = "dd".repeat(64);
test("a card is the decision iff its signature bytes are on the daemon record for its hold", () => {
  const record = { hold_id: "h_a", decision: { signature: { signature_hex: sig } } };
  assert.equal(isTheDecision({ holdId: "h_a", signatureHex: sig }, record), "decision");
  assert.equal(isTheDecision({ holdId: "h_a", signatureHex: "ee".repeat(64) }, record), "not-the-decision");
  assert.equal(isTheDecision({ holdId: "h_a", signatureHex: sig }, { hold_id: "h_a", decision: null }), "not-the-decision");
  assert.equal(isTheDecision({ holdId: "h_a", signatureHex: sig }, null), "unresolved");
});
```

- [ ] **Step 2: Run and watch them fail.**

```bash
cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test "src/features/perch-watch/lib/verdictWrite.test.mjs" "src/features/perch-watch/lib/isTheDecision.test.mjs"
```

Expected: `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement.**

`verdictWrite.ts`:

```ts
import type { PerchDecideOutcome } from "@/shared/api/tauriPerch";
import type { VerdictWriteState } from "@/shared/ui/perch/WriteStateRow";

export type VerdictWriteEvent =
  | { type: "start" }
  | { type: "leg1-ok"; atMs: number; intentEventId: string }
  | { type: "leg1-failed"; reason: string }
  | { type: "leg2-ok"; outcome: PerchDecideOutcome }
  | { type: "leg2-unreachable"; reason: string }
  | { type: "leg2-rejected"; reason: string };

/** Never optimistic: `recorded` is reached only from a relay OK, every terminal state only from `recorded`. */
export function verdictWriteReducer(state: VerdictWriteState, event: VerdictWriteEvent): VerdictWriteState {
  switch (event.type) {
    case "start":
      return state.phase === "idle" ? { phase: "sending" } : state;
    case "leg1-ok":
      return state.phase === "sending" ? { phase: "recorded", atMs: event.atMs } : state;
    case "leg1-failed":
      return { phase: "daemon-unreachable", reason: `the intent card could not be published: ${event.reason}` };
    case "leg2-unreachable":
      return state.phase === "recorded" ? { phase: "daemon-unreachable", reason: event.reason } : state;
    case "leg2-rejected":
      return state.phase === "recorded" ? { phase: "daemon-refused", ruleName: "request_rejected", reason: event.reason } : state;
    case "leg2-ok": {
      if (state.phase !== "recorded") return state;
      const o = event.outcome;
      switch (o.outcome) {
        case "dispatched":
          return { phase: "daemon-dispatched", atMs: o.decided_at_ms, receiptId: o.receipt_id };
        case "refused_late":
          return { phase: "refused-late", ruleName: o.rule ?? "unknown", reason: o.reason ?? "" };
        case "refused_late_governance":
          return { phase: "refused-late-governance", reason: `${o.rule ?? ""}: ${o.reason ?? ""}` };
        case "superseded":
          return { phase: "superseded", winningIntentEventId: o.superseded_by ?? "", winningDecision: (o.reason ?? "").includes("refuse") ? "refuse" : "grant", decidedAtMs: o.decided_at_ms };
        case "expired":
          return { phase: "daemon-refused", ruleName: "hold_expired", reason: "the hold expired before the decision arrived; the action was never taken" };
        case "unknown_hold":
          return { phase: "daemon-refused", ruleName: "unknown_hold", reason: "the daemon has no record of this hold" };
      }
    }
  }
}
```

`useVerdictWrite.ts` drives the machine: `start` → `perchRecordVerdict` → `leg1-ok` (and pushes `{holdId, intentEventId, decision, rationale, decidedAtMs, signature}` onto the `verdictSpool` module store, drained on reconnect by re-posting leg 2 only — never re-signing) → `perchDecideHold` → `leg2-ok` | `leg2-unreachable` (a `daemon unreachable:` prefix) | `leg2-rejected`; on `superseded` it awaits `perchPublishVerdictUpdate({ holdId, ownIntentEventId, supersededBy, supersededAtMs: Date.now() })` and invalidates `perchKeys.holds()`, `perchKeys.needsAction()` and `perchKeys.reconcileDivergences()` (`PERCH_FRESHNESS.holds.invalidatesOnWrite`). `isTheDecision.ts`:

```ts
export function isTheDecision(
  card: { holdId: string; signatureHex: string },
  record: { hold_id: string; decision: { signature: { signature_hex: string } | null } | null } | null,
): "decision" | "not-the-decision" | "unresolved" {
  if (record === null) return "unresolved";
  if (record.hold_id !== card.holdId) return "unresolved";
  const recorded = record.decision?.signature?.signature_hex ?? null;
  return recorded !== null && recorded === card.signatureHex ? "decision" : "not-the-decision";
}
```

`VerdictCard.tsx` reads the hold through `perchKeys.hold(holdId)` and renders `data-perch-decision-verdict="decision|not-the-decision|unresolved"`: "not the decision — another operator's verdict executed" with a link to the winner when the record names a different signature, "unresolved — the daemon is unreachable, two intent records name each other" when null, and never picks one. `perch_publish_verdict_update` in `perch_verdict.rs` builds the update card (same grammar, `leg2: { state: "superseded", superseded_by, superseded_at_ms }`, `e` tag = the own leg-1 id with NIP-10 `reply` marker, `h` = the case channel) and publishes through `submit_governance_event`; `PERCH_RELAY_WRITE_COMMANDS` becomes `["perch_record_verdict", "perch_publish_verdict_update"]` and INV-RF1's console half asserts the marker set is still exactly `["swarm:verdict:v1"]`.

- [ ] **Step 4: Playwright.** `two-legged-write.spec.ts` drives each terminal state through the fixture's `decide` outcomes (`dispatched` with `delay_ms: 1200` so `sending → recorded → acknowledged` are all observed; `refused_late`; `daemonUnreachable`), asserting `data-perch-decision-state` transitions and `perch-decision-undo` count 0. `perch-concurrent-decision.spec.ts`: two contexts (`browser.newContext()` twice, different mock identities via `TEST_IDENTITIES`) against one fixture hold; the second's `decide` entry is `superseded` with `superseded_by` = the first's intent id (read from the first page's `perch-write-state-recorded` node); assert two `swarm:verdict:v1` cards in the case timeline, exactly one with `data-perch-decision-verdict="decision"` on **both** pages, the loser's `perch-verdict-update-published` node carrying `data-perch-superseded-by`, and — the arm that matters — after reloading the loser's page with the update card removed from the mock channel, the loser's first card still renders `not-the-decision` (derived from the daemon record, not from the update). Register the skeleton's verdict-pane test 05 and lifecycle test 04 (INV-36).

- [ ] **Step 5: Run.**

```bash
cd workspace/desktop && pnpm test && pnpm typecheck && pnpm check && pnpm check:file-sizes
cd workspace/desktop && pnpm test:e2e:smoke -- two-legged-write.spec.ts perch-concurrent-decision.spec.ts perch-verdict-pane.spec.ts perch-queue-lifecycle.spec.ts
cd workspace && cargo test --manifest-path desktop/src-tauri/Cargo.toml perch
bash tools/check-perch-write-allowlist.sh
```

Expected: green; the write allowlist still reads exactly five daemon routes.

- [ ] **Step 6: Commit.**

```bash
cd workspace && git add desktop/src desktop/src-tauri desktop/tests
git commit -s -m "feat(desktop): drive the two-legged verdict write and publish superseded when another console wins"
```

---

## Task 28: Milestone exit — the hold half of the demo script, the exit criteria run, and the flag flips on

> Blocked on Task 1.

**Files:**
- Modify: `docs/PERCH-DEV.md` (steps 11–16 appended to the walking-skeleton script)
- Modify: `workspace/preview-features.json` (`"defaultEnabled": true` on `perch`)
- Modify: `docs/plans/ambush-ui/integration/13-PLAN-THE-HOLD.md` (tick the exit criteria below with dates)

**Interfaces:**
- Consumes: everything above, a debug `swarm_detect --config rulesets-dev/perch-dev.yaml --serve --bind 127.0.0.1:9090`, the compose relay stack, `scripts/provision-perch.sh`, the desktop dev build with `AMBUSH_PERCH_DAEMON_URL`, `AMBUSH_PERCH_DAEMON_TOKEN`, `AMBUSH_PERCH_OPERATOR_SEED` and `AMBUSH_PERCH_OPERATOR_ID` exported.
- Produces: the observable behaviours in "Exit criteria", each demonstrated once by hand and recorded.

- [ ] **Step 1: Append the hold half to the demo script.**

```bash
# ── 11. Produce a hold.  The dev profile is live_response, so a RequestResponse
#        that hits RequireHuman is persisted rather than refused (Task 8). ───────
# Push the office-dropper scenario again; its escalation drives Pounce to request
# isolate_host at CRITICAL, which static.human_gate holds (human_gate_severity HIGH).
curl -sf -X POST http://127.0.0.1:9090/v1/ingest/events \
  -H 'content-type: application/json' --data @/tmp/perch-skeleton-events.json | jq '.[].status'
sleep 3
curl -sf "http://127.0.0.1:9090/v1/response/holds" \
  -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN" -H 'x-swarm-schema-version: 1' \
| jq '{open: .open_count, durable: .store_durable, holds: [.holds[] | {hold_id, state, action_kind, case_channel, notified_at_ms}]}'
# Exit criterion 1: open >= 1, durable true, and after ~2 s notified_at_ms is
# non-null and case_channel is a UUID (the bridge filed it).  If notified_at_ms
# stays null, read the daemon log for "hold_undeliverable" — the usual cause is
# a principal with no nostr_pubkey (F18).

# ── 12. Assert the queue record and the alarm reached the relay. ─────────────
CASE_CHANNEL=$(curl -sf "http://127.0.0.1:9090/v1/response/holds" -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN" -H 'x-swarm-schema-version: 1' | jq -r '.holds[0].case_channel')
curl -sf -X POST http://localhost:3000/query \
  -H "X-Pubkey: $PERCH_OPERATOR_PUBKEY" -H 'content-type: application/json' \
  -d "[{\"kinds\":[46010],\"#p\":[\"$PERCH_OPERATOR_PUBKEY\"],\"limit\":20}]" \
| jq '[.[] | select(.tags[] | .[0]=="hold")] | length'      # >= 1
curl -sf -X POST http://localhost:3000/query \
  -H "X-Pubkey: $PERCH_OPERATOR_PUBKEY" -H 'content-type: application/json' \
  -d "[{\"kinds\":[9],\"#h\":[\"$CASE_CHANNEL\"],\"limit\":20}]" \
| jq '[.[] | select(.content | startswith("<!-- swarm:hold:v1 -->"))] | length'   # exactly 1 open card

# ── 13. Open the app.  The Watch (perch flag on) shows the hold in HOLDS with
#        its TTL clock; the row appeared from the 26006 alarm, not from a poll.
cd "$AMBUSH/workspace/desktop" && pnpm dev
#   - select the hold; the Verdict Row renders five slots in order (criterion 7)
#   - press R  -> leg 1: a signed kind:9 swarm:verdict:v1 in the case channel
#                 leg 2: POST /decide -> outcome refused_by_operator (criterion 3)
#   - on the SECOND hold (block_egress), press G, read the blast radius for
#     1.5 s, press Enter -> leg 1, leg 2 -> the daemon executes (dry-run adapter)
#     and the response body carries capability_lease with
#     expires_at_ms - issued_at_ms == 60000 measured from decided_at_ms (criterion 2)
#   - on a THIRD hold (isolate_host with lease_store_path REMOVED from the
#     profile), G+Enter -> refused_late naming runtime.containment_refused,
#     rendered as an outcome, not an error (criterion 8)

# ── 14. Prove the record and the card are two things. ───────────────────────
curl -sf "http://127.0.0.1:9090/v1/response/holds?include_terminal=true" \
  -H "Authorization: Bearer $SWARM_OPERATOR_TOKEN" -H 'x-swarm-schema-version: 1' \
| jq '.holds[] | select(.state=="refused") | {hold_id, decision: {operator_id, voter_id, outcome, nostr_intent_event_id, signature_hex: .decision.signature.signature_hex}}'
# The signature_hex above equals fact.signature.signature_hex inside the
# verdict card the relay stores — the join is the signature, never the event id.

# ── 15. Kill the daemon mid-decision (criterion 5). ───────────────────────────
# Put a hold into deciding with a stalled decide (inject a 70 s sleep in the
# dry-run adapter under AMBUSH_PERCH_SLOW_ADAPTER_MS=70000), press G+Enter, then
# `kill -9` the daemon within 5 s.  Restart it.  Expected: the hold reloads as
# deciding; within one sweep tick it moves to failed with
# "the decision stalled; whether the action ran is unknown"; the console renders
# "the daemon did not answer" and nothing shows a half-authorized state.

# ── 16. Two consoles, one hold (INV-36). ───────────────────────────────────────
# Run a second desktop instance with a second principal (both p-tagged).  Both
# press G+Enter on the same hold within a second.  Expected: one 200, one 409
# hold_already_deciding|hold_already_decided; the loser re-reads, publishes a
# superseded card, and its own card renders "not the decision" on BOTH screens.
```

- [ ] **Step 2: Run every gate once, end to end.**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
bash tools/check-gates-wired.sh && bash tools/check-workspace-layering.sh && bash tools/check-runtime-panic-contract.sh && bash tools/check-visibility-baseline.sh && bash tools/check-no-unrouted-authorize.sh && bash tools/check-perch-write-allowlist.sh && bash tools/check-perch-grant-affordance.sh && bash tools/check-copy-banned-terms.sh && bash tools/check-perch-wire-parity.sh
cd workspace && just ci
cd workspace && RELAY_URL=ws://localhost:3001 cargo test -p ambush-test-client --test e2e_workflow_approval --test e2e_operator_alarm_pgate --test e2e_perch_hold_path -- --ignored
cd workspace/desktop && pnpm test:e2e:smoke
```

Expected: every command exits 0. Record the exact commit hash the run was made against.

- [ ] **Step 3: Flip the flag.**

`workspace/preview-features.json`: the `perch` entry gains `"defaultEnabled": true` (`01-DESIGN.md` §7: it flips on by default at The hold's exit). `E2E_OPT_IN_FEATURES` stays as it is — the existing Home specs keep seeding it off explicitly, because `seedPreviewFeaturesEnabled` writes an override for every listed id; add `perch: false` to the seeded overrides for specs that do not opt in.

- [ ] **Step 4: Commit.**

```bash
git add docs/PERCH-DEV.md workspace/preview-features.json workspace/desktop/tests/helpers docs/plans/ambush-ui/integration/13-PLAN-THE-HOLD.md
git commit -s -m "docs(perch): extend the demo to the hold path and enable the console by default at The hold's exit"
```

---

## Self-Review

Coverage of `01-DESIGN.md` §6's The hold items and the other obligations this milestone carries:

| Design item | Task(s) |
|---|---|
| B1 `HeldAction` + `HeldActionStore` + sweep + `RuntimeEvent::ResponseHeld` | 3 (config), 4 (record), 5 (store + guard), 6 (file store, restart), 7 (event + scope arm), 8 (intercept + C4 gate), 9 (sweep) |
| B2 `POST /v1/response/holds/{id}/decide`, lease minted at decision time | 13 |
| B2r the two hold reads (reconciliation authority, `store_durable`, `deciding_stalled_count`, `Read` scope) | 10 |
| B2o `approved_by` in the receipt audit | 11 |
| B2g governance + partition re-evaluation on decide (G0–G3; G4 unreachable and said so) | 12 |
| B5 gate `/v1/events/stream`, drop its wildcard ACAO, scope the review POST | 14 |
| Bridge: `46010` publish, `26006` alarm, `ensure_case_channel` on `ResponseHeld`, F18 refusal | 15, 16, 17 |
| Relay verification: the landed `46010`/`26006` patches exercised end to end; `CHANNEL_REPAIR_KINDS` +3 (design §8) | 18 |
| Tauri `perch_reads` / `perch_writes` / `perch_verdict` + the sign-gate parity | 19, 20, 21 |
| e2eBridge fixtures for holds, decisions, the alarm control seam | 22 |
| The Watch queues remapped behind the `perch` flag, reconciliation + `UNRECONCILED` split, counters | 23, 24 |
| Verdict pane with the fixed slot order across fifteen kinds | 25 |
| Grant control two-stroke, keymap, `Escape` never marks read | 26 |
| Write-state machine, `superseded`, the signature-keyed reconciliation rule | 27 |
| Walking skeleton extended to a real hold; exit criteria; flag flips on | 28 |
| Decisions the plan set left open | 1 (D4 confirmation), 2 (verdict key provisioning) |

Invariants landed with their subjects: INV-01 (19, 20), INV-02 (25), INV-10 (26), INV-11 (26), INV-12 (21 — the `h` tag on every published verdict card, asserted in `perch_verdict.rs` tests), INV-13 (25's `VerdictCard` through the registry's channel check), INV-18 (9, 24), INV-19 (deferred with `/handoff` to Operator-complete; the expired row it counts exists from 24), INV-22 (19), INV-27 (10's path test, 13), INV-28 (13, 25), INV-29 (21's parity test on the new producer), INV-32 (26), INV-33 (27), INV-34 (26 — `S` declared `disabledOn: ["hold"]`), INV-35 (24), INV-36 (27).

Contradictions in the plan set this plan resolved rather than deferred, each flagged in the summary: the store's crate (`12`/`20` say `swarm-ingest-runtime`, `16`'s skeleton test says `swarm-runtime`; `swarm-runtime` wins because the bridge must hold the store handle without linking the ingest crate, W3-13); the terminal hold card's trigger (`12` §4.7 publishes no `ResponseHeld` on `granted → executed|failed` while `13`'s hold schema requires one terminal card; `decide_hold` publishes `ResponseHeld` on every terminal transition); `HeldActionView` lacking `case_channel` while `14` §7.3.1 builds the leg-1 card's `locator.case_channel` from it (three fields added to the record and the view); the `26006` frame schema id under the rename (`swarm.perch.frame.hold_alarm.v1`); the wire schema's example `key_id: "perch-operator-1"`, which `swarm_crypto::verify_detached_signature` would refuse (the console computes `sha256(pubkey)`); `hold_ttl_ms_by_threat_class` keyed by slug, not `ThreatClass`, because of the `Custom(String)` variant.

Out of this milestone by design: the `swarm:receipt:v1`, `swarm:lease:v1` and `swarm:rollback:v1` presenters (the receipt is in the decide response body and on the terminal hold card's `decision.receipt_id`; the bridge's exhaustive event-to-wire classifier deliberately does not publish `ResponseExecution` as a receipt card, so Operator-complete must name and test the actual producer), `/handoff` and INV-19's control, B2g-s, `P1-16`'s counters (First card), a Settings card for the daemon base URL and bearer (the env fallback and `perch_configure_daemon` carry the demo).

## Exit criteria

Each is observable, not a task; each is demonstrated once on the dev stack by Task 28 and recorded with the commit hash.

1. A destructive `RequestResponse` that hits `RequireHuman` on the live-response dev profile persists a hold: `GET /v1/response/holds` lists it with `store_durable: true`, and `swarmctl` and The Watch show the same open-hold list read through that route.
2. Within two seconds of the hold, the case channel exists with the bridge and the operator as members, one `swarm:hold:v1` card and one `46010` (tags exactly `h`, `p`, `hold`, `card`; no `e`) are stored, one `26006` reached the operator's self-`#p` REQ and reached no other subscriber, and the hold's `notified_at_ms` and `case_channel` are populated on the daemon.
3. `R` on a hold produces a signed `swarm:verdict:v1` card in the case channel **and** a daemon decision record with `outcome: refused_by_operator`, `dispatched: false`, and `decision.signature.signature_hex` equal to the card's `fact.signature.signature_hex`; the console renders `sending → recorded → acknowledged`, never a checkmark before the relay OK, and neither leg is described as the other.
4. `G`, 1500 ms with the blast radius fully in view, `Enter` on a non-containment hold produces a `capability_lease` whose `expires_at_ms − <CAS instant>` is 60,000 ms, a receipt whose `audit.approved_by.hold_id` names the hold, and a `HoldDecisionRecord.governance_clearance` of `receipt_signature_ok`; a single `G`, a held `G`, or `Enter` before the dwell completes records nothing.
5. `G`+`Enter` on `isolate_host` with `runtime.containment.lease_store_path` unset answers 200 with `outcome: refused_late`, `refusal.rule: runtime.containment_refused`, and the console renders it as an outcome in the outcome register with no retry.
6. A hold left undecided for `hold_ttl_ms` moves to `expired` on the sweep, publishes a terminal `swarm:hold:v1` reply card, produces no receipt, no trail and no lease, stays listed in HOLDS as an expired row, and answers `409 hold_expired` to a decide.
7. Killing the daemon between the compare-and-set and the outcome write, then restarting it, reloads the hold as `deciding` and resolves it to `failed` with "the decision stalled; whether the action ran is unknown" within one sweep tick; the console renders the intent card as recorded and not acknowledged, and nothing renders a half-authorized state.
8. A malformed signature answers 422 with nothing written; a bearer whose principal lacks `Approve` answers 403; a replay of the same `nostr_intent_event_id` answers 200 `replayed: true` with the byte-identical record; a hold in `created` (relay stopped before the bridge could file it) is decidable through `swarmctl` and renders in HOLDS from the daemon list with the reason its card never published.
9. A relay `46010` whose `hold_id` the daemon does not know renders `UNRECONCILED` (ordinary register on a non-durable store, destructive on a durable one), offers no grant, and increments `perch_queue_reconcile_divergences_total`; a `46010` or `26006` from an unadmitted pubkey renders nothing and increments `perch_frame_unadmitted_total`.
10. Two consoles deciding one hold: exactly one daemon decision record; the loser receives `409 hold_already_deciding` or `409 hold_already_decided`, re-reads, publishes a `superseded` update card naming the winner, and its first card renders as not the decision on both screens — and still does after the update card is deleted, because the rule joins on `signature_hex`.
11. The Verdict Row renders ACTION → BLAST RADIUS → IF YOU UNDO → WHY WE ARE ASKING → WHAT GRANTING OPENS for all fifteen `ResponseAction` kinds, a pending containment slot for exactly the four containment actions, and `threat_class`/`severity` marked request-carried; the fifteen-variant snapshot test and the Playwright DOM-order test both pass.
12. No rendered string in the perch roots contains `Perch`, `Approve`, `Approved`, a bare `lease` label or a reassurance phrase; no verdict binding uses `a`/`A`; `pnpm check:px-text` and the file-size gate pass; every engine and workspace gate in Task 28 Step 2 exits 0.
13. With the `perch` flag off, Home, the inbox and every pre-existing smoke spec behave exactly as before; with it on (the default after Task 28), `/` is The Watch.

## Sizing

Engineer-days (1 engineer-week = 5 days). Rust tasks serialize through the one Rust engineer unless noted; desktop tasks run on the frontend track in parallel from Task 19 onward once Task 10's DTOs are fixed.

| Task | Days | Note |
|---|---:|---|
| 1 Decision: D4 | 0.5 | a row and a confirmation |
| 2 Decision: verdict key | 0.5 | a row and a decision; option (a) assumed |
| 3 `ResponseHoldSettings` | 1 | |
| 4 Record types | 1.5 | |
| 5 Store + guard | 3 | the state machine and its tests |
| 6 File store + restart | 2 | |
| 7 `ResponseHeld` | 1.5 | seven edits, one argued |
| 8 Intercept + C4 gate | 3 | the router wiring is the cost |
| 9 Sweep | 2 | |
| 10 B2r + router + reads | 4 | includes the 49-path array and the disjointness test |
| 11 B2o | 3 | four call sites, receipt tests |
| 12 B2g | 5 | the move, G1–G3, six tests, the visibility gate |
| 13 B2 decide | 8 | the largest item: wire preimage, engine fn, route, taxonomy, eleven tests |
| 14 B5 | 2 | |
| 15 Bridge HoldId + card + tags + Held arm | 4 | |
| 16 Bridge publisher + callbacks | 5 | |
| 17 Bridge 26006 lane | 2 | |
| 18 Relay verification + repair kinds | 3 | needs the live stack |
| 19 Tauri client + reads | 3 | |
| 20 Tauri decide | 2 | |
| 21 Tauri verdict + key | 4 | includes the second funnel and the inventory test |
| 22 E2E module | 3 | |
| 23 Shared modules | 3 | |
| 24 The Watch | 7 | queue remap, reconciliation, two specs |
| 25 Verdict Row | 7 | fifteen-kind builder, three components, two presenters |
| 26 Keymap + grant | 6 | the dwell gate is where the time goes |
| 27 Two-legged write + superseded | 5 | two Playwright specs incl. two contexts |
| 28 Exit | 3 | the demo run and the gate sweep |
| **Total** | **94 days** | 18.8 engineer-weeks: 11.8 Rust (Tasks 3–21 engine and Tauri), 6.8 frontend, 0.2 decisions. `20-TASK-BREAKDOWN.md` priced the same scope at 17.75 ew; the difference is the bridge hold path (`P0-19` covered findings only), the relay verification, and the Tauri crate's daemon client, none of which had a card. |

Honest risks to the sizing: Task 13's `classify_execution` rule mapping depends on the exact `rule_name` strings `static_gate.rs` and `configurable_gate.rs` emit and may need a day of reading; Task 26's dwell gate has two timing mechanisms and Playwright timing on CI has cost a day in every comparable feature; Task 2 undecided by the time Task 13 starts costs the voter-binding step and Task 21 in full.
