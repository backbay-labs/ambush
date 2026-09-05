# Operator-Complete Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the remaining nine console surfaces, the four daemon items `01-DESIGN.md` §6 assigns to this milestone (B4, B6, B1c, B2g-p), the bridge's lease and rollback cards, the six chart primitives, the last four CI gates, and the deployment packaging, so that a shift can be worked end to end on `/`, `/leases`, `/lanes`, `/ledger`, `/tuning`, `/gaps`, `/policy`, `/handoff`, a case's canvas and terminal, and handed off — with every card that can be signed rendering above tier 0.

**Architecture:** Process A (`swarm_detect --serve`) gains one read route (B4), one event variant (B1c), two partition stamps (B2g-p) and a provisioned spine signing identity (B6) whose per-issuer chain heads live beside the bridge's spool; the in-process bridge turns `open_leases()` diffs and `ContainmentReleased` events into `swarm:lease:v1` and `swarm:rollback:v1` cards and seals every envelope it publishes. Process D (the Tauri console) adds six feature surfaces under `workspace/desktop/src/features/perch*/`, all reading the relay through the seven existing REQs and the daemon through `perch_*` commands whose route strings are Rust constants; the only new daemon-bound non-GET is none — INV-01's five stand. Packaging composes the workspace's relay chart into the engine chart as an aliased dependency and hardens the dev compose.

**Tech Stack:** Rust 1.97.1 / edition 2024 (engine, `crates/`), Rust 1.95.0 / edition 2021 (`workspace/`, incl. `workspace/desktop/src-tauri`), axum, tokio, serde, `ed25519-dalek` through `swarm-crypto` in the engine and directly in Tauri, `prometheus-client`, `nostr`; React 19 + TanStack Router + React Query + Tailwind (rem tokens) + hand-authored SVG; Playwright (mock bridge) + `node:test`; Helm 3 + Docker Compose.

**Spec:** `docs/plans/ambush-ui/integration/01-DESIGN.md` (with `00-DECISIONS.md` ruling over it). Surface specs: `docs/plans/ambush-ui/04-SURFACES-AND-UX.md` §2.4–§2.14, `build/17-COMPONENT-SPECS.md`, `build/18-DATAVIZ.md`, `build/12-BACKEND-BILL-API.md` §11 / §13 / §14, `build/11-BRIDGE-CRATE.md` §9 / §11, `08-TRUST-AND-GOVERNANCE-UX.md` §4 / §6 / §7.

## Global Constraints

- **Engine lints, exact:** root `Cargo.toml` `[workspace.lints.clippy] unwrap_used = "deny"`, `expect_used = "deny"`; every new engine file starts under a crate with `#![forbid(unsafe_code)]`; `[profile.release] panic = "abort"` so no `catch_unwind`; `tools/check-runtime-panic-contract.sh` scans every `crates/*/src` (the bridge included per W3-6). Every new `pub` item carries a `///` doc comment.
- **The TCB rule:** `swarm-crypto`, `swarm-policy`, `swarm-spine` never gain a dependency on `swarm-perch-wire`, `swarm-perch-bridge` or anything under `workspace/`; `swarm-perch-bridge` is in `TRUST_SENSITIVE` (ADR 0015 C2) and its `src/lib.rs` carries the whole-line headings `//! ## Owns` and `//! ## Does not own`; `bash tools/check-workspace-layering.sh` runs on every engine commit. Cross-workspace edges are exactly D2's: engine → `workspace/crates/ambush-ws-client`, `workspace/crates/ambush-sdk`; `workspace/desktop/src-tauri` → `crates/swarm-perch-wire` only.
- **No charting library** (`18-DATAVIZ.md` §1): the chart layer takes zero runtime npm dependencies; every chart is hand-authored SVG; colour reaches a node only through a CSS class resolving `hsl(var(--perch-viz-…))` — never a `fill=`/`stroke=` presentation attribute other than `none` or `url(#…)`, never a hex literal (`tools/check-perch-chart-tokens.sh` R1/R2/R4).
- **Text sizing:** rem tokens only — `text-base`, `text-sm`, `text-xs`, `text-2xs`, `text-3xs`, `text-eyebrow`; no `text-[Npx]`, `text-[Nrem]`, no `font-size="…"` attribute, no `fontSize={…}` prop (`pnpm check:px-text`, `pnpm check:svg-font-size`). A primary content line is `text-sm` or larger; `text-3xs` renders no word.
- **Tokens:** a perch component reads `--perch-*` names only (registry R-4); `var(--ambush-*)`, `var(--card)`, `var(--muted-foreground)` and the other shadcn names are forbidden under `workspace/desktop/src/features/perch*/`, `src/shared/ui/perch/` and `src/shared/viz/`.
- **The 1000 gate-line cap** (`content.split(/\r?\n/).length`) on every governed root; **never edit** the frozen files in `build/15-FILE-SPLIT-PLAN.md`: `shared/api/tauri.ts` (1108), `shared/api/relayClientSession.ts` (1084), `shared/api/types.ts` (1000), `shared/ui/sidebar.tsx` (1011), `shared/ui/markdown.tsx` (1906), `features/search/ui/TopbarSearch.tsx` (998 gate-lines, re-measured 2026-09-02 — new sibling `PerchOmnibox.tsx`, never an edit), `features/channels/useUnreadChannels.ts`, `features/channels/readState/readStateManager.ts`, `features/profile/ui/UserProfilePanel.tsx`; wrap, never edit, `features/channels/ui/ChannelPane.tsx`, `ChannelScreen.tsx`, `ChannelCanvas.tsx`.
- **Copy bans, verbatim** (`APPENDIX-NORMATIVE.md` §7, `build/skeleton/tools/copy-ban-list.tsv`, W3-8): no `Approve`/`Approved` as a control label; no `A`/`a` key on a verdict control; no `Deny`/`Denied` as an operator label; no `verified by`, `trusted`, `proof`, and no shield or lock glyph (`🛡 🔒 🔐 ⚠`) beside an attestation; no `signed`/`verified` on a finding, escalation, hold, containment-lease or bare response-receipt card; no quorum fraction (render `committee of 1 (solo transport)`); no bare source count (always `N sources / M agents` or the typed absence); no `Everything looks good`, `All clear`, `You're all caught up`, `no data`, `nothing to see`; no `hunt` as a noun; no `clowder`; no `Swarm Team Six`; **no rendered `Perch`** (the product is Ambush); no `!` in a rendered string longer than three characters; no bare `lease` or bare `lane` outside the ruled senses.
- **Badges name the chain and the tier:** `Ed25519 · tier 1`, `secp256k1 · tier 0`, `Ed25519 · chained · seq N` for tier 2; `UNATTESTED` and `UNATTESTED — BY DESIGN` under a partition contingency; the rollback badge renders tier, chain, the limit sentence `attestation matches this body`, and the attestation's own `decision` (ADR 0016 C6a).
- **The export bundle** (`08` §6.4): `MANIFEST.json` stamps `verification_tier` (0 | 1 | 2) per file and `answers_who_approved`; `receipts/` and `envelopes/` are byte-identical to what the daemon and relay returned (no reserialization); `UNRECONCILED` holds are excluded; `envelopes/` is empty until B6 and `VERIFY.md` says why.
- **INV-01:** the console's daemon-bound non-GET set stays exactly the five routes in `PERCH_WRITE_ROUTES`; this plan adds reads only (`perch_deposits` exists; `perch_get_incident`, `perch_evasion_coverage`, `perch_policy` are new **GET** commands, each a Rust `const` route in `perch_reads.rs` and a case in `e2ePerchBridge.ts`).
- **Testids and roles:** every testid begins `perch-`; `data-perch-role` is the closed thirteen-value set (`grant refuse verdict-slot blast-radius provenance-row derived source-count evidence-card adversary-string containment-release containment-extend-disabled empty-state gap-link`) — no new value.
- **Commits:** `git commit -s -m "type(scope): subject"` (Conventional Commits) with the attribution trailers in use on this branch; a new `tools/check-*.sh` lands with its `run:` step in `.github/workflows/ci.yml` **in the same commit** (`tools/check-gates-wired.sh`); a new `desktop/scripts/*.mjs` gate lands chained into `workspace/desktop/package.json`'s `check` script in the same commit.
- **Runtime mode (D4):** this milestone runs against the live-response dev profile `rulesets-dev/perch-dev.yaml` with `runtime.containment.lease_store_path` set; on the detect-only profile `/leases` renders `no-containment-lease-store-configured` and every containment task's Playwright spec still passes against the mock bridge.
- **Test commands:** engine `cargo test -p <crate> <filter>` from the repository root; workspace Rust `cd workspace && cargo test -p <crate>`; Tauri Rust `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml <filter>`; desktop unit `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test <file>.test.mjs`; Playwright `cd workspace/desktop && pnpm test:e2e:smoke`; contrast/viz `node docs/plans/ambush-ui/build/viz/contrast.mjs --check`. Activate Hermit (`. ./bin/activate-hermit` inside `workspace/`) before any workspace command.

---

## Consumed from earlier milestones

This plan names files and symbols the Ground, First card and The hold plans create. The names below are the `build/skeleton/` names **renamed per D1** (`swarm:` markers, `perch` prefix). If the landed file differs, the landed file wins and the executor edits the plan's step in place.

| Symbol | Path | Milestone |
|---|---|---|
| `perch_operator_router(config, ingest) -> Result<Router, OperatorHttpError>`, `PerchHttpState { ingest: IngestState }`, `PERCH_ROUTER_PATHS: [&str; N]`, `perch_operator_router_declared_paths()` | `crates/swarm-runtime-http/src/http/perch/mod.rs` | The hold |
| `HeldAction`, `HoldDecisionRecord`, `HeldActionStore` (daemon side) | `crates/swarm-runtime/src/held_action.rs` | The hold |
| `perch_ops::{capture_hold, decide_hold, record_finding_feedback, mint_incident}` | `crates/swarm-ingest-runtime/src/ingest/perch_ops/` | First card / The hold |
| `generate_perch_openapi` binary, `tools/check-perch-openapi.sh`, `tools/generate-perch-openapi.sh` | `crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs` | The hold |
| `PerchBridge::build(BridgeBuildInput)`, `BridgeBuildInput { config, colony_id, events, admitted_identities, containment, hold_store, approve_pubkeys, shutdown }`, `classify(&RuntimeEvent) -> Stream`, `Marker`, `CardBody`, `CaseRouting::ensure_case_channel`, `PublishStep`, `BridgeMetrics`, `PerchBridgeConfig`, `IdentityTable`, the spool (`Spool`, `Cursor`, `GapSlot`) and the pacer | `crates/swarm-perch-bridge/src/` | First card / The hold |
| containment sweep and `CaseRouting` inputs for `LeaseWatcher`; no `leases.rs` stub | `crates/swarm-runtime/src/containment.rs`, `crates/swarm-perch-bridge/src/channels.rs` | First card / The hold; Task 8 creates the working watcher and card body |
| `CardEnvelope::seal_unsigned(kind, issuer, seq, prev, issued_at, fact)`, `CardKind`, `LeaseCard`, `RollbackCard`, `HeldAction`, `HoldDecisionRecord`, `FactIssuer`, `HUMAN_SEP` | `crates/swarm-perch-wire/src/{envelope.rs,cards.rs}` and the TS mirror `workspace/desktop/src/features/perch/wire/` | First card |
| `tauriPerch.ts` (13 wrappers, `PERCH_READ_COMMANDS`, `PERCH_DAEMON_WRITE_COMMANDS`, `PERCH_TAURI_COMMANDS`, `PerchContainmentView`, `PerchReleaseOutcome`), `perchKeys.ts` (`perchKeys`, `PERCH_FRESHNESS`, `PERCH_NO_RETRY`, `isDaemonDependentQuery`), `perchSubscriptions.ts`, `perchEphemeralStore.ts` (`getPerchEphemeralSnapshot`, `subscribePerchEphemeral`, `perchTelemetryAgeMs`) | `workspace/desktop/src/shared/api/` | First card / The hold |
| `CommunityScopedSingleton`, `COMMUNITY_SCOPED_SINGLETONS`, `RESETTERS`, `runResetters` | `workspace/desktop/src/features/communities/communityScopedRegistry.ts` | Ground |
| `PerchView`, `derivePerchShellRoute`, `PERCH_NAV`; the route files under `workspace/desktop/src/app/routes/` | `workspace/desktop/src/app/perchViews.ts`, `routes.ts` | Ground / The hold |
| `AdversaryString`, `DerivedMarker`, `SourceCount` + `agentIdOfSource`, `EmptyState`, `ProvenanceRows`, `WriteStateRow`, `SeverityChip`, `SeverityBar`, `ThreatClassLabel`, `HoldTtlClock`, `EyebrowLabel`, `PillarRail`, `ConfidenceMeter`, `NotchedRegion` | `workspace/desktop/src/shared/ui/perch/` | The hold |
| `PERCH_BINDINGS`, `usePerchKeymap`, `PerchSurfaceBoundary`, `GovernanceStrip` slot in `AppShell` (chrome conditional), `InstrumentationStrip`, `StreamGapRow`, `WatchQueueSection`, `VerdictPane` | `workspace/desktop/src/features/perch/`, `features/perch-watch/` | The hold |
| `swarmCardRegistry` (`satisfies Record<SwarmMarkerKind, SwarmCardEntry>`), `parseSwarmMarker`, `SwarmCardContext`, `EvidenceCardFrame`, presenters for `finding`, `escalation`, `hold`, `verdict`, `receipt` | `workspace/desktop/src/features/perch-evidence/` | First card / The hold |
| `perch_reads.rs` (7 reads), `perch_writes.rs` (`PERCH_WRITE_ROUTES: [&str; 5]`), `perch_verdict.rs`, `crate::perch::client::{perch_daemon_request, PerchMethod, PERCH_DAEMON_WRITES, PerchClientError, redact_for_ipc}`, `perch_sign_gate` | `workspace/desktop/src-tauri/src/commands/`, `src-tauri/src/perch/` | The hold |
| `installPerchBridge`, `perchFixture`, `perchHold`, `emitSwarmCard`, `advancePerchClock`, `readPerchCounter`, `readPerchExportManifest`, `PERCH_CASE_CHANNEL`, `PERCH_LANE_CHANNEL`, `PERCH_ADMITTED_ISSUER`, `PERCH_CONTAINMENT_LEASE`, `PERCH_NOW_MS`; `handlePerchMockCommand` and the `window.__AMBUSH_E2E_PERCH__` / `__AMBUSH_E2E_PERCH_CONTROL__` seams | `workspace/desktop/tests/helpers/perchBridge.ts`, `workspace/desktop/src/testing/perch/e2ePerchBridge.ts` | The hold |
| `tools/check-copy-banned-terms.sh` + `workspace/desktop/scripts/check-copy-banned-terms.mjs` + `tools/copy-ban-list.tsv`, `tools/check-perch-grant-affordance.sh`, `tools/check-perch-adversary-strings.sh`, `tools/check-perch-write-allowlist.sh`, `tools/perch-source-roots.tsv` | root `tools/` | First card (W3-24) |
| `perch.css` (`--perch-*` over Quiet) and the `@import` in `globals.css` | `workspace/desktop/src/shared/styles/globals/perch.css` | Ground |
| `rulesets-dev/perch-dev.yaml` (+ `.sig.json`), `scripts/provision-perch.sh`, the dev `docker-compose.yml` with `relay`, `postgres`, `redis` | root | Ground |

Real-code anchors re-measured on 2026-09-02 against `integrate/workspace` (commit `f649bd87e`): `crates/swarm-runtime/src/escalation.rs:315-330` (twelve classes); `crates/swarm-runtime/src/alert_tuning.rs:6-15` (thresholds), `:52-75` (`AlertTuningRecommendation`, `AlertTuningReport`); `crates/swarm-runtime/src/containment.rs:461-468` (`ContainmentSweepReport`), `:491-496` (`ContainmentSweep` fields), `:537-539` (`open_leases`), `:544-557` (`release`), `:568-613` (`sweep`), `:621-647` (`run_until_shutdown`), `:235` (`verify_release_attestation`); `crates/swarm-runtime/src/runtime_events.rs:127-139`, `:142-173`, `:214-305`, `:308-338`, `:105-119` (`RuntimeEventBroadcaster`); `crates/swarm-ingest-runtime/src/ingest/mod.rs:698-770` (`runtime_event_matches_scope`), `:1755` (`current_substrate`), `:1759` (`current_pheromone_config`), `:1776` (`current_containment_store`), `:1847-1861` (`current_governance_status`), `:2025-2031` (`current_evasion_coverage`), `:2051` (`current_incident_store`); `crates/swarm-pheromone/src/substrate.rs:314-319` (`DepositQuery`), `:358-400` (the trait), `:1268-1304` (`concentration_for`), `:1306-1334` (`filter_deposits`), `:1349-1380` (suppression), `:1412-1421` (`deposit_suppression_key`), `:1705-1711` (`resolved_policy`); `crates/swarm-core/src/pheromone.rs:186-192` (`ThreatClassPolicy`), `:203-234` (`PheromoneDeposit`), `:281`, `:290`, `:297-316`; `crates/swarm-spine/src/envelope.rs:71-101` (`build_signed_envelope`), `:114-146` (`verify_envelope`); `crates/swarm-spine/src/chain.rs:11-15`, `:20-34`, `:75` (`verify_chain_link`); `crates/swarm-crypto/src/lib.rs:59-92` (`Ed25519Signer`, `from_secret_material` = `Keypair::from_seed(sha256(material))`); `crates/swarm-response/src/containment.rs:130-139`, `:271-278`; `crates/swarm-response/src/rollback.rs:41-48` (`RollbackTrigger`), `:211-223`, `:243-285`, `:296-298`; `crates/swarm-runtime-http/src/http/containment.rs:73-88`, `:129-145`, `:158-189`, `:191-247`, `:254-279`; `crates/swarm-runtime-http/src/bin/swarm_detect.rs:726`, `:1001`, `:1022-1075`, `:1113-1143`; `crates/swarm-ingest-runtime/src/ingest/platform_api.rs:811-830` (`/v2/api` router: `/findings`, `/incidents`, `/evasion/coverage`, `/assets/{host_id}/posture`, `/stream/findings`, `/runtime/status`, bearer-authed against the operator principals), `:1263` (`platform_runtime_status_handler`, carries `alert_tuning`), `:1155` (`platform_incidents_handler`, filters on `incident_id`); `crates/swarm-runtime/src/evasion_coverage.rs:103-107` (`EvasionTechniqueGap { technique, threat_class, rationale }`), `:130-138` (`DetectorEvasionCoverageReport { detector, …, intentionally_uncovered }`), `:141-147`; `crates/swarm-policy/src/governance.rs:49-54` (`PartitionState`), `:63-72`, `:182` (`status_report`); `crates/swarm-policy/src/configurable_gate.rs:34-56`, `:143-180`; `crates/swarm-core/src/config/policy.rs:8-24`, `:34-60`; `rulesets/evasion/attack-technique-catalog.yaml` (18 `technique:` keys under 11 `- detector:` entries); `deploy/helm/swarm-team-six/{Chart.yaml,values.yaml,templates/}`; `workspace/deploy/charts/ambush/Chart.yaml` (`name: ambush`, `version: 0.1.8`, optional `postgresql`/`redis` OCI subcharts); `workspace/desktop/src/features/terminal/terminalClient.ts:5-15` (`TerminalAttachRequest`), `TerminalBootstrap.tsx:151-166` (⌘J), `workspace/desktop/src-tauri/src/terminal_runtime.rs:28-40`, `:415-445` (`fence_env`, `context_vars`), `workspace/desktop/src-tauri/crates/ambush-terminal/src/context.rs:88-93`; `workspace/desktop/src/features/channels/ui/ChannelCanvas.tsx` (151 lines, `useCanvasQuery` `:28`, `useSetCanvasMutation` `:29`, `useDeferredValue` `:41`, `canEdit && !isArchived` `:137`); `workspace/desktop/src/features/search/lib/parseSearchOperators.ts:37` (`OPERATOR_RE`), `:78` (`parseSearchOperators`); `workspace/desktop/src/features/search/ui/SearchScopeControls.tsx:37` (`SearchDialogInputRow`); `workspace/desktop/src/shared/hooks/escapeSurfaces.ts:17`, `:26`; `workspace/desktop/src/app/AppShellContext.tsx:32-48` (the three read frontiers); `workspace/desktop/src/shared/features/index.ts` (`useFeatureEnabled`, `FeatureGate`, `getFeature`); `workspace/desktop/src/testing/e2eBridge.ts:14606-14613`; `workspace/desktop/src-tauri/src/managed_agents/runtime.rs:406`, `:868-874` (`process_group(0)`), `workspace/desktop/src-tauri/src/shutdown.rs:127-192`, `workspace/desktop/src-tauri/tauri.conf.json:52-62` (`externalBin`), `workspace/scripts/bundle-sidecars.sh:4`; `.github/workflows/ci.yml:121-122` (gates job), `:491-506` (the `uv` job).

---

## File Structure

### Engine (`crates/`, `rulesets/`, `tools/`, `docs/openapi/`)

| Path | Responsibility |
|---|---|
| `crates/swarm-pheromone/src/substrate.rs` (modify) | `DepositQuery.include_suppressed`; `perch_deposit_slice` — the one reduction B4 serves, tested equal to `concentration_for` |
| `crates/swarm-pheromone/src/lib.rs` (modify) | re-export `PerchDepositSlice`, `PerchSuppressionRecord`, `perch_deposit_slice` |
| `crates/swarm-ingest-runtime/src/ingest/perch_ops/deposits.rs` (create) | B4's engine half: resolve policy, read the raw class slice, reduce, serve the concentration from the same path `query_concentration` takes |
| `crates/swarm-ingest-runtime/src/ingest/perch_ops/policy.rs` (create) | the policy read: rules in file order plus the per-triple evaluation the daemon computes |
| `crates/swarm-ingest-runtime/src/ingest/mod.rs` (modify) | `current_partition_state()`, `current_policy_config()`, the `ContainmentReleased` scope arm |
| `crates/swarm-runtime/src/held_action.rs` (modify) | `partition_state_at_hold` on `HeldAction`, `partition_state_at_execution` on `HoldDecisionRecord` (B2g-p) |
| `crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs` (modify) | stamp the two partition states in `capture_hold` and `decide_hold` |
| `crates/swarm-runtime-http/src/http/perch/deposits.rs` (create) | `GET /v1/operator/pheromone/deposits` handler + DTOs |
| `crates/swarm-runtime-http/src/http/perch/policy.rs` (create) | `GET /v1/operator/policy` handler + DTOs (read-only; the console's `/policy` source) |
| `crates/swarm-runtime-http/src/http/perch/mod.rs` (modify) | two `.route(` lines, two `PERCH_ROUTER_PATHS` entries |
| `crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs` (modify) | the deposits and policy paths and schemas |
| `docs/openapi/perch-operator-v1.json` (regenerate) | the gated artifact |
| `docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml` (modify) | the policy read, `SuppressionRecord.marker_timestamp` stays seconds |
| `crates/swarm-runtime/src/runtime_events.rs` (modify) | B1c: `ContainmentReleased` variant, kind, `as_str`, `parse`, `emitted_at_ms`, `kind` |
| `crates/swarm-runtime/src/containment.rs` (modify) | `ContainmentSweep::with_runtime_events`; publish after every release in `release()` and `sweep()` |
| `crates/swarm-runtime-http/src/bin/swarm_detect.rs` (modify) | hand the broadcaster to the sweep; hand the spine signer config to the bridge |
| `crates/swarm-core/src/config/perch.rs` (modify) | `spine_seed_env` on `PerchBridgeConfig`, `lane_topic_on_crossing` |
| `crates/swarm-perch-wire/src/cards.rs` (modify) | `partition_state_at_hold`, `partition_state_at_execution` fields |
| `crates/swarm-perch-wire/src/envelope.rs` (modify) | transport-neutral `unsigned_envelope_value`, `IssuerChainHead`, `ChainLinkVerdict`, `verify_chain_link`; `signature` remains an optional wire field and no crypto type crosses this crate |
| `crates/swarm-perch-bridge/src/spine.rs` (create) | B6: per-slot spine keypairs derived from `perch.spine_seed_env`, `SpineSigner::seal` |
| `crates/swarm-perch-bridge/src/spool/chain_heads.rs` (create) | B6: per-issuer `IssuerChainHead` store, fsynced, colony-hash-guarded |
| `crates/swarm-perch-bridge/src/leases.rs` (modify) | `LeaseWatcher::poll` implemented; `lease_card_body`; `lease_id → lease_card_id` map |
| `crates/swarm-perch-bridge/src/rollback.rs` (create) | `swarm:rollback:v1` from `ContainmentReleased`, NIP-10 reply to the lease card |
| `crates/swarm-perch-bridge/src/lanes.rs` (create) | lane topic write on an `EscalationLevel` edge, never on a timer |
| `crates/swarm-perch-bridge/src/{stream.rs,cards.rs,pacer.rs,metrics.rs,lib.rs,Cargo.toml}` (modify) | classify arm, `Marker::Rollback` assembly, seal on append, `perch_bridge_lease_store_absent`, `perch_bridge_envelopes_signed_total`, `swarm-spine` + `swarm-crypto` deps |
| `tools/check-perch-chart-tokens.sh` (create, from `build/viz/`) | G2, with its `run:` step |
| `tools/check-perch-tier-allowlist.sh` (create) | the tier allowlist gate (ADR 0021 Q4), flipped after B6 |
| `tools/check-perch-surface-count.sh` (create) | P2-C5: exactly fourteen surfaces |
| `tools/check-perch-notification-fields.sh` (create) | P2-C6: the typed-field allowlist over `features/perch/notifications/copy.ts` |
| `.github/workflows/ci.yml` (modify) | the four `run:` steps |
| `docs/assets/{architecture,architecture-mobile,paths,paths-mobile,pillars,pillars-mobile,roadmap,roadmap-mobile,security-v2,security-mobile-v2,stigmergy,stigmergy-mobile}.svg` (modify) | the 41 copy-gate hits |
| `rulesets-dev/perch-dev.yaml` (modify) | `perch.spine_seed_env`, `perch.lane_topic_on_crossing: true` |

### Desktop (`workspace/desktop/`)

| Path | Responsibility |
|---|---|
| `src/shared/ui/perch/ContainmentTimer.tsx` (+ `containmentTimer.test.mjs`) | two facts, two elements (INV-06) |
| `src/shared/ui/perch/RollbackStepList.tsx` | five distinct words (INV-04), no Undo |
| `src/features/perch-containment/lib/containmentState.ts` (+ test) | `deriveContainmentState(facts)` — the five states from `remaining_ms`, `expired`, daemon reachability |
| `src/features/perch-containment/ui/ContainmentRow.tsx`, `ContainmentBoard.tsx`, `ContainmentReleaseDialog.tsx`, `PartitionSection.tsx` | S6 |
| `src/features/perch-containment/hooks.ts`, `useLeaseClock.ts` | the containment poll (2.5 s stale / 5 s poll), one board-level clock |
| `src/features/perch-evidence/ui/LeaseCard.tsx`, `RollbackCard.tsx` | the two remaining presenters, `maxTier` declared |
| `src/features/perch-evidence/ui/LaneScreen.tsx`, `LaneHeader.tsx`, `lib/laneLiveNumbers.ts` (+ test) | S5 |
| `src/features/sidebar/ui/AppSidebarPerchSection.tsx` (create) | lane rows with the live dot, case rows with the TTL glyph, the four nav items; imported by `AppSidebar.tsx` (+3 lines) |
| `src/features/perch/ui/GovernanceStrip.tsx`, `lib/governanceMode.ts` (+ test), `useGovernanceStrip.ts` | S14 |
| `src/features/perch-shift/ui/LedgerScreen.tsx`, `LedgerResultRow.tsx`, `LedgerExportDialog.tsx`, `PerchOmnibox.tsx`, `lib/ledgerQuery.ts` (+ test), `lib/omniboxCommands.ts` (+ test), `lib/exportBundle.ts` (+ test) | S9 + the ⌘K overlay + the bundle's manifest logic |
| `src-tauri/src/commands/perch_export.rs` (create) | `perch_export_bundle`: writes the directory, re-fetches receipts from the daemon, never reserializes |
| `src/features/perch-policy/ui/TuningScreen.tsx`, `TuningRecommendationCard.tsx`, `lib/tuningProvenance.ts` (+ test) | S10 |
| `src/features/perch-policy/ui/GapsScreen.tsx`, `GapCard.tsx`, `lib/gapsCatalog.ts` (+ test) | S12 |
| `src/features/perch-policy/ui/PolicyScreen.tsx`, `PolicyRuleRow.tsx`, `PolicyTripleEvaluator.tsx`, `lib/policyEvaluation.ts` (+ test) | S7 |
| `src/features/perch-policy/ui/WatchfloorScreen.tsx`, `ColonyHealthBand.tsx`, `ModeBand.tsx` | S8 |
| `src/features/perch-shift/ui/HandoffScreen.tsx`, `WatchClaimPanel.tsx`, `EndWatchSummary.tsx`, `lib/reviewSession.ts` (+ test), `lib/watchClaim.ts` (+ test) | S11 |
| `src/features/perch-evidence/ui/CaseCanvasTab.tsx`, `CaseTtlClock.tsx`, `lib/caseTemplate.ts` (+ test), `lib/caseIncident.ts` | S4 |
| `src/features/terminal/terminalCaseScope.ts` (create) + `terminalClient.ts` (+2 fields) + `TerminalBootstrap.tsx` (+banner line) | S13 pinned to a case |
| `src-tauri/src/terminal_runtime.rs` (modify, +cwd +env) | the case pin on the PTY |
| `src/shared/viz/{types.ts,scales.ts,concentration.ts,markers.tsx,TableToggle.tsx,defs.tsx,viz.css,RateSparkline.tsx}` (+ tests) | the shared chart layer; VIZ-6 |
| `src/shared/time/domains.ts` | `UnixSeconds` / `UnixMillis` brands (create if The hold did not) |
| `src/features/perch-evidence/ui/ConcentrationCurve.tsx`, `HostHeat.tsx`, `KillChainGraph.tsx` | VIZ-1, VIZ-2, VIZ-3 |
| `src/shared/api/tauriPerch.ts` (modify) | `perchGetIncident`, `perchEvasionCoverage`, `perchPolicy`, `perchExportBundle`, `perchSidecar*` added to the closed arrays |
| `src/shared/api/perchKeys.ts` (modify) | `incident`, `evasionCoverage`, `policy`, `governanceStatus`, `watchClaim` freshness rows |
| `src/features/communities/communityScopedRegistry.ts` (modify) | `caseCanvasSeeded`, `ledgerRecentQueries`, `omniboxMode`, `lanesTopicEdge` members |
| `src-tauri/src/commands/perch_reads.rs` (modify) | `perch_get_incident`, `perch_evasion_coverage`, `perch_policy` |
| `src-tauri/src/commands/perch_verify.rs` (create) | tier-2 verification using the wire crate's canonical bytes and structural chain rules plus Tauri's own Ed25519 implementation |
| `src-tauri/src/commands/perch_sidecar.rs` (create, optional) | `perch_sidecar_start/stop/status` |
| `src/testing/perch/e2ePerchBridge.ts` (modify) | cases for every new command, the incident and coverage fixtures |
| `tests/e2e/perch-containment.spec.ts`, `perch-provenance.spec.ts` (modify: #03 un-skipped), `perch-lanes.spec.ts`, `perch-governance-strip.spec.ts`, `perch-ledger.spec.ts`, `perch-omnibox.spec.ts`, `perch-tuning.spec.ts`, `perch-gaps.spec.ts`, `perch-policy.spec.ts`, `perch-handoff.spec.ts`, `perch-case-canvas.spec.ts`, `perch-terminal.spec.ts`, `perch-watchfloor.spec.ts`, `perch-charts.spec.ts` (create) | the smoke specs, each registered in `playwright.config.ts`'s `smoke` `testMatch` |
| `scripts/check-svg-font-size.mjs`, `scripts/check-route-tree.mjs` (create, from `build/viz/` and `build/skeleton/desktop/scripts/`) | G1, P2-C4, chained into `package.json` `check` |
| `src/features/perch/notifications/copy.ts` (create) | the four wake classes' bodies, typed-field interpolation only |
| `src/app/routes/{leases,lanes.$laneId,policy,watch-floor,ledger,tuning,handoff,gaps}.tsx` (create or replace) | lazy route files with `PerchSurfaceBoundary` |

### Packaging (`deploy/`, `docker-compose.yml`, `docs/`)

| Path | Responsibility |
|---|---|
| `docker-compose.yml` (modify) | hardening: pinned digests, loopback-only publishing, healthchecks, secrets from `.env.perch`, resource limits, the `perch` profile |
| `docker-compose.perch.env.example` (create) | the six secrets the dev stack needs |
| `deploy/helm/swarm-team-six/Chart.yaml` (modify) | the relay chart as an aliased, conditional dependency |
| `deploy/helm/swarm-team-six/values.yaml`, `values-production.yaml` (modify) | `relay.*`, `perch.*`, `networkPolicy.*` |
| `deploy/helm/swarm-team-six/templates/networkpolicy.yaml`, `perch-secret.yaml` (create) | brief C2's boundary; the bridge seeds and the operator token |
| `deploy/helm/swarm-team-six/templates/deployment.yaml` (modify) | the perch env from the secret; the bridge spool volume |
| `deploy/helm/swarm-team-six/tests/perch_test.yaml`, `networkpolicy_test.yaml` (create) | `helm unittest` |
| `docs/DEPLOYMENT.md` (create) | the two-process, five-service stack, its secrets and its stated costs (`09` §5 line 4) |
| `docs/plans/ambush-ui/integration/00-DECISIONS.md` §3 (modify) | the three decision rows this plan files |

---

### Task 1: Decision: the RoleGlyph and domain-icon artwork

**Files:**
- Modify: `docs/plans/ambush-ui/integration/00-DECISIONS.md` (§3 table)

**Interfaces:**
- Consumes: `build/17-COMPONENT-SPECS.md` §5.6 and §13 item 1 ("the seventeen marks — no source, no author, no roadmap line"); `build/art/DECISION.md` ("Colony" assigns hues, not glyphs).
- Produces: a row in `00-DECISIONS.md` §3 naming the options and the default; Task 19 step 9 (colony band glyphs) and Task 18 step 7 (agent rows on the kill-chain graph) are **blocked** on it and ship the text fallback until it is decided.

- [ ] **Step 1: Record the open question**

Append to the §3 table in `docs/plans/ambush-ui/integration/00-DECISIONS.md`:

```markdown
| The eight `RoleGlyph` marks and nine `icons.perch.ts` domain icons (`17` §5.6, §13 item 1) | **Not drawn.** Every role renders its slug as text (`ThreatClassLabel`-style mono word) and every domain icon falls back to the nearest lucide mark already bundled (`CircleDot`, `Radar`, `Network`, `Timer`, `FileCheck`, `Undo2`, `Shield`-free). Options: (a) commission the seventeen marks on the 24×24 `createLucideIcon` grid (`workspace/desktop/src/shared/ui/icons.ts:3-21` pattern) — ~3 design-days, no engineering; (b) ship text-only permanently and delete `RoleGlyph`'s eight-state contract; (c) derive glyphs from the Quiet index mark by role hue (rejected: colony.svg assigns hues, and hue is not a glyph) | project owner, with a designer |
```

- [ ] **Step 2: Commit**

```bash
git add docs/plans/ambush-ui/integration/00-DECISIONS.md
git commit -s -m "docs(plans): file the RoleGlyph artwork decision as open"
```

---

### Task 2: Decision: where the watch claim lives

**Files:**
- Modify: `docs/plans/ambush-ui/integration/00-DECISIONS.md` (§3 table)

**Interfaces:**
- Consumes: `04-SURFACES-AND-UX.md` §2.11 (claim = the `topic` of a standing `#watch` ops channel, 12 h TTL, takeover logged as a `kind:40099` row); `00-REGISTRY.md` R-1 (the `#watch` channel is retired as the 26006 delivery mechanism); `00-DECISIONS.md` §3 ("`#watch` operations channel — not built; the watch claim is deferred to Operator-complete — who decides: —"); `APPENDIX-NORMATIVE.md` §4 layer 4 (narrowing the `p` tag itself needs `on_shift_operator_pubkeys` + `POST /v1/operator/watch/claim`).
- Produces: a §3 row; Task 17 steps 8–11 (the claim's write path) are **blocked** on it; Task 12 step 6 (the strip's `watch held by` line) and Task 17's read/render path build against the `WatchClaim` model in `lib/watchClaim.ts` regardless.

- [ ] **Step 1: Record the options**

Append to the §3 table:

```markdown
| Where the watch claim is recorded (`04` §2.11; the `#watch` channel R-1 retired was its home) | **Not decided; the panel renders "no watch is claimed — classes 1–3 page everyone" until it is.** Options: (a) a standing ops channel provisioned by `scripts/provision-perch.sh` (config key `perch.ops_channel`), the claim as its `topic`, one relay-signed `kind:40099` `topic_changed` row per change — R-1 retired the channel only as the 26006 fence, not as a channel; cost ≈1 d, zero new kinds; (b) a NIP-33 addressable `kind:30078` event authored by the claimant with `d = "perch-watch-claim"`, last-writer-wins by `created_at`, relay-generic, no provisioning, but no relay-signed audit row and no takeover record; (c) the daemon field `on_shift_operator_pubkeys` + `POST /v1/operator/watch/claim` (appendix §4 layer 4), which also narrows the hold's `p` tag — a sixth INV-01 write and a v2 daemon item. The panel's read model is identical under (a) and (b): `{holder_pubkey, since_ms, ttl_ms}` | project owner |
```

- [ ] **Step 2: Commit**

```bash
git add docs/plans/ambush-ui/integration/00-DECISIONS.md
git commit -s -m "docs(plans): file the watch-claim home as an open decision"
```

---

### Task 3: Decision: the umbrella chart's name

**Files:**
- Modify: `docs/plans/ambush-ui/integration/00-DECISIONS.md` (§3 table)

**Interfaces:**
- Consumes: `09-ROADMAP-AND-RISKS.md` §4.1 ("Chart rename `swarm-team-six` → `ambush`", D22) and §4.2 exit criterion 6 ("The chart is named `ambush`"); `workspace/deploy/charts/ambush/Chart.yaml` (`name: ambush`, `version: 0.1.8` — the **relay** chart already carries that name under D3).
- Produces: a §3 row; Task 21 step 9 (the rename) is **blocked** on it; the rest of Task 21 composes the relay chart into `deploy/helm/swarm-team-six/` under the alias `relay`, which is correct under every option.

- [ ] **Step 1: Record the collision**

Append to the §3 table:

```markdown
| The engine chart's name after D3 (`09` §4.1 renames `swarm-team-six` → `ambush`; `workspace/deploy/charts/ambush/` is already the relay chart named `ambush`) | **Not decided; the engine chart keeps `swarm-team-six` and gains the relay chart as dependency alias `relay`.** Options: (a) rename the engine chart to `ambush` and keep the relay subchart aliased `relay` (Helm rewrites an aliased dependency's `.Chart.Name` to the alias, so templates do not collide, but two charts named `ambush` in one repository is a review hazard and a `helm upgrade` release-name break); (b) rename the engine chart to `ambush-daemon` and leave the relay chart's name alone; (c) keep `swarm-team-six` (the legacy codename an operator types — the objection `09` §4.1 records). Whatever is chosen, `09` §4.2 criterion 6 is re-worded to name it | deployment owner |
```

- [ ] **Step 2: Commit**

```bash
git add docs/plans/ambush-ui/integration/00-DECISIONS.md
git commit -s -m "docs(plans): file the umbrella chart name collision as an open decision"
```

---

### Task 4: B4 — `GET /v1/operator/pheromone/deposits`

**Files:**
- Modify: `crates/swarm-pheromone/src/substrate.rs:314-333` (`DepositQuery`), `:1306-1334` (`filter_deposits`), append after `:1421`
- Modify: `crates/swarm-pheromone/src/lib.rs` (re-exports)
- Create: `crates/swarm-ingest-runtime/src/ingest/perch_ops/deposits.rs`
- Modify: `crates/swarm-ingest-runtime/src/ingest/perch_ops/mod.rs` (`pub mod deposits;`)
- Create: `crates/swarm-runtime-http/src/http/perch/deposits.rs`
- Modify: `crates/swarm-runtime-http/src/http/perch/mod.rs` (route + path entry)
- Modify: `crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs`
- Modify: `docs/plans/ambush-ui/build/fixtures/http/GET-v1-operator-pheromone-deposits-execution-after-dismiss.json` (`marker_timestamp` to seconds)
- Regenerate: `docs/openapi/perch-operator-v1.json`
- Test: `crates/swarm-pheromone/src/substrate.rs` (`mod tests`), `crates/swarm-runtime-http/src/http/perch/deposits.rs` (`mod tests`)

**Interfaces:**
- Consumes: `PheromoneSubstrate::{query_deposits(DepositQuery), query_concentration(&ThreatClass, i64), query_threat_class_config(&ThreatClass)}`; `PheromoneConfig::resolve_threat_class_policy(Option<&ThreatClassConfig>) -> ThreatClassPolicy`; `PheromoneDeposit::{strength_at(i64), is_evaporated(i64, f64)}`; `IngestState::{current_substrate(), current_pheromone_config()}`; `PerchHttpState`, `require_operator_api_scope(&principal, OperatorScope::Read, "read")`, `OperatorApiError::{bad_request, internal}`, `CURRENT_OPERATOR_API_SCHEMA_VERSION`.
- Produces: `swarm_pheromone::perch_deposit_slice(deposits: &[PheromoneDeposit], threat_class: &ThreatClass, now: i64, policy: &ThreatClassPolicy) -> PerchDepositSlice`; `swarm_pheromone::{PerchDepositSlice { kept: Vec<PheromoneDeposit>, suppressed: Vec<PerchSuppressionRecord>, source_ids: Vec<String> }, PerchSuppressionRecord { event_id, threat_class, marker_timestamp: i64 /* seconds */, removed_deposit_count: usize, analyst_id: Option<String> }}`; `swarm_ingest_runtime::ingest::perch_ops::deposits::{read_deposits(state: &IngestState, query: PerchDepositsQuery) -> Result<PerchDepositsRead, PerchDepositsError>, PerchDepositsQuery { threat_class: ThreatClass, since_seconds: Option<i64>, host_id: Option<String>, limit: usize, now_seconds: Option<i64> }, PerchDepositsRead { now_seconds, policy, concentration, deposits: Vec<PheromoneDeposit>, suppressed, source_ids, distinct_agents: usize, unscoped_source_ids: Vec<String>, truncated: bool }}`; the route `GET /v1/operator/pheromone/deposits` (scope `Read`) answering `DepositsResponse` exactly as `docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml:2123-2200` declares it; `perch_deposits(threatClass)` (already a wrapper) now returns `DepositsResponse`.

- [ ] **Step 1: Write the failing reduction test in `swarm-pheromone`**

Append inside `#[cfg(test)] mod tests` in `crates/swarm-pheromone/src/substrate.rs`:

```rust
    fn perch_test_deposit(
        event_id: &str,
        agent: &str,
        confidence: f64,
        timestamp: i64,
        indicator_extra: serde_json::Value,
    ) -> PheromoneDeposit {
        let mut indicator = serde_json::json!({ "event_id": event_id, "host_id": "host-ops-1" });
        if let (Some(base), Some(extra)) = (indicator.as_object_mut(), indicator_extra.as_object()) {
            for (k, v) in extra {
                base.insert(k.clone(), v.clone());
            }
        }
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator,
            threat_class: ThreatClass::Execution,
            severity: Severity::Critical,
            confidence,
            timestamp,
            decay_half_life: 3600.0,
            agent_id: AgentId(agent.to_string()),
            agent_identity: String::new(),
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
    }

    #[test]
    fn perch_deposit_slice_agrees_with_concentration_for() {
        let now = 1_773_739_125;
        let policy = ThreatClassPolicy {
            half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
        };
        let key = "swarm:ed25519:18085f16811dba240c5bf9ef0c0d0bc6f359e7812cdedf86e7519852307ce470";
        let deposits = vec![
            perch_test_deposit("hunt-evt-1", &format!("{key}:suspicious_process_tree"), 0.9, 1_773_738_872, serde_json::json!({})),
            perch_test_deposit("hunt-evt-1", &format!("{key}:suspicious_scripting"), 0.9, 1_773_738_872, serde_json::json!({})),
            perch_test_deposit("hunt-evt-2", &format!("{key}:suspicious_process_tree"), 0.9, 1_773_738_881, serde_json::json!({})),
            // the Dismiss marker: schema + action, keyed on (execution, hunt-evt-1)
            perch_test_deposit(
                "hunt-evt-1",
                key,
                0.0,
                1_773_739_124,
                serde_json::json!({
                    "schema": swarm_core::types::SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                    "action": "dismiss",
                    "analyst_id": "perch-operator-1"
                }),
            ),
        ];

        let served = concentration_for(&deposits, &ThreatClass::Execution, now, &policy);
        let slice = perch_deposit_slice(&deposits, &ThreatClass::Execution, now, &policy);

        let summed: f64 = slice.kept.iter().map(|d| d.strength_at(now)).sum();
        assert!((summed - served.total_strength).abs() < 1e-9, "{summed} != {}", served.total_strength);
        assert_eq!(slice.source_ids.len(), served.distinct_sources);
        assert_eq!(slice.kept.len(), 1, "two deposits left under the dismiss marker");
        assert_eq!(slice.suppressed.len(), 1);
        assert_eq!(slice.suppressed[0].event_id, "hunt-evt-1");
        assert_eq!(slice.suppressed[0].removed_deposit_count, 2);
        assert_eq!(slice.suppressed[0].marker_timestamp, 1_773_739_124);
        assert_eq!(slice.suppressed[0].analyst_id.as_deref(), Some("perch-operator-1"));
    }

    #[test]
    fn include_suppressed_returns_the_dismissed_rows_too() {
        let key = "swarm:ed25519:18085f16811dba240c5bf9ef0c0d0bc6f359e7812cdedf86e7519852307ce470";
        let deposits = vec![
            perch_test_deposit("hunt-evt-1", &format!("{key}:suspicious_process_tree"), 0.9, 1_773_738_872, serde_json::json!({})),
            perch_test_deposit(
                "hunt-evt-1",
                key,
                0.0,
                1_773_739_124,
                serde_json::json!({ "schema": swarm_core::types::SWARM_PROVIDENCE_FEEDBACK_SCHEMA, "action": "dismiss" }),
            ),
        ];
        let default_query = DepositQuery { threat_class: Some(ThreatClass::Execution), ..DepositQuery::default() };
        assert_eq!(filter_deposits(&deposits, default_query).len(), 1, "marker only");
        let raw = DepositQuery { threat_class: Some(ThreatClass::Execution), include_suppressed: true, ..DepositQuery::default() };
        assert_eq!(filter_deposits(&deposits, raw).len(), 2);
    }
```

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test -p swarm-pheromone perch_deposit_slice_agrees_with_concentration_for`
Expected: FAIL to compile — `perch_deposit_slice` not found, no field `include_suppressed`.

- [ ] **Step 3: Implement the slice and the query flag**

In `crates/swarm-pheromone/src/substrate.rs`, change `DepositQuery`:

```rust
/// Query filters for reading persisted deposits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DepositQuery {
    pub threat_class: Option<ThreatClass>,
    pub since_timestamp: Option<i64>,
    pub host_id: Option<String>,
    pub limit: usize,
    /// Keep deposits a later `dismiss` marker suppressed. Default false, so every
    /// existing caller keeps reading the post-suppression slice. B4 sets it so the
    /// console can render render law 5's suppression row as a row, not a hole.
    #[serde(default)]
    pub include_suppressed: bool,
}
```

In `filter_deposits`, replace the last predicate `&& !is_suppressed_by_feedback(deposit, &suppression)` with `&& (query.include_suppressed || !is_suppressed_by_feedback(deposit, &suppression))`.

Append after `deposit_suppression_key` (`:1421`):

```rust
/// What one `dismiss` marker removed from the sum. Render law 5: this is a
/// timeline row, never a hole in the curve.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerchSuppressionRecord {
    pub event_id: String,
    pub threat_class: ThreatClass,
    /// The marker deposit's own `timestamp`, unix SECONDS — the pheromone clock.
    pub marker_timestamp: i64,
    pub removed_deposit_count: usize,
    pub analyst_id: Option<String>,
}

/// The slice B4 serves: the deposits `concentration_for` summed, in the order it
/// saw them, plus what it skipped and the source-id set it counted.
#[derive(Debug, Clone, PartialEq)]
pub struct PerchDepositSlice {
    /// Post-evaporation, post-suppression, non-zero strength — exactly the set
    /// `concentration_for` summed (`:1281-1296`).
    pub kept: Vec<PheromoneDeposit>,
    /// One record per `(threat_class, event_id)` dismiss key that removed at
    /// least one deposit, oldest marker first.
    pub suppressed: Vec<PerchSuppressionRecord>,
    /// The distinct `agent_id`s of `kept`, sorted lexicographically.
    pub source_ids: Vec<String>,
}

/// Reduce a class's deposits the way `concentration_for` does, keeping the pieces.
///
/// A pass-through of `filter_deposits` is wrong for a chart: it applies no
/// evaporation and takes no `now`, so a curve drawn from it disagrees with the
/// number `swarmctl` and the escalation monitor act on. This function walks the
/// same three `continue`s in the same order, and the test
/// `perch_deposit_slice_agrees_with_concentration_for` holds the two together.
pub fn perch_deposit_slice(
    deposits: &[PheromoneDeposit],
    threat_class: &ThreatClass,
    now: i64,
    policy: &ThreatClassPolicy,
) -> PerchDepositSlice {
    let suppression = latest_feedback_suppression_states(deposits);
    let mut analysts: BTreeMap<FeedbackSuppressionKey, (i64, Option<String>)> = BTreeMap::new();
    for deposit in deposits {
        if let Some((key, FeedbackSuppressionState::Dismiss)) = feedback_suppression_marker(deposit) {
            let analyst = deposit
                .indicator
                .get("analyst_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let replace = analysts
                .get(&key)
                .is_none_or(|(timestamp, _)| *timestamp <= deposit.timestamp);
            if replace {
                analysts.insert(key, (deposit.timestamp, analyst));
            }
        }
    }

    let mut kept = Vec::new();
    let mut sources = BTreeSet::new();
    let mut removed: BTreeMap<FeedbackSuppressionKey, usize> = BTreeMap::new();
    for deposit in deposits
        .iter()
        .filter(|deposit| &deposit.threat_class == threat_class)
    {
        if deposit.is_evaporated(now, policy.evaporation_threshold) {
            continue;
        }
        if is_suppressed_by_feedback(deposit, &suppression) {
            if let Some(key) = deposit_suppression_key(deposit) {
                *removed.entry(key).or_insert(0) += 1;
            }
            continue;
        }
        if deposit.strength_at(now) <= 0.0 {
            continue;
        }
        sources.insert(deposit.agent_id.0.clone());
        kept.push(deposit.clone());
    }

    let mut suppressed: Vec<PerchSuppressionRecord> = removed
        .into_iter()
        .map(|(key, removed_deposit_count)| {
            let (marker_timestamp, analyst_id) = analysts
                .get(&key)
                .cloned()
                .unwrap_or((0, None));
            PerchSuppressionRecord {
                event_id: key.event_id,
                threat_class: key.threat_class,
                marker_timestamp,
                removed_deposit_count,
                analyst_id,
            }
        })
        .collect();
    suppressed.sort_by(|a, b| a.marker_timestamp.cmp(&b.marker_timestamp).then_with(|| a.event_id.cmp(&b.event_id)));

    PerchDepositSlice {
        kept,
        suppressed,
        source_ids: sources.into_iter().collect(),
    }
}
```

`FeedbackSuppressionKey` derives `Clone`? It derives `Debug, Clone, PartialEq, Eq, PartialOrd, Ord` at `:344`; its fields `threat_class`, `event_id` are private to the module, which is fine because this function lives in the same module. Add `use std::collections::BTreeSet;` at the top if absent. In `crates/swarm-pheromone/src/lib.rs` add `pub use substrate::{PerchDepositSlice, PerchSuppressionRecord, perch_deposit_slice};` beside the existing `DepositQuery` re-export.

- [ ] **Step 4: Run the two tests**

Run: `cargo test -p swarm-pheromone perch_deposit_slice include_suppressed`
Expected: 2 passed. Also `cargo test -p swarm-pheromone` — every existing `query_deposits_*` test still passes, because `include_suppressed` defaults to false.

- [ ] **Step 5: Commit the reduction**

```bash
git add crates/swarm-pheromone/src/substrate.rs crates/swarm-pheromone/src/lib.rs
git commit -s -m "feat(pheromone): perch_deposit_slice, the B4 reduction held equal to concentration_for"
```

- [ ] **Step 6: Write the failing engine-op test**

Create `crates/swarm-ingest-runtime/src/ingest/perch_ops/deposits.rs` with only the test module first:

```rust
//! B4's engine half. See `12-BACKEND-BILL-API.md` §11.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::pheromone::ThreatClass;

    #[tokio::test]
    async fn read_deposits_serves_the_concentration_the_monitor_acts_on() {
        let state = crate::ingest::test_support::ingest_state_with_in_memory_substrate().await;
        let now = 1_773_739_125;
        crate::ingest::test_support::seed_execution_scenario(&state, now).await;

        let read = read_deposits(
            &state,
            PerchDepositsQuery {
                threat_class: ThreatClass::Execution,
                since_seconds: None,
                host_id: None,
                limit: 500,
                now_seconds: Some(now),
            },
        )
        .await
        .unwrap();

        let served = state
            .current_substrate()
            .query_concentration(&ThreatClass::Execution, now)
            .await
            .unwrap();
        assert_eq!(read.concentration.total_strength, served.total_strength);
        assert_eq!(read.source_ids.len(), served.distinct_sources);
        assert_eq!(read.distinct_agents, 1, "one agent, two strategies");
        assert!(read.unscoped_source_ids.is_empty());
        assert!(!read.truncated);
        assert_eq!(read.now_seconds, now);
    }

    #[tokio::test]
    async fn a_limit_of_zero_is_refused_and_a_cut_slice_says_so() {
        let state = crate::ingest::test_support::ingest_state_with_in_memory_substrate().await;
        crate::ingest::test_support::seed_execution_scenario(&state, 1_773_739_125).await;
        let zero = read_deposits(&state, PerchDepositsQuery { threat_class: ThreatClass::Execution, since_seconds: None, host_id: None, limit: 0, now_seconds: None }).await;
        assert!(matches!(zero, Err(PerchDepositsError::InvalidLimit(0))));
        let one = read_deposits(&state, PerchDepositsQuery { threat_class: ThreatClass::Execution, since_seconds: None, host_id: None, limit: 1, now_seconds: Some(1_773_739_125) }).await.unwrap();
        assert_eq!(one.deposits.len(), 1);
        assert!(one.truncated);
        // source_ids is computed over the UNTRUNCATED class slice, so it still equals distinct_sources.
        assert_eq!(one.source_ids.len(), one.concentration.distinct_sources);
    }
}
```

`crate::ingest::test_support::{ingest_state_with_in_memory_substrate, seed_execution_scenario}` are the First card plan's test helpers (they build an `IngestState` over `InMemoryPheromoneSubstrate` and deposit the canonical three-deposit `execution` scenario from `fixtures/perch-demo-fixture.json`). If they landed under a different name, use that name; if they did not land, add them in `crates/swarm-ingest-runtime/src/ingest/test_support.rs` as `pub(crate) async fn` wrappers over `IngestState::for_tests()` and three `substrate.deposit(...)` calls with the fixture's `event_id`/`agent_id`/`timestamp`/`confidence` values (`hunt-evt-1` × 2 at `1773738872`, `hunt-evt-2` at `1773738881`, confidence `0.9`, half-life `3600`).

- [ ] **Step 7: Run to see it fail**

Run: `cargo test -p swarm-ingest-runtime perch_ops::deposits`
Expected: FAIL to compile — `read_deposits`, `PerchDepositsQuery`, `PerchDepositsError` missing.

- [ ] **Step 8: Implement the engine op**

Prepend to `crates/swarm-ingest-runtime/src/ingest/perch_ops/deposits.rs`, above the test module:

```rust
use swarm_core::pheromone::{PheromoneConcentration, PheromoneDeposit, ThreatClass, ThreatClassPolicy};
use swarm_pheromone::{DepositQuery, PerchSuppressionRecord, PheromoneSubstrate, SubstrateError, perch_deposit_slice};

use crate::ingest::IngestState;

/// The largest slice the route will serve. An unbounded slice on a wall screen
/// is a denial of service against the renderer (`12` §11.1).
pub const PERCH_DEPOSITS_MAX_LIMIT: usize = 1_000;

/// The query, already validated by the HTTP layer except for `limit`, which is
/// checked here so the engine op refuses `0` even when called from a test.
#[derive(Debug, Clone)]
pub struct PerchDepositsQuery {
    pub threat_class: ThreatClass,
    pub since_seconds: Option<i64>,
    pub host_id: Option<String>,
    pub limit: usize,
    pub now_seconds: Option<i64>,
}

/// What the route serializes. Field names match the OpenAPI document one for one.
#[derive(Debug, Clone)]
pub struct PerchDepositsRead {
    pub now_seconds: i64,
    pub threat_class: ThreatClass,
    pub policy: ThreatClassPolicy,
    pub concentration: PheromoneConcentration,
    pub deposits: Vec<PheromoneDeposit>,
    pub suppressed: Vec<PerchSuppressionRecord>,
    pub source_ids: Vec<String>,
    pub distinct_agents: usize,
    pub unscoped_source_ids: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PerchDepositsError {
    #[error("limit must be between 1 and {PERCH_DEPOSITS_MAX_LIMIT}; got {0}")]
    InvalidLimit(usize),
    #[error("substrate: {0}")]
    Substrate(#[from] SubstrateError),
}

/// The M in "N sources / M agents", computed here so two clients cannot derive
/// it two ways. Split each id once from the right on `:`; an id with no colon did
/// not come through `resolve_deposits` and is its own agent (`12` §11.2).
pub fn distinct_agents(source_ids: &[String]) -> (usize, Vec<String>) {
    let mut agents = std::collections::BTreeSet::new();
    let mut unscoped = Vec::new();
    for id in source_ids {
        match id.rfind(':') {
            Some(cut) => {
                agents.insert(&id[..cut]);
            }
            None => {
                agents.insert(id.as_str());
                unscoped.push(id.clone());
            }
        }
    }
    (agents.len(), unscoped)
}

/// Read the class slice the way the monitor reads it, and serve the served number beside it.
pub async fn read_deposits(
    state: &IngestState,
    query: PerchDepositsQuery,
) -> Result<PerchDepositsRead, PerchDepositsError> {
    if query.limit == 0 || query.limit > PERCH_DEPOSITS_MAX_LIMIT {
        return Err(PerchDepositsError::InvalidLimit(query.limit));
    }
    let now_seconds = query
        .now_seconds
        .unwrap_or_else(|| swarm_runtime::runtime_events::now_ms().div_euclid(1_000));
    let substrate = state.current_substrate();
    let pheromone = state.current_pheromone_config();
    let override_config = substrate.query_threat_class_config(&query.threat_class).await?;
    let policy = pheromone.resolve_threat_class_policy(override_config.as_ref());

    // The whole class, suppressed rows included, so the slice can name what left.
    let raw = substrate
        .query_deposits(DepositQuery {
            threat_class: Some(query.threat_class.clone()),
            since_timestamp: None,
            host_id: None,
            limit: 0,
            include_suppressed: true,
        })
        .await?;
    let slice = perch_deposit_slice(&raw, &query.threat_class, now_seconds, &policy);
    let concentration = substrate
        .query_concentration(&query.threat_class, now_seconds)
        .await?;
    let (distinct_agents, unscoped_source_ids) = distinct_agents(&slice.source_ids);

    // The `deposits` array honours the caller's filters; the counts above do not.
    let mut deposits: Vec<PheromoneDeposit> = slice
        .kept
        .into_iter()
        .filter(|deposit| query.since_seconds.is_none_or(|since| deposit.timestamp >= since))
        .filter(|deposit| {
            query.host_id.as_deref().is_none_or(|host| {
                deposit
                    .indicator
                    .get("host_id")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| deposit.indicator.pointer("/evidence/host_metadata/host_id").and_then(serde_json::Value::as_str))
                    == Some(host)
            })
        })
        .collect();
    deposits.sort_by(|a, b| {
        b.timestamp.cmp(&a.timestamp).then_with(|| {
            let ea = a.indicator.get("event_id").and_then(serde_json::Value::as_str).unwrap_or("");
            let eb = b.indicator.get("event_id").and_then(serde_json::Value::as_str).unwrap_or("");
            ea.cmp(eb)
        })
    });
    let truncated = deposits.len() > query.limit;
    deposits.truncate(query.limit);

    Ok(PerchDepositsRead {
        now_seconds,
        threat_class: query.threat_class,
        policy,
        concentration,
        deposits,
        suppressed: slice.suppressed,
        source_ids: slice.source_ids,
        distinct_agents,
        unscoped_source_ids,
        truncated,
    })
}
```

Add `pub mod deposits;` to `crates/swarm-ingest-runtime/src/ingest/perch_ops/mod.rs`. `swarm-ingest-runtime` already depends on `swarm-pheromone` and `thiserror`.

- [ ] **Step 9: Run the engine-op tests**

Run: `cargo test -p swarm-ingest-runtime perch_ops::deposits`
Expected: 2 passed.

- [ ] **Step 10: Commit**

```bash
git add crates/swarm-ingest-runtime/src/ingest/perch_ops/
git commit -s -m "feat(ingest): read_deposits — the post-suppression, post-evaporation slice beside the served number"
```

- [ ] **Step 11: Write the failing handler test**

Create `crates/swarm-runtime-http/src/http/perch/deposits.rs` with its test module, following the shape of `http/tests.rs`'s `a_release_whose_inverse_failed_keeps_the_lease_open_and_is_not_attested` (`:3622`) — a router built by `perch_operator_router`, a bearer from `SWARM_OPERATOR_TOKEN`, `tower::ServiceExt::oneshot`:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn deposits_route_answers_the_openapi_shape() {
        let (router, token) = super::super::tests::perch_router_for_tests().await;
        let response = router
            .oneshot(
                Request::get("/v1/operator/pheromone/deposits?threat_class=execution&now_seconds=1773739125")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for key in ["schema_version", "now_seconds", "threat_class", "policy", "concentration", "deposits", "suppressed", "source_ids", "distinct_agents", "unscoped_source_ids", "truncated"] {
            assert!(body.get(key).is_some(), "missing {key}");
        }
        assert_eq!(body["now_seconds"], 1_773_739_125);
        assert!(body["deposits"][0].get("strength_at_now").is_some());
        assert!(body["deposits"][0].get("signature").is_none(), "byte arrays are dropped");
    }

    #[tokio::test]
    async fn deposits_route_rejects_limit_zero_and_a_missing_class() {
        let (router, token) = super::super::tests::perch_router_for_tests().await;
        for query in ["threat_class=execution&limit=0", "limit=10"] {
            let response = router
                .clone()
                .oneshot(
                    Request::get(format!("/v1/operator/pheromone/deposits?{query}"))
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        }
    }
}
```

`perch_router_for_tests()` is The hold plan's test constructor for `perch_operator_router` (it seeds the canonical scenario and sets the token env). If it landed under another name in `http/perch/mod.rs`'s `tests`, use that.

- [ ] **Step 12: Run to see it fail**

Run: `cargo test -p swarm-runtime-http perch::deposits`
Expected: FAIL to compile (no handler module).

- [ ] **Step 13: Implement the handler and DTOs**

Prepend to `crates/swarm-runtime-http/src/http/perch/deposits.rs`:

```rust
//! `GET /v1/operator/pheromone/deposits` — B4.
//!
//! NOT a pass-through of `query_deposits`. See `12-BACKEND-BILL-API.md` §11.1
//! for the divergence this route exists to close.

use axum::extract::{Extension, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use swarm_core::config::OperatorScope;
use swarm_core::pheromone::{PheromoneConcentration, PheromoneDeposit, ThreatClass, ThreatClassPolicy};
use swarm_core::types::{AgentRole, Severity};
use swarm_ingest_runtime::control::CURRENT_OPERATOR_API_SCHEMA_VERSION;
use swarm_ingest_runtime::ingest::perch_ops::deposits::{
    PERCH_DEPOSITS_MAX_LIMIT, PerchDepositsError, PerchDepositsQuery, read_deposits,
};
use swarm_pheromone::PerchSuppressionRecord;

use super::PerchHttpState;
use crate::http::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use crate::http::error::OperatorApiError;

/// Query of `GET /v1/operator/pheromone/deposits`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepositsQuery {
    /// Required. One of the twelve standard slugs.
    pub threat_class: Option<ThreatClass>,
    pub since_seconds: Option<i64>,
    pub host_id: Option<String>,
    /// 1..=1000, default 500. `0` is refused: `DepositQuery.limit == 0` means unlimited.
    pub limit: Option<usize>,
    /// Unix SECONDS. Absent means now.
    pub now_seconds: Option<i64>,
}

/// `PheromoneDeposit` minus its byte arrays, plus `strength_at_now`.
#[derive(Debug, Clone, Serialize)]
pub struct PheromoneDepositView {
    pub event_id: String,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub timestamp: i64,
    pub decay_half_life: f64,
    pub agent_id: String,
    pub agent_role: Option<AgentRole>,
    pub agent_identity: String,
    pub host_id: Option<String>,
    pub strategy_id: Option<String>,
    pub strength_at_now: f64,
}

impl PheromoneDepositView {
    fn from_deposit(deposit: &PheromoneDeposit, now_seconds: i64) -> Self {
        let host_id = deposit
            .indicator
            .get("host_id")
            .and_then(serde_json::Value::as_str)
            .or_else(|| deposit.indicator.pointer("/evidence/host_metadata/host_id").and_then(serde_json::Value::as_str))
            .map(str::to_string);
        // The strategy is the segment after the last colon of a scoped id.
        let strategy_id = deposit.agent_id.0.rfind(':').map(|cut| deposit.agent_id.0[cut + 1..].to_string());
        Self {
            event_id: deposit.indicator.get("event_id").and_then(serde_json::Value::as_str).unwrap_or_default().to_string(),
            threat_class: deposit.threat_class.clone(),
            severity: deposit.severity,
            confidence: deposit.confidence,
            timestamp: deposit.timestamp,
            decay_half_life: deposit.decay_half_life,
            agent_id: deposit.agent_id.0.clone(),
            agent_role: deposit.agent_role,
            agent_identity: deposit.agent_identity.clone(),
            host_id,
            strategy_id,
            strength_at_now: deposit.strength_at(now_seconds),
        }
    }
}

/// Response of `GET /v1/operator/pheromone/deposits`.
#[derive(Debug, Clone, Serialize)]
pub struct DepositsResponse {
    pub schema_version: u32,
    pub now_seconds: i64,
    pub threat_class: ThreatClass,
    pub policy: ThreatClassPolicy,
    pub concentration: PheromoneConcentration,
    pub deposits: Vec<PheromoneDepositView>,
    pub suppressed: Vec<PerchSuppressionRecord>,
    pub source_ids: Vec<String>,
    pub distinct_agents: usize,
    pub unscoped_source_ids: Vec<String>,
    pub truncated: bool,
}

pub(super) async fn deposit_list_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    Query(query): Query<DepositsQuery>,
) -> Result<Json<DepositsResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
    let threat_class = query
        .threat_class
        .ok_or_else(|| OperatorApiError::bad_request("threat_class is required; concentration is per class"))?;
    let limit = query.limit.unwrap_or(500);
    if limit == 0 || limit > PERCH_DEPOSITS_MAX_LIMIT {
        return Err(OperatorApiError::bad_request(format!(
            "limit must be between 1 and {PERCH_DEPOSITS_MAX_LIMIT}; 0 is not unlimited on this route"
        )));
    }
    let read = read_deposits(
        &state.ingest,
        PerchDepositsQuery { threat_class, since_seconds: query.since_seconds, host_id: query.host_id, limit, now_seconds: query.now_seconds },
    )
    .await
    .map_err(|error| match error {
        PerchDepositsError::InvalidLimit(_) => OperatorApiError::bad_request(error.to_string()),
        PerchDepositsError::Substrate(inner) => OperatorApiError::internal(inner.to_string()),
    })?;
    let now_seconds = read.now_seconds;
    Ok(Json(DepositsResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        now_seconds,
        threat_class: read.threat_class,
        policy: read.policy,
        concentration: read.concentration,
        deposits: read.deposits.iter().map(|d| PheromoneDepositView::from_deposit(d, now_seconds)).collect(),
        suppressed: read.suppressed,
        source_ids: read.source_ids,
        distinct_agents: read.distinct_agents,
        unscoped_source_ids: read.unscoped_source_ids,
        truncated: read.truncated,
    }))
}
```

In `crates/swarm-runtime-http/src/http/perch/mod.rs` add `pub mod deposits;`, the route
`.route("/v1/operator/pheromone/deposits", get(deposits::deposit_list_handler))` and the string
`"/v1/operator/pheromone/deposits"` in `PERCH_ROUTER_PATHS`. The hold exits with six mounted
paths; this task makes seven (W3-28). `perch_router_paths_are_disjoint_from_the_local_operator_surface`
must count seven — the `threat-class-configs` path on 7766 is a sibling in spelling only.

- [ ] **Step 14: Run the handler tests and the disjointness test**

Run: `cargo test -p swarm-runtime-http perch::`
Expected: the two new tests pass; `perch_router_paths_are_disjoint_from_the_local_operator_surface` passes.

- [ ] **Step 15: Regenerate the OpenAPI JSON and fix the fixture's unit**

Edit `crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs` so its `json!` tree emits the `/v1/operator/pheromone/deposits` path and the `ThreatClassPolicy`, `PheromoneConcentration`, `PheromoneDepositView`, `SuppressionRecord`, `DepositsResponse` schemas exactly as `docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml:573-618` and `:2003-2200` declare them (the committed JSON already contains them; the generator must reproduce those bytes). In the YAML, `SuppressionRecord.marker_timestamp` is declared `Unix SECONDS`; the fixture `docs/plans/ambush-ui/build/fixtures/http/GET-v1-operator-pheromone-deposits-execution-after-dismiss.json` carries `1773739124200` (milliseconds) — change it to `1773739124` and re-run `node docs/plans/ambush-ui/build/fixtures/validate.mjs` (the HTTP snapshots are not hash-pinned; `SHA256SUMS` covers `wire/` only — if `shasum -a 256 -c SHA256SUMS` lists the file, regenerate the sum with `node docs/plans/ambush-ui/build/fixtures/build.mjs`).

Run: `bash tools/generate-perch-openapi.sh && bash tools/check-perch-openapi.sh`
Expected: `valid (openapi-spec-validator 0.9.0)` · `current` · exit 0.

- [ ] **Step 16: Wire the desktop wrapper's return type and the mock**

In `workspace/desktop/src/shared/api/tauriPerch.ts` replace `invokeTauri<unknown>("perch_deposits", …)` with a typed `PerchDepositsResponse` mirroring `DepositsResponse` (fields as above, `threat_class: string`), and in `workspace/desktop/src/testing/perch/e2ePerchBridge.ts` make the `perch_deposits` case answer `fixtures/http/GET-v1-operator-pheromone-deposits-execution.json` (vendored beside `perchDemoFixture.json`) for `execution` and the after-dismiss body once `__AMBUSH_E2E_PERCH_CONTROL__.dismiss("hunt-evt-1")` has been called.

Run: `cd workspace/desktop && pnpm typecheck && node --import ./test-loader.mjs --experimental-strip-types --test src/testing/perch/e2ePerchBridge.test.mjs`
Expected: typecheck clean; the bridge test's "answers every member of PERCH_TAURI_COMMANDS" case passes.

- [ ] **Step 17: Commit**

```bash
git add crates/swarm-runtime-http/src/http/perch/ crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs docs/openapi/perch-operator-v1.json docs/plans/ambush-ui/build/fixtures/http/ workspace/desktop/src/shared/api/tauriPerch.ts workspace/desktop/src/testing/perch/e2ePerchBridge.ts
git commit -s -m "feat(http): GET /v1/operator/pheromone/deposits (B4) with the served concentration beside the slice"
```

---

#### Task 4 status — 2026-09-04

Steps 1-14 landed: the reduction and its two tests in `swarm-pheromone`, the engine op and its
two tests in `swarm-ingest-runtime`, and the mounted route with the path inventory grown to
seven. Root `cargo clippy --workspace --all-targets -- -D warnings` is clean and
`cargo test --workspace` is 1,547 passing.

**Steps 15 and 16 are blocked on two First card artifacts that never landed**, and are not
claimed:

- Step 15 regenerates `docs/openapi/perch-operator-v1.json` with
  `crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs`. Neither exists. The only
  OpenAPI generator in the tree is `generate_platform_openapi.rs`, for the v2 platform API, and
  the only document under `docs/openapi/` is `v2-platform-openapi.json`. The perch contract
  lives at `build/openapi/perch-operator-v1.yaml` and is hand-maintained, so **nothing today
  checks the served shape against it**. Writing the generator is a task in its own right and
  should be one.
- Step 16 wires "the desktop wrapper's return type", describing `perchDeposits(threatClass)` as
  "already a wrapper". There is no `perchDeposits` in `shared/api/tauriPerch.ts`, and no
  `perch_deposits` Tauri command. Adding one means a new command, a new entry in
  `PERCH_TAURI_COMMANDS`, and a new arm in the E2E mock's closed set — all three of which the
  cross-language guards added in The hold now enforce together. It belongs with the surface
  that consumes it (Task 14, the tuning bench) rather than ahead of it.

## Task 5: B1c — `RuntimeEvent::ContainmentReleased`

**Files:**
- Modify: `crates/swarm-runtime/src/runtime_events.rs:127-139`, `:142-173`, `:214-305`, `:308-338`
- Modify: `crates/swarm-runtime/src/containment.rs:491-496`, `:510-521`, `:544-557`, `:568-613`
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs:766-768`
- Modify: `crates/swarm-runtime-http/src/bin/swarm_detect.rs:1001`, `:1029-1038`
- Modify: `crates/swarm-perch-bridge/src/stream.rs` (`classify`)
- Test: `crates/swarm-runtime/src/runtime_events.rs` (`mod tests`), `crates/swarm-runtime/src/containment.rs` (`mod tests`)

**Interfaces:**
- Consumes: `RuntimeEventBroadcaster::{publish(RuntimeEvent), subscribe()}` (`runtime_events.rs:105-119`); `release_lease(...)` and `verify_release_attestation(&RollbackReceipt) -> Result<_, ReleaseAttestationError>` (`containment.rs:235`); `GovernanceAuthority::status_report() -> GovernanceStatusReport` (`governance.rs:182`); `RollbackTrigger` (`rollback.rs:41-48`, `Copy + Serialize`), `PartitionState` (`governance.rs:47-54`).
- Produces: the thirteenth variant
  ```rust
  RuntimeEvent::ContainmentReleased {
      emitted_at_ms: i64,
      lease_id: String,
      trigger: RollbackTrigger,               // manual | expiry
      receipt: RollbackReceipt,
      lease_closed: bool,                     // re-listed after release, never assumed
      attestation_verified: bool,
      attestation_error: Option<String>,
      partition_state_at_execution: Option<PartitionState>,   // B2g-p's execution stamp for the rollback card
  }
  ```
  with `RuntimeEventKind::ContainmentReleased` (`"containment_released"`); `ContainmentSweep::with_runtime_events(self, events: RuntimeEventBroadcaster) -> Self`; the bridge classifies it `Stream::Evidence` (Task 9 consumes it).

- [ ] **Step 1: Write the failing kind round-trip test**

Append inside `#[cfg(test)] mod tests` in `crates/swarm-runtime/src/runtime_events.rs` (create the module if the file has none):

```rust
    #[test]
    fn containment_released_kind_round_trips_through_the_filter_grammar() {
        assert_eq!(RuntimeEventKind::ContainmentReleased.as_str(), "containment_released");
        assert_eq!(RuntimeEventKind::parse("containment_released"), Some(RuntimeEventKind::ContainmentReleased));
        let receipt = swarm_response::rollback::RollbackReceipt {
            rollback_id: "rb_test".into(),
            lease_id: "cl_test".into(),
            origin_receipt_id: "resp_test".into(),
            governance_receipt_id: None,
            trigger: swarm_response::rollback::RollbackTrigger::Expiry,
            mode: swarm_response::ExecutionMode::Enforced,
            status: swarm_response::ResponseStatus::Executed,
            steps: Vec::new(),
            completed_at_ms: 7,
            summary: "0 of 0 steps reversed".into(),
            governance_attestation: None,
        };
        let event = RuntimeEvent::ContainmentReleased {
            emitted_at_ms: 7,
            lease_id: "cl_test".into(),
            trigger: swarm_response::rollback::RollbackTrigger::Expiry,
            receipt,
            lease_closed: true,
            attestation_verified: false,
            attestation_error: Some("unattested".into()),
            partition_state_at_execution: Some(swarm_policy::governance::PartitionState::Healthy),
        };
        assert_eq!(event.emitted_at_ms(), 7);
        assert_eq!(event.kind(), RuntimeEventKind::ContainmentReleased);
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["event_type"], "containment_released");
        assert_eq!(json["trigger"], "expiry");
        assert_eq!(json["partition_state_at_execution"], "healthy");
    }
```

- [ ] **Step 2: Run to see it fail**

Run: `cargo test -p swarm-runtime containment_released_kind_round_trips`
Expected: FAIL to compile — no such variants.

- [ ] **Step 3: Add the variant in the six places**

In `crates/swarm-runtime/src/runtime_events.rs`:

1. `RuntimeEventKind` (`:127-139`): add `ContainmentReleased,` after `ModeTransition,`.
2. `as_str` (`:142-156`): add `Self::ContainmentReleased => "containment_released",`.
3. `parse` (`:158-173`): add `"containment_released" => Some(Self::ContainmentReleased),` before `_ => None`.
4. `RuntimeEvent` (`:214-305`): append the variant exactly as in Interfaces, with imports `use swarm_policy::governance::PartitionState;` and `use swarm_response::rollback::{RollbackReceipt, RollbackTrigger};` (both crates are already dependencies of `swarm-runtime`).
5. `emitted_at_ms` (`:308-322`): add `| Self::ContainmentReleased { emitted_at_ms, .. }` to the arm.
6. `kind` (`:324-338`): add `Self::ContainmentReleased { .. } => RuntimeEventKind::ContainmentReleased,`.

Seventh edit, `crates/swarm-ingest-runtime/src/ingest/mod.rs:766-768`: extend the last arm to

```rust
        RuntimeEvent::EvolutionStatus { .. }
        | RuntimeEvent::AgentHealth { .. }
        | RuntimeEvent::TamperAlert { .. }
        // B1c. A rollback receipt names a host and a governance attestation; it
        // belongs on no Providence-scoped stream (and, until B5, no anonymous one).
        | RuntimeEvent::ContainmentReleased { .. } => false,
```

- [ ] **Step 4: Run the round-trip test**

Run: `cargo test -p swarm-runtime containment_released_kind_round_trips && cargo build -p swarm-ingest-runtime`
Expected: 1 passed; the ingest crate compiles (the exhaustive match has its arm).

- [ ] **Step 5: Write the failing sweep test**

Append inside `containment.rs`'s `mod tests`, reusing the module's existing `open_containment`-style helpers (`http/tests.rs:3137` is the HTTP-side one; the unit module has `sample_lease`/`memory_store` builders beside the `qrt_04` tests — use whichever the file names):

```rust
    #[tokio::test]
    async fn every_release_publishes_a_containment_released_event() {
        let events = crate::runtime_events::RuntimeEventBroadcaster::new(16);
        let mut rx = events.subscribe();
        let store = std::sync::Arc::new(MemoryContainmentLeaseStore::default());
        let executor = std::sync::Arc::new(RecordingRollbackExecutor::default());
        let sweep = ContainmentSweep::new(store.clone(), executor, ExecutionMode::Enforced)
            .with_runtime_events(events);
        let lease = sample_lease("cl_manual", 1_000, 901_000);
        store.open(lease).unwrap();

        let receipt = sweep.release("cl_manual", 5_000).await.unwrap();
        let event = rx.try_recv().unwrap();
        match event {
            crate::runtime_events::RuntimeEvent::ContainmentReleased { lease_id, trigger, lease_closed, receipt: carried, attestation_verified, partition_state_at_execution, .. } => {
                assert_eq!(lease_id, "cl_manual");
                assert_eq!(trigger, RollbackTrigger::Manual);
                assert!(lease_closed);
                assert_eq!(carried.rollback_id, receipt.rollback_id);
                assert!(!attestation_verified, "no governance wired, so unattested");
                assert_eq!(partition_state_at_execution, None, "no governance wired, so no partition state");
            }
            other => panic!("wrong event: {other:?}"),
        }

        // Expiry path: the sweep publishes with trigger = expiry.
        store.open(sample_lease("cl_expiry", 1_000, 2_000)).unwrap();
        let report = sweep.sweep(3_000).await;
        assert_eq!(report.expired, 1);
        match rx.try_recv().unwrap() {
            crate::runtime_events::RuntimeEvent::ContainmentReleased { lease_id, trigger, .. } => {
                assert_eq!(lease_id, "cl_expiry");
                assert_eq!(trigger, RollbackTrigger::Expiry);
            }
            other => panic!("wrong event: {other:?}"),
        }
    }
```

- [ ] **Step 6: Run to see it fail**

Run: `cargo test -p swarm-runtime every_release_publishes_a_containment_released_event`
Expected: FAIL to compile — no `with_runtime_events`.

- [ ] **Step 7: Publish from the sweep**

In `crates/swarm-runtime/src/containment.rs`:

```rust
#[derive(Clone)]
pub struct ContainmentSweep {
    store: Arc<dyn ContainmentLeaseStore>,
    executor: Arc<dyn RollbackExecutor>,
    mode: ExecutionMode,
    governance: Option<Arc<dyn GovernanceAuthority>>,
    /// B1c. `None` publishes nothing, which is the pre-B1c behaviour and what
    /// every existing test constructs.
    runtime_events: Option<crate::runtime_events::RuntimeEventBroadcaster>,
}
```

Set `runtime_events: None` in `new` (and add it to the `Debug` impl as `.field("runtime_events", &self.runtime_events.is_some())`). Add:

```rust
    /// Attach the daemon's broadcaster so every release — manual or expiry —
    /// leaves the process as a `RuntimeEvent::ContainmentReleased`. The bridge
    /// turns it into the `swarm:rollback:v1` card; nothing else can, because the
    /// `RollbackReceipt` is produced inside this module and `run_until_shutdown`
    /// consumes the report internally (`11-BRIDGE-CRATE.md` §9.4).
    pub fn with_runtime_events(mut self, events: crate::runtime_events::RuntimeEventBroadcaster) -> Self {
        self.runtime_events = Some(events);
        self
    }

    /// One publish per release, after the store has been re-read. `lease_closed`
    /// is computed the way the HTTP handler computes it (`http/containment.rs:223-226`),
    /// never assumed from a successful receipt: a failed inverse keeps the lease open.
    fn publish_release(&self, receipt: &RollbackReceipt, trigger: RollbackTrigger, now_ms: i64) {
        let Some(events) = self.runtime_events.as_ref() else {
            return;
        };
        let lease_closed = self
            .store
            .open_leases()
            .map(|leases| !leases.iter().any(|lease| lease.lease_id() == receipt.lease_id))
            .unwrap_or(false);
        let (attestation_verified, attestation_error) = match verify_release_attestation(receipt) {
            Ok(_) => (true, None),
            Err(error) => (false, Some(error.to_string())),
        };
        events.publish(crate::runtime_events::RuntimeEvent::ContainmentReleased {
            emitted_at_ms: now_ms,
            lease_id: receipt.lease_id.clone(),
            trigger,
            receipt: receipt.clone(),
            lease_closed,
            attestation_verified,
            attestation_error,
            partition_state_at_execution: self.governance().map(|g| g.status_report().partition_state),
        });
    }
```

In `release` (`:544-557`) bind the result and publish before returning:

```rust
        let receipt = release_lease(self.store.as_ref(), self.executor.as_ref(), self.mode, lease_id, RollbackTrigger::Manual, now_ms, self.governance()).await?;
        self.publish_release(&receipt, RollbackTrigger::Manual, now_ms);
        Ok(receipt)
```

In `sweep` (`:597`) replace `Ok(receipt) => report.receipts.push(receipt),` with:

```rust
                Ok(receipt) => {
                    self.publish_release(&receipt, RollbackTrigger::Expiry, now_ms);
                    report.receipts.push(receipt);
                }
```

- [ ] **Step 8: Hand the broadcaster to the sweep in `swarm_detect`**

In `crates/swarm-runtime-http/src/bin/swarm_detect.rs`, before line `:1001` (`.with_runtime_events(runtime_events)`) add `let sweep_events = runtime_events.clone();`, and in the sweep construction at `:1029-1038` append `.with_runtime_events(sweep_events.clone())` after `.with_governance(...)`.

- [ ] **Step 9: Classify it in the bridge**

In `crates/swarm-perch-bridge/src/stream.rs` `classify`, add `RuntimeEvent::ContainmentReleased { .. } => Stream::Evidence,` — a rollback receipt is durable evidence, coalesced never, spooled to disk. The `classify_is_exhaustive` test (T-1) constructs one of each variant; add the thirteenth construction to it.

- [ ] **Step 10: Run the whole chain**

Run: `cargo test -p swarm-runtime containment && cargo test -p swarm-perch-bridge classify && cargo build -p swarm-runtime-http --bin swarm_detect && bash tools/check-runtime-panic-contract.sh`
Expected: `every_release_publishes_a_containment_released_event` and the existing `qrt_04_*` tests pass; the bridge's classify test passes; the binary builds; the panic-contract gate is clean.

- [ ] **Step 11: Commit**

```bash
git add crates/swarm-runtime/src/runtime_events.rs crates/swarm-runtime/src/containment.rs crates/swarm-ingest-runtime/src/ingest/mod.rs crates/swarm-runtime-http/src/bin/swarm_detect.rs crates/swarm-perch-bridge/src/stream.rs
git commit -s -m "feat(runtime): RuntimeEvent::ContainmentReleased (B1c) from every manual and expiry release"
```

---

### Task 6: B2g-p — partition state stamped at hold and at execution

**Files:**
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs` (add `current_partition_state`)
- Modify: `crates/swarm-runtime/src/held_action.rs` (`HeldAction`, `HoldDecisionRecord`)
- Modify: `crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs` (`capture_hold`, `decide_hold`)
- Modify: `crates/swarm-perch-wire/src/cards.rs` (`HeldAction`, `HoldDecisionRecord`), the TS mirror `workspace/desktop/src/features/perch/wire/types.ts` and `zod.ts`, the schemas `docs/plans/ambush-ui/build/schemas/card-swarm-hold-v1.schema.json`, `card-swarm-verdict-v1.schema.json` (renamed per W3-1) and the golden vectors + `GOLDEN.sha256`
- Modify: `crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs`, regenerate `docs/openapi/perch-operator-v1.json`
- Modify: `workspace/desktop/tests/e2e/perch-provenance.spec.ts` (#03 un-skipped, retargeted to the rollback card and the terminal hold card)
- Test: `crates/swarm-ingest-runtime/src/ingest/perch_ops/holds.rs` (`mod tests`)

**Interfaces:**
- Consumes: `IngestState.governance_policy: Option<Arc<dyn GovernanceAuthority>>` (`ingest/mod.rs:1375`); The hold's `HeldAction` (daemon record) and `HoldDecisionRecord`; Task 5's `partition_state_at_execution` on the rollback event.
- Produces: `IngestState::current_partition_state(&self) -> Option<PartitionState>`; `HeldAction.partition_state_at_hold: Option<PartitionState>`; `HoldDecisionRecord.partition_state_at_execution: Option<PartitionState>` (daemon, wire, TS, OpenAPI); the desktop's `AmbushRecordTier` → renamed `SwarmRecordTier` `unattested.byDesign` computed as `partition_state ∈ {partitioned, healing}` and `null` rendered as *"the console could not establish it"*.

- [ ] **Step 1: Write the failing decide test**

Append inside `perch_ops/holds.rs`'s `mod tests`:

```rust
    #[tokio::test]
    async fn a_decision_stamps_the_partition_state_at_execution() {
        let state = crate::ingest::test_support::ingest_state_with_governance(
            swarm_policy::governance::PartitionState::Healing,
        )
        .await;
        let hold = crate::ingest::test_support::capture_sample_hold(&state).await;
        assert_eq!(hold.partition_state_at_hold, Some(swarm_policy::governance::PartitionState::Healing));

        let outcome = decide_hold(&state, crate::ingest::test_support::sample_refuse_request(&hold)).await.unwrap();
        assert_eq!(
            outcome.decision.partition_state_at_execution,
            Some(swarm_policy::governance::PartitionState::Healing)
        );
    }

    #[tokio::test]
    async fn without_a_governance_authority_the_stamps_are_null_not_healthy() {
        let state = crate::ingest::test_support::ingest_state_with_in_memory_substrate().await;
        let hold = crate::ingest::test_support::capture_sample_hold(&state).await;
        assert_eq!(hold.partition_state_at_hold, None);
    }
```

`ingest_state_with_governance(state)` wraps `IngestState::with_governance_policy` around a fixed-report `GovernanceAuthority` test double (the `sealed` supertrait means the double lives inside `swarm-policy`'s test support or `swarm-ingest-runtime`'s existing governance fake — `ingest/tests.rs` already constructs one for `/healthz`; reuse it).

- [ ] **Step 2: Run to see it fail**

Run: `cargo test -p swarm-ingest-runtime a_decision_stamps_the_partition_state`
Expected: FAIL to compile — no `partition_state_at_hold` / `partition_state_at_execution`.

- [ ] **Step 3: Add the accessor and the two stamps**

In `crates/swarm-ingest-runtime/src/ingest/mod.rs`, beside `current_governance_status` (`:1847`):

```rust
    /// The governance authority's current partition state, or `None` when no
    /// authority is wired. `None` is rendered as "could not establish", never as
    /// healthy (`13-WIRE-SCHEMAS.md` §6).
    pub fn current_partition_state(&self) -> Option<swarm_policy::governance::PartitionState> {
        self.governance_policy
            .as_ref()
            .map(|policy| policy.status_report().partition_state)
    }
```

In `crates/swarm-runtime/src/held_action.rs` add to `HeldAction`:

```rust
    /// B2g-p. The governance partition state when the hold was created. `None`
    /// when no authority was wired at capture time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_state_at_hold: Option<swarm_policy::governance::PartitionState>,
```

and to `HoldDecisionRecord`:

```rust
    /// B2g-p. The partition state when the decision ran, read AFTER dispatch so a
    /// contingency-lease execution is stamped `partitioned`/`healing` and renders
    /// `UNATTESTED — BY DESIGN` rather than `UNATTESTED` (INV-08).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_state_at_execution: Option<swarm_policy::governance::PartitionState>,
```

In `perch_ops/holds.rs`, set `partition_state_at_hold: state.current_partition_state()` where `capture_hold` builds the record; in `decide_hold`, set `partition_state_at_execution: state.current_partition_state()` on the record **after** the dispatch call returns and before the store's terminal write. Mirror both fields on the wire crate's `HeldAction` and `HoldDecisionRecord` (`crates/swarm-perch-wire/src/cards.rs`), on the TS types and zod schemas, on the two JSON schemas (`"partition_state_at_hold": {"oneOf": [{"$ref": "common.schema.json#/$defs/PartitionState"}, {"type": "null"}]}`, same for `_execution`), and regenerate the golden vectors and `GOLDEN.sha256` with the wire crate's `regen` recipe (`crates/swarm-perch-wire/README.md`). Add both properties to the OpenAPI `HeldActionView` and `HoldDecisionRecord` schemas in the YAML and the generator; regenerate the JSON.

- [ ] **Step 4: Run the tests and the parity gate**

Run: `cargo test -p swarm-ingest-runtime partition_state && cargo test -p swarm-perch-wire && bash tools/check-perch-wire-parity.sh && bash tools/check-perch-openapi.sh`
Expected: all pass; parity reports the two new fields present on both sides.

- [ ] **Step 5: Un-skip the provenance spec**

In `workspace/desktop/tests/e2e/perch-provenance.spec.ts` test `03`, delete the `test.skip(...)` call and retarget the loop: emit a `swarm:rollback:v1` card (`marker: "swarm:rollback:v1"`) with `body: { rollback_receipt: { ...fixture rollback, governance_attestation: undefined }, partition_state_at_execution: state }` for each of the four states and assert `perch-attestation-badge-rollback-${state}` reads `UNATTESTED` for `healthy`/`degraded` and `UNATTESTED — BY DESIGN` for `partitioned`/`healing`; add a fifth iteration with `partition_state_at_execution: null` asserting the text `UNATTESTED · the console could not establish the partition state`. The rollback presenter that renders these lands in Task 10; until then this spec is red, which is the intended ordering (Task 10 step 12 turns it green).

- [ ] **Step 6: Commit**

```bash
git add crates/swarm-ingest-runtime/src/ingest/ crates/swarm-perch-wire/ workspace/desktop/src/features/perch/wire/ docs/plans/ambush-ui/build/schemas/ docs/plans/ambush-ui/build/skeleton/perch-wire/golden/ crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs docs/openapi/perch-operator-v1.json docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml workspace/desktop/tests/e2e/perch-provenance.spec.ts
git commit -s -m "feat(ingest): stamp partition state at hold and at execution (B2g-p)"
```

---

#### Tasks 5 and 6 status — 2026-09-04

**Task 5 is complete.** `RuntimeEvent::ContainmentReleased` exists in all seven places, both
release paths publish it, the daemon hands the sweep its broadcaster, and the bridge classifies
it as `Stream::Evidence` with a test pinning that choice rather than only its existence.

**Task 6 landed its Rust and wire halves.** The two stamps, the `current_partition_state`
accessor, the wire-crate mirrors, both JSON-schema declarations, `zod.ts` and `types.ts`. The
parity gate reports 324 fields on both sides, up from 322, and every golden vector is
byte-identical because both fields skip serialization when absent.

Two of its steps are **not done**, for the same reason Task 4 stopped:

- the OpenAPI half (`HeldActionView` and `HoldDecisionRecord` in the YAML, then a regenerated
  JSON) needs `generate_perch_openapi.rs`, which does not exist. See the Task 4 status note.
- Step 5 un-skips `workspace/desktop/tests/e2e/perch-provenance.spec.ts`. That file does not
  exist either; First card's E2E set is `perch-finding-card` and `perch-marker-admission`, and
  The hold added four more. The rendering half of INV-08 therefore has no spec yet, and this
  task does not claim one.

## Task 7: B6 — signed spine envelopes on the bridge's publish path

**Files:**
- Modify: `crates/swarm-core/src/config/perch.rs` (`PerchBridgeConfig.spine_seed_env`)
- Create: `crates/swarm-perch-bridge/src/spine.rs`
- Create: `crates/swarm-perch-bridge/src/spool/chain_heads.rs`
- Modify: `crates/swarm-perch-bridge/src/spool/mod.rs` (`pub mod chain_heads;`), `src/lib.rs` (`pub mod spine;`, build wiring), `src/cards.rs` (seal at assembly), `src/metrics.rs` (`bridge_envelopes_signed`), `Cargo.toml` (`swarm-spine`, `swarm-crypto`)
- Modify: `crates/swarm-perch-wire/src/envelope.rs` (transport-neutral signing bytes and chain DTOs only; no crypto dependency)
- Modify: `rulesets-dev/perch-dev.yaml` (`perch.spine_seed_env: PERCH_BRIDGE_SPINE_SEED`)
- Modify: `tools/check-workspace-layering.sh` (no edit needed — the bridge is already `TRUST_SENSITIVE`; verify only)
- Test: `crates/swarm-perch-bridge/src/spine.rs`, `src/spool/chain_heads.rs`, `tests/wire_parity.rs`, `crates/swarm-perch-wire/src/envelope.rs`

**Interfaces:**
- Consumes: `swarm_spine::envelope::{build_signed_envelope(&Keypair, u64, Option<String>, Value, String) -> SpineResult<Value>, verify_envelope(&Value) -> SpineResult<bool>, issuer_from_keypair(&Keypair) -> String, now_rfc3339()}`; `swarm_crypto::Keypair::from_seed`; the transport-neutral `swarm_perch_wire::envelope::{canonical_bytes, compute_envelope_hash_hex, unsigned_envelope_value, IssuerChainHead, ChainLinkVerdict, verify_chain_link}`; `IdentityTable` slot labels; the spool's per-`(colony_id, issuer)` `seq` assigned at append.
- Produces: `SpineSigner::from_config(config: &PerchBridgeConfig, colony_id: &str, slots: &[String]) -> Result<SpineSigner, BridgeError>`; `SpineSigner::issuer(&self, slot: &str) -> &str`; `SpineSigner::seal(&self, slot: &str, kind: CardKind, heads: &mut ChainHeadStore, fact: Value) -> Result<CardEnvelope, BridgeError>`; `ChainHeadStore::{open(dir, colony_id) -> Result<Self, BridgeError>, head(&self, issuer) -> Option<&IssuerChainHead>, advance(&mut self, head: IssuerChainHead) -> Result<(), BridgeError>}`; the metric `perch_bridge_envelopes_signed_total{issuer}`; `BridgeError::{MissingSpineSeed, ChainHeadCorrupt}`; config key `perch.spine_seed_env` (default `"PERCH_BRIDGE_SPINE_SEED"`, 32 bytes of hex; absent while `enabled` → `BridgeError::MissingSpineSeed`).

- [ ] **Step 1: Extend the transport-neutral wire verification inputs.** In
  `swarm-perch-wire/src/envelope.rs`, add wire-owned `IssuerChainHead` and
  `ChainLinkVerdict`, `unsigned_envelope_value` (removes `envelope_hash` and
  `signature`), and `verify_chain_link` (checks issuer equality, `seq = head.seq + 1`,
  and `prev_envelope_hash = head.envelope_hash`). It performs no signature operation.
  `canonical_bytes` and `compute_envelope_hash_hex` remain the W3-27 JCS functions from
  First card. Tests cover a valid link, issuer mismatch, sequence gap and hash mismatch.

- [ ] **Step 2: Re-prove the dependency boundary.** Run `cargo test -p
  swarm-perch-wire envelope` and the exact metadata assertion from First card Task 1;
  no dependency named `swarm-*` may appear. Run the bridge's `wire_parity` differential
  suite against `swarm_spine::envelope_signing_bytes` again. A mismatch blocks B6.

- [ ] **Step 3: Keep signing in the bridge.** `SpineSigner::seal` calls
  `swarm_spine::build_signed_envelope`, verifies the result once with
  `swarm_spine::verify_envelope`, and then deserializes the resulting JSON into the
  wire-owned `CardEnvelope`. No keypair type or verification function crosses into the
  wire crate. The Tauri side later obtains `canonical_bytes(unsigned_envelope_value(v))`
  from the shared crate and verifies the signature with its existing `ed25519-dalek`.

- [ ] **Step 4: Write the failing bridge integration test.** Generate a
  `swarm_crypto::Keypair`, seal a finding through `SpineSigner`, assert the engine spine
  verifies it, assert the wire crate computes the same hash and chain verdict, strip the
  signature and assert the Tauri-style verifier fixture reports tier 0. Run it red before
  implementing `SpineSigner::seal`.

- [ ] **Step 5: Commit the neutral wire additions and bridge test with the bridge half.**
  Do not create a separate wire commit that temporarily adds an engine dependency.

- [ ] **Step 6: Write the failing chain-head store test**

Create `crates/swarm-perch-bridge/src/spool/chain_heads.rs` starting with its tests:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn heads_survive_reopen_and_refuse_a_regression() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = "swarm:ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        {
            let mut store = ChainHeadStore::open(dir.path(), "colony-a").unwrap();
            assert!(store.head(issuer).is_none());
            store.advance(IssuerChainHead { issuer: issuer.into(), seq: 1, envelope_hash: "0x01".into() }).unwrap();
            store.advance(IssuerChainHead { issuer: issuer.into(), seq: 2, envelope_hash: "0x02".into() }).unwrap();
        }
        let mut store = ChainHeadStore::open(dir.path(), "colony-a").unwrap();
        assert_eq!(store.head(issuer).map(|h| h.seq), Some(2));
        let regress = store.advance(IssuerChainHead { issuer: issuer.into(), seq: 2, envelope_hash: "0x03".into() });
        assert!(matches!(regress, Err(BridgeError::ChainHeadRegression { .. })));
    }

    #[test]
    fn a_store_written_under_another_colony_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        ChainHeadStore::open(dir.path(), "colony-a").unwrap();
        assert!(matches!(ChainHeadStore::open(dir.path(), "colony-b"), Err(BridgeError::ColonyMismatch { .. })));
    }
}
```

- [ ] **Step 7: Run to see it fail**

Run: `cargo test -p swarm-perch-bridge chain_heads`
Expected: FAIL to compile.

- [ ] **Step 8: Implement the store**

Prepend to `chain_heads.rs`:

```rust
//! Per-issuer chain heads for B6, persisted beside the spool.
//!
//! One JSON file, rewritten atomically (write `chain-heads.json.tmp`, fsync,
//! rename) on every advance. The file carries the colony id so a spool directory
//! moved between colonies fails loudly (`11-BRIDGE-CRATE.md` T-7's rule, applied
//! one file over). Sizes: ten issuers × one head; rewriting the whole file is
//! cheaper than a log, and there is no partial-write state to recover.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
pub use swarm_perch_wire::envelope::IssuerChainHead;

use crate::error::BridgeError;

const FILE_NAME: &str = "chain-heads.json";

#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    colony_id: String,
    heads: BTreeMap<String, IssuerChainHead>,
}

/// The chain-head store. Holds the newest `(seq, envelope_hash)` per issuer.
#[derive(Debug)]
pub struct ChainHeadStore {
    path: PathBuf,
    colony_id: String,
    heads: BTreeMap<String, IssuerChainHead>,
}

impl ChainHeadStore {
    /// Open or create `<dir>/chain-heads.json` for `colony_id`.
    ///
    /// # Errors
    ///
    /// [`BridgeError::ColonyMismatch`] when the file was written under another
    /// colony; [`BridgeError::ChainHeadCorrupt`] when it does not parse; `Io`
    /// on the filesystem.
    pub fn open(dir: &Path, colony_id: &str) -> Result<Self, BridgeError> {
        let path = dir.join(FILE_NAME);
        let heads = if path.exists() {
            let bytes = std::fs::read(&path)?;
            let on_disk: OnDisk = serde_json::from_slice(&bytes)
                .map_err(|error| BridgeError::ChainHeadCorrupt { path: path.clone(), reason: error.to_string() })?;
            if on_disk.colony_id != colony_id {
                return Err(BridgeError::ColonyMismatch { expected: colony_id.to_string(), found: on_disk.colony_id });
            }
            on_disk.heads
        } else {
            BTreeMap::new()
        };
        let store = Self { path, colony_id: colony_id.to_string(), heads };
        store.persist()?;
        Ok(store)
    }

    /// The newest head for `issuer`, if any envelope was ever sealed under it.
    pub fn head(&self, issuer: &str) -> Option<&IssuerChainHead> {
        self.heads.get(issuer)
    }

    /// Record a newly sealed envelope's head. `seq` must be exactly `previous + 1`
    /// (or `1` on a fresh issuer); anything else is a programming error the store
    /// refuses rather than persists, because a persisted regression is a gap the
    /// console would render as a forgery.
    pub fn advance(&mut self, head: IssuerChainHead) -> Result<(), BridgeError> {
        let expected = self.heads.get(&head.issuer).map_or(1, |h| h.seq + 1);
        if head.seq != expected {
            return Err(BridgeError::ChainHeadRegression { issuer: head.issuer, expected, found: head.seq });
        }
        self.heads.insert(head.issuer.clone(), head);
        self.persist()
    }

    fn persist(&self) -> Result<(), BridgeError> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&OnDisk { colony_id: self.colony_id.clone(), heads: self.heads.clone() })
            .map_err(|error| BridgeError::ChainHeadCorrupt { path: self.path.clone(), reason: error.to_string() })?;
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}
```

Add to `crates/swarm-perch-bridge/src/error.rs`:

```rust
    #[error("perch.spine_seed_env `{env}` is unset or shorter than 32 bytes of hex; the bridge refuses to start rather than publish unsigned envelopes under a signing profile")]
    MissingSpineSeed { env: String },
    #[error("chain-heads file {path} is unreadable: {reason}")]
    ChainHeadCorrupt { path: PathBuf, reason: String },
    #[error("chain head for {issuer} would regress: expected seq {expected}, got {found}")]
    ChainHeadRegression { issuer: String, expected: u64, found: u64 },
    #[error("spool directory belongs to colony {found}, not {expected}")]
    ColonyMismatch { expected: String, found: String },
```

(`ColonyMismatch` may already exist for the spool's colony hash — reuse it if so.) Add `pub mod
chain_heads;` to `spool/mod.rs`, `tempfile` to `[dev-dependencies]`, and `swarm-spine = { path =
"../swarm-spine" }`, `swarm-crypto = { path = "../swarm-crypto" }` to `[dependencies]`. The
bridge is already listed in `TRUST_SENSITIVE`; these are bridge → TCB edges and do not create the
forbidden reverse edge from `swarm-crypto`, `swarm-policy` or `swarm-spine` into the bridge or
wire crate. Verify RULE 2 and RULE 3 without editing the gate, and record the ADR 0015 C1
amendment: the bridge's declared engine dependencies become `swarm-core`, `swarm-runtime`,
`swarm-response`, `swarm-spine`, `swarm-crypto`.

- [ ] **Step 9: Run the store tests and the layering gate**

Run: `cargo test -p swarm-perch-bridge chain_heads && bash tools/check-workspace-layering.sh`
Expected: 2 passed; layering clean.

- [ ] **Step 10: Write the failing signer test**

Create `crates/swarm-perch-bridge/src/spine.rs` with its tests:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SEED: &str = "0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100";

    #[test]
    fn slots_derive_distinct_issuers_deterministically() {
        let a = SpineSigner::from_seed_hex(SEED, "colony-a", &["perch-alarm".into(), "perch-telemetry".into()]).unwrap();
        let b = SpineSigner::from_seed_hex(SEED, "colony-a", &["perch-alarm".into(), "perch-telemetry".into()]).unwrap();
        assert_eq!(a.issuer("perch-alarm"), b.issuer("perch-alarm"));
        assert_ne!(a.issuer("perch-alarm"), a.issuer("perch-telemetry"));
        assert!(a.issuer("perch-alarm").starts_with("swarm:ed25519:"));
        let other = SpineSigner::from_seed_hex(SEED, "colony-b", &["perch-alarm".into()]).unwrap();
        assert_ne!(a.issuer("perch-alarm"), other.issuer("perch-alarm"), "colony id is in the derivation");
    }

    #[test]
    fn seal_chains_per_issuer_and_the_spine_verifies_every_link() {
        let dir = tempfile::tempdir().unwrap();
        let signer = SpineSigner::from_seed_hex(SEED, "colony-a", &["perch-alarm".into()]).unwrap();
        let mut heads = crate::spool::chain_heads::ChainHeadStore::open(dir.path(), "colony-a").unwrap();
        let fact = |n: u64| serde_json::json!({ "schema": "swarm.perch.hold.v1", "issuer": {"swarm_agent_id": "x", "role": null}, "emitted_at_ms": n });
        let first = signer.seal("perch-alarm", swarm_perch_wire::CardKind::Hold, &mut heads, fact(1)).unwrap();
        let second = signer.seal("perch-alarm", swarm_perch_wire::CardKind::Hold, &mut heads, fact(2)).unwrap();
        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 2);
        assert_eq!(second.prev_envelope_hash.as_deref(), Some(first.envelope_hash.as_str()));
        let head = swarm_perch_wire::envelope::IssuerChainHead { issuer: first.issuer.clone(), seq: 1, envelope_hash: first.envelope_hash.clone() };
        let verdict = swarm_perch_wire::envelope::verify_chain_link(&serde_json::to_value(&second).unwrap(), Some(&head)).unwrap();
        assert!(verdict.is_valid());
        assert!(swarm_spine::envelope::verify_envelope(&serde_json::to_value(&second).unwrap()).unwrap());
    }
}
```

- [ ] **Step 11: Run to see it fail**

Run: `cargo test -p swarm-perch-bridge spine::`
Expected: FAIL to compile.

- [ ] **Step 12: Implement the signer**

Prepend to `spine.rs`:

```rust
//! B6: the spine signing identities and the seal step.
//!
//! One configured secret root, one Ed25519 keypair per bridge identity slot,
//! derived exactly the way the Nostr keys are (`identity.rs`, `11` §7.2) with a
//! different domain string so the two chains can never share key material:
//!
//! ```text
//! spine_secret[slot] = SHA-256( b"swarm.perch.bridge.spine.v1" || 0x00 || root || 0x00 || colony_id || 0x00 || slot_label )
//! ```
//!
//! The root comes from `perch.spine_seed_env`, never from a public identifier —
//! `approval.rs:1807-1809` derives from a public ledger id and that is exactly the
//! forgery this file exists to prevent (`12` §13.2).

use std::collections::BTreeMap;

use serde_json::Value;
use swarm_crypto::{Keypair, sha256};
use swarm_perch_wire::{CardEnvelope, CardKind};
use swarm_perch_wire::envelope::IssuerChainHead;
use swarm_spine::envelope::{build_signed_envelope, issuer_from_keypair, now_rfc3339, verify_envelope};

use crate::error::BridgeError;
use crate::spool::chain_heads::ChainHeadStore;

const DOMAIN: &[u8] = b"swarm.perch.bridge.spine.v1";

/// The per-slot spine keypairs. Holds secret material; never `Debug`-prints it.
pub struct SpineSigner {
    keys: BTreeMap<String, Keypair>,
    issuers: BTreeMap<String, String>,
}

impl std::fmt::Debug for SpineSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpineSigner").field("slots", &self.issuers.keys().collect::<Vec<_>>()).finish()
    }
}

impl SpineSigner {
    /// Read the root from the environment variable `config.spine_seed_env` names.
    ///
    /// # Errors
    ///
    /// [`BridgeError::MissingSpineSeed`] when the variable is unset, empty, not
    /// hex, or shorter than 32 bytes.
    pub fn from_config(config: &swarm_core::config::PerchBridgeConfig, colony_id: &str, slots: &[String]) -> Result<Self, BridgeError> {
        let env = config.spine_seed_env.trim().to_string();
        let raw = std::env::var(&env).map_err(|_| BridgeError::MissingSpineSeed { env: env.clone() })?;
        Self::from_seed_hex(raw.trim(), colony_id, slots).map_err(|_| BridgeError::MissingSpineSeed { env })
    }

    /// Derive every slot's keypair from 32 bytes of hex.
    ///
    /// # Errors
    ///
    /// [`BridgeError::MissingSpineSeed`] (with an empty `env`) when `seed_hex` is not 64 hex characters.
    pub fn from_seed_hex(seed_hex: &str, colony_id: &str, slots: &[String]) -> Result<Self, BridgeError> {
        let root = hex::decode(seed_hex).map_err(|_| BridgeError::MissingSpineSeed { env: String::new() })?;
        if root.len() < 32 {
            return Err(BridgeError::MissingSpineSeed { env: String::new() });
        }
        let mut keys = BTreeMap::new();
        let mut issuers = BTreeMap::new();
        for slot in slots {
            let mut preimage = Vec::with_capacity(DOMAIN.len() + root.len() + colony_id.len() + slot.len() + 3);
            preimage.extend_from_slice(DOMAIN);
            preimage.push(0);
            preimage.extend_from_slice(&root);
            preimage.push(0);
            preimage.extend_from_slice(colony_id.as_bytes());
            preimage.push(0);
            preimage.extend_from_slice(slot.as_bytes());
            let keypair = Keypair::from_seed(sha256(&preimage).as_bytes());
            issuers.insert(slot.clone(), issuer_from_keypair(&keypair));
            keys.insert(slot.clone(), keypair);
        }
        Ok(Self { keys, issuers })
    }

    /// The `swarm:ed25519:<hex>` issuer for a slot. Panics never: an unknown slot is
    /// a programming error surfaced as the empty string, which `seal` refuses.
    pub fn issuer(&self, slot: &str) -> &str {
        self.issuers.get(slot).map_or("", String::as_str)
    }

    /// Seal `fact` under `slot`, advancing that issuer's chain head.
    ///
    /// `seq` is `head.seq + 1` (or 1), `prev_envelope_hash` is the head's hash, and
    /// the head store is advanced only after the envelope is built — a failed seal
    /// leaves the chain where it was.
    ///
    /// # Errors
    ///
    /// [`BridgeError::UnknownSlot`] for a slot not in the table; a spine refusal
    /// or wire decode mapped to [`BridgeError::Envelope`]; and the chain-head
    /// store's errors.
    pub fn seal(&self, slot: &str, kind: CardKind, heads: &mut ChainHeadStore, fact: Value) -> Result<CardEnvelope, BridgeError> {
        let keypair = self.keys.get(slot).ok_or_else(|| BridgeError::UnknownSlot { slot: slot.to_string() })?;
        let issuer = self.issuer(slot).to_string();
        let (seq, prev) = match heads.head(&issuer) {
            Some(head) => (head.seq + 1, Some(head.envelope_hash.clone())),
            None => (1, None),
        };
        let found = fact.get("schema").and_then(Value::as_str).unwrap_or_default();
        if found != kind.fact_schema() {
            return Err(BridgeError::Envelope(format!("fact schema {found:?} does not match {}", kind.fact_schema())));
        }
        let value = build_signed_envelope(keypair, seq, prev, fact, now_rfc3339())
            .map_err(|error| BridgeError::Envelope(error.to_string()))?;
        if !verify_envelope(&value).map_err(|error| BridgeError::Envelope(error.to_string()))? {
            return Err(BridgeError::Envelope("spine rejected its newly signed envelope".to_string()));
        }
        let envelope: CardEnvelope = serde_json::from_value(value)
            .map_err(|error| BridgeError::Envelope(error.to_string()))?;
        heads.advance(IssuerChainHead { issuer, seq, envelope_hash: envelope.envelope_hash.clone() })?;
        Ok(envelope)
    }
}
```

Add `BridgeError::UnknownSlot { slot: String }` and `BridgeError::Envelope(String)`; add `hex` (already a workspace dependency) to the bridge's manifest if absent. In `crates/swarm-core/src/config/perch.rs` add to `PerchBridgeConfig`:

```rust
    /// Environment variable holding 32 bytes of hex: the root of the SPINE key
    /// derivation (B6). Distinct from `nostr_seed_env` on purpose — the transport
    /// chain and the record chain must not share material (ADR 0016).
    #[serde(default = "default_spine_seed_env")]
    pub spine_seed_env: String,
```

with `fn default_spine_seed_env() -> String { "PERCH_BRIDGE_SPINE_SEED".into() }`, and set `spine_seed_env: PERCH_BRIDGE_SPINE_SEED` in `rulesets-dev/perch-dev.yaml`'s `perch:` block.

- [ ] **Step 13: Run the signer tests**

Run: `cargo test -p swarm-perch-bridge spine::`
Expected: 2 passed.

- [ ] **Step 14: Seal on the publish path and count it**

In `crates/swarm-perch-bridge/src/cards.rs`, where `CardBody` is assembled from a fact (`hold_card`, the finding/escalation/receipt builders, and Task 8/9's lease and rollback builders), replace the `CardEnvelope::seal_unsigned(kind, issuer, seq, prev, issued_at, fact)` call with `signer.seal(slot, kind, heads, fact)`, threading `&SpineSigner` and `&mut ChainHeadStore` from the spool-append site in `receive.rs`/`pacer.rs` (whichever the landed crate seals in — `11` §3.7 assigns `seq` at spool append, so the seal happens there and the sealed body is what the spool stores). Keep `seal_unsigned` reachable only from `#[cfg(test)]` and the fixture generator. In `lib.rs::PerchBridge::build`, construct `SpineSigner::from_config(&input.config, &input.colony_id, &identity_table.slot_labels())?` and `ChainHeadStore::open(&spool_dir, &input.colony_id)?` before the spools open — a missing seed is fatal at startup (`F1`'s shape), never a silent unsigned publish. In `metrics.rs` register `bridge_envelopes_signed` as `Family<IssuerLabel, Counter>` (emits `perch_bridge_envelopes_signed_total{issuer}`) and increment it in `seal`'s caller.

Add to the bridge's test module a `T-16b`:

```rust
    #[test]
    fn every_published_card_body_carries_a_signature_that_verifies() {
        // Drive one card of each bridge-authored marker through the assembly path with a
        // test signer and assert `verify_envelope` is Ok(true) on each body's JSON.
    }
```

written against the same fixtures T-16 (`no_signature_field_in_any_card_body`) uses — and **rewrite T-16**: after B6 the field `signature` IS present on the envelope, so T-16's assertion narrows to `fact` (no `signature`, `signed_by` or `verified` key inside the fact object — ADR 0016 C4 is about the fact, and the envelope signature is the spine's).

- [ ] **Step 15: Run the bridge suite and the panic contract**

Run: `cargo test -p swarm-perch-bridge && bash tools/check-runtime-panic-contract.sh && bash tools/check-workspace-layering.sh`
Expected: all pass, including the rewritten T-16 and T-16b.

- [ ] **Step 16: Commit**

```bash
git add crates/swarm-perch-bridge/ crates/swarm-core/src/config/perch.rs rulesets-dev/perch-dev.yaml
git commit -s -m "feat(bridge): sign every envelope with a provisioned spine identity and chain it per issuer (B6)"
```

---

#### Task 7 status — 2026-09-04

Steps 1 through 13 landed, plus the startup half of step 14. The wire crate's keyless chain
primitives, the durable chain-head store, the spine signer, and construction of both in
`PerchBridge::build` — so a signing profile with an unusable seed **refuses to start**, which is
the security property the task exists for. Engine gates green: 1,566 tests, clippy `-D warnings`,
layering and panic-contract.

**Step 14 landed for the evidence path.** The pacer signs at append through
`SpineSigner::seal_at` and commits the durable head on ACKNOWLEDGEMENT and nowhere else. That
split is the design point: the pacer restores `prev_envelope_hash` when a frame is not
acknowledged, precisely so an unpublished card never advances the chain, and a seal that wrote
the durable head at append would advance it for a card the relay never took — the next real card
would then chain from a link nobody can fetch, a broken chain produced by the mechanism meant to
guarantee it. A head that cannot be advanced is logged rather than propagated: the card IS
published, so returning an error would re-send a frame the relay already took; the next seal
reads the stale head, produces a duplicate `seq`, and the store refuses it — visible, not a
silent fork.

The envelope is issued under the SPINE identity rather than the Nostr key that publishes it, and
`a_card_built_with_a_signer_carries_a_signature_that_verifies` asserts the signature verifies
under the issuer it names. Without a signer the envelope is unsigned, which is what the fixture
generator and the pre-B6 tests construct.

**Task 7 is complete.** The hold path seals under the spine too — a hold is the record an
operator acts on, so it is the last card that should be publishable without attestation. The
`bridge_envelopes_signed{issuer}` metric is registered and incremented where the seal happens, so
an operator comparing it with `bridge_source_events_published` can see whether what reached the
relay was signed rather than taking it on faith. T-16 is narrowed: the ENVELOPE now carries a
signature, which is the point of B6, and the ban applies to the FACT — a card that vouched for
itself would be asking a reader to trust the thing under examination.

## Task 8: Bridge — response receipts first, then `swarm:lease:v1` from the 1 Hz containment sweep poll

**Files:**
- Create: `crates/swarm-perch-bridge/src/leases.rs` (working watcher and card body; copied skeleton text may be used as a starting point but no `todo!()` is committed)
- Modify: `crates/swarm-perch-bridge/src/cards.rs` (`RuntimeEvent::ResponseExecution` → `Marker::Receipt`, plus `Marker::Lease` assembly), `src/pacer.rs` (publish and commit receipts before the lease poll can observe them), `src/lib.rs` (spawn the poll task), `src/metrics.rs` (`bridge_receipt_cards_published`, `bridge_receipt_unrouted`, `bridge_lease_store_absent`, `bridge_lease_cards_published`), `src/channels.rs` (`receipt_id → hunt_id` and `hunt_id → case_channel` lookups exposed as `CaseRouting::case_for_receipt`)
- Test: `crates/swarm-perch-bridge/src/leases.rs` and `src/cards.rs` (`mod tests`)

**Interfaces:**
- Consumes: `RuntimeEvent::ResponseExecution`; the `swarm.perch.receipt.v1` wire DTO/schema; `ContainmentSweep::open_leases() -> Result<Vec<ContainmentLease>, ContainmentStoreError>`; `ContainmentLease::{lease_id(), action(), action_kind(), origin_receipt_id(), governance_receipt_id(), issued_at_ms(), expires_at_ms()}` and its `serde(into = ContainmentLeaseRecord)` serialization; `swarm_perch_wire::cards::{ReceiptCard, LeaseCard, LeaseLocator, TtlSource, FactIssuer}`; `CaseRouting` (the `hunt_id → case_channel` map, `11` §9.1.4) plus the `receipt_id → hunt_id` map recorded only after the receipt card is acknowledged; `SpineSigner::seal` (Task 7); the evidence spool.
- Produces: `response_receipt_card(event, case_channel, issuer) -> Result<CardBody, BridgeError>` and its real `swarm:receipt:v1` kind:9 event; `LeaseWatcher::poll(&mut self) -> Result<LeaseDiff, BridgeError>` (implemented); `lease_card_body(lease: &ContainmentLease, case_channel: Uuid, issuer: FactIssuer) -> serde_json::Value` (the `swarm.perch.lease.v1` fact); `LeaseCardIndex { by_lease_id: BTreeMap<String, Hex64> }` persisted in the evidence spool's cursor sidecar so Task 9 can `e`-tag the rollback card; receipt and lease counters plus their explicit unrouted counters.

- [ ] **Step 0: Land the receipt producer the lease join depends on (W3-29).** Write tests that feed a `ResponseExecution` with a known `hunt_id` and `receipt_id` through the evidence pacer, assert one kind:9 `swarm:receipt:v1` event in that hunt's case channel with no host or detector detail, then assert `CaseRouting::case_for_receipt(receipt_id)` resolves only after relay `OK true`. A missing case route leaves the record uncommitted and increments `perch_bridge_receipt_unrouted_total`; it is never silently skipped. Implement the builder from the wire DTO/schema, seal it through Task 7's signer, and add the `receipt_id → hunt_id` mapping on acknowledgement. Run `cargo test -p swarm-perch-bridge response_receipt` and extend the ignored relay test to query the exact event id from the case channel before starting the lease-poll test.

- [ ] **Step 1: Write the failing poll test**

Create `leases.rs` with its imports, types and this failing test module before adding the implementation:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use swarm_response::ExecutionMode;
    use swarm_runtime::containment::{ContainmentSweep, MemoryContainmentLeaseStore, RecordingRollbackExecutor};

    fn sweep_with(leases: &[(&str, i64, i64)]) -> (Arc<ContainmentSweep>, Arc<MemoryContainmentLeaseStore>) {
        let store = Arc::new(MemoryContainmentLeaseStore::default());
        for (id, issued, expires) in leases {
            store.open(swarm_runtime::containment::test_support::sample_lease(id, *issued, *expires)).unwrap();
        }
        let sweep = Arc::new(ContainmentSweep::new(store.clone(), Arc::new(RecordingRollbackExecutor::default()), ExecutionMode::Enforced));
        (sweep, store)
    }

    #[test]
    fn poll_reports_appeared_and_disappeared_by_lease_id() {
        let (sweep, store) = sweep_with(&[("cl_a", 1_000, 901_000)]);
        let mut watcher = LeaseWatcher::new(Some(sweep));
        let first = watcher.poll().unwrap();
        assert_eq!(first.appeared.iter().map(|l| l.lease_id().to_string()).collect::<Vec<_>>(), vec!["cl_a"]);
        assert!(first.disappeared.is_empty());

        store.open(swarm_runtime::containment::test_support::sample_lease("cl_b", 2_000, 902_000)).unwrap();
        store.close("cl_a").unwrap();
        let second = watcher.poll().unwrap();
        assert_eq!(second.appeared.iter().map(|l| l.lease_id().to_string()).collect::<Vec<_>>(), vec!["cl_b"]);
        assert_eq!(second.disappeared, vec!["cl_a".to_string()]);

        let third = watcher.poll().unwrap();
        assert!(third.appeared.is_empty() && third.disappeared.is_empty(), "a steady state emits nothing");
    }

    #[test]
    fn no_store_publishes_nothing_and_reports_absent() {
        let mut watcher = LeaseWatcher::new(None);
        let diff = watcher.poll().unwrap();
        assert!(diff.appeared.is_empty() && diff.disappeared.is_empty());
        assert!(watcher.store_absent());
    }

    #[test]
    fn lease_card_body_carries_the_lease_verbatim_and_nothing_clock_derived() {
        let (sweep, _) = sweep_with(&[("cl_a", 1_000, 901_000)]);
        let lease = sweep.open_leases().unwrap().remove(0);
        let case = uuid::Uuid::parse_str("27799e23-ab25-4659-b381-3de47ea7ca4d").unwrap();
        let body = lease_card_body(&lease, case, FactIssuer { swarm_agent_id: "containment-sweep".into(), role: None, nostr_pubkey: None });
        assert_eq!(body["schema"], "swarm.perch.lease.v1");
        assert_eq!(body["lease"]["lease_id"], "cl_a");
        assert_eq!(body["lease"]["expires_at_ms"], 901_000);
        assert_eq!(body["ttl_source"], "runtime.containment.lease_ttl_ms");
        assert_eq!(body["locator"]["case_channel"], case.to_string());
        for forbidden in ["remaining_ms", "expired", "signature", "signed_by", "verified"] {
            assert!(body.to_string().contains(forbidden) == false, "{forbidden} must not be baked into an immutable card");
        }
    }
}
```

`swarm_runtime::containment::test_support::sample_lease` and `MemoryContainmentLeaseStore`/`RecordingRollbackExecutor` are what `containment.rs`'s own `mod tests` builds at `:648+`; if they are private, promote the builders into a `#[cfg(any(test, feature = "test-support"))] pub mod test_support` in `swarm-runtime` and enable that feature from the bridge's `[dev-dependencies]`.

- [ ] **Step 2: Run to see it fail**

Run: `cargo test -p swarm-perch-bridge leases::`
Expected: compile failure because `LeaseWatcher::poll`, `store_absent` and `lease_card_body` are not implemented yet.

- [ ] **Step 3: Implement the poll and the body**

Implement the three functions in `leases.rs`:

```rust
    /// One poll. Returns the containment leases that newly appeared and the ids
    /// that left `open_leases()` since the previous poll.
    pub fn poll(&mut self) -> Result<LeaseDiff, BridgeError> {
        let Some(sweep) = self.sweep.as_ref() else {
            return Ok(LeaseDiff::default());
        };
        let current = sweep.open_leases().map_err(|error| BridgeError::LeaseStore { reason: error.to_string() })?;
        let now: BTreeSet<String> = current.iter().map(|lease| lease.lease_id().to_string()).collect();
        let appeared = current
            .into_iter()
            .filter(|lease| !self.open.contains(lease.lease_id()))
            .collect();
        let disappeared = self.open.difference(&now).cloned().collect();
        self.open = now;
        Ok(LeaseDiff { appeared, disappeared })
    }

    /// True on the shipped default: no `runtime.containment.lease_store_path`.
    pub fn store_absent(&self) -> bool {
        self.sweep.is_none()
    }
```

and

```rust
pub fn lease_card_body(lease: &ContainmentLease, case_channel: uuid::Uuid, issuer: FactIssuer) -> serde_json::Value {
    // `ContainmentLease` serializes as its private `ContainmentLeaseRecord`
    // (`swarm-response/src/containment.rs:129-130`), which is the shape the schema
    // pins. Nothing here reads a clock.
    serde_json::json!({
        "schema": "swarm.perch.lease.v1",
        "issuer": issuer,
        "emitted_at_ms": lease.issued_at_ms(),
        "locator": {
            "lease_id": lease.lease_id(),
            "case_channel": case_channel.to_string(),
            "origin_receipt_id": lease.origin_receipt_id(),
            "receipt_card_id": serde_json::Value::Null,
        },
        "lease": lease,
        "ttl_source": "runtime.containment.lease_ttl_ms",
    })
}
```

with `use swarm_perch_wire::cards::FactIssuer;` and `BridgeError::LeaseStore { reason: String }` added to `error.rs`. The `receipt_card_id` locator is filled by the caller when the routing map knows the `swarm:receipt:v1` card id for `origin_receipt_id`, else stays `null` (the schema allows null).

- [ ] **Step 4: Run the three tests**

Run: `cargo test -p swarm-perch-bridge leases::`
Expected: 3 passed.

- [ ] **Step 5: Wire the poll into the bridge**

In `lib.rs::PerchBridge::run`, spawn a `tokio::time::interval(Duration::from_millis(LEASE_POLL_MS))` task (`MissedTickBehavior::Delay`) that on every tick calls `watcher.poll()`; for each `appeared` lease, resolve `case_channel = routing.case_for_receipt(lease.origin_receipt_id())` (a new `CaseRouting` method joining `receipt_id → hunt_id → case_channel`; an unresolvable receipt is `perch_bridge_lease_unrouted_total` + `warn!`, and the card is retried on the next tick rather than dropped — the receipt card usually lands a tick earlier), build the fact with `lease_card_body`, seal it with `signer.seal("perch-alarm", CardKind::Lease, heads, fact)`, append `Marker::Lease` on the evidence spool into the case channel, and record `lease_id → <Nostr event id at publish>` in `LeaseCardIndex` (persisted with the cursor). For each `disappeared` id do nothing but `debug!` — Task 9's event carries the receipt. On `watcher.store_absent()` set the gauge `perch_bridge_lease_store_absent = 1` at build time and skip the task. Register both metrics in `metrics.rs` (`bridge_lease_store_absent` as `Gauge<i64>`, `bridge_lease_cards_published` as `Counter` — no `_total` suffix at registration, `11` §11.1) and extend T-11's name list.

- [ ] **Step 6: Run the bridge suite**

Run: `cargo test -p swarm-perch-bridge`
Expected: all pass; T-11 sees the two new names exactly once each.

- [ ] **Step 7: Commit**

```bash
git add crates/swarm-perch-bridge/
git commit -s -m "feat(bridge): publish response receipts before containment lease cards"
```

---

### Task 9: Bridge — `swarm:rollback:v1` from `ContainmentReleased`, as a NIP-10 reply to the lease card

**Files:**
- Create: `crates/swarm-perch-bridge/src/rollback.rs`
- Modify: `crates/swarm-perch-bridge/src/cards.rs` (`Marker::Rollback` arm in the receive-side card assembly), `src/lib.rs` (`pub mod rollback;`), `src/metrics.rs` (`bridge_rollback_cards_published`, `bridge_rollback_unrouted`)
- Test: `crates/swarm-perch-bridge/src/rollback.rs` (`mod tests`)

**Interfaces:**
- Consumes: `RuntimeEvent::ContainmentReleased { … }` (Task 5); `LeaseCardIndex` (Task 8); `swarm_perch_wire::cards::{RollbackCard, RollbackLocator, ReleaseOutcome}`; the tag builders in `swarm_perch_wire::tags` (`h`, `e`, `t`, `l`, `k`); `SpineSigner::seal`.
- Produces: `rollback_card_body(event: &ContainmentReleasedFields, case_channel: Uuid, lease_card_id: &str) -> Value` (the `swarm.perch.rollback.v1` fact: `rollback_receipt` verbatim, `release_response` present only for `trigger == manual`, `partition_state_at_execution` carried through, `null` preserved as `null`); `rollback_tags(case_channel, lease_card_id, severity, threat_class_slug) -> Vec<Vec<String>>` with exactly one `e` tag naming the lease card; metrics `perch_bridge_rollback_cards_published_total{trigger}` and `perch_bridge_rollback_unrouted_total`.

- [ ] **Step 1: Write the failing body test**

Create `rollback.rs` with its tests:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn receipt(trigger: RollbackTrigger) -> RollbackReceipt {
        RollbackReceipt {
            rollback_id: "rb_81c4a588".into(),
            lease_id: "cl_9b3645fc".into(),
            origin_receipt_id: "resp:hunt-evt-1:lease:hunt-evt-1:isolate_host:1773738979300".into(),
            governance_receipt_id: None,
            trigger,
            mode: swarm_response::ExecutionMode::Enforced,
            status: swarm_response::ResponseStatus::Executed,
            steps: vec![swarm_response::rollback::RollbackStepOutcome {
                kind: swarm_core::types::ResponseRollbackStepKind::RestoreHostConnectivity,
                status: swarm_response::rollback::RollbackStepStatus::Reversed,
                detail: "host-ops-1 network interfaces re-enabled".into(),
            }],
            completed_at_ms: 1_773_739_879_950,
            summary: "1 of 1 steps reversed".into(),
            governance_attestation: None,
        }
    }

    #[test]
    fn a_manual_release_carries_the_release_response_and_an_expiry_does_not() {
        let case = uuid::Uuid::parse_str("27799e23-ab25-4659-b381-3de47ea7ca4d").unwrap();
        let manual = ContainmentReleasedFields {
            emitted_at_ms: 1_773_739_879_950,
            lease_id: "cl_9b3645fc".into(),
            trigger: RollbackTrigger::Manual,
            receipt: receipt(RollbackTrigger::Manual),
            lease_closed: false,
            attestation_verified: false,
            attestation_error: Some("no governance attestation is present".into()),
            partition_state_at_execution: Some(swarm_policy::governance::PartitionState::Healing),
        };
        let body = rollback_card_body(&manual, case, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        assert_eq!(body["schema"], "swarm.perch.rollback.v1");
        assert_eq!(body["release_response"]["lease_closed"], false);
        assert_eq!(body["release_response"]["attestation_verified"], false);
        assert_eq!(body["partition_state_at_execution"], "healing");
        assert_eq!(body["rollback_receipt"]["steps"][0]["status"], "reversed");
        assert_eq!(body["locator"]["lease_card_id"], "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        let expiry = ContainmentReleasedFields { trigger: RollbackTrigger::Expiry, receipt: receipt(RollbackTrigger::Expiry), partition_state_at_execution: None, ..manual };
        let body = rollback_card_body(&expiry, case, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        assert!(body.get("release_response").is_none(), "an expiry has no HTTP body to carry");
        assert_eq!(body["partition_state_at_execution"], serde_json::Value::Null, "null stays null; the console says it could not establish it");
    }

    #[test]
    fn the_rollback_card_replies_to_exactly_one_lease_card() {
        let case = uuid::Uuid::parse_str("27799e23-ab25-4659-b381-3de47ea7ca4d").unwrap();
        let tags = rollback_tags(case, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", swarm_core::types::Severity::Critical, "execution");
        let e_tags: Vec<_> = tags.iter().filter(|t| t[0] == "e").collect();
        assert_eq!(e_tags.len(), 1);
        assert_eq!(e_tags[0][1], "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        assert!(tags.iter().any(|t| t[0] == "h" && t[1] == case.to_string()));
        assert!(tags.iter().any(|t| t[0] == "k" && t[1] == "rollback"));
    }
}
```

- [ ] **Step 2: Run to see it fail**

Run: `cargo test -p swarm-perch-bridge rollback::`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the body, the tags and the arm**

Prepend to `rollback.rs`:

```rust
//! `swarm:rollback:v1` — the only card that can reach tier 1 today, published by
//! the bridge for BOTH release triggers now that B1c exists (`01-DESIGN.md` §4).
//! The operator key still publishes exactly one marker (W3-19).

use serde_json::{Value, json};
use swarm_core::types::Severity;
use swarm_policy::governance::PartitionState;
use swarm_response::rollback::{RollbackReceipt, RollbackTrigger};

/// The `ContainmentReleased` variant's fields, destructured once at the classify seam.
#[derive(Debug, Clone)]
pub struct ContainmentReleasedFields {
    pub emitted_at_ms: i64,
    pub lease_id: String,
    pub trigger: RollbackTrigger,
    pub receipt: RollbackReceipt,
    pub lease_closed: bool,
    pub attestation_verified: bool,
    pub attestation_error: Option<String>,
    pub partition_state_at_execution: Option<PartitionState>,
}

/// The `swarm.perch.rollback.v1` fact. `release_response` rides only on a manual
/// release: an expiry comes from the sweep with no HTTP request and therefore no
/// such body (`card-swarm-rollback-v1.schema.json`).
pub fn rollback_card_body(event: &ContainmentReleasedFields, case_channel: uuid::Uuid, lease_card_id: &str) -> Value {
    let mut fact = json!({
        "schema": "swarm.perch.rollback.v1",
        "issuer": { "swarm_agent_id": "containment-sweep", "role": Value::Null, "nostr_pubkey": Value::Null },
        "emitted_at_ms": event.emitted_at_ms,
        "locator": {
            "rollback_id": event.receipt.rollback_id,
            "lease_id": event.lease_id,
            "case_channel": case_channel.to_string(),
            "lease_card_id": lease_card_id,
        },
        "rollback_receipt": event.receipt,
        "partition_state_at_execution": event.partition_state_at_execution,
    });
    if event.trigger == RollbackTrigger::Manual {
        fact["release_response"] = json!({
            "lease_closed": event.lease_closed,
            "fully_reversed": event.receipt.fully_reversed(),
            "attestation_verified": event.attestation_verified,
            "attestation_error": event.attestation_error,
        });
    }
    fact
}

/// The closed tag budget for a rollback card: `h` (case), ONE `e` (the lease card,
/// NIP-10 reply), `t`, `l`, `k`. Never a `p`.
pub fn rollback_tags(case_channel: uuid::Uuid, lease_card_id: &str, severity: Severity, threat_class_slug: &str) -> Vec<Vec<String>> {
    vec![
        vec!["h".into(), case_channel.to_string()],
        vec!["e".into(), lease_card_id.to_string(), String::new(), "reply".into()],
        vec!["t".into(), threat_class_slug.to_string()],
        vec!["l".into(), serde_json::to_value(severity).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()],
        vec!["k".into(), "rollback".into()],
    ]
}
```

In the receive-side card assembly (`cards.rs`, the exhaustive match over evidence-stream events), add the `RuntimeEvent::ContainmentReleased { .. }` arm: destructure into `ContainmentReleasedFields`, look up `case_channel` and `lease_card_id` through `LeaseCardIndex` (Task 8) keyed on `lease_id` — if either is missing, increment `perch_bridge_rollback_unrouted_total`, log at `error` naming the lease id, and spool the card **without** an `e` tag into the case channel when only the card id is missing, or hold it in the spool's retry slot when the case is unknown (a rollback for a lease the bridge never announced is F20's shape: visible, never silent). Seal with `signer.seal("perch-alarm", CardKind::Rollback, heads, fact)`; count `perch_bridge_rollback_cards_published_total{trigger}`. Register both metrics; extend T-11.

- [ ] **Step 4: Run the bridge suite**

Run: `cargo test -p swarm-perch-bridge`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/swarm-perch-bridge/
git commit -s -m "feat(bridge): swarm:rollback:v1 from ContainmentReleased, replying to the lease card"
```

---

#### Tasks 8 and 9 status — 2026-09-04

**Task 8's read half landed**: `LeaseWatcher` reports transitions rather than state, distinguishes
"no store" from "an empty store", and leaves its view untouched when a read fails so a transient
error does not report every lease as disappeared. `lease_card_body` reads no clock.

**Task 9's card landed**: `rollback_card_body` and `rollback_tags`, with `release_response` riding
only on a manual release — an expiry comes from the sweep with no request behind it, and a card
that invented one would describe a request nobody made. `fully_reversed` is passed through
rather than recomputed, so "we undid it" and "we went through the motions" stay distinguishable.

**Not landed, and both blocked on the same missing piece:** the receive-side arms that PUBLISH
these cards. Task 8 step 0 requires a `receipt_id → hunt_id` map recorded on acknowledgement and
`CaseRouting::case_for_receipt`, and Task 9's arm needs a `LeaseCardIndex` keyed on `lease_id` to
supply the `e` tag's parent. Both are routing state that has to be written on ACK for the same
reason the chain head is (Task 7): a card the relay did not take must not leave a route behind
pointing at it. The card bodies above are complete and tested; wiring them is the routing work.

## Task 10: Containments — `/leases`

**Files:**
- Create: `workspace/desktop/src/shared/ui/perch/ContainmentTimer.tsx`, `containmentTimer.test.mjs`
- Create: `workspace/desktop/src/shared/ui/perch/RollbackStepList.tsx`
- Create: `workspace/desktop/src/features/perch-containment/lib/containmentState.ts`, `containmentState.test.mjs`
- Create: `workspace/desktop/src/features/perch-containment/lib/copy.ts`
- Create: `workspace/desktop/src/features/perch-containment/hooks.ts`, `useLeaseClock.ts`
- Create: `workspace/desktop/src/features/perch-containment/ui/ContainmentRow.tsx`, `ContainmentBoard.tsx`, `ContainmentReleaseDialog.tsx`, `PartitionSection.tsx`
- Create: `workspace/desktop/src/features/perch-evidence/ui/LeaseCard.tsx`, `RollbackCard.tsx` (skip the create if The hold landed them; keep the steps that add `maxTier` and the decision badge)
- Create or replace: `workspace/desktop/src/app/routes/leases.tsx`
- Create: `workspace/desktop/tests/e2e/perch-containment.spec.ts` (from `build/skeleton/tests/playwright/`, renamed per D1)
- Modify: `workspace/desktop/playwright.config.ts` (`smoke` `testMatch`), `workspace/desktop/src/features/perch-evidence/lib/swarmCardRegistry.tsx` (two entries), `workspace/desktop/src/shared/api/perchKeys.ts` (no new key: `containments` exists)

**Interfaces:**
- Consumes: `perchListContainments() -> Promise<PerchContainmentView[]>` and `perchReleaseContainment(leaseId) -> Promise<PerchReleaseOutcome>` (`tauriPerch.ts`); `perchKeys.containments()` with `PERCH_FRESHNESS.containments` (`staleTime: 2_500`, `poll: 5_000`); `PERCH_NO_RETRY`; `ProvenanceRows`, `AdversaryString`, `EmptyState`, `EyebrowLabel`, `usePerchKeymap`, `PerchSurfaceBoundary`; `getPerchEphemeralSnapshot().governance` (the 26004 frame — `partition_state`, `active_contingency_leases`, `unauthorized_partition_actions`, `last_reconciliation_report_id`); the wire `LeaseCard`/`RollbackCard` zod decoders; the copy constants `CONTAINMENT`, `ROLLBACK_STATUS`, `ROLLBACK_SUMMARY` (`06` §5.6, transcribed below).
- Produces: `deriveContainmentState(facts: ContainmentFacts): ContainmentState` where `ContainmentFacts = { remainingMs: number; expired: boolean; daemonReachable: boolean }` and `ContainmentState = "open" | "expiring" | "expired-still-listed" | "daemon-down-open" | "daemon-down-expired"`; `useLeaseClock(): number` (one board-level `nowMillis`, 1 Hz); `ContainmentBoard` (S6) with `data-testid="perch-containment-board"`; the registry entries `lease: { presenter: LeaseCard, maxTier: 0 }` and `rollback: { presenter: RollbackCard, maxTier: 1 }`.

- [ ] **Step 1: Write the failing state-derivation test**

Create `workspace/desktop/src/features/perch-containment/lib/containmentState.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { deriveContainmentState, EXPIRING_UNDER_MS } from "./containmentState.ts";

test("remaining_ms and expired are two facts: 0/false and 0/true differ", () => {
  assert.equal(deriveContainmentState({ remainingMs: 0, expired: false, daemonReachable: true }), "expiring");
  assert.equal(deriveContainmentState({ remainingMs: 0, expired: true, daemonReachable: true }), "expired-still-listed");
});

test("expiring is strictly under fifteen seconds", () => {
  assert.equal(EXPIRING_UNDER_MS, 15_000);
  assert.equal(deriveContainmentState({ remainingMs: 15_000, expired: false, daemonReachable: true }), "open");
  assert.equal(deriveContainmentState({ remainingMs: 14_999, expired: false, daemonReachable: true }), "expiring");
});

test("daemon down splits by the same fact", () => {
  assert.equal(deriveContainmentState({ remainingMs: 40_000, expired: false, daemonReachable: false }), "daemon-down-open");
  assert.equal(deriveContainmentState({ remainingMs: 0, expired: true, daemonReachable: false }), "daemon-down-expired");
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-containment/lib/containmentState.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement the derivation and the copy**

Create `workspace/desktop/src/features/perch-containment/lib/containmentState.ts`:

```ts
/**
 * The five states of a containment row. `remaining_ms` SATURATES AT ZERO
 * (crates/swarm-response/src/containment.rs:276), so it alone cannot tell
 * "expires in an instant" from "expired an hour ago and the sweep failed";
 * `expired` is the field that answers that (http/containment.rs:78-87). A
 * caller passes the named struct so it cannot pass one fact and lose the other.
 */
export type ContainmentFacts = {
  remainingMs: number;
  expired: boolean;
  daemonReachable: boolean;
};

export type ContainmentState =
  | "open"
  | "expiring"
  | "expired-still-listed"
  | "daemon-down-open"
  | "daemon-down-expired";

/** 18-DATAVIZ.md §8.2: `expiring` is `remaining_ms < 15_000`. */
export const EXPIRING_UNDER_MS = 15_000;

export function deriveContainmentState(facts: ContainmentFacts): ContainmentState {
  if (!facts.daemonReachable) {
    return facts.expired ? "daemon-down-expired" : "daemon-down-open";
  }
  if (facts.expired) return "expired-still-listed";
  return facts.remainingMs < EXPIRING_UNDER_MS ? "expiring" : "open";
}

/** `remaining_ms` recomputed from the daemon's `expires_at_ms` and the board clock — never from a config constant. */
export function remainingMsAt(expiresAtMs: number, nowMs: number): number {
  return Math.max(0, expiresAtMs - nowMs);
}
```

Create `workspace/desktop/src/features/perch-containment/lib/copy.ts` (every string passes the ban list; "containment lease" is always spelled out):

```ts
export const CONTAINMENT = {
  open: "Open · {remaining} remaining",
  expiringSoon: "Open · {remaining} remaining · releases automatically",
  expired: "EXPIRED — {host} may still be contained",
  expiredBody:
    "This containment lease passed its expiry {ago} ago and is still listed as open. remaining_ms saturates at zero, so “0s” and “expired” are two separate facts and this is the second one. The sweep tried and failed. Nothing will release {host} without you.",
  attemptsUnknown: "last attempt: — (the runtime does not report attempt counts)",
  releaseConfirmTitle: "Release containment on {host}?",
  releaseConfirmBody:
    "The daemon runs {inverseKind} against {target} and co-signs the release on the governance chain. If the inverse fails, the containment lease stays open and the response reports lease_closed: false.",
  releaseConfirmCta: "Ask the daemon to release",
  releasedClosed: "Released. lease_closed: true · fully_reversed: {fullyReversed}",
  releasedNotClosed:
    "NOT RELEASED. The daemon returned 200 but lease_closed: false — the inverse failed and the containment is still in effect. The next sweep will retry.",
  releasedUnattested:
    "Released, UNATTESTED. No governor was available to co-sign. The release proceeded because refusing to undo a containment over a bookkeeping failure inverts the safety argument. The receipt says so plainly.",
  daemonDownOpen:
    "Early release needs the running daemon. The TTL is the only backstop; this containment lease self-releases at {expiresAt}.",
  daemonDownExpired:
    "Early release needs the running daemon. The TTL has already passed and the sweep already failed. This will not clear on its own.",
  extendDisabled:
    "A containment lease cannot be extended. Request the action again to open a new containment lease with its own receipt.",
  noStore: {
    title: "No containment lease store is configured",
    body:
      "runtime.containment.lease_store_path is unset. A granted quarantine_file, suspend_process, isolate_host or terminate_user_session is refused at the decide route; the other eight destructive actions are unaffected.",
  },
  none: {
    title: "No open containments",
    body:
      "Nothing is currently isolated, quarantined or suspended. {n} destructive actions ran in this window without a hold. Expired containment leases are released by the sweep and appear in the Ledger.",
    action: { label: "Search released containments", href: "/ledger?q=swarm:lease" },
  },
} as const;

export const ROLLBACK_STATUS = {
  reversed: { label: "Reversed", body: "The inverse ran against the real target and succeeded." },
  simulated: { label: "Simulated", body: "The inverse was rehearsed. No real target was touched, so nothing was restored." },
  irreversible: { label: "Irreversible", body: "No inverse exists for this step. The world was not restored and no adapter can restore it." },
  unsupported: { label: "Unsupported", body: "The configured adapter cannot execute this inverse." },
  failed: { label: "Failed", body: "The inverse was attempted against a real target and failed." },
} as const;

export const ROLLBACK_SUMMARY = {
  fullyReversed: "Fully reversed — every step reported Reversed.",
  notFullyReversed:
    "Not fully reversed. {n} of {total} steps: {breakdown}. fully_reversed() requires every step to be Reversed; Simulated and Irreversible do not count.",
} as const;
```

- [ ] **Step 4: Run the derivation test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-containment/lib/containmentState.test.mjs`
Expected: 3 passed.

- [ ] **Step 5: Write the failing timer test**

Create `workspace/desktop/src/shared/ui/perch/containmentTimer.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ContainmentTimer } from "./ContainmentTimer.tsx";

test("two facts render as two elements, and zero/expired differ from zero/open", () => {
  const open = renderToStaticMarkup(React.createElement(ContainmentTimer, { remainingMs: 0, expired: false, expiresAtMs: 1_773_739_879_900, daemonReachable: true }));
  const expired = renderToStaticMarkup(React.createElement(ContainmentTimer, { remainingMs: 0, expired: true, expiresAtMs: 1_773_739_879_900, daemonReachable: true }));
  assert.notEqual(open, expired);
  for (const html of [open, expired]) {
    assert.match(html, /data-testid="perch-containment-remaining"/);
    assert.match(html, /data-testid="perch-containment-expired"/);
    assert.doesNotMatch(html, /<progress/);
  }
  assert.match(expired, /role="alert"/);
  assert.doesNotMatch(open, /role="alert"/);
});

test("the remaining figure is text-sm tabular and never a bar", () => {
  const html = renderToStaticMarkup(React.createElement(ContainmentTimer, { remainingMs: 41_000, expired: false, expiresAtMs: 1_773_739_879_900, daemonReachable: true }));
  assert.match(html, /text-sm[^"]*tabular-nums|tabular-nums[^"]*text-sm/);
  assert.match(html, /00:41/);
});
```

- [ ] **Step 6: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/shared/ui/perch/containmentTimer.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 7: Implement `ContainmentTimer` and `RollbackStepList`**

Create `workspace/desktop/src/shared/ui/perch/ContainmentTimer.tsx`:

```tsx
import * as React from "react";

import { deriveContainmentState } from "@/features/perch-containment/lib/containmentState";
import { cn } from "@/shared/lib/cn";

export type ContainmentTimerProps = {
  /** Saturates at zero by construction — swarm-response/src/containment.rs:276. */
  remainingMs: number;
  /** A SEPARATE fact. True on a still-listed lease means the sweep tried and failed. */
  expired: boolean;
  /** For the "self-releases at" sentence. A wall clock, not a delta. */
  expiresAtMs: number;
  daemonReachable: boolean;
  className?: string;
};

function mmss(ms: number): string {
  const total = Math.floor(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

/** Two facts, two DOM elements, never one bar (INV-06). */
export function ContainmentTimer({ remainingMs, expired, expiresAtMs, daemonReachable, className }: ContainmentTimerProps) {
  const state = deriveContainmentState({ remainingMs, expired, daemonReachable });
  const wall = new Date(expiresAtMs).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const expiredWord =
    state === "expired-still-listed" || state === "daemon-down-expired"
      ? "EXPIRED, HOST STILL CONTAINED · the sweep tried and failed"
      : state === "expiring"
        ? "EXPIRING"
        : "OPEN";
  return (
    <div className={cn("flex flex-col gap-0.5", className)} data-perch-containment-state={state}>
      <span
        data-testid="perch-containment-remaining"
        aria-live="off"
        aria-label={`${mmss(remainingMs)} remaining, self-releases at ${wall}`}
        className={cn("text-sm tabular-nums text-perch-fg", state === "expiring" && "text-perch-sev-high")}
      >
        {mmss(remainingMs)}
      </span>
      {expired ? (
        <span data-testid="perch-containment-expired" role="alert" className="text-sm font-medium text-perch-fg">
          <span aria-hidden="true" className="mr-1 inline-block h-2 w-2 rounded-full bg-perch-danger-mark" />
          {expiredWord}
        </span>
      ) : (
        <span data-testid="perch-containment-expired" className="text-xs text-perch-fg-muted">
          {expiredWord} · self-releases at {wall}
        </span>
      )}
    </div>
  );
}
```

`text-perch-fg`, `text-perch-fg-muted`, `text-perch-sev-high`, `bg-perch-danger-mark` are the Tailwind utilities Ground's `perch.css` + `tailwind.config.js` extension expose over `--perch-foreground`, `--perch-foreground-muted`, `--perch-sev-high`, `--perch-danger-mark`. The danger hue is a mark only; the word carries the meaning (`19-TOKENS` "NEVER TEXT").

Create `workspace/desktop/src/shared/ui/perch/RollbackStepList.tsx`:

```tsx
import * as React from "react";

import { ROLLBACK_STATUS, ROLLBACK_SUMMARY } from "@/features/perch-containment/lib/copy";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";

/** Exactly five. crates/swarm-response/src/rollback.rs:211-223. `restored()` is true only for Reversed. */
export type RollbackStepStatus = "reversed" | "simulated" | "irreversible" | "unsupported" | "failed";

export type RollbackStepListProps = {
  steps: readonly { label: string; status: RollbackStepStatus; reason?: string }[];
  /** From ContainmentReleaseResponse's BODY, never the HTTP status. */
  fullyReversed: boolean;
};

/** A read-only outcome list. No Undo lives here (INV-03); the release control is ContainmentRow's. */
export function RollbackStepList({ steps, fullyReversed }: RollbackStepListProps) {
  const breakdown = Object.entries(
    steps.reduce<Record<string, number>>((acc, step) => ({ ...acc, [step.status]: (acc[step.status] ?? 0) + 1 }), {}),
  )
    .map(([status, n]) => `${n} ${ROLLBACK_STATUS[status as RollbackStepStatus].label}`)
    .join(", ");
  const reversed = steps.filter((s) => s.status === "reversed").length;
  return (
    <div className="flex flex-col gap-1">
      <ol className="flex flex-col gap-1">
        {steps.map((step, index) => (
          <li key={`${step.label}-${index}`} data-testid={`perch-rollback-step-${index}`} className="flex items-baseline gap-2 text-sm">
            <span className="font-medium text-perch-fg">{ROLLBACK_STATUS[step.status].label}</span>
            <span className="font-mono text-xs text-perch-fg-secondary">{step.label}</span>
            {step.reason ? <AdversaryString value={step.reason} className="text-xs" /> : null}
          </li>
        ))}
      </ol>
      <p data-testid="perch-rollback-fully-reversed" className="text-xs text-perch-fg-muted">
        {fullyReversed
          ? ROLLBACK_SUMMARY.fullyReversed
          : ROLLBACK_SUMMARY.notFullyReversed
              .replace("{n}", String(reversed))
              .replace("{total}", String(steps.length))
              .replace("{breakdown}", breakdown)}
      </p>
    </div>
  );
}
```

- [ ] **Step 8: Run the timer test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/shared/ui/perch/containmentTimer.test.mjs`
Expected: 2 passed.

- [ ] **Step 9: Commit the primitives**

```bash
git add workspace/desktop/src/shared/ui/perch/ContainmentTimer.tsx workspace/desktop/src/shared/ui/perch/containmentTimer.test.mjs workspace/desktop/src/shared/ui/perch/RollbackStepList.tsx workspace/desktop/src/features/perch-containment/lib/
git commit -s -m "feat(desktop): ContainmentTimer and RollbackStepList — two facts, five words"
```

- [ ] **Step 10: Write the failing Playwright spec**

Copy `docs/plans/ambush-ui/build/skeleton/tests/playwright/perch-containment.spec.ts` to `workspace/desktop/tests/e2e/perch-containment.spec.ts`, rename `emitAmbushCard` → `emitSwarmCard` and every `ambush:` marker to `swarm:`, and add `"**/perch-containment.spec.ts"` to the `smoke` project's `testMatch` in `workspace/desktop/playwright.config.ts`. The five tests (`01` two elements / `02` lease_closed:false in the error register / `03` five distinct rollback words / `04` no extend affordance / `05` snooze disabled on a hold row) drive `installPerchBridge(page, perchFixture({ containments: [...] }))`, navigate to `#/leases`, and assert on `perch-containment-remaining`, `perch-containment-expired`, `perch-containment-release-outcome`, `perch-rollback-step-*`, `[data-perch-role="containment-extend-disabled"]`.

Run: `cd workspace/desktop && pnpm test:e2e:smoke -- --grep "Perch containments"`
Expected: 5 failed — the route renders nothing yet.

- [ ] **Step 11: Implement the board, the row, the dialog, the partition section, the hooks, the route**

`workspace/desktop/src/features/perch-containment/hooks.ts`:

```ts
import { useQuery } from "@tanstack/react-query";

import { perchListContainments, type PerchContainmentView } from "@/shared/api/tauriPerch";
import { PERCH_FRESHNESS, PERCH_NO_RETRY, perchKeys } from "@/shared/api/perchKeys";
import { useRelayConnection } from "@/shared/api/useRelayConnection";
import { useDaemonReachability } from "@/features/perch/useDaemonReachability";

export function useContainmentsQuery() {
  const daemon = useDaemonReachability();
  return useQuery<PerchContainmentView[]>({
    queryKey: perchKeys.containments(),
    queryFn: perchListContainments,
    staleTime: PERCH_FRESHNESS.containments.staleTime,
    refetchInterval: daemon.reachable ? PERCH_FRESHNESS.containments.poll : false,
    ...PERCH_NO_RETRY,
  });
}
```

(`useDaemonReachability` is The hold's hook behind the verdict pane's "daemon unreachable" state; if it landed as `useDaemonStatus`, use that name. `useRelayConnection` is imported only if the hook gates on both; the containment poll gates on the daemon.)

`useLeaseClock.ts`:

```ts
import * as React from "react";

/** One board-level clock. Rows derive from the scalar; nobody runs a per-row interval (18 §8.6). */
export function useLeaseClock(): number {
  const [nowMs, setNowMs] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);
  return nowMs;
}
```

`ContainmentRow.tsx` composes `ContainmentTimer` (remaining recomputed via `remainingMsAt(expires_at_ms, nowMs)` from the daemon's `expires_at_ms` and `expired` from the daemon's field), a `ProvenanceRows` block with `swarmRecord: { state: "no-signature-of-its-own", onVerify }` (a containment lease carries no signature), the action kind in mono with `<AdversaryString>` around `scope_value`, the release chip (`data-perch-role="containment-release"`, `data-testid="perch-containment-release"`, an **outlined** chip reading `Release — requires Maintenance scope`, disabled with `CONTAINMENT.daemonDownOpen`/`daemonDownExpired` when the daemon is unreachable), and a row menu whose one disabled item carries `data-perch-role="containment-extend-disabled"` and the `extendDisabled` sentence. The row's `IF YOU UNDO` cell names the rung: `TerminateUserSession → irreversible`, the other three `→ executable inverse` (12 destructive → 4 leased → 3 reversible).

`ContainmentReleaseDialog.tsx` is a Radix `AlertDialog` whose action has `variant="outline"` (required prop after `17` §8), copy from `CONTAINMENT.releaseConfirm*`, and on confirm calls `perchReleaseContainment(leaseId)` through a `usePerchWrite` machine (`sending → settled`); the settled branch renders `releasedClosed` when `lease_closed`, `releasedNotClosed` in the error register (`data-perch-register="error"`, `role="alert"`) when `lease_closed === false` **regardless of status**, `releasedUnattested` when `attestation_verified === false && attestation_error` mentions "unattested"; then `RollbackStepList` from `outcome.steps` and `fullyReversed`, and invalidates `perchKeys.containments()`.

`PartitionSection.tsx` renders only while the 26004 frame's `partition_state !== "healthy"`: `HEALING — governance is reconciling partition-era activity`, `contingency leases redeemed during the partition  {active_contingency_leases}` with the note `these carry no governance receipt by design (dispatcher.rs:575) — UNATTESTED here is expected, not a fault`, `unauthorized partition actions recorded  {unauthorized_partition_actions}` in the destructive register with no rounding, and `reconciliation report  {last_reconciliation_report_id}` (`08` §4.4).

`ContainmentBoard.tsx` (S6): H1 `Containments`; the table sorted **as served** (never re-sorted — `expires_at_ms` then `lease_id` is the daemon's order); states: `loading` (`LOADING.deposits`-style skeleton rows), `no-containment-lease-store-configured` (an `EmptyState kind="governing-number"` with `CONTAINMENT.noStore` and `governingNumber: { label: "runtime.containment.lease_store_path", value: "unset", source: "crates/swarm-core/src/config/runtime.rs:81-87" }` — detected from `perch_bridge_lease_store_absent` in the governance strip's diagnostics or from the daemon's `503` on the list route), `empty` (`CONTAINMENT.none`, `governing-number`, no `/gaps` link), `populated`, `daemon-unreachable` (rows readable, releases disabled), plus `PartitionSection`. `useLeaseClock` feeds every row one `nowMs`. `usePerchKeymap` binds `J`/`K`/`Enter` on the list; no verdict verbs on this surface.

`app/routes/leases.tsx`:

```tsx
import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";

import { PerchSurfaceBoundary } from "@/features/perch/ui/PerchSurfaceBoundary";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const LazyContainmentBoard = React.lazy(() =>
  import("@/features/perch-containment/ui/ContainmentBoard").then((m) => ({ default: m.ContainmentBoard })),
);

export const Route = createFileRoute("/leases")({
  component: () => (
    <React.Suspense fallback={<ViewLoadingFallback kind="leases" />}>
      <PerchSurfaceBoundary surface="Containments" resetKey="/leases">
        <LazyContainmentBoard />
      </PerchSurfaceBoundary>
    </React.Suspense>
  ),
});
```

Regenerate `routeTree.gen.ts` (`pnpm vite build --mode e2e` or any vite command) and commit it.

- [ ] **Step 12: The two presenters and the registry entries**

`features/perch-evidence/ui/LeaseCard.tsx` renders the `swarm.perch.lease.v1` fact inside `EvidenceCardFrame`: action kind, `scope_value` through `AdversaryString`, `issued_at_ms`/`expires_at_ms` as wall clocks, a `ContainmentTimer` fed by the board clock, `ttl_source` rendered as `TTL from runtime.containment.lease_ttl_ms`, and `ProvenanceRows` at tier 0 with the human line `containment lease {lease_id} · {action_kind} · issued {ISO} · expires {ISO} · origin receipt {receipt_id}`. `RollbackCard.tsx` renders the `swarm.perch.rollback.v1` fact: `RollbackStepList` from `rollback_receipt.steps`, the trigger word (`manual` / `expiry`), `release_response` when present (`lease_closed:false` in the error register), and the attestation badge — `data-testid={`perch-attestation-badge-rollback-${state}`}` — computed by:

```ts
export function rollbackBadge(fact: RollbackFact): { text: string; tier: 0 | 1; decision: "approve" | "veto" | null; limit: string | null } {
  const attestation = fact.rollback_receipt.governance_attestation ?? null;
  const verified = fact.release_response?.attestation_verified ?? false;
  if (attestation && verified) {
    return {
      text: "Ed25519 · tier 1 · attestation matches this body",
      tier: 1,
      decision: attestation.payload?.decision === "veto" ? "veto" : "approve",
      limit: "no trust anchor: this does not prove a governor you trust authorized it, and no chain linkage was checked (ADR 0010:125-131, :140-144)",
    };
  }
  if (attestation && !verified) {
    return { text: `ATTESTATION MISMATCH · ${fact.release_response?.attestation_error ?? "unverified"}`, tier: 0, decision: null, limit: null };
  }
  const p = fact.partition_state_at_execution;
  if (p === null) return { text: "UNATTESTED · the console could not establish the partition state", tier: 0, decision: null, limit: null };
  if (p === "partitioned" || p === "healing") {
    return { text: "UNATTESTED — BY DESIGN", tier: 0, decision: null, limit: "redeemed under a contingency lease during a partition. No governance receipt is required or expected on this path (dispatcher.rs:575)." };
  }
  return { text: "UNATTESTED", tier: 0, decision: null, limit: "no governance authority was wired, or none could sign" };
}
```

rendered as three elements: the badge text, `decision {approve|veto}` beside it when tier 1 (never omitted — a Veto receipt verifies too, ADR 0016 C6a), and the limit sentence. The word `approve` here is the receipt's own enum value rendered in lowercase mono inside `<code>` — the copy gate's `approve` row is case-insensitive with no identifier exemption (W3-22), so render the decision as the literal wire value through `<AdversaryString value={decision} />`, which the gate does not scan (it is data, INV-14's domain), and never as an authored literal. Add to `swarmCardRegistry.tsx`: `lease: { presenter: LeaseCard, maxTier: 0 }`, `rollback: { presenter: RollbackCard, maxTier: 1 }`. Re-run the un-skipped provenance `03`.

- [ ] **Step 13: Run the specs and the gates**

Run: `cd workspace/desktop && pnpm typecheck && pnpm check && pnpm test:e2e:smoke -- --grep "Perch containments|Perch provenance"`
Expected: containment `01`–`05` pass; provenance `03` passes; `pnpm check` (biome, px-text, pubkey-truncation, csp-pin, copy-bans) clean. Then from the root: `bash tools/check-perch-grant-affordance.sh` — R5 finds exactly one `containment-extend-disabled` and no other `extend` under the containment root; `bash tools/check-copy-banned-terms.sh` clean over the new files.

- [ ] **Step 14: Commit**

```bash
git add workspace/desktop/src/features/perch-containment/ workspace/desktop/src/features/perch-evidence/ui/LeaseCard.tsx workspace/desktop/src/features/perch-evidence/ui/RollbackCard.tsx workspace/desktop/src/features/perch-evidence/lib/swarmCardRegistry.tsx workspace/desktop/src/app/routes/leases.tsx workspace/desktop/src/app/routeTree.gen.ts workspace/desktop/tests/e2e/perch-containment.spec.ts workspace/desktop/playwright.config.ts
git commit -s -m "feat(desktop): Containments board — remaining_ms and expired as two facts, release read from the body"
```

---

### Task 11: Lanes — `/lanes/$laneId`

**Files:**
- Create: `crates/swarm-perch-bridge/src/lanes.rs` (topic write on an `EscalationLevel` edge), `src/coalesce.rs` (implemented escalation edge/heartbeat reducer; no future telemetry stubs)
- Modify: `crates/swarm-perch-bridge/src/cards.rs`, `src/receive.rs`, `src/pacer.rs`, `src/lib.rs`, `src/metrics.rs` (`bridge_escalation_cards_published`, `bridge_coalesced`, `bridge_lane_topic_writes`), `src/config.rs` / `crates/swarm-core/src/config/perch.rs` (`lane_topic_on_crossing: bool`, default `true`)
- Create: `workspace/desktop/src/features/perch-evidence/lib/laneLiveNumbers.ts`, `laneLiveNumbers.test.mjs`
- Create: `workspace/desktop/src/features/perch-evidence/lib/laneCopy.ts`
- Create: `workspace/desktop/src/features/perch-evidence/ui/LaneScreen.tsx`, `LaneHeader.tsx`
- Create: `workspace/desktop/src/features/sidebar/ui/AppSidebarPerchSection.tsx`; modify `AppSidebar.tsx` (+3 lines: import, feature gate, mount — the file is at 952 gate-lines, 48 of headroom)
- Create or replace: `workspace/desktop/src/app/routes/lanes.$laneId.tsx`
- Create: `workspace/desktop/tests/e2e/perch-lanes.spec.ts`; modify `playwright.config.ts`
- Test: `crates/swarm-perch-bridge/src/lanes.rs` (`mod tests`), the two `.test.mjs`

**Interfaces:**
- Consumes: `RuntimeEvent::Escalation { threat_class, level, total_strength, distinct_sources, peak_confidence, mode_changed, current_mode, .. }`; `PerchBridgeConfig.lane_channels: BTreeMap<ThreatClass, Uuid>`; the relay's `kind:9002` topic edit (`set_topic`, `workspace/crates/ambush-relay/src/handlers/side_effects.rs`; any member may set a topic) published by the `perch-alarm` identity, which holds `ChannelsWrite`; `getPerchEphemeralSnapshot().concentrations: Map<threatClassSlug, PerchConcentration>` and `perchTelemetryAgeMs(snapshot)` (`perchEphemeralStore.ts`); `perchDeposits(threatClass)` (Task 4's typed response) with `perchKeys.deposits(threatClass)`; `SourceCount` (both arms, `17` §4.8); `ThreatClassLabel`; `EmptyState`; `ChannelPane` wrapped, never edited; the `case-live`-shaped REQ for a lane (`perchSubscriptions.ts` `lane-movement` for the sidebar, `case-live` on the open lane); `useChannelMuteState` (`features/channels`) for INV-21.
- Produces: `EscalationReducer::offer(&RuntimeEvent, now_ms) -> EscalationDisposition` and `escalation_card(...) -> CardBody`, so the durable `swarm:escalation:v1` event lands in the configured threat-class channel on a level edge or bounded heartbeat; `LaneTopicEdge::observe(&mut self, threat_class: &ThreatClass, level: Option<EscalationLevel>) -> Option<TopicWrite>` (an edge detector: emits once per level change, never per tick); `laneLiveNumbers(snapshot, slug, policy) -> LaneLiveNumbers | null` where `LaneLiveNumbers = { totalStrength, distinctSources, peakConfidence, alertThreshold, incidentThreshold, ageMs, aboveAlert: boolean }`; `LaneScreen` (S5) at `data-testid="perch-lane-screen"`; `AppSidebarPerchSection` rendering the twelve lane rows with `data-testid={`perch-lane-row-${slug}`}`, the live dot when `aboveAlert`, `data-perch-muted="true"` on first run, the case rows with the TTL glyph, and the four nav items `Containments · Policy · Tuning · Gaps`.

- [ ] **Step 0: Land the escalation-card producer (W3-29).** Start `coalesce.rs` with only the implemented `EscalationReducer`: first level, a level change, and a heartbeat at `perch.escalation_heartbeat_ms` publish; identical intervening samples increment `perch_bridge_coalesced_total{stream="evidence"}` and do not enter the disk spool. `RuntimeEvent::Escalation` becomes a `swarm:escalation:v1` card in that class's configured channel, carrying the served strength/source/confidence numbers and current mode. Tests prove 600 identical observations produce one initial card plus bounded heartbeats, Alert→Incident produces exactly one edge card, `Custom` without a configured channel is counted/unrouted rather than folded into a standard class, and a live relay query returns the card by its exact event id. Only then proceed to the topic edge and UI.

- [ ] **Step 1: Write the failing edge test**

Create `crates/swarm-perch-bridge/src/lanes.rs` with its tests:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::pheromone::ThreatClass;
    use swarm_runtime::runtime_events::EscalationLevel;

    #[test]
    fn a_level_change_writes_once_and_a_repeat_writes_nothing() {
        let mut edge = LaneTopicEdge::default();
        assert!(edge.observe(&ThreatClass::LateralMovement, Some(EscalationLevel::Alert)).is_some());
        for _ in 0..600 {
            assert!(edge.observe(&ThreatClass::LateralMovement, Some(EscalationLevel::Alert)).is_none(), "600 identical ticks are one edge");
        }
        let incident = edge.observe(&ThreatClass::LateralMovement, Some(EscalationLevel::Incident)).unwrap();
        assert_eq!(incident.topic, "lateral_movement · INCIDENT · escalated");
        let cleared = edge.observe(&ThreatClass::LateralMovement, None).unwrap();
        assert_eq!(cleared.topic, "lateral_movement · below alert_threshold");
        assert!(edge.observe(&ThreatClass::DataExfiltration, None).is_none(), "a class that never escalated has no edge to clear");
    }
}
```

- [ ] **Step 2: Run to see it fail**

Run: `cargo test -p swarm-perch-bridge lanes::`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the edge detector and wire it**

Prepend to `lanes.rs`:

```rust
//! Lane topic writes, edge-triggered. `04` §2.5 deleted the 1 Hz topic rewrite:
//! a topic write is a durable relay-signed `kind:9002` plus a `kind:40099` row,
//! and twelve lanes at 1 Hz is 6x one identity's write quota. The topic changes
//! only when `EscalationLevel` changes, which `deescalation_cooldown_secs` bounds.

use std::collections::BTreeMap;

use swarm_core::pheromone::ThreatClass;
use swarm_runtime::runtime_events::EscalationLevel;

/// One topic write the pacer will publish as a `kind:9002` edit on the lane channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicWrite {
    pub threat_class: ThreatClass,
    pub topic: String,
}

/// Per-class last level. `None` is "below alert_threshold".
#[derive(Debug, Default)]
pub struct LaneTopicEdge {
    last: BTreeMap<String, Option<EscalationLevel>>,
}

impl LaneTopicEdge {
    /// Observe the level the escalation stream reports for a class (`None` when a
    /// snapshot shows the class below `alert_threshold`). Returns a write only on a
    /// change, and never for a class that has never been above threshold.
    pub fn observe(&mut self, threat_class: &ThreatClass, level: Option<EscalationLevel>) -> Option<TopicWrite> {
        let slug = threat_class.slug().to_string();
        let previous = self.last.get(&slug).copied().flatten();
        if !self.last.contains_key(&slug) && level.is_none() {
            return None;
        }
        if previous == level {
            return None;
        }
        self.last.insert(slug.clone(), level);
        let topic = match level {
            Some(EscalationLevel::Alert) => format!("{slug} · ALERT · escalated"),
            Some(EscalationLevel::Incident) => format!("{slug} · INCIDENT · escalated"),
            None => format!("{slug} · below alert_threshold"),
        };
        Some(TopicWrite { threat_class: threat_class.clone(), topic })
    }
}
```

(`ThreatClass::slug()` is the snake_case wire name; if the core type exposes it under another name — `as_str` — use that.) In the receive loop's `Escalation` arm, after classification, feed `edge.observe(&threat_class, Some(level))` and, on every `ConcentrationSnapshot`, feed `None` for each class whose `total_strength < alert_threshold`; a returned `TopicWrite` becomes a `PublishStep::SetLaneTopic { channel: lane_channels[&class], topic }` on the **alarm** identity's evidence spool (a topic edit is a `kind:9002` with `h` = the lane and a `topic` tag; the relay emits the `kind:40099` audit row itself). Gate the whole thing on `config.lane_topic_on_crossing` (default `true`). Count `perch_bridge_lane_topic_writes_total{threat_class}`.

- [ ] **Step 4: Run the bridge tests**

Run: `cargo test -p swarm-perch-bridge lanes:: && cargo test -p swarm-perch-bridge escalation_edge_triggers`
Expected: pass; T-5 still shows 600 identical escalations → 2 frames.

- [ ] **Step 5: Commit the bridge half**

```bash
git add crates/swarm-perch-bridge/ crates/swarm-core/src/config/perch.rs
git commit -s -m "feat(bridge): publish escalation edges and update lane topics only on level changes"
```

- [ ] **Step 6: Write the failing live-numbers test**

Create `workspace/desktop/src/features/perch-evidence/lib/laneLiveNumbers.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { laneLiveNumbers } from "./laneLiveNumbers.ts";

const policy = { half_life_secs: 3600, evaporation_threshold: 0.01, min_sources_for_escalation: 2, alert_threshold: 2, incident_threshold: 5 };

test("reads the 26001 frame for one class and marks above-alert from config, never from a percentage", () => {
  const snapshot = {
    concentrations: new Map([["execution", { threat_class: "execution", total_strength: 2.696884, distinct_sources: 2, peak_confidence: 0.9 }]]),
    telemetryReceivedAtMs: 1_773_739_200_000,
  };
  const n = laneLiveNumbers(snapshot, "execution", policy, 1_773_739_201_500);
  assert.deepEqual(n, {
    totalStrength: 2.696884,
    distinctSources: 2,
    peakConfidence: 0.9,
    alertThreshold: 2,
    incidentThreshold: 5,
    ageMs: 1500,
    aboveAlert: true,
  });
});

test("a class with no frame is null, never zero", () => {
  const snapshot = { concentrations: new Map(), telemetryReceivedAtMs: null };
  assert.equal(laneLiveNumbers(snapshot, "impact", policy, 1), null);
});
```

- [ ] **Step 7: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-evidence/lib/laneLiveNumbers.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 8: Implement the live numbers, the copy and the screen**

`laneLiveNumbers.ts`:

```ts
import type { PerchConcentration, PerchEphemeralSnapshot } from "@/shared/api/perchEphemeralStore";
import type { ThreatClassPolicy } from "@/shared/viz/types";

export type LaneLiveNumbers = {
  totalStrength: number;
  distinctSources: number;
  peakConfidence: number;
  alertThreshold: number;
  incidentThreshold: number;
  /** Age of the newest 26001 frame. Rendered as a number; past 5 s the header says "stale". */
  ageMs: number;
  aboveAlert: boolean;
};

/** The sidebar dot and the lane header read this, never a channel topic (04 §2.5). */
export function laneLiveNumbers(
  snapshot: Pick<PerchEphemeralSnapshot, "concentrations" | "telemetryReceivedAtMs">,
  slug: string,
  policy: ThreatClassPolicy,
  nowMs: number,
): LaneLiveNumbers | null {
  const c: PerchConcentration | undefined = snapshot.concentrations.get(slug);
  if (!c || snapshot.telemetryReceivedAtMs === null) return null;
  return {
    totalStrength: c.total_strength,
    distinctSources: c.distinct_sources,
    peakConfidence: c.peak_confidence,
    alertThreshold: policy.alert_threshold,
    incidentThreshold: policy.incident_threshold,
    ageMs: nowMs - snapshot.telemetryReceivedAtMs,
    aboveAlert: c.total_strength >= policy.alert_threshold,
  };
}
```

`laneCopy.ts`:

```ts
export const LANE = {
  headerLive: "live · 1 Hz · ephemeral",
  headerStale: "telemetry stale · last frame {seconds}s ago",
  customLanded: "classified Custom({name}) → shown in {slug}",
  quiet: {
    title: "No live deposits in {threatClass}",
    body: "Concentration is {strength} against an alert threshold of {alertThreshold}, from {sources}. Deposits decay on a {halfLife}s half-life, so this can go quiet without anything being resolved.",
    action: { label: "See what this lane cannot see", href: "/gaps?threat_class={slug}" },
  },
  mutedNote: "Muted on first run: every top-level post in an unmuted channel notifies (shouldNotify.ts:56-58), and an unmuted lane would page on every escalation card.",
  annotationsOnly: "Human messages here are annotations on the record. Decisions are recorded on a case.",
} as const;
```

`LaneHeader.tsx` renders `<ThreatClassLabel threatClass={slug} />`, `strength {totalStrength.toFixed(2)}` and `<SourceCount minSourcesForEscalation={policy.min_sources_for_escalation} sourceIds={depositsQuery.data?.source_ids ?? null} distinctSources={n.distinctSources} idsUnavailable={depositsQuery.isError ? "daemon-unreachable" : "not-on-this-card"} />` — the **id-carrying arm** when B4 answered (`17` §12 step 24: every lane row switches from the absence form to the expansion in this change), `alert {alertThreshold} · incident {incidentThreshold}` as numbers, and the `headerLive`/`headerStale` line (`ageMs > 5_000` → stale, `<DerivedMarker fn="perchEphemeralStore:26001" />` beside it). It reserves a `data-testid="perch-lane-curve-slot"` region that Task 19 fills with `ConcentrationCurve` in regime A; until then the slot renders nothing (no placeholder text).

`LaneScreen.tsx` (S5) resolves `laneId` → the threat-class slug through `PerchBridgeConfig`'s lane map as published in `scripts/provision-perch.sh`'s output (`workspace/desktop/src/features/perch/lib/laneChannels.ts`, a `Record<slug, uuid>` read from the community's `perch` settings — created here if The hold did not), mounts `LaneHeader`, then the timeline by **wrapping** `ChannelPane` with `channelId={laneId}`; the `EmptyState kind="swarm-produced-nothing"` (`LANE.quiet`, links `/gaps?threat_class=…`, names 18/11) replaces the pane when the lane has zero `kind:9` cards; a `LANE.customLanded` row renders above any escalation card whose `threat_class` is `{ custom }`; the composer keeps Ambush's plain-message path (annotations) and the header line says `annotationsOnly`. Snooze (`S`) is enabled on lane rows (`PERCH_BINDINGS` already declares it for `finding`/`case` rows; a lane row is neither — pass `rowType: "lane"` so `E` promotes and nothing else binds).

`AppSidebarPerchSection.tsx` renders inside `<FeatureGate feature="perch">`: the `LANES` group (twelve rows in `standard_threat_classes()` order — `lateral_movement, data_exfiltration, privilege_escalation, command_and_control, initial_access, persistence, supply_chain, defense_evasion, credential_access, discovery, execution, impact` — each `data-testid={`perch-lane-row-${slug}`}`, a filled dot `data-perch-lane-above-alert="true"` when `laneLiveNumbers(...)?.aboveAlert`, `data-perch-muted={String(isMuted(laneChannelId))}`), the `CASES` group (open case channels with a TTL glyph from `channels.ttl_deadline`), and the four nav items from `PERCH_NAV`. On first mount with the feature on, it calls the existing mute mutation for each of the twelve lane channels whose mute state is unset and persists `perch-lanes-muted.v1` in localStorage (a `CommunityScopedSingleton` member `lanesMutedOnce` with a resetter) — INV-21.

`routes/lanes.$laneId.tsx` mirrors Task 10 step 11's route file with `createFileRoute("/lanes/$laneId")`, `resetKey={laneId}`, `ViewLoadingFallback kind="lane"`.

- [ ] **Step 9: Run the unit test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-evidence/lib/laneLiveNumbers.test.mjs`
Expected: 2 passed.

- [ ] **Step 10: Write the Playwright spec and make it pass**

Create `workspace/desktop/tests/e2e/perch-lanes.spec.ts` (register in `smoke`):

```ts
import { expect, test } from "@playwright/test";
import { installPerchBridge, perchFixture, PERCH_LANE_CHANNEL } from "../helpers/perchBridge";
import { waitForAnimations } from "../helpers/animations";

test.describe("Perch lanes", () => {
  test.beforeEach(async ({ page }) => {
    await installPerchBridge(page, perchFixture());
  });

  test("01 — twelve lane rows, in escalation.rs order, all muted on first run", async ({ page }) => {
    await page.goto("#/");
    const rows = page.locator('[data-testid^="perch-lane-row-"]');
    await expect(rows).toHaveCount(12);
    await expect(rows.first()).toHaveAttribute("data-testid", "perch-lane-row-lateral_movement");
    await expect(rows.last()).toHaveAttribute("data-testid", "perch-lane-row-impact");
    await expect(page.locator('[data-perch-muted="false"]')).toHaveCount(0);
  });

  test("02 — the dot follows the 26001 frame, not a topic", async ({ page }) => {
    await page.goto("#/");
    await page.evaluate(() =>
      window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral(26001, {
        concentrations: [{ threat_class: "execution", total_strength: 2.7, distinct_sources: 2, peak_confidence: 0.9 }],
      }),
    );
    await expect(page.getByTestId("perch-lane-row-execution")).toHaveAttribute("data-perch-lane-above-alert", "true");
    await expect(page.getByTestId("perch-lane-row-impact")).not.toHaveAttribute("data-perch-lane-above-alert", "true");
  });

  test("03 — the lane header renders N sources / M agents once B4 answered", async ({ page }) => {
    await page.goto(`#/lanes/${PERCH_LANE_CHANNEL}`);
    await page.evaluate(() =>
      window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral(26001, {
        concentrations: [{ threat_class: "execution", total_strength: 2.65, distinct_sources: 2, peak_confidence: 0.9 }],
      }),
    );
    const count = page.locator('[data-testid="perch-lane-screen"] [data-perch-role="source-count"]');
    await expect(count).toHaveText(/2 sources \/ 1 agent/);
    await expect(page.getByTestId("perch-lane-screen")).toContainText("alert 2 · incident 5");
    await waitForAnimations(page);
  });

  test("04 — a quiet lane links /gaps and names the thresholds", async ({ page }) => {
    await page.goto(`#/lanes/${PERCH_LANE_CHANNEL}`);
    const empty = page.locator('[data-perch-role="empty-state"]');
    await expect(empty).toContainText("alert threshold of 2");
    await expect(empty.locator('[data-perch-role="gap-link"]')).toHaveCount(1);
  });
});
```

Run: `cd workspace/desktop && pnpm typecheck && pnpm test:e2e:smoke -- --grep "Perch lanes"`
Expected: 4 passed (the mock's `perch_deposits` case answers `execution` with the two-strategy, one-agent fixture, which is what `2 sources / 1 agent` reads).

- [ ] **Step 11: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh && bash tools/check-perch-adversary-strings.sh`
Expected: clean — `Lanes` as a standalone nav label passes the `bare-lane` row's whole-string exemption; `LANE.quiet.body` carries `sources` followed by `/ … agents` through `SourceCount`'s rendered form.

```bash
git add workspace/desktop/src/features/perch-evidence/ workspace/desktop/src/features/sidebar/ui/AppSidebarPerchSection.tsx workspace/desktop/src/features/sidebar/ui/AppSidebar.tsx workspace/desktop/src/features/perch/ workspace/desktop/src/app/routes/lanes.\$laneId.tsx workspace/desktop/src/app/routeTree.gen.ts workspace/desktop/tests/e2e/perch-lanes.spec.ts workspace/desktop/playwright.config.ts
git commit -s -m "feat(desktop): lanes — twelve muted threat-class channels with live numbers from the 26001 frame"
```

---

### Task 12: Governance strip

**Files:**
- Create: `workspace/desktop/src/features/perch/lib/governanceMode.ts`, `governanceMode.test.mjs`
- Create: `workspace/desktop/src/features/perch/lib/governanceCopy.ts`
- Create: `workspace/desktop/src/features/perch/useGovernanceStrip.ts`
- Create or replace: `workspace/desktop/src/features/perch/ui/GovernanceStrip.tsx` (The hold may have landed a slot-only version; this task fills the contract of `17` §6.4)
- Create: `workspace/desktop/tests/e2e/perch-governance-strip.spec.ts`; modify `playwright.config.ts`
- Modify: `workspace/desktop/src/shared/api/perchKeys.ts` (`governanceStatus` row) only if The hold did not add it

**Interfaces:**
- Consumes: the 26004 frame in `getPerchEphemeralSnapshot().governance: { partition_state, total_governors, healthy_governors, quorum_threshold, active_contingency_leases, unauthorized_partition_actions, last_transition_at_ms, last_reconciliation_report_id, receivedAtMs } | null`; the 26003 frame `mode: { current: "normal" | "alert" | "incident", triggering_threat_class: string | null, receivedAtMs }`; `perchTelemetryAgeMs`; the bridge-shedding flag from the `26000` gauge's `shed` field (`perchEphemeralStore`); `useRelayConnection()`'s 2 s debounce discipline (`shared/api/useRelayConnection.ts:22-64`); the watch-claim read model `WatchClaim | null` from Task 17's `lib/watchClaim.ts` (`{ holderPubkey, holderLabel, sinceMs, ttlMs }`) — until Task 17 lands, the hook returns `null`.
- Produces: `derivePerchGovernanceMode(input: GovernanceInput): PerchGovernanceMode` where `PerchGovernanceMode = "healthy" | "degraded" | "partitioned" | "healing" | "fail-closed-no-transport" | "stale" | "bridge-down"` and `GovernanceInput = { partitionState, totalGovernors, healthyGovernors, receivedAtMs, nowMs, bridgeShedding, staleAfterMs }`; `GovernanceStrip` (S14, 28 px, `data-testid="perch-governance-strip"`, `perch-governance-mode`, `perch-governance-watch-claim`) mounted by `AppShell`'s chrome conditional on every route including `bare`.

- [ ] **Step 1: Write the failing mode test**

Create `workspace/desktop/src/features/perch/lib/governanceMode.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { derivePerchGovernanceMode, GOVERNANCE_STALE_AFTER_MS } from "./governanceMode.ts";

const base = { partitionState: "healthy", totalGovernors: 1, healthyGovernors: 1, receivedAtMs: 1_000_000, nowMs: 1_001_000, bridgeShedding: false, staleAfterMs: GOVERNANCE_STALE_AFTER_MS };

test("committee of one on a fresh frame is healthy", () => {
  assert.equal(derivePerchGovernanceMode(base), "healthy");
});

test("more than one governor is the FAIL-CLOSED register, not a healthier one", () => {
  assert.equal(derivePerchGovernanceMode({ ...base, totalGovernors: 3, healthyGovernors: 3 }), "fail-closed-no-transport");
});

test("a stale frame outranks its own claim of health", () => {
  assert.equal(derivePerchGovernanceMode({ ...base, nowMs: 1_000_000 + GOVERNANCE_STALE_AFTER_MS + 1 }), "stale");
  assert.equal(derivePerchGovernanceMode({ ...base, receivedAtMs: null }), "bridge-down");
});

test("partition states pass through", () => {
  for (const s of ["degraded", "partitioned", "healing"]) {
    assert.equal(derivePerchGovernanceMode({ ...base, partitionState: s }), s);
  }
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch/lib/governanceMode.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement the projection and the copy**

`governanceMode.ts`:

```ts
export type PerchGovernanceMode =
  | "healthy"
  | "degraded"
  | "partitioned"
  | "healing"
  | "fail-closed-no-transport"
  | "stale"
  | "bridge-down";

/** Governance liveness is not restart-safe; a strip saying `healthy` from a stale snapshot is worse than one saying nothing (04 §1.2). Two missed 1 Hz frames plus the pacer's own tick. */
export const GOVERNANCE_STALE_AFTER_MS = 3_000;

export type GovernanceInput = {
  partitionState: "healthy" | "degraded" | "partitioned" | "healing";
  totalGovernors: number;
  healthyGovernors: number;
  receivedAtMs: number | null;
  nowMs: number;
  bridgeShedding: boolean;
  staleAfterMs: number;
};

/** A PROJECTION, marked derived on the strip. The daemon's frame is authoritative; this only decides which register the strip paints. */
export function derivePerchGovernanceMode(input: GovernanceInput): PerchGovernanceMode {
  if (input.receivedAtMs === null) return "bridge-down";
  if (input.nowMs - input.receivedAtMs > input.staleAfterMs) return "stale";
  // SoloGovernorTransport serves a committee of one and refuses larger; a deployment
  // that admits peer governors without a networked transport fails closed on every
  // destructive action (08 §5.3). More governors is strictly worse today.
  if (input.totalGovernors > 1) return "fail-closed-no-transport";
  return input.partitionState;
}
```

`governanceCopy.ts` (every string clears the ban list — `committee of 1 (solo transport)`, never a fraction):

```ts
export const GOVERNANCE = {
  healthy: "GOVERNANCE healthy · committee of 1 (solo transport) · recv {ago} ago",
  degraded: "GOVERNANCE degraded · committee of 1 (solo transport) · recv {ago} ago",
  partitioned: "GOVERNANCE PARTITIONED · destructive response runs only under contingency leases · recv {ago} ago",
  healing: "GOVERNANCE HEALING · reconciling partition-era activity · {unauthorized} unauthorized partition actions · recv {ago} ago",
  failClosed: "GOVERNANCE committee of {n} · no networked transport · destructive response FAILS CLOSED — every destructive action will be vetoed until a transport is installed",
  stale: "GOVERNANCE last frame {ago} ago · the strip is showing a stale snapshot, not the current state",
  bridgeDown: "bridge: down (last envelope {lastSeen}) · holds may not be reaching the console",
  shedding: "bridge is shedding the evidence stream to protect the alarm stream",
  mode: { normal: "mode normal", alert: "mode ALERT", incident: "mode INCIDENT" },
  modeDown: "de-escalated to {mode} · the daemon named no threat class",
  cooldown: "cooldown {seconds}s",
  watchHeld: "watch held by {holder} since {since}",
  watchStale: "watch claim by {holder} is stale ({ago} old) — classes 1–3 page everyone",
  watchNone: "no watch claimed — classes 1–3 page everyone",
  derived: "derived · derivePerchGovernanceMode()",
} as const;
```

- [ ] **Step 4: Run the mode tests**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch/lib/governanceMode.test.mjs`
Expected: 4 passed.

- [ ] **Step 5: Implement the hook and the strip**

`useGovernanceStrip.ts` subscribes to the ephemeral store with `useSyncExternalStore(subscribePerchEphemeral, getPerchEphemeralSnapshot)`, reads a 1 Hz `nowMs` from a single `setInterval`, computes `derivePerchGovernanceMode`, and applies the **debounce**: a non-`healthy` mode must persist for 2 000 ms before the painted mode changes to it; `healthy` clears immediately (copy of `useRelayConnection.ts:22-64`'s discipline, re-implemented here rather than imported because that hook debounces a different signal). It also exposes `swarmMode` from the 26003 frame with `modeDown: boolean` when the newest transition lowered the mode (`transition_down` sets `triggering_threat_class = None` — the row must not attribute the recovery to a class), the `cooldownSeconds` remaining from `deescalation_cooldown_secs` (rendered as a number), and the watch claim from `useWatchClaim()` (Task 17; returns `null` until then).

`GovernanceStrip.tsx` — fixed `28px` (`chromeLayout.ts:5` precedent), two lines, `role="status" aria-live="polite"` on the region, plus one `role="alert"` node raised **once** when the mode enters `partitioned` or `fail-closed-no-transport` (tracked in a ref so it does not re-announce each tick). Line 1 is the mode sentence from `GOVERNANCE` with `{ago}` rendered from `receivedAtMs` (`41s ago`, `41m ago`) and a `<DerivedMarker fn="derivePerchGovernanceMode()" />` chip; line 2 is the watch line (`watchHeld` / `watchStale` / `watchNone`) plus `mode` and `cooldown`. `data-testid="perch-governance-strip"`, `data-testid="perch-governance-mode"` on line 1 with `data-perch-governance-mode={mode}`, `data-testid="perch-governance-watch-claim"` on the watch span. The strip reads `--perch-*` only; `partitioned`/`fail-closed` use `border-perch-danger` (a border, never text colour), the word carries the meaning. `AppShell` mounts it above the chrome conditional so it survives `chrome: "bare"` (The hold's conditional already reserves the slot; this task replaces the slot's placeholder).

- [ ] **Step 6: The `watch held by` line reads the claim model only**

The line renders `watchHeld` when `claim && nowMs - claim.sinceMs <= claim.ttlMs`, `watchStale` when a claim exists past its TTL, `watchNone` otherwise. It never reads a channel topic or a relay event directly — Task 17 decides the source behind `useWatchClaim` (blocked on Task 2), and the strip is finished without it.

- [ ] **Step 7: Playwright**

Create `workspace/desktop/tests/e2e/perch-governance-strip.spec.ts` (register in `smoke`):

```ts
import { expect, test } from "@playwright/test";
import { installPerchBridge, perchFixture } from "../helpers/perchBridge";

const frame = (over: Record<string, unknown>) => ({
  partition_state: "healthy", total_governors: 1, healthy_governors: 1, quorum_threshold: 1,
  active_contingency_leases: 0, unauthorized_partition_actions: 0, last_transition_at_ms: 1_773_739_100_000, last_reconciliation_report_id: null,
  ...over,
});

test.describe("Perch governance strip", () => {
  test.beforeEach(async ({ page }) => {
    await installPerchBridge(page, perchFixture());
    await page.goto("#/");
  });

  test("01 — committee of one, never a fraction, on every route including the wall screen", async ({ page }) => {
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral(26004, frame({})));
    for (const route of ["#/", "#/leases", "#/watch-floor"]) {
      await page.goto(route);
      const strip = page.getByTestId("perch-governance-strip");
      await expect(strip).toContainText("committee of 1 (solo transport)");
      await expect(strip).not.toContainText(/\d+\s*\/\s*\d+/);
    }
  });

  test("02 — three governors is the fail-closed register", async ({ page }) => {
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral(26004, frame({ total_governors: 3, healthy_governors: 3 })));
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.advanceClock(2_100));
    await expect(page.getByTestId("perch-governance-mode")).toHaveAttribute("data-perch-governance-mode", "fail-closed-no-transport");
    await expect(page.getByTestId("perch-governance-mode")).toContainText("FAILS CLOSED");
  });

  test("03 — a non-healthy state waits two seconds; healthy clears at once", async ({ page }) => {
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral(26004, frame({ partition_state: "degraded" })));
    await expect(page.getByTestId("perch-governance-mode")).toHaveAttribute("data-perch-governance-mode", "healthy");
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.advanceClock(2_100));
    await expect(page.getByTestId("perch-governance-mode")).toHaveAttribute("data-perch-governance-mode", "degraded");
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral(26004, frame({})));
    await expect(page.getByTestId("perch-governance-mode")).toHaveAttribute("data-perch-governance-mode", "healthy");
  });

  test("04 — no frame for three seconds renders stale, and a de-escalation names no class", async ({ page }) => {
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral(26004, frame({})));
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.advanceClock(3_500));
    await expect(page.getByTestId("perch-governance-mode")).toContainText("stale snapshot");
    await page.evaluate(() => window.__AMBUSH_E2E_PERCH_CONTROL__.emitEphemeral(26003, { from: "incident", to: "alert", triggering_threat_class: null, reason: "cooldown" }));
    await expect(page.getByTestId("perch-governance-strip")).toContainText("the daemon named no threat class");
    await expect(page.getByTestId("perch-governance-watch-claim")).toContainText("no watch claimed");
  });
});
```

Run: `cd workspace/desktop && pnpm test:e2e:smoke -- --grep "Perch governance strip"`
Expected: 4 passed (`advanceClock` moves the frozen clock the store and the hook read, so the 2 s debounce is observable without sleeping).

- [ ] **Step 8: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh`
Expected: clean; the `quorum-fraction` row finds nothing.

```bash
git add workspace/desktop/src/features/perch/ workspace/desktop/tests/e2e/perch-governance-strip.spec.ts workspace/desktop/playwright.config.ts
git commit -s -m "feat(desktop): governance strip — committee of one, a staleness clock, and the fail-closed register"
```

---

### Task 13: Ledger — `/ledger`, the ⌘K omnibox, the export bundle, and tier-2 verification

**Files:**
- Create: `workspace/desktop/src/features/perch-shift/lib/ledgerQuery.ts`, `ledgerQuery.test.mjs`
- Create: `workspace/desktop/src/features/perch-shift/lib/omniboxCommands.ts`, `omniboxCommands.test.mjs`
- Create: `workspace/desktop/src/features/perch-shift/lib/exportBundle.ts`, `exportBundle.test.mjs`
- Create: `workspace/desktop/src/features/perch-shift/lib/ledgerCopy.ts`
- Create: `workspace/desktop/src/features/perch-shift/hooks.ts` (`useLedgerSearch`, `useRecentLedgerQueries`)
- Create: `workspace/desktop/src/features/perch-shift/ui/LedgerScreen.tsx`, `LedgerResultRow.tsx`, `LedgerExportDialog.tsx`, `PerchOmnibox.tsx`
- Create: `workspace/desktop/src-tauri/src/commands/perch_export.rs`, `perch_verify.rs`
- Modify: `workspace/desktop/src-tauri/src/commands/mod.rs`, `src-tauri/src/lib.rs` (two handler entries), `workspace/desktop/src/shared/api/tauriPerch.ts` (`perchExportBundle`, `perchVerifyEnvelope` added to `PERCH_READ_COMMANDS`-style arrays — both are local, non-daemon-bound; `perchVerifyArtifact` stays), `workspace/desktop/src/testing/perch/e2ePerchBridge.ts` (cases), `workspace/desktop/src/app/useAppShellKeyboardShortcuts.ts` (`Cmd-K` retargeted from `onSearchEverything` to `openPerchOmnibox` when the feature is on — a 4-line edit; the file is not on the frozen list), `workspace/desktop/src/features/communities/communityScopedRegistry.ts` (`ledgerRecentQueries`, `omniboxMode`)
- Create: `tools/check-perch-tier-allowlist.sh`, `tools/perch-tier-allowlist.tsv`; modify `.github/workflows/ci.yml` (one `run:` step in the `gates` job)
- Create or replace: `workspace/desktop/src/app/routes/ledger.tsx`
- Create: `workspace/desktop/tests/e2e/perch-ledger.spec.ts`, `perch-omnibox.spec.ts`; modify `playwright.config.ts`

**Interfaces:**
- Consumes: `parseSearchOperators(raw) -> { text, from, in, since, until }` (`features/search/lib/parseSearchOperators.ts:78`); `useSearchResults` (`features/search/useSearchResults.ts:102`) and `searchMessages` (`shared/api/tauri.ts:451`, NIP-50 through the relay — the relay re-authorizes every hit; the console adds no second search path); `SearchDialogInputRow` (`SearchScopeControls.tsx:37`), `useSearchMenuKeyboardNavigation`, `useDeferredModalOpen`, `Dialog`/`DialogContent`/`DialogTitle`; `acquireEscapeSurface()` (`shared/hooks/escapeSurfaces.ts:26`); `parseSwarmMarker` + `swarmCardRegistry` (to decode a hit into a `LedgerResultRowModel`); `perchVerifyArtifact(artifactId) -> { canonical_bytes_b64 }`; `perchListHolds()` (for the `UNRECONCILED` exclusion); `perchKeys.ledger(query)`; `swarm_perch_wire::envelope::{canonical_bytes, compute_envelope_hash_hex, unsigned_envelope_value, verify_chain_link, IssuerChainHead, ChainLinkVerdict}` plus the Tauri crate's existing `ed25519-dalek` (Task 7, W3-27); `tauri-plugin-dialog` (`save`/`open` directory picker, already a dependency); `swarmCardRegistry` entries' `maxTier` (Task 10 added `lease: 0`, `rollback: 1`; The hold's five carry `finding 0, escalation 0, hold 0, verdict 1, receipt 0`).
- Produces: `buildLedgerQuery(raw: string): LedgerQuery` where `LedgerQuery = { text: string; from: string | null; in: string | null; since: number | null; until: number | null; ftsTerms: { class?: string; action?: string; host?: string; agent?: string } }`; `PERCH_COMMANDS: readonly PerchCommandSpec[]` (exactly two entries); `parseOmniboxInput(raw) -> { mode: "query" | "command"; body: string }`; `matchCommand(body, commands) -> { spec, args } | null`; `buildExportManifest(entries: ExportEntry[], opts) -> ExportManifest` with `verification_tier` per file and `answers_who_approved: false`; the Tauri command `perch_export_bundle(input: ExportBundleInput) -> Result<ExportBundleReport, String>` (writes `MANIFEST.json`, `receipts/`, `envelopes/`, `holds/`, `canvas.md`, `VERIFY.md`, `DERIVED.json` under a directory the operator picked); `perch_verify_envelope(envelope_json: String, known_head: Option<KnownHead>) -> EnvelopeVerdict { tier: 0 | 2, signature_ok: bool, chain: "new" | "valid" | "hash_mismatch" | "sequence_mismatch" | "invalid_head" | "not_run", issuer: string }`; `tools/check-perch-tier-allowlist.sh` asserting the registry's `maxTier` values equal `tools/perch-tier-allowlist.tsv` in both directions.

- [ ] **Step 1: Write the failing query test**

Create `workspace/desktop/src/features/perch-shift/lib/ledgerQuery.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { buildLedgerQuery } from "./ledgerQuery.ts";

test("keeps the four inherited operators verbatim and adds four FTS-term operators", () => {
  const q = buildLedgerQuery("from:whisker-7a3f in:case-0042 after:2026-08-01 class:command_and_control action:block_egress host:web-04 agent:pouncer-2b18 beacon");
  assert.equal(q.from, "whisker-7a3f");
  assert.equal(q.in, "case-0042");
  assert.equal(typeof q.since, "number");
  assert.deepEqual(q.ftsTerms, { class: "command_and_control", action: "block_egress", host: "web-04", agent: "pouncer-2b18" });
  // The four Perch operators become text terms — NIP-01 indexes single-letter tags only,
  // and these events are signed, so strategy_id / host_id / receipt_id reach FTS alone.
  assert.equal(q.text, "command_and_control block_egress web-04 pouncer-2b18 beacon");
});

test("a token that is not at a token boundary is literal, as the inherited parser insists", () => {
  const q = buildLedgerQuery("built-in:react class:execution");
  assert.equal(q.in, null);
  assert.equal(q.ftsTerms.class, "execution");
  assert.equal(q.text, "built-in:react execution");
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/ledgerQuery.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement the query builder and the copy**

`ledgerQuery.ts`:

```ts
import { parseSearchOperators } from "@/features/search/lib/parseSearchOperators";

export type LedgerQuery = {
  text: string;
  from: string | null;
  in: string | null;
  since: number | null;
  until: number | null;
  ftsTerms: { class?: string; action?: string; host?: string; agent?: string };
};

/** Token-start only, like the inherited OPERATOR_RE — never `\b`, which fires after `-` and `/`. */
const PERCH_OPERATOR_RE = /(?:^|\s)(class|action|host|agent):(\S+)/gi;

/**
 * Four inherited operators (from: in: after: before:) plus four of Perch's own that
 * are FTS terms, not filters: NIP-01 indexes only single-letter tags and these events
 * are signed, so `strategy_id`, `host_id`, `receipt_id` and `lease_id` are reachable
 * through NIP-50 text search only (APPENDIX-NORMATIVE.md §3). The value is kept in
 * the text so it participates in the search; the operator prefix is stripped.
 */
export function buildLedgerQuery(raw: string): LedgerQuery {
  const ftsTerms: LedgerQuery["ftsTerms"] = {};
  let stripped = "";
  let last = 0;
  for (const match of raw.matchAll(PERCH_OPERATOR_RE)) {
    const index = match.index ?? 0;
    stripped += raw.slice(last, index);
    const key = match[1].toLowerCase() as keyof LedgerQuery["ftsTerms"];
    const value = match[2].replace(/[.,;:!?]+$/g, "");
    ftsTerms[key] = value;
    stripped += ` ${value}`;
    last = index + match[0].length;
  }
  stripped += raw.slice(last);
  const inherited = parseSearchOperators(stripped);
  return {
    text: inherited.text.replace(/\s+/g, " ").trim(),
    from: inherited.from,
    in: inherited.in,
    since: inherited.since,
    until: inherited.until,
    ftsTerms,
  };
}
```

`ledgerCopy.ts`:

```ts
export const LEDGER = {
  title: "Ledger",
  placeholder: "from:  in:  after:  before:  class:  action:  host:  agent:  or free text",
  noResults: {
    title: "No matches for {query}",
    body: "The Ledger searches finding, escalation, hold, receipt, containment-lease and rollback cards, plus case canvases and human verdicts. Fields inside a card body — strategy_id, host_id, receipt_id, lease_id — are full-text only and cannot be filtered as operators.",
    action: { label: "Query syntax", href: "/settings#ledger-syntax" },
  },
  degraded: "The relay is unreachable. Results below are the last page received, not a fresh search.",
  unreconciled: "UNRECONCILED · a relay row with no daemon record · excluded from export",
  export: {
    cta: "Export for the record",
    title: "Export {n} results",
    body: "Writes the cards, their envelopes, and a DERIVED.json listing every value the console computed rather than received. Governance attestations in the bundle can be re-verified; the other cards can only be compared against the daemon. There is no shipped offline verifier for a response receipt.",
    constraintWho: "This bundle answers “a human was asked”, not “who decided”, until approved_by rides on the receipt (B2o). MANIFEST.json says answers_who_approved: {answersWho}.",
    constraintHorizon: "Its horizon is the relay's configured audit-retention window, not the case TTL. Rows older than that window were detached and are not here.",
    envelopesEmpty: "envelopes/ is empty: no card in this result set carries a spine signature. VERIFY.md says so.",
    pdfRefused: "A PDF is not offered. A human-readable report is generated from the bundle, beside it, never instead of it.",
    written: "Wrote {files} files to {dir}. MANIFEST.json stamps a verification_tier on every one.",
  },
  verify: {
    tier0: "TRANSPORT-SIGNED ONLY · secp256k1 · tier 0 · the daemon is the record",
    tier0Cta: "Verify against the daemon",
    tier2: "Ed25519 · chained · seq {seq} · tier 2",
    chainGap: "Sequence gap · expected {expected}, received {received} · a gap renders as a gap",
    reFetched: "Re-fetched from the daemon: {verdict}",
    identical: "byte-identical",
    differs: "DIFFERS from the daemon's copy",
  },
} as const;
```

- [ ] **Step 4: Run the query test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/ledgerQuery.test.mjs`
Expected: 2 passed.

- [ ] **Step 5: Write the failing omnibox registry test**

Create `omniboxCommands.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { PERCH_COMMANDS, matchCommand, parseOmniboxInput } from "./omniboxCommands.ts";

test("the registry is exactly two commands and neither runs a write", () => {
  assert.equal(PERCH_COMMANDS.length, 2);
  const verbs = PERCH_COMMANDS.map((c) => c.verb).sort();
  assert.deepEqual(verbs, ["open", "release containment"]);
  for (const c of PERCH_COMMANDS) {
    assert.ok(c.consequence.length > 0, "a command with no consequence line is a spec bug");
    assert.ok(!("run" in c));
  }
});

test("> as the FIRST character switches mode; anywhere else it is query text", () => {
  assert.deepEqual(parseOmniboxInput("> open gaps"), { mode: "command", body: "open gaps" });
  assert.deepEqual(parseOmniboxInput("strength > 2"), { mode: "query", body: "strength > 2" });
  assert.deepEqual(parseOmniboxInput(""), { mode: "query", body: "" });
});

test("release containment stages a write on /leases and never posts", () => {
  const m = matchCommand("release containment cl_9b3645fc", PERCH_COMMANDS);
  assert.ok(m);
  assert.deepEqual(m.spec.effect, { kind: "request-write", write: "release-containment" });
  assert.deepEqual(m.args, ["cl_9b3645fc"]);
  const nav = matchCommand("open gaps", PERCH_COMMANDS);
  assert.deepEqual(nav?.spec.effect, { kind: "navigate", view: "gaps" });
  assert.equal(matchCommand("release cap-77f3a2", PERCH_COMMANDS), null, "cap- names a capability lease, a different object");
  assert.equal(matchCommand("grant hold h_a07aeacf", PERCH_COMMANDS), null, "a destructive verb one keystroke from every surface is what render law 6 forbids");
});
```

- [ ] **Step 6: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/omniboxCommands.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 7: Implement the command registry**

`omniboxCommands.ts`:

```ts
import type { PerchView } from "@/app/perchViews";

export type PerchOmniboxMode = "query" | "command";

/**
 * One command. `run` is NOT here: the omnibox emits an intent and the surface
 * that owns the write performs it, so a command can never become a sixth
 * un-audited write path (INV-01's five-call allowlist). 17 §6.13.
 */
export type PerchCommandSpec = {
  verb: string;
  args: readonly string[];
  effect: { kind: "navigate"; view: PerchView } | { kind: "request-write"; write: "release-containment" };
  consequence: string;
};

const OPENABLE: readonly PerchView[] = ["watch", "leases", "policy", "watchfloor", "ledger", "tuning", "handoff", "gaps", "settings"];

/** Exactly two. A third is a written argument, not a convenience. */
export const PERCH_COMMANDS: readonly PerchCommandSpec[] = [
  {
    verb: "release containment",
    args: ["lease_id"],
    effect: { kind: "request-write", write: "release-containment" },
    consequence: "opens Containments with the row focused and its release control armed — the daemon is asked only from that surface",
  },
  {
    verb: "open",
    args: ["surface"],
    effect: { kind: "navigate", view: "watch" },
    consequence: "navigates; changes nothing",
  },
];

export function parseOmniboxInput(raw: string): { mode: PerchOmniboxMode; body: string } {
  if (raw.startsWith(">")) return { mode: "command", body: raw.slice(1).trim() };
  return { mode: "query", body: raw };
}

export function matchCommand(body: string, commands: readonly PerchCommandSpec[]): { spec: PerchCommandSpec; args: readonly string[] } | null {
  const trimmed = body.trim();
  for (const spec of commands) {
    if (!trimmed.startsWith(spec.verb)) continue;
    const rest = trimmed.slice(spec.verb.length).trim();
    const args = rest.length === 0 ? [] : rest.split(/\s+/);
    if (args.length !== spec.args.length) continue;
    if (spec.effect.kind === "navigate") {
      const view = args[0] as PerchView;
      if (!OPENABLE.includes(view)) continue;
      return { spec: { ...spec, effect: { kind: "navigate", view } }, args };
    }
    if (spec.effect.kind === "request-write" && !/^cl_[A-Za-z0-9_-]{4,}$/.test(args[0] ?? "")) continue;
    return { spec, args };
  }
  return null;
}
```

- [ ] **Step 8: Run the registry test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/omniboxCommands.test.mjs`
Expected: 3 passed.

- [ ] **Step 9: Write the failing manifest test**

Create `exportBundle.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { buildExportManifest, planExportFiles } from "./exportBundle.ts";

const entries = [
  { kind: "receipt", id: "resp-1", bytes: new Uint8Array([123, 125]), tier: 0, reconciled: true },
  { kind: "rollback", id: "rb_81c4a588", bytes: new Uint8Array([123, 125]), tier: 1, reconciled: true },
  { kind: "hold", id: "h_a07aeacf", bytes: new Uint8Array([123, 125]), tier: 0, reconciled: true, verdictCardId: "cccc" },
  { kind: "hold", id: "h_ghost", bytes: new Uint8Array([123, 125]), tier: 0, reconciled: false },
  { kind: "envelope", id: "seq-7", bytes: new Uint8Array([123, 125]), tier: 2, reconciled: true },
];

test("every file gets a verification_tier and the bundle says it does not answer who approved", () => {
  const files = planExportFiles(entries);
  assert.ok(files.some((f) => f.path === "receipts/resp-1.json" && f.verification_tier === 0));
  assert.ok(files.some((f) => f.path === "receipts/rb_81c4a588.json" && f.verification_tier === 1));
  assert.ok(files.some((f) => f.path === "envelopes/seq-7.json" && f.verification_tier === 2));
  assert.ok(!files.some((f) => f.path.includes("h_ghost")), "UNRECONCILED is excluded, never silently included");
  const manifest = buildExportManifest(files, { exportingOperator: "swarm:ed25519:" + "a".repeat(64), derived: [{ fn: "derivePerchGovernanceMode()", value: "healthy" }] });
  assert.equal(manifest.answers_who_approved, false);
  assert.equal(manifest.files.length, files.length);
  assert.ok(manifest.files.every((f) => typeof f.sha256 === "string" && f.sha256.length === 64));
  assert.deepEqual(Object.keys(manifest).sort(), ["answers_who_approved", "exporting_operator", "files", "generated_at", "manifest_signature", "verification_tiers_present"].sort());
});

test("envelopes/ is present and empty, not omitted, when nothing is signed", () => {
  const files = planExportFiles(entries.filter((e) => e.kind !== "envelope"));
  assert.ok(files.some((f) => f.path === "envelopes/.keep"));
});
```

- [ ] **Step 10: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/exportBundle.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 11: Implement the bundle planner and the manifest**

`exportBundle.ts`:

```ts
import { createHash } from "node:crypto";

export type ExportEntry = {
  kind: "receipt" | "rollback" | "hold" | "envelope" | "verdict";
  id: string;
  /** The daemon's or relay's bytes, VERBATIM. Never reserialized. */
  bytes: Uint8Array;
  tier: 0 | 1 | 2;
  /** false = a relay row with no daemon record (W3-18). Excluded. */
  reconciled: boolean;
  verdictCardId?: string;
};

export type ExportFile = { path: string; bytes: Uint8Array; verification_tier: 0 | 1 | 2 };

export function planExportFiles(entries: readonly ExportEntry[]): ExportFile[] {
  const files: ExportFile[] = [];
  let envelopes = 0;
  for (const e of entries) {
    if (!e.reconciled) continue;
    const dir = e.kind === "receipt" || e.kind === "rollback" ? "receipts" : e.kind === "hold" || e.kind === "verdict" ? "holds" : "envelopes";
    if (dir === "envelopes") envelopes += 1;
    files.push({ path: `${dir}/${e.id}.json`, bytes: e.bytes, verification_tier: e.tier });
  }
  if (envelopes === 0) files.push({ path: "envelopes/.keep", bytes: new Uint8Array(), verification_tier: 0 });
  return files;
}

export type ExportManifest = {
  generated_at: string;
  exporting_operator: string;
  answers_who_approved: false;
  verification_tiers_present: (0 | 1 | 2)[];
  files: { path: string; sha256: string; verification_tier: 0 | 1 | 2 }[];
  /** Detached Ed25519 over the canonical manifest body; filled by the Tauri command. */
  manifest_signature: string | null;
};

export function buildExportManifest(files: readonly ExportFile[], opts: { exportingOperator: string; derived: readonly { fn: string; value: unknown }[] }): ExportManifest {
  const tiers = Array.from(new Set(files.map((f) => f.verification_tier))).sort() as (0 | 1 | 2)[];
  return {
    generated_at: new Date().toISOString(),
    exporting_operator: opts.exportingOperator,
    answers_who_approved: false,
    verification_tiers_present: tiers,
    files: files.map((f) => ({ path: f.path, sha256: createHash("sha256").update(f.bytes).digest("hex"), verification_tier: f.verification_tier })),
    manifest_signature: null,
  };
}

/** VERIFY.md, per tier, as commands a reader can run with swarmctl and nothing else. */
export function renderVerifyMd(manifest: ExportManifest): string {
  const lines = ["# VERIFY", "", "This bundle answers “a human was asked”, not “who approved this” (answers_who_approved: false).", ""];
  if (manifest.verification_tiers_present.includes(0)) {
    lines.push("## Tier 0 files", "These files carry no Ed25519 signature; re-fetch them from the daemon to verify:", "", "    swarmctl evidence fetch --id <id> | diff - receipts/<id>.json", "");
  }
  if (manifest.verification_tiers_present.includes(1)) {
    lines.push("## Tier 1 files", "A governance attestation rides inside the receipt. Check the signature and the subject binding:", "", "    swarmctl containment verify-release --receipt receipts/<id>.json", "", "No trust anchor: this does not prove a governor you trust authorized it.", "");
  }
  if (manifest.verification_tiers_present.includes(2)) {
    lines.push("## Tier 2 files", "Spine envelopes with seq and prev_envelope_hash. Check the signature and the chain per issuer:", "", "    swarmctl spine verify --dir envelopes/", "");
  } else {
    lines.push("## envelopes/", "Empty: no card in this result set carries a spine signature (B6 has not sealed these issuers' cards, or the set predates it).", "");
  }
  return lines.join("\n");
}
```

(`node:crypto` is available in the `node:test` runner; in the renderer the manifest is built by the Tauri command, which hashes in Rust — the TypeScript planner is the unit under test and the source of the file list the command receives.)

- [ ] **Step 12: Run the manifest test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/exportBundle.test.mjs`
Expected: 2 passed.

- [ ] **Step 13: Commit the pure modules**

```bash
git add workspace/desktop/src/features/perch-shift/lib/
git commit -s -m "feat(desktop): ledger query grammar, the two-command omnibox registry, and the export manifest planner"
```

- [ ] **Step 14: Write the failing Tauri verification test**

Create `workspace/desktop/src-tauri/src/commands/perch_verify.rs` with tests first:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sealed(seq: u64, prev: Option<String>, emitted_at_ms: i64) -> serde_json::Value {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let issuer = format!("swarm:ed25519:{}", hex::encode(key.verifying_key().to_bytes()));
        let mut value = serde_json::json!({
            "schema": "swarm.spine.envelope.v1", "issuer": issuer, "seq": seq,
            "prev_envelope_hash": prev, "issued_at": "2026-08-30T02:41:07Z",
            "capability_token": null,
            "fact": { "schema": "swarm.perch.finding.v1", "issuer": {"swarm_agent_id": "a", "role": null}, "emitted_at_ms": emitted_at_ms }
        });
        let bytes = swarm_perch_wire::envelope::canonical_bytes(&value).unwrap();
        let hash = swarm_perch_wire::envelope::compute_envelope_hash_hex(&value).unwrap();
        let signature = hex::encode(key.sign(&bytes).to_bytes());
        value["envelope_hash"] = serde_json::json!(hash);
        value["signature"] = serde_json::json!(signature);
        value
    }

    #[test]
    fn a_sealed_envelope_verifies_at_tier_two_and_a_stripped_one_is_tier_zero() {
        let sealed = sealed(1, None, 1);
        let json = serde_json::to_string(&sealed).unwrap();
        let verdict = verify_envelope_json(&json, None).unwrap();
        assert_eq!(verdict.tier, 2);
        assert!(verdict.signature_ok);
        assert_eq!(verdict.chain, "new");
        let mut stripped: serde_json::Value = serde_json::from_str(&json).unwrap();
        stripped.as_object_mut().unwrap().remove("signature");
        let verdict = verify_envelope_json(&stripped.to_string(), None).unwrap();
        assert_eq!(verdict.tier, 0);
        assert_eq!(verdict.chain, "not_run");
    }

    #[test]
    fn a_sequence_gap_renders_as_a_gap() {
        let first = sealed(1, None, 1);
        let first_hash = first["envelope_hash"].as_str().unwrap().to_string();
        let third = sealed(3, Some(first_hash.clone()), 3);
        let head = KnownHead { issuer: first["issuer"].as_str().unwrap().to_string(), seq: 1, envelope_hash: first_hash };
        let verdict = verify_envelope_json(&serde_json::to_string(&third).unwrap(), Some(head)).unwrap();
        assert_eq!(verdict.chain, "sequence_mismatch");
        assert_eq!(verdict.tier, 2, "the signature still verifies; the chain does not — two separate rows");
    }
}
```

- [ ] **Step 15: Run to see it fail**

Run: `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_verify`
Expected: FAIL to compile.

- [ ] **Step 16: Implement `perch_verify.rs` and `perch_export.rs`**

`perch_verify.rs`:

```rust
//! Tier-2 verification of a spine envelope, in the Tauri process — never in the
//! webview and never by asking the relay (ADR 0016 C2). The shared wire crate
//! supplies canonical bytes and structural chain rules; this process verifies
//! Ed25519 with its own dependency (W3-27).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use swarm_perch_wire::envelope::{ChainLinkVerdict, IssuerChainHead, canonical_bytes, compute_envelope_hash_hex, unsigned_envelope_value, verify_chain_link};

/// The newest head the console has seen for this issuer (from `perchSeqTracking`).
#[derive(Debug, Clone, Deserialize)]
pub struct KnownHead {
    pub issuer: String,
    pub seq: u64,
    pub envelope_hash: String,
}

/// What the PROVENANCE block renders. Signature and chain are two rows, never merged.
#[derive(Debug, Clone, Serialize)]
pub struct EnvelopeVerdict {
    pub tier: u8,
    pub signature_ok: bool,
    pub chain: &'static str,
    pub issuer: String,
}

fn signature_verifies(envelope: &serde_json::Value, issuer: &str, bytes: &[u8]) -> bool {
    let Some(key_hex) = issuer.strip_prefix("swarm:ed25519:") else { return false; };
    let Ok(key_vec) = hex::decode(key_hex) else { return false; };
    let Ok(key_bytes) = <[u8; 32]>::try_from(key_vec.as_slice()) else { return false; };
    let Some(signature_hex) = envelope.get("signature").and_then(serde_json::Value::as_str) else { return false; };
    let Ok(signature_bytes) = hex::decode(signature_hex.trim_start_matches("0x")) else { return false; };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else { return false; };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else { return false; };
    key.verify(bytes, &signature).is_ok()
}

/// Pure so the test needs no `AppState`.
pub fn verify_envelope_json(envelope_json: &str, known_head: Option<KnownHead>) -> Result<EnvelopeVerdict, String> {
    let envelope: serde_json::Value = serde_json::from_str(envelope_json).map_err(|e| format!("envelope is not JSON: {e}"))?;
    let issuer = envelope.get("issuer").and_then(serde_json::Value::as_str).unwrap_or_default().to_string();
    let unsigned = unsigned_envelope_value(&envelope).map_err(|e| e.to_string())?;
    let claimed_hash = envelope.get("envelope_hash").and_then(serde_json::Value::as_str).unwrap_or_default();
    let hash_ok = compute_envelope_hash_hex(&unsigned).map_err(|e| e.to_string())? == claimed_hash;
    let bytes = canonical_bytes(&unsigned).map_err(|e| e.to_string())?;
    let signature_ok = hash_ok && signature_verifies(&envelope, &issuer, &bytes);
    let tier = if signature_ok { 2 } else { 0 };
    let chain = if tier != 2 {
        "not_run"
    } else {
        let head = known_head.map(|h| IssuerChainHead { issuer: h.issuer, seq: h.seq, envelope_hash: h.envelope_hash });
        match verify_chain_link(&envelope, head.as_ref()) {
            Ok(ChainLinkVerdict::NewChain) => "new",
            Ok(ChainLinkVerdict::ValidContinuation) => "valid",
            Ok(ChainLinkVerdict::HashMismatch { .. }) => "hash_mismatch",
            Ok(ChainLinkVerdict::SequenceMismatch { .. }) => "sequence_mismatch",
            Ok(ChainLinkVerdict::InvalidChainHead { .. }) | Err(_) => "invalid_head",
        }
    };
    Ok(EnvelopeVerdict { tier, signature_ok, chain, issuer })
}

#[tauri::command]
pub async fn perch_verify_envelope(envelope_json: String, known_head: Option<KnownHead>) -> Result<EnvelopeVerdict, String> {
    verify_envelope_json(&envelope_json, known_head)
}
```

`perch_export.rs` — `#[tauri::command] pub async fn perch_export_bundle(input: ExportBundleInput, state: State<'_, AppState>) -> Result<ExportBundleReport, String>` where `ExportBundleInput { directory: String, files: Vec<{ path, bytes_b64, verification_tier }>, canvas_md: String, derived_json: String, verify_md: String }`: refuse any `path` containing `..` or an absolute component; create `receipts/`, `envelopes/`, `holds/`; write every file's bytes **exactly as received** (base64-decoded, no JSON round trip); write `canvas.md`, `DERIVED.json`, `VERIFY.md`; build `MANIFEST.json` by hashing each written file with `sha2`, sign the RFC 8785 canonical manifest body with the operator's Ed25519 key from the keyring (`state.perch_operator_signer()` — The hold's accessor behind `perch_record_verdict`; the secret never crosses IPC, only `manifest_signature` and `exporting_operator` do), and return `{ files_written: usize, manifest_path: String }`. Register both commands in `commands/mod.rs` and `lib.rs`'s `generate_handler![]` (two entries; `lib.rs` is at 940 gate-lines), add `perchExportBundle` and `perchVerifyEnvelope` wrappers to `tauriPerch.ts` under a new `PERCH_LOCAL_COMMANDS` array (local writes to disk and local verification — not Ambush-bound, so outside INV-01's five and outside `PERCH_DAEMON_WRITE_COMMANDS`; `PERCH_TAURI_COMMANDS` concatenates it so the mock asserts coverage), and add the two cases to `e2ePerchBridge.ts` (the export case records the request into `window.__AMBUSH_E2E_PERCH__.lastExport` so `readPerchExportManifest` can read it).

- [ ] **Step 17: Run the Tauri tests and the write-allowlist gate**

Run: `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_ && bash tools/check-perch-write-allowlist.sh`
Expected: the two verify tests pass; the allowlist gate still reads exactly five daemon routes (the export command opens no socket to an Ambush host — `perch_daemon_request` is called only with `PerchMethod::Get` for the receipt re-fetch).

- [ ] **Step 18: Commit the Tauri half**

```bash
git add workspace/desktop/src-tauri/src/commands/perch_verify.rs workspace/desktop/src-tauri/src/commands/perch_export.rs workspace/desktop/src-tauri/src/commands/mod.rs workspace/desktop/src-tauri/src/lib.rs workspace/desktop/src/shared/api/tauriPerch.ts workspace/desktop/src/testing/perch/e2ePerchBridge.ts
git commit -s -m "feat(desktop): tier-2 envelope verification and the export bundle writer in the Tauri process"
```

- [ ] **Step 19: The screen, the rows, the dialog, the omnibox**

`hooks.ts`: `useLedgerSearch(query: LedgerQuery)` wraps `useSearchResults` with `perchKeys.ledger(serialized)`; every hit is passed through `parseSwarmMarker` + the admission set — an unadmitted signer's hit is counted (`perchUnadmittedFrameCount`) and rendered as prose at most; a hold hit whose `hold_id` is absent from `perchListHolds()` is marked `unreconciled: true`. `useRecentLedgerQueries()` keeps the five most recent queries in `localStorage` (`perch-ledger-recent.v1`, a `CommunityScopedSingleton` member `ledgerRecentQueries` with a resetter).

`LedgerResultRow.tsx` (`data-testid={`perch-ledger-row-${eventId}`}`): line 1 `text-sm` — card kind word, action/detector, host through `AdversaryString`, time; line 2 `text-xs` — operator or agent, the tier badge from `ProvenanceRows`' vocabulary (`secp256k1 · tier 0` / `Ed25519 · tier 1` / `Ed25519 · chained · seq N · tier 2` via `perchVerifyEnvelope` when the body carries `signature`); an `unreconciled` row renders `LEDGER.unreconciled` in the destructive register with `data-perch-unreconciled="true"` and no export checkbox.

`LedgerExportDialog.tsx` (`data-testid="perch-ledger-export"`): body copy `LEDGER.export.body`, the two constraints as body paragraphs (`constraintWho` with `{answersWho}` = `false`, `constraintHorizon`), `envelopesEmpty` when no row is tier 2, `pdfRefused`; on confirm: directory picker (`tauri-plugin-dialog` `open({ directory: true })`), then for every reconciled row collect bytes — receipts/rollbacks re-fetched through `perchVerifyArtifact(id).canonical_bytes_b64` (the daemon's bytes, INV-26), envelopes as the relay event's `content` fenced-JSON block bytes verbatim, holds as the `kind:9` event JSON verbatim plus its `swarm:verdict:v1` card id — then `planExportFiles`, `buildExportManifest`, `renderVerifyMd`, `DERIVED.json` from the `derivedMarkerLedger` singleton (every `<DerivedMarker>` rendered on this surface registers `{fn, value}` there; INV-17: non-empty iff any derived element rendered), and `perchExportBundle(...)`; renders `LEDGER.export.written` with the count.

`LedgerScreen.tsx` (S9): `SearchDialogInputRow`-styled bar with `LEDGER.placeholder`, `buildLedgerQuery` on every change (debounced 250 ms), `useLedgerSearch`, states `idle` (recent queries), `loading` (`LOADING.ledger`), `ready` (rows, virtualized above 200), `empty` (`EmptyState kind="governing-number"` with `LEDGER.noResults`, never `/gaps`), `degraded` (`LEDGER.degraded` above the last page). `Export ▾` opens the dialog over the current result set. `usePerchKeymap` binds `J`/`K`/`Enter`; no verdict verbs.

`PerchOmnibox.tsx` (`17` §6.13): a `Dialog` with a visually hidden `DialogTitle`, the input `role="combobox"` with `aria-expanded`/`aria-activedescendant` and the mode chip (`data-testid="perch-omnibox-mode"`, `query` / `command`) inside `aria-describedby`; `parseOmniboxInput` on every keystroke; query mode reuses `useLedgerSearch` and renders `LedgerResultRow`s (`perch-omnibox-result-${id}`), `Enter` navigates to the row's case or lane; command mode renders `PERCH_COMMANDS` with their consequence lines (`perch-omnibox-command-${slug}`), `Enter` on a `command-armed` match dispatches the **effect** only — `navigate` calls `useAppNavigation().goPerch(view)`, `request-write` navigates to `/leases?focus=<lease_id>&arm=release` and nothing else; an unmatched verb renders the registry (`command-unknown`), never a toast. `acquireEscapeSurface()` in a `useEffect` with the release in cleanup (a leaked acquire disables Escape-to-mark-read for the session); `Escape` closes and never marks read; a route change closes it. `useAppShellKeyboardShortcuts.ts:73-77`'s `Cmd-K` arm calls `openPerchOmnibox()` when `useFeatureEnabled("perch")` and `onSearchEverything()` otherwise.

`routes/ledger.tsx` mirrors Task 10 step 11 with `createFileRoute("/ledger")`, `resetKey="/ledger"`, `ViewLoadingFallback kind="ledger"`.

- [ ] **Step 20: Write the two Playwright specs and make them pass**

`perch-ledger.spec.ts` (`smoke`): `01` — a seeded case with a receipt, a hold and a verdict card; `from:` and `in:` and a free-text substring of the receipt body each return the same row (`09` §4.2 criterion 2); `02` — a relay-only hold (`relayOnlyHoldIds: ["h_ghost"]`) renders `perch-ledger-row-*` with `data-perch-unreconciled="true"` and the export manifest read through `readPerchExportManifest(page)` lists no `holds/h_ghost.json`; `03` — every manifest file has `verification_tier ∈ {0,1,2}`, `answers_who_approved === false`, and with no tier-2 rows `envelopes/.keep` is present; `04` — the empty state names the FTS-only limit and has zero `[data-perch-role="gap-link"]`.

`perch-omnibox.spec.ts` (`smoke`): `01` — `Cmd-K` opens `perch-omnibox`, `Escape` closes it and the active channel's unread count is unchanged (`Escape` never marks read); `02` — typing `>` switches `perch-omnibox-mode` to `command`, deleting it returns to `query`; `03` — `> release containment cl_9b3645fc` + `Enter` lands on `#/leases?focus=cl_9b3645fc&arm=release` with `perch-containment-release` focused and **no** `perch_release_containment` call recorded in the mock (`readPerchCounter(page, "perch_release_containment_calls") === 0`); `04` — `> grant hold h_a07aeacf` renders `perch-omnibox-command-*` for the two registry entries and no error toast.

Run: `cd workspace/desktop && pnpm typecheck && pnpm test:e2e:smoke -- --grep "Perch ledger|Perch omnibox"`
Expected: 8 passed.

- [ ] **Step 21: The tier allowlist gate**

Create `tools/perch-tier-allowlist.tsv`:

```
# tools/perch-tier-allowlist.tsv -- which card types may declare maxTier > 0 and why.
# Read by tools/check-perch-tier-allowlist.sh, which asserts EQUALITY in both
# directions against swarmCardRegistry.tsx's maxTier declarations (21-ADRS.md Q4).
card	maxTier	precondition
rollback	1	none -- verify_release_attestation ships today
verdict	1	B2 landed and provisions the operator's Ed25519 key
finding	2	B6 landed (Task 7): the bridge seals every envelope
escalation	2	B6 landed
hold	2	B6 landed
receipt	2	B6 landed
lease	2	B6 landed
```

Create `tools/check-perch-tier-allowlist.sh`: read the TSV; extract every `maxTier: N` beside its key from `workspace/desktop/src/features/perch-evidence/lib/swarmCardRegistry.tsx` with `awk`; fail on any card whose declared value differs from the table, on any table row with no registry entry, and on an empty extraction (`refusing to pass silently`); run a planted fixture first (a copy of the registry with `finding` bumped to `2` while the table says `0` must fail; the clean control must pass). Add to `.github/workflows/ci.yml`'s `gates` job, after the `check-gates-wired` step:

```yaml
      - name: Check the Perch card tier allowlist
        run: bash tools/check-perch-tier-allowlist.sh
```

The registry's five pre-B6 entries move from `0` to `2` in this step **because Task 7 landed** (the precondition column says so); the Playwright provenance `01` already asserts a tier-2 badge names the chain and the seq.

Run: `bash tools/check-perch-tier-allowlist.sh && bash tools/check-gates-wired.sh`
Expected: `clean over 7 card(s)`; the wiring gate sees the new script named by a real `run:`.

- [ ] **Step 22: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh && bash tools/check-perch-adversary-strings.sh && bash tools/check-perch-grant-affordance.sh`
Expected: clean — `data-perch-role="grant"` appears in no file under `perch-shift/` (R2: exactly one file may declare it).

```bash
git add workspace/desktop/src/features/perch-shift/ workspace/desktop/src/app/routes/ledger.tsx workspace/desktop/src/app/routeTree.gen.ts workspace/desktop/src/app/useAppShellKeyboardShortcuts.ts workspace/desktop/src/features/communities/communityScopedRegistry.ts workspace/desktop/src/features/perch-evidence/lib/swarmCardRegistry.tsx workspace/desktop/tests/e2e/perch-ledger.spec.ts workspace/desktop/tests/e2e/perch-omnibox.spec.ts workspace/desktop/playwright.config.ts tools/check-perch-tier-allowlist.sh tools/perch-tier-allowlist.tsv .github/workflows/ci.yml
git commit -s -m "feat(desktop): the Ledger, its Cmd-K overlay, the export bundle with verification tiers, and the tier allowlist gate"
```

---

### Task 14: Tuning bench — `/tuning`

**Files:**
- Create: `workspace/desktop/src/features/perch-policy/lib/tuningProvenance.ts`, `tuningProvenance.test.mjs`
- Create: `workspace/desktop/src/features/perch-policy/lib/tuningCopy.ts`
- Create: `workspace/desktop/src/features/perch-policy/ui/TuningScreen.tsx`, `TuningRecommendationCard.tsx`
- Create: `workspace/desktop/src/features/perch-policy/hooks.ts` (`useOperatorStatusQuery`, `useIncidentQuery`)
- Modify: `workspace/desktop/src-tauri/src/commands/perch_reads.rs` (`perch_operator_status` pinned to `GET /v2/api/runtime/status`; new `perch_get_incident` → `GET /v2/api/incidents?incident_id=`), `workspace/desktop/src/shared/api/tauriPerch.ts` (`perchGetIncident`), `perchKeys.ts` (`incident(id)` row: `staleTime: 60_000`, no poll), `workspace/desktop/src/testing/perch/e2ePerchBridge.ts`
- Create or replace: `workspace/desktop/src/app/routes/tuning.tsx`
- Create: `workspace/desktop/tests/e2e/perch-tuning.spec.ts`; modify `playwright.config.ts`

**Interfaces:**
- Consumes: `perchOperatorStatus()` returning the daemon's `/v2/api/runtime/status` body, of which `alert_tuning: AlertTuningReport { reviewed_findings, false_positive_findings, recommendation_count, recommendations: AlertTuningRecommendation[] }` and `false_positive_tracking: { reviewed_findings, false_positive_findings, false_positive_rate, latest_feedback_at_ms, detectors }` (`crates/swarm-runtime/src/service/types.rs:228`, `alert_tuning.rs:52-75`); `AlertTuningRecommendation { kind: "host_exclusion_review" | "detector_threshold_review" | "detector_rule_review", priority: "high" | "medium" | "low", summary, next_step, strategy_id?, host_id?, reviewed_findings, false_positive_findings, false_positive_rate, supporting_signals: string[] }`; `IncidentRecord { incident_id, trigger_finding_id?, trigger_strategy_id?, feedback_audit_entries: AnalystFeedbackAuditEntry[], false_positive_measurements: FalsePositiveMeasurement[], … }` (`crates/swarm-spine/src/incident.rs:210-243`); `InstrumentationStrip` with `readOnly` (The hold); `ModerationQueueCard.tsx`'s grouped-card pattern **forked** (the `ShieldAlert` at `:314` removed → `AlertTriangle`); `EmptyState`, `AdversaryString`.
- Produces: `deriveTuningProvenance(rec, incidents) -> TuningProvenance` where `TuningProvenance = { origin: "analyst-promoted" | "correlation-produced" | "unresolved"; thisWeekVerdicts: number; totalVerdicts: number; fractionThisWeek: number | null; derivedFn: "tuningProvenance.ts:deriveTuningProvenance" }`; `TuningRecommendationCard` (every one of the eight fields rendered); `TuningScreen` (S10, `data-testid="perch-tuning-screen"`); `perchGetIncident(incidentId) -> Promise<IncidentRecord | null>`.

- [ ] **Step 1: Write the failing provenance test**

Create `tuningProvenance.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { deriveTuningProvenance, incidentOrigin } from "./tuningProvenance.ts";

test("an incident minted by promote-to-case is analyst-promoted; the correlation namespace is correlation-produced", () => {
  assert.equal(incidentOrigin({ incident_id: "incident:hunt-evt-1:1773738882400" }), "correlation-produced");
  assert.equal(incidentOrigin({ incident_id: "perch-case:27799e23-ab25-4659-b381-3de47ea7ca4d" }), "analyst-promoted");
  assert.equal(incidentOrigin({ incident_id: "something-else" }), "unresolved");
});

test("the this-week fraction counts measurements reviewed inside the window and never invents one", () => {
  const weekStartMs = 1_773_100_000_000;
  const rec = { kind: "detector_rule_review", strategy_id: "suspicious_process_tree", host_id: null, reviewed_findings: 3, false_positive_findings: 2, false_positive_rate: 0.67, summary: "", next_step: "", priority: "high", supporting_signals: [] };
  const incidents = [
    { incident_id: "perch-case:a", false_positive_measurements: [
      { finding_id: "f1", strategy_id: "suspicious_process_tree", reviewed_at_ms: weekStartMs + 1, false_positive: true },
      { finding_id: "f2", strategy_id: "suspicious_process_tree", reviewed_at_ms: weekStartMs - 1, false_positive: true },
      { finding_id: "f3", strategy_id: "suspicious_process_tree", reviewed_at_ms: weekStartMs + 2, false_positive: false },
    ] },
  ];
  const p = deriveTuningProvenance(rec, incidents, weekStartMs);
  assert.equal(p.origin, "analyst-promoted");
  assert.equal(p.totalVerdicts, 3);
  assert.equal(p.thisWeekVerdicts, 2);
  assert.equal(p.fractionThisWeek, 2 / 3);
  assert.equal(deriveTuningProvenance(rec, [], weekStartMs).fractionThisWeek, null, "no denominator, no fraction");
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-policy/lib/tuningProvenance.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement provenance and copy**

`tuningProvenance.ts`:

```ts
export type IncidentOrigin = "analyst-promoted" | "correlation-produced" | "unresolved";

/**
 * ADR 0018 C3: a promote-to-case incident is minted under an id scheme that CANNOT
 * collide with the correlation engine's `incident:{hunt_id}:{created_at_ms}`. The
 * First card plan mints `perch-case:<case channel uuid>` (12 §9.4). Anything else
 * is `unresolved` and rendered as such — never guessed.
 */
export function incidentOrigin(record: { incident_id: string }): IncidentOrigin {
  if (record.incident_id.startsWith("incident:")) return "correlation-produced";
  if (record.incident_id.startsWith("perch-case:")) return "analyst-promoted";
  return "unresolved";
}

export type TuningProvenance = {
  origin: IncidentOrigin;
  thisWeekVerdicts: number;
  totalVerdicts: number;
  fractionThisWeek: number | null;
  derivedFn: "tuningProvenance.ts:deriveTuningProvenance";
};

type Measurement = { finding_id: string; strategy_id: string; host_id?: string | null; reviewed_at_ms: number; false_positive: boolean };
type Incident = { incident_id: string; false_positive_measurements: Measurement[] };
type Recommendation = { kind: string; strategy_id?: string | null; host_id?: string | null };

/** Which verdicts fed this recommendation, and how many landed this week — the C9 fraction, per card. DERIVED, marked. */
export function deriveTuningProvenance(rec: Recommendation, incidents: readonly Incident[], weekStartMs: number): TuningProvenance {
  const matching = incidents.flatMap((i) =>
    i.false_positive_measurements
      .filter((m) => (rec.strategy_id ? m.strategy_id === rec.strategy_id : true))
      .filter((m) => (rec.kind === "host_exclusion_review" && rec.host_id ? m.host_id === rec.host_id : true))
      .map((m) => ({ origin: incidentOrigin(i), m })),
  );
  const totalVerdicts = matching.length;
  const thisWeekVerdicts = matching.filter(({ m }) => m.reviewed_at_ms >= weekStartMs).length;
  const origins = new Set(matching.map((x) => x.origin));
  const origin: IncidentOrigin = origins.size === 1 ? [...origins][0] : origins.size === 0 ? "unresolved" : "analyst-promoted";
  return {
    origin,
    thisWeekVerdicts,
    totalVerdicts,
    fractionThisWeek: totalVerdicts === 0 ? null : thisWeekVerdicts / totalVerdicts,
    derivedFn: "tuningProvenance.ts:deriveTuningProvenance",
  };
}
```

(When the measurements span both origins the card says `mixed: {a} analyst-promoted · {c} correlation-produced` — the `origin` field carries the majority for the badge and the card prints both counts.)

`tuningCopy.ts`:

```ts
export const TUNING = {
  title: "Tuning bench",
  subtitle: "What this week's verdicts changed. The next step after a recommendation is a config diff a human signs; this surface stops at the recommendation and what it came from.",
  kinds: {
    host_exclusion_review: { label: "Host exclusion review", minimum: "needs 2 reviewed findings and 2 false positives on one host (rate ≥ 0.75)" },
    detector_threshold_review: { label: "Detector threshold review", minimum: "needs 4 reviewed findings and 2 false positives on one detector (rate ≥ 0.50)" },
    detector_rule_review: { label: "Detector rule review", minimum: "needs 3 reviewed findings and 2 false positives on one detector (rate ≥ 0.34)" },
  },
  cap: "capped at 6 recommendations (alert_tuning.rs:6)",
  origin: {
    "analyst-promoted": "from verdicts on analyst-promoted cases",
    "correlation-produced": "from verdicts on correlation-produced incidents",
    unresolved: "incident origin not resolvable from its id",
  },
  window: "The daemon's evidence window is the {limit} newest incidents in a store that is {durability}. {restartNote}",
  windowVolatile: "A restart destroys every measurement ever written.",
  windowDurable: "It survives a restart.",
  linkVerdicts: "See the verdicts in the Ledger",
  none: {
    title: "No recommendations yet",
    body: "A detector-rule review needs 3 reviewed findings and 2 false positives on one detector; a threshold review needs 4 and 2; a host exclusion needs 2 and 2 on one host. You have recorded {reviewed} reviewed, {fp} false positive. Confirm, Dismiss and Investigate all count toward the denominator; only Dismiss counts as a false positive.",
    action: { label: "Open the watch", href: "/" },
  },
  c9Restated: "These three numbers are owned by The Watch and restated here.",
} as const;
```

- [ ] **Step 4: Run the provenance test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-policy/lib/tuningProvenance.test.mjs`
Expected: 2 passed.

- [ ] **Step 5: The reads**

In `perch_reads.rs` set `const ROUTE_OPERATOR_STATUS: &str = "/v2/api/runtime/status";` (the tuning report an operator can read lives on the daemon's `/v2/api`, `20` §1.4 — not on `swarmctl serve`'s `/v1/operator/status`) and add:

```rust
const ROUTE_INCIDENTS: &str = "/v2/api/incidents";

/// `GET /v2/api/incidents?incident_id=…` on the daemon (platform_api.rs:1155). Read-only.
#[tauri::command]
pub async fn perch_get_incident(incident_id: String, state: State<'_, AppState>) -> Result<Option<serde_json::Value>, String> {
    if incident_id.is_empty() || incident_id.contains(['&', '?', '#']) {
        return Err("incident_id must be a bare id".into());
    }
    let body = crate::perch::client::perch_daemon_request(&state, PerchMethod::Get, &format!("{ROUTE_INCIDENTS}?incident_id={}", urlencoding::encode(&incident_id)), None).await.map_err(redact_for_ipc)?;
    let page: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok(page.get("items").and_then(|items| items.as_array()).and_then(|items| items.first().cloned()))
}
```

(`urlencoding` is already a workspace dependency; if not, `percent-encoding` is — use whichever the Tauri crate already pulls.) Add `perchGetIncident(incidentId)` to `tauriPerch.ts` and `PERCH_READ_COMMANDS`, the `perchKeys.incident(id)` row (`staleTime: 60_000`, `poll: false`, `why: "a record assembled once; refetch on demand only"`), the mock case answering `fixtures/http/POST-v1-operator-incidents.json`'s record for its id, and the `generate_handler!` entry.

- [ ] **Step 6: The card and the screen**

`TuningRecommendationCard.tsx` (forked from `ModerationQueueCard.tsx`'s grouped-card layout; `ShieldAlert` replaced by `AlertTriangle`; `data-testid={`perch-tuning-card-${index}`}`): the kind label and priority chip (`SeverityChip`-styled, word first), `summary` and `next_step` through `AdversaryString`, `strategy_id` in mono, `host_id` through `AdversaryString` when present, `reviewed_findings / false_positive_findings` and `false_positive_rate` as `{fp} of {reviewed} · {rate}` (every number with its denominator), `supporting_signals` as a list through `AdversaryString`, the provenance line `TUNING.origin[origin] · {thisWeek} of {total} verdicts this week` with `<DerivedMarker fn={provenance.derivedFn} />`, and the link `TUNING.linkVerdicts` → `/ledger?q=agent:{strategy_id}` (plus `host:{host_id}` for a host exclusion). No Apply button, disabled or otherwise.

`TuningScreen.tsx` (S10): `useOperatorStatusQuery()` (`perchKeys.operatorStatus()`, `staleTime: 60_000`, on-demand only — `04` §2.10 refuses polling it) and, for the provenance, `useIncidentQuery(id)` for each `incident_id` referenced by the recommendations' measurements (the status body carries `recent_incident_ids`; if it does not, provenance renders `unresolved` with the reason `the status body does not name its incidents`). Top: `InstrumentationStrip readOnly` restating the three C9 numbers with `TUNING.c9Restated` and a link to `/`. Then the `TUNING.window` sentence from the status body's `store_durable` and `recent_decisions_limit` (default 20; `12` BL-1). Then the cards (`≤ 6`). Empty: `EmptyState kind="governing-number"` with `TUNING.none` filled from `alert_tuning.reviewed_findings` / `false_positive_findings`, `governingNumber: { label: "DETECTOR_RULE_MIN_REVIEWED", value: "3", source: "crates/swarm-runtime/src/alert_tuning.rs:13" }`, never `/gaps`.

`routes/tuning.tsx` mirrors Task 10 step 11 (`/tuning`, `kind="tuning"`).

- [ ] **Step 7: Playwright**

`perch-tuning.spec.ts` (`smoke`): `01` — with the mock status carrying one `detector_rule_review` for `suspicious_process_tree`, the card renders all eight fields (assert `summary`, `next_step`, `strategy_id`, `2 of 3 · 0.67`, one `supporting_signals` item) and the provenance line names `analyst-promoted`; `02` — the empty status renders `No recommendations yet` naming `3`, `4` and `2` and has zero `gap-link`s; `03` — the C9 strip on `/tuning` carries `readOnly` and links to `/`; `04` — no element under `perch-tuning-screen` has text matching `/apply/i`.

Run: `cd workspace/desktop && pnpm typecheck && pnpm test:e2e:smoke -- --grep "Perch tuning"`
Expected: 4 passed.

- [ ] **Step 8: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh`
Expected: clean.

```bash
git add workspace/desktop/src/features/perch-policy/ workspace/desktop/src-tauri/src/commands/perch_reads.rs workspace/desktop/src-tauri/src/lib.rs workspace/desktop/src/shared/api/tauriPerch.ts workspace/desktop/src/shared/api/perchKeys.ts workspace/desktop/src/testing/perch/e2ePerchBridge.ts workspace/desktop/src/app/routes/tuning.tsx workspace/desktop/src/app/routeTree.gen.ts workspace/desktop/tests/e2e/perch-tuning.spec.ts workspace/desktop/playwright.config.ts
git commit -s -m "feat(desktop): tuning bench — every recommendation field, with its verdict provenance marked derived"
```

---

### Task 15: Gaps — `/gaps`

**Files:**
- Create: `workspace/desktop/src/features/perch-policy/lib/gapsCatalog.ts`, `gapsCatalog.test.mjs`
- Create: `workspace/desktop/src/features/perch-policy/ui/GapsScreen.tsx`, `GapCard.tsx`
- Modify: `workspace/desktop/src-tauri/src/commands/perch_reads.rs` (`perch_evasion_coverage`), `tauriPerch.ts`, `perchKeys.ts` (`evasionCoverage()`: `staleTime: 300_000`, no poll), `e2ePerchBridge.ts`
- Create or replace: `workspace/desktop/src/app/routes/gaps.tsx`
- Create: `workspace/desktop/tests/e2e/perch-gaps.spec.ts`; modify `playwright.config.ts`

**Interfaces:**
- Consumes: `GET /v2/api/evasion/coverage` on the daemon (`platform_api.rs:814`, `platform_evasion_coverage_handler` at `:1337`) returning `EvasionCoverageSnapshot { generated_at_ms, suite_name, suite_path, corpus_version, detectors: DetectorEvasionCoverageReport[] }` where each detector carries `detector: string` and `intentionally_uncovered: EvasionTechniqueGap[]` = `{ technique, threat_class, rationale }` (`evasion_coverage.rs:103-107`, `:130-147`) — the same `rulesets/evasion/attack-technique-catalog.yaml` the daemon loads, served by the daemon so the console never carries a stale copy; `EmptyState`; `ThreatClassLabel`.
- Produces: `groupGaps(snapshot) -> { detectors: { detector: string; gaps: EvasionTechniqueGap[] }[]; techniqueCount: number; detectorCount: number }`; `GapsScreen` (S12, `data-testid="perch-gaps-screen"`) filterable by `?threat_class=`; `GapCard` (one row per technique, rationale verbatim as trusted text — the catalog is a checked-in ruleset, not adversary input); `perchEvasionCoverage() -> Promise<EvasionCoverageSnapshot>`; the numbers `18` and `11` read from the served snapshot and asserted against the checked-in YAML by a Rust test.

- [ ] **Step 1: Write the failing grouping test**

Create `gapsCatalog.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { groupGaps } from "./gapsCatalog.ts";

test("groups by detector, counts distinct techniques and detectors, keeps the rationale verbatim", () => {
  const snapshot = {
    generated_at_ms: 1, suite_name: "evasion-breadth-v1", suite_path: "scenario-suites/evasion-breadth-v1.yaml", corpus_version: "1",
    detectors: [
      { detector: "suspicious_process_tree", intentionally_uncovered: [
        { technique: "T1204.001", threat_class: "initial_access", rationale: "The detector only sees normalized process starts after execution and cannot reason about phishing-link delivery or attachment-open provenance." },
        { technique: "T1036.005", threat_class: "defense_evasion", rationale: "Legitimate-name or path-masquerading requires richer signer and file-origin telemetry than the current process-start payload carries." },
      ] },
      { detector: "dns_exfiltration", intentionally_uncovered: [
        { technique: "T1071.001", threat_class: "command_and_control", rationale: "DNS-over-HTTPS and other application-layer tunneling over web protocols bypass the DNS-query-specific normalization." },
      ] },
      { detector: "covered_everywhere", intentionally_uncovered: [] },
    ],
  };
  const g = groupGaps(snapshot);
  assert.equal(g.techniqueCount, 3);
  assert.equal(g.detectorCount, 2, "a detector with no declared gap is not a row");
  assert.equal(g.detectors[0].gaps[0].rationale, snapshot.detectors[0].intentionally_uncovered[0].rationale);
});

test("filtering by threat class keeps only matching techniques and recounts", () => {
  const snapshot = { generated_at_ms: 1, suite_name: "", suite_path: "", corpus_version: "", detectors: [
    { detector: "a", intentionally_uncovered: [{ technique: "T1", threat_class: "initial_access", rationale: "r" }, { technique: "T2", threat_class: "impact", rationale: "r" }] },
  ] };
  const g = groupGaps(snapshot, "impact");
  assert.equal(g.techniqueCount, 1);
  assert.equal(g.detectors[0].gaps[0].technique, "T2");
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-policy/lib/gapsCatalog.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement the grouping**

`gapsCatalog.ts`:

```ts
export type EvasionTechniqueGap = { technique: string; threat_class: string; rationale: string };
export type EvasionCoverageSnapshot = {
  generated_at_ms: number;
  suite_name: string;
  suite_path: string;
  corpus_version: string;
  detectors: { detector: string; intentionally_uncovered: EvasionTechniqueGap[] }[];
};

export type GapsGrouped = {
  detectors: { detector: string; gaps: EvasionTechniqueGap[] }[];
  techniqueCount: number;
  detectorCount: number;
};

/** The honest answer to a quiet queue. No editorializing: the catalog's prose is better than a summary of it (04 §2.12). */
export function groupGaps(snapshot: EvasionCoverageSnapshot, threatClass?: string): GapsGrouped {
  const detectors = snapshot.detectors
    .map((d) => ({ detector: d.detector, gaps: d.intentionally_uncovered.filter((g) => (threatClass ? g.threat_class === threatClass : true)) }))
    .filter((d) => d.gaps.length > 0);
  const techniques = new Set(detectors.flatMap((d) => d.gaps.map((g) => g.technique)));
  return { detectors, techniqueCount: techniques.size, detectorCount: detectors.length };
}
```

- [ ] **Step 4: Run the grouping test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-policy/lib/gapsCatalog.test.mjs`
Expected: 2 passed.

- [ ] **Step 5: Pin the served counts to the checked-in YAML**

Append to `crates/swarm-runtime/src/evasion_coverage.rs`'s `mod tests`:

```rust
    #[test]
    fn the_shipped_catalog_declares_eighteen_techniques_across_eleven_detectors() {
        let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rulesets/evasion/attack-technique-catalog.yaml")).unwrap();
        let catalog: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        let detectors = catalog["detectors"].as_sequence().unwrap();
        let with_gaps = detectors.iter().filter(|d| d["intentionally_uncovered"].as_sequence().is_some_and(|s| !s.is_empty())).count();
        let techniques: usize = detectors.iter().map(|d| d["intentionally_uncovered"].as_sequence().map_or(0, |s| s.len())).sum();
        assert_eq!(with_gaps, 11, "APPENDIX-NORMATIVE.md §6 pins 11 detectors; update the appendix row when the catalog changes");
        assert_eq!(techniques, 18, "APPENDIX-NORMATIVE.md §6 pins 18 techniques");
    }
```

(`serde_yaml` is a workspace dependency; add it to `swarm-runtime`'s `[dev-dependencies]` if absent — the catalog loader itself already parses YAML, so reuse its loader function instead when it is `pub(crate)`.)

Run: `cargo test -p swarm-runtime the_shipped_catalog_declares`
Expected: 1 passed.

- [ ] **Step 6: The read, the screen, the card**

In `perch_reads.rs`: `const ROUTE_EVASION_COVERAGE: &str = "/v2/api/evasion/coverage";` and `perch_evasion_coverage(state) -> Result<serde_json::Value, String>` (GET, bearer from the keyring, `redact_for_ipc` on errors); `tauriPerch.ts` `perchEvasionCoverage()`; `perchKeys.evasionCoverage()` (`staleTime: 300_000`, `poll: false`, `why: "a checked-in ruleset; changes on deploy, not on a tick"`); the mock case answers a snapshot built from the eighteen catalog rows vendored to `workspace/desktop/src/testing/perch/evasionCoverage.fixture.json` (generated by `node scripts/generate-evasion-fixture.mjs rulesets/evasion/attack-technique-catalog.yaml`, committed; a `check` step diffs it against the YAML so the mock cannot drift).

`GapCard.tsx` (`data-testid={`perch-gap-${technique}`}`): `technique` in mono `text-sm`, `<ThreatClassLabel threatClass={threat_class} />`, `rationale` as plain `text-sm` prose (trusted). No coverage percentage anywhere.

`GapsScreen.tsx` (S12): H1 `Gaps`, the sentence `{techniqueCount} techniques across {detectorCount} detectors are declared uncovered · suite {suite_name} · corpus {corpus_version}`, the `?threat_class=` filter chip (from the lane's `/gaps?threat_class=…` link), one `EyebrowLabel` group per detector with its `GapCard`s; states `loading`, `daemon-unreachable` (`the daemon serves the catalog; it is unreachable — the last snapshot is {ago} old`, with the cached query shown), `ready`. This surface has no empty state of its own: a catalog with zero declared gaps renders `0 techniques declared uncovered · coverage claims are made by the catalog, not by this screen`.

`routes/gaps.tsx` mirrors Task 10 step 11 (`/gaps`, `kind="gaps"`).

- [ ] **Step 7: Playwright**

`perch-gaps.spec.ts` (`smoke`): `01` — `#/gaps` renders `18 techniques across 11 detectors`, eleven `EyebrowLabel` groups, eighteen `perch-gap-*` cards, and one card's text equals the fixture's rationale verbatim; `02` — `#/gaps?threat_class=defense_evasion` renders only `defense_evasion` cards and the recount; `03` — no text matches `/\d+\s*%/` under `perch-gaps-screen`.

Run: `cd workspace/desktop && pnpm typecheck && pnpm test:e2e:smoke -- --grep "Perch gaps"`
Expected: 3 passed.

- [ ] **Step 8: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh`
Expected: clean.

```bash
git add workspace/desktop/src/features/perch-policy/ workspace/desktop/src-tauri/src/commands/perch_reads.rs workspace/desktop/src-tauri/src/lib.rs workspace/desktop/src/shared/api/ workspace/desktop/src/testing/perch/ workspace/desktop/src/app/routes/gaps.tsx workspace/desktop/src/app/routeTree.gen.ts workspace/desktop/tests/e2e/perch-gaps.spec.ts workspace/desktop/playwright.config.ts crates/swarm-runtime/src/evasion_coverage.rs
git commit -s -m "feat(desktop): gaps — the daemon's declared-uncovered catalog, grouped by detector, rationale verbatim"
```

---

### Task 16: Policy — `/policy`, read-only, with the daemon evaluating the triple

**Files:**
- Create: `crates/swarm-ingest-runtime/src/ingest/perch_ops/policy.rs`
- Create: `crates/swarm-runtime-http/src/http/perch/policy.rs`; modify `http/perch/mod.rs` (route + path entry), `generate_perch_openapi.rs`, `docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml`; regenerate `docs/openapi/perch-operator-v1.json`
- Modify: `crates/swarm-policy/src/configurable_gate.rs:44-56` (`selector_matches` becomes `pub fn` — a widening `tools/check-visibility-baseline.sh` must see: it is private today, so the key is new, not widened)
- Modify: `crates/swarm-ingest-runtime/src/ingest/mod.rs` (`current_policy_config()`)
- Create: `workspace/desktop/src/features/perch-policy/lib/policyEvaluation.ts`, `policyEvaluation.test.mjs`, `policyCopy.ts`
- Create: `workspace/desktop/src/features/perch-policy/ui/PolicyScreen.tsx`, `PolicyRuleRow.tsx`, `PolicyTripleEvaluator.tsx`
- Modify: `perch_reads.rs` (`perch_policy`), `tauriPerch.ts`, `perchKeys.ts` (`policy(triple)`), `e2ePerchBridge.ts`
- Create or replace: `workspace/desktop/src/app/routes/policy.tsx`
- Create: `workspace/desktop/tests/e2e/perch-policy.spec.ts`; modify `playwright.config.ts`

**Interfaces:**
- Consumes: `PolicyConfig { human_gate_severity: Severity, lease_ttl_ms: i64, max_actions_per_scope_per_minute, rules: Vec<PolicyRuleConfig> }` (`crates/swarm-core/src/config/policy.rs:8-24`); `PolicyRuleConfig { name, decision: allow|deny, threat_class, actions: Vec<PolicyActionSelector>, min_severity, max_severity, time_window_utc: Option<{start_hour_utc, end_hour_utc}>, max_actions_per_agent_per_minute: Option<usize>, reason: Option<String> }` (`:34-60`); `ConfigurableApprovalGate::selector_matches(rule, request, threat_class)` (`configurable_gate.rs:44-56`) and `evaluate`'s first-match-wins order (`:143-180`); `IngestState.stack.load_full().service.config.policy`; `PerchHttpState`, `require_operator_api_scope(Read)`.
- Produces: `GET /v1/operator/policy?threat_class=&severity=&action=` (scope `Read`; all three query params optional together — absent renders rules only) answering `PolicyResponse { schema_version, human_gate_severity, lease_ttl_ms, source: { path, attested: bool }, rules: PolicyRuleView[], evaluation: PolicyEvaluation | null }` where `PolicyRuleView = PolicyRuleConfig + { index: usize }` and `PolicyEvaluation = { triple: { threat_class, severity, action }, verdicts: { rule_index, verdict: "decides" | "not_matched" | "not_reached" }[], fallthrough: { gate: "static", verdict: "require_human" | "allow", reason } | null, warning: "request_carried_selectors" }` — computed by the daemon with the real `selector_matches`, so two clients cannot disagree (the reason B4 computes M); `evaluateTriple(rules, triple) -> verdicts` on the client is a **display-only** mirror, tested equal to the daemon's answer on the shipped ruleset and marked derived; `PolicyScreen` (S7, `data-testid="perch-policy-screen"`); `PolicyTripleEvaluator` (`data-testid="perch-policy-evaluator"`); `PolicyRuleRow` (`data-testid={`perch-policy-rule-${index}`}`, `data-perch-policy-verdict`).

- [ ] **Step 1: Write the failing daemon evaluation test**

Create `crates/swarm-ingest-runtime/src/ingest/perch_ops/policy.rs` with tests:

```rust
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    fn shipped_policy() -> swarm_core::config::PolicyConfig {
        let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rulesets/default.yaml")).unwrap();
        let config: swarm_core::config::SwarmConfig = serde_yaml::from_str(&raw).unwrap();
        config.policy
    }

    #[test]
    fn the_shipped_c2_rule_outranks_the_human_gate_at_critical() {
        let policy = shipped_policy();
        let evaluation = evaluate_triple(&policy, &PolicyTriple { threat_class: ThreatClass::CommandAndControl, severity: Severity::Critical, action: "block_egress".into() });
        let decides: Vec<_> = evaluation.verdicts.iter().filter(|v| v.verdict == RuleVerdict::Decides).collect();
        assert_eq!(decides.len(), 1);
        assert_eq!(decides[0].rule_index, 1, "command-and-control-emergency-block is the second rule in file order");
        assert_eq!(evaluation.verdicts[0].verdict, RuleVerdict::NotMatched);
        assert_eq!(evaluation.verdicts[2].verdict, RuleVerdict::NotReached);
        assert!(evaluation.fallthrough.is_none());
        assert!(evaluation.outranks_human_gate, "block_egress is destructive and human_gate_severity is HIGH, yet this triple is allowed outright");
    }

    #[test]
    fn an_unmatched_triple_falls_through_to_the_static_gate() {
        let policy = shipped_policy();
        let evaluation = evaluate_triple(&policy, &PolicyTriple { threat_class: ThreatClass::Impact, severity: Severity::High, action: "isolate_host".into() });
        assert!(evaluation.verdicts.iter().all(|v| v.verdict == RuleVerdict::NotMatched));
        let fallthrough = evaluation.fallthrough.unwrap();
        assert_eq!(fallthrough.verdict, "require_human");
        assert_eq!(fallthrough.reason, "authorized but held for human approval");
    }
}
```

- [ ] **Step 2: Run to see it fail**

Run: `cargo test -p swarm-ingest-runtime perch_ops::policy`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the evaluation**

In `crates/swarm-policy/src/configurable_gate.rs` change `fn selector_matches(` (`:44`) to `pub fn selector_matches(` with a doc comment (`/// Whether `rule` selects `request` for `threat_class`. Public so the operator surface can evaluate a triple with the same predicate the gate uses.`). Then `perch_ops/policy.rs`:

```rust
//! The read behind `/policy`. Rules in file order, and the per-triple evaluation
//! the daemon computes with the gate's own predicate so no client re-implements it.

use serde::{Deserialize, Serialize};
use swarm_core::config::{PolicyConfig, PolicyRuleConfig, PolicyRuleDecision};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{ActionRequest, ResponseAction, Severity};
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::static_gate::destructive_action_kinds;

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyTriple {
    pub threat_class: ThreatClass,
    pub severity: Severity,
    /// A `ResponseAction::kind()` slug, e.g. `block_egress`.
    pub action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerdict {
    Decides,
    NotMatched,
    NotReached,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleVerdictView {
    pub rule_index: usize,
    pub verdict: RuleVerdict,
}

#[derive(Debug, Clone, Serialize)]
pub struct Fallthrough {
    pub gate: &'static str,
    pub verdict: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvaluation {
    pub triple: PolicyTripleEcho,
    pub verdicts: Vec<RuleVerdictView>,
    pub fallthrough: Option<Fallthrough>,
    /// True when the deciding rule is `allow` and the action is one of the twelve
    /// destructive kinds at or above `human_gate_severity` — the case `04` §2.7 exists for.
    pub outranks_human_gate: bool,
    pub warning: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyTripleEcho {
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub action: String,
}

/// Build the minimal `ActionRequest` `selector_matches` reads: severity, action, and
/// the threat class inside `evidence["escalation"]` — the request-carried fields the
/// permanent banner warns about.
fn request_for(triple: &PolicyTriple) -> Option<ActionRequest> {
    let action: ResponseAction = serde_json::from_value(serde_json::json!({ "type": triple.action, "host_id": "evaluator", "target": "evaluator", "credential_id": "evaluator", "domain": "evaluator", "session_id": "evaluator", "file_path": "evaluator", "process_id": 0, "account_id": "evaluator", "task_id": "evaluator", "zone_id": "evaluator", "principal": "evaluator" })).ok()?;
    Some(ActionRequest {
        requested_by: swarm_core::types::AgentId("perch-policy-evaluator".into()),
        action,
        severity: triple.severity,
        evidence: serde_json::json!({ "escalation": { "threat_class": triple.threat_class } }),
        ..ActionRequest::evaluator_defaults()
    })
}

/// First match in file order decides (`configurable_gate.rs:143-180`). Everything
/// after it is `not_reached`; everything before it is `not_matched`.
pub fn evaluate_triple(policy: &PolicyConfig, triple: &PolicyTriple) -> PolicyEvaluation {
    let echo = PolicyTripleEcho { threat_class: triple.threat_class.clone(), severity: triple.severity, action: triple.action.clone() };
    let Some(request) = request_for(triple) else {
        return PolicyEvaluation { triple: echo, verdicts: Vec::new(), fallthrough: None, outranks_human_gate: false, warning: "request_carried_selectors" };
    };
    let mut verdicts = Vec::with_capacity(policy.rules.len());
    let mut decided: Option<&PolicyRuleConfig> = None;
    for (index, rule) in policy.rules.iter().enumerate() {
        let verdict = if decided.is_some() {
            RuleVerdict::NotReached
        } else if ConfigurableApprovalGate::selector_matches(rule, &request, &triple.threat_class) {
            decided = Some(rule);
            RuleVerdict::Decides
        } else {
            RuleVerdict::NotMatched
        };
        verdicts.push(RuleVerdictView { rule_index: index, verdict });
    }
    let destructive = destructive_action_kinds().contains(&triple.action.as_str());
    let fallthrough = if decided.is_none() {
        Some(if destructive && triple.severity >= policy.human_gate_severity {
            Fallthrough { gate: "static", verdict: "require_human", reason: "authorized but held for human approval" }
        } else {
            Fallthrough { gate: "static", verdict: "allow", reason: "static.default_allow" }
        })
    } else {
        None
    };
    let outranks_human_gate = matches!(decided, Some(rule) if rule.decision == PolicyRuleDecision::Allow) && destructive && triple.severity >= policy.human_gate_severity;
    PolicyEvaluation { triple: echo, verdicts, fallthrough, outranks_human_gate, warning: "request_carried_selectors" }
}
```

`ActionRequest::evaluator_defaults()` and `destructive_action_kinds()` name the two things the shipped tree spells differently: `ActionRequest`'s remaining fields (`swarm-policy/src/lib.rs:45-58`) get a constructor for a synthetic request, and the twelve destructive kinds are the `static_gate.rs:37-53` list — expose it as `pub fn destructive_action_kinds() -> &'static [&'static str]` in `static_gate.rs` (private today; a new key for the visibility baseline, verified with `STS_VISIBILITY_HEAD_REV= bash tools/check-visibility-baseline.sh`). Add `pub mod policy;` to `perch_ops/mod.rs` and `IngestState::current_policy_config(&self) -> PolicyConfig` (`self.stack.load_full().service.config.policy.clone()`) beside `current_pheromone_config`.

- [ ] **Step 4: Run the evaluation tests**

Run: `cargo test -p swarm-ingest-runtime perch_ops::policy && cargo test -p swarm-policy && STS_VISIBILITY_HEAD_REV= bash tools/check-visibility-baseline.sh`
Expected: 2 passed; the policy crate's own tests unchanged; the visibility gate reports two new keys, no widened ones.

- [ ] **Step 5: The route**

`crates/swarm-runtime-http/src/http/perch/policy.rs`: `PolicyQuery { threat_class: Option<ThreatClass>, severity: Option<Severity>, action: Option<String> }` (`deny_unknown_fields`; all three or none — a partial triple is `400`); `PolicyResponse { schema_version, human_gate_severity, lease_ttl_ms, source: PolicySource { path: String, attested: bool }, rules: Vec<PolicyRuleView>, evaluation: Option<PolicyEvaluation> }` where `source.path` is `state.ingest.config_path()` and `attested` is whether a `.sig.json` sibling exists (`rulesets/default.yaml.sig.json` — the reason the surface is read-only); handler `policy_handler` with `require_operator_api_scope(Read)`. Route `.route("/v1/operator/policy", get(policy::policy_handler))` and the `PERCH_ROUTER_PATHS` entry (eight paths now; the disjointness test's comment count moves from 7 to 8 — update the literal). Add the path and schemas to the YAML (`/v1/operator/policy`, `PolicyResponse`, `PolicyRuleView`, `PolicyEvaluation`) and the generator; regenerate the JSON; `bash tools/check-perch-openapi.sh` green. A handler test mirrors Task 4 step 11 with `?threat_class=command_and_control&severity=CRITICAL&action=block_egress` asserting `evaluation.verdicts[1].verdict == "decides"` and `outranks_human_gate == true`.

- [ ] **Step 6: Commit the daemon half**

```bash
git add crates/swarm-policy/src/ crates/swarm-ingest-runtime/src/ingest/ crates/swarm-runtime-http/src/http/perch/ crates/swarm-runtime-http/src/bin/generate_perch_openapi.rs docs/openapi/perch-operator-v1.json docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml
git commit -s -m "feat(http): GET /v1/operator/policy — rules in file order and the daemon's own triple evaluation"
```

- [ ] **Step 7: Write the failing client mirror test**

Create `policyEvaluation.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { evaluateTripleLocally, SEVERITY_ORDER } from "./policyEvaluation.ts";

const shipped = [
  { index: 0, name: "execution-after-hours-autorespond", decision: "allow", threat_class: "execution", actions: ["deploy_decoy", "escalate"], min_severity: "HIGH", max_severity: "CRITICAL" },
  { index: 1, name: "command-and-control-emergency-block", decision: "allow", threat_class: "command_and_control", actions: ["block_egress", "escalate"], min_severity: "CRITICAL", max_severity: "CRITICAL" },
  { index: 2, name: "credential-access-destructive-deny", decision: "deny", threat_class: "credential_access", actions: ["revoke_credential"], min_severity: "LOW", max_severity: "HIGH" },
];

test("the display mirror agrees with the daemon on the shipped ruleset", () => {
  const v = evaluateTripleLocally(shipped, { threat_class: "command_and_control", severity: "CRITICAL", action: "block_egress" });
  assert.deepEqual(v.map((x) => x.verdict), ["not_matched", "decides", "not_reached"]);
  assert.deepEqual(SEVERITY_ORDER, ["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
});

test("shadowing is per triple, never static: the same rule decides one triple and not another", () => {
  const a = evaluateTripleLocally(shipped, { threat_class: "credential_access", severity: "HIGH", action: "revoke_credential" });
  const b = evaluateTripleLocally(shipped, { threat_class: "credential_access", severity: "CRITICAL", action: "revoke_credential" });
  assert.equal(a[2].verdict, "decides");
  assert.equal(b[2].verdict, "not_matched", "CRITICAL is above max_severity HIGH");
});
```

- [ ] **Step 8: Run to see it fail, then implement the mirror, copy, screen**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-policy/lib/policyEvaluation.test.mjs`
Expected: FAIL — cannot find module.

`policyEvaluation.ts` implements `evaluateTripleLocally(rules, triple)` with `SEVERITY_ORDER` index comparison and the same three rules (`threat_class ===`, `min ≤ severity ≤ max`, `actions.length === 0 || actions.includes(action)`), first match decides, later rules `not_reached`. It is used **only** to keep the evaluator responsive while the daemon's answer is in flight, and the daemon's `evaluation` replaces it on arrival with `<DerivedMarker fn="policyEvaluation.ts:evaluateTripleLocally">` shown while the mirror is on screen and a `disagreement` row if the two ever differ (they must not; the test above pins the shipped ruleset).

`policyCopy.ts`:

```ts
export const POLICY = {
  title: "Policy",
  readOnly: "Read-only. {path} is sha256-pinned inside a signed attestation ({sig}) whose key is not in this repository; an edit here would produce a config the runtime refuses to start on.",
  header: "policy.human_gate_severity = {humanGateSeverity} · policy.lease_ttl_ms = {leaseTtlMs} (the capability lease's authorization window, not the containment lease's TTL)",
  evaluate: "EVALUATE AGAINST",
  verdicts: { decides: "DECIDES THIS TRIPLE", not_matched: "not matched", not_reached: "not reached" },
  outranks: "THIS RULE OUTRANKS THE HUMAN GATE. {action} is destructive and human_gate_severity is {humanGateSeverity}, but this rule matches first and allows it outright at {severity}.",
  allowNote: "no human will be asked for these actions on {threatClass} findings at {min} or above.",
  denyNote: "these are refused before any human sees them.",
  fallthrough: "no rule matched → StaticApprovalGate → RequireHuman at ≥ {humanGateSeverity} for the twelve destructive actions, else static.default_allow (\"authorized for immediate execution\")",
  requestCarried: "threat_class and severity are supplied by the requesting agent. threat_class is read from request.evidence[\"escalation\"][\"threat_class\"] (configurable_gate.rs:34-41); severity is a field on ActionRequest (swarm-policy/src/lib.rs:54-55). An agent chooses which rule judges its own destructive action.",
  window: "active {start}:00–{end}:00 UTC",
  agentLimit: "≤ {n} per agent per minute",
  noRules: {
    title: "policy.rules is empty",
    body: "Every request falls through to the static gate, which asks a human for any of the twelve destructive actions at {humanGateSeverity} or above and allows the rest.",
  },
} as const;
```

`PolicyTripleEvaluator.tsx`: three selects — threat class (twelve slugs), severity (`SEVERITY_ORDER`), action (the fifteen `ResponseActionKind` slugs) — default `command_and_control / CRITICAL / block_egress` (the shipped ruleset's whole reason for the surface); on change, `perchPolicy(triple)` with `perchKeys.policy(triple)`. `PolicyRuleRow.tsx`: index, `name` in mono, `decision` as `ALLOW`/`DENY` (the policy's typed word, rendered as the wire value through `<code>` — the `deny-label` row is case-sensitive on `Deny`/`Denied` as prose; `DENY` in a mono code element is the config literal, and the exemption `PolicyVerdict|policy_verdict` is added to the rendered string as a `data-perch-policy-decision` attribute so the gate's exemption matches), the selector line `threat_class {tc} · actions {list} · {min}…{max}`, the window and agent-limit chips, `reason` through `AdversaryString` (config-authored but rendered as data), the verdict chip from `POLICY.verdicts`, `POLICY.outranks` in the destructive register when `outranks_human_gate` and this rule decides, `allowNote`/`denyNote` under an `ⓘ`-free plain line. `PolicyScreen.tsx` (S7): the `readOnly` banner with `source.path`/`sig`, the `header` line, the evaluator, the rules (file order, never re-sorted), the `fallthrough` line, and the **permanent** `requestCarried` banner (`role="note"`, never conditional). Empty rules → `EmptyState kind="governing-number"` with `POLICY.noRules`, `governingNumber: { label: "policy.human_gate_severity", value, source: "rulesets/default.yaml:93" }`, never `/gaps`.

`perch_reads.rs`: `const ROUTE_POLICY: &str = "/v1/operator/policy";` and `perch_policy(triple: Option<PolicyTripleInput>)`; `tauriPerch.ts` `perchPolicy(triple?)`; `perchKeys.policy(triple)` (`staleTime: 60_000`, `poll: false`); the mock case computes verdicts with `evaluateTripleLocally` over the shipped three rules. `routes/policy.tsx` mirrors Task 10 step 11.

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-policy/lib/policyEvaluation.test.mjs`
Expected: 2 passed.

- [ ] **Step 9: Playwright**

`perch-policy.spec.ts` (`smoke`): `01` — the default triple marks rule 1 `DECIDES THIS TRIPLE`, rule 0 `not matched`, rule 2 `not reached`, and the outranks sentence is present in the destructive register; `02` — changing severity to `HIGH` moves every rule to `not matched` and renders the fallthrough line; `03` — the request-carried banner is present on load and after every evaluation; `04` — no element under `perch-policy-screen` is an editable input other than the three evaluator selects; `05` — a deliberately shadowed test ruleset (the mock's `shadowed` fixture: two `allow` rules with identical selectors) renders the second as `not reached` for the matching triple (`09` §4.2 criterion 3).

Run: `cd workspace/desktop && pnpm typecheck && pnpm test:e2e:smoke -- --grep "Perch policy"`
Expected: 5 passed.

- [ ] **Step 10: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh && bash tools/check-perch-adversary-strings.sh`
Expected: clean (`DENY` renders as a wire value in `<code>` with the `policy_verdict` exemption token in the same extracted string).

```bash
git add workspace/desktop/src/features/perch-policy/ workspace/desktop/src-tauri/src/commands/perch_reads.rs workspace/desktop/src-tauri/src/lib.rs workspace/desktop/src/shared/api/ workspace/desktop/src/testing/perch/e2ePerchBridge.ts workspace/desktop/src/app/routes/policy.tsx workspace/desktop/src/app/routeTree.gen.ts workspace/desktop/tests/e2e/perch-policy.spec.ts workspace/desktop/playwright.config.ts
git commit -s -m "feat(desktop): policy — rules in file order, shadowing evaluated per triple by the daemon, read-only"
```

---

### Task 17: Handoff — `/handoff`, the ReviewSession, and the watch claim

**Files:**
- Create: `workspace/desktop/src/features/perch-shift/lib/reviewSession.ts`, `reviewSession.test.mjs`
- Create: `workspace/desktop/src/features/perch-shift/lib/watchClaim.ts`, `watchClaim.test.mjs`
- Create: `workspace/desktop/src/features/perch-shift/lib/handoffCopy.ts`
- Create: `workspace/desktop/src/features/perch-shift/useWatchClaim.ts`, `useShiftFrontiers.ts`
- Create: `workspace/desktop/src/features/perch-shift/ui/HandoffScreen.tsx`, `WatchClaimPanel.tsx`, `EndWatchSummary.tsx`
- Create or replace: `workspace/desktop/src/app/routes/handoff.tsx`
- Create: `workspace/desktop/tests/e2e/perch-handoff.spec.ts`; modify `playwright.config.ts`
- Modify: `workspace/desktop/src/features/communities/communityScopedRegistry.ts` (`shiftLedger`, `watchClaimCache`)

**Interfaces:**
- Consumes: `AppShellContext`'s three read frontiers `getChannelReadAt(channelId)`, `getThreadReadAt(rootId, channelId?)`, `getMessageReadAt(messageId)` (`app/AppShellContext.tsx:32-48`); `perchListHolds()` → `{ holds, open_count, expired_undecided_count, deciding_stalled_count, store_durable }` (The hold's B2r list shape); `perchListContainments()`; the snooze list (`perchKeys.snoozes()`, `kind:30300` events authored by me — `KIND_EVENT_REMINDER = 30300` in `shared/constants/kinds.ts:68`); the verdicts I recorded this shift (`verdictSpool` + the case timelines' `swarm:verdict:v1` cards with my pubkey); `perchReviewedFindings(sinceMs)` (B3r) for `reviewed / total`; the promoted/suppressed counter from `InstrumentationStrip`'s source; `perchCreateReviewSession({ notes, caseChannels }) -> { session_id }` (the fifth INV-01 write, `POST /v1/operator/review/sessions`, `ReviewSessionCreateRequest { title, notes, artifact_refs }`); `sendChannelMessage` (`shared/api/tauriMessages.ts:5`) for the plain `kind:9` handoff message in each touched case; `useCanvasQuery(channelId)` for each case's canvas `## Handoff notes` section; `WatchClaim` from Task 2's decision (read model only until decided).
- Produces: `composeReviewSession(input: ShiftInput) -> ReviewSessionDraft` where `ReviewSessionDraft = { title: string; notes: string; artifactRefs: string[]; blockers: { expiredUndecided: number } }` and `notes` is the END WATCH block from `04` §2.11 rendered as plain text; `WatchClaim = { holderPubkey: string; holderLabel: string; sinceMs: number; ttlMs: number }`; `claimState(claim, nowMs) -> "none" | "held" | "stale"`; `PERCH_WATCH_CLAIM_TTL_MS = 43_200_000`; `HandoffScreen` (S11, `data-testid="perch-handoff-screen"`) whose End-watch control is disabled while `expired_undecided_count > 0` and enabled only after an explicit acknowledgement row that does not reduce the count (INV-19); `WatchClaimPanel` (`data-testid="perch-watch-claim-panel"`).

- [ ] **Step 1: Write the failing composition test**

Create `reviewSession.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { composeReviewSession } from "./reviewSession.ts";

const input = {
  operator: "connor",
  shiftStartMs: Date.UTC(2026, 2, 17, 22, 0, 0),
  nowMs: Date.UTC(2026, 2, 18, 6, 12, 0),
  cases: [
    { channelId: "27799e23-ab25-4659-b381-3de47ea7ca4d", slug: "case-0042", threatClass: "lateral_movement", readToMs: Date.UTC(2026, 2, 18, 5, 58, 0), canvasLines: 14, openThreadsUnread: 1, archivedAtMs: null, handoffNotes: "web-04 still isolated; ask ops about the rebuild" },
    { channelId: "0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5061", slug: "case-0039", threatClass: "execution", readToMs: null, canvasLines: 0, openThreadsUnread: 0, archivedAtMs: Date.UTC(2026, 2, 18, 3, 11, 0), handoffNotes: null },
  ],
  findings: { reviewed: 87, total: 214 },
  holds: { expiredUndecided: 1 },
  containments: [{ leaseId: "cl_9b3645fc", host: "web-04", remainingMs: 0, expired: true }, { leaseId: "cl_2", host: "db-01", remainingMs: 300_000, expired: false }],
  snoozes: [{ returnsAtMs: Date.UTC(2026, 2, 18, 9, 0, 0) }, { returnsAtMs: Date.UTC(2026, 2, 18, 9, 30, 0) }],
  verdicts: { confirm: 9, dismiss: 1, grant: 1, refuse: 0 },
  promotion: { promoted: 12, suppressed: 340 },
};

test("the END WATCH block carries every resumption fact, including reviewed/unreviewed counts", () => {
  const draft = composeReviewSession(input);
  assert.match(draft.title, /^END WATCH — connor, 22:00 → 06:12$/);
  assert.match(draft.notes, /CASES TOUCHED\s+2/);
  assert.match(draft.notes, /case-0042\s+lateral_movement\s+you read to 05:58 · canvas 14 lines · 1 open thread unread/);
  assert.match(draft.notes, /case-0039\s+archived 03:11/);
  assert.match(draft.notes, /FINDINGS REVIEWED\s+87 \/ 214\s+\(127 unreviewed carry forward\)/);
  assert.match(draft.notes, /HOLDS EXPIRED UNDECIDED\s+1/);
  assert.match(draft.notes, /OPEN CONTAINMENTS\s+2\s+\(1 EXPIRED, host still contained → \/leases\)/);
  assert.match(draft.notes, /SNOOZES RETURNING\s+2\s+next 09:00/);
  assert.match(draft.notes, /VERDICTS RECORDED\s+11\s+9 confirm · 1 dismiss · 1 grant/);
  assert.match(draft.notes, /PROMOTED \/ SUPPRESSED\s+12 \/ 340/);
  assert.match(draft.notes, /HANDOFF NOTES · case-0042\n\s+web-04 still isolated/);
  assert.deepEqual(draft.artifactRefs, ["case:27799e23-ab25-4659-b381-3de47ea7ca4d", "case:0e1d2c3b-4a59-4687-9a0b-1c2d3e4f5061", "containment-lease:cl_9b3645fc", "containment-lease:cl_2"]);
  assert.equal(draft.blockers.expiredUndecided, 1);
});

test("no exclamation mark and no reassurance in the generated notes", () => {
  const draft = composeReviewSession({ ...input, holds: { expiredUndecided: 0 } });
  assert.doesNotMatch(draft.notes, /!/);
  assert.doesNotMatch(draft.notes, /all clear|caught up|looks good|no data|nothing to see/i);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/reviewSession.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement the composer**

`reviewSession.ts`:

```ts
export type ShiftCase = {
  channelId: string;
  slug: string;
  threatClass: string;
  readToMs: number | null;
  canvasLines: number;
  openThreadsUnread: number;
  archivedAtMs: number | null;
  handoffNotes: string | null;
};

export type ShiftInput = {
  operator: string;
  shiftStartMs: number;
  nowMs: number;
  cases: ShiftCase[];
  findings: { reviewed: number; total: number };
  holds: { expiredUndecided: number };
  containments: { leaseId: string; host: string; remainingMs: number; expired: boolean }[];
  snoozes: { returnsAtMs: number }[];
  verdicts: { confirm: number; dismiss: number; grant: number; refuse: number };
  promotion: { promoted: number; suppressed: number };
};

export type ReviewSessionDraft = {
  title: string;
  notes: string;
  artifactRefs: string[];
  blockers: { expiredUndecided: number };
};

const hhmm = (ms: number) => {
  const d = new Date(ms);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
};
const pad = (label: string, value: string) => `  ${label.padEnd(26)}${value}`;

/** 04 §2.11's END WATCH block, as the notes of a ReviewSession. Every number carries its denominator. */
export function composeReviewSession(input: ShiftInput): ReviewSessionDraft {
  const title = `END WATCH — ${input.operator}, ${hhmm(input.shiftStartMs)} → ${hhmm(input.nowMs)}`;
  const lines: string[] = [title, ""];
  lines.push(pad("CASES TOUCHED", String(input.cases.length)));
  for (const c of input.cases) {
    if (c.archivedAtMs !== null) {
      lines.push(`    ${c.slug.padEnd(10)} archived ${hhmm(c.archivedAtMs)}`);
    } else {
      const read = c.readToMs === null ? "nothing read" : `you read to ${hhmm(c.readToMs)}`;
      const threads = `${c.openThreadsUnread} open thread${c.openThreadsUnread === 1 ? "" : "s"} unread`;
      lines.push(`    ${c.slug.padEnd(10)} ${c.threatClass.padEnd(18)} ${read} · canvas ${c.canvasLines} lines · ${threads}`);
    }
  }
  const unreviewed = input.findings.total - input.findings.reviewed;
  lines.push(pad("FINDINGS REVIEWED", `${input.findings.reviewed} / ${input.findings.total}   (${unreviewed} unreviewed carry forward)`));
  lines.push(pad("HOLDS EXPIRED UNDECIDED", `${input.holds.expiredUndecided}${input.holds.expiredUndecided > 0 ? "   must be acknowledged before ending" : ""}`));
  const expired = input.containments.filter((c) => c.expired).length;
  lines.push(pad("OPEN CONTAINMENTS", `${input.containments.length}${expired > 0 ? `   (${expired} EXPIRED, host still contained → /leases)` : ""}`));
  const next = input.snoozes.map((s) => s.returnsAtMs).sort((a, b) => a - b)[0];
  lines.push(pad("SNOOZES RETURNING", `${input.snoozes.length}${next === undefined ? "" : `   next ${hhmm(next)}`}`));
  const v = input.verdicts;
  lines.push(pad("VERDICTS RECORDED", `${v.confirm + v.dismiss + v.grant + v.refuse}   ${v.confirm} confirm · ${v.dismiss} dismiss · ${v.grant} grant${v.refuse ? ` · ${v.refuse} refuse` : ""}`));
  lines.push(pad("PROMOTED / SUPPRESSED", `${input.promotion.promoted} / ${input.promotion.suppressed}`));
  for (const c of input.cases) {
    if (c.handoffNotes) {
      lines.push("", `  HANDOFF NOTES · ${c.slug}`, `    ${c.handoffNotes}`);
    }
  }
  return {
    title,
    notes: lines.join("\n"),
    artifactRefs: [...input.cases.map((c) => `case:${c.channelId}`), ...input.containments.map((c) => `containment-lease:${c.leaseId}`)],
    blockers: { expiredUndecided: input.holds.expiredUndecided },
  };
}
```

- [ ] **Step 4: Run the composer test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/reviewSession.test.mjs`
Expected: 2 passed.

- [ ] **Step 5: Write the failing claim-state test and implement the model**

`watchClaim.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { claimState, PERCH_WATCH_CLAIM_TTL_MS } from "./watchClaim.ts";

test("twelve hours, then stale; none pages everyone", () => {
  assert.equal(PERCH_WATCH_CLAIM_TTL_MS, 43_200_000);
  const claim = { holderPubkey: "ab".repeat(32), holderLabel: "connor", sinceMs: 1_000, ttlMs: PERCH_WATCH_CLAIM_TTL_MS };
  assert.equal(claimState(null, 5_000), "none");
  assert.equal(claimState(claim, 1_000 + PERCH_WATCH_CLAIM_TTL_MS), "held");
  assert.equal(claimState(claim, 1_001 + PERCH_WATCH_CLAIM_TTL_MS), "stale");
});
```

`watchClaim.ts`:

```ts
/** 04 §3.0: proposed 12 h. */
export const PERCH_WATCH_CLAIM_TTL_MS = 43_200_000;

export type WatchClaim = { holderPubkey: string; holderLabel: string; sinceMs: number; ttlMs: number };
export type WatchClaimState = "none" | "held" | "stale";

/** A client-side PAGING FILTER only. It never changes who is p-tagged on a hold (every Approve principal, appendix §4 layer 1). */
export function claimState(claim: WatchClaim | null, nowMs: number): WatchClaimState {
  if (!claim) return "none";
  return nowMs - claim.sinceMs <= claim.ttlMs ? "held" : "stale";
}
```

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-shift/lib/watchClaim.test.mjs`
Expected: 1 passed.

- [ ] **Step 6: Commit the pure modules**

```bash
git add workspace/desktop/src/features/perch-shift/lib/reviewSession.ts workspace/desktop/src/features/perch-shift/lib/reviewSession.test.mjs workspace/desktop/src/features/perch-shift/lib/watchClaim.ts workspace/desktop/src/features/perch-shift/lib/watchClaim.test.mjs
git commit -s -m "feat(desktop): the END WATCH composer and the watch-claim state model"
```

- [ ] **Step 7: The frontiers hook, the copy, the screen**

`handoffCopy.ts`:

```ts
export const HANDOFF = {
  title: "Handoff",
  takeCta: "Take the watch",
  endCta: "End watch and publish handoff",
  noClaim: { title: "No watch is claimed", body: "Classes 1–3 page every Approve-scoped operator until someone takes the watch.", action: { label: "Take the watch" } },
  claimHeld: "Watch held by {holder} since {since}",
  claimStale: "Watch claim by {holder} is {ago} old and stale. Paging has fallen back to everyone.",
  claimDoesNot: "Taking the watch does not change who is p-tagged on a hold — every Approve-scoped operator's queue gets the row. It only decides whose workstation pages for classes 1–3.",
  claimUndecided: "Where the claim is recorded is not yet decided (00-DECISIONS.md §3). Until it is, this panel renders the read model and offers no take control.",
  takeover: "Taking a held watch overwrites the claim and records both times. Nothing gates it; it is logged.",
  blocked: "{n} hold(s) expired undecided this shift. End watch is disabled until each is acknowledged below. Acknowledging changes nothing about the hold.",
  ackRow: "Expired undecided after {minutes}m. Nothing ran. The finding is still open.",
  ackCta: "Acknowledge",
  published: "Handoff published: review session {sessionId}, and a message in each touched case.",
  daemonDown: "End watch needs the running daemon to record the review session. The handoff message can still be published to each case.",
} as const;
```

`useShiftFrontiers.ts` reads `AppShellContext` and, for every case channel joined this shift (channels of `channelType: "stream"` with `perch-case` metadata whose join time ≥ `shiftStartMs` — the shift start is stored in the `shiftLedger` singleton when the watch is taken or, without a claim, the first perch route visit of the session), returns `ShiftCase[]` with `readToMs = getChannelReadAt(channelId)`, `openThreadsUnread` from the case's thread roots where `getThreadReadAt(rootId) < root.lastReplyAt`, `canvasLines` from `useCanvasQuery(channelId).data?.content.split("\n").length`, `handoffNotes` = the text under the `## Handoff notes` heading of that canvas (`caseTemplate.ts` from Task 18 exports `sectionText(markdown, "Handoff notes")`), `archivedAtMs` from the channel row. Open cases are read from the **daemon's** hold list's `case_id`s, not from the channel row alone (`CaseTtlClock`'s caveat: a channel can archive under an active investigation).

`useWatchClaim.ts` returns `WatchClaim | null` from `perchKeys.watchClaim()`; its `queryFn` is the **decision-blocked** seam: it returns `null` until Task 2's row is decided, with the source (`perch.ops_channel` topic / NIP-33 event / daemon field) plugged in here and nowhere else. `GovernanceStrip` (Task 12) already consumes it.

`WatchClaimPanel.tsx`: renders `claimState`: `none` → `HANDOFF.noClaim` (`EmptyState kind="governing-number"`, never `/gaps`) with the take control **absent** and `HANDOFF.claimUndecided` while Task 2 is open; `held` → `claimHeld`; `stale` → `claimStale`; always `claimDoesNot` and `takeover` as body text. Steps 8–11 below add the take/end write path once Task 2 is decided.

`EndWatchSummary.tsx` renders `composeReviewSession(...)`'s `notes` in a `<pre className="text-sm font-mono">` (the block is the artifact; it is not restyled), the acknowledgement rows for each expired-undecided hold (`data-testid={`perch-handoff-ack-${holdId}`}`, `HANDOFF.ackRow`, an `Acknowledge` control that sets a local `acknowledged: Set<holdId>` in the `shiftLedger` singleton — **it does not reduce the count**; INV-19), and the `HANDOFF.endCta` control, `disabled` while `blockers.expiredUndecided > acknowledged.size`, with `HANDOFF.blocked` beside it. On confirm: `perchCreateReviewSession({ notes: draft.notes, caseChannels: cases.map(c => c.channelId) })` through `usePerchWrite` (`sending → settled`; no optimistic state), then `sendChannelMessage(channelId, draft.notes)` into each touched case (a plain `kind:9`, no marker — the handoff is a human message, not an engine card; `perch_sign_gate` lets it through because line 0 is `END WATCH — …`), then `HANDOFF.published`. Daemon unreachable → `HANDOFF.daemonDown`, the case messages still publish.

`HandoffScreen.tsx` (S11): `WatchClaimPanel` on top, `EndWatchSummary` below, `InstrumentationStrip readOnly` restating the C9 numbers with a link to `/`. `routes/handoff.tsx` mirrors Task 10 step 11 (`/handoff`, `kind="handoff"`).

- [ ] **Step 8: BLOCKED on Task 2 — the claim's write path, option (a)**

If `00-DECISIONS.md` §3 records option (a): `takeWatch()` sets the `perch.ops_channel`'s topic to `watch:{myPubkeyHex}:{nowMs}` through the existing channel-metadata mutation (`features/channels/hooks.ts`'s topic edit → `kind:9002`), `endWatch()` sets it to `watch:none`; `useWatchClaim` parses the channel's `topic` and the relay's `kind:40099` `topic_changed` rows give the audit trail. The panel's take control renders and the strip's line follows.

- [ ] **Step 9: BLOCKED on Task 2 — option (b)**

If option (b): `takeWatch()` publishes `kind:30078` with `d = "perch-watch-claim"` and content `{ holder: myPubkeyHex, since_ms }` through `send_channel_message`'s kind parameter path (a NIP-33 addressable event; `perch_sign_gate` admits it — it is neither `46010` nor a `kind:9` marker); `useWatchClaim` runs a REQ `{kinds:[30078], "#d":["perch-watch-claim"], limit:1}` (an **eighth** REQ — `perchSubscriptions.ts`'s "seven, no more" comment must be amended with the decision row cited, and `perchSteadyStateReqFrames` re-asserted at 8).

- [ ] **Step 10: BLOCKED on Task 2 — option (c)**

If option (c): a sixth INV-01 write is required; this plan does **not** add it. Record the daemon item as a First-card-style bill row and leave `takeWatch()` absent; the panel keeps `claimUndecided`.

- [ ] **Step 11: BLOCKED on Task 2 — the Playwright half of the claim**

Whichever option lands, add to `perch-handoff.spec.ts`: `05` — taking the watch renders `Watch held by …` on `/handoff` and on the governance strip; `06` — a claim `advanceClock`'d past 12 h renders `stale` in both places and the strip says `classes 1–3 page everyone`.

- [ ] **Step 12: Playwright for the unblocked half**

`perch-handoff.spec.ts` (`smoke`): `01` — with the fixture's two cases joined and `holds: [expired undecided h_1c28ae79]`, `/handoff` renders the END WATCH block with `HOLDS EXPIRED UNDECIDED 1` and `perch-handoff-end` disabled; `02` — pressing `perch-handoff-ack-h_1c28ae79` enables `perch-handoff-end` and the count in the block still reads `1` (INV-19); `03` — confirming records exactly one `perch_create_review_session` call in the mock (`readPerchCounter(page, "perch_create_review_session_calls") === 1`) and one `send_channel_message` per touched case, and renders `HANDOFF.published`; `04` — with no claim, the panel reads `No watch is claimed` and has zero `gap-link`s.

Run: `cd workspace/desktop && pnpm typecheck && pnpm test:e2e:smoke -- --grep "Perch handoff"`
Expected: `01`–`04` pass; `05`/`06` are `test.fixme` until Task 2 is decided, each `fixme` naming the decision row.

- [ ] **Step 13: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh && bash tools/check-perch-write-allowlist.sh`
Expected: clean; the write allowlist still reads exactly five (the review-session route was already the fifth).

```bash
git add workspace/desktop/src/features/perch-shift/ workspace/desktop/src/features/communities/communityScopedRegistry.ts workspace/desktop/src/app/routes/handoff.tsx workspace/desktop/src/app/routeTree.gen.ts workspace/desktop/tests/e2e/perch-handoff.spec.ts workspace/desktop/playwright.config.ts
git commit -s -m "feat(desktop): handoff — the END WATCH review session, blocked on expired-undecided acknowledgement"
```

---

### Task 18: Case Canvas tab, the kill-chain graph, and the swarmctl terminal pinned to a case

**Files:**
- Create: `workspace/desktop/src/features/perch-evidence/lib/caseTemplate.ts`, `caseTemplate.test.mjs`
- Create: `workspace/desktop/src/features/perch-evidence/lib/caseIncident.ts`
- Create: `workspace/desktop/src/features/perch-evidence/ui/CaseCanvasTab.tsx`, `CaseTtlClock.tsx`, `KillChainGraph.tsx`
- Modify: `workspace/desktop/src/features/perch-evidence/ui/CaseScreen.tsx` (The hold's; adds the `Canvas` tab and the terminal pin — the file is new in The hold and has budget)
- Create: `workspace/desktop/src/features/terminal/terminalCaseScope.ts`, `terminalCaseScope.test.mjs`
- Modify: `workspace/desktop/src/features/terminal/terminalClient.ts:5-15` (`caseId?: string`, `caseSlug?: string`), `TerminalBootstrap.tsx` (the banner line + re-pin on case change), `workspace/desktop/src-tauri/src/terminal_runtime.rs:28-40` (`case_id: Option<String>`, `case_slug: Option<String>`), `:415-445` (cwd + env)
- Modify: `workspace/desktop/src/features/communities/communityScopedRegistry.ts` (`caseCanvasSeeded`)
- Create: `workspace/desktop/tests/e2e/perch-case-canvas.spec.ts`, `perch-terminal.spec.ts`; modify `playwright.config.ts`

**Interfaces:**
- Consumes: `ChannelCanvas` (`features/channels/ui/ChannelCanvas.tsx`, unchanged: `{ channelId, canEdit, isArchived }`), `useCanvasQuery(channelId, enabled)` / `useSetCanvasMutation(channelId)` (`features/channels/hooks.ts:966`, `:979`); `perchGetIncident(incidentId)` (Task 14) returning `IncidentRecord` with `included_members`/`rejected_members` (`IncidentMemberDecision { investigation_id, hunt_id, finding_id, reason, shared_keys, evidence_links: { dimension, explanation, shared_values, weight }[], confidence_score }`, `crates/swarm-spine/src/incident.rs:99-170`) and `graph_dimensions`; the case's `incident_id` from the hold record's `rationale` / the promotion response (B3i returns `incident_id`, stored in the case's `perch` metadata by The hold); `TerminalAttachRequest` (`terminalClient.ts:5-15`), `AttachRequest` (`terminal_runtime.rs:28-40`), `fence_env` + `context_vars` (`:429-444`), `portable_pty::CommandBuilder::cwd`; `swarmctl`'s twelve global `--*-results-dir` flags default to **relative** `data/…` paths (`crates/swarm-cli/src/core.inc:119-152`), so a per-case working directory scopes every default without flag injection; `channels.ttl_deadline` (`shared/api/types.ts`).
- Produces: `PERCH_CASE_TEMPLATE` (five headings, nothing else); `sectionText(markdown, heading) -> string | null`; `CaseCanvasTab` (`perch-case-canvas`, `perch-case-canvas-seeded`, `perch-case-canvas-seed-retry`); `CaseTtlClock` (`perch-case-ttl`); `KillChainGraph` with a **required** `rejected` prop (VIZ-3, `perch-killchain`); `caseTerminalScope(caseId, slug, stateRoot) -> { cwd: string; env: [string, string][] }` with `AMBUSH_CASE_ID`, `AMBUSH_CASE`, `SWARM_RESULTS_ROOT`; the terminal banner line `124 of 126 swarmctl subcommands are not HTTP clients. This is a real shell on this host. · pinned to {slug}`.

- [ ] **Step 1: Write the failing template test**

Create `caseTemplate.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { PERCH_CASE_TEMPLATE, sectionText, shouldSeed } from "./caseTemplate.ts";

test("five fixed headings, no prose, no placeholders", () => {
  assert.equal(PERCH_CASE_TEMPLATE, ["## Timeline", "", "## Hypothesis", "", "## Actions taken", "", "## Open questions", "", "## Handoff notes", ""].join("\n"));
  assert.doesNotMatch(PERCH_CASE_TEMPLATE, /TODO|example|e\.g\./i);
});

test("seed only a canvas that never had content, only with edit rights, only once per channel", () => {
  const seeded = new Set();
  assert.equal(shouldSeed({ content: null, isSuccess: true, canEdit: true, channelId: "a", seeded }), true);
  seeded.add("a");
  assert.equal(shouldSeed({ content: null, isSuccess: true, canEdit: true, channelId: "a", seeded }), false);
  assert.equal(shouldSeed({ content: "", isSuccess: true, canEdit: true, channelId: "b", seeded }), false, "an emptied canvas has had content");
  assert.equal(shouldSeed({ content: null, isSuccess: true, canEdit: false, channelId: "c", seeded }), false);
  assert.equal(shouldSeed({ content: null, isSuccess: false, canEdit: true, channelId: "d", seeded }), false);
});

test("sectionText reads the text under one heading and null when the heading is absent", () => {
  const md = "## Timeline\n02:38 promoted\n\n## Handoff notes\nweb-04 still isolated\nask ops\n";
  assert.equal(sectionText(md, "Handoff notes"), "web-04 still isolated\nask ops");
  assert.equal(sectionText(md, "Hypothesis"), null);
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-evidence/lib/caseTemplate.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement the template module**

`caseTemplate.ts`:

```ts
/**
 * Five fixed markdown headings and nothing else. No prose, no placeholders,
 * no examples: an operator must not have to delete a machine's guesses at
 * 03:00, and a template with sample text becomes a template nobody edits.
 * 04 §2.4's four plus Handoff notes, which /handoff reads (17 §6.14).
 */
export const PERCH_CASE_TEMPLATE = ["## Timeline", "", "## Hypothesis", "", "## Actions taken", "", "## Open questions", "", "## Handoff notes", ""].join("\n");

export function shouldSeed(input: { content: string | null; isSuccess: boolean; canEdit: boolean; channelId: string; seeded: Set<string> }): boolean {
  return input.isSuccess && input.content === null && input.canEdit && !input.seeded.has(input.channelId);
}

/** The text under `## {heading}` up to the next `## `, trimmed; null when the heading is absent. */
export function sectionText(markdown: string, heading: string): string | null {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((l) => l.trim() === `## ${heading}`);
  if (start === -1) return null;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => l.startsWith("## "));
  return rest.slice(0, end === -1 ? rest.length : end).join("\n").trim();
}
```

- [ ] **Step 4: Run the template test**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch-evidence/lib/caseTemplate.test.mjs`
Expected: 3 passed.

- [ ] **Step 5: The tab, the clock, the graph**

`CaseTtlClock.tsx` (`17` §6.12): renders `channels.ttl_deadline` as a wall clock (`archives at 08:12` / `archives in 5h 12m`, `text-xs` label, `text-sm` figure, `aria-live="off"`), never a bar, with the caveat tooltip `a failed TTL refresh is downgraded to a warning (schema.sql:984-988), so a case can archive under an active investigation; open cases are read from the daemon`.

`CaseCanvasTab.tsx` (`17` §6.14) wraps `<ChannelCanvas channelId={caseChannelId} canEdit={canEdit} isArchived={isArchived} />` unchanged; a `useEffect` runs `shouldSeed(...)` against `useCanvasQuery(caseChannelId)` and, when true, adds the id to the `caseCanvasSeeded` singleton (`CommunityScopedSingleton` member with a resetter — switching communities must not re-seed a case whose canvas an operator deliberately emptied) and calls `setCanvasMutation.mutateAsync(PERCH_CASE_TEMPLATE)` exactly once; states `loading`, `empty-seeding` (the five headings render immediately from the constant, `data-testid="perch-case-canvas-seeded"`), `ready`, `editing`, `read-only`, `relay-degraded` (`ChannelCanvas` already renders `RELAY_UNREACHABLE_SHORT`), `seed-failed` (the headings render as **uncommitted** text with `perch-case-canvas-seed-retry`; never an empty canvas shown as saved). The tab header carries `CaseTtlClock`. Below the canvas, the read-only `KillChainGraph` figure for the case's incident (`useIncidentQuery(incidentId)`), or, for a hand-promoted case with a single-member incident, the VIZ-3 `empty` state sentence `this case was promoted by hand, so the correlation stage has produced no graph; a verdict recorded now attaches to the single-member incident record minted at promotion`.

`KillChainGraph.tsx` (VIZ-3, `18` §6): props `{ incidentId, included: IncidentMemberDecision[], rejected: IncidentMemberDecision[], dimensions: IncidentGraphDimension[], state: VizState }` — `rejected` has no default and no optional marker; a fixed column/row grid computed once (no force layout); nodes `232×56` `rounded-md`, `--perch-card` fill, a 2.5 px evidence top rail, three lines (`strategy_id` `text-sm` mono; `host · finding_id · confidence` `text-xs`; `reason` `text-2xs` truncated to 33 characters with the whole reason in the table); edges typed by dimension as four dash patterns (`temporal` solid, `causal` `4 2`, `entity` `2 2`, `semantic` `6 3`), never four colours; rejected members below a 1 px `--perch-border-strong` rule at 62 % opacity with a `3 3` dashed border and the `reason` printed in full; above 12 nodes the drawing keeps the seed plus its direct links and the rest goes to the table; `role="img"`, `<title>`, a sentence `aria-label`, and the mandatory `TableToggle` (Task 19's shared component — if Task 19 has not landed, the graph ships its own minimal `<table>` toggle and Task 19 replaces it) with one row per member, an included/rejected column and the **full** `finding_id`. Colour reaches every node through `viz.css` classes only (Task 19 lands `viz.css`; until then the graph's stylesheet is `killChain.css` under `src/shared/styles/globals/`, folded into `viz.css` by Task 19).

- [ ] **Step 6: The case screen's tab and the terminal pin**

In `CaseScreen.tsx` add the `Canvas` tab beside `Timeline · Members · Evidence`, and pass `caseId`/`caseSlug` to the terminal panel: `TerminalBootstrap` reads `useTerminalCaseScope()` (below) and includes `caseId`, `caseSlug` in `TerminalConnection.attach(...)`'s request; when the open case changes, the panel re-attaches (a new PTY under the new cwd) and the banner says `re-pinned to {slug}`.

- [ ] **Step 7: BLOCKED on Task 1 — agent rows on the graph**

The node's first line renders the producing agent as a text slug (`whisker-7a3f`) beside `strategy_id`. When Task 1 lands artwork, `RoleGlyph` replaces the slug's leading text glyph; until then no glyph is drawn and no placeholder box is reserved.

- [ ] **Step 8: Write the failing terminal-scope test**

`terminalCaseScope.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { caseTerminalScope, TERMINAL_BANNER_LINE } from "./terminalCaseScope.ts";

test("a case pin is a working directory plus three env vars, so swarmctl's relative data/ defaults land under the case", () => {
  const scope = caseTerminalScope("27799e23-ab25-4659-b381-3de47ea7ca4d", "case-0042", "/var/lib/ambush/perch");
  assert.equal(scope.cwd, "/var/lib/ambush/perch/cases/27799e23-ab25-4659-b381-3de47ea7ca4d");
  assert.deepEqual(scope.env, [
    ["AMBUSH_CASE_ID", "27799e23-ab25-4659-b381-3de47ea7ca4d"],
    ["AMBUSH_CASE", "case-0042"],
    ["SWARM_RESULTS_ROOT", "/var/lib/ambush/perch/cases/27799e23-ab25-4659-b381-3de47ea7ca4d"],
  ]);
});

test("a slug that is not shell-safe is replaced by the id, never interpolated", () => {
  const scope = caseTerminalScope("27799e23-ab25-4659-b381-3de47ea7ca4d", "$(rm -rf /)", "/root");
  assert.equal(scope.env[1][1], "27799e23-ab25-4659-b381-3de47ea7ca4d");
});

test("the banner is the non-fiction line", () => {
  assert.equal(TERMINAL_BANNER_LINE, "124 of 126 swarmctl subcommands are not HTTP clients. This is a real shell on this host.");
});
```

- [ ] **Step 9: Run to see it fail, then implement**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/terminal/terminalCaseScope.test.mjs`
Expected: FAIL — cannot find module.

`terminalCaseScope.ts`:

```ts
/** 04 §2.13. The PTY is the operator's tool, not an agent's (08 §7.7 control 4). */
export const TERMINAL_BANNER_LINE = "124 of 126 swarmctl subcommands are not HTTP clients. This is a real shell on this host.";

const SAFE_SLUG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * swarmctl's twelve `--*-results-dir` flags default to RELATIVE `data/…` paths
 * (crates/swarm-cli/src/core.inc:119-152), so pinning the shell's working
 * directory under the case scopes every default without injecting flags, and
 * every invocation is attributable to the case by its path.
 */
export function caseTerminalScope(caseId: string, caseSlug: string, stateRoot: string): { cwd: string; env: [string, string][] } {
  const slug = SAFE_SLUG.test(caseSlug) ? caseSlug : caseId;
  const cwd = `${stateRoot}/cases/${caseId}`;
  return {
    cwd,
    env: [
      ["AMBUSH_CASE_ID", caseId],
      ["AMBUSH_CASE", slug],
      ["SWARM_RESULTS_ROOT", cwd],
    ],
  };
}
```

Rust side, `terminal_runtime.rs`: add `case_id: Option<String>`, `case_slug: Option<String>` to `AttachRequest` (`:28-40`); after `fence_env(...)` and the `context_vars` loop (`:429-444`), when `request.case_id` is `Some`: validate it is a UUID (`uuid::Uuid::parse_str`), compute `cwd = app_data_dir.join("perch/cases").join(case_id)`, `std::fs::create_dir_all(&cwd)`, `command.cwd(&cwd)`, and `command.env("AMBUSH_CASE_ID", …)`, `("AMBUSH_CASE", slug-or-id)`, `("SWARM_RESULTS_ROOT", cwd)` — the same three names the TS scope computes, so the two sides are tested against one table. Keys are inserted after `fence_env` because it `env_clear()`s first. `TerminalBootstrap.tsx` renders `TERMINAL_BANNER_LINE · pinned to {slug}` in the panel header (`data-testid="perch-terminal-banner"`) and re-attaches on `caseId` change.

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/terminal/terminalCaseScope.test.mjs && cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml terminal_runtime`
Expected: 3 passed; the existing terminal Rust tests pass with the two optional fields absent.

- [ ] **Step 10: Playwright**

`perch-case-canvas.spec.ts` (`smoke`): `01` — opening a fresh case's `Canvas` tab renders the five headings immediately (`perch-case-canvas-seeded`) and records exactly one `set_channel_canvas` mock call; `02` — reopening the same case seeds nothing (call count stays 1); `03` — a case whose canvas is `""` is not seeded; `04` — the kill-chain figure for the fixture incident renders `included` nodes and the `rejected` half below the rule with reasons in full, and its table toggle lists every `finding_id` untruncated; `05` — `CaseTtlClock` renders a wall clock and no `<progress>`.

`perch-terminal.spec.ts` (`smoke`): `01` — `⌘J` on `/cases/{id}` opens the panel whose header contains `pinned to case-0042` and the banner line; `02` — the mock's last `terminal_attach` request carries `caseId` and `caseSlug`; `03` — navigating to a second case re-pins (a second attach with the new id).

Run: `cd workspace/desktop && pnpm typecheck && pnpm test:e2e:smoke -- --grep "Perch case canvas|Perch terminal"`
Expected: 8 passed.

- [ ] **Step 11: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh && bash tools/check-perch-adversary-strings.sh`
Expected: clean — the `IncidentMemberDecision.reason` strings render through `AdversaryString`.

```bash
git add workspace/desktop/src/features/perch-evidence/ workspace/desktop/src/features/terminal/ workspace/desktop/src-tauri/src/terminal_runtime.rs workspace/desktop/src/features/communities/communityScopedRegistry.ts workspace/desktop/tests/e2e/perch-case-canvas.spec.ts workspace/desktop/tests/e2e/perch-terminal.spec.ts workspace/desktop/playwright.config.ts
git commit -s -m "feat(desktop): case canvas seeded once, the kill-chain graph with its refused half, and the terminal pinned to a case"
```

---

### Task 19: Watchfloor — `/watch-floor`, bare chrome, and the chart primitives

**Files:**
- Modify: `crates/swarm-perch-bridge/src/coalesce.rs` (add the completed ingest, concentration and agent reducers), `src/alarm.rs` (26003/26005 dual publication), `src/lib.rs`, `src/metrics.rs`; `crates/swarm-runtime-http/src/bin/swarm_detect.rs` (typed governance-status provider); `crates/swarm-perch-wire/src/frames.rs`, the 26000 schema, TypeScript mirror and golden (add the missing `shed` count consistently)
- Create: `workspace/desktop/src/shared/time/domains.ts` (skip if The hold landed it)
- Create: `workspace/desktop/src/shared/viz/types.ts`, `scales.ts`, `concentration.ts`, `concentration.test.mjs`, `markers.tsx`, `TableToggle.tsx`, `defs.tsx`, `viz.css`, `RateSparkline.tsx`, `sourceAttribution.ts`, `sourceAttribution.test.mjs`
- Create: `workspace/desktop/src/features/perch-evidence/ui/ConcentrationCurve.tsx`, `HostHeat.tsx`
- Create: `workspace/desktop/src/features/perch-policy/ui/WatchfloorScreen.tsx`, `ColonyHealthBand.tsx`, `ModeBand.tsx`, `lib/watchfloorCopy.ts`
- Modify: `workspace/desktop/src/features/perch-evidence/ui/LaneHeader.tsx` (Task 11's curve slot), `workspace/desktop/src/features/agents/ui/AgentStatusBadge.tsx:58` (a `pulse?: boolean` prop, default true, so the wall passes `false` — the file is at 60 lines), `workspace/desktop/src/shared/styles/globals.css` (`@import "./viz/viz.css"` inside the `@import` block, above `@config`)
- Create: `workspace/desktop/scripts/check-svg-font-size.mjs` (from `build/viz/`), `tools/check-perch-chart-tokens.sh` (from `build/viz/`); modify `workspace/desktop/package.json` (`check:svg-font-size`, chained), `.github/workflows/ci.yml` (one `run:` step)
- Create or replace: `workspace/desktop/src/app/routes/watch-floor.tsx`
- Create: `workspace/desktop/tests/e2e/perch-watchfloor.spec.ts`, `perch-charts.spec.ts`; modify `playwright.config.ts`

**Interfaces:**
- Consumes: `derivePerchShellRoute` returning `chrome: "bare"` for `watchfloor` (`perchViews.ts`); `getPerchEphemeralSnapshot()` — `concentrations` (26001, 12 classes at 1 Hz), `agents: Map<agentId, PerchAgentFrame>` (26002), `mode` (26003), `ingest` (26000: `accepted`, `rejected`, `by_source`, `shed`); `perchDeposits(threatClass)` (Task 4) for regime A; `policy` per class from the deposits response or, on the wall, from the `26001` frame's `policy` block if the bridge carries it — else from the daemon's `perchPolicy()` per class (Task 16 serves `policy.rules`, not thresholds; thresholds come from `perchDeposits(...).policy` and are cached per class with `staleTime: 300_000`); `SourceCount` + `agentIdOfSource` (`shared/ui/perch/SourceCount.tsx`, imported, never reimplemented — `17` §7 item 5); `DerivedMarker`; `AgentStatusBadge` with its 15 s grace; `useStableMap` (`shared/hooks/useStableReference.ts`).
- Produces: `UnixSeconds`/`UnixMillis` brands; `VizState`, `EmptyReason`, `DegradedDetail`, `ThreatClassPolicy`, `SourceAttribution`, `sourceCounts(...)`; `strengthAt(deposit, nowSeconds)`, `concentrationAt(deposits, nowSeconds, policy)`, `snapshotEpsilon(policy, served)`, `snapshotDisagrees(derived, served, policy)`, `interpolate(sample, atSeconds, halfLifeSecs)`; `linearScale`, `sparkScale`; `<DerivedMarker>`/`<ServedMarker route>`; `<TableToggle rows>`; `<VizDefs>` mounted once; the paint classes `.viz-series-1…6`, `.stop-series-1…6`, `.viz-threshold`, `.viz-incident`, `.viz-grid`, `.viz-hatch`, `.viz-axis`; `ConcentrationCurve` (VIZ-1), `HostHeat` (VIZ-2), `RateSparkline` (VIZ-6); `WatchfloorScreen` (S8, `perch-watchfloor`); G1 and G2 wired.

- [ ] **Step 0: Make every Watchfloor frame real before building its consumer (W3-29).** Extend `coalesce.rs` with closed reducers: 26000 counts `Ingest` accepted/rejected/by collector source plus `shed`; 26001 is last-wins over `ConcentrationSnapshot` with an exact `coalesced_from`; 26002 is last health per agent plus an allowlisted `AgentAction.action_kind` tally whose `details`/`hunt_id` never cross the boundary. `alarm.rs` publishes 26003 and the path-free/count-only 26005 immediately from their uncoalesced disk records, then commits only on `OK true`. Add a typed `governance_status` provider to `BridgeBuildInput` (a closure over `IngestState::current_governance_status`, so the bridge still does not depend on `swarm-ingest-runtime`) and publish 26004 on change plus a 15-second heartbeat. The telemetry publisher drains at most one frame per tick for its identity, always prioritizing 26001; the other kinds retain their latest aggregate until sent, so the 50-frames/5-second admission budget is structurally respected. Amend the neutral 26000 DTO/schema/TS mirror/golden with `shed: u64` in this same commit. Unit tests cover reduction, privacy-field absence, priority/fairness, byte size and retry; the ignored relay test publishes and observes each kind 26000–26005 from an admitted identity. Run the bridge, wire, parity and live tests and commit this engine half before any Watchfloor mock-backed UI commit.

- [ ] **Step 1: Write the failing concentration test**

Create `workspace/desktop/src/shared/viz/concentration.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { concentrationAt, interpolate, snapshotDisagrees, snapshotEpsilon, strengthAt } from "./concentration.ts";

const policy = { half_life_secs: 3600, evaporation_threshold: 0.01, min_sources_for_escalation: 2, alert_threshold: 2, incident_threshold: 5 };
const key = "swarm:ed25519:18085f16811dba240c5bf9ef0c0d0bc6f359e7812cdedf86e7519852307ce470";
const deposits = [
  { agent_id: `${key}:suspicious_process_tree`, strategy_id: "suspicious_process_tree", threat_class: "execution", severity: "CRITICAL", confidence: 0.9, timestamp: 1773738872, decay_half_life: 3600, indicator: {}, event_id: "hunt-evt-1" },
  { agent_id: `${key}:suspicious_scripting`, strategy_id: "suspicious_scripting", threat_class: "execution", severity: "CRITICAL", confidence: 0.9, timestamp: 1773738872, decay_half_life: 3600, indicator: {}, event_id: "hunt-evt-1" },
  { agent_id: `${key}:suspicious_process_tree`, strategy_id: "suspicious_process_tree", threat_class: "execution", severity: "CRITICAL", confidence: 0.9, timestamp: 1773738881, decay_half_life: 3600, indicator: {}, event_id: "hunt-evt-2" },
];

test("the closed form reproduces the canonical checkpoints to six decimals", () => {
  assert.equal(concentrationAt(deposits.slice(0, 2), 1773738872, policy).total_strength.toFixed(6), "1.800000");
  assert.equal(concentrationAt(deposits, 1773738881, policy).total_strength.toFixed(6), "2.696884");
  assert.equal(concentrationAt(deposits, 1773738965, policy).total_strength.toFixed(6), "2.653617");
  assert.equal(concentrationAt(deposits, 1773738965, policy).distinct_sources, 2);
});

test("CR-4: a sample at t excludes deposits with timestamp > t", () => {
  assert.equal(concentrationAt(deposits, 1773738875, policy).total_strength.toFixed(6), (2 * strengthAt(deposits[0], 1773738875)).toFixed(6));
});

test("the tolerance is the evaporation floor, served, and >= trips", () => {
  assert.equal(snapshotEpsilon(policy, 2.65), 0.01);
  assert.equal(snapshotDisagrees(2.65, 2.66, policy), true);
  assert.equal(snapshotDisagrees(2.65, 2.659, policy), false);
});

test("regime B interpolation is exponential, never linear", () => {
  const s0 = { at: 1773738881, total_strength: 2.696884, distinct_sources: 2, peak_confidence: 0.9 };
  const at = 1773738881 + 3600;
  assert.equal(interpolate(s0, at, 3600).toFixed(6), (2.696884 / 2).toFixed(6));
});
```

- [ ] **Step 2: Run to see it fail**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/shared/viz/concentration.test.mjs`
Expected: FAIL — cannot find module.

- [ ] **Step 3: Implement the shared layer**

`shared/time/domains.ts` (if absent):

```ts
declare const S: unique symbol;
declare const M: unique symbol;
export type UnixSeconds = number & { readonly [S]: true };
export type UnixMillis = number & { readonly [M]: true };
export const nowSeconds = (): UnixSeconds => Math.floor(Date.now() / 1000) as UnixSeconds;
export const nowMillis = (): UnixMillis => Date.now() as UnixMillis;
// No conversion helper is exported. Crossing domains is named at the call site (07 §8).
```

`shared/viz/types.ts` — verbatim `18` §3.3: `VizState`, `EmptyReason`, `DegradedDetail`, `ThreatClassPolicy`, `SourceAttribution`, `DepositView`, `SuppressionMarker`, `ConcentrationSample`. `sourceAttribution.ts`:

```ts
import { agentIdOfSource } from "@/shared/ui/perch/SourceCount";
import type { SourceAttribution } from "./types";

/** Render law 2 at the call site: both numbers from one function, never a bare count. */
export function sourceCounts(a: Extract<SourceAttribution, { kind: "ids" }>): { sources: number; agents: number } {
  return { sources: new Set(a.sourceIds).size, agents: new Set(a.sourceIds.map(agentIdOfSource)).size };
}

export function attributionText(a: SourceAttribution): string {
  if (a.kind === "ids") {
    const { sources, agents } = sourceCounts(a);
    return `${sources} source${sources === 1 ? "" : "s"} / ${agents} agent${agents === 1 ? "" : "s"}`;
  }
  return `${a.distinctSources} source${a.distinctSources === 1 ? "" : "s"} / agent count not carried`;
}
```

with `sourceAttribution.test.mjs` asserting `attributionText({kind:"ids", sourceIds:[`${key}:a`, `${key}:b`]}) === "2 sources / 1 agent"` and the operator-feedback bare id counts as its own agent (the `17` §4.8 shape guard).

`concentration.ts`:

```ts
import type { UnixSeconds } from "@/shared/time/domains";
import type { ConcentrationSample, DepositView, ThreatClassPolicy } from "./types";

/** crates/swarm-core/src/pheromone.rs:281-287, verbatim. */
export function strengthAt(d: Pick<DepositView, "confidence" | "timestamp" | "decay_half_life">, now: number): number {
  if (now <= d.timestamp) return d.confidence;
  return d.confidence * Math.pow(0.5, (now - d.timestamp) / d.decay_half_life);
}

/** substrate.rs:1268-1304's reduction over a slice B4 already suppressed and evaporated. CR-4 excludes deposits after `now`. */
export function concentrationAt(deposits: readonly DepositView[], now: number, policy: ThreatClassPolicy): { total_strength: number; distinct_sources: number; peak_confidence: number } {
  let total = 0;
  let peak = 0;
  const sources = new Set<string>();
  for (const d of deposits) {
    if (d.timestamp > now) continue;
    const s = strengthAt(d, now);
    if (s < policy.evaporation_threshold) continue;
    if (s <= 0) continue;
    total += s;
    peak = Math.max(peak, d.confidence);
    sources.add(d.agent_id);
  }
  return { total_strength: total, distinct_sources: sources.size, peak_confidence: peak };
}

/** THE one epsilon (registry §2, A11): one deposit's worth, served by the daemon, never a percentage of an unrelated dial. */
export function snapshotEpsilon(policy: ThreatClassPolicy, served: number): number {
  return Math.max(policy.evaporation_threshold, 1e-9 * Math.abs(served));
}

/** `>=`: a deposit contributing exactly the floor is the smallest real event, and it must trip. */
export function snapshotDisagrees(derived: number, served: number, policy: ThreatClassPolicy): boolean {
  return Math.abs(served - derived) >= snapshotEpsilon(policy, served);
}

/** Regime B: S(t) = S(t0) · 2^(−(t − t0)/H). Exact only if every live deposit carries H — the caption names the assumption. */
export function interpolate(sample: ConcentrationSample, atSeconds: number, halfLifeSecs: number): number {
  return sample.total_strength * Math.pow(0.5, (atSeconds - sample.at) / halfLifeSecs);
}

export function forwardSegmentNote(): string {
  return "forward segment is an extrapolation and a lower bound: decay only subtracts and a new deposit only adds — except after a suppression, which subtracts retroactively";
}
```

`scales.ts` — `linearScale(domain, range)`, `sparkScale(values, height)` (window min–max, never zero-based; a flat series centred). `markers.tsx` — `DerivedMarker` re-exported from `shared/ui/perch/DerivedMarker` plus `ServedMarker({ route })` rendering `served · {route}` in `text-2xs`. `TableToggle.tsx` — `{ rows: Record<string, string | number>[]; caption: string; label: string }` rendering a real `<table>` behind a `<details>` (`data-testid="perch-viz-table"`). `defs.tsx` — one `<svg width="0" height="0" aria-hidden><defs>` with `perchHatch` (45°, 1 px, 6 px pitch, `.viz-hatch` stroke) and `perchAreaGrad` (`.stop-series-1` at offset 0 with `stop-opacity .30`, offset 1 at `.02`), mounted once in `WatchfloorScreen` and `LaneHeader`. `viz.css`:

```css
/* desktop/src/shared/viz/viz.css — the only place a chart names a colour. */
.viz-series-1 { fill: hsl(var(--perch-viz-series-1)); stroke: hsl(var(--perch-viz-series-1)); }
.viz-series-2 { fill: hsl(var(--perch-viz-series-2)); stroke: hsl(var(--perch-viz-series-2)); }
.viz-series-3 { fill: hsl(var(--perch-viz-series-3)); stroke: hsl(var(--perch-viz-series-3)); }
.viz-series-4 { fill: hsl(var(--perch-viz-series-4)); stroke: hsl(var(--perch-viz-series-4)); }
.viz-series-5 { fill: hsl(var(--perch-viz-series-5)); stroke: hsl(var(--perch-viz-series-5)); }
.viz-series-6 { fill: hsl(var(--perch-viz-series-6)); stroke: hsl(var(--perch-viz-series-6)); }
.stop-series-1 { stop-color: hsl(var(--perch-viz-series-1)); }
.stop-series-2 { stop-color: hsl(var(--perch-viz-series-2)); }
.stop-series-3 { stop-color: hsl(var(--perch-viz-series-3)); }
.stop-series-4 { stop-color: hsl(var(--perch-viz-series-4)); }
.stop-series-5 { stop-color: hsl(var(--perch-viz-series-5)); }
.stop-series-6 { stop-color: hsl(var(--perch-viz-series-6)); }
.viz-threshold { stroke: hsl(var(--perch-chart-rule)); fill: none; stroke-opacity: .6; stroke-dasharray: 5 5; }
.viz-incident  { stroke: hsl(var(--perch-sev-critical)); fill: none; stroke-dasharray: 2 6; }
.viz-grid      { stroke: hsl(var(--perch-viz-grid)); fill: none; }
.viz-unfilled  { fill: hsl(var(--perch-viz-unfilled)); }
.viz-hatch     { stroke: hsl(var(--perch-viz-suppressed-hatch)); stroke-opacity: var(--perch-alpha-hatch, .35); }
.viz-axis      { fill: hsl(var(--perch-chart-axis-ink)); }
.viz-rule-label { fill: hsl(var(--perch-chart-rule-label)); }
.viz-danger-mark { stroke: hsl(var(--perch-danger-mark)); }
.viz-plot-ground { fill: hsl(var(--perch-card)); }
@media (prefers-reduced-motion: reduce) { .crossring { display: none; } }
```

The tokens `--perch-viz-series-1…6`, `--perch-chart-rule`, `--perch-chart-rule-label`, `--perch-chart-axis-ink`, `--perch-viz-grid`, `--perch-viz-unfilled` (T7's name, never `-track`), `--perch-viz-suppressed-hatch`, `--perch-alpha-hatch: 0.35` are added to Ground's `perch.css` in **both** theme blocks as HSL triplets aliased over Quiet's tokens (`--perch-viz-grid` = `--perch-border`, `--perch-viz-unfilled` = `--perch-surface-raised`, `--perch-viz-suppressed-hatch` = `--perch-foreground-muted`, series 1 = the substrate mark, series 3 = the authority mark, the rest from `18` §3.2's six-value palette measured ≥ 3:1 on every surface), and `node docs/plans/ambush-ui/build/viz/contrast.mjs --check` is pointed at `workspace/desktop/src/shared/styles/globals/perch.css` (its `CSS` constant becomes an argv path) and must exit 0.

- [ ] **Step 4: Run the shared-layer tests**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/shared/viz/concentration.test.mjs src/shared/viz/sourceAttribution.test.mjs && node docs/plans/ambush-ui/build/viz/contrast.mjs --check workspace/desktop/src/shared/styles/globals/perch.css`
Expected: 6 passed; contrast check exit 0 (run the last command from the repository root).

- [ ] **Step 5: Commit the shared layer**

```bash
git add workspace/desktop/src/shared/viz/ workspace/desktop/src/shared/time/domains.ts workspace/desktop/src/shared/styles/globals/perch.css workspace/desktop/src/shared/styles/globals.css docs/plans/ambush-ui/build/viz/contrast.mjs
git commit -s -m "feat(desktop): the shared chart layer — closed form, the one epsilon, paint classes, table toggle"
```

- [ ] **Step 6: VIZ-1 `ConcentrationCurve`**

`ConcentrationCurve.tsx` with the `18` §4.1 props verbatim (`threatClass, policy, samples, deposits | null, suppressions, now, nowFromDaemon, attribution, state`), 960-unit viewBox, `max-width: 960px`, the geometry of `18` §4.2 (label gutter to 174, plot 186→940, deposit trains 32 apart, area gradient `url(#perchAreaGrad)`, curve `stroke-width 2` `stroke-linejoin round` via `.viz-series-1`, threshold rule `.viz-threshold` with its **literal config value** labelled 8 px above via `.viz-rule-label` `text-2xs`, the `incident_threshold` rule `.viz-incident` or, off-scale, a `2 6` dashed rule at the top labelled `incident_threshold 5.00 — above this view`, drop-line and `r=5` crossing dot with a one-shot `.crossring`); y from 0 to `max(alert_threshold × 1.35, peak) × 1.08`, never zero-suppressed; x ticks at 0/¼/½/¾/1 in `HH:MM`; ≤ 120 sampled points in a `useMemo` keyed on the newest sample; deposit trains (regime A) one row per strategy-scoped source with dot radius `2.6 + 2.2 × confidence` and opacity `0.35 + 0.55 × (strengthAt/confidence)`, a suppressed dot kept with a `.viz-danger-mark` cross; the nine states of `18` §4.5 including `disagrees` (snap to the served value, caption `snapshotDisagrees → true`, folded within one second) and `suppressed` (hatched span `url(#perchHatch)`, marker line `DISMISSED HH:MM by <operator>` through `AdversaryString`, visible step, the arithmetic preview sentence of `18` §4.6 with its three load-bearing clauses); caption `total_strength N.NN · {attributionText} · peak_confidence N.NN` with `<ServedMarker route="GET /v1/operator/pheromone/deposits">` beside the served number and `<DerivedMarker fn="concentration.ts:concentrationAt">` beside the curve; the ±30 s skew warning when `|now − nowFromDaemon| > 30`; `role="img"`, `<title>Concentration decay — {threatClass}</title>`, sentence `aria-label`, `TableToggle` with one row per deposit (`agent`, `strategy_id`, `host_id`, `timestamp`, `confidence`, `strength_at`). Every `<text>` carries `className="text-2xs viz-axis"` or `"text-sm"` — no `font-size` attribute anywhere. Mount it in `LaneHeader`'s `perch-lane-curve-slot` (regime A, 90 min window).

- [ ] **Step 7: VIZ-2 `HostHeat` and VIZ-6 `RateSparkline`**

`HostHeat.tsx` (`18` §5): `rows` computed by the caller from the deposits slice (per-host `Σ strengthAt`, `attribution` ids per host, `depositCount`, `dominantThreatClass`) with one plate-level `<DerivedMarker fn="HostHeat:perHostSum — the runtime has no per-host concentration">`; sorted bars, `--perch-viz-series-1` to the threshold and `--perch-viz-series-3` beyond it, a 1 px `.viz-threshold` tick at the same x on every bar; the unattributed row `host unattributed · no host_id on N deposits` always last; empty state = swarm-produced-nothing (`Concentration 0.00 on every host` + the 18/11 sentence + `/gaps` via `EmptyState kind="swarm-produced-nothing"`); `VirtualizedList` above 200 rows; `TableToggle`.

`RateSparkline.tsx` (`18` §9): `{ values: number[]; seriesClass: "viz-series-1" | "sev-medium" | "sev-high"; stale?: boolean; label: string; value: string }`, 60×16 or 220×22, `stroke-width 1.5`, last point `r=1.5`, min–max scale with the caption saying so, a stale series **stops** rather than flat-lining, `aria-hidden` on the path (the number beside it is the announcement), a `by_source` stacked bar capped at five + `other` (the cap is applied by the bridge), and `shed` as its own series from the 26000 gauge's `shed` field — never merged with `rejected`. The plate sentence about the ingest stream the console refuses to carry (`18` §9.3) renders beneath.

- [ ] **Step 8: The wall screen**

`watchfloorCopy.ts`:

```ts
export const WATCHFLOOR = {
  title: "Watchfloor",
  decay: "DECAY FIELD · 12 classes · curve is an interpolation; the header number is the runtime's",
  colony: "COLONY · {n} agents · liveness from the 26002 health stream (never Nostr presence: a dead agent reads online for up to 180 s there)",
  mode: "MODE",
  cooldown: "deescalation_cooldown_secs {n} · {remaining}s remaining",
  stale: "No concentration snapshot for {seconds}s. Curves below are the last received values, not current ones.",
  noClicks: "This screen changes nothing. Decisions are recorded on /.",
  regimeB: "regime B · snapshot-only · assumes every live deposit carries half_life_secs {h}",
} as const;
```

`WatchfloorScreen.tsx` (S8): renders under `chrome: "bare"` (the governance strip survives above it); three bands — `DECAY FIELD` (twelve `ConcentrationCurve`s in regime B from the 26001 samples, 60 min window, `deposits: null`, `attribution: { kind: "count-only", reason: "concentration-frame" }`, keyed and memoized with `useStableMap` so eleven unchanged classes bail per tick, one `<VizDefs>` for the whole wall), `COLONY` (`ColonyHealthBand`: eight roles × instances from the 26002 frames on `AgentStatusBadge` with `pulse={false}` — **never** pulsing on the wall — and the 15 s grace kept; a role with no instance renders its slug in muted ink, not an empty cell), `MODE` (`ModeBand`: `normal | ALERT | INCIDENT` monotonic upward with `transition_down` rendered as the de-escalation row naming no class, and the cooldown as a number). No control on the screen mutates anything (`WATCHFLOOR.noClicks` in the footer). `RateSparkline`s for `accepted`, `rejected`, `shed` sit in the header. Budget: ≤ 4 ms `ScriptDuration` per 1 Hz tick — the interpolated "now" marker moves by a CSS transform on one `<g>`; measured by `tests/e2e/perf/watchfloor-busy.perf.ts` (register it in the `perf` project if one exists, else in `smoke` behind `test.skip(!process.env.PERCH_PERF)`).

`routes/watch-floor.tsx` mirrors Task 10 step 11 (`/watch-floor`, `kind="watchfloor"`); `AppShell`'s chrome conditional (The hold) already hides the rail and sidebar for `bare`.

- [ ] **Step 9: BLOCKED on Task 1 — colony band glyphs**

`ColonyHealthBand` renders each role as its text slug in `text-sm` mono. When Task 1 lands artwork, `RoleGlyph` is placed before the slug at size 16; no box is reserved until then.

- [ ] **Step 10: G1 and G2, wired with their first subject**

Copy `docs/plans/ambush-ui/build/viz/check-svg-font-size.mjs` to `workspace/desktop/scripts/check-svg-font-size.mjs` (its allowlist entries for `EmojiBurstProvider.tsx` and `ProfileAvatarEditor.utils.ts` stay; re-verify the line numbers with the script's own self-test), add `"check:svg-font-size": "node ./scripts/check-svg-font-size.mjs src"` to `workspace/desktop/package.json` and append `&& pnpm check:svg-font-size` to `check`. Copy `docs/plans/ambush-ui/build/viz/check-perch-chart-tokens.sh` to `tools/check-perch-chart-tokens.sh`; its default scan roots become `workspace/desktop/src/shared/viz` plus every `*Curve*`/`*Heat*`/`*Sparkline*`/`*Timeline*`/`*Graph*` file under `workspace/desktop/src/features/perch*/` (in-repository now — no `PERCH_DESKTOP_ROOT`, no second checkout: replace the variable's default with `"$ROOT_DIR/workspace/desktop"`); R4's 38-name alternation gains the `--ambush-*` names (`--ambush-index`, `--ambush-ink`, `--ambush-plate`, …, the 33 `--ambush-` variables in `theme.css`) because under D3 those are the live shadcn-equivalents a chart must not read. Add to `.github/workflows/ci.yml`'s `gates` job:

```yaml
      - name: Check Perch chart tokens
        run: bash tools/check-perch-chart-tokens.sh
```

Run: `cd workspace/desktop && pnpm check:svg-font-size && cd ../.. && bash tools/check-perch-chart-tokens.sh && bash tools/check-gates-wired.sh`
Expected: `check-svg-font-size: OK (… files, self-test 7 caught / 6 controls clean, …)`; `check-perch-chart-tokens: OK (N file(s); self-test: 4 rules fired …)`; the wiring gate is clean.

- [ ] **Step 11: Playwright**

`perch-charts.spec.ts` (`smoke`): `01` — on `/lanes/{id}` with the fixture deposits, the curve's caption shows `total_strength 2.65` from the served number and the plot renders exactly two deposit-train rows; `02` — after `__AMBUSH_E2E_PERCH_CONTROL__.dismiss("hunt-evt-1")` the curve renders the hatched span, the marker line `DISMISSED … by perch-operator-1`, two crossed dots that are **still present**, and the arithmetic sentence containing `a detector you did not review`; `03` — a served snapshot differing from the interpolation by ≥ 0.01 renders `snapshotDisagrees → true` and the curve snaps to the served value; `04` — every chart under the page has `role="img"`, a `<title>`, and a `perch-viz-table` toggle; `05` — no `<text>` element under any chart has a `font-size` attribute (a DOM sweep).

`perch-watchfloor.spec.ts` (`smoke`): `01` — `/watch-floor` renders no sidebar and no colony rail (`app-sidebar`, `community-rail` absent) while `perch-governance-strip` is present; `02` — twelve curves render in `escalation.rs` order, each captioned `regime B`; `03` — no `AgentStatusBadge` under `perch-watchfloor` carries `animate-pulse`; `04` — a 26003 `incident → alert` frame renders the de-escalation row `the daemon named no threat class`; `05` — telemetry silence for 6 s renders `WATCHFLOOR.stale` with the literal age.

Run: `cd workspace/desktop && pnpm typecheck && pnpm test:e2e:smoke -- --grep "Perch charts|Perch watchfloor"`
Expected: 10 passed.

- [ ] **Step 12: The 72-hour soak, stated not skipped**

`09` §5 exit criterion 1 (72 h on a spare monitor, no memory climb) is a manual run at milestone exit: `docs/PERCH-DEV.md` gains a `## Watchfloor soak` section with the command (`pnpm tauri dev` against the dev compose, `/watch-floor`, Activity Monitor's memory column sampled hourly) and the pass condition (< 10 % RSS growth over 72 h). It is not automated and this plan does not claim it is.

- [ ] **Step 13: Gates and commit**

Run: `cd workspace/desktop && pnpm check && cd ../.. && bash tools/check-copy-banned-terms.sh && bash tools/check-perch-chart-tokens.sh`
Expected: clean.

```bash
git add workspace/desktop/src/features/perch-evidence/ui/ConcentrationCurve.tsx workspace/desktop/src/features/perch-evidence/ui/HostHeat.tsx workspace/desktop/src/features/perch-evidence/ui/LaneHeader.tsx workspace/desktop/src/features/perch-policy/ workspace/desktop/src/features/agents/ui/AgentStatusBadge.tsx workspace/desktop/src/shared/viz/RateSparkline.tsx workspace/desktop/src/app/routes/watch-floor.tsx workspace/desktop/src/app/routeTree.gen.ts workspace/desktop/scripts/check-svg-font-size.mjs workspace/desktop/package.json tools/check-perch-chart-tokens.sh .github/workflows/ci.yml workspace/desktop/tests/e2e/perch-charts.spec.ts workspace/desktop/tests/e2e/perch-watchfloor.spec.ts workspace/desktop/playwright.config.ts docs/PERCH-DEV.md
git commit -s -m "feat(desktop): the Watchfloor under bare chrome, and the concentration, host-heat and rate charts"
```

---

### Task 20: The remaining CI gates (P2-C4, P2-C5, P2-C6) and the copy gate's SVG asset rewrite

**Files:**
- Create: `workspace/desktop/scripts/check-route-tree.mjs` (from `build/skeleton/desktop/scripts/`); modify `workspace/desktop/package.json`
- Create: `tools/check-perch-surface-count.sh`, `tools/perch-surfaces.tsv`
- Create: `tools/check-perch-notification-fields.sh`; create `workspace/desktop/src/features/perch/notifications/copy.ts`, `notificationBodies.test.mjs`
- Modify: `.github/workflows/ci.yml` (two `run:` steps)
- Modify: `tools/copy-scope.tsv` (`docs/assets`: `deferred` → `required`)
- Modify: the twelve SVGs under `docs/assets/`

**Interfaces:**
- Consumes: `workspace/desktop/src/app/routes.ts` and `routeTree.gen.ts`; `app/perchViews.ts`'s `PERCH_NAV`; `APPENDIX-NORMATIVE.md` §1's fourteen surfaces; `04` §3.2's four wake classes; `06` §7.2's typed-field allowlist (`actionKind`, `severity`, `threatClass`, `inverseKind`, `rollbackStatus`, `cardKind`, `perchLabel`, `holdIdShort`, `leaseIdShort`, `relative`, `n`, `m`, `strength`, `incidentThreshold`); `tools/check-copy-banned-terms.sh` (First card, W3-24) and its asset half over `docs/assets/`; `tools/check-gates-wired.sh`.
- Produces: `pnpm check:route-tree` (exit 1 on any path declared in one file and absent from the other; exit 2 on a parse that finds zero routes); `tools/check-perch-surface-count.sh` asserting exactly fourteen rows in `tools/perch-surfaces.tsv` and that every routed row's path appears in `routes.ts` and every unrouted row's component file exists; `tools/check-perch-notification-fields.sh` failing on any `{name}` interpolation in `features/perch/notifications/copy.ts` outside the fourteen-name allowlist and on more or fewer than four exported wake-class bodies; `NOTIFICATION_BODIES` with exactly four keys `incident`, `holdNamedYou`, `containmentFailedToRelease`, `snoozeDue`; `docs/assets/*.svg` clean under `bash tools/check-copy-banned-terms.sh`.

- [ ] **Step 1: The route-tree gate**

Copy `docs/plans/ambush-ui/build/skeleton/desktop/scripts/check-route-tree.mjs` to `workspace/desktop/scripts/check-route-tree.mjs`; add `"check:route-tree": "node ./scripts/check-route-tree.mjs"` and append `&& pnpm check:route-tree` to `check`. Under D3 `routes.ts` carries Ambush's existing routes plus the ten perch routes and no redirect stubs (W3-5); the extractor counts whatever is declared.

Run: `cd workspace/desktop && pnpm check:route-tree`
Expected: `21 route paths in sync` (the existing twelve plus eight new Operator-complete routes
landed by Tasks 10–19 plus `/cases/$caseId` from The hold), exit 0. Then plant a break: add
`route("/nowhere", "nowhere.tsx")` to `routes.ts` without regenerating → exit 1 naming
`/nowhere`; revert.

- [ ] **Step 2: The surface-count gate**

Create `tools/perch-surfaces.tsv`:

```
# tools/perch-surfaces.tsv -- the fourteen surfaces of APPENDIX-NORMATIVE.md §1 (ADR 0011 clause 1, inside the perch feature area only under D3).
# Read by tools/check-perch-surface-count.sh, which asserts EXACTLY fourteen rows, that every routed row's path is declared in workspace/desktop/src/app/routes.ts, and that every row's component file exists.
id	surface	route	component
S1	The Watch	/	workspace/desktop/src/features/perch-watch/ui/WatchScreen.tsx
S2	Verdict Row	-	workspace/desktop/src/features/perch-watch/ui/VerdictPane.tsx
S3	Case	/cases/$caseId	workspace/desktop/src/features/perch-evidence/ui/CaseScreen.tsx
S4	Case Canvas	-	workspace/desktop/src/features/perch-evidence/ui/CaseCanvasTab.tsx
S5	Lanes	/lanes/$laneId	workspace/desktop/src/features/perch-evidence/ui/LaneScreen.tsx
S6	Containments	/leases	workspace/desktop/src/features/perch-containment/ui/ContainmentBoard.tsx
S7	Policy	/policy	workspace/desktop/src/features/perch-policy/ui/PolicyScreen.tsx
S8	Watchfloor	/watch-floor	workspace/desktop/src/features/perch-policy/ui/WatchfloorScreen.tsx
S9	Ledger	/ledger	workspace/desktop/src/features/perch-shift/ui/LedgerScreen.tsx
S10	Tuning bench	/tuning	workspace/desktop/src/features/perch-policy/ui/TuningScreen.tsx
S11	Handoff	/handoff	workspace/desktop/src/features/perch-shift/ui/HandoffScreen.tsx
S12	Gaps	/gaps	workspace/desktop/src/features/perch-policy/ui/GapsScreen.tsx
S13	swarmctl terminal	-	workspace/desktop/src/features/terminal/terminalCaseScope.ts
S14	Governance strip	-	workspace/desktop/src/features/perch/ui/GovernanceStrip.tsx
```

Create `tools/check-perch-surface-count.sh` in the house shape (`set -euo pipefail`, a fixture pass first — a throwaway TSV with fifteen rows must fail, thirteen must fail, fourteen with a missing component must fail, the real one must pass — then the real scan; `python3` standard library only, no `PERCH_DESKTOP_ROOT`, roots under `$ROOT_DIR/workspace/desktop`). Wire it:

```yaml
      - name: Check the Perch surface count is exactly fourteen
        run: bash tools/check-perch-surface-count.sh
```

Run: `bash tools/check-perch-surface-count.sh && bash tools/check-gates-wired.sh`
Expected: `clean: 14 surfaces, 10 routed, 4 unrouted`; wiring clean.

- [ ] **Step 3: Write the failing notification-bodies test**

Create `workspace/desktop/src/features/perch/notifications/notificationBodies.test.mjs`:

```js
import assert from "node:assert/strict";
import { test } from "node:test";

import { NOTIFICATION_BODIES, NOTIFICATION_FIELDS } from "./copy.ts";

test("exactly four wake classes, and every interpolation is a typed field", () => {
  assert.deepEqual(Object.keys(NOTIFICATION_BODIES).sort(), ["containmentFailedToRelease", "holdNamedYou", "incident", "snoozeDue"]);
  for (const body of Object.values(NOTIFICATION_BODIES)) {
    for (const [, name] of body.matchAll(/\{([a-zA-Z]+)\}/g)) {
      assert.ok(NOTIFICATION_FIELDS.includes(name), `${name} is not a typed field`);
    }
    assert.doesNotMatch(body, /!/);
  }
});

test("class 3 carries no TTL-backstop sentence, because the TTL has already failed", () => {
  assert.doesNotMatch(NOTIFICATION_BODIES.containmentFailedToRelease, /backstop|self-releases|TTL will/i);
  assert.match(NOTIFICATION_BODIES.containmentFailedToRelease, /will not clear on its own/);
});
```

- [ ] **Step 4: Run to see it fail, then implement the copy and the gate**

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch/notifications/notificationBodies.test.mjs`
Expected: FAIL — cannot find module.

`copy.ts`:

```ts
/** 06 §7.2's typed-field allowlist. tools/check-perch-notification-fields.sh reads this array. */
export const NOTIFICATION_FIELDS = [
  "actionKind", "severity", "threatClass", "inverseKind", "rollbackStatus", "cardKind", "perchLabel",
  "holdIdShort", "leaseIdShort", "relative", "n", "m", "strength", "incidentThreshold",
] as const;

/**
 * The four wake classes (04 §3.2). A fifth key here fails
 * tools/check-perch-notification-fields.sh. Findings never page.
 * OS notification bodies are rendered by the OS, so no adversary-controlled
 * string may reach them: every interpolation is a typed field.
 */
export const NOTIFICATION_BODIES = {
  incident: "Mode INCIDENT · {threatClass} · strength {strength} crossed incident_threshold {incidentThreshold}",
  holdNamedYou: "A held {actionKind} at {severity} names you · hold {holdIdShort} · decide within {relative}",
  containmentFailedToRelease: "Containment lease {leaseIdShort} expired and the sweep failed. The host is still contained. This will not clear on its own.",
  snoozeDue: "Snooze returned · {cardKind} {perchLabel}",
} as const;
```

`tools/check-perch-notification-fields.sh`: fixture first (a planted `{command_line}` must fail; a planted fifth key must fail; the real file must pass), then `awk` over `workspace/desktop/src/features/perch/notifications/copy.ts`: extract `NOTIFICATION_FIELDS`, extract every `{name}` inside `NOTIFICATION_BODIES`, fail on any name outside the array, fail on a key count ≠ 4. Wire it:

```yaml
      - name: Check the Perch notification bodies interpolate only typed fields
        run: bash tools/check-perch-notification-fields.sh
```

`use-feed-desktop-notifications.ts`'s perch branch (The hold) reads `NOTIFICATION_BODIES` by key and nothing else.

Run: `cd workspace/desktop && node --import ./test-loader.mjs --experimental-strip-types --test src/features/perch/notifications/notificationBodies.test.mjs && cd ../.. && bash tools/check-perch-notification-fields.sh && bash tools/check-gates-wired.sh`
Expected: 2 passed; `clean: 4 wake classes, 14 typed fields`; wiring clean.

- [ ] **Step 5: Commit the three gates**

```bash
git add workspace/desktop/scripts/check-route-tree.mjs workspace/desktop/package.json tools/check-perch-surface-count.sh tools/perch-surfaces.tsv tools/check-perch-notification-fields.sh workspace/desktop/src/features/perch/notifications/ .github/workflows/ci.yml
git commit -s -m "chore(ci): route-tree, surface-count and notification-field gates (P2-C4, P2-C5, P2-C6)"
```

- [ ] **Step 6: Activate the asset scope and measure the violations**

Change the single `tools/copy-scope.tsv` row for `docs/assets` from `deferred` to
`required`, retaining a reviewed reason that names this task. This working-tree change makes the
gate red until Step 7 clears the corpus; the status flip and the rewrites land atomically in Step
8, so no committed SHA claims the scope without enforcing it.

Run: `bash tools/check-copy-banned-terms.sh 2>&1 | tee /tmp/copy-gate-assets.txt; grep -c "docs/assets" /tmp/copy-gate-assets.txt`
Expected (per `16` §6.3, measured 2026-08-30): **41** hits in **12** files across **8** rows — `bare-lane` 14 (`architecture` 4, `architecture-mobile` 2, `security-v2` 2, `security-mobile-v2` 2, `pillars` 2, `pillars-mobile` 2), `trust-claim` 7, `bare-source-count` 4 (`stigmergy`, `stigmergy-mobile`), `hunt-noun` 4 (`paths`, `paths-mobile`), `clowder` 4 (`roadmap`, `roadmap-mobile`), `legacy-codename` 4, `approve` 2, `bare-lease` 2. If First card's P0-25 already rewrote any, the residue is what this step prints; work from the printed list, not from the table.

- [ ] **Step 7: Rewrite the twelve assets**

Every hit is in an `aria-label` or a `<text>` node. Rewrite in place, keeping geometry and ids:

| Row | Replace | With |
|---|---|---|
| `bare-lane` | `ASYNC LANE`, `CONTEXT LANE`, `EVOLUTION LANE`, `critical lane`, `hot lane` | `ASYNC STREAM`, `CONTEXT STREAM`, `EVOLUTION STREAM`, `critical path`, `hot path` (the ruled words: `stream` for a transport class, `path` for the fast path) |
| `trust-claim` | `Proof`, `proof of …`, `trusted`, `verified by` | `Receipt`, `receipt for …`, `admitted`, `attestation matches this body` |
| `bare-source-count` | `3 sources` | `3 sources / 1 agent` (stigmergy draws one host and three detectors on one agent — the law's own case) |
| `hunt-noun` | `hunt` / `hunts` as a noun | `case` / `cases` (`hunt_id` and `hunt-evt-1` field labels stay) |
| `clowder` | `clowder`, `clowders` | `colony`, `colonies` |
| `legacy-codename` | `Swarm Team Six` | `Ambush` |
| `approve` | `Approve`, `approval` | `record a decision`, `human decision` |
| `bare-lease` | `lease` | `capability lease` or `containment lease`, whichever the figure draws |

Then the `px-text` sibling rule from `18` G1 (an SVG `font-size="11"` attribute is what `check-px-text` cannot see): the assets are README art, not product surfaces, and G1 scans `desktop/src` only — leave their `font-size` attributes alone; note it in the commit body.

Run: `bash tools/check-copy-banned-terms.sh`
Expected: exit 0 over `docs/assets/`, and the perch roots unchanged. Open each rewritten SVG in a browser once and confirm the text still fits its box (a `<text>` that grew by six characters can overflow a 138×42 rectangle — widen the `rect` `width` rather than shrinking the font).

- [ ] **Step 8: Commit**

```bash
git add tools/copy-scope.tsv docs/assets/
git commit -s -m "docs(assets): rewrite the twelve README diagrams to clear the copy gate (41 hits, 8 rows)"
```

---

### Task 21: Packaging — compose hardening, and the relay trio in the Helm chart

**Files:**
- Modify: `docker-compose.yml`; create `docker-compose.perch.env.example`, `docs/DEPLOYMENT.md`
- Modify: `deploy/helm/swarm-team-six/Chart.yaml`, `values.yaml`, `values-production.yaml`, `templates/deployment.yaml`
- Create: `deploy/helm/swarm-team-six/templates/networkpolicy.yaml`, `templates/perch-secret.yaml`, `tests/perch_test.yaml`, `tests/networkpolicy_test.yaml`, `ci/perch-values.yaml`
- Modify: `.github/workflows/ci.yml` (a `helm-lint` step in an existing job that has no toolchain besides `python3` gains `azure/setup-helm`; or reuse `workspace-ci.yml`'s chart job — see step 8)

**Interfaces:**
- Consumes: the Ground compose services `relay`, `postgres`, `redis` beside `swarm-detect` and `nats` (`01-DESIGN.md` §12); the relay chart `workspace/deploy/charts/ambush` (`version: 0.1.8`, optional `postgresql`/`redis` OCI subcharts, `secrets.existingSecret`, `relayUrl`, `ownerPubkey`, `relay.bindAddr: "0.0.0.0:3000"`, health on `/_liveness` `/_readiness`); the engine chart (`swarm-team-six`, `service.port: 9090`, `secrets.files`, `swarmConfig` rendered into a ConfigMap, `persistence.mountPath: /var/lib/swarm`); `PerchBridgeConfig` keys (`perch.enabled`, `relay_url`, `nostr_seed_env`, `spine_seed_env`, `auth_tag_env`, `spool_dir`, `lane_channels`); `OperatorAuthConfig.token_env` (`SWARM_OPERATOR_TOKEN`); brief C2 (the relay lives inside the operator's network boundary, never on the internet; daemon ports are never routable from the operator LAN — `09` §9 S3, S4).
- Produces: a `docker compose --profile perch up` that brings up `swarm-detect` (bridge enabled, `rulesets-dev/perch-dev.yaml`), `relay`, `postgres`, `redis` with pinned image digests, loopback-only published ports, healthchecks on every service, secrets from `.env.perch`, memory limits, and the relay's `AMBUSH_RELAY_PRIVATE_KEY` provisioned by `scripts/provision-perch.sh`; `helm install ambush-dev deploy/helm/swarm-team-six -f ci/perch-values.yaml` bringing up daemon + NATS + relay + Postgres + Redis in one command (`09` §4.2 criterion 6) with a `NetworkPolicy` that admits the console's CIDR to the relay's `3000` only, the relay to Postgres/Redis only, and nothing to `9090` except the console CIDR's operator subnet; `docs/DEPLOYMENT.md` stating the five services, the six secrets, the relay's forty migrations (auto-applied), the retention window as an audit requirement, and the `/v2/api` polling note.

- [ ] **Step 1: Write the failing compose contract test**

Create `tools/check-perch-compose.sh` (a gate; lands with its `run:` step in step 8) whose fixture pass plants a `docker-compose.yml` with an unpinned image (`image: postgres:17-alpine`), a world-published port (`"3000:3000"`) and a service with no `healthcheck`, and asserts all three fail; then over the real file it asserts, with `python3` + `yaml` **absent** (the CI image has only the standard library), using a line-oriented scan: every `image:` under the `perch` profile services carries `@sha256:`; every `ports:` entry begins `"127.0.0.1:`; every service has a `healthcheck:` block; the `relay` service has `env_file: [.env.perch]` and **no** inline `AMBUSH_RELAY_PRIVATE_KEY`; the `swarm-detect` service sets `PERCH_BRIDGE_NOSTR_SEED`, `PERCH_BRIDGE_SPINE_SEED` and `SWARM_OPERATOR_TOKEN` only through `env_file`.

Run: `bash tools/check-perch-compose.sh`
Expected: FAIL on the real file (the Ground compose is unpinned and unprofiled).

- [ ] **Step 2: Harden the compose**

Edit `docker-compose.yml` so the four perch services sit under `profiles: [perch]`, e.g.

```yaml
  relay:
    image: ghcr.io/backbay-labs/ambush@sha256:<digest of the release the dev stack runs>
    profiles: [perch]
    env_file: [.env.perch]
    environment:
      DATABASE_URL: postgres://ambush:${POSTGRES_PASSWORD}@postgres:5432/ambush
      REDIS_URL: redis://redis:6379
      RELAY_URL: ws://127.0.0.1:3000
    ports:
      - "127.0.0.1:3000:3000"
    depends_on:
      postgres: { condition: service_healthy }
      redis: { condition: service_healthy }
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:3000/_readiness || exit 1"]
      interval: 5s
      timeout: 3s
      retries: 12
    deploy: { resources: { limits: { memory: 512m } } }
    restart: unless-stopped
```

with `postgres` (`postgres@sha256:…`, `127.0.0.1:5432`, `pg_isready`, a named volume, 512m) and `redis` (`redis@sha256:…`, `127.0.0.1:6379`, `redis-cli ping`, 128m) alike; `swarm-detect` gains `profiles: [default, perch]`, `env_file: [.env.perch]`, `--config /app/rulesets-dev/perch-dev.yaml` under the profile (an override in `docker-compose.perch.yml` is acceptable if the profile cannot carry a different `command`), the spool volume `perch-spool:/var/lib/ambush/perch-spool`, and its existing `9090` binding narrowed to `"127.0.0.1:9090:9090"`. Create `docker-compose.perch.env.example`:

```
# copy to .env.perch; scripts/provision-perch.sh fills the relay key and the two bridge seeds
POSTGRES_PASSWORD=change-me
AMBUSH_RELAY_PRIVATE_KEY=
PERCH_BRIDGE_NOSTR_SEED=
PERCH_BRIDGE_SPINE_SEED=
PERCH_BRIDGE_AUTH_TAG=
SWARM_OPERATOR_TOKEN=
```

and add `.env.perch` to `.gitignore` (verify `tools/check-no-committed-keys.sh` stays green — the example carries empty values).

Run: `bash tools/check-perch-compose.sh && docker compose --profile perch config >/dev/null`
Expected: gate clean; compose config parses.

- [ ] **Step 3: Bring the stack up once**

Run: `cp docker-compose.perch.env.example .env.perch && bash scripts/provision-perch.sh --fill-env .env.perch && docker compose --profile perch up -d && sleep 20 && docker compose --profile perch ps && curl -fsS http://127.0.0.1:9090/readyz && curl -fsS http://127.0.0.1:3000/_readiness && docker compose --profile perch down`
Expected: five services `healthy`; both readiness probes 200; the relay's log shows its migrations applied on start.

- [ ] **Step 4: Commit the compose**

```bash
git add docker-compose.yml docker-compose.perch.env.example .gitignore tools/check-perch-compose.sh
git commit -s -m "chore(deploy): harden the perch dev compose — pinned digests, loopback ports, healthchecks, env-file secrets"
```

- [ ] **Step 5: The Helm dependency**

Edit `deploy/helm/swarm-team-six/Chart.yaml`:

```yaml
dependencies:
  - name: nats
    version: 0.1.0
    repository: file://charts/nats
    condition: nats.enabled
  # The Ambush relay chart lives in this repository under workspace/ (D2). Aliased
  # so its templates render under `relay`, whatever the umbrella is finally called
  # (00-DECISIONS.md §3, "The engine chart's name after D3").
  - name: ambush
    alias: relay
    version: 0.1.8
    repository: file://../../../workspace/deploy/charts/ambush
    condition: relay.enabled
```

Add to `values.yaml`:

```yaml
relay:
  enabled: false
  relayUrl: ""            # wss://relay.<colony>.internal — REQUIRED when enabled
  ownerPubkey: ""         # the operator's 64-hex Nostr pubkey
  postgresql: { enabled: true }   # quickstart; production sets false and externalPostgresql
  redis: { enabled: true }
  secrets: { existingSecret: "" }

perch:
  enabled: false
  # One Secret carrying PERCH_BRIDGE_NOSTR_SEED, PERCH_BRIDGE_SPINE_SEED,
  # PERCH_BRIDGE_AUTH_TAG and SWARM_OPERATOR_TOKEN. Created by templates/perch-secret.yaml
  # from `values` ONLY when existingSecret is empty (dev); production points at a Secret
  # created out of band.
  existingSecret: ""
  seeds: { nostr: "", spine: "", authTag: "", operatorToken: "" }
  spoolSize: 2Gi

networkPolicy:
  enabled: false
  # CIDRs allowed to reach the relay's 3000 and the daemon's 9090. Brief C2: the relay
  # is inside the operator's boundary; 9090 is never routable from the operator LAN
  # except from the console subnet.
  consoleCidrs: []
```

`templates/perch-secret.yaml` renders a `Secret` named `{{ include "swarm-team-six.fullname" . }}-perch` from `.Values.perch.seeds` when `perch.enabled && not perch.existingSecret`; `templates/deployment.yaml` gains `envFrom: [secretRef: {name: <perch secret or existingSecret>}]` and a `perch-spool` PVC mount at `/var/lib/ambush/perch-spool` when `perch.enabled`, and the rendered `swarmConfig` carries `perch.enabled: true`, `perch.relay_url: {{ .Values.relay.relayUrl }}`, `perch.spool_dir: /var/lib/ambush/perch-spool`. `templates/networkpolicy.yaml`:

```yaml
{{- if .Values.networkPolicy.enabled }}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "swarm-team-six.fullname" . }}-perch
  labels:
    {{- include "swarm-team-six.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "swarm-team-six.selectorLabels" . | nindent 6 }}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        {{- range .Values.networkPolicy.consoleCidrs }}
        - ipBlock: { cidr: {{ . | quote }} }
        {{- end }}
      ports:
        - { port: {{ .Values.service.port }}, protocol: TCP }
  egress:
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: relay
      ports:
        - { port: 3000, protocol: TCP }
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: nats
      ports:
        - { port: 4222, protocol: TCP }
{{- end }}
```

plus a second policy for the relay pod (`podSelector: app.kubernetes.io/name: relay`; ingress from `consoleCidrs` and from the daemon's selector on `3000`; egress to `postgresql` `5432` and `redis` `6379` only). `ci/perch-values.yaml` enables `relay`, `perch` (with throwaway seeds), `networkPolicy` (`consoleCidrs: ["10.0.0.0/8"]`), `nats`.

- [ ] **Step 6: Write the chart tests**

`tests/perch_test.yaml` (`helm unittest`):

```yaml
suite: perch composition
templates: [deployment.yaml, perch-secret.yaml, networkpolicy.yaml]
tests:
  - it: renders the perch secret and mounts the spool when perch is enabled
    values: [../ci/perch-values.yaml]
    template: deployment.yaml
    asserts:
      - contains: { path: spec.template.spec.containers[0].envFrom, content: { secretRef: { name: RELEASE-NAME-swarm-team-six-perch } } }
      - contains: { path: spec.template.spec.containers[0].volumeMounts, content: { name: perch-spool, mountPath: /var/lib/ambush/perch-spool } }
  - it: renders no perch secret when an existing secret is named
    set: { perch.enabled: true, perch.existingSecret: my-perch }
    template: perch-secret.yaml
    asserts: [{ hasDocuments: { count: 0 } }]
  - it: never opens 9090 to an unlisted CIDR
    values: [../ci/perch-values.yaml]
    template: networkpolicy.yaml
    documentIndex: 0
    asserts:
      - equal: { path: spec.ingress[0].from[0].ipBlock.cidr, value: 10.0.0.0/8 }
      - lengthEqual: { path: spec.ingress, count: 1 }
```

Run: `cd deploy/helm/swarm-team-six && helm dependency update && helm unittest . && helm lint . -f ci/perch-values.yaml && helm template ambush-dev . -f ci/perch-values.yaml | grep -c '^kind: '`
Expected: the three tests pass; lint clean; the template renders the daemon Deployment, the relay Deployment/Service, Postgres and Redis StatefulSets, the two NetworkPolicies, the perch Secret and the ConfigMap.

- [ ] **Step 7: Install once**

Run (against a local kind/minikube cluster): `helm install ambush-dev deploy/helm/swarm-team-six -f deploy/helm/swarm-team-six/ci/perch-values.yaml --wait --timeout 600s && kubectl get pods && kubectl port-forward svc/ambush-dev-relay 3000:3000 & sleep 5 && curl -fsS http://127.0.0.1:3000/_readiness && helm uninstall ambush-dev`
Expected: every pod `Running`/`Ready`; the relay's readiness answers 200 (`09` §4.2 criterion 6, first half).

- [ ] **Step 8: Wire the chart check into CI**

The engine `ci.yml` has no Helm toolchain. Add a job `helm-charts` (its own job, like the OpenAPI one: a red test must not mask a broken chart) with `azure/setup-helm@v4`, `helm unittest` via the `helm-unittest` plugin pinned by version, and the two `run:` lines `bash tools/check-perch-compose.sh` and `cd deploy/helm/swarm-team-six && helm dependency update && helm lint . -f ci/perch-values.yaml && helm unittest .`; `paths-ignore` for `workspace/**` stays because the relay chart is consumed by path from `workspace/deploy/charts/ambush` — add `workspace/deploy/charts/ambush/**` to this job's `paths:` filter so a relay chart change re-runs it.

Run: `bash tools/check-gates-wired.sh`
Expected: clean (`check-perch-compose.sh` is named by a real `run:`).

- [ ] **Step 9: BLOCKED on Task 3 — the rename**

If Task 3 lands option (a) or (b): rename `deploy/helm/swarm-team-six/` to `deploy/helm/<name>/`, `Chart.yaml` `name:`, every `swarm-team-six.` helper in `templates/_helpers.tpl` and the templates, `image.repository`, and add a `## Migrating a release` note to `docs/DEPLOYMENT.md` (a release name does not follow a chart rename; `helm uninstall` + `helm install` with the PVC retained). Re-run step 6. If option (c): delete this step and leave `09` §4.2 criterion 6's last sentence amended in the exit criteria below.

- [ ] **Step 10: The deployment document**

Create `docs/DEPLOYMENT.md`: the two processes (A on 9090 with the bridge in-process; C the relay on 3000 with Postgres and Redis; NATS optional), the six secrets and which process reads each, the relay's migrations (auto-applied at start; no migration Job), the network boundary (brief C2: the relay inside the operator's boundary, never on the internet; 9090 never routable from the operator LAN except the console subnet), the audit-retention window as a configured requirement with the `DETACH PARTITION` job's floor stated in quarters not hours, the `/v2/api` polling note (`perchOperatorStatus` is on demand), the stated cost (`09` §5 line 4: Postgres, Redis, forty migrations and a chat relay entering a two-container product), and the `docker compose --profile perch up` / `helm install` commands from steps 3 and 7.

- [ ] **Step 11: Commit**

```bash
git add deploy/helm/swarm-team-six/ docs/DEPLOYMENT.md .github/workflows/ci.yml tools/check-perch-compose.sh
git commit -s -m "chore(deploy): compose the relay, Postgres and Redis into the engine chart with a network policy"
```

---

### Task 22: Optional — the laptop sidecar: `swarm_detect` supervised by the desktop's managed-agent runtime

This task is clearly separable: nothing above depends on it, and cutting it removes the laptop demo only (`01-DESIGN.md` §12 "Laptop demo").

**Files:**
- Modify: `workspace/scripts/bundle-sidecars.sh:4` (`SIDECARS+=(swarm_detect)` when `PERCH_SIDECAR=1`), `workspace/desktop/src-tauri/tauri.conf.json:55-62` (`binaries/swarm_detect`)
- Create: `workspace/desktop/src-tauri/src/perch_sidecar.rs`, `perch_sidecar_tests.rs`
- Create: `workspace/desktop/src-tauri/src/commands/perch_sidecar.rs` (`perch_sidecar_start`, `perch_sidecar_stop`, `perch_sidecar_status`); modify `commands/mod.rs`, `lib.rs`, `shutdown.rs:127-192` (the sidecar joins the SIGTERM fan-out)
- Modify: `workspace/desktop/src/shared/api/tauriPerch.ts` (`PERCH_LOCAL_COMMANDS`), `e2ePerchBridge.ts`
- Create: `workspace/desktop/src/features/settings/ui/PerchSidecarPanel.tsx` (a settings panel; `SettingsPanels.tsx` gains one lazy entry — 3 lines)

**Interfaces:**
- Consumes: `spawn_agent_child`'s discipline (`managed_agents/runtime.rs:406`, `:868-874`: `command.process_group(0)` on Unix, `CREATE_NO_WINDOW` on Windows, `process_lifecycle::create_job_for_child` for the job object, `finish_spawn`); `shutdown_managed_agents`'s SIGTERM → 2 s → SIGKILL fan-out over process groups (`shutdown.rs:153-192`); Tauri's sidecar resolution (`tauri::path::BaseDirectory::Resource` + `externalBin` naming `swarm_detect-<triple>`); the engine's release build of `swarm_detect` (`cargo build --release -p swarm-runtime-http --bin swarm_detect`, edition 2024 under the root toolchain — the workspace's 1.95 toolchain never compiles it; the binary is copied, per `bundle-sidecars.sh`'s existing "run cargo first" contract); `rulesets-dev/perch-dev.yaml`; the app data dir.
- Produces: `PerchSidecar::start(app: &AppHandle, profile: SidecarProfile) -> Result<SidecarStatus, String>` where `SidecarProfile { config_path: PathBuf, bind: "127.0.0.1:9090", env: Vec<(String, String)> }` and `SidecarStatus { pid: u32, started_at_ms: i64, healthz: "starting" | "ready" | "unhealthy" | "stopped" }`; `PerchSidecar::stop(&self) -> Result<(), String>` (SIGTERM the process group, wait 2 s, SIGKILL); a health poll of `GET http://127.0.0.1:9090/readyz` every 5 s; the three Tauri commands (local process control — not Ambush-bound, outside INV-01); the settings panel showing `SidecarStatus`, the profile path, and the two seeds' **presence** (never their values).

- [ ] **Step 1: Write the failing supervisor test**

Create `perch_sidecar_tests.rs` (included from `perch_sidecar.rs` with `#[path]`, the `agent_config.rs:577` precedent):

```rust
use super::*;

#[tokio::test]
async fn a_sidecar_that_exits_is_reported_stopped_and_its_group_is_reaped() {
    // `sh -c 'sleep 30'` stands in for swarm_detect: same spawn path, same group kill.
    let sidecar = PerchSidecar::spawn_for_tests(vec!["sh".into(), "-c".into(), "sleep 30".into()]).await.unwrap();
    assert!(matches!(sidecar.status().healthz, Healthz::Starting));
    sidecar.stop().await.unwrap();
    assert!(matches!(sidecar.status().healthz, Healthz::Stopped));
    #[cfg(unix)]
    {
        // The group is gone: kill(-pgid, 0) fails with ESRCH.
        let pgid = sidecar.pgid().unwrap();
        assert_eq!(unsafe_free_kill_probe(pgid), Err(libc::ESRCH));
    }
}

#[test]
fn the_seeds_never_cross_ipc() {
    let status = SidecarStatus { pid: 1, started_at_ms: 0, healthz: Healthz::Ready, profile_path: "/x".into(), seeds_present: SeedsPresent { nostr: true, spine: true } };
    let json = serde_json::to_string(&status).unwrap();
    assert!(!json.contains("SEED"), "presence only, never a value");
}
```

`unsafe_free_kill_probe` is a small safe wrapper the module exposes for tests around `libc::kill` — the workspace crate already links `libc` for `shutdown.rs:192`; the wrapper returns `Result<(), i32>` from `std::io::Error::last_os_error().raw_os_error()`. (The Tauri crate is not under the engine's `forbid(unsafe_code)`; `shutdown.rs` already calls `libc::kill` inside `unsafe`. Reuse its helper rather than adding a second `unsafe` block.)

- [ ] **Step 2: Run to see it fail**

Run: `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_sidecar`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the supervisor and the commands**

`perch_sidecar.rs`: a `PerchSidecar { child: Mutex<Option<std::process::Child>>, status: Mutex<SidecarStatus>, pgid: Option<i32> }` held in `AppState` as `Arc<PerchSidecar>`; `start` resolves the bundled binary through Tauri's sidecar path (`app.path().resolve("binaries/swarm_detect", BaseDirectory::Resource)` — the `-<triple>` suffix is stripped by Tauri's bundler on copy, `backend.rs:569`'s note), builds `Command::new(bin).args(["--config", profile.config_path, "--serve", "--bind", "127.0.0.1:9090"])` with `envs(profile.env)` (the two seeds and the operator token read from the keyring entries `perch-sidecar-nostr-seed`, `perch-sidecar-spine-seed`, `perch-operator-token` — never from the renderer), `process_group(0)` on Unix / `CREATE_NO_WINDOW` + `create_job_for_child` on Windows, `stdout`/`stderr` to a rotating log under the app data dir, then spawns the 5 s `/readyz` poll; `stop` sends SIGTERM to `-pgid`, waits 2 s, SIGKILLs, joins the child, sets `Stopped`; `shutdown_managed_agents` (`shutdown.rs:127`) calls `sidecar.stop()` first so the daemon dies with the app. The three commands in `commands/perch_sidecar.rs` take/return only `SidecarProfile` (a config path chosen from the settings panel, validated to live under the app data dir or the bundled `rulesets/`) and `SidecarStatus`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_sidecar && cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_daemon_client`
Expected: 2 passed; INV-22's tests still pass (the sidecar commands return no token-bearing value).

- [ ] **Step 5: Bundle and bring it up once**

Run: `cargo build --release -p swarm-runtime-http --bin swarm_detect && cd workspace && PERCH_SIDECAR=1 bash scripts/bundle-sidecars.sh && cd desktop && pnpm tauri dev`
Then in the app: Settings → Ambush daemon → Start with `rulesets-dev/perch-dev.yaml`. Expected: `SidecarStatus.healthz` reaches `ready` within 30 s; the governance strip shows `recv Ns ago` from the sidecar's bridge; quitting the app leaves no `swarm_detect` process (`pgrep swarm_detect` is empty).

- [ ] **Step 6: Commit**

```bash
git add workspace/scripts/bundle-sidecars.sh workspace/desktop/src-tauri/tauri.conf.json workspace/desktop/src-tauri/src/perch_sidecar.rs workspace/desktop/src-tauri/src/perch_sidecar_tests.rs workspace/desktop/src-tauri/src/commands/ workspace/desktop/src-tauri/src/lib.rs workspace/desktop/src-tauri/src/shutdown.rs workspace/desktop/src/shared/api/tauriPerch.ts workspace/desktop/src/testing/perch/e2ePerchBridge.ts workspace/desktop/src/features/settings/
git commit -s -m "feat(desktop): supervise swarm_detect as a bundled sidecar under the managed-agent discipline (laptop demo)"
```

---

## Self-Review

Every `01-DESIGN.md` §6 / §7 / §9 / §12 item this milestone owns, and the `04` surface it lands, mapped to a task. A row with no task is a gap; there are none, and three items are deliberately left as decisions.

| Spec item | Task |
|---|---|
| `01` §6 **B4** `GET /v1/operator/pheromone/deposits` — post-suppression, post-evaporation, `source_ids`, `now_seconds`, served concentration | Task 4 |
| `01` §6 **B6** signed envelopes on the publish path — configured signing identity, per-issuer `seq`/`prev_envelope_hash` store | Task 7 (daemon/bridge), Task 13 steps 14–21 (console verification, tier allowlist) |
| `01` §6 **B1c** `RuntimeEvent::ContainmentReleased` | Task 5 |
| `01` §6 **B2g-p** partition stamps at hold and at execution | Task 6 |
| `11` §9.3 lease cards from the 1 Hz `open_leases()` diff; `perch_bridge_lease_store_absent` | Task 8 |
| `11` §9.4 rollback cards (both triggers under W3-19), NIP-10 reply to the lease card | Task 9 |
| `11` §11 metrics registry additions (`envelopes_signed`, `lease_cards_published`, `rollback_cards_published`, `lane_topic_writes`, `lease_store_absent`) | Tasks 7, 8, 9, 11 |
| `04` §2.6 Containments — two facts, release from the body, no extend, the lease-store state, partition section | Task 10 |
| `04` §2.5 Lanes — twelve muted channels, topic on a crossing only, live numbers from 26001, `Custom` lands in the nearest lane | Task 11 |
| `04` §2.14 / §1.2 Governance strip — committee of one, staleness clock, 2 s debounce, watch holder, de-escalation | Task 12 |
| `04` §2.9 Ledger + ⌘K overlay + export (`08` §6.4 bundle shape, `verification_tier`, `answers_who_approved`, UNRECONCILED excluded) | Task 13 |
| `17` §6.13 `PerchOmnibox` (P2-C1) | Task 13 steps 5–8, 19–20 |
| `04` §2.10 Tuning bench — every recommendation field, provenance, C9 restated, no Apply | Task 14 |
| `04` §2.12 Gaps — 18 / 11 grouped by detector, rationale verbatim | Task 15 |
| `04` §2.7 Policy — file order, shadowing evaluated per triple, permanent request-carried banner, read-only | Task 16 |
| `04` §2.11 Handoff — End watch composes a `ReviewSession`, INV-19 acknowledgement, the watch claim | Task 17 (claim write path blocked on Task 2) |
| `04` §2.4 / `17` §6.14 Case Canvas tab + seeded template (P2-C2) | Task 18 |
| `18` §6 `KillChainGraph` with its required `rejected` half | Task 18 |
| `04` §2.13 swarmctl terminal pinned to a case | Task 18 |
| `04` §2.8 Watchfloor — bare chrome, three bands, no pulse, ≤ 1 Hz | Task 19 |
| `18` §2 concentration mathematics, ε = `evaporation_threshold` (A11), CR-1…CR-10 | Task 19 steps 1–5 |
| `18` §4, §5, §9 VIZ-1, VIZ-2, VIZ-6; §8 VIZ-5 (the containment board); §6 VIZ-3 | Tasks 19, 10, 18 (VIZ-4 `IncidentTimeline` is The hold's case timeline; its `superseded` row is INV-36's) |
| `18` §13 G1 `check-svg-font-size.mjs`, G2 `check-perch-chart-tokens.sh` (P2-C3) | Task 19 step 10 |
| `20` §12.5 P2-C4 route tree, P2-C5 surface count, P2-C6 notification fields | Task 20 |
| `16` §6.3 the twelve SVG rewrites (W3-24 deferred them here) | Task 20 steps 6–8 |
| `01` §12 packaging: compose hardening; Helm gains the relay trio; brief C2 network policy; D22 | Task 21 (rename blocked on Task 3) |
| `01` §12 laptop sidecar | Task 22 (optional) |
| `08` §4 lease UX (INV-05, 06, 07), §6.2 tiers (INV-25), §6.4 bundle (INV-26), §7.7 PTY rule, INV-03/04/08/09/16/17/20/21/24 | Tasks 10, 13, 18, 19, 20 |
| `21` Q4 tier allowlist gate | Task 13 step 21 |

**Placeholder scan.** Searched this document for `TBD`, `TODO`, `implement later`, `fill in`, `add error handling`, `add validation`, `handle edge cases`, `write tests for`, `similar to Task`: none. `todo!()` appears only in an explicit prohibition: the new producer modules must be complete in the commit that creates them.

**Type consistency.** `PerchDepositSlice`/`PerchSuppressionRecord` (Task 4) are what `PerchDepositsRead` and `DepositsResponse` carry; `ContainmentReleased`'s eight fields (Task 5) are exactly `ContainmentReleasedFields` (Task 9); `partition_state_at_execution` is `Option<PartitionState>` on the event, the decide record and the rollback fact (Tasks 5, 6, 9, 10); `SpineSigner::seal` (Task 7) is what Tasks 8, 9 and the card assembly call; its JSON deserializes into the transport-neutral `CardEnvelope`, and `perch_verify.rs` verifies the wire crate's canonical bytes with Tauri's `ed25519-dalek`; `ContainmentFacts`/`deriveContainmentState` (Task 10) feed `ContainmentTimer`; `laneLiveNumbers` (Task 11) reads `PerchEphemeralSnapshot`; `WatchClaim`/`claimState` (Task 17) are what `GovernanceStrip` (Task 12) consumes through `useWatchClaim`; `SourceAttribution`/`attributionText` (Task 19) import `agentIdOfSource` from `SourceCount` rather than re-deriving; `PERCH_COMMANDS` (Task 13) navigates with `PerchView` (`perchViews.ts`); `NOTIFICATION_BODIES` keys (Task 20) are the four wake classes of `04` §3.2.

**Contradictions found while writing, recorded rather than resolved silently.**

1. `11-BRIDGE-CRATE.md` §9.4 decision 1 has the **console** publish `swarm:rollback:v1` for an operator release; W3-19 rules the operator key publishes exactly one marker. This plan follows W3-19 and `01-DESIGN.md` §4's author column ("bridge (operator-driven)"): B1c fires on **both** triggers (Task 5) and the bridge publishes both rollback cards (Task 9).
2. The copied wire skeleton contradicted D2 by declaring engine dependencies. W3-27 resolves it: the wire crate is transport-neutral, signing remains in the bridge, and the Tauri process verifies the shared canonical bytes with its existing `ed25519-dalek`. Task 7 and Task 13 include both the dependency-graph assertion and the engine-versus-wire differential vectors.
3. `docs/plans/ambush-ui/build/fixtures/http/…-after-dismiss.json` carries `marker_timestamp: 1773739124200` (milliseconds) while the OpenAPI declares seconds and every deposit `timestamp` is seconds. Task 4 step 15 fixes the fixture to `1773739124`.
4. `09-ROADMAP-AND-RISKS.md` §4.1 renames the engine chart to `ambush`; `workspace/deploy/charts/ambush` already carries that name. Task 3 files it.
5. `tauriPerch.ts`'s skeleton comment reads `GET /v1/operator/status` for `perch_operator_status`; that route is on `swarmctl serve` (7766). `20` §1.4 is right: the daemon serves the tuning report at `/v2/api/runtime/status`. Task 14 pins the constant.
6. `04` §2.7 assumes `policy.rules` is readable and names no route; none exists on 9090. Task 16 adds `GET /v1/operator/policy` (a read, outside the bill's labels) rather than serving the ruleset through a second process.
7. The team brief describes `PerchOmnibox` as "named but never specified" and the canvas template as "no owner"; `17` revision 2 §6.13 and §6.14 specify both. This plan builds from `17` rev 2 and files no decision for either.

## Implementation status

Recorded 2026-09-04, on `codex/ambush-operator-complete`. **This milestone is
not claimed as accepted**: the fifteen exit criteria below are observable
behaviours on a running dev stack with the console, and the console half had
not been driven against that stack when this was written. **Update,
2026-09-05:** it has been, headless through Tauri's own IPC layer
(`evidence/walking-skeleton.md`); the rendered tree on a real window is the
seam that remains, and acceptance is the owner's read. The original reason
follows — the same limitation The hold recorded, for
the same reason (the console's daemon surface goes through Tauri commands
holding the bearer and the operator's Ed25519 key, which a browser cannot
call). The `perch` preview flag stays off by default.

| Task | Landed | Not landed, and why |
|---|---|---|
| 1–3 open decisions | filed in `00-DECISIONS.md` §3 with the fallback each plan builds against | the decisions themselves are the owner's |
| 4 B4 deposits | `perch_deposit_slice`, the engine op, the mounted route (seven paths) | OpenAPI regeneration — `generate_perch_openapi.rs` and `docs/openapi/perch-operator-v1.json` do not exist; the contract is hand-maintained YAML. A task, not a step |
| 5 `ContainmentReleased` | the 13th runtime event, published from both release paths | — |
| 6 partition stamp | both fields across five sides; parity 324 both ways | the provenance Playwright spec un-skips a file that does not exist |
| 7 B6 spine | wire primitives, chain-head store, signer, sealing on the publish path with the durable head advancing only on ACK, and the console's `perch_verify_envelope` | — |
| 8–9 | wire and bridge halves as landed in The hold | — |
| 10 containment board | `/leases`, the state model, the timer, the rollback list, the release confirmation dialog, the partition section and its Playwright spec | — |
| 11 lane screen | `laneLiveNumbers`, `laneCopy`, `LaneScreen`, `/lanes/$laneId`, the regime-B curve in the header slot, and `PerchNav` making all ten routes reachable | — |
| 12 governance | `derivePerchGovernanceMode`, `governanceCopy`, `GovernanceStrip`, mounted above the outlet on every route including the Watchfloor's bare chrome | — |
| 13 ledger and export | `buildLedgerQuery`, `planExportFiles`, `buildExportManifest`, `omniboxCommands`, `LedgerScreen`, `/ledger`, the tier allowlist gate, `perch_verify.rs`, `perch_export.rs`, the ⌘K omnibox | — |
| 14 tuning | `tuningProvenance`, `TuningScreen`, `/tuning` | the daemon reads behind it |
| 15 gaps | `gapsCatalog`, `GapsScreen`, `/gaps` | — |
| 16 policy | `policyEvaluation`, `PolicyScreen`, `/policy` | the daemon-side policy route; the screen renders an empty rule list until it exists |
| 17 handoff | `reviewSession`, `watchClaim`, `shiftLedger`, `handoffPublish`, the frontier fold, `HandoffScreen`, `/handoff` | the daemon-side review session — see **W3-36**: the route cannot accept this body |
| 18 case canvas | `caseTemplate`, `caseTtlClock`, `killChainLayout`, `CaseScreen`, `CaseCanvasTab`, `KillChainGraph`, the terminal pin in TS **and** Rust | the Playwright specs; agent rows on the graph (blocked on Task 1) |
| 19 Watchfloor | the whole of it: the shared layer, three charts, `WatchfloorScreen`, `/watch-floor`, two gates, the four reducers, and the telemetry publisher that drains and signs them once per tick | the 72-hour soak, which is manual |
| 20 CI gates | route-tree, surface-count and notification-field gates, all wired, all with fixtures | the SVG asset rewrite |
| 21 packaging | the compose gate (which found two real defects), the relay chart dependency, NetworkPolicy, perch secret, 12 chart tests, the deployment section | `docker compose up` and `helm install` — no working Docker daemon and no cluster here. Image digests are **not** pinned and the gate says so on every run |
| 22 sidecar (optional) | supervisor with group-kill, three commands, health poll, settings panel (mounted under Settings → Detector on 2026-09-05; it had been built and mounted nowhere), opt-in bundling | never bundled or run: it needs an engine release build and a Tauri bundle |

**Amendment W3-36** records the one place the plan and the implementation
could not be reconciled: Task 17's END WATCH block cannot go to
`POST /v1/operator/review/sessions`, because that route refuses an empty ref
list and resolves every ref against the review workbench's own evidence stores,
and a case channel is not one of those.

## Exit criteria

Observable behaviours, each checkable by a person with the dev stack and the console:

1. `/leases` lists an open containment lease with `remaining_ms` and `expired` as two elements; a lease whose inverse failed renders `NOT RELEASED … lease_closed: false` in the error register on an HTTP 200; no extend control exists, and the disabled row-menu item says why; on the detect-only profile the board reads `No containment lease store is configured` naming the key.
2. A TTL expiry in the daemon produces a `swarm:rollback:v1` card in the case channel within two pacer ticks, as a reply to the lease card, whose badge reads `UNATTESTED` or `UNATTESTED — BY DESIGN` from the stamped partition state, and — when attested — `Ed25519 · tier 1 · attestation matches this body` with the attestation's `decision` beside it.
3. `/lanes/$laneId` shows `strength / N sources / M agents · alert 2.0 · incident 5.0` from the 26001 frame and B4's ids, all twelve lanes are muted on first run, and a lane's topic changes only when its escalation level changes (the relay's `kind:40099` rows count one per crossing, not per second).
4. The governance strip on every route, including `/watch-floor`, reads `committee of 1 (solo transport)`, never a fraction; a three-governor frame renders the fail-closed register; a frame older than three seconds renders `stale`; a `transition_down` names no class.
5. `/ledger` returns the same finding by `from:`, by `in:` and by a free-text substring of its body, and a card published one second ago is findable; `Export` writes a directory whose `MANIFEST.json` stamps `verification_tier` on every file and `answers_who_approved: false`, whose `receipts/` bytes equal the daemon's re-fetched bytes, and which omits every `UNRECONCILED` hold; `⌘K` opens the omnibox, `> release containment <id>` stages the release on `/leases` and POSTs nothing.
6. After B6, every bridge-authored card's provenance block reads `Ed25519 · chained · seq N · tier 2`, a stripped signature drops it to tier 0, and a sequence gap renders as a gap; `tools/check-perch-tier-allowlist.sh` is green with five rows at `2`.
7. `/tuning`'s total-strength header for a class equals `swarmctl`'s number for the same class at the same instant (through B4's served `concentration`), every recommendation renders its eight fields with its provenance marked derived, and the empty state names `3`, `4` and `2`.
8. `/gaps` reads `18 techniques across 11 detectors` from the daemon and shows each rationale verbatim; `/gaps?threat_class=…` filters and recounts; no percentage appears.
9. `/policy` marks the shipped `command-and-control-emergency-block` as deciding `command_and_control / CRITICAL / block_egress` and prints the outranks sentence; a deliberately shadowed ruleset renders the shadowed rule `not reached`; the request-carried banner is always present; nothing on the page is editable.
10. `/handoff` composes the END WATCH block with reviewed/unreviewed counts, refuses to end while an expired-undecided hold is unacknowledged, records exactly one review session and one message per touched case on confirm, and the incoming analyst's `/` resumes on the three read frontiers the outgoing one left.
11. A fresh case's `Canvas` tab shows the five headings at once and writes them exactly once; the kill-chain figure shows the refused members below the rule with reasons in full; `⌘J` on a case opens a shell whose header says `pinned to <case>` and whose `swarmctl` writes land under that case's directory.
12. `/watch-floor` renders twelve regime-B curves labelled interpolation with the header showing the runtime's `total_strength`, no navigation chrome, no pulsing badge, and survives 72 hours on a spare monitor with < 10 % RSS growth (manual, `docs/PERCH-DEV.md`).
13. `pnpm check` runs `check:svg-font-size` and `check:route-tree`; `tools/check-gates-wired.sh` is green with `check-perch-chart-tokens.sh`, `check-perch-tier-allowlist.sh`, `check-perch-surface-count.sh`, `check-perch-notification-fields.sh` and `check-perch-compose.sh` wired; `bash tools/check-copy-banned-terms.sh` exits 0 over `docs/assets/`.
14. `docker compose --profile perch up` brings up five healthy services on loopback-only ports with pinned digests; `helm install … -f ci/perch-values.yaml` brings up daemon + NATS + relay + Postgres + Redis in one command with a NetworkPolicy that admits the console CIDR to `3000` and `9090` and nothing else to `9090`.
15. (Optional, Task 22) The desktop starts and stops a bundled `swarm_detect` from Settings, the strip shows its bridge's frames, and quitting the app leaves no daemon process.

## Sizing

One engineer-day = one engineer, one day, on this project only; the +25 % gate tax `09` §6 bakes into every frontend number is included here too. Wave 1 sized this scope as Phase 2 (25 ew) plus the parts of Phase 3 this plan absorbs (Watchfloor 4, telemetry perf 2, CI guards 1, verify affordance 1.5, deployment docs 1 = 9.5 ew), i.e. **34.5 ew** excluding Phase 3's 3 ew buffer; `20` §2.3 re-sized Phase 2 to 28 ew with the six carry-forwards. This plan's bottom-up total is **135 engineer-days = 27 ew**, including six days for milestone exit and excluding the optional five-day sidecar. It is below the wave-1 figure because the deletion track is withdrawn (D3), the relay chart is composed rather than authored, and the ⌘K overlay reuses five search modules verbatim; above `20`'s Phase-2 figure because B6 is 1.4 ew rather than 1 (the verdict-card chain and the console-side verification were underpriced), the policy read route is new, and W3-29 now prices the previously unowned receipt, escalation and 26000–26005 producers.

| Task | Days | Note |
|---|---:|---|
| 1 Decision: artwork | 0.5 | filing only |
| 2 Decision: watch claim | 0.5 | filing only |
| 3 Decision: chart name | 0.5 | filing only |
| 4 B4 deposits read | 5 | the reduction, the route, the OpenAPI byte-match, four substrate backends unread by wave 2 (`12` §11.3) |
| 5 B1c `ContainmentReleased` | 2.5 | seven edits plus the sweep's broadcaster |
| 6 B2g-p partition stamps | 2 | daemon, wire, TS, schemas, goldens, OpenAPI |
| 7 B6 daemon/bridge | 7 | signer, chain heads, seal on append, T-16 rewrite, layering |
| 8 Bridge receipt + lease cards | 5.5 | the receipt producer and acknowledged routing precede the poll, receipt→hunt→case join and card index |
| 9 Bridge rollback cards | 3 | both triggers, NIP-10 reply, unrouted handling |
| 10 Containments | 7 | two primitives, board, dialog, partition section, two presenters, five specs |
| 11 Lanes | 9 | durable escalation producer and reducer, bridge edge write, screen, sidebar section, muting, four specs |
| 12 Governance strip | 4 | projection, debounce, alerts, four specs |
| 13 Ledger + omnibox + export + tier-2 verify + tier gate | 14 | the largest surface: grammar, two Tauri commands, the bundle, the overlay, eight specs, one gate |
| 14 Tuning bench | 6 | provenance, the incident read, the card fork |
| 15 Gaps | 3.5 | the coverage read, the grouping, the pinned counts |
| 16 Policy | 8 | a new daemon route with the gate's own predicate, the evaluator, five specs |
| 17 Handoff | 9 | composer, frontiers hook, review session write, acknowledgement rows; the claim's write path is unpriced pending Task 2 (option a ≈ 1 d, b ≈ 2 d) |
| 18 Case canvas + kill chain + terminal | 8 | seeding, VIZ-3, the PTY pin on both sides, eight specs |
| 19 Real 26000–26005 frames + Watchfloor + chart layer + G1/G2 | 20 | reducers, publishers and live relay proof first; then the shared layer, three charts, wall, two gates and perf probe; the soak is manual |
| 20 CI gates + SVG rewrite | 5 | three gates with fixtures; twelve assets, 41 hits, each checked in a browser |
| 21 Packaging | 9 | compose hardening, the chart dependency, two policies, chart tests, one real install, the deployment doc |
| 22 Sidecar (optional) | 5 | supervisor, commands, panel, bundling; separable |
| Integration and milestone exit (walking the fifteen criteria on the dev stack, fixing what they find) | 6 | not a task; the criteria are the checklist |
| **Total** | **129 (+5 optional) + 6 exit = 135 days = 27 ew** | one Rust engineer carries Tasks 4–9, 11's producer, 16's daemon half and 19's frame prelude (≈ 34 days serial, all after The hold's B1/B2); two frontend engineers can run Tasks 10–20 in parallel once Tasks 4, 5, 7 and the frame contracts have landed |

The honest caveat `09` §6 already states applies: the Rust chain is serial through one engineer, and B6 (Task 7) sits behind B1 (The hold) and in front of every tier-2 render. If B6 slips, Tasks 10–20 still ship at tier 0 with the allowlist rows at `0`, which is a rendered honest state, not a fallback.
