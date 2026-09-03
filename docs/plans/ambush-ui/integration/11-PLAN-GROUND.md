# Ground Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the ground under the console: the `swarm:` rename applied to every wave-2 artifact, the three capped desktop files split, the relay admitting a channel-scoped kind 46010 and fencing kind 26006, the three security prerequisites landed, the operator principal able to carry a Nostr pubkey, and a dev stack that runs the daemon beside the relay — so that First card can start with nothing in its way.

**Architecture:** Every task here is a precondition the First card plan names, and none of them renders a card. Work splits into two independent tracks that can run in parallel: the **engine track** (rename and re-pin, B0, the dev ruleset and its signing binary, the dev compose, the engine CI `changes` job) and the **workspace track** (the three splits, the relay patches, the CSP pin, the sign gate, the resetter registry, the ws-client panic sites, the feature-gate entry, the repair-kinds constant). They join at Task 14.

**Tech Stack:** Rust 1.97.1 (engine) and 1.95.0 (workspace), cargo nextest, TanStack Router, React 19, Node's built-in test runner, Playwright, lefthook, Docker Compose, Postgres 17, Redis 7.

**Spec:** `docs/plans/ambush-ui/integration/01-DESIGN.md` (§2, §4, §8, §9, §12), with `00-DECISIONS.md` D1–D4 and rows W3-1, W3-6, W3-7, W3-8, W3-23, W3-24.

## Global Constraints

- Engine crates: `#![deny(unsafe_code)]`, `clippy::unwrap_used` and `clippy::expect_used` denied workspace-wide, `panic = "abort"` in release, edition 2024, `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Workspace crates: no new `unwrap()` / `expect()` in production paths, no `unsafe`, doc comments on new public API, `cargo clippy` clean under `just check`.
- Marker namespace is `swarm:`; the sign-gate regex is `^<!-- swarm:[a-z]+:v\d+ -->$` applied to line 0 with `trim_end` only; the chat app's `ambush:wave:v1` and `ambush:config-nudge` markers must keep working.
- The feature prefix is `perch`; the rendered word "Perch" is banned; no rendered "Approve" as a control label; no verdict verb on key `A`.
- Desktop text sizes are rem tokens only (`pnpm check:px-text`); new desktop code never grows a file over 1000 gate-lines (`scripts/check-file-sizes-core.mjs`, `content.split(/\r?\n/).length`) and never edits the frozen files named in `../build/15-FILE-SPLIT-PLAN.md` §7 (`tauri.ts` 1108, `relayClientSession.ts` 1084, `types.ts` 1000, `sidebar.tsx` 1011, `markdown.tsx` 1904).
- Kind 46010 is published with `h` (case channel), `p` (one per Approve principal), `hold`, `card`, and **never `e`** (RF-D1). Kind 26006 is global, carries `p`, and is in `P_GATED_KINDS` (R-1).
- `OperatorPrincipalConfig` is `#[serde(deny_unknown_fields)]`; every new field is `#[serde(default)]`.
- Every gate script lands with the workflow `run:` step that wires it, in the same commit (`tools/check-gates-wired.sh`).
- Commits: `git commit -s`, Conventional Commits subjects, the attribution trailers in use on this branch.

---

## File Structure

**Engine track**

| Path | Responsibility |
|---|---|
| `docs/plans/ambush-ui/build/schemas/card-swarm-*.schema.json`, `common.schema.json`, `card-envelope.schema.json`, `event-46010-hold-notice.schema.json` | wave-2 schemas under the `swarm:` namespace (renamed files and `const` values) |
| `docs/plans/ambush-ui/build/skeleton/perch-wire/**` | Rust/TS skeleton and golden vectors renamed; `GOLDEN.sha256` re-pinned |
| `docs/plans/ambush-ui/build/fixtures/**` | the canonical fixture renamed; `SHA256SUMS` regenerated; `validate.mjs` green |
| `docs/plans/ambush-ui/build/prototypes/*.html`, `skeleton/desktop/**`, `skeleton/tests/**` | strings renamed |
| `docs/plans/ambush-ui/build/skeleton/tools/copy-ban-list.tsv` | `Perch` added as a rendered-word ban |
| `crates/swarm-core/src/config/operator.rs` | `nostr_pubkey: Option<String>` on `OperatorPrincipalConfig` and `OperatorAuthConfig`, validated |
| `rulesets/perch-dev.yaml`, `rulesets/perch-dev.yaml.sig.json` | the dev profile and its debug-signed sidecar |
| `crates/swarm-runtime-http/src/bin/sign_dev_ruleset.rs` | writes the sidecar with the in-repo debug key |
| `docker-compose.yml` | gains `postgres`, `redis`, `relay` beside `swarm-detect` |
| `scripts/provision-perch.sh` | creates the twelve lane channels and the memberships the bridge and the operator need |
| `.github/workflows/ci.yml` | a `changes` job so engine lanes skip on workspace-only changes without leaving required checks pending |

**Workspace track**

| Path | Responsibility |
|---|---|
| `workspace/desktop/src/features/messages/ui/MessageThreadGuides.tsx`, `MessageBody.tsx` | MR-1, MR-2 from `../build/refactor/` |
| `workspace/desktop/src/app/useAppShellBackgroundSync.ts`, `useCommunityDestinationRestore.ts`, `useChannelCreationHandlers.ts`, `AppShellSettingsSurface.tsx` | AS-1 … AS-4 |
| `workspace/desktop/src/features/home/ui/HomeMessagesDetail.tsx`, `HomeInboxAuxiliaryPane.tsx`, `HomeFeedUnavailable.tsx`, `features/home/useHomeInboxFilterChange.ts` | HV-1 … HV-4 |
| `workspace/crates/ambush-relay/src/handlers/ingest.rs` | 46010 admitted and channel-scoped (three hunks + seven tests) |
| `workspace/crates/ambush-core/src/kind.rs` | `KIND_OPERATOR_ALARM_FRAME = 26006` in `P_GATED_KINDS` and `ALL_KINDS` (+ three tests) |
| `workspace/crates/ambush-test-client/tests/e2e_workflow_approval.rs`, `e2e_operator_alarm_pgate.rs` | the fourteen relay E2E tests |
| `workspace/Justfile` (`test-unit`), `.github/workflows/workspace-ci.yml` | run `handlers::ingest::tests` and the two E2E binaries |
| `workspace/desktop/src-tauri/src/channel_reconnect_repair.rs` | `CHANNEL_REPAIR_KINDS` + 46010, 40100, 39005 |
| `workspace/desktop/src-tauri/tauri.conf.json`, `src-tauri/src/csp_pin_tests.rs` | the pinned CSP and its test |
| `workspace/desktop/src/features/profile/**` (four files deleted) | animated-avatar capture removed |
| `workspace/desktop/src-tauri/src/perch_sign_gate.rs`, `commands/{identity,messages,project_git_workflow}.rs` | the gate and its five call sites; the inventory test |
| `workspace/desktop/src/features/communities/communityScopedRegistry.ts`, `useCommunityInit.ts` | the typed resetter registry |
| `workspace/crates/ambush-ws-client/src/connection.rs`, `error.rs`; `tools/check-runtime-panic-contract.sh` | four panic sites become typed errors; the crate joins the panic-contract enumeration |
| `workspace/preview-features.json` | the `perch` feature entry |

---

### Task 1: Apply the `swarm:` rename to the wave-2 artifacts and re-pin (W3-1, W3-8, W3-16)

**Files:**
- Modify/rename: everything under `docs/plans/ambush-ui/build/{schemas,skeleton,fixtures,prototypes,tokens,viz}/` that carries `ambush:`, `ambush.perch.` or `card-ambush-`
- Modify: `docs/plans/ambush-ui/build/skeleton/tools/copy-ban-list.tsv`
- Modify: `docs/plans/ambush-ui/build/13-WIRE-SCHEMAS.md` (a ruling banner at the top)

**Interfaces:**
- Produces: the seven marker strings `<!-- swarm:finding:v1 -->` … `<!-- swarm:rollback:v1 -->`; fact schema ids `swarm.perch.<card>.v1`; schema files `card-swarm-<slug>-v1.schema.json`; the verdict preimage `{decided_at_ms, decision, hold_id, rationale_sha256}` in `card-swarm-verdict-v1.schema.json`.

- [x] **Step 1: Measure the surface.** From the repo root:
  ```bash
  grep -rlE "ambush:(finding|escalation|hold|verdict|receipt|lease|rollback):v1|ambush\.perch\.|card-ambush-" docs/plans/ambush-ui/build | wc -l
  ```
  Record the count in the commit message; expect roughly 120 files.
- [x] **Step 2: Rename file names first.**
  ```bash
  cd docs/plans/ambush-ui/build
  for f in $(git ls-files | grep 'card-ambush-'); do git mv "$f" "${f//card-ambush-/card-swarm-}"; done
  ```
- [x] **Step 3: Rename strings.** Only the seven slugs and the schema id; never the `ambush-*` crate names, the `--ambush-*` CSS variables, or the chat app's own `ambush:wave:v1`:
  ```bash
  git ls-files | xargs sed -i '' -E \
    -e 's/ambush:(finding|escalation|hold|verdict|receipt|lease|rollback):v([0-9]+)/swarm:\1:v\2/g' \
    -e 's/ambush\.perch\./swarm.perch./g' \
    -e 's/card-ambush-/card-swarm-/g'
  git diff --stat | tail -1
  ```
- [x] **Step 4: Apply PA-3 to the verdict schema.** In `schemas/card-swarm-verdict-v1.schema.json`, make `rationale_sha256` a required decision member beside `decided_at_ms`, `decision`, and `hold_id`; update `skeleton/perch-wire/golden/card-swarm-verdict-v1.json` and `card-swarm-verdict-v1-superseded.json` to carry it. Its value is 64 lowercase hex when `rationale` exists and JSON `null` when absent, matching `12-BACKEND-BILL-API.md` D13 and the operator OpenAPI's canonical four-member preimage.
- [x] **Step 5: Recompute the pinned hashes with the artifacts' own tools.** Read `fixtures/validate.mjs` to find the function that recomputes `envelope_hash` (it "recomputes 14 envelope hashes and matches them"); use it to rewrite `envelope_hash` in every vector whose `fact.schema` changed, then:
  ```bash
  (cd skeleton/perch-wire/golden && shasum -a 256 $(ls *.json | grep -v manifest.json | sort) > GOLDEN.sha256)
  (cd fixtures && shasum -a 256 $(git ls-files . | grep -v SHA256SUMS | sort) > SHA256SUMS)
  node fixtures/validate.mjs            # expected: 0 failures, 14 hashes matched, 3 issuer chains intact
  bash skeleton/perch-wire/parity-gate.sh   # expected: 312 fields, exit 0 after W3-16 adds rationale_sha256
  git diff --exit-code -- tokens viz    # the rejected token package is gone; the shipped Quiet copies stay untouched
  ```
- [x] **Step 6: Ban the rendered word.** Append to `skeleton/tools/copy-ban-list.tsv` a row in the file's seven-column layout: id `product-codename`, case-sensitive portable ERE `(^|[^A-Za-z])Perch([^A-Za-z]|$)`, and message `The product is Ambush; Perch is an internal codename (00-DECISIONS D1).` (`awk` has no `\b`, as the ban-list header records). Run the corpus parity check the file's README names (`node ../scripts/check-copy-banned-terms.mjs` over `tools/fixtures/copy-corpus/`) and confirm the expected-row count rises by the rows your new pattern hits in `violations.copy.ts` (add one deliberate `Perch` line there and to `expected.tsv`).
- [x] **Step 7: Banner.** Prepend to `13-WIRE-SCHEMAS.md`: `> **Wave 3 (2026-09-02): the marker namespace is `swarm:` and the fact schema id is `swarm.perch.<card>.v1` (00-DECISIONS W3-1); the verdict preimage has four members (W3-16). The bodies of this document still say `ambush:` where they quote wave 2; the schemas and goldens are authoritative.`
- [x] **Step 8: Commit.**
  ```bash
  git add -A docs/plans/ambush-ui/build && git commit -s -m "docs(plans): apply the swarm: marker namespace to the wave-2 artifacts and re-pin"
  ```

### Task 2: Split the three capped desktop files (`../build/15-FILE-SPLIT-PLAN.md`, ten commits)

**Files:**
- Modify: `workspace/desktop/src/features/messages/ui/MessageRow.tsx` (999 gate-lines), `workspace/desktop/src/app/AppShell.tsx` (998), `workspace/desktop/src/features/home/ui/HomeView.tsx` (994)
- Create: the ten extracted modules listed in File Structure
- Test: existing colocated `*.test.mjs` for each file; `workspace/desktop/tests/e2e/` smoke project

**Interfaces:**
- Produces (MR-2, the seam that First card uses): `MessageBody.tsx` exporting `MessageBody(props: MessageBodyProps)` where `MessageBodyProps` carries `message`, `profiles` (required, per `15` §6.2, so provenance does not silently degrade), and the five render-affecting ranges `15` §4.3 names; a `default:` branch that calls `parseWaveMessageContent` and then markdown, with **one comment line marking where `useSwarmCardSurface()` will be inserted by First card** (`// perch seam: see 12-PLAN-FIRST-CARD.md Task 17`).

- [x] **Step 1: Re-derive the anchors.** The drafts were cut at `eed74bde2`; re-anchor them against the moved files:
  ```bash
  cd docs/plans/ambush-ui/build/refactor && node line-ledger.mjs --buzz ../../../../../workspace
  ```
  Expected: every anchor matched (exit 0). The explicit root is `workspace`, not `workspace/desktop`, because the ledger entries begin with `desktop/`. If it exits 2, an anchor moved in the rebrand; find it with `grep -n` and update the ledger before continuing — never the file.
- [x] **Step 2: MR-1 — extract `MessageThreadGuides.tsx`.** Copy `refactor/MessageThreadGuides.tsx` into `workspace/desktop/src/features/messages/ui/`, delete the extracted range from `MessageRow.tsx` per the ledger, import the component. Run:
  ```bash
  cd workspace && just desktop-check && just desktop-typecheck && just desktop-test && just file-size-check
  ```
  Expected: green; `MessageRow.tsx` at 798 gate-lines (three lines above the draft projection because its re-export did not import `ThreadDepthGuideAction` into local scope). The repository test command is required because it installs the alias and TypeScript loader; raw `node --test` does neither. Commit: `refactor(desktop): extract MessageThreadGuides from MessageRow (MR-1)`.
- [ ] **Step 3: MR-2 — extract `MessageBody.tsx` with the seam.** Same procedure with `refactor/MessageBody.tsx`; add the seam comment line in the `default:` branch; make `profiles` a required prop and pass it from `MessageRow`. Add a unit test `MessageBody.test.mjs` asserting that a body starting with `<!-- ambush:wave:v1 -->` still renders the wave fallback text (this pins the chat app's own marker across the split). Run the same gate; expect ~705 gate-lines. Commit: `refactor(desktop): extract MessageBody, the renderer seam (MR-2)`.
- [ ] **Step 4: AS-1 … AS-4 on `AppShell.tsx`.** One commit each from the four drafts (`useAppShellBackgroundSync.ts` −49, `useCommunityDestinationRestore.ts` −44, `useChannelCreationHandlers.ts` −77 returning booleans, `AppShellSettingsSurface.tsx` −48). After each: `just desktop-check && just desktop-typecheck && just desktop-test && just file-size-check`. Expect `AppShell.tsx` at ~780 gate-lines after AS-4. Commits: `refactor(desktop): extract useAppShellBackgroundSync (AS-1)` … `(AS-4)`.
- [ ] **Step 5: HV-1 … HV-4 on `HomeView.tsx`.** No drafts exist; cut per `15` §5.5's table. Under D3, **HV-1 extracts** the messages detail pane into `HomeMessagesDetail.tsx` (it is not deleted: The Watch replaces it only when the `perch` feature is enabled). HV-2 extracts `HomeInboxAuxiliaryPane.tsx` unchanged; HV-3 lifts the filter-change selection logic into `useHomeInboxFilterChange.ts` (a pure function `selectAfterFilterChange(items, filter, previousSelection)` that First card will extend with the four queues); HV-4 extracts `HomeFeedUnavailable.tsx`. Write `useHomeInboxFilterChange.test.mjs` covering: selection preserved when still visible, selection moves to the first visible item otherwise, empty list clears selection. Expect `HomeView.tsx` at ~736 gate-lines. Four commits `refactor(desktop): … (HV-n)`.
- [ ] **Step 6: E2E smoke.** `cd workspace/desktop && pnpm test:e2e:smoke` — expected: the existing smoke project green (it builds the mock bridge; `pnpm run build` is the wrong command).

### Task 3: Re-land the relay patches and the repair-kinds constant (W3-7)

**Files:**
- Modify: `workspace/crates/ambush-relay/src/handlers/ingest.rs` (import block :13–37; `required_scope_for_kind` arm before :545; `requires_h_channel_scope` body :704–733; tests after :3853)
- Modify: `workspace/crates/ambush-core/src/kind.rs` (`P_GATED_KINDS` :159–169; a constant after :469; `ALL_KINDS` :635–766; tests)
- Create: `workspace/crates/ambush-test-client/tests/e2e_workflow_approval.rs`, `e2e_operator_alarm_pgate.rs`
- Modify: `workspace/Justfile` (`test-unit`), `.github/workflows/workspace-ci.yml` (the relay E2E job)
- Modify: `workspace/desktop/src-tauri/src/channel_reconnect_repair.rs` (`CHANNEL_REPAIR_KINDS`)

**Interfaces:**
- Produces: `ambush_core::kind::KIND_OPERATOR_ALARM_FRAME: u32 = 26006`; `required_scope_for_kind(46010, _) == Ok(Scope::MessagesWrite)`; `requires_h_channel_scope(46010) == true`.

- [ ] **Step 1: Rewrite the patches' identifiers** (measured clean on 2026-09-02):
  ```bash
  S=$(mktemp -d)
  for p in relay-46010 relay-26006-pgate; do
    sed -e 's#crates/buzz-#crates/ambush-#g; s#buzz_core#ambush_core#g; s#buzz_test_client#ambush_test_client#g; s#BuzzTestClient#AmbushTestClient#g; s#buzz-relay#ambush-relay#g; s#buzz-core#ambush-core#g; s#buzz-test-client#ambush-test-client#g' \
      docs/plans/ambush-ui/build/patches/$p.patch > "$S/$p.patch"
  done
  git apply --check --directory=workspace --exclude='workspace/.github/*' --exclude='workspace/justfile' "$S/relay-46010.patch" "$S/relay-26006-pgate.patch"
  ```
  Expected: silent (clean).
- [ ] **Step 2: Apply the source hunks.** Same command without `--check`. `git status --short` shows `ingest.rs`, `kind.rs` modified and the two E2E files added.
- [ ] **Step 3: Hand-apply the Justfile hunk.** Open `docs/plans/ambush-ui/build/patches/relay-46010.patch` at the `justfile` hunk (`@@ -378,8 +378,14 @@ test-unit:`); apply its intent to `workspace/Justfile`'s `test-unit` recipe: add a `cargo nextest run -p ambush-relay --lib -E 'test(handlers::ingest::tests)'` line (the patch documents that no CI job ran that module before).
- [ ] **Step 4: Run the unit tests.**
  ```bash
  cd workspace && cargo test -p ambush-relay --lib workflow_approval && cargo test -p ambush-core --lib operator_alarm
  ```
  Expected: 7 and 3 tests pass. Also `cargo test -p ambush-relay --lib global_only_and_channel_scoped_are_disjoint` still passes (46010 is channel-scoped, not global-only).
- [ ] **Step 5: Run the E2E tests.** Requires Postgres and Redis (`workspace/.env` points at `127.0.0.1`, see the rebrand memory about the Lima VM squatting IPv6 localhost):
  ```bash
  cd workspace && cargo test -p ambush-test-client --test e2e_workflow_approval -- --ignored && cargo test -p ambush-test-client --test e2e_operator_alarm_pgate -- --ignored
  ```
  Expected: 6 and 8 pass, including `a_named_principal_receives_the_frame_and_an_unnamed_one_does_not` and the needs-action INNER JOIN test.
- [ ] **Step 6: Wire CI.** In `.github/workflows/workspace-ci.yml`, add both binaries to the relay E2E job where `--test e2e_event_reminder` is listed (archive step, line ~405) and to the matching `cargo nextest run -E 'binary(...)'` step (~794). YAML must parse.
- [ ] **Step 7: The repair-kinds constant.** In `channel_reconnect_repair.rs`, extend `CHANNEL_REPAIR_KINDS` with `46010`, `40100`, `39005` and add a test:
  ```rust
  #[test]
  fn repair_kinds_cover_perch_case_channel_kinds() {
      for kind in [46010u32, 40100, 39005] {
          assert!(CHANNEL_REPAIR_KINDS.contains(&kind), "kind {kind} must be repaired on reconnect");
      }
  }
  ```
  Run `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml repair_kinds_cover_perch` → pass.
- [ ] **Step 8: Commit** (two commits): `fix(relay): admit kind:46010 workflow approval requests, channel-scoped` and `feat(relay): fence kind:26006 operator alarm frames behind the p-gate`.

### Task 4: H1 — delete animated-avatar capture and pin the CSP (INV-30 as narrowed by W3-23)

**Files:**
- Delete: `workspace/desktop/src/features/profile/ui/AnimatedAvatarCapture.tsx`, `ui/AnimatedAvatarCapture.helpers.ts`, `lib/animatedAvatarCapture.ts`, `lib/animatedAvatarCapture.test.mjs`
- Modify: their import sites (find with `grep -rln "AnimatedAvatarCapture\|animatedAvatarCapture" workspace/desktop/src`)
- Modify: `workspace/desktop/src-tauri/tauri.conf.json` line 39
- Create: `workspace/desktop/src-tauri/src/csp_pin_tests.rs` (+ `mod csp_pin_tests;` under `#[cfg(test)]` in `lib.rs`)

- [ ] **Step 1: Write the failing test.**
  ```rust
  //! INV-30 (as narrowed by 00-DECISIONS W3-23): the CSP is a pinned literal.
  const PINNED_CSP: &str = "default-src 'self'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self' ipc: http://ipc.localhost ambush-media: http://ambush-media.localhost https: http: wss: ws:; img-src 'self' ambush-media: http://ambush-media.localhost data: blob: https: http:; media-src 'self' ambush-media: http://ambush-media.localhost data: blob: https: http:; worker-src 'self' blob:";

  #[test]
  fn csp_is_the_pinned_literal() {
      let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json"))
          .unwrap_or_else(|e| panic!("tauri.conf.json must parse: {e}"));
      let csp = conf["app"]["security"]["csp"].as_str().unwrap_or_default();
      assert_eq!(csp, PINNED_CSP, "security.csp changed; widening it is a reviewed edit of this test");
  }

  #[test]
  fn csp_has_no_remote_script_source() {
      let script_src = PINNED_CSP.split(';').find(|d| d.trim().starts_with("script-src")).unwrap_or_default();
      assert!(!script_src.contains("http"), "script-src must not name a remote host: {script_src}");
  }
  ```
  (Adjust the JSON path if the key sits at the top level in this Tauri version; `grep -n '"csp"' tauri.conf.json` shows it.)
- [ ] **Step 2: Run it.** `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml csp_` → `csp_is_the_pinned_literal` FAILS (the live CSP still carries the mediapipe host).
- [ ] **Step 3: Delete the feature.** Remove the four files; remove the capture entry point from the profile UI at each import site (the avatar picker keeps static images). Run `cd workspace && just desktop-check && just desktop-typecheck && just desktop-test`.
- [ ] **Step 4: Pin.** Edit line 39 of `tauri.conf.json` to the literal above (the only change is the removal of ` https://cdn.jsdelivr.net/npm/@mediapipe/`). Assert no other reference remains: `grep -rn "mediapipe\|storage.googleapis.com" workspace/desktop/src workspace/desktop/src-tauri/src` → nothing.
- [ ] **Step 5: Run.** The two tests pass; `pnpm test:e2e:smoke` green.
- [ ] **Step 6: Commit.** `feat(desktop)!: remove animated-avatar capture and pin the CSP`.

### Task 5: H2 — `perch_sign_gate` at every signing boundary (INV-29, W3-2)

**Files:**
- Create: `workspace/desktop/src-tauri/src/perch_sign_gate.rs` (+ `pub mod perch_sign_gate;` in `lib.rs`)
- Modify: `commands/identity.rs` (`sign_event`, ~:107), `commands/messages.rs` (`send_channel_message` ~:409, `send_managed_agent_channel_message` ~:697, the third `content: String` command at ~:862–878), `commands/project_git_workflow.rs` (~:78–92)
- Create: `workspace/desktop/src-tauri/src/perch_sign_gate_inventory_tests.rs`

**Interfaces:**
- Produces: `pub fn perch_sign_gate(kind: u16, content: &str) -> Result<(), String>`; `pub fn is_swarm_marker_line(line: &str) -> bool`.

- [ ] **Step 1: Write the failing tests** in `perch_sign_gate.rs`:
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;
      #[test] fn refuses_kind_46010_outright() { assert!(perch_sign_gate(46010, "anything").is_err()); }
      #[test] fn refuses_a_kind_9_governance_marker() {
          assert!(perch_sign_gate(9, "<!-- swarm:verdict:v1 -->\n{}\nhuman").is_err());
          assert!(perch_sign_gate(9, "<!-- swarm:finding:v1 -->").is_err());
          assert!(perch_sign_gate(9, "<!-- swarm:hold:v12 -->   ").is_err(), "trailing whitespace is trimmed");
      }
      #[test] fn allows_the_chat_apps_own_markers_and_prose() {
          assert!(perch_sign_gate(9, "<!-- ambush:wave:v1 -->\nhello").is_ok());
          assert!(perch_sign_gate(9, "hello <!-- swarm:verdict:v1 -->").is_ok(), "not the whole line");
          assert!(perch_sign_gate(9, " <!-- swarm:verdict:v1 -->").is_ok(), "leading space: the renderer will not parse it either");
          assert!(perch_sign_gate(40002, "<!-- swarm:verdict:v1 -->").is_ok(), "only kind 9 carries cards");
      }
      #[test] fn marker_grammar_is_exact() {
          assert!(is_swarm_marker_line("<!-- swarm:finding:v1 -->"));
          assert!(!is_swarm_marker_line("<!-- swarm:Finding:v1 -->"));
          assert!(!is_swarm_marker_line("<!-- swarm:finding:1 -->"));
          assert!(!is_swarm_marker_line("<!-- swarm:finding:v -->"));
          assert!(!is_swarm_marker_line("<!-- swarm::v1 -->"));
      }
  }
  ```
- [ ] **Step 2: Run.** `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml perch_sign_gate` → compile failure (functions undefined).
- [ ] **Step 3: Implement.**
  ```rust
  //! ADR 0014 C1 / INV-29: no renderer-supplied content may be signed as a swarm
  //! governance marker, on any command. `perch_record_verdict` is the only
  //! producer of `swarm:verdict:v1`, and it never passes its content here.

  /// The kind the swarm bridge alone may publish (a held destructive action).
  pub const KIND_WORKFLOW_APPROVAL_REQUESTED: u16 = 46010;

  /// Refuses kind 46010 outright and any kind 9 whose line 0 is exactly a
  /// `<!-- swarm:<slug>:v<N> -->` marker (line 0 is `trim_end`ed, never `trim_start`ed,
  /// matching the renderer's whole-line rule).
  pub fn perch_sign_gate(kind: u16, content: &str) -> Result<(), String> {
      if kind == KIND_WORKFLOW_APPROVAL_REQUESTED {
          return Err("restricted: kind 46010 is published by the swarm bridge only".to_string());
      }
      if kind == 9 {
          let line0 = content.split('\n').next().unwrap_or("").trim_end();
          if is_swarm_marker_line(line0) {
              return Err("restricted: swarm markers are produced by perch_record_verdict only".to_string());
          }
      }
      Ok(())
  }

  /// `^<!-- swarm:[a-z]+:v\d+ -->$` without a regex dependency.
  pub fn is_swarm_marker_line(line: &str) -> bool {
      let Some(rest) = line.strip_prefix("<!-- swarm:") else { return false };
      let Some(rest) = rest.strip_suffix(" -->") else { return false };
      let mut parts = rest.split(':');
      let (Some(slug), Some(version), None) = (parts.next(), parts.next(), parts.next()) else { return false };
      let slug_ok = !slug.is_empty() && slug.bytes().all(|b| b.is_ascii_lowercase());
      let version_ok = version.len() >= 2 && version.starts_with('v') && version[1..].bytes().all(|b| b.is_ascii_digit());
      slug_ok && version_ok
  }
  ```
- [ ] **Step 4: Run.** The four tests pass.
- [ ] **Step 5: Wire the five call sites.** In each command, immediately after the kind is resolved and **before** `state.signing_keys()`: `crate::perch_sign_gate::perch_sign_gate(kind, &content)?;` — for `sign_event` the `kind: u16` parameter as-is; for `send_channel_message` the resolved `Option<u32>` cast with `u16::try_from(kind).map_err(|_| "invalid kind".to_string())?`; for the announcement path its `kind: u16`. Where the command's error type is not `String`, map with the command's existing conversion.
- [ ] **Step 6: The inventory test** (`perch_sign_gate_inventory_tests.rs`, following `egress_guard_tests.rs`'s shape):
  ```rust
  //! ADR 0014 C1 obligation 3: the set of commands that must call the gate is
  //! asserted, not remembered. Every `#[tauri::command]` under commands/ that
  //! reaches `state.signing_keys()` and takes a `content: String` parameter
  //! must call `perch_sign_gate(` in the same function body.
  use std::{fs, path::Path};

  fn command_bodies(src: &str) -> Vec<(String, String)> {
      let mut out = Vec::new();
      let mut idx = 0;
      while let Some(pos) = src[idx..].find("#[tauri::command]") {
          let start = idx + pos;
          let sig_start = src[start..].find("fn ").map(|p| start + p).unwrap_or(start);
          let name_end = src[sig_start + 3..].find(['(', '<']).map(|p| sig_start + 3 + p).unwrap_or(sig_start + 3);
          let name = src[sig_start + 3..name_end].trim().to_string();
          let body_end = src[start..].find("\n}\n").map(|p| start + p + 3).unwrap_or(src.len());
          out.push((name, src[start..body_end].to_string()));
          idx = body_end;
      }
      out
  }

  #[test]
  fn every_content_signing_command_calls_the_gate() {
      let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands");
      let mut violations = Vec::new();
      let mut audited = 0;
      for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}")).flatten() {
          let path = entry.path();
          if path.extension().and_then(|e| e.to_str()) != Some("rs") || path.to_string_lossy().ends_with("_tests.rs") { continue; }
          let src = fs::read_to_string(&path).unwrap_or_default();
          for (name, body) in command_bodies(&src) {
              let signs = body.contains("signing_keys()");
              let takes_content = body.contains("content: String");
              if signs && takes_content {
                  audited += 1;
                  if !body.contains("perch_sign_gate(") { violations.push(format!("{}::{name}", path.display())); }
              }
          }
      }
      assert!(audited >= 5, "baseline on 2026-09-02 was five commands; found {audited}");
      assert!(violations.is_empty(), "commands signing renderer content without the gate: {violations:?}");
  }
  ```
  Register with `#[cfg(test)] mod perch_sign_gate_inventory_tests;` in `lib.rs`.
- [ ] **Step 7: Run.** `cargo test --manifest-path workspace/desktop/src-tauri/Cargo.toml every_content_signing_command_calls_the_gate` → pass once all five sites are wired; deliberately remove one call and confirm it fails, then restore.
- [ ] **Step 8: Commit.** `feat(desktop): gate every content-signing command against swarm governance markers (INV-29)`.

### Task 6: H3 — `resetCommunityState` as a typed registry (INV-23)

**Files:**
- Create: `workspace/desktop/src/features/communities/communityScopedRegistry.ts`, `communityScopedRegistry.test.mjs`
- Modify: `workspace/desktop/src/features/communities/useCommunityInit.ts` (`resetCommunityState`, :54–84)

**Interfaces:**
- Produces: `export const COMMUNITY_SCOPED_SINGLETONS = [...] as const`; `export type CommunityScopedSingleton`; `export const RESETTERS: Record<CommunityScopedSingleton, Resetter>`; `export async function runResetters(ctx: ResetContext): Promise<void>`; `export type ResetContext = { resetAvatarState: boolean; isMacTauri: boolean }`.

- [ ] **Step 1: Write the failing test.**
  ```js
  import test from "node:test";
  import assert from "node:assert/strict";
  import { COMMUNITY_SCOPED_SINGLETONS, RESETTERS, runResetters } from "./communityScopedRegistry.ts";

  test("every named singleton has a resetter and nothing else does", () => {
    assert.deepEqual(Object.keys(RESETTERS).sort(), [...COMMUNITY_SCOPED_SINGLETONS].sort());
  });

  test("resetters run in declaration order, sequentially", async () => {
    const order = [];
    const fakes = Object.fromEntries(COMMUNITY_SCOPED_SINGLETONS.map((k) => [k, async () => { order.push(k); }]));
    await runResetters({ resetAvatarState: true, isMacTauri: false }, fakes);
    assert.deepEqual(order, [...COMMUNITY_SCOPED_SINGLETONS]);
  });

  test("avatar resetters are skipped when resetAvatarState is false", async () => {
    const order = [];
    const fakes = Object.fromEntries(COMMUNITY_SCOPED_SINGLETONS.map((k) => [k, () => { order.push(k); }]));
    await runResetters({ resetAvatarState: false, isMacTauri: false }, fakes);
    assert.ok(!order.includes("avatarProfileSync") && !order.includes("avatarPresentations"));
  });
  ```
- [ ] **Step 2: Run.** `cd workspace/desktop && node --test src/features/communities/communityScopedRegistry.test.mjs` → module not found.
- [ ] **Step 3: Implement** `communityScopedRegistry.ts`, transcribing the 21 calls in `resetCommunityState`'s body in their current order:
  ```ts
  export const COMMUNITY_SCOPED_SINGLETONS = [
    "relayClient", "navigationDeepLinkDrain", "rateLimitGate", "drafts",
    "agentObserverStore", "activeAgentTurnsStore", "agentWorkingSignal", "trayAgentActivity",
    "avatarProfileSync", "avatarPresentations", "sidebarRelayConnectionCard", "mediaCaches",
    "linkPreviewMetadataCache", "videoPlayerState", "renderScopedReactionHydration",
    "backgroundMediaUploads", "linkPreviewPreparations", "persistentAgentAudienceStore",
    "searchHitEventCache", "markdownNodeCache", "messageLinkMetadataCache",
  ] as const;
  export type CommunityScopedSingleton = (typeof COMMUNITY_SCOPED_SINGLETONS)[number];
  export type ResetContext = { resetAvatarState: boolean; isMacTauri: boolean };
  export type Resetter = (ctx: ResetContext) => void | Promise<void>;
  const AVATAR_ONLY = new Set<CommunityScopedSingleton>(["avatarProfileSync", "avatarPresentations"]);
  const MAC_TAURI_ONLY = new Set<CommunityScopedSingleton>(["trayAgentActivity"]);
  export const RESETTERS: Record<CommunityScopedSingleton, Resetter> = {
    relayClient: () => relayClient.disconnect(),
    navigationDeepLinkDrain: () => resetNavigationDeepLinkDrain(),
    rateLimitGate: () => resetRateLimitGate(),
    drafts: () => clearAllDrafts(),
    agentObserverStore: () => resetAgentObserverStore(),
    activeAgentTurnsStore: () => resetActiveAgentTurnsStore(),
    agentWorkingSignal: () => resetAgentWorkingSignal(),
    trayAgentActivity: () => { void clearTrayAgentActivity(); },
    avatarProfileSync: () => resetAvatarProfileSync(),
    avatarPresentations: () => resetAvatarPresentations(),
    sidebarRelayConnectionCard: () => resetSidebarRelayConnectionCardState(),
    mediaCaches: () => resetMediaCaches(),
    linkPreviewMetadataCache: () => resetLinkPreviewMetadataCache(),
    videoPlayerState: () => resetVideoPlayerState(),
    renderScopedReactionHydration: () => resetRenderScopedReactionHydration(),
    backgroundMediaUploads: () => resetBackgroundMediaUploads(),
    linkPreviewPreparations: () => resetLinkPreviewPreparations(),
    persistentAgentAudienceStore: () => resetPersistentAgentAudienceStore(),
    searchHitEventCache: () => clearSearchHitEventCache(),
    markdownNodeCache: () => clearMarkdownNodeCache(),
    messageLinkMetadataCache: () => resetMessageLinkMetadataCache(),
  };
  export async function runResetters(ctx: ResetContext, resetters: Record<CommunityScopedSingleton, Resetter> = RESETTERS): Promise<void> {
    for (const key of COMMUNITY_SCOPED_SINGLETONS) {
      if (AVATAR_ONLY.has(key) && !ctx.resetAvatarState) continue;
      if (MAC_TAURI_ONLY.has(key) && !ctx.isMacTauri) continue;
      await resetters[key](ctx);
    }
  }
  ```
  (Imports are the ones `useCommunityInit.ts` already has; move them.) `resetCommunityState` becomes `await runResetters({ resetAvatarState, isMacTauri: isTauri() && isMacPlatform() })`.
- [ ] **Step 4: Run.** The three tests pass; `just desktop-check && just desktop-typecheck && just desktop-test` green; the existing community-switch specs in `tests/e2e/` still pass under `pnpm test:e2e:smoke`.
- [ ] **Step 5: Commit.** `refactor(desktop): resetCommunityState as a typed, exhaustive resetter registry (INV-23)`.

### Task 7: H7 — the ws-client's four panic sites become typed errors (W3-6)

**Files:**
- Modify: `workspace/crates/ambush-ws-client/src/connection.rs` (:165–175 and :225–235), `error.rs`
- Modify: `tools/check-runtime-panic-contract.sh` (enumeration)

- [ ] **Step 1: Write the failing test** in `connection.rs`'s test module — a buffer whose `position()` match and `remove()` disagree cannot be constructed from outside, so test the extracted helper instead:
  ```rust
  #[test]
  fn take_buffered_returns_a_typed_error_when_the_slot_is_not_the_expected_variant() {
      let mut buf: std::collections::VecDeque<RelayMessage> = std::collections::VecDeque::new();
      buf.push_back(RelayMessage::Notice("x".into()));
      let got = take_buffered(&mut buf, 0, |m| matches!(m, RelayMessage::Auth { .. }));
      assert!(matches!(got, Err(WsClientError::Protocol(_))));
  }
  ```
- [ ] **Step 2: Run.** `cd workspace && cargo test -p ambush-ws-client take_buffered` → compile failure.
- [ ] **Step 3: Implement.** Add to `error.rs` a variant `Protocol(String)` (with its `Display` arm, `"protocol: {0}"`) if none like it exists. In `connection.rs`:
  ```rust
  /// Removes `idx` from the buffer and returns it only if it satisfies `is_expected`;
  /// otherwise a typed error. Replaces `remove(idx).unwrap()` + `unreachable!()`
  /// (ADR 0015 C6 as amended by 00-DECISIONS W3-6): the daemon that will host
  /// this client runs with panic = "abort".
  fn take_buffered(
      buf: &mut std::collections::VecDeque<RelayMessage>,
      idx: usize,
      is_expected: impl Fn(&RelayMessage) -> bool,
  ) -> Result<RelayMessage, WsClientError> {
      match buf.remove(idx) {
          Some(msg) if is_expected(&msg) => Ok(msg),
          Some(other) => { buf.push_front(other); Err(WsClientError::Protocol("buffered relay message changed variant between position() and remove()".into())) }
          None => Err(WsClientError::Protocol("buffered relay message vanished between position() and remove()".into())),
      }
  }
  ```
  Replace both `match self.buffer.remove(idx).unwrap() { … _ => unreachable!() }` blocks with `match take_buffered(&mut self.buffer, idx, |m| matches!(m, RelayMessage::Auth { .. }))? { RelayMessage::Auth { challenge } => return Ok(challenge), _ => return Err(WsClientError::Protocol("auth slot was not an AUTH frame".into())) }` and the `Ok` equivalent (keyed on `event_id`).
- [ ] **Step 4: Run.** `cargo test -p ambush-ws-client` green; `grep -n "unwrap()\|unreachable!" workspace/crates/ambush-ws-client/src/connection.rs` → nothing outside `#[cfg(test)]`.
- [ ] **Step 5: Bring the crate under the engine's panic gate.** In `tools/check-runtime-panic-contract.sh`, add `workspace/crates/ambush-ws-client/src` to the enumerated roots (the script's header names them). Run `bash tools/check-runtime-panic-contract.sh` → exit 0.
- [ ] **Step 6: Commit.** `fix(ws-client): replace the four panic sites with typed errors; enrol the crate in the panic contract`.

### Task 8: B0 — `nostr_pubkey` on the operator principal

**Files:**
- Modify: `crates/swarm-core/src/config/operator.rs` (`OperatorPrincipalConfig` :118–129, `OperatorAuthConfig`, `effective_principals` :153–168, validation)

**Interfaces:**
- Produces: `pub nostr_pubkey: Option<String>` on both structs; `OperatorPrincipalConfig::nostr_pubkey_bytes(&self) -> Option<[u8; 32]>`.

- [ ] **Step 1: Write the failing tests** in the module's test block:
  ```rust
  #[test]
  fn principal_without_nostr_pubkey_still_loads() {
      let yaml = "operator_id: ops\ntoken_env: SWARM_OPERATOR_TOKEN\nscopes: [approve]\n";
      let p: OperatorPrincipalConfig = serde_yaml::from_str(yaml).unwrap_or_else(|e| panic!("{e}"));
      assert!(p.nostr_pubkey.is_none());
  }
  #[test]
  fn principal_with_nostr_pubkey_round_trips_and_validates() {
      let hex = "a".repeat(64);
      let yaml = format!("operator_id: ops\ntoken_env: T\nscopes: [approve]\nnostr_pubkey: {hex}\n");
      let p: OperatorPrincipalConfig = serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("{e}"));
      assert_eq!(p.nostr_pubkey.as_deref(), Some(hex.as_str()));
      assert!(p.validate().is_ok());
      assert_eq!(p.nostr_pubkey_bytes().map(|b| b.len()), Some(32));
  }
  #[test]
  fn malformed_nostr_pubkey_is_rejected_at_validation() {
      for bad in ["npub1abc", &"A".repeat(64), &"a".repeat(63)] {
          let p = OperatorPrincipalConfig { operator_id: "o".into(), token_env: "T".into(), token_expires_at_ms: None, scopes: vec![OperatorScope::Approve], nostr_pubkey: Some(bad.to_string()) };
          assert!(p.validate().is_err(), "{bad}");
      }
  }
  #[test]
  fn legacy_single_principal_form_carries_the_pubkey_through() {
      let auth = OperatorAuthConfig { nostr_pubkey: Some("b".repeat(64)), ..OperatorAuthConfig::default() };
      assert_eq!(auth.effective_principals()[0].nostr_pubkey.as_deref(), Some("b".repeat(64).as_str()));
  }
  ```
- [ ] **Step 2: Run.** `cargo test -p swarm-core nostr_pubkey` → compile failure.
- [ ] **Step 3: Implement.** Add to both structs:
  ```rust
  /// The operator's Nostr public key (64 lowercase hex), used by the swarm bridge to
  /// `p`-tag held actions and hold alarms so they reach this principal's console.
  /// Optional: without it no hold can be addressed to this principal (00-DECISIONS D1;
  /// 01-DESIGN §6 B0). It is configured, not proven — see ADR 0016.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub nostr_pubkey: Option<String>,
  ```
  `effective_principals()` copies `self.nostr_pubkey.clone()` into the synthesized principal. Add `pub fn nostr_pubkey_bytes(&self) -> Option<[u8; 32]>` decoding hex, and extend the existing `validate()` (or the config loader's principal validation) with: if `Some(k)`, then `k.len() == 64 && k.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))`, else `Err(OperatorConfigError::InvalidNostrPubkey { operator_id })`.
- [ ] **Step 4: Run.** The four tests pass; `cargo clippy --workspace --all-targets -- -D warnings` clean; `swarmctl validate` on `rulesets/default.yaml` still passes (the field is absent there).
- [ ] **Step 5: Commit.** `feat(core): nostr_pubkey on operator principals (B0)`.

### Task 9: The dev ruleset and its signing binary (P0-22)

**Files:**
- Create: `rulesets/perch-dev.yaml`, `rulesets/perch-dev.yaml.sig.json`
- Create: `crates/swarm-runtime-http/src/bin/sign_dev_ruleset.rs` (+ `[[bin]]` entry)

- [ ] **Step 1: Generate, then edit.**
  ```bash
  cargo run -p swarm-runtime-http --bin swarmctl -- init --mode detect_only --output rulesets/perch-dev.yaml
  ```
  Then set, keeping every other generated value: `operator_surface.enabled: true`; `correlation.enabled: true`; `correlation.incident_store` to the file-backed variant (the `BundleStoreConfig` enum's non-memory arm — `swarmctl validate` rejects an unknown key, so the wrong spelling fails loudly); `audit.recent_decisions_limit: 200`; one operator principal with `scopes: [read, rehearse, approve, maintenance]`, `token_env: SWARM_OPERATOR_TOKEN`, and `nostr_pubkey` set to the dev operator key `scripts/provision-perch.sh` prints. Leave `runtime.mode: detect_only` (D4).
- [ ] **Step 2: The signing binary.**
  ```rust
  //! Signs a development ruleset with the in-repo DEBUG key. A `--release` daemon
  //! refuses this signature (the debug trust root is `#[cfg(debug_assertions)]`
  //! only), which is the intended behaviour: production signs its own.
  fn main() -> Result<(), Box<dyn std::error::Error>> {
      let path = std::env::args().nth(1).ok_or("usage: sign_dev_ruleset <ruleset.yaml>")?;
      swarm_runtime::config::write_debug_test_config_signature(&path)?;
      println!("wrote {path}.sig.json");
      Ok(())
  }
  ```
- [ ] **Step 3: Sign and validate.** `cargo run -p swarm-runtime-http --bin sign_dev_ruleset -- rulesets/perch-dev.yaml && cargo run -p swarm-runtime-http --bin swarmctl -- validate --config rulesets/perch-dev.yaml` → valid; commit the sidecar (`git status --porcelain rulesets/` clean afterwards).
- [ ] **Step 4: Prove the release refusal.** `cargo run --release -p swarm-runtime-http --bin swarm_detect -- --config rulesets/perch-dev.yaml --serve --bind 127.0.0.1:9099` → exits with a signature-trust error (record the text in the commit message). Debug build: `cargo run -p swarm-runtime-http --bin swarm_detect -- --config rulesets/perch-dev.yaml --serve --bind 127.0.0.1:9099` → `curl -sf http://127.0.0.1:9099/readyz` succeeds and the log says the operator surface is enabled.
- [ ] **Step 5: Commit.** `feat(rulesets): perch-dev profile with a debug-signed sidecar and its signing binary`.

### Task 10: The dev stack — relay, Postgres, Redis beside the daemon (P0-21)

**Files:**
- Modify: `docker-compose.yml`
- Create: `scripts/provision-perch.sh`

- [ ] **Step 1: Add the three services**, transcribed from `workspace/docker-compose.yml`'s `postgres` and `redis` blocks (same images, healthchecks and memory limits; ports bound to `127.0.0.1`), plus:
  ```yaml
    relay:
      build:
        context: ./workspace
        dockerfile: Dockerfile
      container_name: ambush-relay
      env_file: ./workspace/.env
      ports:
        - "127.0.0.1:3000:3000"
      depends_on:
        postgres: { condition: service_healthy }
        redis: { condition: service_healthy }
      healthcheck:
        test: ["CMD-SHELL", "wget -qO- http://localhost:3000/health || exit 1"]
        interval: 10s
        timeout: 3s
        retries: 5
      restart: unless-stopped
  ```
  The relay applies its own migrations on start (`workspace/CLAUDE.md`). `swarm-detect` gains `depends_on: relay`.
- [ ] **Step 2: Provisioning.** `scripts/provision-perch.sh` uses `workspace/target/release/ambush` (the CLI) with a generated dev operator key to: mint the twelve lane channels named by `standard_threat_classes()` (open visibility), print the operator pubkey (for Task 9's `nostr_pubkey`), and write `.perch-dev/lane-channels.json` (git-ignored) mapping threat-class slug → channel UUID. Membership for the bridge identities is First card's job (it derives them).
- [ ] **Step 3: Run.** `docker compose up -d postgres redis relay && curl -sf -H 'Accept: application/nostr+json' http://localhost:3000 | head -c 200` → the NIP-11 document; `bash scripts/provision-perch.sh` → twelve channel ids.
- [ ] **Step 4: Commit.** `feat(dev): compose the relay stack beside swarm-detect, and provision the lanes`.

### Task 11: `preview-features.json` gains `perch`

**Files:**
- Modify: `workspace/preview-features.json`
- Test: `workspace/desktop/src/shared/features/manifest.test.mjs` (create if absent)

- [ ] **Step 1: Failing test.**
  ```js
  import test from "node:test"; import assert from "node:assert/strict";
  import { getFeature } from "./manifest.ts";
  test("the perch console is a desktop preview feature, off by default", () => {
    const f = getFeature("perch");
    assert.ok(f, "perch entry missing from preview-features.json");
    assert.deepEqual(f.platforms, ["desktop"]);
    assert.notEqual(f.defaultEnabled, true);
  });
  ```
- [ ] **Step 2: Run** → fails. **Step 3:** append to `features`: `{ "id": "perch", "name": "Operator console", "description": "Lanes, cases and the verdict queue for the swarm engine", "platforms": ["desktop"] }`. **Step 4:** run → pass; `just desktop-check`. **Step 5:** commit `feat(desktop): register the perch console as a preview feature`.

### Task 12: Engine CI gains a `changes` job

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1:** Add a first job, modelled on `workspace-ci.yml`'s:
  ```yaml
    changes:
      runs-on: ubuntu-latest
      outputs:
        engine: ${{ steps.filter.outputs.engine }}
      steps:
        - uses: actions/checkout@v4
          with: { fetch-depth: 2 }
        - uses: dorny/paths-filter@ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d # v4.0.3
          id: filter
          with:
            token: ''
            filters: |
              engine:
                - '!workspace/**'
                - '!docs/plans/**'
  ```
  and `needs: changes` + `if: needs.changes.outputs.engine == 'true'` on every existing job. Jobs skipped by `if:` satisfy branch protection; a top-level `paths:` would not.
- [ ] **Step 2:** `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → ok; `bash tools/check-gates-wired.sh` → still finds every gate's `run:` step. Commit `ci(engine): skip engine lanes on workspace-only changes without pending required checks`.

### Task 13: Documentation touch-ups the tasks above force

- [ ] **Step 1:** `01-DESIGN.md` §9: move H8 to First card (W3-24) and note W3-23 on H1. **Step 2:** `workspace/CLAUDE.md`: add one paragraph under "Community Switching" pointing at `communityScopedRegistry.ts` as the inventory. **Step 3:** commit `docs: align the design and the workspace guide with Ground`.

### Task 14: Ground exit

- [ ] **Step 1:** At the root: `cargo build --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` (expect the known flaky notification tests noted in `.planning/STATE.md` to be the only noise) and every `tools/check-*.sh` that CI runs.
- [ ] **Step 2:** In `workspace/`: `just ci`.
- [ ] **Step 3:** The fixture validators of Task 1 step 5, again, from a clean checkout.
- [ ] **Step 4:** Record the exit in `20-ROADMAP.md`'s milestone table with the commit hash.

---

## Self-Review

- **Spec coverage.** `01-DESIGN.md` §2 layout (Task 12 completes CI); §4 wire (Task 1); §7 seam precondition (Task 2), feature gate (Task 11); §8 relay (Task 3); §9 H1 (Task 4), H2 (Task 5), H3 (Task 6), H7 (Task 7), H8 moved (W3-24); §6 B0 (Task 8); §12 dev stack and dev ruleset (Tasks 9, 10).
- **Placeholder scan.** Task 1 step 5 and Task 9 step 1 instruct the executor to read a tool or enum before acting; both name the tool and the check that fails loudly if the reading was wrong.
- **Type consistency.** `perch_sign_gate(kind: u16, content: &str)` in Task 5 is the signature `12-PLAN-FIRST-CARD.md` wires into `perch_record_verdict`'s neighbours; `RESETTERS` / `COMMUNITY_SCOPED_SINGLETONS` are what First card's `perchSubscriptions` and `perchEphemeralStore` register into; `KIND_OPERATOR_ALARM_FRAME` is the constant the bridge's alarm publisher and the console's `watch-alarm` REQ both cite.

## Exit criteria

1. `grep -rE "ambush:(finding|escalation|hold|verdict|receipt|lease|rollback):v1|ambush\.perch\." docs/plans/ambush-ui/build` returns nothing; the four validators in Task 1 step 5 pass.
2. `AppShell.tsx`, `MessageRow.tsx`, `HomeView.tsx` measure ≤ 800 gate-lines each and `MessageBody.tsx` carries the seam comment.
3. A signed kind 46010 with an `h` tag is accepted by the relay and appears in the needs-action feed of its `p`-tagged pubkey; a `REQ {kinds:[26006]}` without `#p` = self is `CLOSED`.
4. `tauri.conf.json`'s CSP equals the pinned literal and names no remote script host; the desktop builds and the smoke E2E project passes.
5. `every_content_signing_command_calls_the_gate` passes and fails when any one call is removed.
6. `runResetters` covers the 21 singletons; community switching E2E green.
7. `ambush-ws-client` has zero `unwrap()` / `unreachable!()` in production paths and is enumerated by the engine's panic gate.
8. A principal with `nostr_pubkey` loads; a malformed one is rejected at validation.
9. `docker compose up` brings up relay, Postgres, Redis and `swarm-detect`; a debug `swarm_detect --config rulesets/perch-dev.yaml --serve` reports ready; a release build refuses the same file.
10. `getFeature("perch")` exists and is off by default.

## Sizing

| Task | Days | Note |
|---|---|---|
| 1 rename and re-pin | 1 | mechanical; the hash recomputation is the only judgement |
| 2 three splits | 3 | ten commits; HV drafts are written from scratch |
| 3 relay patches + repair kinds | 1 | patches proven to apply; E2E needs the local stack |
| 4 CSP pin | 0.5 | |
| 5 sign gate + inventory test | 1 | five call sites, differing error types |
| 6 resetter registry | 1 | |
| 7 ws-client panic sites | 0.5 | |
| 8 B0 | 0.5 | |
| 9 dev ruleset + signer | 0.5 | |
| 10 dev stack + provisioning | 1 | the CLI channel-create path must be exercised |
| 11 feature entry | 0.25 | |
| 12 engine CI changes job | 0.5 | verifiable only on push |
| 13–14 docs and exit | 0.75 | |
| **Total** | **~11.5 days** | two tracks in parallel: ~6 days wall-clock |

Wave 2 priced Phase 0 at 24.75 engineer-weeks; the difference is the withdrawn deletion programme (D3), the fork and rebrand tasks already done, and the plan set's own drafts doing the splits.
