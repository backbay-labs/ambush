# 10 — The relay fork, as an applicable patch

**Artifacts — two patches, not one.**

| Patch | Bytes / lines | `sha256` | Shape | Destination |
|---|---|---|---|---|
| `build/patches/relay-46010.patch` | 23,744 B / 564 lines | `1f47383c14e86e5b037ac3c8ec6ada0103a8748ecf3d89d20d45b0f03c072dbe` | 4 files, 7 hunks, +500 / −5 | **an upstream PR to `block/buzz`** (§7) |
| `build/patches/relay-26006-pgate.patch` | 28,945 B / 699 lines | `b63eb4b1beed84bdab504309525afb39ef99974fde2aa6423c5018f776e64998` | 3 files, 6 hunks, +652 / −0 | **carried by Perch** (§11), separately upstreamable later |

**Both apply to** `BUZZ` = `/Users/connor/Medica/backbay/buzz` @
`eed74bde2f4797714335ac10c56c0b0244c1def4`, **alone and in either order.** Verified this
session on a scratch copy of every file either patch touches:

```
$ git -C $BUZZ apply --check build/patches/relay-46010.patch      ; echo $?   # 0
$ git -C $BUZZ apply --check build/patches/relay-26006-pgate.patch ; echo $?  # 0
$ # then, on a scratch tree seeded from eed74bde2:
  order 1,2: apply-ok=1  ci.yml e2e lines=2  tests/=[e2e_operator_alarm_pgate.rs e2e_workflow_approval.rs]
  order 2,1: apply-ok=1  ci.yml e2e lines=2  tests/=[e2e_operator_alarm_pgate.rs e2e_workflow_approval.rs]
  p1 alone : apply-ok=1  ci.yml e2e lines=1  tests/=[e2e_workflow_approval.rs]
  p2 alone : apply-ok=1  ci.yml e2e lines=1  tests/=[e2e_operator_alarm_pgate.rs]
$ git -C $BUZZ status --porcelain | wc -l                                     # 0
```

Commutativity is not a nicety here. If the 46010 fix is accepted upstream, only the second
patch is carried, and it must still apply to a tree that already contains the first change.
It cost one line: `relay-46010.patch`'s `ci.yml` hunk is generated with two lines of context
rather than three, so its trailing context stops short of the line the second patch inserts.
(An earlier draft with three lines of trailing context failed in the 2→1 order, measured.)

To apply: `git apply build/patches/<name>.patch` from the Buzz repo root, then `git commit -s`
— the **DCO Check** fails any commit without a `Signed-off-by` trailer.

This document owns both patches and the relay-side behaviour they turn on. It does **not** own
the bridge that publishes the events (`11-BRIDGE-CRATE.md`), their wire bodies
(`13-WIRE-SCHEMAS.md`), the daemon routes they mirror (`12-BACKEND-BILL-API.md`), or the
console's read model (`14-CLIENT-ARCHITECTURE.md`). Shared values are cited from
`APPENDIX-NORMATIVE.md`, never restated.

> **Where the second patch came from.** Wave 1 left the `26006` disclosure hole unowned:
> this document and `11-BRIDGE-CRATE.md` each named the other as its owner. Wave 2 then
> produced **two** owners with **opposite** designs — `13-WIRE-SCHEMAS.md`'s amendment W-1
> (give the frame an `h` tag) and `21-ADRS.md` / ADR 0017's clause C3 (add the kind to
> `P_GATED_KINDS`) — each stating in its own text that no other mechanism is needed.
> **§11 is the arbitration**, made here because both mechanisms are relay behaviour and this
> document owns the relay. Short version: they are not alternatives, they compose, they
> compose only under a rule neither document states, and the rule is load-bearing enough to
> have its own two E2E tests. Read §11 before implementing either.

---

## 0. What was verified, and what was not

| Claim | Method | Result |
|---|---|---|
| Each patch applies to a clean `eed74bde2` tree | `git apply --check`, each alone | **verified**, exit 0 both, working tree still clean (`git status --porcelain` → 0 lines) |
| The two patches commute | seeded scratch tree, `git apply` in both orders, then diffed the result against the intended files | **verified** — identical trees, and each applied alone produces exactly its own half |
| Every changed or added Rust file is rustfmt-canonical **after both patches** | applied both to a scratch tree, ran `rustfmt --edition 2021` on all four Rust files, diffed | **verified** — `ingest.rs`, `kind.rs`, `e2e_workflow_approval.rs`, `e2e_operator_alarm_pgate.rs` all report CANONICAL. Toolchain is the repo's own pin (`rust-toolchain.toml` → 1.95.0, edition 2021, no `rustfmt.toml`). `just fmt-check` will pass. |
| Every symbol either patch names exists with the arity and type used | read at the line in `crates/buzz-core/src/kind.rs`, `crates/buzz-relay/src/handlers/{ingest,event,req}.rs`, `crates/buzz-relay/src/subscription.rs`, `crates/buzz-ws-client/src/message.rs`, `crates/buzz-test-client/src/lib.rs` | **verified** — citations in §3, §6 and §11 |
| Neither patch touches a file-size-governed path | `just file-size-check` runs only the `desktop/`, `web/`, `mobile/` checkers (`justfile:106-110`); `crates/`, `justfile` and `.github/` are ungoverned | **verified** |
| The relay unit tests actually run in CI | `just test-unit` → `.github/workflows/ci.yml:143` (`run: just test-unit`). `buzz-relay --lib` is filtered (`justfile:381-382`), which is why patch 1 edits the justfile; `buzz-core --lib` is **not** filtered (`justfile:318`, `cargo nextest run -p buzz-core -p buzz-auth --lib`), which is why patch 2 does not | **verified** — see §6.5 and §3.5 |
| **`cargo check` / `cargo clippy` pass** | **not run.** The Buzz tree has no `target/` at this SHA and a cold `cargo clippy --workspace --all-targets` would fetch and build the whole dependency graph. | **NOT verified.** A maintainer must run `just check`. §6.6 lists the two lints most likely to bite and why I believe they do not. |
| **The fourteen E2E tests pass** | **not run.** Six in `e2e_workflow_approval.rs` and eight in `e2e_operator_alarm_pgate.rs`; all fourteen are `#[tokio::test] #[ignore]` and need a live relay plus Postgres, Redis and MinIO (`scripts/start-relay-for-tests.sh:64`). | **NOT verified.** Written against signatures read at the line this session; runtime behaviour unproven. |

Anything marked **PROPOSED** is a decision this document makes, not a fact read at a line.

---

## 1. The claim under test, adjudicated clause by clause

The claim, from `APPENDIX-NORMATIVE.md` §3 and `00-BRIEF.md` §4.4 / §11.3: *kind 46010 is
defined, listed and queried in Buzz but cannot be published by anything; the fork is two match
arms in `ingest.rs` plus four client registration points; say "two relay arms, six registration
points".*

| # | Clause | Verdict | Evidence |
|---|---|---|---|
| 1 | 46010 is defined | **true** | `crates/buzz-core/src/kind.rs:578` — `pub const KIND_WORKFLOW_APPROVAL_REQUESTED: u32 = 46010;` |
| 2 | 46010 is in `ALL_KINDS` | **true** | `crates/buzz-core/src/kind.rs:745` |
| 3 | 46010 is queried | **true, and far more widely than stated** | six independent consumer surfaces — §2 |
| 4 | Nothing can publish it | **true** | `required_scope_for_kind`'s default arm at `crates/buzz-relay/src/handlers/ingest.rs:545` is `_ => Err("restricted: unknown event kind")`; its only non-test caller `ingest_event` (`:2249-2252`) turns that into `IngestError::Rejected` — §3.1 |
| 5 | Nothing emits it | **true** | the only site that intends to is the WF-08 stub at `crates/buzz-workflow/src/executor.rs:726` (`// TODO (WF-08): create approval record in DB, emit kind:46010.`), which returns `StepResult::Suspended` instead (`:729-731`) |
| 6 | The fork is **two match arms** | **incomplete — it is three hunks in one file, and a second patch in another** | the symbol is not imported: `grep -n KIND_WORKFLOW_APPROVAL crates/buzz-relay/src/handlers/ingest.rs` returns nothing at this SHA. Adding it to the `use buzz_core::kind::{…}` block at `:13-37` makes rustfmt reflow **three** lines, because `:35` is already 98 of 100 columns. §3.3. Separately, §11 adds four hunks in `buzz-core/src/kind.rs` for `26006`. |
| 7 | `required_scope_for_kind` before `:545` | **exact** | insertion point confirmed at the line |
| 8 | `requires_h_channel_scope` at `:703-732` | **off by one at both ends** | the `fn` is at `:704`, `:703` is its doc comment, `:733` is the closing brace, the `matches!` body is `:705-732`, and the append point is after `:731` (`KIND_HUDDLE_GUIDELINES`). Confirms the ground note. |
| 9 | **four client registration points** | **false as costed — the real cost is zero** | §5. `46010` never needs to render as a timeline row, because `ambush:hold:v1` on `kind:9` is what renders (`APPENDIX-NORMATIVE.md` §3), and the needs-action feed is Rust plus one `switch` arm that already exists. |
| 10 | "two relay arms, six registration points" | **should become "three hunks in `ingest.rs` and a second patch of four hunks in `buzz-core/src/kind.rs`; zero client registration points"** | amendment **RF-A1**, §10; supersedes the "one line in `kind.rs`" arithmetic in `21-ADRS.md`'s AD-A7 — §11.8 |
| 11 | No `search_tsv` change | **true, for both kinds** | `schema/schema.sql:223-227`'s `CASE WHEN kind IN (1059, 30179, 30300, 30350, 30622, 44100, 44101, 44200)` excludes 46010; and `26006` is ephemeral, so the storage half of the `P_GATED` contract does not apply to it either (`crates/buzz-core/src/kind.rs:156-158`, and the tripwire's own skip rule at `crates/buzz-search/tests/fts_integration.rs:1421-1422`) |
| 12 | No p-gate change | **true of `46010`; false of the fork as a whole** | `P_GATED_KINDS` (`crates/buzz-core/src/kind.rs:159-169`) does not gain 46010 — an explicit-kinds REQ naming it clears `p_gated_filters_authorized` (`crates/buzz-relay/src/handlers/req.rs:1182-1216`, applied at `:219-242` **only when `channel_id.is_none()`**). It **does** gain `26006`: patch 2, argued in §11. |
| 13 | 46010 must **not** also go into `is_global_only_kind` | **true and load-bearing** | `global_only_and_channel_scoped_are_disjoint` (`ingest.rs:3830-3838`) sweeps `0..=65535` asserting the two sets never overlap. Adding 46010 to both trips it. Patch 1 adds a positive test for the same fact (§6.1). |

**Three clauses the plan set does not carry at all**, each verified and each consequential:

| # | Fact | Evidence |
|---|---|---|
| 14 | **No CI job executes `handlers::ingest::tests`.** `just test-unit` enumerates packages by hand and, for `buzz-relay`, selects only `-E 'test(/^api::admin::/) …'` (`justfile:381-382`). `backend-integration` selects named Postgres suites (`.github/workflows/ci.yml:744, 756, 794, 811, 836, 850`) — none in `handlers::ingest`. `relay-e2e` (`ci.yml:862-863`) runs `buzz-test-client` binaries only. `cargo clippy --workspace --all-targets` (`justfile:122`) **compiles** the test module and never runs it. | The justfile's own comment block at `justfile:358-380` documents this failure mode having already happened once — verbatim at `:363-367`: *"nothing in CI runs `cargo test --workspace`, `just test-unit` did not enumerate `buzz-relay --lib`, and Backend Integration selects only the `#[ignore]`d Postgres suites — so these non-ignored tests ran in no lane and a red one could ship green (exactly how a broken admin test slipped past every gate once)"*. **Patch 1 therefore edits `justfile` as well** — a fourth file the plan never budgeted. §6.5 |
| 15 | Channel-scoping 46010 acquires **two** preconditions the plan does not name — a NIP-10 thread-metadata side effect and a channel-membership gate. | §4 |
| 16 | **The `26006` alarm frame has two mutually-composable relay mechanisms and one silent interaction between them.** Neither `13-WIRE-SCHEMAS.md` nor ADR 0017 states the interaction, and a client that trips it gets its **entire** subscription refused with a message about `#p` tags. | §11 |

---

## 2. Why upstream should take patch 1: six consumers, zero producers

The plan calls the fork "upstreamable to block/buzz as a bug fix". It is stronger than that.
Every row below was read at the line this session; each says who reads 46010, in what process,
and what it does with it.

| # | Consumer | Where | What it does |
|---|---|---|---|
| 1 | **A Postgres trigger** | `migrations/0023_push_match_gate.sql:26` (and `0018_push_match_queue.sql:27`), asserted by `crates/buzz-db/src/runtime/migration.rs:952` | `enqueue_push_match_job()` fires `AFTER INSERT ON events` inside the relay's write transaction; `IF NEW.kind IN (7, 9, 1059, 40007, 46010) THEN … INSERT INTO push_match_queue` — the mobile push pipeline is already wired to wake a phone for a 46010 row that can never be written |
| 2 | **The relay's own feed SQL** | `crates/buzz-db/src/store/feed.rs:191-193` | `build_needs_action_query` interpolates the constant into `AND e.kind IN ({KIND_WORKFLOW_APPROVAL_REQUESTED}, {KIND_STREAM_REMINDER})` after an `INNER JOIN event_mentions`; runs in the relay process, reached from `crates/buzz-relay/src/api/bridge.rs:1201-1212` when a `POST /query` filter carries `feed_types` |
| 3 | **The ACP harness** | `crates/buzz-acp/src/lib.rs:2111`, `setup_mode.rs:413` and `:527`, documented at `crates/buzz-acp/README.md:225` | the default `SubscribeMode::Mentions` rule subscribes to `[KIND_STREAM_MESSAGE, KIND_WORKFLOW_APPROVAL_REQUESTED, KIND_STREAM_REMINDER]`; `setup_mode`'s main loop explicitly `continue`s on any kind that is not 9 or 46010, i.e. 46010 is one of exactly two kinds the setup agent acts on |
| 4 | **The Desktop app** | `desktop/src-tauri/src/commands/messages.rs:97-101` (Tauri Rust process) and `desktop/src/shared/constants/kinds.ts:34`, `features/home/lib/inbox.ts:165,186`, `features/search/ui/SearchResultItem.tsx:172`, `features/notifications/lib/feed.ts:34` (renderer) | `get_feed` hand-builds `{"kinds":[46010,46011,46012],"#p":[me],"limit":20}` and POSTs it to `/query`; the renderer has headline text, preview text, a search-result label and a notification category for the kind |
| 5 | **The Flutter mobile app** | `mobile/lib/features/activity/activity_provider.dart:47, 476, 511` and `feed_item.dart:62, 87` | `_fetch()` sends `NostrFilter(kinds: [46010, 46011, 46012], tags: {'#p': [myPk]}, limit: 20)` through `session.queryRelay`; `needsActionKinds` classifies the result and `feed_item.dart:87` renders `'A workflow is waiting for approval.'` |
| 6 | **The workflow engine** | `crates/buzz-workflow/src/executor.rs:713-732` | the `RequestApproval` step generates a token and carries `// TODO (WF-08): create approval record in DB, emit kind:46010.` at `:726` — the intended producer, unbuilt |

**Six consumers, zero producers.** Four clients, one DB trigger and one SQL query all reference
a kind the relay rejects at ingest with `"restricted: unknown event kind"`.

Two honest qualifications a maintainer will want, both verified:

- **Migration 0023's own comment is already stale**, and this patch does not change that.
  It says *"Keep this allowlist identical to the relay's validated NIP-PL descriptor"*
  (`migrations/0023_push_match_gate.sql:25`), but `PUSH_KINDS` is
  `&[9, 40_002, 45_001, 45_003]` (`crates/buzz-relay/src/handlers/push_lease.rs:18`) — 46010, 7,
  1059 and 40007 are all in the trigger and none is in the descriptor allowlist that
  `validate_push_filter` enforces at `push_lease.rs:281`. So an enqueued 46010 would match
  nothing that `validate_push_filter` admits. Out of scope for this patch; recorded so nobody
  claims the patch "completes mobile push for approvals". (Read as a fact about the two lists,
  not as a trace of the whole push-match pipeline, which I did not follow.)
- **The ACP harness's subscription REQ always carries `#h`** —
  `crates/buzz-acp/src/relay.rs:3267`, in the harness process, inserts
  `req_filter.insert("#h".into(), json!([channel_id.to_string()]))` with the comment
  *"#h — always present (channel scope)"*. So channel-scoping 46010 makes the harness's
  already-shipped subscription capable of receiving it live. Before this patch, a hypothetical
  globally-published 46010 could not have reached the harness at all, because a channel-scoped
  subscription never receives a global event (`crates/buzz-relay/src/subscription.rs:487-492`).
  **The second arm is not overhead — it is what makes the existing consumer work.**

---

## 3. Patch 1, site by site

### 3.1 Arm 1 — `required_scope_for_kind`

**Who calls it, in what process, what it does to the data.** `required_scope_for_kind` is a
private free function at `crates/buzz-relay/src/handlers/ingest.rs:437-547`. Its only non-test
caller is `ingest_event` at `:2249-2252`, running in the `buzz-relay` process on the shared
WebSocket + HTTP ingest path (`POST /events` enters at `crates/buzz-relay/src/api/bridge.rs:925`;
the WS `["EVENT", …]` frame at `crates/buzz-relay/src/handlers/event.rs:761`). It maps a kind to
the `buzz_auth::Scope` the authenticated principal must already hold, and the caller turns `Err`
into `IngestError::Rejected` — so the event is dropped **before** storage, before the mention
index, before fan-out, and before the `is_command_kind` branch at `:2278`.

Two details a patch author will get wrong from the plan text alone:

- The signature is **two arguments**: `fn required_scope_for_kind(kind: u32, event: &Event) -> Result<Scope, &'static str>` (`:437`). Every test call site passes `&dummy`.
- The arm must sit **before** `:545`, not merely inside the function — `_ =>` is the default.

```diff
@@ -542,6 +542,10 @@ fn required_scope_for_kind(kind: u32, event: &Event) -> Result<Scope, &'static s
         KIND_DM_OPEN | KIND_DM_ADD_MEMBER | KIND_DM_HIDE => Ok(Scope::MessagesWrite),
         KIND_WORKFLOW_DEF | KIND_WORKFLOW_TRIGGER => Ok(Scope::MessagesWrite),
         KIND_APPROVAL_GRANT | KIND_APPROVAL_DENY => Ok(Scope::MessagesWrite),
+        // A workflow step waiting on a human. Publishing one is an ordinary
+        // member write into the channel the decision belongs to; the decision
+        // itself is authorized elsewhere, never by this event's presence.
+        KIND_WORKFLOW_APPROVAL_REQUESTED => Ok(Scope::MessagesWrite),
         _ => Err("restricted: unknown event kind"),
     }
 }
```

`Scope::MessagesWrite` is the same scope the three neighbouring workflow/DM/approval-command arms
take (`:542-544`), so the arm introduces no new capability. `is_command_kind`
(`crates/buzz-core/src/kind.rs:815-826`) is `{WORKFLOW_DEF, DM_OPEN, DM_ADD_MEMBER, DM_HIDE,
WORKFLOW_TRIGGER, APPROVAL_GRANT, APPROVAL_DENY}` — 46010 is absent, so it is **not** diverted to
`command_executor::handle_command` and falls through to ordinary insert.

### 3.2 Arm 2 — `requires_h_channel_scope`

**Who calls it, in what process, what it does to the data.** `pub(crate) fn
requires_h_channel_scope(kind: u32) -> bool` at `ingest.rs:704-733` is read **twice** by
`ingest_event` in the relay process and once by tests in a sibling module
(`crates/buzz-relay/src/handlers/event.rs:1232, 1241, 1245`):

1. `ingest.rs:2460-2464` — `if requires_h_channel_scope(kind_u32) && channel_id.is_none()` rejects
   `"invalid: channel-scoped events must include an h tag"`. **This is the compartment.**
2. `ingest.rs:2987-2997` — the same predicate gates `resolve_nip10_thread_meta`. See §4.2.

```diff
@@ -729,6 +733,9 @@ pub(crate) fn requires_h_channel_scope(kind: u32) -> bool {
             | KIND_HUDDLE_PARTICIPANT_LEFT
             | KIND_HUDDLE_ENDED
             | KIND_HUDDLE_GUIDELINES
+            // A pending approval names the channel it belongs to. Scoping it
+            // keeps it inside that channel's membership and fan-out compartment.
+            | KIND_WORKFLOW_APPROVAL_REQUESTED
     )
 }
```

### 3.3 The third hunk — the import the plan does not mention

`crates/buzz-relay/src/handlers/ingest.rs` does not import `KIND_WORKFLOW_APPROVAL_REQUESTED`
today. The `use buzz_core::kind::{…}` block spans `:13-37`, is rustfmt-sorted, and line `:35` is
already 98 of the default 100 columns — so inserting the symbol reflows three lines. This is the
rustfmt-canonical result, produced by running `rustfmt --edition 2021` on the edited file and
diffing until idempotent:

```diff
@@ -32,9 +32,9 @@ use buzz_core::kind::{
     KIND_READ_STATE, KIND_REPORT, KIND_STREAM_MESSAGE, KIND_STREAM_MESSAGE_BOOKMARKED,
     KIND_STREAM_MESSAGE_DIFF, KIND_STREAM_MESSAGE_EDIT, KIND_STREAM_MESSAGE_PINNED,
     KIND_STREAM_MESSAGE_SCHEDULED, KIND_STREAM_MESSAGE_V2, KIND_STREAM_REMINDER, KIND_TEAM,
-    KIND_TEAM_CATALOG, KIND_TEXT_NOTE, KIND_USER_STATUS, KIND_WORKFLOW_DEF, KIND_WORKFLOW_TRIGGER,
-    RELAY_ADMIN_ADD_MEMBER, RELAY_ADMIN_CHANGE_ROLE, RELAY_ADMIN_REMOVE_MEMBER,
-    RELAY_ADMIN_SET_WORKSPACE_PROFILE,
+    KIND_TEAM_CATALOG, KIND_TEXT_NOTE, KIND_USER_STATUS, KIND_WORKFLOW_APPROVAL_REQUESTED,
+    KIND_WORKFLOW_DEF, KIND_WORKFLOW_TRIGGER, RELAY_ADMIN_ADD_MEMBER, RELAY_ADMIN_CHANGE_ROLE,
+    RELAY_ADMIN_REMOVE_MEMBER, RELAY_ADMIN_SET_WORKSPACE_PROFILE,
 };
```

Hand-writing the insertion without running rustfmt produces a *different* three lines and fails
`just fmt-check`. That is the whole reason this hunk is worth a section.

### 3.4 What patch 1 deliberately does not touch

Each verified absent, so a reviewer can stop looking:

| Not changed by patch 1 | Why | Evidence |
|---|---|---|
| `schema/schema.sql`, `migrations/` | no new column, no new index, no `search_tsv` case | `schema.sql:223-227` excludes 46010; `events` is RANGE-partitioned on `created_at` with `events_p_future` already open |
| `P_GATED_KINDS` | 46010 is not p-gated and does not become so. **`26006` does — that is patch 2, §3.5 and §11.** | `crates/buzz-core/src/kind.rs:159-169` |
| `is_global_only_kind` | adding 46010 there would trip `global_only_and_channel_scoped_are_disjoint` | `ingest.rs:621-701`, test at `:3830-3838` |
| `is_relay_only_kind` | clients may submit 46010 | `crates/buzz-core/src/kind.rs:830-840` |
| `is_command_kind` | 46010 must reach storage, not `command_executor` | `crates/buzz-core/src/kind.rs:815-826` |
| The ingest path for `26000`–`26006` | ephemeral kinds never reach `required_scope_for_kind` at all: `handle_event` short-circuits at `crates/buzz-relay/src/handlers/event.rs:698-752` and returns before `ingest_event`. Proven in-tree by `ephemeral_kinds_not_in_scope_allowlist` (`ingest.rs:3851-3854`). **The ephemeral block needs no `ingest.rs` change; what it needs is a read rule, which is patch 2.** | |
| Any client file | §5 | |

### 3.5 Patch 2, site by site

Patch 2 (`relay-26006-pgate.patch`) is the read rule for the operator alarm frame. The
argument for it, and the arbitration against the competing design, is §11; this subsection is
only the mechanics.

**Hunk A — the constant** (`crates/buzz-core/src/kind.rs`, in the ephemeral block after
`KIND_HUDDLE_REACTION` at `:471-473`). Buzz declares every kind it reserves, ephemeral ones
included, so a bare integer in `P_GATED_KINDS` would be the only one in the file.

```rust
/// Ephemeral: operator alarm frame, reserved for an out-of-tree producer.
///
/// The relay neither emits nor interprets this kind; it reserves the number and
/// enforces its read rule. …
pub const KIND_OPERATOR_ALARM_FRAME: u32 = 26006;
```

> **DECISION RF-D7 (binding).** The `buzz-core` symbol is **`KIND_OPERATOR_ALARM_FRAME`**, not
> `KIND_PERCH_HOLD_ALARM`. Reason: this hunk lands in `block/buzz`'s own kind registry, and
> ADR 0017's Consequences section claims the change is "separately upstreamable to `block/buzz`".
> A downstream product's name in an upstream namespace is precisely what makes it un-upstreamable
> — a Buzz maintainer has no `Perch` and no `hold`. The doc comment says "reserved for an
> out-of-tree producer" and describes the read rule, which is all a relay maintainer needs to
> reason about. Perch's own name for the frame is unaffected: `APPENDIX-NORMATIVE.md` §3 keeps
> calling it the hold alarm, and `13-WIRE-SCHEMAS.md`'s
> `frame-26006-hold-alarm.schema.json` keeps its filename. This resolves the illustrative name
> in the review note and in `21-ADRS.md`; it is a rename of one Rust identifier, nothing else.

**Hunk B — the read rule** (`P_GATED_KINDS`, `kind.rs:159-169` → `:159-175`):

```diff
     KIND_AGENT_TURN_METRIC,
+    // Operator alarm frames name their recipients in `p`. Without this entry a
+    // community member can open `REQ {"kinds":[26006]}` and enumerate every
+    // frame, because a channel-less event returns every subscription match from
+    // `filter_fanout_by_access` without consulting `p` tags. Ephemeral, so the
+    // storage-layer half of the P_GATED contract does not apply.
+    KIND_OPERATOR_ALARM_FRAME,
 ];
```

**Hunk C — `ALL_KINDS`** (`kind.rs:700`, beside `KIND_AGENT_OBSERVER_FRAME`). House convention:
every ephemeral neighbour (`KIND_PRESENCE_UPDATE`, `KIND_TYPING_INDICATOR`, `KIND_PAIRING`,
`KIND_AGENT_OBSERVER_FRAME`) is listed, and the only consumer of the array is
`no_duplicate_kind_values` (`kind.rs:902-908`), which the new entry satisfies.

**Hunk D — three unit tests** in `kind.rs`'s own `mod tests`: `operator_alarm_frame_is_p_gated`,
`operator_alarm_frame_is_ephemeral` (which is what makes the skipped `search_tsv` obligation
correct rather than forgotten — it fails first if the number ever moves out of 20000–29999), and
`operator_alarm_frame_is_the_wire_value`.

**Hunk E — a new E2E binary**, `crates/buzz-test-client/tests/e2e_operator_alarm_pgate.rs`,
eight `#[tokio::test] #[ignore]` tests. §11.7 lists them and says which one ADR 0017's proposed
test list gets wrong.

**Hunk F — one CI line** (`.github/workflows/ci.yml`, the `Relay E2E` job at `:862-863`): a
separate `cargo test … --test e2e_operator_alarm_pgate -- --ignored --nocapture` invocation
after the two existing `e2e_relay` ones, following their precedent. A separate invocation, not
an addition to patch 1's list, for two reasons: it isolates a failure, and it is what makes the
two patches commute.

**No `justfile` edit.** Patch 1 needs one because `buzz-relay --lib` is filtered to
`api::admin`; patch 2 does not, because `just test-unit` runs `cargo nextest run -p buzz-core
-p buzz-auth --lib` unfiltered at `justfile:318`. Verified at the line — this is an asymmetry
worth knowing before anyone "helpfully" adds a filter for symmetry.

---

## 4. What channel-scoping newly costs, and the decisions this document makes

Adding a kind to `requires_h_channel_scope` is not one effect. It is three, and the plan set names
only the first.

### 4.1 An `h`-less 46010 is now rejected — intended

`ingest.rs:2460-2464`. This is the compartment `00-BRIEF.md` §11.3 argues for and it works as
described.

### 4.2 An `e`-tagged 46010 becomes a NIP-10 reply — unbudgeted

`ingest.rs:2987-2997` gates `resolve_nip10_thread_meta` on the **same** predicate:

```rust
2987    let thread_meta = if requires_h_channel_scope(kind_u32) {
2988        if let Some(ch_id) = channel_id {
2989            resolve_nip10_thread_meta(tenant.community(), &event, ch_id, state)
```

So a 46010 carrying an `e` tag becomes a reply, mutates `reply_count` / `descendant_count` on its
thread root inside the insert transaction (`ingest.rs:3156-3190` →
`Db::insert_event_with_thread_metadata`, `crates/buzz-db/src/store/event.rs:1673-1698`), and
triggers a relay-signed `kind:39005` thread summary (`ingest.rs:3219-3226`). Inflating a finding
card's reply badge every time a hold is published is a visible, wrong side effect.

> **DECISION RF-D1 (binding).** A `kind:46010` published by Perch's bridge **carries no `e` tag,
> ever.** Its only single-letter tags are `h` (the case channel, mandatory) and `p` (one per
> principal). Threading a hold to its finding is done by the `ambush:hold:v1` `kind:9` marker
> card, which is a chat message and is *supposed* to count as a reply.
> Owner: `11-BRIDGE-CRATE.md` enforces it at the publish seam; `16-INVARIANT-TESTS.md` asserts it.
> This narrows `APPENDIX-NORMATIVE.md` §3's tag budget for one kind; it does not contradict it.

This costs nothing to enforce and removes an entire class of "why did the reply count jump"
investigation. It is not a relay change.

### 4.3 The publisher must be a member of the case channel — unbudgeted

`ingest.rs:2509-2552` applies `check_channel_membership` (`:742-772`) to every event with a
resolved `channel_id`, unless the kind is on the `skip_membership` list at `:2517-2522`
(`{NIP29_JOIN_REQUEST, NIP29_CREATE_GROUP, STREAM_MESSAGE_EDIT, NIP29_EDIT_METADATA,
NIP29_DELETE_EVENT, NIP29_DELETE_GROUP}`). 46010 is not on it. `check_channel_membership` calls
`state.is_member_cached(community, channel, pubkey)` and falls back to `channel.visibility ==
"open"`, otherwise rejecting `"restricted: not a channel member"`.

> **DECISION RF-D2 (binding).** The bridge's Nostr key **joins every case channel at case
> creation**, in the same operation that creates it — not lazily on first hold. A case channel is
> private (`visibility != "open"`), so there is no open-channel fallback to rely on, and a
> membership failure surfaces at hold time, which is the worst possible moment.
> Owner: `11-BRIDGE-CRATE.md` (the join call) and `12-BACKEND-BILL-API.md` / `20-TASK-BREAKDOWN.md`
> (case creation). `16-INVARIANT-TESTS.md` asserts it; the E2E test
> `non_member_cannot_publish_into_a_private_channel` (§6.2) pins the relay behaviour that makes
> it necessary.
>
> **The same rule applies to the alarm frame under §11's `h`-tag mechanism**, for a different
> function in a different code path: `handle_ephemeral_event` membership-checks the publisher at
> `crates/buzz-relay/src/handlers/event.rs:850-852`. So the bridge must join the standing
> `#watch` operations channel before it can publish a single `26006` there. Pinned by patch 2's
> `a_non_member_cannot_publish_a_channel_scoped_frame`.

### 4.4 What does **not** change, and why the read path survives

A global `POST /query` with no `#h` still returns channel-scoped 46010s.
`apply_channel_scope_to_query` (`crates/buzz-relay/src/handlers/req.rs:1069-1092`) runs in the
relay process for both REQ historical delivery (`req.rs:345`) and `POST /query`
(`bridge.rs:1372, :1670`); with no `#h` it sets `query.channel_ids = accessible_channels` and
leaves `channel_ids_include_global = true` (`crates/buzz-db/src/store/event.rs:144`), which the
SQL builder renders as `AND (channel_id IS NULL OR channel_id IN (…))` (`event.rs:442-461`).

**Consequence: the fork causes no regression for any of the six consumers in §2.** Every one of
them is a query or history path, and every one of them keeps working. Only *live fan-out to a
global REQ* changes — and the one in-tree live 46010 subscription, the ACP harness's, is already
`#h`-scoped (§2). The Desktop and mobile paths are `queryRelay` / `POST /query`, not live REQs.

### 4.5 Two operators, one hold — what the relay does and does not do

`APPENDIX-NORMATIVE.md` §4 layer 1 puts one `p` tag on the 46010 for **every**
`OperatorScope::Approve` principal, and `00-BRIEF.md` §13's declined-amendment note confirms the
console does not narrow that. So more than one console legitimately holds the same open hold.
That is not a defect; it is what the `p` fan-out is for. But nothing in the wave-2 set says what
happens when two of them decide it, and three relay facts settle where the answer can live.

1. **Both consoles really do see it.** `build_needs_action_query` joins
   `event_mentions` and filters `AND m.pubkey_hex = $reader`
   (`crates/buzz-db/src/store/feed.rs:182-183, :189`), in the relay process, per reader — so one
   stored 46010 with two `p` tags is returned to two different readers' feeds. The Desktop's
   `get_feed` (`desktop/src-tauri/src/commands/messages.rs:97-101`) does the same with an
   explicit `"#p":[me]`.
2. **The relay has no compare-and-set and no last-writer-wins for this shape.** Deduplication is
   by event id only — `ON CONFLICT DO NOTHING` (`crates/buzz-db/src/store/event.rs:5` and
   `:327`). `kind:9` is neither replaceable (`is_replaceable` is `{0, 3, 41, 10000..=19999}`,
   `crates/buzz-core/src/kind.rs:776-778`) nor parameterized-replaceable (30000–39999,
   `:783-785`), so a second `ambush:verdict:v1` card **never supersedes the first**. Two signed
   human-decision records land in the case channel and both persist.
3. **Deletion is not the remedy.** `KIND_NIP29_DELETE_EVENT` (9005) exists
   (`crates/buzz-core/src/kind.rs:341`), so the losing console *could* try to erase its card.
   It must not: a signed decision record that can be removed by the operator who lost a race is
   not a record. The `holds/` directory of `08` §6.4's export bundle would then differ depending
   on who tidied up.

> **What this document contributes, and to whom.** The resolution has to be **additive and on the
> wire**, because the relay offers no place to put it. Concretely:
>
> - `12-BACKEND-BILL-API.md` §4.4 already resolves the daemon side (`409 hold_already_deciding`)
>   — it is the only compare-and-set in the system.
> - `13-WIRE-SCHEMAS.md` owns `card-ambush-verdict-v1.schema.json`, whose `leg2.state` enum is
>   `sending | recorded | acknowledged | refused_late` and has no value meaning "another
>   operator's decision was the one that executed". **A value is needed** (`superseded` is the
>   obvious name), carrying the winner's `nostr_intent_event_id`, published by whichever console
>   receives the 409. It is an ordinary `kind:9` marker card, so RF-D3 still holds: zero client
>   registration points.
> - `16-INVARIANT-TESTS.md` needs the reconciliation rule in INV-12/INV-35's neighbourhood: a
>   verdict card with **no matching daemon decision record** renders as *not the decision*,
>   never as a decision. That rule is what covers the case the update card cannot — the losing
>   console's window is closed before it can publish anything.
>
> This document does not write those; it records why the relay cannot, and that the publish order
> (`13-WIRE-SCHEMAS.md`: the signed card is published **before** the daemon call) is what makes
> the losing card exist in the first place.

---

## 5. The client registration points, re-costed: the answer is zero

`APPENDIX-NORMATIVE.md` §3 charges the fork **four client registration points**:
`CHANNEL_EVENT_KINDS`, `CHANNEL_TIMELINE_CONTENT_KINDS`, `isTimelineContentEvent`, and a
`MessageRow` renderer arm. All four exist and all four were read this session:

| Point | Where | Who reads it, in what process, what it does |
|---|---|---|
| 1 | `desktop/src/shared/constants/kinds.ts:100-113` (`CHANNEL_EVENT_KINDS`) | the renderer's live-REQ kind set — `relayChannelFilters.ts:33` spreads it into `buildChannelFilter`'s `kinds`, and `relayReconnectReplay.ts:104-111` requires `CHANNEL_EVENT_KINDS.every(k => filter.kinds.includes(k))` before it will page reconnect history |
| 2 | `desktop/src/shared/constants/kinds.ts:137-149` (`CHANNEL_TIMELINE_CONTENT_KINDS`) | the cold-load history REQ's kind set (`relayChannelFilters.ts:80`, `buildChannelHistoryFilter`), and the `Set` three reconciliation modules build to decide what counts as a row |
| 3 | `desktop/src/features/messages/lib/formatTimelineMessages.ts:52-66` (`isTimelineContentEvent`) | a pure `event.kind === …` disjunction over eleven kinds, deciding which events become `TimelineMessage` rows |
| 4 | `desktop/src/features/messages/ui/MessageRow.tsx:381-459` (`renderBody()`) | the memoized row component's body-renderer switch, `default:` at `:414` |

Points 2 and 3 are held in lockstep in **both directions** by a `node:test` at
`desktop/src/features/messages/lib/formatTimelineMessages.test.mjs:663-676`, so they can only be
paid together.

**But Perch does not need any of them**, and the reason is structural rather than a shortcut:

1. **The hold's *rendered* card is `ambush:hold:v1` on `kind:9`** — `APPENDIX-NORMATIVE.md` §3's
   marker registry. `kind:9` is already in points 1, 2 and 3, and `MessageRow`'s `default:` arm at
   `:414-426` already content-sniffs (`parseWaveMessageContent`, `:415`). Marker cards cost zero
   registration points; that is the shipped precedent.
2. **The hold's queue entry does not go through the timeline at all.** The Desktop needs-action
   feed is built in `desktop/src-tauri/src/commands/messages.rs:49-165`, in the Tauri Rust process,
   which hand-builds `{"kinds":[46010,46011,46012],"#p":[me],"limit":20}` and POSTs it to `/query`
   (`desktop/src-tauri/src/relay.rs:360-389`, NIP-98 authed), maps hits to
   `FeedItemCategory::NeedsAction` at `:146-149`, and returns them to the renderer as `FeedItem`s.
   The only TypeScript that knows the number is a `switch` arm at
   `desktop/src/features/home/lib/inbox.ts:165` and an `if` at `:186` — **both already present**.
3. **The live nudge is the `26006` ephemeral frame, not the 46010** —
   `APPENDIX-NORMATIVE.md` §4 layer 2, which is the correct design precisely because a global REQ
   can never receive a channel-scoped event.

So a raw 46010 landing in a case channel is simply not fetched by
`buildChannelHistoryFilter` and not delivered by `buildChannelFilter`'s live REQ. It is silently
absent from the timeline, which is what we want: the marker card is the row.

> **DECISION RF-D3 (binding).** Perch pays **zero** of the four client registration points.
> 46010 is a queue record, not a timeline row.
> **The condition under which this reverses:** if a future surface needs the raw 46010 to appear
> as its own row in the case channel timeline, all four must be paid **together** (points 2 and 3
> are test-locked, and point 1 without the others silently disables reconnect history paging for
> every subscription that omits the kind — `relayReconnectReplay.ts:109`). That is a four-file
> change gated behind `MessageRow.tsx` having been split first (`15-FILE-SPLIT-PLAN.md`), because
> the file is at 999 of a hard 1000 gate-lines.

This is the largest correction in this document and it is worth what it saves: the four points
would otherwise have forced the `MessageRow` split into the fork's critical path.

---

## 6. The test list a Buzz maintainer would demand

Ten relay/core unit tests, fourteen E2E tests, and the CI wiring that makes both actually run.
All are in the two patches.

### 6.1 Relay unit tests — `crates/buzz-relay/src/handlers/ingest.rs` (patch 1)

Placed immediately after `ephemeral_kinds_not_in_scope_allowlist` (`:3851-3854`), the closest
topical neighbour, following the house `long_form_*` cluster pattern (`:3711-3738`). All seven are
pure functions over a kind integer: no Postgres, no relay process, no network.

| Test | Asserts | Guards against |
|---|---|---|
| `workflow_approval_requested_is_in_scope_allowlist` | `required_scope_for_kind(46010, &dummy).is_ok()` | the arm being removed in a future refactor of the match |
| `workflow_approval_requested_requires_messages_write_scope` | `== Scope::MessagesWrite` | someone "hardening" it to `ChannelsWrite` or an admin scope, which would silently stop ordinary members publishing |
| `workflow_approval_requested_requires_h_tag` | `requires_h_channel_scope(46010)` | arm 2 being dropped, which re-admits community-global holds |
| `workflow_approval_requested_is_not_global_only` | `!is_global_only_kind(46010)` | the disjointness sweep at `:3830-3838` — a positive statement of the invariant at the one kind that could break it |
| `workflow_approval_requested_is_not_a_command_kind` | `!buzz_core::kind::is_command_kind(46010)` | 46010 later joining the command set, which would route it to `command_executor::handle_command` and reject it absent a `workflow_approvals` row (`command_executor.rs:1041-1045`) |
| `workflow_approval_granted_and_denied_stay_unpublishable` | `required_scope_for_kind(46011/46012, &dummy).is_err()` | scope creep — this change is exactly one kind wide |
| `workflow_approval_kinds_are_the_wire_values` | `46010 / 46011 / 46012` | the Desktop feed query and the mobile provider hard-code these as JSON integers and the feed SQL interpolates the constant into a string; no type checker guards the numbers |

Three more, in `crates/buzz-core/src/kind.rs`'s own `mod tests` (patch 2): `..._is_p_gated`,
`..._is_ephemeral`, `..._is_the_wire_value` — §3.5 hunk D.

### 6.2 E2E — `crates/buzz-test-client/tests/e2e_workflow_approval.rs` (patch 1, new file, 402 lines)

Written against the API read this session: `BuzzTestClient::{connect, send_event, subscribe,
collect_until_eose, recv_event, disconnect}` (`crates/buzz-test-client/src/lib.rs:90-215`),
`OkResponse {event_id, accepted, message}` (`crates/buzz-ws-client/src/message.rs:49-57`), and the
kind:9007 channel-creation helper pattern from `crates/buzz-test-client/tests/e2e_relay.rs:170-207`.
All six are `#[tokio::test] #[ignore]`, matching the suite convention.

One string in the new file is a wire literal, not prose: `Tag::parse(["channel_type", "stream"])`
in the channel-creation helper is Buzz's own `channel_type` value, copied verbatim from
`crates/buzz-test-client/tests/e2e_relay.rs:180`. It is not a use of the ruled word in
`APPENDIX-NORMATIVE.md` §7 and changing it would break the test.

| # | Test | What it proves |
|---|---|---|
| 1 | `approval_request_with_an_h_tag_is_accepted` | the write path, end to end through a real relay: the thing the change exists to enable |
| 2 | `approval_request_without_an_h_tag_is_rejected` | arm 2's compartment, asserted on the **exact** rejection string `"invalid: channel-scoped events must include an h tag"` — a string equality, so a reworded rejection is a deliberate decision rather than a silent one. The test creates a channel first so the account is a normal member and the rejection is specifically the scoping rule. |
| 3 | `approval_granted_and_denied_kinds_stay_unpublishable` | the change's width, at the wire: 46011/46012 still return `"restricted: unknown event kind"` |
| 4 | `channel_subscription_receives_it_and_a_global_subscription_never_does` | **the negative case, with a positive control.** §6.3 |
| 5 | `approval_request_reaches_the_needs_action_feed` | the `query_needs_action` INNER JOIN path. §6.4 |
| 6 | `non_member_cannot_publish_into_a_private_channel` | the membership precondition RF-D2 exists to satisfy; asserts `"restricted: not a channel member"` |

Eight more in `e2e_operator_alarm_pgate.rs` (patch 2) — listed in §11.7, likewise all
`#[tokio::test] #[ignore]`.

### 6.3 The negative case, done so it cannot pass vacuously

`APPENDIX-NORMATIVE.md` §4 item 2 is the load-bearing claim for every consumer built on this kind:
*"the fork makes 46010 channel-scoped, and global subscriptions never receive channel-scoped
events."* The mechanism is `fan_out_scoped`
(`crates/buzz-relay/src/subscription.rs:379-495`), which runs in the relay's subscriber loop,
called from `handlers/event.rs:241-250` and `dispatch_persistent_event`: when `event.channel_id`
is `Some`, it consults **only** `channel_kind_index` / `channel_wildcard_index` (`:387-423`); a
REQ registers in those indexes only when it carried an `#h` the reader can access
(`handlers/req.rs:277-293`). The comment says it outright at `:487-492`:

```
// NOTE: The scoping invariant is symmetric:
// - Global subscriptions (channel_id = None) do NOT receive channel-scoped events.
// - Channel-scoped subscriptions do NOT receive global events.
```

(Confirming the ground note: the comment block is `:487-492`, not the appendix's `:486-491`.)

A naive negative test — "open a global REQ, publish, assert nothing arrives" — passes if the
publish silently failed, if the relay was down, or if fan-out never ran. So the test opens
**both** subscriptions on **one** connection, drains for the whole window rather than stopping at
the first hit, and asserts the positive control **first**:

```rust
    // Positive control first: if this fails the negative assertion below proves
    // nothing, because the event may simply never have been fanned out.
    assert!(
        delivered_to.contains(&channel_sub),
        "channel-scoped REQ must receive the approval request; delivered_to = {delivered_to:?}"
    );
    assert!(
        !delivered_to.contains(&global_sub),
        "a global REQ must NEVER receive a channel-scoped event, even with a matching #p; \
         see the symmetric scoping invariant in crates/buzz-relay/src/subscription.rs"
    );
```

The global REQ is `{kinds:[46010], "#p":[reader]}` — deliberately the exact filter shape
`APPENDIX-NORMATIVE.md` §4 forbids any document from specifying, so the prohibition has an
executable reason rather than a citation. The same pattern is reused three times in patch 2's
E2E file, for the same reason.

### 6.4 The `query_needs_action` INNER JOIN path

This is the test the plan set most needs and the one that is easiest to write wrong.

**What it exercises.** `build_needs_action_query`
(`crates/buzz-db/src/store/feed.rs:171-201`) runs in the relay process against Postgres:
`SELECT … FROM events e INNER JOIN event_mentions m ON e.community_id = m.community_id AND e.id =
m.event_id` (`:182-183`), `AND m.pubkey_hex = $reader` (`:189`), `AND e.kind IN (46010, 40007)`
(`:191-193`), then `push_visible_channel_filter` (`:56-73`), capped at `FEED_MAX_LIMIT = 100`
(`:29`, applied at `:178`). Its only caller is `crates/buzz-relay/src/api/bridge.rs:1201-1212`,
reached only when a `POST /query` filter carries the non-standard `feed_types` extension
(`extract_feed_types`, `bridge.rs:332-336`; dispatch `:1155-1246`).

**Why the shipped test does not cover it.** `query_needs_action_is_scoped_across_communities`
already exists at `crates/buzz-db/src/store/feed.rs:657-700` and does store a 46010 with a `p` tag
into a channel and query it back. But its fixture is `store_feed_event` (`:585-605`), which calls
`crate::event::insert_event` and `crate::insert_mentions` **directly**, bypassing `ingest_event`
entirely. It proves the read side over a hand-inserted row. Nothing in the tree proves the *write*
side can produce such a row — which is exactly what this change creates.

**Why it matters beyond coverage.** The mention index is written on a **separate transaction**
from the event insert, and a failure is downgraded to a `warn!`:

```rust
1690        if result.1 {
1691            if let Err(e) =
1692                crate::insert_mentions(&self.pool, community_id, event, channel_id).await
1693            {
1694                tracing::warn!(event_id = %event.id, "Failed to insert mentions: {e}");
1695            }
1696        }
```

(`crates/buzz-db/src/store/event.rs:1690-1696`, inside `Db::insert_event_with_thread_metadata`,
the storage call `ingest_event` makes for 46010 at `ingest.rs:3156-3190`.) So a 46010 can be
stored, `OK`'d to the publisher, and permanently invisible to every `#p` feed — and a republish is
deduplicated by event id, so the hole does not self-heal. This test is the only mechanical
detector of that.

**The wire shape**, taken from the one in-repo producer of `feed_types`
(`crates/buzz-cli/src/commands/feed.rs:40-60`):

```rust
    let body = serde_json::json!([{
        "#p": [reader_hex],
        "limit": 50,
        "feed_types": ["needs_action"],
    }]);
```

The filter is deliberately **kindless**, and that is safe only because `#p` is exactly the reader:
`p_gated_filters_authorized` (`req.rs:1182-1216`, applied to `POST /query` at `bridge.rs:1076`)
treats `filter.kinds.as_ref().is_none_or(…)` as "can match a p-gated kind" and closes the
subscription unless `#p` equals the reader's own pubkey. A test that omits `#p` gets a 4xx that
looks like the feature is broken.

> **Read this together with §11.4.** That same `is_none_or` clause is why patch 2 changes the
> risk profile of *every* kindless filter in the product: once `26006` is p-gated, a kindless
> `POST /query` or REQ must carry `#p = self` or be refused. The `needs_action` shape above
> already does; a future kindless filter that does not will fail in a way that reads like a
> different bug.

### 6.5 The CI wiring — without which none of the above runs

**Relay unit tests (patch 1).** As established in §1 row 14, `handlers::ingest::tests` is executed
by no CI job. Patch 1 extends the one `buzz-relay --lib` selection that exists, in `just
test-unit` (run by the `unit-tests` CI job at `.github/workflows/ci.yml:143` — `run: just
test-unit`):

```diff
+        # handlers::ingest::tests::workflow_approval_* joins the same selection:
+        # they are pure functions over a kind integer (scope allowlist, h-scope
+        # set, global-only set, command routing) with no Postgres and no relay
+        # process, and until they were named here `buzz-relay --lib` outside
+        # api::admin ran in no CI job at all -- clippy --all-targets compiles
+        # handlers::ingest's test module but never executes it.
         cargo nextest run -p buzz-relay --lib \
-            -E 'test(/^api::admin::/) - test(=…) - test(=…)'
+            -E '(test(/^api::admin::/) - test(=…) - test(=…)) + test(/^handlers::ingest::tests::workflow_approval_/)'
```

(Elided for width; the patch carries the full filter verbatim.) All seven test names share the
`workflow_approval_` prefix, so the regex selects exactly them and nothing else in a 2,200-line
test module that has never run and may not be green.

**Core unit tests (patch 2).** No justfile edit: `justfile:318` already runs
`cargo nextest run -p buzz-core -p buzz-auth --lib` with no filterset, so the three new `kind.rs`
tests execute on the first push.

**E2E.** Both patches add to the existing `Relay E2E` job (`ci.yml:862-863`), which runs against
a relay started by `./scripts/start-relay-for-tests.sh --no-build` — a script that brings up
`postgres redis minio minio-init` (`scripts/start-relay-for-tests.sh:64`), so the Postgres the
`needs_action` test requires is present. Patch 1 extends the existing multi-binary invocation;
patch 2 adds its own line beside the two `e2e_relay` invocations:

```diff
           cargo test -p buzz-test-client --test e2e_relay nip43_membership_snapshots_are_rejected -- --ignored --nocapture
+          cargo test -p buzz-test-client --test e2e_operator_alarm_pgate -- --ignored --nocapture
```

**A trap both patches avoid, recorded so nobody re-introduces it.** `cargo test -- --ignored` runs
**only** ignored tests. An earlier draft put the wire-value pin (`46010 == 46010`) in the E2E file
as a plain `#[test]`; it would have executed in no CI job at all. Every wire-value pin lives in a
unit test module instead — `handlers::ingest::tests` for patch 1 (made real by the justfile edit)
and `buzz_core::kind::tests` for patch 2 (already real).

### 6.6 What a maintainer will still ask for, and the honest answer

| Request | Status |
|---|---|
| "Does it compile?" | **Not verified here** — §0. Every symbol, arity and type was read at the line; `rustfmt` parses all four Rust files and reports them canonical. Run `just check`. |
| "Does clippy pass?" | Not verified. The two plausible lints are `uninlined_format_args` (every non-inlined `{}` in the new code takes a field access or method call, which the lint does not flag) and `needless_range_loop` (no ranges). |
| "Is there a bench or perf risk?" | No. Both `ingest.rs` arms are `matches!` / `match` on a `u32`, compiled to a jump table alongside ~80 existing arms. `P_GATED_KINDS` grows from six entries to seven and is scanned by a `.contains()` once per REQ filter. |
| "What about the `web/` client?" | `web/` has no 46010 or 26006 reference (`grep -rn 46010 web/src` → no hits). Nothing to do. |
| "Should 46011/46012 come too?" | No — test 3 pins that they do not. They have no producer and no reader contract; `get_feed` and the mobile provider query them only as speculative siblings of 46010. Widening is a separate argument. |
| "Why does `buzz-core` reserve a kind nothing in this repo emits?" | Because the read rule has to live where the relay reads it, and the relay is this repo. §11 and the constant's own doc comment. If a maintainer prefers not to reserve the number, patch 2 stays carried; patch 1 is unaffected, which is the whole reason they are two patches. |

---

## 7. The upstream PR (patch 1 only)

The plan offers this to `block/buzz` as a genuine bug fix rather than a fork. Here is the PR a
maintainer would accept. **It speaks Buzz's vocabulary, not Perch's** — the object is a *workflow
approval request*, the surface is the *needs-action feed*, and neither Ambush nor Perch is
mentioned. `APPENDIX-NORMATIVE.md` §7's bans govern Perch's rendered strings; they do not license
renaming an upstream project's own domain object in a PR to that project. (§13 measures exactly
which bans this implicates and adjudicates each.)

**Patch 2 is deliberately not in this PR.** Its subject is a kind with zero in-tree consumers and
zero in-tree producers, so it has none of the argument that makes patch 1 land. Offering both
together would put a maintainer in the position of accepting a downstream product's reservation as
the price of a fix to their own bug. Patch 2 goes up separately, later, on its own merits — §11.9.

### 7.1 Title

```
fix(relay): admit kind:46010 at ingest and scope it to its channel
```

### 7.2 Body

```markdown
## What

Two match arms in `crates/buzz-relay/src/handlers/ingest.rs` (plus the import they need):

- `required_scope_for_kind`: `KIND_WORKFLOW_APPROVAL_REQUESTED => Ok(Scope::MessagesWrite)`
- `requires_h_channel_scope`: add `KIND_WORKFLOW_APPROVAL_REQUESTED`

## Why

`kind:46010` is defined (`buzz-core/src/kind.rs:578`), listed in `ALL_KINDS` (`:745`), and read by
six independent surfaces:

| Reader | Where |
|---|---|
| the `push_match_queue` trigger | `migrations/0023_push_match_gate.sql:26` — `NEW.kind IN (7, 9, 1059, 40007, 46010)` |
| `query_needs_action` | `buzz-db/src/store/feed.rs:191-193` |
| the ACP harness's default mention rule | `buzz-acp/src/lib.rs:2111`, `setup_mode.rs:413`, README:225 |
| Desktop `get_feed` | `desktop/src-tauri/src/commands/messages.rs:97-101` |
| Desktop inbox / search / notifications | `shared/constants/kinds.ts:34`, `home/lib/inbox.ts:165,186`, `search/ui/SearchResultItem.tsx:172`, `notifications/lib/feed.ts:34` |
| the Flutter activity feed | `mobile/lib/features/activity/activity_provider.dart:47,476,511` |

But `required_scope_for_kind`'s default arm (`ingest.rs:545`) rejects it with
`"restricted: unknown event kind"`, and `ingest_event` (`:2249-2252`) turns that into
`IngestError::Rejected` — so no client, agent or internal path can produce one. The intended
producer is still a TODO: `buzz-workflow/src/executor.rs:726`.

The result today is a needs-action feed, a push trigger and an agent subscription that are wired
to a kind the relay refuses at the door.

## Why both arms, not just the first

`46010` is in neither `requires_h_channel_scope` nor `is_global_only_kind`. Adding only the scope
arm would admit it as a community-global event with no `h` tag: `filter_fanout_by_access` would
have no channel to membership-check against, and an approval request for one channel would fan out
to every global subscriber in the community. Scoping it also means the ACP harness's existing
subscription can receive it — that REQ always carries `#h` (`buzz-acp/src/relay.rs:3267`), so a
globally-stored 46010 could never have reached the harness at all.

## Compatibility

No regression for any of the six readers. All of them are query/history paths, and
`apply_channel_scope_to_query` (`buzz-relay/src/handlers/req.rs:1069-1092`) leaves
`channel_ids_include_global = true` for a filter without `#h`, so a global query keeps returning
channel-scoped rows via `AND (channel_id IS NULL OR channel_id IN (…))`. Only *live fan-out to a
global REQ* changes, and the one live 46010 subscription in the tree is already `#h`-scoped.

Two behaviours a producer inherits, both intended and both tested here:

- an `h`-less 46010 is now rejected (`"invalid: channel-scoped events must include an h tag"`);
- the publisher must be a member of the channel, or the channel must be `visibility = "open"`
  (`ingest.rs:2509-2552` → `check_channel_membership`), since 46010 is not on the
  `skip_membership` list.

Also worth knowing for whoever builds the producer: `requires_h_channel_scope` additionally gates
NIP-10 thread-metadata resolution (`ingest.rs:2987-2997`), so a 46010 carrying an `e` tag becomes
a reply and mutates `reply_count` / `descendant_count` on its root. If approval requests should
not inflate a thread's reply badge, they should not carry an `e` tag.

## Deliberately not included

- `46011` / `46012` stay rejected — they have no producer and no reader contract. A test pins this.
- No `search_tsv` change: 46010 is not in `schema/schema.sql:223-227`'s privacy CASE.
- No `P_GATED_KINDS`, `is_global_only_kind`, `is_relay_only_kind` or `is_command_kind` change.
- No migration. No ephemeral-kind change (ephemerals never reach `required_scope_for_kind` —
  `handlers/event.rs:698-752`).

## Tests

Seven unit tests in `handlers::ingest::tests` (scope, `Scope::MessagesWrite` specifically, h-scope,
not-global-only, not-a-command-kind, 46011/46012 still rejected, and a pin on the three wire
integers — the Desktop and mobile clients hard-code them as JSON, so no type checker guards them).

A new E2E binary `crates/buzz-test-client/tests/e2e_workflow_approval.rs`: accepted with `h`,
rejected without, siblings still rejected, `needs_action` feed round-trip through the `feed_types`
bridge extension (which exercises the `event_mentions` INNER JOIN — that index is written on a
separate transaction and a failure is only a `warn!`, so this is the one mechanical detector of a
stored-but-invisible approval), non-member rejected on a private channel, and a channel-scoped vs.
global fan-out test with an explicit positive control so the negative assertion cannot pass
vacuously.

## CI wiring

`handlers::ingest::tests` was executed by no CI job — `just test-unit` selects only
`test(/^api::admin::/)` from `buzz-relay --lib`, `backend-integration` selects named Postgres
suites, and `clippy --all-targets` compiles the module without running it. The new tests are
named into that same selection, and the E2E binary is added to the `Relay E2E` job, so both
actually run.
```

### 7.3 The rationale, and the three review questions to have answers ready for

The PR is acceptable because it does not ask the maintainer to believe anything about a downstream
product. It closes a gap entirely internal to Buzz: six of Buzz's own surfaces read a kind Buzz's
own relay refuses. The diff is small, the tests are specific, and the CI-wiring half is a fix the
justfile's own comments already argue for.

| Likely question | Answer |
|---|---|
| *"Why now, if nothing emits it?"* | Because WF-08 (`executor.rs:726`) will, and the shape of the admission decides whether the resulting event is compartmented or community-global. Deciding it while the set of producers is empty costs nothing; deciding it after one ships is a migration. |
| *"`MessagesWrite` — is that right? An approval sounds privileged."* | The scope proves the transport may submit message writes; it never authorizes the decision. That is the same reasoning the three neighbouring arms use for `KIND_WORKFLOW_TRIGGER` and `KIND_APPROVAL_GRANT`/`DENY` (`:543-544`), and the grant/deny path re-derives authority in `command_executor::handle_approval_grant` (`command_executor.rs:1020-1064`), which rejects `"invalid: approval not found"` at `:1045` absent a real `workflow_approvals` row. |
| *"Does this let a member forge an approval request for someone else?"* | It lets any member publish an event of that kind into a channel they belong to, exactly as they can publish a `kind:9`. It grants nothing: the decision surface must still resolve the event against its own record. Perch's client-side admission rule (`08` INV-15) is a rendering decision, not something this patch claims. |

---

## 8. Fallback if upstream declines

`00-BRIEF.md` §2.3 requires the fork stay small precisely so that "decline" is survivable.
Three options; one is chosen.

### Option A — carry the patches (**chosen**)

Maintain both patch files and apply them to a pinned `block/buzz` SHA in the relay image build.
Patch 2 is carried regardless of patch 1's fate (§7).

**Maintenance cost, measured rather than estimated.** The hunks land in five regions of two files.
Their conflict exposure:

| Hunk | File / context | Conflicts when |
|---|---|---|
| import (`ingest.rs:32-37`) | a rustfmt-packed `use` list | **any** kind constant is added to or removed from `ingest.rs`'s imports — the highest-churn hunk |
| scope arm (`ingest.rs:542-545`) | the last four arms of an ~80-arm match | a new kind is added near the end of the allowlist |
| h-scope arm (`ingest.rs:729-733`) | the tail of a `matches!` | a new channel-scoped kind is added |
| relay tests (`ingest.rs:3853+`) | after `ephemeral_kinds_not_in_scope_allowlist` | a test is added at that exact point |
| `P_GATED_KINDS` / const / `ALL_KINDS` / core tests (`kind.rs`) | four append points in a rarely-reordered file | a kind is added at the same append point — low churn; `P_GATED_KINDS` has six entries and gained its most recent one with `KIND_AGENT_TURN_METRIC` |
| `justfile`, `ci.yml` | one line each per patch | the surrounding recipe/step changes |

A `git apply --3way` failure here is always a one-line manual re-insert, never a semantic merge —
the hunks add lines to sorted lists and never modify an existing line except the rustfmt reflow.
**Realistic cost: 10–20 minutes per upstream rebase, most of it re-running `rustfmt` on the import
block.** That figure is an estimate from hunk placement, not a measurement across real upstream
churn. Budget it as a recurring task in the relay image pipeline, not as engineering work.

**The load-bearing risk is not the conflict — it is silence.** If a rebase drops the h-scope hunk
while keeping the scope hunk (the exact failure a fuzzy 3-way merge produces, because the two
hunks are 190 lines apart and independently appliable), holds become community-global and nothing
fails loudly. The same is true of patch 2's `P_GATED_KINDS` line, which is one line in an array
and would drop in silence. Mitigation, mandatory:

> **DECISION RF-D4 (binding).** The relay image build runs, **after** applying the patches and
> **before** publishing the image, failing the build on a non-zero exit:
>
> ```
> cargo nextest run -p buzz-relay --lib -E 'test(/^handlers::ingest::tests::workflow_approval_/)'
> cargo nextest run -p buzz-core  --lib -E 'test(/^kind::tests::operator_alarm_frame_/)'
> ```
>
> Ten tests, all infra-free. Four of the first seven fail if either `ingest.rs` arm is missing;
> `operator_alarm_frame_is_p_gated` fails if the `P_GATED_KINDS` line is missing. These are the
> patches' own integrity check. Owner: `20-TASK-BREAKDOWN.md`, Phase 0.

### Option B — a Perch-side relay fork repo

Rejected. It converts two patch files into a repository with its own release process, and every
Buzz relay CVE becomes a merge. Nothing about these changes wants a fork's blast radius.

### Option C — abandon 46010 and carry the hold on `kind:9` with an eighth marker

Technically viable and the reason to keep it on the table: `kind:9` needs no relay change at all,
and `MessageRow`'s `default:` sniff already renders marker cards.

Rejected on one ground, verified: **the needs-action queue would stop existing.**
`query_needs_action` (`feed.rs:191-193`) and the Desktop's `get_feed`
(`messages.rs:97-101`) both select on `kind IN (46010, …)`. A `kind:9` marker card lands in the
channel timeline and in the *mentions* section of the feed, never in needs-action. Perch would then
have to build its own queue query — which means either adding `feed_types` support to a new Rust
path or carrying a client-side scan of every `kind:9` in every case channel. That is strictly more
code in strictly more places than the two arms, and it puts the queue's authority in the client.

It also fails `APPENDIX-NORMATIVE.md` §3's rule for an eighth marker (*what an operator cannot
reconstruct without it after the ephemeral has decayed*) in reverse: the marker would be doing a
**queue** job, not an evidence job.

**If Option C is ever forced** (upstream declines *and* patch-carrying is ruled out), the correct
shape is `ambush:hold:v1` as the sole carrier plus a client-side needs-action projection built
from the case-channel history REQ — and `04`/`07` must be told the queue is now a client
derivation with no server-side authority, which changes `APPENDIX-NORMATIVE.md` §4 layer 3
materially. Record it as a kill-criterion consequence, not a fallback. Note that Option C does
**not** relieve patch 2: the alarm frame's read rule is independent of how the durable record is
carried.

---

## 9. The write-allowlist invariant, and how it is mechanized

`00-BRIEF.md` §8.1: *"The relay copy of every finding and receipt will be faster to query,
prettier to render, and searchable. An operator under time pressure will start treating it as the
record."* The fork makes that risk concrete, because it is the moment the relay starts holding an
Ambush-authored durable object.

The mitigation is not a rule about how cards are rendered. It is a rule about what may be
**written**, because a relay cannot become the record for something it never receives.

> ### INV-RF1 (PROPOSED, binding on Perch) — the closed write allowlist
>
> The `swarm-perch-bridge` process publishes exactly **nine kinds** to the relay and no others:
> `46010`, `kind:9` (carrying exactly the seven `ambush:*:v1` markers of
> `APPENDIX-NORMATIVE.md` §3), and the ephemeral block `26000`–`26006`. The operator's own key
> publishes exactly one: `kind:9` carrying `ambush:verdict:v1`, and only through
> `perch_record_verdict` (`08` INV-29).
>
> ### INV-RF2 (PROPOSED, binding on Perch) — every allowlisted kind names its authority
>
> Each entry in the allowlist declares, in one static table, the daemon read that is authoritative
> for it — or declares explicitly that none exists. A rendered verification affordance may cite
> **only** the daemon route in that column. An entry whose route column is `none` renders its card
> with the absence stated, never with a verification affordance.

The second half is what gives the first teeth. A closed set of kinds still lets the relay become
the record if the console verifies against the relay copy. The table below is the artifact; its
route column was checked against `AMBUSH` this session.

### 9.1 The table

| Kind | Marker | Daemon authority for re-verification | Status of that route |
|---|---|---|---|
| `46010` | — | `GET /v1/response/holds/{hold_id}` | **bill B2r** — does not exist today |
| `9` | `ambush:hold:v1` | `GET /v1/response/holds/{hold_id}` | **bill B2r** |
| `9` | `ambush:verdict:v1` | the same hold's `decision` field, via B2r | **bill B2r** (+ **B2o** for `approved_by`). See §4.5: this is also the read that decides whether a verdict card is *the* decision or a superseded one. |
| `9` | `ambush:lease:v1` | `GET /v1/operator/containment/leases` | **exists** — `AMB crates/swarm-runtime-http/src/http/containment.rs:262-270`, merged into the daemon's listener at `bin/swarm_detect.rs:1116-1125` |
| `9` | `ambush:rollback:v1` | the `POST …/leases/{id}/release` response body | **exists** — `containment.rs:191-247`; read `lease_closed` / `fully_reversed`, never the HTTP status |
| `9` | `ambush:finding:v1` | **none by id.** B3r is `GET /v1/operator/findings/reviewed?since_ms=` — a review-state list, not a by-id read | **bill B3r, and it does not answer "re-fetch this finding"** |
| `9` | `ambush:receipt:v1` | **none.** No receipt-by-id route exists in either the 49-route operator surface (`AMB http/state.rs:292-488`) or the daemon's 16 (`AMB crates/swarm-ingest-runtime/src/ingest/mod.rs:2540-2576`) | **none, and none is on the bill** |
| `9` | `ambush:escalation:v1` | **none.** `RuntimeEvent::Escalation` exists only on the broadcast channel (`AMB crates/swarm-runtime/src/runtime_events.rs:214-305`); no route serves it | **none, by design** |
| `26000`–`26006` | — | n/a — ephemeral, aggregates only, never a record | n/a |

**Three of the seven markers have no daemon re-read at all.** That is a finding, not a gap in this
document: `finding`, `receipt` and `escalation` cards can only ever be relay mirrors, so under
INV-RF2 each must render the absence rather than a verification affordance. `08` §6.2's tier
vocabulary already has the words for it; this table is what tells a component author which cards
get them. Raising `receipt` to a re-readable card would be a new bill item, and this document does
not add one.

**On `hold_id`'s format**, which the route column depends on: this document does not define it and
does not restate it. It is minted by B1 and specified as opaque by `12-BACKEND-BILL-API.md`
(`hold_id` is opaque (uuid), never derived from `hunt_id`), and `13-WIRE-SCHEMAS.md` owns the one
pattern that should be `$ref`'d from every card, frame and OpenAPI path parameter that carries it.
Neither patch here constructs a `hold_id` — patch 2's E2E deliberately uses opaque content markers
— so **the fork imposes no format and must not be read as endorsing one.**

### 9.2 Mechanization

Three layers, in increasing order of what they catch:

**(a) The type system — free, catches the common case.** The bridge exposes exactly one publish
entry point, taking a closed enum:

```rust
// AMBUSH crates/swarm-perch-bridge/src/wire.rs   (PROPOSED — the crate does not exist)

/// The complete set of kinds Perch may write to the relay. INV-RF1.
/// Adding a variant is a brief amendment, not a code change: see
/// docs/plans/ambush-ui/build/10-RELAY-FORK.md §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerchWireKind {
    HoldRecord,            // 46010
    FindingCard,           // 9 + ambush:finding:v1
    EscalationCard,        // 9 + ambush:escalation:v1
    HoldCard,              // 9 + ambush:hold:v1
    VerdictCard,           // 9 + ambush:verdict:v1
    ReceiptCard,           // 9 + ambush:receipt:v1
    LeaseCard,             // 9 + ambush:lease:v1
    RollbackCard,          // 9 + ambush:rollback:v1
    Telemetry(EphemeralKind), // 26000..=26006
}

/// The only function in the crate that constructs a signed Nostr event.
pub async fn publish(kind: PerchWireKind, body: WireBody) -> Result<EventId, WireError>;
```

**(b) A Rust test in the bridge crate — catches drift in the table.** Asserts the enum's
cardinality, that every non-ephemeral variant maps to a `DaemonAuthority` entry, and that every
entry is either a route string or the explicit `DaemonAuthority::NoReRead { reason }`. This is the
test that fails when someone adds a marker without deciding its authority.

**(c) `tools/check-perch-relay-write-allowlist.sh`** (PROPOSED — does not exist) — catches the
bypass. Greps the bridge crate for any Nostr event construction outside `wire.rs`
(`EventBuilder::new`, `sign_with_keys`, a bare `Kind::Custom`) and fails on a hit.

> **Name change, and why.** An earlier draft of this document called layer (c)
> `tools/check-perch-write-allowlist.sh`. That filename is now **taken** by a delivered artifact
> with a different subject: `16-INVARIANT-TESTS.md` ships
> `build/skeleton/tools/check-perch-write-allowlist.sh`, which enforces INV-01 — the **console's**
> five non-GET daemon routes — and whose own header states it deliberately does not cover
> "anything the bridge does. The bridge is a different process with a different key and its own
> budget." Two gates, two subjects, two names. INV-RF1's gate is renamed here rather than
> colliding, and this is the only edit that resolution needs.

> **A hard prerequisite nobody may skip.** `AMB tools/check-gates-wired.sh` enumerates every
> `tools/check-*.sh` and `tools/verify-*.sh`, **tracked or untracked**, and fails if any is not
> named by a real `run:` command of a real step of a real job in a `.github/workflows/*.yml` — it
> walks the workflow structure rather than grepping, and rejects a step carrying any `if:` other
> than `always()` / `!cancelled()` (`tools/check-gates-wired.sh:19-56`). **So the script and its
> workflow step must land in the same commit**, or CI fails in a way that looks like the new gate
> is broken.
>
> Inventory re-checked this session: `AMB tools/` holds **14** `check-*.sh` and **1**
> `verify-*.sh`. Neither `check-perch-relay-write-allowlist.sh` nor
> `check-copy-banned-terms.sh` — which `APPENDIX-NORMATIVE.md` §2 and §7 name as the enforcing
> gate for the vocabulary bans — is among them, and `BUZZ` has no `tools/` directory at all.
> Both exist only as wave-2 skeletons under `build/skeleton/tools/`. (This also corrects a ground
> note that put the AMBUSH count at 23.)

**Where each layer lives.** (a) and (b) are `11-BRIDGE-CRATE.md`'s to build; (c) is a new gate that
`20-TASK-BREAKDOWN.md` must carry as a Phase-0 row **with an owner and an engineer-week figure**,
and whose `run:` step must be added to `build/skeleton/tools/ci-wiring.snippet.yml` (which today
names only the five delivered gates) in the same change. This document owns only the invariant and
the table.

### 9.3 What the write allowlist does not cover, stated so nobody assumes it does

- **Ordinary Buzz writes by the operator's own key** — creating a case channel (`kind:9007`),
  membership, reactions, ordinary `kind:9` chat in a case. Those are the operator acting as a Buzz
  user and are outside INV-RF1, which binds the *bridge*.
- **Reads.** The relay is a legitimate read/subscribe/search substrate; that is the whole
  integration decision (`00-BRIEF.md` §4.1). INV-RF1/RF2 constrain what accumulates there and what
  may be verified from it — not what may be queried.
- **Gap detection.** `00-BRIEF.md` §8.1's other two mitigations — a per-issuer monotonic sequence
  so a gap renders as a gap, and a disk-backed spool — are `11-BRIDGE-CRATE.md`'s and
  `13-WIRE-SCHEMAS.md`'s. Note for them: the daemon's `GET /v1/events/stream` route sets
  `.id(event.emitted_at_ms().to_string())` (`AMB crates/swarm-ingest-runtime/src/ingest/demo.rs:1703`),
  a millisecond timestamp that collides at the concentration monitor's 10 Hz cadence, so the
  sequence cannot be derived from it.

---

## 10. Proposed brief amendments

Per `APPENDIX-NORMATIVE.md`'s own rule, changing it is a brief amendment under `00-BRIEF.md` §12.
Seven, each with the evidence that forces it. **RF-A1 and `21-ADRS.md`'s AD-A7 target the same
sentence; file one row, using the RF-A1 text below, which corrects AD-A7's arithmetic (§11.8).**

| # | Target | Was | Proposed | Forced by |
|---|---|---|---|---|
| **RF-A1** | `APPENDIX-NORMATIVE.md` §3, *"Two relay match arms … plus four client registration points … Say 'two relay arms, six registration points'."* | 2 + 4 | **"three hunks in `buzz-relay/src/handlers/ingest.rs`, plus a second patch of four hunks in `buzz-core/src/kind.rs`; zero client registration points."** The third `ingest.rs` hunk is the `KIND_WORKFLOW_APPROVAL_REQUESTED` import (absent at `eed74bde2`, reflowing three lines of a rustfmt-packed `use` block); the `kind.rs` patch is the `26006` read rule (§11) and is four hunks, not one line, because Buzz declares every kind it reserves and the entry needs its own tests; the four client points are unnecessary because 46010 is a queue record and `ambush:hold:v1` on `kind:9` is the rendered row. Keep the four-point cost documented as the price of a future decision to render raw 46010 rows. | §1 rows 6 and 10, §3.3, §3.5, §5, §11.8 |
| **RF-A2** | `APPENDIX-NORMATIVE.md` §3, *`requires_h_channel_scope` at `:703-732`* | `:703-732` | **`:704-733`** (`matches!` body `:705-732`, append after `:731`). Same drift in `03` §5.1 and `00-BRIEF.md` §4.4/§11.3. | read at the line |
| **RF-A3** | `APPENDIX-NORMATIVE.md` §4 item 2, *`subscription.rs:486-491`* | `:486-491` | **`:487-492`**, inside `fan_out_scoped` (`:379-495`). The claim itself is correct and now has an executable test (§6.3). | read at the line |
| **RF-A4** | `APPENDIX-NORMATIVE.md` §3's tag budget, as applied to 46010 | `h`, `e`/`p`, `t`, `l`, `k`, `d` | **`46010` carries `h` and `p` only — never `e`** (RF-D1). `requires_h_channel_scope` double-duties as the NIP-10 thread-metadata gate at `ingest.rs:2987-2997`, so an `e`-tagged hold mutates `reply_count`/`descendant_count` on its root and emits a relay-signed `kind:39005`. This narrows the budget for one kind; it does not change it. | §4.2 |
| **RF-A5** | The copy gate's scope note (`build/skeleton/tools/copy-ban-list.tsv` header, and `APPENDIX-NORMATIVE.md` §7's "rendered strings") | unscoped | **The ban list is scoped to Perch's own rendered strings and the Perch feature roots `14-CLIENT-ARCHITECTURE.md` §2.1 defines. It is never run against a patch, PR body or test written against another project's own code.** Otherwise the gate fails on `KIND_WORKFLOW_APPROVAL_REQUESTED`, on `push_lease.rs`, and on `e2e_workflow_approval.rs` — none of which Perch may rename. A gate that fails on another project's own identifiers is a gate that gets switched off. §13 measures exactly what this exempts, with the gate's own engine and ban list: 57 lines in this document and 57 in `relay-46010.patch`, every one an upstream identifier or a quoted line of Buzz's own code. | §13 |
| **RF-A6** | `APPENDIX-NORMATIVE.md` §3's `26000`–`26006` row ("global, no `h`") **and** §4 layer 2 | global, no `h` | **`26006` carries an `h` naming the standing `#watch` operations channel AND is listed in `P_GATED_KINDS`. `26000`–`26005` stay global and ungated.** Plus the composition rule RF-D6: any REQ that can match `26006` names exactly one channel across every filter, or carries `#p = self` on every filter. Supersedes `13-WIRE-SCHEMAS.md`'s W-1 and ADR 0017's C3 by absorbing both — **file one row, not two.** | §11 |
| **RF-A7** | `APPENDIX-NORMATIVE.md` §6 verified counts | — | **Add**: `AMB tools/` holds 14 `check-*.sh` + 1 `verify-*.sh` at this SHA; `BUZZ` has no `tools/` directory. Every `tools/check-perch-*` and `tools/check-copy-banned-terms.sh` citation in the plan set is PROPOSED. | §9.2 |

Two further corrections that are **not** amendments because they concern `00-BRIEF.md` §4.4's
prose rather than a normative value, recorded for the integrator:

- §4.4 says the fork is "two match arms in `ingest.rs`" and lists the consequences of arm 2 as
  "so a hold is channel-scoped and compartmentalization applies to it." It omits the NIP-10 and
  membership consequences (§4.2, §4.3), both of which are binding on the bridge.
- §4.4's "This is upstreamable to block/buzz as a bug fix: the kind is defined, in `ALL_KINDS`, and
  queried by the desktop needs-action feed, and nothing can emit it" understates the case by four
  consumers. §2 has the full list, and the PR body in §7.2 uses it.

---

> **INTEGRATOR RULING, 2026-08-30 — see [`00-REGISTRY.md`](00-REGISTRY.md) R-1.** The `h`-tag
> layer below is **retracted**. `kind:26006` is **global and carries no `h` tag**; `P_GATED_KINDS`
> is the whole delivery fence, and every Perch REQ that can match `26006` carries `#p` equal to the
> reader's own pubkey on every filter. The relay findings in this section are all correct and
> unchanged — what is overruled is only the conclusion that both layers should ship. R-1 states the
> four grounds and states plainly what the ruling gives up. **`relay-26006-pgate.patch` is
> unaffected** and still applies clean.

## 11. The `26006` arbitration — decided here

Wave 1 left this hole unowned. Wave 2 produced two owners with opposite designs, each stating that
no other mechanism is needed. This section decides it, because both designs are relay behaviour and
this document owns the relay. Everything below was read at the line this session.

### 11.1 The hole, and the two proposals

The hole: `filter_fanout_by_access` (`crates/buzz-relay/src/handlers/event.rs:115-222`) returns
every subscription match unchanged for a **channel-less** event —
`let Some(channel_id) = stored_event.channel_id else { return matches; };` at `:177` — and nothing
before that point consults `p` tags (the two gates that run first are `AUTHOR_ONLY_KINDS` at
`:139-152` and `SHARED_GATED_KINDS` at `:157-175`, neither of which covers 26006). So a
community-global alarm frame is delivered to any authenticated member who opens
`REQ {kinds:[26006]}`, disclosing the existence, severity, action kind and case channel of every
hold in the colony.

| Proposal | Where | Mechanism | Claim made about it |
|---|---|---|---|
| **W-1** | `13-WIRE-SCHEMAS.md`, amendment W-1 | give `26006` an `h` tag naming the standing `#watch` operations channel | "the only one of four options that closes the `#p` hole with zero relay change and no third fork site" |
| **C3 / AD-A7** | `21-ADRS.md`, ADR 0017 clause C3 | add `26006` to `P_GATED_KINDS` in `buzz-core` | "This is the third relay-side hunk and it closes Fact 2 … one line in one array". ADR 0017 also **explicitly rejects** the `h`-tag option. |

### 11.2 What the relay actually does with an `h`-tagged ephemeral

`handle_event` branches on `is_ephemeral(kind_u32)` at
`crates/buzz-relay/src/handlers/event.rs:698` and calls `handle_ephemeral_event` (`:795-906`),
which at `:850` does this, in the relay process, on the WebSocket ingest path:

```rust
850    if let Some(ch_id) = super::ingest::extract_channel_id(&event) {
851        super::ingest::check_channel_membership(&conn.tenant, &state, ch_id, &pubkey_bytes, None)
852            .await?;
…
873        let stored_event = StoredEvent::new(event.clone(), Some(ch_id));
874        fan_out_event_to_local_subscribers(&state, conn.tenant.community(), &stored_event).await;
```

`extract_channel_id` (`ingest.rs:550-561`) reads the `h` tag and parses it as a UUID. So an
`h`-tagged ephemeral, today, with no relay change:

1. **Requires the publisher to be a member** of that channel, or the channel to be
   `visibility = "open"` (`check_channel_membership`, `ingest.rs:742-772`).
2. **Fans out through the channel indexes**, because `StoredEvent` carries `Some(ch_id)` — so
   `fan_out_scoped` uses `channel_kind_index` and a global REQ can never receive it
   (`subscription.rs:487-492`).
3. **Re-checks each recipient's membership** when the channel is private:
   `filter_fanout_by_access` falls past `:177`, reads visibility (`:184-203`), and for `"private"`
   calls `is_member_cached` per recipient in the loop at `:205-220`.
4. **Keeps all three properties across pods**: the Redis path builds its `StoredEvent` from the
   topic at `event.rs:287-292` and applies the same `filter_fanout_by_access` at `:307`.

**This is not novel.** `KIND_HUDDLE_REACTION` (24810) is an in-tree ephemeral documented as
"Channel-scoped to the ephemeral huddle channel with an `h` tag; never stored in the timeline"
(`crates/buzz-core/src/kind.rs:471-473`) and takes exactly this route. W-1's mechanism is shipped,
tested and used.

> **Correction to ADR 0017.** Its rejection of the `h`-tag option reads: *"re-imposes the
> membership precondition on the alarm — meaning the bridge must be a member of the case channel
> before the alarm can be sent, and an operator must be a member before it can be received … wrong
> for the alarm, whose job is to reach a human who may not yet be in the case."* That argument is
> sound against **`h` = the case channel**. W-1 does not propose that. W-1's `h` is the standing
> **`#watch` operations channel**, of which every operator is already a member and which exists
> precisely so an alarm reaches a human who is not in the case. The ADR rejected a design nobody
> proposed. Its clause C3 survives on its own merits — §11.5 — but its Alternatives entry should be
> corrected, or a reader will conclude the `h` tag was considered and found wanting.

### 11.3 What `P_GATED_KINDS` actually gates

`p_gated_filters_authorized` (`crates/buzz-relay/src/handlers/req.rs:1182-1216`) is a pure function
over the REQ's filters. It is called from four places — `handle_req` (`req.rs:221`), `POST /query`
(`api/bridge.rs:1076` and `:1595`) and `COUNT` (`handlers/count.rs:44`). In `handle_req` it is
applied **only inside `if channel_id.is_none()`** (`req.rs:219`), and the comment says why at
`:215-218`:

```
// Only applies to GLOBAL subscriptions (channel_id = None):
// channel-scoped subs can never receive globally-stored events because of
// the fan_out() invariant in subscription.rs.
```

Its logic: a filter "can match a p-gated kind" when `filter.kinds` is `None` **or** names one
(`:1185-1188`); such a filter passes only if its `#p` values are non-empty and **all** equal the
reader's own pubkey (`:1211-1214`); and the whole thing is an `.all()` over filters (`:1184`).

So C3's effect is precise and narrow: **it fences the global-REQ route and nothing else.** It has
no effect at all on a channel-scoped subscription, and no effect on fan-out.

### 11.4 The interaction neither document states

Two functions decide "is this REQ channel-scoped", and they disagree.

| | `extract_channel_id_from_filters` (`req.rs:1152-1180`) | `extract_channel_ids_from_filters` (`req.rs:1120-1133`) |
|---|---|---|
| Bound to | `channel_id` at `req.rs:96` — the p-gate's condition at `:219` | `requested_channel_ids` at `:97` → `authorized_requested_channels` at `:189` → `register_channels_scoped` at `:277-278` |
| Returns `None` when | **any** filter lacks an `h`, **or** two filters name **different** channel ids (`:1163-1168`) | any filter lacks an `h` (the `?` at `:1124`) |
| Result for a two-channel REQ | `None` — **treated as global by the p-gate** | `Some([a, b])` — registered channel-scoped for fan-out |

**Consequence.** A REQ that names two or more distinct channels is channel-scoped for delivery and
*global* for the p-gate. Combine that with the `.all()` in `p_gated_filters_authorized` and a
single alarm filter can refuse the entire subscription:

- `[{kinds:[26006], "#h":[watch]}, {kinds:[26001]}]` — the second filter has no `h`, so
  `channel_id` is `None`, the p-gate runs, the first filter names a p-gated kind with no `#p`, and
  the relay sends `CLOSED "restricted: p-gated events require #p matching your pubkey"` for the
  whole REQ, taking the unrelated telemetry filter with it.
- `[{kinds:[26006], "#h":[watch]}, {kinds:[9], "#h":[case]}]` — every filter names a channel and
  the reader is a member of both, and it is **still** refused, because the ids differ.

Both are refused with a message about `#p` tags, on a REQ the author believes is channel-scoped.
That is what "applying both closes the subscription" means, and it is real — but it is a property
of a *particular REQ shape*, not of the two mechanisms. Both mechanisms coexist without any
interaction at all in a REQ that names exactly one channel, which is the shape
`13-WIRE-SCHEMAS.md` already specifies ("the Watchfloor opens TWO REQs: global 26000–26005 +
h-scoped 26006").

### 11.5 DECISION RF-D5 — both, layered, with the failure each one covers

> **DECISION RF-D5 (binding).** Both mechanisms ship.
>
> **Layer 1, the compartment: the `h` tag (W-1).** `26006` carries an `h` naming the standing
> `#watch` operations channel. This is the primary mechanism. It needs **zero relay change**, it
> reuses a shipped and tested path (§11.2), it enforces publisher membership, channel-scoped
> fan-out and per-recipient re-authorization on a private channel, and it does so **on the sending
> pod at delivery time**, not at subscription time — so a stale subscription that survives a
> membership change cannot leak.
>
> **Layer 2, the backstop: `P_GATED_KINDS` (C3 / AD-A7), delivered as `relay-26006-pgate.patch`.**
> Layer 1 has one failure mode and it is silent: **if the bridge ever publishes a `26006` without
> an `h` tag** — a bug, a config default, a fallback path, a partially-applied rebase of the
> bridge's own publish seam — `handle_ephemeral_event` takes the `else` branch at
> `event.rs:875-902`, the frame becomes community-global, `filter_fanout_by_access` returns every
> match at `:177`, and **nothing fails loudly**. The alarm still arrives at the right operators, so
> the console looks correct while the frame is readable by everyone. `P_GATED_KINDS` is the only
> mechanism in the relay that fences that route, and it costs four hunks in a file with almost no
> churn.
>
> **Neither layer covers forgery.** A member with `MessagesWrite` can publish a `26006` of their
> own; the ephemeral scope check at `event.rs:698-708` admits any such token. The console's
> admitted-issuer render rule (`08` INV-15, ADR 0017 C5) is the whole defence there, and it is a
> render rule, not a relay rule. Say so; do not let two delivery fences imply a third property.

### 11.6 DECISION RF-D6 — the composition rule

> **DECISION RF-D6 (binding, on the console).** Any REQ frame whose filter set can match kind
> `26006` must satisfy **one** of:
>
> **(a)** every filter in the frame carries `#h`, and all of them name the **same single** channel; or
> **(b)** every filter in the frame carries `#p` equal to the reader's own pubkey.
>
> Nothing else registers. A frame that satisfies neither is refused **in its entirety** with
> `"restricted: p-gated events require #p matching your pubkey"` — including its non-alarm filters
> (§11.4).
>
> Owner: `14-CLIENT-ARCHITECTURE.md`'s subscription manager, which budgets seven subscriptions and
> is therefore under exactly the pressure that would merge the alarm REQ into a multi-channel one
> to save a slot. **The alarm REQ is one of the seven and may not be merged.**
> `13-WIRE-SCHEMAS.md`'s two-REQ Watchfloor design already complies; RF-D6 is what stops a later
> refactor undoing it silently.
> Asserted by patch 2's `mixing_an_h_scoped_alarm_filter_with_a_global_filter_closes_the_whole_req`
> and `naming_two_channels_in_one_req_closes_an_alarm_filter`.

### 11.7 The eight tests in `e2e_operator_alarm_pgate.rs`

| # | Test | What it proves | Corrects |
|---|---|---|---|
| 1 | `global_alarm_subscription_without_a_p_filter_is_closed` | the backstop, in the direction that matters — the exact `CLOSED` string, asserted by equality | ADR 0017's first proposed case, kept |
| 2 | `global_alarm_subscription_naming_another_pubkey_is_closed` | `#p` must equal the reader's **own** pubkey, not merely be present | new |
| 3 | `a_named_principal_receives_the_frame_and_an_unnamed_one_does_not` | positive control **and** negative in one drain window: A is `p`-tagged and receives; B holds an equally well-formed self-`#p` subscription and receives nothing | ADR 0017's second and third cases, **corrected**: the frame under test is deliberately **`h`-less**, because under W-1 a production `26006` is channel-scoped and would reach *neither* global subscription. ADR 0017's test as written would fail once W-1 lands. |
| 4 | `an_alarm_frame_is_never_stored` | the premise that lets patch 2 skip the `search_tsv` obligation — asserted, not assumed | new |
| 5 | `a_channel_scoped_frame_reaches_a_member_and_no_global_subscriber` | layer 1, with a positive control, and the fact that an `h`-scoped alarm REQ naming one channel is **accepted** (the p-gate does not run) | new — this is the test that proves the two layers compose |
| 6 | `a_non_member_cannot_publish_a_channel_scoped_frame` | the publisher-membership precondition layer 1 brings, and therefore RF-D2's extension to `#watch` | new |
| 7 | `mixing_an_h_scoped_alarm_filter_with_a_global_filter_closes_the_whole_req` | RF-D6 clause (a), first half | new |
| 8 | `naming_two_channels_in_one_req_closes_an_alarm_filter` | RF-D6 clause (a), second half — the non-obvious one | new |

Test 5 and tests 7–8 are the reason this arbitration needed code rather than prose: they are the
only artifacts in the wave-2 set that distinguish "the two mechanisms conflict" from "the two
mechanisms compose under a rule", and they fail loudly if either belief is wrong.

Every negative assertion in the file is paired with a positive control drained in the same window,
and `expect_closed` treats an `EOSE` for the subscription under test as a hard failure rather than
a timeout — reporting an *accepted* subscription as "timed out" would hide exactly the defect the
test exists to catch.

### 11.8 Correction to AD-A7's arithmetic

`21-ADRS.md`'s AD-A7 and ADR 0017 C3 both describe the `buzz-core` change as **"one line in one
array."** Measured, it is:

| | |
|---|---|
| `P_GATED_KINDS` entry | 1 line + 5 lines of comment (the file comments every non-obvious entry; `KIND_AGENT_TURN_METRIC` has three) |
| the constant it names | 1 line + a 14-line doc comment. Buzz declares every kind it reserves — a bare `26006` would be the only integer literal in the array. `#![warn(missing_docs)]` is on for this crate (`crates/buzz-core/src/lib.rs:2`) and CLAUDE.md requires doc comments on new public API. |
| `ALL_KINDS` | 1 line, house convention: every ephemeral neighbour is listed |
| tests | 3 unit tests in `kind.rs`'s own `mod tests`, one of which (`..._is_ephemeral`) is what keeps the skipped `search_tsv` obligation correct rather than forgotten |
| E2E | a new 601-line binary, 8 tests |
| CI | 1 line in `ci.yml` |

**Total: 4 hunks in `kind.rs` plus a new test binary plus a CI line — a second patch, not a fourth
hunk of the first.** The distinction is not pedantry: it is what makes patch 1 upstreamable on its
own (§7) and what makes the two independently rebasable. RF-A1 carries the corrected wording, and
supersedes AD-A7's on the same sentence. **File one amendment row.**

### 11.9 What stays open

- **Does `#watch` membership equal the `Approve` principal set?** Layer 1 delivers to every member
  of `#watch`; layer 2's `p` tags name every `Approve` principal. If the channel is wider — a
  `Read`-scoped analyst is a member — layer 1 discloses to them what layer 2 alone would not.
  Owner: `04` §2.11 (which invents `#watch`) and `12-BACKEND-BILL-API.md` (which owns
  `OperatorScope`). This document's position: **`#watch` membership must be exactly the `Approve`
  principal set, or layer 1 is weaker than layer 2 and the pair is only as strong as layer 1.**
  Not decidable here; flagged as a Phase-0 configuration question with a named consequence.
- **`#watch` does not exist.** It is a Perch construct from `04` §2.11 that nobody has built, and
  under RF-D2's extension the bridge must join it before it can publish one frame.
  `11-BRIDGE-CRATE.md` and `20-TASK-BREAKDOWN.md` own creating it.
- **Upstreaming patch 2.** ADR 0017 claims the change is "separately upstreamable … with the same
  one-sentence justification" as 24200's. That is plausible — the doc comment in §3.5 is written to
  make the case without naming Perch — but a maintainer may reasonably decline to reserve a number
  for an out-of-tree producer. Assume carried; treat acceptance as a bonus.

---

## 12. What this document still does not decide

- **The body of the 46010 event and the 26006 frame.** `13-WIRE-SCHEMAS.md`.
- **Who publishes them and with what key**, and the 50-frames-per-5s WS admission budget
  (`BUZZ crates/buzz-relay/src/connection.rs:671-681`, `admission.rs:9,40-45`) and 120/min vs.
  60/min message tiers (`connection.rs:690-695`) that constrain the publisher. `11-BRIDGE-CRATE.md`.
- **The `hold_id` format.** §9.1. `12-BACKEND-BILL-API.md` mints it; `13-WIRE-SCHEMAS.md` owns the
  one pattern every schema should `$ref`.
- **The two-operator resolution.** §4.5 states the relay-side facts and names the three owners.
- **Whether `cargo check` and `cargo clippy` pass, and whether the fourteen E2E tests pass** — §0.

---

## 13. The banned-terms census, measured

`APPENDIX-NORMATIVE.md` §7's vocabulary bans are enforced (in the plan set's design) by
`tools/check-copy-banned-terms.sh`, whose ban list ships as
`build/skeleton/tools/copy-ban-list.tsv`. Neither exists in either repository (§9.2). Rather than
assert compliance, I ran all 13 rows of that list over this document and both patches.

**The engine matters, and my first attempt got it wrong.** The ban list's own header states that
five rows need the word-boundary idiom `(^|[^a-z])word([^a-z]|$)` because *awk EREs have no `\b`*.
BSD `grep -E` on macOS does not treat `^` inside an alternation group the way awk does, and a
grep-based census silently reported **zero** `bare-lane` hits on a line that plainly contains the
word. The numbers below come from awk reading the shipped `.tsv`, honouring each row's `flags`,
`minlen` and `exempt` columns — the same engine and the same data the gate uses. The harness is
`scratchpad/perch-build/relayfork/ban-census.sh`; it is a **line-wise** approximation over prose,
not the gate's rendered-string extractor, and its own header says so.

This section is measured **apart from the rest of the document**, because a section that quotes a
ban list trips it, and folding the two together makes the number move every time the section is
edited.

```
$ bash ban-census.sh build/skeleton/tools/copy-ban-list.tsv <sections 0-12>
ROW                  SEV        HITS   EXEMPT
approve              P0           54        0
bare-lease           P1            4        2
exclamation          hygiene      17        0
bare-lane            P1            0        1
deny-label / trust-claim / shield-glyph / quorum-fraction /
bare-source-count / reassurance / hunt-noun / clowder /
legacy-codename                     0        -

$ bash ban-census.sh build/skeleton/tools/copy-ban-list.tsv <section 13 alone>
approve 4, bare-lane 3, bare-source-count 2, hunt-noun 2, clowder 2,
bare-lease 2, exclamation 2   -- every one a quotation of the rule it names
```

Adjudication of every non-zero row in sections 0–12:

| Row | Hits | Adjudication |
|---|---|---|
| `approve` | 54 lines | **Upstream identifiers and Buzz's own domain object**: `KIND_WORKFLOW_APPROVAL_REQUESTED`, its siblings `KIND_APPROVAL_GRANT` / `KIND_APPROVAL_DENY`, the `workflow_approvals` table, `e2e_workflow_approval.rs`, `command_executor::handle_approval_grant`, and the mobile string `'A workflow is waiting for approval.'` read out of `feed_item.dart:87`. Perch may not rename another project's domain object in a PR to that project (§7). **Amendment RF-A5** scopes the gate so this is not a false failure. |
| `bare-lease` | 4 | All four are the identifier `push_lease.rs` (Buzz's NIP-PL module, cited three times) or the Rust enum variant `LeaseCard`. My own prose about that module was rewritten from "would match no lease subscription" to "would match nothing that `validate_push_filter` admits" — compliant, and more precise about what the descriptor allowlist actually does. |
| `exclamation` | 17 | Every one is a Rust or YAML token, never prose: `matches!`, `assert!`, `warn!`, `json!`, `!=`, `!is_global_only_kind(…)`, `!cancelled()`, `#![warn(missing_docs)]`. The row's `minlen 4` cannot distinguish code from copy in a document that quotes code. |
| `bare-source-count` | **0** | Two hits in the previous revision, both meaning "source code" and neither a source *count*: "the source says why at" → "the comment says why at", and "written against another project's source" → "…another project's own code". Rewriting was cheaper than arguing. |
| `bare-lane` | **0 unexempt, 1 exempt** | The exempt hit is §1 row 14, which reproduces Buzz's `justfile` comment verbatim (*"…ran in no lane and a red one could ship green"*) because it is the strongest evidence that the CI hole is known. Altering a quotation to satisfy a copy rule would be worse than the hit — but the harness exempts it for the **wrong reason**, and that is a live gate defect. See §13.1. |
| everything else | 0 | — |

The same census over both patches:

```
relay-46010.patch        approve 57, exclamation 65, everything else 0
relay-26006-pgate.patch  exclamation 92, everything else 0
```

Both `exclamation` totals are Rust tokens (`assert!`, `!ok.accepted`, `matches!`).
`relay-26006-pgate.patch` scores **zero** on `approve` — the second patch names no Buzz workflow
object at all, which is a small piece of evidence that RF-D7's rename
(`KIND_OPERATOR_ALARM_FRAME`) was right for reasons beyond upstream taste.

Under RF-A5 neither patch is in the gate's scope, which is the correct outcome: a copy gate that
inspects a diff against another repository is inspecting the wrong artifact.

### 13.1 A gate finding for `16-INVARIANT-TESTS.md`, found by running the list rather than reading it

**The `exempt` column is an unanchored substring match, and one row's exemption is short enough to
fire by accident.** `bare-lane`'s exempt list contains the bare token `12`, so **any** line
carrying a line-number citation such as `justfile:122`, `ci.yml:1201` or `:126` is exempted from
the `lane` rule outright. That is exactly what happened above: §1 row 14 contains the banned word
and was exempted because the same table cell cites `justfile:122`.

The `pattern` column is carefully word-bounded — the list's header documents the idiom and says
four live false positives forced it. The `exempt` column is not, and nobody checked it in the
other direction. `lease_id`, `agent`, `hunt_id` and the rest are long enough that an accidental
collision is unlikely; `12` is not.

Suggested fix, cheap and in the owner's hands: word-bound the numeric exemption the same way the
patterns are — `(^|[^0-9])12([^0-9]|$)` — or drop `12` and keep `twelve`, since the row exists to
permit "the twelve threat classes" and the digit form appears in the plan set mostly as "12
destructive actions", which the `threat` / `impact` / `credential` tokens already cover.

This is not a defect in this document. It is a false negative in a delivered gate, of exactly the
shape the gate's own fixture pattern was built to catch — a rule that reports over a region it
never actually inspected — and it is worth a row in `tools/fixtures/copy-corpus/`: a planted
`lane` violation on a line that also carries a line-number citation, which must still fail.
