# 14 — Perch client architecture

**What this is.** How Perch is organized *inside* the Buzz desktop codebase: the feature tree, the
router, the React Query key design, the subscription manager, the Tauri command surface, the
colony-scoped singleton registry, the memo discipline, virtualization, error boundaries, and a
gate-line budget per module.

**Status.** Producer artifact. Values that cross documents come from
`APPENDIX-NORMATIVE.md`; where I believe one is wrong I say so as a proposed brief amendment (§13)
rather than quietly using a different number.

**Ships with this document** — real files, not excerpts, under
`docs/plans/ambush-ui/build/skeleton/desktop/`:

| File | Target path in BUZZ | What it is |
|---|---|---|
| `src/app/routes.ts` | `desktop/src/app/routes.ts` | the Perch route declaration, replacing Buzz's |
| `src/app/perchViews.ts` | `desktop/src/app/perchViews.ts` | `PerchView`, `derivePerchShellRoute`, `PERCH_NAV` |
| `src/shared/api/perchKeys.ts` | same | the key factory **and** a freshness row for every key |
| `src/shared/api/perchSubscriptions.ts` | same | the reconciling subscription manager + gap detection + the repair-kind assertion |
| `src/shared/api/perchEphemeralStore.ts` | same | the 26xxx store, deliberately not the query cache |
| `src/shared/api/tauriPerch.ts` | same | thirteen command wrappers: 7 reads, 5 daemon writes, 1 relay write |
| `src/features/perch/colonyScopedRegistry.ts` | same | the typed `resetColonyState` |
| `src/features/perch/ui/PerchSurfaceBoundary.tsx` | same | the per-surface error fence |
| `src-tauri/src/commands/perch_writes.rs` | same | the five **daemon** writes, routes as constants |
| `src-tauri/src/commands/perch_verdict.rs` | same | **leg 1** — the one relay write, and the only sanctioned signer of a verdict card |
| `scripts/check-route-tree.mjs` | `desktop/scripts/check-route-tree.mjs` | **a gate that runs today**: §3.5, executed this session against the real Buzz tree |

**Verification convention.** `[V]` means I read it in this session at BUZZ
`eed74bde2` / AMBUSH's current tree. `[P]` means PROPOSED — a decision this document makes, with
nothing in either tree to point at yet.

**Revision status.** This is the second version, after a four-critic red-team pass against real
source. Seven things changed and four of them change what a producer builds: §5.3 retracts a claim
about the reconnect repair and replaces it with the mechanism plus a Rust-side fix (C8); §5.2.1
ratifies one of three competing `26006` designs and withdraws a peer's amendment; §7.3 adds
`perch_record_verdict`, without which leg 1 was unpublishable, and corrects the command count from a
figure that did not add up; §7.3.2 rebuilds `DecideHoldInput` against the wire contract it could not
have satisfied; §7.4.1 arbitrates three mock-bridge designs down to one; §7.6 is new and handles two
operators deciding one hold; and §3.5's proposed gate is now written and executed. §15.1 lists what
was retracted, because a revision that quietly deletes a wrong claim teaches nobody anything.

**What this document does not own.** The marker-renderer registry's component surface, props and
presenter files (`17-COMPONENT-SPECS.md` §3 — I own only its *wiring*, §6). The mechanics of
splitting `AppShell.tsx` and `MessageRow.tsx` (`15-FILE-SPLIT-PLAN.md`). The invariant test bodies
(`16-INVARIANT-TESTS.md`). The daemon API shapes (`12-BACKEND-BILL-API.md`). Tokens (`19`), charts
(`18`), copy (`06`/`09` in the spec extract).

---

## 1. Corrections this document acts on

Each was measured this session, and each changes what a producer builds.

**C1 — Buzz uses two virtualizers, not one, and the case timeline is on the other one.**
`07` §9 says "Buzz already virtualizes with `@tanstack/react-virtual` behind one primitive … Nine
surfaces use it today, including `MessageTimeline`". Measured `[V]`: `VirtualizedList`
(`@tanstack/react-virtual`, `BUZZ desktop/src/shared/ui/VirtualizedList.tsx:1`) has **7 JSX call
sites across 6 files** — `InboxListPane.tsx:706`, `EmojiAutocomplete.tsx:66`, `PulseView.tsx:276`
and `:297`, `ForumView.tsx:231`, `CommunityMembersSettingsCard.tsx:363`, `MembersSidebar.tsx:828`.
`MessageTimeline` is **not** among them: the timeline renders through
`features/messages/ui/TimelineMessageList.tsx`, which imports `VList` from **`virtua`** at `:2` and
renders it at `:738` with **`shift={isPrepend}`** at `:747`. Three sibling hooks type against
`VListHandle` (`useVirtualizedBottomSettle.ts:2`, `useTimelineRetention.ts:2`,
`timelineRetention.ts:1`). Both libraries are direct dependencies —
`@tanstack/react-virtual ^3.14.2` and `virtua 0.49.3` (exact pin), `package.json:52,86`. §10 decides
which Perch surface gets which, and why the choice is forced rather than aesthetic.

**C2 — Buzz has exactly one React error boundary, and its fallback replaces the window.**
`grep -rln 'componentDidCatch|getDerivedStateFromError' desktop/src` returns one file `[V]`:
`app/RootErrorBoundary.tsx`, mounted at `main.tsx:86` outside every provider, whose own doc comment
records that the reconciler's error boundary "isn't one" and whose fallback is a full-screen "Buzz
failed to start" splash (`:40-53`). No plan document notices this. §11 decides what a crashed Perch
surface does instead.

**C3 — the renderer→Rust command surface is 256 distinct literals, not 205.**
`APPENDIX-NORMATIVE.md` §6 gives "264 call-shaped occurrences / 205 distinct command literals / 57
files"; the buzz-touchpoints ground pass reproduced 205/57 and 269–270 occurrences. Measured this
session with the method stated: `grep -rn 'invokeTauri[<(]' desktop/src --include='*.ts'
--include='*.tsx'` → **270** lines (269 excluding the definition at `tauri.ts:296`); distinct
literals via `grep -rhoE 'invokeTauri(<[^(]*>)?\(\s*"[^"]+"'` → **206**; files → **57** `[V]`.
*But* `invokeTauri` is not the whole surface: a raw `invoke("…")` from `@tauri-apps/api/core`
accounts for a further **56** distinct literals across 82 call-shaped occurrences, of which 2 are
plugin commands (`plugin:websocket|send` and one sibling). Union, deduplicated: **256** distinct
command literals `[V]`. Against **348** `#[tauri::command]` definitions under `desktop/src-tauri/src`
and **336** entries in the `generate_handler!` argument at `lib.rs:519-863` `[V]`. §7 works from 256.

**C4 — `shared/api` has forty sibling-file precedents, not eight.**
The buzz-touchpoints pass named eight files importing `invokeTauri` from `./tauri`. Measured:
**40** files under `desktop/src/shared/api/` reference `invokeTauri` `[V]`. The pattern is not a
workaround; it is the house style, and it is why §7 puts every Perch wrapper in a new file without
apology.

**C5 — `channel-window` is missing from `RELAY_QUERY_ROOTS`, and that is correct.**
Worth recording because it is the trap in the middle of the key design.
`relayQueryInvalidation.ts:1-36` lists 34 roots `[V]`; `channel-window` is a live `useQuery` root
(`features/messages/hooks.ts:247-258`) and is absent. It is *not* a bug: that query's `queryFn`
reads the cache (`queryClient.getQueryData(queryKey) ?? emptyChannelWindowStore()`) with
`staleTime: Infinity`, so invalidating it would refetch from the cache — a no-op. The allowlist
encodes a real distinction between *relay-served* and *cache-mirror* queries. §4 preserves that
distinction explicitly rather than losing it in a one-line predicate.

**C6 — `max_filters: 10` is advertised, not enforced.**
`07` §6 and the spec extract both list it as a ceiling. It is advertised in NIP-11 at
`BUZZ crates/buzz-relay/src/nip11.rs:133` `[V]`, but `grep 'filters.len()'` over
`crates/buzz-relay/src` returns only two test assertions in `protocol.rs` `[V]`. `MAX_SUBSCRIPTIONS
= 1024` **is** enforced, per connection, at `handlers/req.rs:25` and `:73-76` (relay process; a REQ
past the cap is answered `"error: too many subscriptions"`) `[V]`. Treat 10 filters as a contract, not
a fence: do not design something that needs eleven, and do not assume the relay will stop you.

**C7 — `/settings` is already a real route** (already recorded by the ground pass; restated because
§3 acts on it). `routes.ts:8` + `routes/settings.tsx:24-27` declare it with a `validateSearch` that
rewrites the retired `?section=doctor` `[V]`. What is unfinished is that `AppShell.tsx:173` sets
`settingsOpen` from the pathname and the branch at `:784-823` renders `LazySettingsScreen`
**instead of** the outlet at `:941` — which is why `routes/settings.tsx:33-35` returns `null` `[V]`.

The next four were found in the revision pass, after a red-team review, and three of them change
what a producer builds. C8 in particular invalidates a claim the first draft of §5.3 made.

**C8 — the reconnect keyset repair is served by a Rust command with a hard-coded fifteen-kind
constant, and the renderer's kinds never reach it.**
The first draft of §5.3 said "supersetting `CHANNEL_EVENT_KINDS` keeps Buzz's paged reconnect
repair". That is half true, and the half it gets wrong is the half that matters. Measured `[V]`:

- `replayReconnectHistoryPages` (`BUZZ desktop/src/shared/api/relayReconnectReplay.ts:129-178`,
  renderer) calls `requestRepair({channelId, since, limit, until, beforeId})`.
- That request type (`desktop/src/shared/api/channelReconnectRepair.ts:4-10`) **carries no kinds**,
  and its own doc comment at `:12` calls the page "fixed-kind".
- `get_channel_reconnect_repair` (`desktop/src-tauri/src/commands/channel_reconnect_repair.rs:45-68`,
  the **Tauri Rust process**) builds the filter at `:10-42` and inserts
  `CHANNEL_REPAIR_KINDS` — `const [u32; 15]` at `:6-8`, exactly the members of `CHANNEL_EVENT_KINDS`
  in a different order — then calls `query_relay` at `:63`, which POSTs `{api_base}/query` with a
  NIP-98 header (`desktop/src-tauri/src/relay.rs:360-389`).
- `repair_filter_is_fixed_and_keyset_scoped` (`:74-96`) pins the constant into the filter as a test.

So `shouldPageReconnectReplay` returning true buys the lossless walk **for Buzz's fifteen kinds**.
`46010`, `40100` and `39005` are not among them. §5.3 is rewritten around this, and the fix is a
Rust edit in the same PR — not a client-side one.

**C9 — `e2eBridge.ts`'s command switch contains no prefix-matching arm, so the delegating guard has
no ordering constraint.** The first draft listed this as unverified. Measured: every `startsWith(`
in the file (12 occurrences) tests a storage key, a URL, a subscription id or a filename — none
tests `command` `[V]`. The guard must precede `default:` at `:14593-14594` and nothing else. The
same `handleMockCommand` closure is installed both as the Tauri IPC via `mockIPC` at `:14601` and on
`window.__BUZZ_E2E_INVOKE_MOCK_COMMAND__` at `:14597`, so one guard covers both seams. §7.4.

**C10 — the terminal chord is two `event.code` literals in two files, not "unbudgeted work".**
`APPENDIX-NORMATIVE.md` §2 binds `Cmd-\`` and two peer artifacts reported the shipped chord as
`Cmd/Ctrl-J` with different conclusions about the cost. Measured `[V]`: `TerminalBootstrap.tsx:146-168`
(renderer) registers one handler on **both** `keydown` and `keyup` in the **capture** phase, matches
`event.code === "KeyJ"` with meta-or-ctrl and no alt/shift, calls `stopImmediatePropagation()` on
both, and toggles only on `keyup`; its guard `panel.mode !== "closed"` means it only **opens**.
`TerminalSubstrate.tsx:69` carries the matching `KeyJ` for the close side. Rebinding is those two
literals. Two consequences: the registry's chord wins (§14), and Perch's bare `J`/`K` selection keys
are unaffected either way, because the handler requires a modifier.

**C11 — the operator's Ed25519 key has a real home, and Buzz's existing sign-out already wipes it.**
Needed because §7.5 now declares `perch_record_verdict`. `SecretStore::shared(keyring_service())`
(`app_state.rs:435`; service `"buzz-desktop"`, or `"buzz-desktop-dev"` in debug builds, at
`app_state_keyring.rs:9-17`) exposes `store(key, value)` / `load(key)` (`secret_store.rs:729-741`,
`:549`) `[V]`. `store` mutates the service's single keyring **blob** (`:731-734`), and
`delete_all_with_legacy_cleanup` (`:756-800`, the sign-out path, called from `reset.rs:124`)
enumerates that blob's key names at wipe time rather than consulting a fixed allowlist `[V]`. So a
Perch secret stored there is destroyed by the existing path with **zero new code and no allowlist to
forget**.

---

## 2. The feature tree

### 2.1 Six directories, bound to `17-COMPONENT-SPECS.md` §1.1

`17` decided the tree and I bind to it rather than re-deciding: `features/perch/`,
`perch-watch/`, `perch-evidence/`, `perch-containment/`, `perch-policy/`, `perch-shift/`, plus
`shared/ui/perch/`. The reason is the one `17` gives and it is structural, not stylistic — a
`features/<f>` must not import from another `features/<f>`, so one `features/perch` would turn every
cross-surface primitive into an intra-feature import and hide exactly the coupling the file-size
ratchet exists to surface.

`17` did not assign the architecture-owned modules a home. This document does:

| Module | Directory | Why here |
|---|---|---|
| `perchKeys.ts`, `perchSubscriptions.ts`, `perchEphemeralStore.ts`, `tauriPerch.ts` | `shared/api/` | Every one of the six features reads them. Anything else would make `perch-watch` a dependency of `perch-containment`. |
| `perchViews.ts` | `app/` | It is the router's own union; `AppShell.helpers.ts` and the sidebar both consume it, and neither is a feature. |
| `colonyScopedRegistry.ts` | `features/perch/` | `17` defines `features/perch/` as shell-level. `07` §7 proposed `features/colony/`; a seventh feature directory would contradict `17` for no gain. **Departure from `07` §7, recorded.** |
| `PerchSurfaceBoundary.tsx` | `features/perch/ui/` | Same shell-level bucket; it fences surfaces rather than being one. |
| `perch_reads.rs`, `perch_writes.rs`, `perch_verdict.rs` | `src-tauri/src/commands/` | Buzz's own flat command directory (`commands/mod.rs`'s mod block `:1-73`). **Three files, not one**: the split is what lets `check-perch-write-allowlist.sh` read exactly five daemon routes and INV-RF1 read exactly one relay publisher, with no arithmetic and no risk of one gate counting the other's entries (§7.3). |
| `e2ePerchBridge.ts` + the vendored fixture | `src/testing/perch/` | `16-INVARIANT-TESTS.md`'s path, adopted over this document's earlier `src/testing/perchBridgeFixtures.ts` (§7.4.1). Ungoverned root. |
| `check-route-tree.mjs` | `desktop/scripts/` | Beside `check-px-text.mjs` and `check-pubkey-truncation.mjs`, the two gates already chained into `pnpm check`. Not a governed root, so it carries no size budget. |

`07` §7 also names the function `resetColonyState()`; the task brief calls it `resetPerchState`. I
keep **`resetColonyState()`** — `07` §7 is the owning section, "colony" is the Ambush word for a
deployment, and `APPENDIX-NORMATIVE.md` §7 does not rule on the name. The union member type stays
`ColonyScopedSingleton`, which is what INV-23 already names.

### 2.2 Conventions, inherited whole

Read from `BUZZ desktop/src/features/home/` (43 files this session, `[V]`) and identical across the
tree: components at `features/<f>/ui/PascalCase.tsx`; pure functions and types at
`features/<f>/lib/camelCase.ts`; hooks at the feature root as `useCamelCase.ts`; React Query hooks
in `features/<f>/hooks.ts`; `node:test` unit tests colocated as `*.test.mjs`. Named exports only.
No barrel files — `find desktop/src/features -name index.ts` returns exactly one hit, on the delete
list `[V]`.

Two Buzz conventions Perch must consciously keep:

- **Query-key factories live in `lib/`.** `features/messages/lib/messageQueryKeys.ts:3-13` is the
  precedent — three `as const` tuple factories in one small pure module `[V]`. `perchKeys.ts` is that
  shape hoisted to `shared/api/` because it spans features.
- **`data-testid` values are load-bearing for theming.** The Buzz brand cascade selects on them
  (`app-sidebar`, `stream-list`, `dm-list`, `community-rail`), so renaming a Buzz concept without
  updating the testid silently breaks theming with no compile error (`00-BRIEF.md` §5.2). Every
  Perch testid is `perch-`-prefixed (`17` §1.3) so a Perch id can never collide with a themed Buzz
  one.

### 2.3 Surface → directory map

Fourteen surfaces (`APPENDIX-NORMATIVE.md` §1: ten routed, four unrouted) across the six directories.

| # | Surface | Route | Directory | Phase |
|---|---|---|---|:-:|
| S1 | The Watch | `/` | `perch-watch/ui/WatchScreen.tsx` | 1 |
| S2 | Verdict Row | detail pane of `/` | `perch-watch/ui/VerdictPane.tsx` | 1 |
| S3 | Case | `/cases/$caseId` | `perch-evidence/ui/CaseScreen.tsx` | 1–2 |
| S4 | Case Canvas | tab inside a case | `perch-evidence/ui/CaseCanvasTab.tsx` | 2 |
| S5 | Lanes | `/lanes/$laneId` | `perch-evidence/ui/LaneScreen.tsx` | 2 |
| S6 | Containments | `/leases` | `perch-containment/ui/ContainmentBoard.tsx` | 2 |
| S7 | Policy | `/policy` | `perch-policy/ui/PolicyScreen.tsx` | 2 |
| S8 | Watchfloor | `/watch-floor` | `perch-policy/ui/WatchfloorScreen.tsx` | 3 |
| S9 | Ledger | `/ledger` + `Cmd-K` overlay | `perch-shift/ui/LedgerScreen.tsx` | 2 |
| S10 | Tuning bench | `/tuning` | `perch-policy/ui/TuningScreen.tsx` | 2 |
| S11 | Handoff | `/handoff` | `perch-shift/ui/HandoffScreen.tsx` | 2 |
| S12 | Gaps | `/gaps` | `perch-policy/ui/GapsScreen.tsx` | 2 |
| S13 | swarmctl terminal | panel, case-scoped | `features/terminal/` (taken verbatim) | 2 |
| S14 | Governance strip | chrome, every route | `perch/ui/GovernanceStrip.tsx` | 1 |

S8 lands in `perch-policy/` rather than its own directory because it reads the same telemetry
snapshot as S5 and S7 and shares the chart primitives; a seventh directory for one Phase-3 surface
would buy nothing. S13 needs no Perch directory: `00-BRIEF.md` §5.1 takes `features/terminal` and
`src-tauri/src/terminal_runtime.rs` verbatim, and the only change is that
`TerminalAttachRequest` gains a case id (`features/terminal/terminalClient.ts:5-15`).

---

## 3. Routing

### 3.1 The mechanism, and what it costs

Three files, and the plugin sits between them. `desktop/vite.config.ts:11-23` configures
`tanstackRouter({ routesDirectory: "./src/app/routes", generatedRouteTree:
"./src/app/routeTree.gen.ts", virtualRouteConfig: "./src/app/routes.ts" })`; the plugin runs at
dev-server start and at build and regenerates the **committed** `routeTree.gen.ts` (292 lines) from
`routes.ts` plus the files it names `[V]`. `router.tsx:5-11` builds the router with
`createHashHistory()`, so every URL is `#/…` and lives in the user's window state `[V]`.
`routes/root.tsx:5-7` is `createRootRoute({ component: AppShell })`.

Adding one route costs five edits `[V]`:

1. one line in `app/routes.ts`;
2. one file `app/routes/<name>.tsx` exporting `export const Route = createFileRoute("/<path>")({…})`
   — house pattern is `React.lazy` + `<React.Suspense fallback={<ViewLoadingFallback kind="…"/>}>`
   (`routes/agents.tsx:34-50`);
3. regenerate and commit `routeTree.gen.ts` by running any vite command;
4. a `go<Name>` callback in `app/navigation/useAppNavigation.ts` (479 lines, a flat list of
   `React.useCallback` wrappers over `commitNavigation` at `:30-72`, returning **20** entries at
   `:457-478`);
5. a branch in `deriveShellRoute` (`app/AppShell.helpers.ts:217-268`) **and** a member of the
   `AppView` union (`:5-12`).

Perch pays 1–4 per route and replaces 5 outright (§3.3).

### 3.2 The route table, written out

`skeleton/desktop/src/app/routes.ts` is the file. Eleven Perch paths per
`APPENDIX-NORMATIVE.md` §1 — an `index()` plus ten `route()` entries — plus **three redirect stubs**.

The stubs are not optional. `createHashHistory` means an old `#/channels/<uuid>` link lives in the
user's window state and in their history, and Buzz's own answer to a retired route is a redirect
that keeps the bookmark alive rather than dead-ending it — `routes/reminders.tsx:7-11`, whose comment
says exactly that `[V]`. Perch keeps three:

| Retired path | Redirect | Why this one |
|---|---|---|
| `/channels/$channelId` | `/cases/$channelId` | A Perch case id **is** the NIP-29 channel UUID, so an old channel bookmark is a valid case URL. This is the highest-traffic Buzz path. |
| `/agents` | `/watch-floor` | The colony-health band is where the roster went. |
| `/pulse` | `/watch-floor` | `00-BRIEF.md` §5.2 maps pulse → Watchfloor. |

`/workflows`, `/projects`, `/messages/new`, `/reminders` and the forum post route get **no** stub:
their concept is deleted rather than moved, and a redirect to an unrelated surface is worse than a
not-found. This is a decision, recorded in §14.

### 3.3 One view union, one derivation

`AppView` exists twice today with no compiler link: `AppShell.helpers.ts:5-12` (7 members) and
`features/sidebar/ui/AppSidebarPinnedHeader.tsx:16-23` as `SidebarSelectedView` (7 members,
character-identical) `[V]`. Neither imports the other. A new view therefore compiles fine and
mis-highlights the rail.

`skeleton/desktop/src/app/perchViews.ts` replaces both with one `PerchView` union, one
`derivePerchShellRoute`, and one `PERCH_NAV` array carrying a conditional-type assertion that every
nav entry's `view` is a real `PerchView`. `deriveShellRoute`'s consumers are unchanged in shape: it
is called from a `useMemo` at `AppShell.tsx:159-162` in the renderer, and its `selectedView` is what
drives sidebar highlighting and what `useMarkAsReadShortcuts.ts:41` tests before marking a channel
read `[V]`.

Two additions over Buzz's return shape:

- `selectedCaseId` **and** `selectedLaneId` as separate fields. Buzz returns one
  `selectedChannelId` because it has one kind of channel; Perch has two, they render differently, and
  collapsing them means every consumer re-derives which it got from the pathname it was trying not to
  parse.
- `chrome: "full" | "bare"` — §3.4.

### 3.4 Full-screen surfaces, without copying the settings takeover

**DECIDED.** Perch does **not** move `/settings` into the outlet, and does **not** copy its
takeover for the Watchfloor.

Buzz's settings surface is a shell-level replacement: `AppShell.tsx:173` computes
`settingsOpen = location.pathname === "/settings"`, and the branch at `:784-823` renders
`LazySettingsScreen` **instead of** the `<Outlet />` at `:941`, nine providers deep inside
`AppShellChannelSurface` `[V]`. That is why `routes/settings.tsx:33-35` returns `null`. The plan set
(`APPENDIX-NORMATIVE.md` §1, `04` §1.1) treats "make `/settings` a real route" as Phase 0 work; the
ground pass established it is already a real route and that the genuine unfinished work is moving it
through the outlet — a larger, unbudgeted task.

The Watchfloor is the surface that would have forced the question: a wall screen must not carry
navigation chrome. Both available answers are bad — copy the takeover (a second copy of the shell
body) or move Settings first (unbudgeted). So Perch takes a third: `derivePerchShellRoute` returns
`chrome: "bare"` for `watchfloor`, and `AppShell` renders the colony rail, the sidebar and the top
chrome **conditionally on that flag** while the outlet stays mounted on every route. One conditional
in the existing JSX, no second shell, no unmounted outlet, and the governance strip — which
`04` §2.14 requires on every route — survives the bare mode because it renders above the branch.

Settings keeps its takeover in Phase 0 and 1, unchanged and untouched. Moving it into the outlet
becomes a Phase 2 cleanup that is now *optional* rather than blocking, because no Perch surface
depends on it. **This is a departure from `APPENDIX-NORMATIVE.md` §1's "must become a real route
before the first new surface" phrasing** — see §13, amendment A11.

The `Cmd-K` Ledger overlay is not a route at all. It is a Radix dialog over the current surface,
which is what `04` §2.9 describes and what Buzz's own `Cmd-K` already is
(`useAppShellKeyboardShortcuts.ts:73-77` dispatches `onSearchEverything()`) `[V]`.

### 3.5 `routeTree.gen.ts` has no gate, and that is a shipping hazard

The generated tree is committed (`git ls-files` confirms) and consumed only by `router.tsx:3` `[V]`.
Nothing verifies it matches `routes.ts`. A producer who edits `routes.ts` and commits without
running a vite command ships a route that does not exist at runtime, and no check catches it.

**The gate is written and it runs.** `skeleton/desktop/scripts/check-route-tree.mjs` ships with this
document — not a sketch. It reads `src/app/routes.ts`, extracts every `route("…")` and `index("…")`
path literal, reads `src/app/routeTree.gen.ts`, extracts every `path: "…"`, and fails on the
symmetric difference. A text comparison, not a build: no vite, no `node_modules`, no network.

Exercised this session against the real BUZZ tree at `eed74bde2` and against three planted fixtures
(a copy of Buzz's two files in the scratchpad, mutated one way at a time):

| Case | Result |
|---|---|
| real `desktop/` unmodified | `12 route paths in sync` — **exit 0** |
| a route added to `routes.ts`, tree not regenerated | `declared in routes.ts, absent from routeTree.gen.ts: /watch-floor` — **exit 1** |
| a route removed from `routes.ts`, tree still carrying it | `present in routeTree.gen.ts, absent from routes.ts: /workflows` — **exit 1** |
| `routes.ts` replaced with a stub the parser cannot read | `parsed zero routes … a gate that scans nothing passes everything` — **exit 2** |

That last row is the guard the wave-2 review asked every gate to carry: a scanner that finds nothing
must fail, not pass. Two of the three checks a peer reported as "measured" turned out to have been
run against a file that was not the committed one, and a vacuous-scan guard is the cheapest defence
against being the fourth.

My own `routes.ts` parses to **14** paths under the same extractor — eleven Perch routes plus the
three redirect stubs — which is the number §3.2 claims.

**Wiring, and why it needs no workflow edit.** One line in `desktop/package.json`:

```
"check:route-tree": "node ./scripts/check-route-tree.mjs",
"check": "biome check . && pnpm check:px-text && pnpm check:pubkey-truncation && pnpm check:route-tree",
```

`just check` runs `desktop-check`, which is `cd desktop && pnpm check` (`BUZZ justfile:96,133-134`),
and `just ci` runs `check` (`:304`) `[V]`. So the gate reaches `just check`, `just ci`, the pre-push
lane and CI's desktop job through the existing chain.

This matters for a reason the rest of the wave-2 gate inventory does not share: AMBUSH's
`tools/check-gates-wired.sh` enumerates `tools/check-*.sh` and `tools/verify-*.sh` **in the Ambush
repository** and requires each to be named by a real `run:` command in a workflow (`:19-56`, read
this session). A Buzz-side `desktop/scripts/*.mjs` is outside its scope entirely. So unlike every
Ambush-side guard in this plan set, this one is a **one-part change**, and it is done.

It remains strictly weaker than regenerating and diffing — it cannot see a stale `validateSearch` or
a changed component import — and strictly stronger than nothing, which is what exists today.

### 3.6 Lazy loading, per route

Buzz's index route is **not** lazy: `routes/index.tsx:6` imports `HomeScreen` directly `[V]`. Every
other content route is `React.lazy` + `Suspense` with a `ViewLoadingFallback`. Perch keeps that
split exactly: `/` (The Watch) is eager because it is the screen a shift starts on and a Suspense
flash on the queue is the wrong first impression; the other nine are lazy.

`ViewLoadingFallback` is **not** reusable verbatim — `17` §2.2 established it imports
`BuzzLoadingState` (delete list) and its `ViewLoadingFallbackKind` union at `:8-14` is literally
Buzz's routes (`agents | channel | forum | projects | pulse | workflows`), none of which is a Perch
route `[V]`. It is a re-skin whose union becomes `PerchView`. `17` §8 owns the re-skin; this document
owns that the route files must not land before it, or nine `Suspense` fallbacks reference a union
member that does not exist.

---

## 4. React Query

### 4.1 What Buzz does, and the one property it lacks

Client defaults: `retry: 1`, `refetchOnWindowFocus: false`, `networkMode: "always"`,
`gcTime: 5 * 60_000`, plus a `focusManager` rewired to app focus rather than document focus
(`shared/api/queryClient.ts:23-37`) `[V]`. Two clients exist: a machine-scoped one at `App.tsx:805`
and a **community-scoped** one at `App.tsx:235`, the latter inside a component `App.tsx:630`
remounts with `key={communityKey}` (`:407`) `[V]`.

Keys are ~50 flat per-feature constants with no factory, and reconnect healing consults one
hand-maintained `Set` of 34 roots (`relayQueryInvalidation.ts:1-36`) as the React Query `predicate`
at `useReconnectRelay.ts:62` and `useRelayAutoHeal.ts:113-119` — both in the renderer, both on a
degraded→connected transition `[V]`. A query whose `key[0]` is not in that Set is never invalidated
on reconnect and goes stale permanently, silently, and only under network churn.

The missing property is not the registry. It is that **the key does not say who owns the answer**.

### 4.2 Source-as-first-segment

`perchKeys.ts` makes it the first segment: `"relay" | "daemon" | "local"`. Healing then needs no
registry —

```ts
export const isRelayDependentQuery  = (q) => q.queryKey[0] === "relay";
export const isDaemonDependentQuery = (q) => q.queryKey[0] === "daemon";
```

— and the two predicates exist separately because Perch has two backends that fail independently.
The relay can be up while the daemon is unreachable, and that is exactly the state in which
`/leases` must degrade honestly: with the daemon down, the containment TTL is the only backstop, and
Perch has to say so rather than showing a stale countdown as if it were live. Buzz's single-backend
assumption does not survive the fork. This is `07` §7's design, completed.

`isRelayDependentQuery` is passed at exactly the two sites Buzz passes its own — no new wiring, one
import swap.

### 4.3 The freshness table is part of the type

The failure mode a key factory alone does not fix is a `staleTime` chosen at each call site by
whoever wrote the hook. `perchKeys.ts` carries `PERCH_FRESHNESS`, a
`satisfies Record<keyof typeof perchKeys, PerchFreshness>` — so an unlisted key is a compile error,
a listed non-key is a compile error, and every row carries a `why` string that survives review.
Twenty rows, one per read. Highlights and the reasoning that is not obvious:

| Key | `staleTime` | Poll | The load-bearing reason |
|---|---:|---:|---|
| `holds` | 0 | none | Refetched on connect, on reconnect and on every `26006`. **Never polled**: the alarm is the trigger, and a poll would hide a dead alarm path instead of surfacing it. |
| `needsAction` | 0 | none | Runs *beside* `holds`, never instead. `build_needs_action_query` (`BUZZ crates/buzz-db/src/store/feed.rs:171-201`, relay process, INNER JOINs `event_mentions` and filters `kind IN (46010, 40007)` at `:191-193`) has **no status join**, so a decided hold stays in it forever. |
| `containments` | 2,500 | 5,000 | Half the poll, so a navigation inside the window does not double-fetch. |
| `caseTimeline`, `caseWindow` | `Infinity` | none | Buzz's cache-as-store pattern (`features/messages/hooks.ts:247-258` sets `staleTime: Infinity` and reads the cache in the `queryFn`) `[V]`. Live events mutate the cache; a refetch fights the merge. **This is C5's distinction preserved**: a `relay`-source key can still be a cache mirror, and its `staleTime: Infinity` is what makes reconnect invalidation harmless rather than wrong. |
| `operatorStatus` | 60,000 | none | On demand only. `platform_runtime_status_handler` loads incidents with `.recent(usize::MAX)`; `04` §2.10 refuses polling it explicitly. |
| `admittedIssuers` | 300,000 | none | Long on purpose: the set feeds every marker parse and every `26xxx` frame (INV-15), and it must be reference-stable or it defeats the memo on every evidence card (§9). |
| `artifactVerification` | `Infinity` | none | A byte diff of an immutable artifact. Re-running it can only produce the same answer or a new bug. |

Every polling row is gated on connection state by its calling hook, copying
`features/home/hooks.ts:19-23` — Buzz pauses the home-feed poll while the relay is not connected
because the failed requests consume the quota the recovery path needs `[V]`.

`PERCH_NO_RETRY = { retry: 0 }` is applied per hook to every `daemon`-source query, overriding the
client-wide `retry: 1`. A retried governance read against a partitioned daemon is a lie with a delay
attached; the operator needs the refusal.

### 4.4 Governance actions are never optimistic — and the mechanism, not the promise

`07` §7 states the policy and `08` INV-33 tests it. The mechanism is what this document adds.

Optimistic is permitted for: marking a case read, collapsing a queue section, resizing the inbox
pane, setting a snooze (with rollback), editing the case canvas, posting a human message in a case
(Buzz's `pending`/`localKey` on `RelayEvent`, `shared/api/types.ts:188,195`).

Optimistic is **forbidden** for: recording a grant or a refusal on a held action; Confirm / Dismiss /
Investigate on a finding; releasing a containment. Three different reasons, and it matters that they
are different: the grant has two legs and two authorities and the daemon may refuse; Dismiss
retroactively removes every deposit at or before the marker from a concentration sum, so an
optimistic dismiss draws a curve collapse that may not have happened; and a release's `lease_closed`
is read from the body, not from a 200, so there is no optimistic state that can honestly represent
it.

Enforcement is structural, not a review note. **DECIDED:** governance writes do not go through
`useMutation`'s `onMutate` at all. They go through a small `usePerchWrite` wrapper whose returned
object has **no `onMutate` hook to pass** and whose state machine is a **four-phase** union rather
than a boolean:

```ts
type PerchWriteState =
  | { phase: "idle" }
  | { phase: "sending" }                                 // leg 1 or leg 2 in flight
  | { phase: "recorded"; atMs: number }                  // relay OK'd the intent card
  | { phase: "settled"; outcome: PerchDecideOutcome };   // the daemon answered
```

`recorded` is the state that matters, and it is exactly what `perch_record_verdict` returning
successfully means: the operator's decision exists as a signed intent card on the relay and the world
has not changed. Collapsing it into a checkmark is the single easiest way to make Perch lie. INV-33's
test is then a type-level assertion plus a DOM assertion that all four phases render distinctly,
rather than a hunt for `onMutate` call sites.

`settled` carries a `PerchDecideOutcome`, and **`superseded` is one of its values** — the state in
which this console's decision was recorded, signed, real, and not the one that executed (§7.6). It
is a `settled` outcome and not an error, for the same reason `refused_late` is: it is the system
working. A console that rendered it as a failed write would teach an operator that a colleague
deciding first is a bug.

### 4.5 Invalidation, per write

`invalidatesOnWrite` on each freshness row is the whole policy. Two entries are worth stating in
prose because they are the ones a producer would get wrong:

- A **decide** (grant or refuse) invalidates `holds` *and* `needsAction` *and*
  `reconcileDivergences` — because the relay row survives the decision (no status join) and the
  divergence counter is how anyone learns the notification path is broken.
- A **finding verdict** invalidates `reviewedFindings` but **not** `deposits`. The deposit slice is
  refetched only after a **Dismiss**, because only `Dismiss` sets `false_positive`
  (`AMB crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:473-495`, daemon process,
  builds the `FalsePositiveMeasurement` with `false_positive = matches!(action, Dismiss)`); Confirm
  and Investigate move the denominators without suppressing a deposit.

### 4.6 No colony segment in the key — and the condition under which that changes

`07` §11.3 asks for colony-prefixed keys against a future federated view. **DECIDED: v1 keys carry
no colony segment.** The `QueryClient` is already colony-scoped — it is constructed inside a
component that `App.tsx:630` remounts on `key={communityKey}` — so two colonies never share one
cache, and a colony segment inside a colony-scoped client is dead weight that invites the belief
that one client holds two.

The condition under which this must change is precise, and it is written into `perchKeys.ts`'s doc
comment so nobody has to find it here: **a read view that renders two colonies at once**. When that
exists it gets its own `QueryClient`, not a wider key — because a wider key would let a cross-colony
component subscribe to a single-colony cache entry and get an answer, which is the conflation
`00-BRIEF.md` §9 forbids. Recorded as a commitment.

---

## 5. The subscription manager

`skeleton/desktop/src/shared/api/perchSubscriptions.ts` is the file.

### 5.1 One primitive, one reconciler

Every Perch REQ goes through `relayClient.subscribeLive` (`relayClientSession.ts:410-417` → the
private `subscribe` at `:599-650`, renderer): it generates a `live-${uuid}` subId, registers
`{mode:"live", filter, onEvent, resolveReady}` in `this.subscriptions`, sends `["REQ", subId,
filter]` through `sendRawWithReconnectRetry` (one reconnect retry), resolves readiness on EOSE or a
250 ms timeout, and returns an async disposer that CLOSEs `[V]`. **Perch needs no new client method
and no new Tauri command for relay work**: `sendRaw` (`:652-664`) hands the frame to the native
socket via `invoke("plugin:websocket|send")`, so the socket lives in Rust and all Nostr framing is
TypeScript.

The reconciler is Buzz's own shape, hoisted. `useLiveChannelUpdates.ts:364-419` holds a
`Map<channelId, dispose>` in a ref, diffs it against the target set, disposes what left, opens what
arrived with `Promise.allSettled`, and retries with exponential backoff on failure `[V]`. Perch's
`syncPerchSubscriptions` is that function with three changes:

1. **Hoisted out of a hook**, because Perch's REQs are declared by six features and the frame budget
   is global.
2. **Keyed by a stable filter serialization**, so an unchanged filter does not churn the REQ. `since`
   is deliberately excluded from the serialization — it is `now` on every rebuild, and including it
   would tear down and re-open every live REQ on every render that touches the manager. This is the
   single most expensive mistake available in the file and it is called out in the source.
3. **Priority ordering on open**, so `watch-alarm` is established first.

### 5.2 The REQ inventory, per surface

Seven subscriptions, maximum, ever. Values from `APPENDIX-NORMATIVE.md` §3 and the per-surface
tables in `03` §8 / `07` §6; the buildable form is `buildPerchSubscriptions()`.

| id | Filter | Open when | Notes |
|---|---|---|---|
| `watch-alarm` | `{kinds:[26006],"#p":[me],limit:0}` | always | **The only live path to a hold.** Global, no `#h` — ratified in §5.2.1. |
| `watch-snoozes` | `{kinds:[30300],authors:[me],limit:100}` | always | Due times computed client-side. |
| `watch-named-you` | `{kinds:[9],"#p":[me],limit:100}` | always | Partitioned client-side on the `k` tag. |
| `lane-movement` | `{kinds:[9],"#h":[…12 lanes],limit:1}` | always | **One** REQ, not twelve. |
| `case-activity` | `{kinds:[9,46010],"#h":[…cases],limit:1}` | cases taken | Multi-`#h`; see §5.3. |
| `case-live` | `{kinds:[…CHANNEL_EVENT_KINDS, 39005, 46010, 40100],"#h":[case],limit:1000,since:now}` | a case open | Paged-repair-eligible; §5.3 for what that does and does not buy. |
| `telemetry` | `{kinds:[26000…26005],limit:0}` | Watchfloor / lane / strip mounted | Global, no `#h`. |

Four things this table encodes that are not obvious.

**A REQ of `{kinds:[46010],"#p":[me]}` cannot work.** The two-arm fork makes 46010 channel-scoped;
`fan_out_scoped` (`BUZZ crates/buzz-relay/src/subscription.rs:379-495`, relay process, called from
`handlers/event.rs:241-250` and from `dispatch_persistent_event`) routes an event with `channel_id =
Some(..)` through the channel indexes only, and a REQ with no `#h` registers in the global indexes.
The invariant is stated outright in the source at `:487-492`. The HTTP backfill still works, so the
defect passes every cold-load test and appears only as "the queue never updates live". `26006` is
the live path.

**`26006` is global, carries no `h`, and this is now ratified rather than assumed.** Three artifacts
shipped three designs for one frame — an `h` tag naming a standing `#watch` channel
(`13-WIRE-SCHEMAS.md` amendment W-1), `P_GATED_KINDS` (`ADR 0017` clause C3), and the global `#p`
REQ this file implements. Applying the first two together closes the subscription entirely, and only
one of the three was ever built. **DECIDED: C3. W-1 is withdrawn.** The argument is in §5.2.1 and
it is mechanical, not editorial.

**`26006` is a nudge with no authority.** It triggers the daemon re-read; a row appears only if
`GET /v1/response/holds` confirms it. A hold the list does not confirm renders **nothing** — an
alarm alone never produces a decidable row, which is also what makes a duplicate alarm harmless. A
Perch that was disconnected when the alarm fired **missed it** (ephemerals are never replayed),
which is why the daemon list is re-read on connect, on reconnect and on every alarm.

**Twelve lanes on one REQ.** `#h` accepts up to `MAX_EXPLICIT_CHANNEL_VALUES = 128` values across a
REQ's filters (`BUZZ crates/buzz-relay/src/handlers/req.rs:42`) `[V]`. A REQ per lane spends twelve
subscription slots and twelve admission frames on a view nobody is reading.

### 5.2.1 The `26006` delivery decision, settled

The registry already answers this. `APPENDIX-NORMATIVE.md` §3 lists the ephemeral block as "global
(no `h`)", and §4 layer 2 says "an ephemeral `26006` frame, **global, no `h`**, `p` = the same set.
This is the only live path." The appendix's own rule is that a document cites it and does not restate
it, and that where a document restates a value the appendix wins. W-1 is a *departure from the
registry* with no ratified amendment behind it.

That would be enough. The mechanism makes it decisive, and I read both paths rather than taking the
registry's word:

1. **An `h`-tagged `26006` delivers nothing to the filter every consumer writes.**
   `handle_ephemeral` (`BUZZ crates/buzz-relay/src/handlers/event.rs:849-903`, relay process)
   branches on `extract_channel_id`. With an `h` tag it calls `check_channel_membership`, publishes
   on `EventTopic::Channel(ch_id)`, and fans out with `StoredEvent::new(event, Some(ch_id))` at
   `:874` — the channel-kind index. Without one it takes the `Uuid::nil()` global path at `:875-903`.
   A REQ with no `#h` registers in the global index and, per `subscription.rs:487-492`, never
   receives a channel-scoped event `[V]`.

2. **An `h`-tagged `26006` does not close the disclosure W-1 was proposed to close.** A
   channel-scoped ephemeral is delivered to every **member** of that channel;
   `filter_fanout_by_access` does not consult `p` tags. W-1 narrows the audience from "every
   community member" to "every `#watch` member" and stops there — and it buys that with a standing
   channel nobody has built, bridge membership in it (the RF-D2 pattern), and a second REQ.

3. **An `h`-tagged `26006` puts the frame permanently outside the one gate that *can* close it.**
   `p_gated_filters_authorized` (`crates/buzz-relay/src/handlers/req.rs:1182-1216`) requires every
   `#p` value in a filter naming a p-gated kind to equal the authenticated pubkey. It is called at
   REQ registration at `:219-226` — inside `if channel_id.is_none()`, whose comment says exactly
   that: the gate applies only to **global** subscriptions `[V]`. Channel-scoping the frame disables
   its own fix.

So C3 is the mechanism: one line adding `26006` to `P_GATED_KINDS`
(`BUZZ crates/buzz-core/src/kind.rs:159-169`), an array that **already carries an ephemeral** —
`KIND_AGENT_OBSERVER_FRAME`, present, per the doc comment at `:156-158`, for exactly this
filter-layer enforcement `[V]`. With it, `{kinds:[26006]}` with no `#p` and
`{kinds:[26006],"#p":[someone_else]}` are both answered
`CLOSED "restricted: p-gated events require #p matching your pubkey"`, and the filter in this
document is the only admissible one.

**What this decision does not do:** it does not delete the `#watch` ops channel. That channel exists
for the watch claim (`04` §2.11) and `perchKeys.watchClaim()` still reads it. W-1 is withdrawn for
the alarm frame only.

**What is still open until the line lands:** the disclosure. Any authenticated member can open
`REQ {kinds:[26006]}` today and receive every hold alarm. The client cannot fix that; the
admitted-issuer gate closes the *forgery* half only, and `perchEphemeralStore.ts` says so at the
gate rather than implying more.

### 5.3 What a reconnect actually recovers — two mechanisms, and only one of them reads our filter

This is the section a red-team review corrected, and the correction matters more than the original
finding did. The first draft said supersetting `CHANNEL_EVENT_KINDS` "keeps Buzz's paged reconnect
repair". Half of that is true. The half that is not would have converted a **visible** five-second
degradation into a **silent** partial hole.

**Mechanism 1 — eligibility, decided in the renderer from our filter.**
`shouldPageReconnectReplay` (`BUZZ desktop/src/shared/api/relayReconnectReplay.ts:103-111`,
renderer, called per live subscription by `replayLiveSubscriptions` at `:232`) returns true only for
a filter with `limit > 0`, exactly one `#h`, and
`CHANNEL_EVENT_KINDS.every(k => filter.kinds.includes(k))` `[V]`. An **eligible** subscription gets
its **original filter re-sent verbatim** (`:314-317`) plus a paged keyset backfill; an **ineligible**
one degrades to `buildReconnectReplayFilter` (`:82-101`) — one REQ,
`since = lastSeenCreatedAt − RECONNECT_REPLAY_SKEW_SECS (5)`, `limit = min(filter.limit, 500)`.
Five seconds is not a repair for a minute-long disconnect, so the naive Perch filter
`{kinds:[9,46010,40100,40099]}` — which `07` §6 and the spec extract both write — must not be
written. `perchCaseLiveKinds()` supersets the constant and **spreads** it, so `00-BRIEF.md` §5.4's
huddle deletion (which removes 48100–48103 from `CHANNEL_EVENT_KINDS`,
`shared/constants/kinds.ts:100-113` `[V]`) cannot desynchronise the eligibility test.

**Mechanism 2 — what the backfill fetches, and it is not our filter.** `[V]`

`replayReconnectHistoryPages` (`:129-178`) walks the missed window with a composite
`(created_at, id)` cursor at `RECONNECT_REPLAY_PAGE_LIMIT = 500` per page, over a lookback of
`RECONNECT_REPLAY_CHANNEL_LOOKBACK_SECS = 1865` seconds (900 relay future tolerance + 960 DB floor
+ 5 margin, `:22-28`), retrying to `PAGE_REPLAY_MAX_ATTEMPTS = 3` behind the rate-limit gate and
pinning `pendingReplaySince` so an exhausted backfill cannot let live events erase the unresolved
window. Every page is a call to `requestRepair({channelId, since, limit, until, beforeId})`.

That request type carries **no kinds** (`desktop/src/shared/api/channelReconnectRepair.ts:4-10`; its
doc comment at `:12` calls the page "fixed-kind"). It invokes `get_channel_reconnect_repair`
(`desktop/src-tauri/src/commands/channel_reconnect_repair.rs:45-68`, the **Tauri Rust process**),
which builds the filter at `:10-42`, inserts `CHANNEL_REPAIR_KINDS` — `const [u32; 15]` at `:6-8`,
member-for-member `CHANNEL_EVENT_KINDS` in a different order — and calls `query_relay` at `:63`,
which POSTs `{api_base}/query` with a NIP-98 auth header after awaiting the shared rate-limit gate
(`desktop/src-tauri/src/relay.rs:360-389`). `repair_filter_is_fixed_and_keyset_scoped` (`:74-96`)
pins the constant into the filter as a test, on purpose: the renderer must not be able to widen the
repair page.

**So the keyset walk fetches Buzz's fifteen kinds and nothing else.** `46010`, `40100` and `39005`
are not in it.

**The residual, measured rather than asserted.** The Perch kinds are *not* lost outright, because an
eligible subscription's re-sent REQ is the original filter — `{…, "#h":[case], limit: 1000, since:
<subscription-open>}` — and the relay answers it from storage. What they lose is the *lossless*
property. The relay serves that REQ `ORDER BY created_at DESC, id ASC LIMIT` with the requested
limit clamped by `DEFAULT_MAX_PAGE_LIMIT = 1000` (`BUZZ crates/buzz-db/src/store/event.rs:599`,
`:33`, relay process) `[V]` — newest-first truncation. So the hole opens when more than `limit`
matching events accumulate in one case channel after the subscription opened, at which point the
**oldest** events in that window are dropped, and a hold notice is exactly the kind of low-frequency
event that sits at the old end of a chatty case.

That is a narrower defect than "every Perch event in that window is silently lost", and I record the
narrowing because the difference decides the fix. It is also still a defect, and it is invisible.

**DECIDED — extend the Rust constant, in the same PR as the fork.**
`CHANNEL_REPAIR_KINDS` goes from 15 to 18: `+46010, +40100, +39005`. The cost is one Rust constant
and one literal in `repair_filter_is_fixed_and_keyset_scoped`, in a file
(`channel_reconnect_repair.rs`, 110 lines) with no size pressure. It rides the same PR as the relay
fork because it is the same change: 46010 becoming a channel event is what creates the obligation.

**DECIDED — assert the two lists against each other, because nothing else can.**
A TypeScript constant and a Rust constant describing one wire filter, in two languages, with no
compiler link, is precisely the shape that produced this defect. `perchSubscriptions.ts` exports
`PERCH_CASE_REPAIR_KINDS = [46010, 40100, 39005]` and `assertPerchRepairKindsCovered(repairKinds,
isDevBuild)`, which **throws in a dev or E2E build** and returns a rendered message in production.
Production does not crash: a shipped build cannot fix the constant, and crashing a console over a
backfill gap is a worse failure than the gap. The point is to fail on the machine of whoever changed
one of the two lists. Handed to `16-INVARIANT-TESTS.md` as **INV-CR1**, whose Rust half extracts the
literal from `channel_reconnect_repair.rs:6-8`.

**The independent backstop, and its honest limit.** If the constant ever regresses, a marker card
lost inside the missed window shows up as a forward jump in its issuer's `seq` and the gap renders
(§5.7). That is a genuinely independent mechanism — different process, different data path, no
shared failure mode — which is why a regression here degrades visibly rather than lying. Its limit:
it only fires once a *later* card from the same issuer arrives, so it is a backstop and not a
substitute.

**One consequence for `case-activity`, recorded so nobody "fixes" it.** It stays multi-`#h` and
therefore stays ineligible for the paged repair. That is deliberate: it is a nudge whose
authority is the daemon hold list and the case timeline, not itself. Splitting it into twelve REQs
to gain eligibility would spend twelve subscription slots to make a nudge lossless.

**A property of Buzz's own code worth knowing before relying on any of this.** On the exhaustion
path (`:399-402`) `markReconnectRepairDone` is called *and* `pendingReplaySince` stays pinned —
cleared only when a pass genuinely completes (`:390-393`) `[V]`. That is honest at the data layer:
the next reconnect retries the window. It is invisible at the UI layer, and the subscription object
holding it lives in `relayClientSession`'s private map, which `subscribeLive` does not expose and
which is frozen at 1084 gate-lines. Perch therefore does **not** read it, and the seq detector above
is the surfacing mechanism instead.

### 5.4 Ephemeral and stored are consumed separately

The relay makes no client-side distinction: an ephemeral `26xxx` and a stored `kind:9` both arrive
as `["EVENT", subId, event]` on the same socket and land in the same `onEvent` — `subscribe`
(`relayClientSession.ts:599-650`) has one dispatch path `[V]`. The divergence is entirely ours, and
it is load-bearing.

**Stored events → the React Query cache**, via the existing merge paths.
**Ephemeral frames → `perchEphemeralStore.ts`**, a module-level snapshot read with
`useSyncExternalStore`. Never the query cache. Three reasons, in the file:

1. **Last-wins per subject, not append.** A 1 Hz `ConcentrationSnapshot` is a replacement, not an
   event; keeping history would grow without bound on a wall screen that runs for years.
2. **No invalidation semantics.** `invalidateQueries` on reconnect must not *look* like it can
   recover telemetry. It cannot: ephemerals are not stored and are not replayed. Every ephemeral
   consumer names its authoritative re-read instead.
3. **Referential stability under no-change** — §9.

The publish side copies Buzz's shipped ephemeral shape verbatim: `sendTypingIndicator`
(`relayClientSession.ts:299-320`, renderer) returns immediately when `this.wsId === null` because it
is "not worth triggering a reconnect for ephemeral typing", signs, and does
`void this.sendRaw(["EVENT", event]).catch(() => {})` — no OK wait, no retry, no error surface `[V]`.
Perch has no client-side ephemeral publisher today (the bridge publishes the 26xxx block), but if
one ever appears, that is its shape.

**The admitted-issuer gate is on the read path, and it does not close the disclosure.**
`applyPerchEphemeralFrame` drops any frame whose pubkey is not in the admitted set and **counts**
it — `perchUnadmittedFrameCount()` is rendered, because a silently dropped frame is
indistinguishable from a quiet swarm. That closes the *forgery* half of the problem: the ephemeral
ingest gate is a single scope test every chat-capable member passes
(`BUZZ crates/buzz-relay/src/handlers/event.rs:698-707`, relay process: `if !scopes.is_empty() &&
!scopes.contains(&Scope::MessagesWrite)` reject) `[V]`, so without the client rule any member could
publish a fabricated `26003` and page the rotation. It does **not** close the *disclosure* half:
`filter_fanout_by_access` (`handlers/event.rs:115-222`, the single guarded send chokepoint for local
WS delivery in the relay process) applies only the receiver tenant label, `AUTHOR_ONLY_KINDS` and
`SHARED_GATED_KINDS` to a channel-less event and then returns every match at `:177-179` without
consulting `p` tags `[V]`. Any authenticated community member who opens `REQ {kinds:[26006]}`
receives every hold alarm.

The disclosure half needs a relay change and §5.2.1 makes the call: `26006` joins `P_GATED_KINDS`,
which moves the enforcement to REQ registration, where a filter without `#p = self` is refused
outright. Until that line lands the client behaves identically and the hole is open. The client
cannot fix it, and this document does not pretend otherwise — but the fix is now one named line
rather than "three options".

### 5.5 Frame budget, with the arithmetic

`enforce_ws_admission` (`BUZZ crates/buzz-relay/src/connection.rs:652-706`, relay process, runs on
**every** inbound EVENT/REQ/COUNT frame before dispatch) charges the principal's `LimitType::WsEvents`
counter with `limit = human_ws_events_per_sec × WS_BURST_WINDOW_SECS` — 10 × 5 = **50 frames per
rolling 5 s window, per pubkey, with no agent exemption** (`admission.rs:9,40-45`) `[V]`. No plan
document budgets REQ frames against this counter. Here is the budget.

**Steady state.** Seven REQ frames at open, then **zero** until navigation. Inbound EVENT frames are
not charged to the reader. The operator's own publishes are charged against a separate per-minute
counter, and the tier is `human_messages_per_min = 60` — selected at `connection.rs:690-695` by
`is_agent = ctx.agent_owner_pubkey.is_some()`, and an operator key carries no NIP-OA owner
attestation `[V]`. Sixty verdicts a minute is not a queue anyone has.

**Reconnect, the real exposure.** All seven REQs go out at once, plus one paged-history REQ per
eligible subscription. Buzz caps that blast at `REPLAY_BATCH_SIZE = 8` with
`REPLAY_INTER_BATCH_DELAY_MS = 50` and re-checks the rate-limit gate before every batch
(`relayReconnectReplay.ts:47-62`, `:300-307`) `[V]`. Seven subscriptions fit in one batch. Only
`case-live` is paged-repair-eligible (§5.3), so:

> **7 REQ + 1 history REQ = 8 frames in one 5 s window, against a budget of 50. Headroom: 42.**

Those 42 are the room the un-shed `26006` alarms and the operator's own publishes need. **Perch adds
no second batcher** — reusing Buzz's replay path means the rate-limit gate, the ordering, and the
visible-surface-first sort (`relayReconnectReplay.ts:281-296`) all apply unchanged.

For contrast, this is the budget the bridge does **not** have: a pre-coalescing 10 Hz concentration
publisher would consume the entire 50-frame window by itself, which is why
`APPENDIX-NORMATIVE.md` §3's "coalesced 10 Hz → 1 Hz in the bridge, before IPC" is a hard
requirement. That is `11-BRIDGE-CRATE.md`'s problem; it is stated here so the two budgets are
visibly the same budget.

### 5.6 Reconnect and backfill, end to end

Perch inherits the whole path and adds one step.

1. `relayReconnectController` drives the reconnect; `useReconnectRelay` (renderer) subscribes to it
   and, **on success, defers query invalidation to a `setTimeout(…, 0)` so callers render the
   recovered state first** (`useReconnectRelay.ts:58-70`) `[V]`. Perch changes only the predicate.
2. `replayLiveSubscriptions` re-sends every live REQ in batches of 8, visible surface first, and
   pages history for eligible subscriptions with retry and a pinned floor (§5.3).
3. **Perch's addition:** on the same success edge, re-read the daemon — `holds`, `containments`,
   `reviewedFindings` — through `isDaemonDependentQuery`. The relay coming back does not mean the
   daemon ever went away, and the daemon coming back does not fire a relay event. Two predicates,
   two triggers.
4. Then the reconciler runs: `holds` (daemon) versus `needsAction` (relay), rendering the three
   divergence cases from `07` §5.6 and incrementing
   `perch_queue_reconcile_divergences_total`. A divergence is a bug in the notification path and
   must be countable before anyone argues it does not happen.

One operational caution inherited verbatim: a subscription can be evicted with a `CLOSED` carrying a
specific reason string, and only `"channel access revoked"` is in the desktop client's drop-set, so a
client that treats every `CLOSED` as fatal reconnect-storms during case churn. `syncPerchSubscriptions`
does not interpret `CLOSED` at all — it is below the manager, in `relayClientSession`.

### 5.7 Gap detection

Every published envelope carries a per-issuer monotonic `seq` (`07` §5.4). `observeIssuerSeq` is fed
every decoded card body in arrival order and returns a gap the moment one opens, so the row renders
immediately rather than on the next poll.

Three properties the implementation commits to:

- **Namespaced by `(colony, issuer)`, never `issuer` alone.** Two colonies each running a `whisker`
  both emit `seq: 1`; merging them under one key produces a false gap, or — worse — a false
  continuity (`07` §11.1). In v1 the store is colony-scoped by remount, so the colony is the store's
  identity rather than a key segment; the parameter exists so the federated case cannot be
  retrofitted wrongly.
- **A seq below the high-water mark is not a gap.** It is a duplicate or a late arrival. Only a
  forward jump opens one.
- **A gap is never healed from the relay.** The relay does not know what the bridge dropped; only the
  daemon does. The row's affordance re-fetches the `(issuer, seq-range)` from the daemon, and the
  gap closes only when it is served. This is the difference between marking a hole and hiding one.

The gap row is a full-width row **above queue 1** on The Watch, never a toast (`04` §2.1). Sequence
gap count across all issuers is a C9 metric with target **0, always** — any nonzero value is a P0.

**Dependency, stated plainly:** none of this works until the bridge supplies `seq`. The daemon's SSE
stream sets `.id(event.emitted_at_ms().to_string())` — a millisecond timestamp that collides at the
monitor's 10 Hz cadence and is not monotonic across issuers — and `RuntimeEvent` has no `seq` field.
So a receive-side counter in the client detects nothing about what the daemon dropped *before* the
bridge. `observeIssuerSeq` detects loss **between the bridge and this client**, which is real and
worth detecting, and it is honest to say it detects nothing more until B6.

---

## 6. The client half of the marker-renderer registry

`17-COMPONENT-SPECS.md` §3 owns the registry: the types, the parse contract, the `satisfies
Record<>` dispatcher, the seven presenters, the four refusal cards, the `MessageBody` seam. This
section owns only how it is wired into the client, and it is short because `17` got the hard part
right.

**Three bindings this document makes:**

1. **`MessageRow` gains zero props.** `17` §3.7 puts `isAdmittedIssuer` on an
   `AmbushAdmissionContext` read from context rather than drilled as a prop, and this document is
   where the provider is mounted: **inside `AppShellProvider`** (`AppShell.tsx:708-993`; its `value` object at `:709-745` already
   carries 30 fields), keyed on
   the admitted-issuer set's version, memoized through
   `shared/hooks/useStableReference.ts`'s `useStableSet` (`:62-70`) `[V]`.

   **A separate provider nested inside it, never a 31st field on its `value`.** That object literal
   is rebuilt on every `AppShell` render, so anything merged into it is a new identity every render
   — which is precisely the failure `CLAUDE.md` gotcha 6 describes, applied to every evidence card
   in an open case at once. Mounting the admission provider lower — per case, per timeline — is the
   opposite mistake: it would remount on every navigation and throw the memo away just as
   thoroughly.

2. **The admitted-issuer set is a query, and it is the one whose staleness is deliberately long.**
   `perchKeys.admittedIssuers()` with `staleTime: 300_000` and no poll (§4.3). It is invalidated by
   an explicit admission change, never by a timer, because a timer-driven identity change would make
   every evidence card in an open case re-render on a schedule for no reason.
3. **The same admitted set gates the ephemeral store** (§5.4) and the `46010` queue path
   (INV-15 extends the rule to the stored kind). One set, three consumers, one invalidation.
   Registered in the colony reset registry as `admittedIssuerSet` (§8).

**The registration-point arithmetic, restated because it is the thing most likely to be over-paid.**
`APPENDIX-NORMATIVE.md` §3's "four client registration points" is the cost of the **46010 fork**, not
of a marker. `kind:9` is already in `CHANNEL_EVENT_KINDS` (`shared/constants/kinds.ts:100-113`), in
`CHANNEL_TIMELINE_CONTENT_KINDS` (`:137-149`), and in `isTimelineContentEvent`
(`features/messages/lib/formatTimelineMessages.ts:52-66`), and `MessageRow.renderBody`'s `default:`
arm already content-sniffs (`parseWaveMessageContent` at `MessageRow.tsx:415`) `[V]`. The seven
`ambush:*:v1` markers cost **zero** of the four. An eighth marker costs one union member, one
decoder-plus-presenter file and one registry line, with `tsc` failing until the entry exists.

**What the fork does cost, on the client:** all four points, plus the parity test.
`formatTimelineMessages.test.mjs:663-676` (a `node:test` in `pnpm test`, therefore in
`just desktop-test` and in the pre-push fast lane) asserts in **both directions** that every
`CHANNEL_TIMELINE_CONTENT_KINDS` entry satisfies `isTimelineContentEvent` and every
`CHANNEL_AUX_EVENT_KINDS` entry does not `[V]`. You cannot add to one set without the other. And
`shouldPageReconnectReplay` requires every `CHANNEL_EVENT_KINDS` member (§5.3), so adding 46010 to
that constant *widens the eligibility test for every existing subscription* — which is exactly why
`perchCaseLiveKinds()` spreads the constant instead of listing kinds.

---

## 7. The Tauri command surface delta

### 7.1 The measured surface

| Fact | Value | Method `[V]` |
|---|---:|---|
| `invokeTauri` call-shaped occurrences | **270** (269 excl. the definition) | `grep -rn 'invokeTauri[<(]' desktop/src --include='*.ts' --include='*.tsx'` |
| distinct literals via `invokeTauri` | **206** | `grep -rhoE 'invokeTauri(<[^(]*>)?\(\s*"[^"]+"'` then dedupe |
| files containing a call | **57** | `grep -rln` |
| distinct literals via raw `invoke` | **56** (2 are `plugin:*`) | same regex on `(?<!\w)invoke` |
| **union, deduplicated** | **256** | `cat … \| sort -u \| wc -l` |
| `#[tauri::command]` definitions | **348** under `src-tauri/src` | `grep -rn '#\[tauri::command\]'` |
| `generate_handler!` entries | **336** at `lib.rs:519-863` | count of indented identifiers |

The gap between 348 definitions and 256 called literals is real: some commands are reached only from
Rust-side plumbing or are dead. Perch does not need to resolve it — deleting a subsystem deletes both
halves.

### 7.2 Deleted, by subsystem

Counted as `#[tauri::command]` definitions, with the second column the subset actually reached from
TypeScript through `invokeTauri` `[V]`:

| Subsystem | Defs | Called | `00-BRIEF.md` §5.4 verdict |
|---|---:|---:|---|
| `huddle/` | 37 | 6 | delete — "surgery, not deletion. Budget it." |
| `commands/agent*` + `managed_agents/` | 38 | 25 | delete the process-management half; keep roster, badge, 15 activity render classes |
| `archive/` + `identity_archive` + `observer_archive` | 23 | 16 | keep — the encrypted-backup test-restore step is explicitly retained |
| `commands/project*` | 24 | 11 | delete (NIP-34 git forge, 279 files) |
| `commands/personas*` | 18 | 15 | delete (persona catalogs) |
| `commands/media*` + `link_preview` + `qr_download` | 15 | 12 | keep media; **delete `link_preview`** (remote fetch is egress from an analyst workstation) |
| `commands/workflows.rs` | 11 | 9 | delete as an approval producer; `WorkflowRunTrace` survives as presentation |
| `commands/teams*` + `team_snapshot` | 11 | 6 | delete |
| `terminal_runtime.rs` | 9 | 0 | **keep verbatim** — reached by raw `invoke`, which is why the `invokeTauri` count shows zero |
| `commands/social.rs` | 8 | 6 | delete (pulse-as-social) |
| `commands/mesh_llm*` | 6 | 6 | delete (git-URL dependency, license unverified) |

That last row of the terminal is the reason §7.1 insists on the 256 union: a survey that counted only
`invokeTauri` would have concluded `features/terminal` has no Rust surface and deleted nine commands
`00-BRIEF.md` §5.1 takes verbatim.

Everything not listed survives: identity (22), channels (17), messages (11), profile (8),
relay_members (6), canvas (2), dms (2), notifications, clipboard, window chrome, updater, pairing,
prevent_sleep, os_idle, deep_link, native_websocket, tray_menu, and the channel-window /
reconnect-repair pair the case timeline depends on.

### 7.3 New: thirteen commands — 7 reads, 5 daemon writes, 1 relay write

`skeleton/desktop/src/shared/api/tauriPerch.ts`,
`skeleton/desktop/src-tauri/src/commands/perch_writes.rs`, and
`skeleton/desktop/src-tauri/src/commands/perch_verdict.rs`.

**The first draft of this section was wrong twice, and the second way was blocking.** It said
"eleven new Tauri commands: 7 reads + 5 writes" — which is not eleven — and it omitted
`perch_record_verdict` entirely while three other files referred to it as though it existed. Since
`perch_sign_gate` (INV-29) refuses every `ambush:<slug>:v<n>` marker through the generic
`sign_event` command, and no other command was declared, **the console as specified could not
publish leg 1 at all**: a two-legged write with one leg. Corrected here, in `tauriPerch.ts`, and by
the new `perch_verdict.rs`.

| Group | Count | File | Closed by |
|---|:-:|---|---|
| reads (GET) | 7 | `commands/perch_reads.rs` | nothing — INV-01 gates non-GET only |
| **daemon** writes (non-GET) | 5 | `commands/perch_writes.rs` | INV-01, `PERCH_WRITE_ROUTES` |
| **relay** write (leg 1) | 1 | `commands/perch_verdict.rs` | INV-RF1, `PERCH_RELAY_PUBLISHED_*` |
| **total** | **13** | | |

**Reads (7):** `perch_list_holds`, `perch_get_hold`, `perch_list_containments`,
`perch_reviewed_findings`, `perch_deposits`, `perch_operator_status`, `perch_verify_artifact`.

**Daemon writes (5), and the set is closed by INV-01:** `perch_decide_hold` (B2),
`perch_finding_feedback` (B3), `perch_mint_incident` (B3i), `perch_release_containment`,
`perch_create_review_session`.

**Relay write (1), closed by INV-RF1:** `perch_record_verdict`.

**Two closed sets, two files, no arithmetic — and that is the point.** `PERCH_WRITE_ROUTES` in
`perch_writes.rs` is `[&str; 5]` and `tools/check-perch-write-allowlist.sh` reads exactly five
daemon routes out of that file. `PERCH_RELAY_PUBLISHED_KINDS` / `PERCH_RELAY_PUBLISHED_MARKERS` in
`perch_verdict.rs` are `[9]` and `["swarm:verdict:v1"]`, and INV-RF1's relay allowlist reads those.
Merging them would make INV-01's "exactly five non-GET requests to an Ambush host" read six and be
wrong; keeping them apart is also the file-level expression of the process boundary. `10-RELAY-FORK.md`
INV-RF1 already says "the operator's own key publishes exactly one: `kind:9` / `swarm:verdict:v1`,
only via `perch_record_verdict`" — this is the file that makes that sentence true.

**DECIDED — no generic passthrough.** There is deliberately no
`perch_daemon_request(method, path, body)`. One command per route, and **the route string is a Rust
`const`, never a parameter**. Two invariants need this and neither can get it any other way:

- INV-01 requires the set of non-GET requests the console issues to an Ambush host to be
  *enumerable* and to equal exactly five. With a generic command the path is renderer-controlled and
  there is nothing to enumerate.
- INV-22 requires the daemon bearer token never to appear in any value crossing IPC into the webview.
  A generic command's natural return type is the raw response, and a raw response is one header away
  from carrying it. Every command returns a typed struct built field by field.

#### 7.3.1 `perch_record_verdict` — leg 1, and where the operator's key lives

The command signs and publishes the `swarm:verdict:v1` card and returns exactly three values.
What the Rust side does, in order, in the Tauri process:

1. Validate `hold_id` against the pinned `hold_<uuidv4>` form
   (`openapi/perch-operator-v1.yaml` `HoldId`, 41 chars) and refuse locally. A malformed id costs no
   round trip.
2. **GET the hold from the daemon by id** and refuse unless it is decidable. The card's ACTION
   sentence, severity, case channel and blast radius are built from *that* answer. The renderer
   supplies only the decision, the rationale and the arming timestamp — the three things a human
   actually produced. This is what `PERCH_SIGN_REFUSAL`'s own words ("builds the card from
   daemon-fetched hold state") were promising, and it is why a compromised webview cannot forge a
   card body even though it can ask for a card.
3. Stamp `decided_at_ms` from this process's clock.
4. Sign the **RFC 8785 canonical JSON of `{decided_at_ms, decision, hold_id, rationale_sha256}`** —
   four members, key-sorted — with the operator's **Ed25519** key. Byte-identical to what the decide
   route verifies, so **one signature serves both legs** and there is no window in which the card and
   the decision record can disagree.
5. Build the body in `13-WIRE-SCHEMAS.md`'s grammar (marker alone on line 0, human line, blank line,
   fenced JSON), sign the `kind:9` event with the **Nostr secp256k1** identity, and publish it into
   the case channel with an `h` tag and **no `e` tag** (RF-D1 — an e-tagged card becomes a NIP-10
   reply, mutating `reply_count`/`descendant_count` and emitting a relay-signed `kind:39005`).
6. Return `{nostr_intent_event_id, decided_at_ms, signature}` and nothing else.

**It does not call the decide route.** Leg 2 is a separate command in a separate file invoked
separately by the renderer, so "Perch never authorizes" is a property of the process graph rather
than of a code comment. A successful return means an intent record exists and the world has not
changed — the `recorded` phase of §4.4's write machine, which must never render as a completed
action.

**Two chains, never conflated** (ADR 0016). The Nostr secp256k1 key
(`state.signing_keys()`, `app_state.rs:278-291`, which refuses while `identity_lost` or
`keyring_locked` is set `[V]`) signs the **event** and says who published. The Ambush operator
Ed25519 key signs the **preimage** and says who decided. Every verification surface must name which
chain it checked.

**Where the Ed25519 secret lives, and what never crosses IPC.** A sibling entry in the same OS
keyring Buzz already uses: `SecretStore::shared(keyring_service())` (`app_state.rs:435`; service
`"buzz-desktop"`, `"buzz-desktop-dev"` in debug, `app_state_keyring.rs:9-17`), through
`store(key, value)` / `load(key)` (`secret_store.rs:729-741`, `:549`) `[V]`. C11's two verified
consequences: `store` mutates the service's single keyring blob (`:731-734`) and
`delete_all_with_legacy_cleanup` (`:756-800`, the sign-out path, called from `reset.rs:124`)
enumerates that blob's key names at wipe time rather than consulting a fixed allowlist — so Buzz's
existing sign-out destroys the Perch secret with **zero new code and no allowlist to forget**. No
command in any of the three Perch Rust files returns the secret or a type that could carry it.
`public_key_hex` does cross IPC, because the decide route derives `voter_id` from it; it is public
by construction.

**Provisioning is not designed here** — who mints the keypair, how `public_key_hex` reaches
`OperatorPrincipalConfig`, and what a second workstation does belong to `12-BACKEND-BILL-API.md` and
task B0. This document states only that the secret lives in that store and never crosses IPC.

**A second signing path exists and must also be gated.** `send_channel_message`
(`BUZZ desktop/src-tauri/src/commands/messages.rs:409-...`, Tauri Rust process) takes an arbitrary
`content: String` and an optional `kind: Option<u32>`, snapshots `state.signing_keys()` at `:447`,
and publishes `[V]`. Gating only `sign_event` leaves a renderer able to sign a `kind:9`
`ambush:*:v1` body through that command instead. `perch_sign_gate(kind_num, &content)` must be
called there too, right after `kind_num` is resolved at `:452`. Handed to `16-INVARIANT-TESTS.md` as
an INV-29 completeness finding; recorded here because this file is the sanctioned path and its value
depends on the unsanctioned ones being closed.

#### 7.3.2 `perch_decide_hold`'s input shape, corrected against the wire contract

The first draft declared `DecideHoldInput { hold_id, decision, rationale, nostr_intent_event_id,
signature: String }`. Every request built from it would have failed, in three separate ways:

| Field | What the contract says | What the first draft did |
|---|---|---|
| `decided_at_ms` | in `required`, and **inside the signature preimage** | absent — the daemon cannot recompute a signed member, so verification is impossible |
| `signature` | `$ref: DetachedSignature` — an object carrying `algorithm`, `key_id`, `public_key_hex`, `signature_hex` | a bare `String`, so the route has no `public_key_hex` from which to derive `voter_id` and run its 403 binding check |
| `armed_at_ms` | optional, advisory, **outside** the preimage | absent |

The corrected struct carries all of them, and `rationale` is `Option<String>` because its SHA-256 is
inside the preimage — which is the whole reason it is a parameter of `perch_record_verdict` and not
something the renderer can substitute afterwards. All four of `decidedAtMs`, `signature`,
`nostrIntentEventId` and `rationale` are passed through **verbatim** from `perchRecordVerdict`; the
renderer computes none of them and cannot.

`hold_id` stays on the struct and is a **path parameter**, not a body member: the body schema is
`additionalProperties: false`, so the request builder must not serialise it. Asserted in
`perch_writes.rs`'s tests, along with a field-set check against `HoldDecisionRequest`'s `required`
list — because two hand-written descriptions of one wire object in two languages with no compiler
link is exactly what produced the defect.

**Two typed-outcome rules that are architecture, not API design.** `perch_decide_hold` returns
`RefusedLate` and `RefusedLateGovernance` inside `Ok`, never `Err` — a late policy refusal is the
system working, and rendering it as a client error teaches operators that refusals are bugs
(INV-28). `perch_release_containment` returns the daemon's body verbatim and must not collapse
`lease_closed: false` on a 200 into an `Err` — the handler deliberately reports it that way
(`AMB crates/swarm-runtime-http/src/http/containment.rs:191-247`, daemon process; `lease_closed` is
computed by re-listing at `:219-226`) so a caller cannot read success into an unfinished release, and
a client that discards the distinction throws away the safety property.

### 7.4 Where a new command registers, and the one step that breaks everything if skipped

Measured cost, in order `[V]`:

1. a new `desktop/src-tauri/src/commands/<name>.rs`;
2. `mod <name>;` in `commands/mod.rs` (mod block `:1-73`) and `pub use <name>::*;` (`:74-127`),
   re-exported into `lib.rs` by `use commands::*;` at `lib.rs:59`;
3. one entry each in the flat `tauri::generate_handler![]` argument at `lib.rs:519-863` — 336 entries
   today; `lib.rs` is **938 gate-lines** against a 1000 cap in the governed `src-tauri/src` root, so
   **62 lines of slack** absorb Perch's thirteen (13 entries plus a blank line leaves 48 to spare);
4. **no** capabilities entry — `desktop/src-tauri/capabilities/default.json` lists only core and
   plugin permissions, none per command;
5. a TypeScript wrapper in a **new** `shared/api/` file — `tauri.ts` is 1108 gate-lines and frozen;
6. **a case in the E2E mock bridge.**

Step 6 is the one that looks optional and is not. `desktop/src/testing/e2eBridge.ts` is 14,620 lines
behind one `switch (command)` whose `default:` throws
`` `Unsupported mocked Tauri command: ${command}` `` at `:14594`, installed as the Tauri IPC via
`mockIPC` at `:14601` and **also** exposed on `window.__BUZZ_E2E_INVOKE_MOCK_COMMAND__` at `:14597`
`[V]`. A new command called during mount breaks **every** mock-mode Playwright spec with a
"Community connection failed" render that is indistinguishable from a product bug — the exact symptom
`BUZZ CLAUDE.md` warns about for a wrong build.

#### 7.4.1 One seam, one module path, one fixture corpus

Three wave-2 artifacts specified three ways to do this, and the review was right that the five
Playwright specs could not then be driven from the demo scenario. `22-DEMO-FIXTURE.md` seeds through
five existing `window` seams and edits nothing; `16-INVARIANT-TESTS.md` wants four new
`__BUZZ_E2E_PERCH*` seams and a delegation into `src/testing/perch/e2ePerchBridge.ts`; this document
proposed the prefix guard with fixtures in `desktop/src/testing/perchBridgeFixtures.ts`. The task
brief puts the arbitration here, so here it is.

**DECIDED, and each clause takes a peer's answer where the peer's was better:**

1. **The seam is this document's prefix guard.** One `if` immediately before `default:`:

   ```ts
   if (command.startsWith("perch_")) {
     return handlePerchMockCommand(command, args);
   }
   ```

   Three lines in the upstream file, which respects `00-BRIEF.md` §5.1's "do not split it" while
   keeping the 14,620-line switch from growing by thirteen. **Verified this session (C9):** no other
   arm in that switch matches on a command prefix — all twelve `startsWith(` calls in the file test a
   storage key, a URL, a subscription id or a filename — so the guard has no ordering constraint
   against an existing arm and must simply precede `default:`. The first draft listed that as
   unverified; it is now measured. And because `handleMockCommand` is the same closure behind both
   `mockIPC` and `window.__BUZZ_E2E_INVOKE_MOCK_COMMAND__`, one guard covers both seams.

2. **The module path is `16`'s**, not this document's: `desktop/src/testing/perch/e2ePerchBridge.ts`.
   A directory, not a single fixtures file, because it also has to hold the fixture loader and the
   frozen clock. `desktop/src/testing/perchBridgeFixtures.ts` is withdrawn. `src/testing` is
   ungoverned by the size gate (`desktop/scripts/check-file-sizes.mjs:10-55`) `[V]`, so the module may
   be as large as the fixtures need.

3. **The four extra `window` seams are installed by that module, not by `e2eBridge.ts`.**
   `__BUZZ_E2E_EMIT_PERCH_EPHEMERAL__`, `__BUZZ_E2E_PERCH_ADVANCE__`, `__BUZZ_E2E_PERCH_COUNTER__`
   and `__BUZZ_E2E_PERCH_EXPORT_MANIFEST__` are assigned at module import time. This is the clause
   that dissolves the apparent conflict: `16`'s helper needs those seams to exist, not to be added to
   the upstream file, and nothing in `16/skeleton/tests/playwright/helpers/perchBridge.ts` requires
   otherwise. `__BUZZ_E2E_PERCH__` is set by `installPerchBridge` through `page.addInitScript` and
   touches no repo file at all. `__BUZZ_E2E_PERCH_QUEUE_RECONCILED__` is set by the **app**, not the
   bridge — it is the queue reconciler's own readiness flag (§5.6 step 4) and belongs beside the
   divergence counter.

4. **One fixture corpus: `build/fixtures/perch-demo-fixture.json`.** It is the only machine-validated
   one, and `fixtures/derive-ids.mjs` regenerates every id from a public label, so it is the only one
   that can be regenerated rather than transcribed. It is vendored to
   `desktop/src/testing/perch/perchDemoFixture.json` and imported by the delegated module.
   `perchBridgeFixtures.ts` and its contents are withdrawn; this document's earlier fixture module is
   the second corpus the review objected to and it should not exist.

5. **`22`'s five-seam seeding path is unchanged and is not in competition with any of this.** It
   seeds *Buzz* state — channels, messages, feed items — through
   `__BUZZ_E2E_INVOKE_MOCK_COMMAND__`, `__BUZZ_E2E_EMIT_MOCK_MESSAGE__`,
   `__BUZZ_E2E_PUSH_MOCK_FEED_ITEM__`, `__BUZZ_E2E_HAS_MOCK_LIVE_SUBSCRIPTION__` and
   `__BUZZ_E2E_INVALIDATE_CHANNELS__`. The delegated module answers *Perch daemon* commands. Those
   are two halves of one scenario, not two designs for one half, and `22`'s "the mock-bridge seed
   edits nothing" survives intact — the one three-line edit belongs to the command guard, which `22`
   never needed.

The net upstream change is therefore **three lines**, and there is one fixture corpus, one module
path and one seam design across all three artifacts. `16` changes its fixture import;
`22` changes nothing.

#### 7.4.2 The mock module answers all thirteen, and asserts that it does

`tauriPerch.ts` exports `PERCH_TAURI_COMMANDS` — the concatenation of the three closed sets. The
delegated module asserts at import time that it has a handler for every member, so a fourteenth
command cannot be added without the mock following it in the same change. That is the same mechanism
as the `satisfies Record<>` tables elsewhere in this document, applied to the one boundary where a
missing entry does not fail to compile but does fail every spec at once with a misleading symptom.

### 7.5 What still needs a raw `invoke`, and what does not

Perch needs **no** new Tauri command for relay work. The Nostr protocol framing is entirely
TypeScript: `sendRaw` (`relayClientSession.ts:652-664`) serializes the frame and hands it to the
native socket via `invoke("plugin:websocket|send", …)` `[V]`. New kinds, new REQs and new EVENT
publishes are pure TS.

The commands above exist for exactly one reason: **leg 2 of the two-legged write must not be
reachable from the renderer's network stack.** That is the process boundary the brief demands, and it
is what turns "Perch never authorizes" from a convention into a property. A renderer that is fully
compromised can *ask* for an `swarm:verdict:v1` card — and even then it supplies only the decision,
the rationale and the arming timestamp, because `perch_record_verdict` builds the body from the
daemon's own hold record (§7.3.1) — and it still cannot reach the daemon except through five named
commands whose routes are compiled in.

### 7.6 Two consoles, one hold

Nothing in the wave-2 set handled this, and it is reachable in the shipped default plus one added
principal.

**The premise, verified.** `APPENDIX-NORMATIVE.md` §4 layer 1 `p`-tags **every** operator principal
holding `OperatorScope::Approve`, and §13's declined amendment leaves the watch claim explicitly
unable to narrow that set (layer 4: "It does **not** change the `p` tag"). So more than one console
can legitimately hold the same open hold, and both operators can press Enter.

**What then happens, from three artifacts I checked rather than assumed.** Leg 1 is published before
leg 2 — it must be, because the leg-1 card's event id *is* leg 2's idempotency key. The relay has no
compare-and-set and a `kind:9` is immutable, so **both** signed verdict cards land in the case
channel and stay there. The daemon's store does have a compare-and-set (`12-BACKEND-BILL-API.md` §4.4
D2/D3: the CAS into `deciding` happens before any policy evaluation), so exactly one wins and the
other gets a 409: `hold_already_deciding` when the winner is still in flight, `hold_already_decided`
when it is terminal.

The failure this creates is not in the daemon. It is that the case channel now contains two signed,
real, human-authored decision records for one action, with nothing marking which one executed — and
the Ledger export's `holds/` directory would carry both.

**DECIDED — the authority is the daemon's decision record, not any card.**

> A verdict card renders as **the decision** if and only if the daemon's `HoldDecisionRecord` for
> that `hold_id` names that card's event id in `nostr_intent_event_id`. Every other verdict card on
> the same hold renders as **not the decision — another operator's verdict executed**, with a link
> to the one that did.

This rule is what makes the state correct with **zero extra events**, and that property is the whole
reason it is written this way round. The obvious design — have the losing console publish an update
card — cannot be the authority, because the losing console is exactly the thing that may have
crashed, lost the network, or been closed. A render rule that depends on the loser being alive fails
in the case it exists for.

**DECIDED — the losing console publishes the update card anyway, as an optimisation.** On a 409
naming a different `nostr_intent_event_id`, `perch_decide_hold` returns
`outcome: "superseded", superseded_by: <winner's id>` inside `Ok` (it is not an error; it is the
system working), and the console publishes a second `swarm:verdict:v1` as a NIP-10 reply to its own
leg-1 card with `leg2.state: "superseded"` and the winner's id. It does **not** retry, does **not**
re-sign, and does **not** render its own row as recorded. The card makes the state legible to a
reader who has only the relay — a Ledger export read months later, a case channel opened by someone
without daemon access — which is worth publishing but is never what the console itself believes.

**And when the daemon is unreachable:** two verdict cards on one hold and no authority to consult.
Both render as **unresolved**, each naming the other. Never pick one. That is the third state and it
is the one a console with no daemon is actually in.

**PROPOSED AMENDMENT to `13-WIRE-SCHEMAS.md`** — `card-swarm-verdict-v1.schema.json`'s `leg2.state`
enum is `sending | recorded | acknowledged | refused_late`; none of those means "another operator's
decision was the one that executed". Add `superseded`, and a `superseded_by` field constrained to 64
lowercase hex. `13` owns the schema; I do not edit it. **The render rule above holds whether or not
the amendment lands**, because it reads the daemon, and that is deliberate: a decision that depends
on a peer ratifying a schema change is a decision that is not made.

**Handed to `16-INVARIANT-TESTS.md`:** a P0 two-console E2E, in INV-12/INV-35's neighbourhood. Two
mock consoles, one hold, both arm and record; assert exactly one `HoldDecisionRecord`, two verdict
cards on the relay, exactly one rendering as the decision on **both** consoles, and — the arm that
actually matters — the same outcome when the losing console never publishes its update card.

---

## 8. `resetColonyState` — the colony-scoped singleton inventory

`skeleton/desktop/src/features/perch/colonyScopedRegistry.ts` is the file.

### 8.1 What exists today, exactly

`resetCommunityState` is one function at
`BUZZ desktop/src/features/communities/useCommunityInit.ts:54-84`, body `:59-83`, **21 calls** read
line by line this session `[V]`. Three sit behind two conditionals (`clearTrayAgentActivity` behind
`isTauri() && isMacPlatform()` at `:66`; `resetAvatarProfileSync` and `resetAvatarPresentations`
behind the `resetAvatarState` argument at `:69`). Exactly one is awaited
(`resetNavigationDeepLinkDrain`). It runs in the renderer from a single `useEffect` — at `:149` when
leaving a community and `:260-266` when switching — is skipped on first mount
(`hasInitializedRef`, `:143`/`:249`/`:283`), and a throw renders an explicit error state rather than
proceeding.

The doc comment at `:47-53` states the contract and one deliberate limit: hook-managed singletons
(`ChannelMuteSyncManager`, `ChannelSectionSyncManager`) are destroyed by effect cleanup and need no
entry.

The partner is the remount boundary: `App.tsx:407` builds
`` communityKey = `${activeCommunity?.id ?? "none"}-${reinitKey}-${currentPubkey ?? "anonymous"}-${signerEpoch}` ``,
applied as `key=` on the query provider at `:630` and on `AppReady` at `:640` `[V]`.

### 8.2 The twelve that survive, the nine that go with their subsystem

| Buzz resetter | Line | Perch |
|---|---:|---|
| `relayClient.disconnect()` | 59 | keep → `relayClient` |
| `resetNavigationDeepLinkDrain()` | 60 | keep → `deepLinkDrain` (still the only `await`) |
| `resetRateLimitGate()` | 61 | keep → `rateLimitGate` |
| `clearAllDrafts()` | 62 | keep → `drafts` |
| `resetAgentObserverStore()` | 63 | **delete** — ACP subprocess harness goes |
| `resetActiveAgentTurnsStore()` | 64 | **delete** — same |
| `resetAgentWorkingSignal()` | 65 | **delete** — same |
| `clearTrayAgentActivity()` | 67 | keep → `trayActivity`, guard moved inside |
| `resetAvatarProfileSync()` | 70 | **delete** — animated avatars go |
| `resetAvatarPresentations()` | 71 | **delete** — same |
| `resetSidebarRelayConnectionCardState()` | 73 | keep → `sidebarRelayConnectionCard` |
| `resetMediaCaches()` | 74 | keep → `mediaCaches` |
| `resetLinkPreviewMetadataCache()` | 75 | **delete** — remote link-preview fetching goes |
| `resetVideoPlayerState()` | 76 | **delete** — video review goes with huddle |
| `resetRenderScopedReactionHydration()` | 77 | keep → `renderScopedReactions` |
| `resetBackgroundMediaUploads()` | 78 | keep → `backgroundMediaUploads` |
| `resetLinkPreviewPreparations()` | 79 | **delete** — same as `:75` |
| `resetPersistentAgentAudienceStore()` | 80 | **delete** — persistent agent audience goes |
| `clearSearchHitEventCache()` | 81 | keep → `searchHitEventCache` |
| `clearMarkdownNodeCache()` | 82 | keep → `markdownNodeCache` |
| `resetMessageLinkMetadataCache()` | 83 | keep → `messageLinkMetadataCache` |

Twelve survive, nine go with their subsystem. **The registry is also the delete checklist**: deleting
a subsystem without deleting its registry entry is a compile error, so the two changes cannot drift.

### 8.3 The fifteen Perch adds

`perchSubscriptions` · `perchSeqTracking` · `perchEphemeralStore` · `holdListMirror` ·
`reviewStateMirror` · `containmentClock` · `depositSuppressionCache` · `admittedIssuerSet` ·
`verdictDraftStore` · `verdictSpool` · `snoozeTicker` · `keymapArmingState` ·
`escapeSurfaceLease` · `reconcileDivergenceCounter` · `derivedMarkerLedger`.

Twenty-seven members total. Four deserve a sentence because they are the ones a reader would not
predict:

- **`admittedIssuerSet`** — the set three consumers gate on (§6). A leaked set from colony A would
  make colony B's bridge look unadmitted *and* colony A's forged frames look admitted. This is the
  member where a miss is not a stale cache but a security failure, and it is the reason the union is
  typed.
- **`escapeSurfaceLease`** — `shared/hooks/escapeSurfaces.ts` is a module-level integer incremented by
  `acquireEscapeSurface()` and decremented by an idempotent release (`:14-33`) `[V]`. It is
  intentionally *not* community-scoped, and Perch does not make it so. What is registered is the
  release of **Perch's own** acquire: a queue surface that holds one for its lifetime satisfies
  `APPENDIX-NORMATIVE.md` §2's "Escape never marks read" without editing
  `useMarkAsReadShortcuts.ts` at all — but a leaked acquire disables Escape-to-mark-read permanently,
  across colonies, for the rest of the session.
- **`keymapArmingState`** — `G` arms a grant and `D` arms a dismiss; both are module-level because they
  must survive a row re-render and must reset on `hold_id` change (INV-11). A grant armed in colony
  A and still armed in colony B is the worst bug in this document.
- **`verdictSpool`** — leg 1 succeeded and leg 2 has not; the console republishes from this on
  reconnect. Colony-scoped by definition, and a cross-colony leak would republish one colony's intent
  card into another's case channel, where the relay's `h`-tag check would reject it — visibly, which
  is the only good news in the sentence.

### 8.4 The mechanism, and the two tests

`COLONY_RESETTERS: Record<ColonyScopedSingleton, Resetter>` is the whole mechanism. Adding a union
member without a resetter is a `tsc` error; an extra key is a `tsc` error. No lint rule, no review
checklist. That is INV-23's first half.

INV-23's second half is a test asserting that every module under `features/**` exporting a `reset*`
function appears in `COLONY_RESETTERS`. The type catches "declared but not wired"; the test catches
"written but not declared". Both are needed and neither substitutes.

**The test must not overclaim.** Buzz's doc comment records that hook-managed singletons are
deliberately out of scope, and the registry covers module-level singletons only. Anything
colony-scoped living in a hook is fenced by the `key={colonyKey}` remount and by nothing else, and a
test that implied otherwise would be worse than no test.

Two implementation details in the file that are decisions, not style:

- **The `isTauri() && isMacPlatform()` guard moves inside the resetter.** The registry has no
  conditional entries, because a conditional entry is an entry a reader can talk themselves out of.
- **`resetColonyState` awaits sequentially, not `Promise.all`.** `relayClient.disconnect()` must land
  before the subscription manager tears its REQs down, or CLOSE frames race a dead socket and produce
  log noise that reads as a bug.

---

## 9. `React.memo` and referential stability on the high-rate lists

`BUZZ CLAUDE.md` gotcha 6 is the governing text: `React.memo` skips a re-render only when **every**
prop is reference-stable, and one unstable prop — an inline arrow, a hook returning a fresh
`{}`/`[]`/`Map` — defeats it. Two named repeat offenders: React Query result objects are a new
identity every render (depend on `mutation.mutateAsync`, not the object), and derived `Map`/array
state needs a content-equality ref cache. The cache exists:
`shared/hooks/useStableReference.ts` exports `useStableMap` (`:9-17`), `useStableArrayShallow`
(`:33-43`) and `useStableSet` (`:62-70`) `[V]`.

`MessageRow` is the exhibit. It is `React.memo(fn, comparator)` with a hand-written comparator at
`MessageRow.tsx:935-995`; `17` §1.5 measured **46** `&&`-joined clauses over 46 distinct prop paths
(16 `message.*`, 30 row props) — correcting the ground pass's 60 `[V]`. Any new prop drilled in for
Perch must be added there **or the row silently stops updating**, and any unstable prop defeats the
memo for every row in an open case on every streamed event.

Six offenders on Perch's hot path, four inherited from `07` §9 and two found here:

| Offender | Fix | Why it matters here |
|---|---|---|
| `Map<threatClass, Concentration>` rebuilt from each 1 Hz snapshot | content-equality merge **at write time**, inside `perchEphemeralStore` | Eleven of twelve classes are usually unchanged; the store returns the *same Map instance* on a quiet tick, so the whole lane list bails. Doing it at write time rather than in a `useMemo` means a non-React reader gets the property too. |
| `Map<agentId, AgentFrame>` from the telemetry frames | same store, same merge | Eight roles × N instances on a wall screen that runs for years. |
| `useMutation` result threaded into the verdict row | pass `mutateAsync` and a `status` string, never the mutation object | Gotcha 6's own example. `usePerchWrite` (§4.4) returns a narrow union precisely so there is no object to pass. |
| containment `remaining_ms` recomputed per second per row | **one** `useContainmentClock()` tick at the board level publishing a single `nowMillis`; each row derives from a scalar prop | Per-row intervals produce N timers and N re-renders per second, and `05`/`08` require `remaining_ms` and `expired` as two separate elements, which doubles the DOM churn if it is per-row. |
| `isAdmittedIssuer` drilled as a prop into `MessageBody` | context + `useStableSet`, mounted at `AppShellProvider` (§6) | A prop would need a 47th comparator clause *and* would be a fresh closure each render, defeating the memo on every evidence card at once. |
| The `PerchSubscriptionSpec[]` array rebuilt each render | `syncPerchSubscriptions` compares a **stable serialization**, and `since` is excluded from it | Not a memo problem — a network problem. Including `since` would CLOSE and re-REQ every live subscription on every render that touches the manager. Called out in the source because it is silent, expensive, and passes every test. |

**The measurement discipline is Buzz's, verbatim:** measure with DevTools **closed** and no
per-keystroke logging (an open Web Inspector plus a `console.log` per keystroke inflates the numbers),
and isolate by removing one suspect at a time rather than guessing.

---

## 10. Virtualization

Buzz ships both, and C1 established which is where. The choice is therefore not "pick one" — it is
"do not move a surface across the boundary that already exists".

**DECIDED:**

| Perch surface | Library | Reason |
|---|---|---|
| The Watch queues (all four) | `VirtualizedList` (`@tanstack/react-virtual`) | The inbox is already on it — `InboxListPane.tsx:706` with `estimateSize={96}` `[V]`. Rows are pure functions of an inbox item and tolerate unmount/remount, which is exactly `VirtualizedList`'s stated migration contract (`VirtualizedList.tsx:12-17`). |
| Ledger results | `VirtualizedList` | Same shape as the queue. |
| Case timeline | **`virtua`'s `VList`** | Not a preference. `TimelineMessageList.tsx:747` passes `shift={isPrepend}` `[V]` — virtua's anchor-preserving prepend, which keeps scroll position stable when older pages load above the viewport. `@tanstack/react-virtual` has no equivalent in `VirtualizedList`, and three sibling hooks (`useVirtualizedBottomSettle`, `useTimelineRetention`, `timelineRetention`) type against `VListHandle`. Porting the case timeline to `VirtualizedList` means reimplementing prepend anchoring, bottom-settle and retention — for a surface Perch is otherwise taking whole. |
| Containments board | plain list | A colony with more than ~200 open containments is an incident, not a scrolling problem. |
| Policy rules, Tuning cards | `content-visibility-auto-row` | Both are `<details>`-shaped and expand in place, which is precisely the case `VirtualizedList`'s contract sends elsewhere: "surfaces with in-DOM row state (open `<details>`, drag-and-drop) should use `content-visibility` instead" (`VirtualizedList.tsx:13-15`) `[V]`. The utility exists at `shared/styles/globals/utilities.css:35`. |
| Watchfloor SVG | neither | Hand-authored, 1 Hz, `18-DATAVIZ.md` owns it. |

**The correction stands as a commitment:** `07` §9's table says the case timeline uses
`VirtualizedList` "inherited from `MessageTimeline`". It is inherited from `MessageTimeline`, and
`MessageTimeline` is on virtua. A producer who follows `07` §9 literally rewrites the timeline for no
reason and loses prepend anchoring in the process.

Perch introduces **no third virtualizer** and removes neither. `virtua` is pinned exactly (`0.49.3`)
and `@tanstack/react-virtual` is a caret range — keep it that way; the timeline's scroll behaviour is
the most fragile thing in the client and a minor virtua bump is the kind of change that should be a
deliberate PR.

---

## 11. Error boundaries and what a crashed surface does

C2 established the state of play: one boundary, outside every provider, whose fallback replaces the
window with "Buzz failed to start".

For a chat app that is a reasonable posture. For Perch it is not. A throw inside the Watchfloor's
hand-authored SVG would take down the verdict queue on the same screen, and the operator would see a
generic startup splash while a destructive action sat un-decided behind it.

**DECIDED — three tiers.**

1. **`RootErrorBoundary` stays exactly as it is.** It catches the class of failure it was written for
   (a WebKit `SecurityError` from `localStorage` under a denied-storage origin, block/buzz#5078) and
   Perch has no reason to touch it.
2. **One `PerchSurfaceBoundary` per outlet route**, mounted inside each `routes/*.tsx` around the
   lazy screen, inside the `Suspense`. `resetKey` is the route's own parameter (`caseId`, `laneId`)
   or the route path, so navigating away and back clears the error.
3. **Three interior boundaries** where a crash must not take a sibling down: the **verdict pane**
   (`resetKey = hold_id`), each **evidence card** in a case timeline (`resetKey = event id`), and the
   **governance strip** (no reset key — a strip that keeps crashing must keep saying so).

The rule the component exists to enforce, and it is a safety rule rather than a UX one:

> **A crashed surface never renders in a neutral or reassuring register, and never implies that the
> state behind it is settled.**

Concretely, in `PerchSurfaceBoundary.tsx`:

- The fallback is `role="alert"` in the destructive register. It is one of only two assertive regions
  in Perch (`17` §1.7 names the other: an expired, still-listed containment).
- **Its colours are `--perch-*`, and the danger hue is a border only.** Every class in the component
  is `bg-perch-card` / `text-perch-fg` / `text-perch-fg-muted` / `border-perch-danger` /
  `border-perch-border` — never `bg-card`, `text-muted-foreground` or `border-destructive`.
  `ThemeProvider` writes 38 bare Buzz shadcn names **inline** on the root element (`applyTheme`,
  `ThemeProvider.tsx:436-446`, looping `root.style.setProperty` over every var `createThemeVars`
  returns; `applyCachedVars` at `:398-409` does the same pre-paint), and no normal-priority
  stylesheet beats an inline declaration `[V]`. A crash fallback authored against
  `border-destructive` would repaint with whatever Buzz syntax theme is loaded — on the one surface
  whose whole job is to look wrong. `19-TOKENS.md` also marks `--perch-danger-mark` NEVER TEXT
  (3.70:1 on raised in dark), so the hue is a border and the **word** carries the meaning, in
  `--perch-foreground`. No shield, lock or warning glyph appears anywhere in the component.
- **It carries no `data-perch-role`.** `17` §1.4's thirteen values are closed and
  `check-perch-grant-affordance.sh` R1 asserts the closure, so inventing a fourteenth here would fail
  the gate. A crashed surface is not one of the things those greps hunt; the `data-testid` is what
  the specs bind to, and testids may churn where `data-perch-role` may not.
- It **names the surface** and says what is not known. A blank pane and "there is nothing to decide"
  are different facts and an operator cannot tell them apart.
- **A crashed verdict pane leaves its queue row undecided.** The boundary performs no write, cancels
  no in-flight leg, and clears no arming state except by remount. There is no code path from a render
  crash to a recorded decision, and `componentDidCatch` must never be tempted into "cleanup" that
  touches a write.
- The retry control is not primary and its copy says the decision was not recorded, so a successful
  remount cannot be mistaken for a successful write.
- Every catch increments a counter. A crashed surface is a countable event, not an anecdote; the
  count is read by `/settings` and by the strip's diagnostics row.

**What a boundary cannot do, stated so nobody relies on it:** React error boundaries do not catch
errors in event handlers, in `setTimeout`/`requestAnimationFrame` callbacks, in async code, or during
SSR. The verdict path's failure modes are almost all in those categories — a rejected `invokeTauri`,
a relay `CLOSED`, a timed-out publish — and every one of them is handled by the three-state write
machine in §4.4, not by a boundary. The boundary is for render throws only, which in Perch means a
malformed card body reaching a presenter, and that is exactly why `17` §3.4's parse contract returns
a typed refusal instead of throwing.

---

## 12. File-size budget

The gate counts `content.split(/\r?\n/).length` — **`wc -l` plus one** for a newline-terminated file
(`BUZZ scripts/check-file-sizes-core.mjs:24-29`), and `allowedLineCount` (`:31-33`) is
`baseLines <= 1000 ? 1000 : baseLines`, so an over-cap file is **frozen at its current size** and a
new file gets a hard 1000 `[V]`. It is differential against the merge-base (`HEAD^1` under
`GITHUB_ACTIONS`), runs from `just file-size-check` (`justfile:106-110`) into `just check` and
`just ci`, and runs **unfiltered on every pre-push** (`lefthook.yml:90-93`).

Governed roots that matter here: `src/app`, `src/features`, `src/shared/api`, `src/shared/context`,
`src/shared/lib`, `src/shared/ui` (`.ts`/`.tsx`), `src/shared/styles` (`.css`), `src-tauri/src`,
`src-tauri/crates` (`.rs`). **Ungoverned:** `src/shared/constants` (so `kinds.ts` may grow),
`src/testing`, `src/shared/hooks`, `src/shared/theme`, `src/main.tsx`, `desktop/tests/` `[V]`.

### 12.1 Frozen files a Perch patch must not touch

Measured with the gate's own counter this session `[V]`:

| File | Gate-lines | Cap in force | Headroom |
|---|---:|---:|---:|
| `shared/api/tauri.ts` | 1108 | 1108 | **0** |
| `shared/api/relayClientSession.ts` | 1084 | 1084 | **0** |
| `shared/api/types.ts` | **1000** | 1000 | **0** |
| `shared/ui/sidebar.tsx` | 1011 | 1011 | **0** |
| `shared/ui/markdown.tsx` | 1906 | 1906 | **0** |
| `features/messages/ui/MessageRow.tsx` | **999** | 1000 | **1** |
| `app/AppShell.tsx` | **998** | 1000 | **2** |
| `features/home/ui/HomeView.tsx` | 994 | 1000 | 6 |
| `src-tauri/src/lib.rs` | **938** | 1000 | **62** |
| `shared/styles/globals/theme.css` | 968 | 1000 | 32 |

Every Perch Tauri wrapper, subscription helper and shared type therefore lands in a **new** file
under `shared/api/` — forty sibling precedents (C4). `MessageRow.tsx` and `AppShell.tsx` cannot
absorb even a small edit, which makes `15-FILE-SPLIT-PLAN.md` a **prerequisite** for the first client
change rather than a follow-up.

### 12.2 Budget per architecture-owned module

Stated in gate-lines; a module whose spec exceeds ~600 is split at spec time, not at review.

The `Skeleton` column is the measured gate-line count of the file shipped with this document
(`content.split(/\r?\n/).length`, the gate's own counter, run over each file this session).
`Budget` is the ceiling a filled-in implementation must stay under.

| File | Skeleton | Budget | Notes |
|---|---:|---:|---|
| `app/routes.ts` | 50 | 80 | replaces a 19-line file; parses to 14 paths under the delivered gate |
| `app/perchViews.ts` | 169 | 220 | union + derivation + nav registry + the type assertion |
| `app/routes/*.tsx` × 11 | — | 60 each | `createFileRoute` + `validateSearch` + lazy + boundary |
| `shared/api/perchKeys.ts` | 263 | 320 | 20 key factories + 20 freshness rows with prose |
| `shared/api/perchSubscriptions.ts` | **654** | 800 | inventory + the `26006` argument + manager + budget + repair-kind assertion + gap detection |
| `shared/api/perchEphemeralStore.ts` | 291 | 360 | store + admission gate + merge |
| `shared/api/tauriPerch.ts` | 391 | 460 | 13 wrappers + shapes + the three closed sets |
| `features/perch/colonyScopedRegistry.ts` | 176 | 240 | 27-member union + registry + the "what it does not cover" note |
| `features/perch/ui/PerchSurfaceBoundary.tsx` | 175 | 220 | |
| `src-tauri/src/commands/perch_writes.rs` | 402 | 500 | 5 daemon writes + route constants + 3 tests |
| `src-tauri/src/commands/perch_verdict.rs` | 241 | 320 | leg 1 + key-material contract + 3 tests |
| `src-tauri/src/commands/perch_reads.rs` | — | 340 | 7 read commands |
| `scripts/check-route-tree.mjs` | 124 | — | **ungoverned root** (`desktop/scripts` is not in the gate's rule list) |
| `src/testing/perch/e2ePerchBridge.ts` | — | — | **ungoverned root**; may be as large as the fixtures need |

Sum of the shipped skeletons: **2,936** gate-lines across eleven files. Two are above the ~600 line
at which a spec is supposed to split before it is written, and both are deliberate:

- `perchSubscriptions.ts` (654) carries an argument that had to be written *somewhere* — §5.2.1's
  `26006` decision and §5.3's repair analysis are load-bearing at the call site, not in a document a
  producer may not open. Its split line, if it comes, is between the manager (`syncPerchSubscriptions`
  + `buildPerchSubscriptions`) and gap detection (`observeIssuerSeq` + the gap store): they share no
  state and gap detection has no relay dependency at all, so the split is a pure file move.
- `perch_writes.rs` (402) is under its own budget and grew only by the corrected `DecideHoldInput`
  and its drift test.

Every file is comfortably inside the 1000 cap and every one has room for a filled-in implementation
to exceed its skeleton.

**Net line delta to Buzz's own files**, which is what the differential ratchet actually measures:

| File | Delta | Note |
|---|---:|---|
| `app/routes.ts` | +41 | new file content replaces old |
| `shared/constants/kinds.ts` | +2 | 46010 into two sets — **ungoverned root**, free |
| `features/messages/lib/formatTimelineMessages.ts` | +1 | 46010 into `isTimelineContentEvent` |
| `features/messages/ui/MessageRow.tsx` | **−40** | the `default:` arm (`:414-461`, 48 lines) becomes one `<MessageBody/>` call — `17` §2.5 |
| `app/AppShell.tsx` | net ≤ 0 required | the chrome conditional (§3.4) must be offset by a hook extraction in the same commit |
| `src-tauri/src/lib.rs` | +14 | thirteen handler entries plus a blank line; 938 → 952, leaving 48 |
| `src-tauri/src/commands/mod.rs` | +6 | three `mod` lines and three `pub use` lines |
| `src-tauri/src/commands/channel_reconnect_repair.rs` | +3 | `CHANNEL_REPAIR_KINDS` 15 → 18, plus its pinned test literal (§5.3) |
| `src-tauri/src/commands/identity.rs` | +1 | the `perch_sign_gate` call (INV-29); 790 lines, no pressure |
| `src-tauri/src/commands/messages.rs` | +1 | the second `perch_sign_gate` call in `send_channel_message` (§7.3.1) |
| `desktop/package.json` | +1 | `check:route-tree`, chained into `check` (§3.5) |
| `src/testing/e2eBridge.ts` | +3 | the delegating guard — ungoverned root |

`MessageRow.tsx` going **negative** is the only reason a Perch marker can land at all, and it is why
the split is sequenced first.

---

## 13. Proposed brief amendments, and one withdrawal

Raised here rather than routed around, per `00-BRIEF.md` §12. Nothing in §14 or in any skeleton file
depends on one of these being ratified — that separation is deliberate, because the wave-2 review's
systemic finding was producers baking unratified amendments into constants where a correct prose
correction cannot reach them.

**A11 — `/settings` moves from "must become a real route before the first new surface" to
"already a route; moving it into the outlet is optional Phase-2 cleanup".**
`APPENDIX-NORMATIVE.md` §1 row 11 and `04` §1.1 both describe work that is already done: `routes.ts:8`
+ `routes/settings.tsx:24-27` declare a real route with a `validateSearch` `[V]`. The genuine
unfinished work is that `AppShell.tsx:173`/`:784-823` render it *instead of* the outlet. §3.4 removes
the dependency by giving `derivePerchShellRoute` a `chrome` mode, so no Perch surface needs the outlet
freed. **Not applied to the data:** `PERCH_NAV` carries `phase: 0` for `/settings`, the registry's
value, and will keep carrying it until this amendment is ratified.

**A12 — the appendix's `invokeTauri` row should read "256 distinct renderer→Rust command literals
(206 via `invokeTauri` + 56 via raw `invoke`, 6 shared), 57 files", with the method.** C3. The
existing "205 / 57" is a correct count of the wrong set — it misses `features/terminal`'s nine
commands entirely, which `00-BRIEF.md` §5.1 takes verbatim.

**A13 — `07` §9's virtualization table is wrong about the case timeline.** C1. `MessageTimeline`
renders through `virtua`'s `VList` with `shift={isPrepend}`, not `VirtualizedList`, and
`VirtualizedList` has 7 call sites across 6 files rather than "nine surfaces". §10 records the
corrected assignment.

**A14 — add `PERCH_CONTAINMENT_CLOCK_HZ = 1` to `APPENDIX-NORMATIVE.md` §6, proposed.**
One board-level tick, not a per-row interval (§9). It is currently implicit in `07` §9's fix column
and has no name, which means two producers will implement it twice.

**A15 — the appendix's key-map row `Cmd-\`` is correct and stays; the *cost* of honouring it is two
`event.code` literals, not "unbudgeted work".** C10. `TerminalBootstrap.tsx:151` (open) and
`TerminalSubstrate.tsx:69` (close) are the two sites `[V]`. Two peer artifacts reported the shipped
chord and drew opposite conclusions about whether the registry could be honoured; it can, cheaply.
The capture-phase / keydown-and-keyup / toggle-on-keyup mechanics are untouched by the rebinding, and
Perch's bare `J`/`K` selection keys are unaffected either way because the handler requires a
modifier. `prototypes/watch.html` renders `⌘J` and `prototypes/case.html` renders the registry's
chord with a flag; this amendment settles it in the registry's favour.

**A16 — `CHANNEL_REPAIR_KINDS` is a load-bearing constant the appendix does not name.** §5.3. It is
the Rust mirror of `CHANNEL_EVENT_KINDS` that decides what a reconnect keyset walk actually fetches,
and no plan document mentions it. Proposed as a row in §6's verified counts:
"`CHANNEL_REPAIR_KINDS` | **15** kinds, Rust-side, must become 18 for Perch |
`desktop/src-tauri/src/commands/channel_reconnect_repair.rs:6-8`".

### 13.1 One withdrawal, and it is a peer's

**W-1 is withdrawn** — `13-WIRE-SCHEMAS.md`'s amendment giving `26006` an `h` tag naming a standing
`#watch` channel. §5.2.1 carries the argument: the registry already says global-no-`h`, an
`h`-tagged frame delivers nothing to the only filter anyone implemented, it narrows the disclosure
audience rather than closing it, and it puts the frame permanently outside `p_gated_filters_authorized`
— which applies only when `channel_id.is_none()`. `ADR 0017` clause C3 is the mechanism.

I record this as a withdrawal rather than a competing proposal because the failure the wave-2 review
named was two artifacts each declaring itself the decision. One of the two has to stand down, and the
one contradicting the registry is the one that should.

**This does not delete the `#watch` ops channel.** It exists for the watch claim (`04` §2.11) and
`perchKeys.watchClaim()` still reads it. W-1 is withdrawn for the alarm frame only.

## 14. Decisions this document makes, in one list

Bind to these; peers and the integrator can cite them. Items marked **[revised]** changed in the
red-team revision pass and supersede the first draft.

1. **Feature tree** per `17` §1.1; architecture modules placed per §2.1. `colonyScopedRegistry.ts`
   goes in `features/perch/`, **not** a seventh `features/colony/` directory (departs from `07` §7).
   Those six directories plus `shared/ui/perch/` are also the canonical **Perch feature roots** the
   copy gate scans and the invariant greps scope to — one definition, in §2.1, not a list repeated
   in each guard.
2. **`resetColonyState()`** keeps `07` §7's name over the brief's `resetPerchState`.
3. **Eleven routes**, plus **three redirect stubs** (`/channels/$channelId` → `/cases/$channelId`,
   `/agents` and `/pulse` → `/watch-floor`) and **no stub** for `/workflows`, `/projects`,
   `/messages/new`, `/reminders` or the forum post route.
4. **`/` is eager; the other nine content routes are lazy** — matching Buzz's own split.
5. **Full-screen surfaces use `chrome: "bare"`, not the settings takeover.** The outlet stays mounted
   on every route. Settings keeps its takeover unchanged in Phase 0–1.
6. **One `PerchView` union** in `app/perchViews.ts`, replacing both hand-written copies, with a
   conditional-type assertion binding `PERCH_NAV` to it.
7. **[revised] `PERCH_NAV` carries the registry's values, not this document's amendments.**
   `/settings` is `phase: 0` (`APPENDIX-NORMATIVE.md` §1) even though §13's A11 proposes changing
   that row's reason, and the `/handoff` label is **"Handoff"** — the surface's registry name — not
   "End watch". A nav item carrying one of that surface's two verbs is wrong for half of every shift:
   an operator arriving at 22:00 is *taking* the watch. `prototypes/watch.html` renders "End watch"
   in the rail; that is a one-word divergence and `06` owns the final string.
8. **[revised] `26006` is global, `#p`-selected, no `h` tag — ratified, with `13`'s W-1 withdrawn.**
   The mechanism is `P_GATED_KINDS` (ADR 0017 C3), one line in `buzz-core/src/kind.rs`. §5.2.1.
9. **Query keys carry their source in segment 0**; two healing predicates, not one.
10. **No colony segment in a key in v1.** A cross-colony read view gets its own `QueryClient`, not a
    wider key.
11. **`PERCH_FRESHNESS` is `satisfies Record<keyof typeof perchKeys, …>`** — every read has a
    `staleTime`, a poll policy, an invalidation set and a written reason, or it does not compile.
12. **`daemon`-source queries set `retry: 0`.**
13. **Governance writes never use `onMutate`**; `usePerchWrite` exposes a four-value phase union with
    no optimistic slot.
14. **Seven subscriptions maximum**, ever; twelve lanes on one REQ; open cases subscribed lazily.
15. **[revised] `perchCaseLiveKinds()` supersets `CHANNEL_EVENT_KINDS` AND `CHANNEL_REPAIR_KINDS`
    gains three members in the same PR.** Eligibility is decided from our filter; what the keyset
    walk *fetches* is a Rust constant our filter never reaches
    (`channel_reconnect_repair.rs:6-8`). Superset alone leaves the Perch kinds riding only the
    re-sent live REQ, bounded by `limit` and served newest-first. `PERCH_CASE_REPAIR_KINDS` +
    `assertPerchRepairKindsCovered` keep the two languages from drifting again; the `seq` gap
    detector is the independent backstop. §5.3.
16. **Ephemeral frames never enter the React Query cache.** `perchEphemeralStore` +
    `useSyncExternalStore`, last-wins per subject, content-equality merge at write time.
17. **Unadmitted `26xxx` frames are counted and dropped, and the count renders.** That closes the
    forgery half only; the disclosure half is decision 8's one line.
18. **`since` is excluded from the subscription filter's stable serialization.**
19. **Gap detection is namespaced `(colony, issuer)`; a gap is healed only from the daemon.**
20. **[revised] Thirteen new Tauri commands: 7 reads + 5 daemon writes + 1 relay write.** One route
    per command, route strings as Rust constants, no generic passthrough ever. The daemon writes are
    `perch_writes.rs`'s closed five (INV-01); the relay write is `perch_verdict.rs`'s
    `perch_record_verdict` (INV-RF1). **Two files, two closed sets, never merged.**
21. **[new] `perch_record_verdict` builds the card from the daemon's own hold record**, signs the
    RFC 8785 canonical `{decided_at_ms, decision, hold_id, rationale_sha256}` with the operator's
    Ed25519 key, and publishes the `kind:9` card with an `h` tag and no `e` tag. One signature serves
    both legs. The Ed25519 secret lives in `SecretStore::shared(keyring_service())` and never crosses
    IPC; only `public_key_hex` does, because the decide route derives `voter_id` from it.
    `perch_sign_gate` must also be called from `send_channel_message`, or the gate has a second door.
22. **[new] `DecideHoldInput` matches `HoldDecisionRequest` field for field** — `decided_at_ms` and
    `armed_at_ms` present, `signature` a `DetachedSignature` object — with a drift test asserting the
    field set against the schema's `required` list.
23. **[new] The authority on which verdict card is the decision is the daemon's
    `HoldDecisionRecord`, never a card.** A losing console publishes a `superseded` update card as an
    optimisation; the render rule does not depend on it having survived. With no daemon, both cards
    render unresolved and neither is picked. §7.6.
24. **`RefusedLate`, `Superseded` and `lease_closed: false` are returned in `Ok`, never `Err`.**
25. **[revised] One delegating `perch_` guard in `e2eBridge.ts` (three lines); one module path,
    `src/testing/perch/e2ePerchBridge.ts`; one fixture corpus,
    `build/fixtures/perch-demo-fixture.json`.** The four `__BUZZ_E2E_PERCH*` seams are installed by
    that module, not by the upstream file. `perchBridgeFixtures.ts` is withdrawn. §7.4.1.
26. **27-member `ColonyScopedSingleton` union**; twelve Buzz resetters survive, nine go with their
    subsystem, fifteen are new; conditionals move inside resetters; the reset is sequential.
27. **The Watch queues and the Ledger use `@tanstack/react-virtual`; the case timeline stays on
    `virtua`.** No third virtualizer, no port either way.
28. **Three tiers of error boundary**, and a crashed surface renders in the destructive register,
    names itself, and never implies the state behind it is settled.
29. **[new] Perch-authored components read only `--perch-*` tokens.** `PerchSurfaceBoundary.tsx` is
    the exhibit: `bg-perch-card`, `text-perch-fg`, `border-perch-danger`, never `bg-card` /
    `text-muted-foreground` / `border-destructive`. `ThemeProvider` writes 38 bare Buzz names inline
    on the root element (`ThemeProvider.tsx:436-446`, `:398-409`; 38 counted in `adaptive-theme.ts`)
    and no stylesheet beats an inline declaration. Binding to `19-TOKENS.md`'s TOKEN NAMESPACE
    commitment. The danger hue is a border only — 19 marks it NEVER TEXT — and the word carries the
    meaning.
30. **[new] No Perch file invents a `data-perch-role` value.** `17` §1.4's thirteen are closed and
    `check-perch-grant-affordance.sh` R1 asserts the closure, so the crash fallback carries a
    `data-testid` and no role attribute.
31. **One containment clock at board level**, not one interval per row.
32. **`AppShell.tsx`'s net line delta must be ≤ 0** in the commit that adds the chrome conditional.
33. **[new] `desktop/scripts/check-route-tree.mjs` ships and is wired through
    `desktop/package.json`'s `check` chain**, which `just check` and `just ci` already run. It is a
    one-part change: `tools/check-gates-wired.sh` covers AMBUSH `tools/` only. §3.5.

## 15. What this document could not verify, what changed under review, and what is blocked

### 15.1 Resolved since the first draft

Three items moved from "could not verify" to measured, and one claim was retracted.

- **The `e2eBridge.ts` guard ordering (C9).** Resolved: no arm in that switch matches on a command
  prefix. All twelve `startsWith(` calls test a storage key, a URL, a subscription id or a filename
  `[V]`. The guard must precede `default:` and nothing else.
- **The terminal chord's cost (C10).** Resolved: two `event.code` literals, `TerminalBootstrap.tsx:151`
  and `TerminalSubstrate.tsx:69` `[V]`.
- **Where the operator's Ed25519 key lives (C11).** Resolved against real Buzz plumbing, including
  the property that Buzz's existing sign-out wipes it with no allowlist to update `[V]`.
- **RETRACTED: "supersetting `CHANNEL_EVENT_KINDS` keeps Buzz's paged reconnect repair."** It keeps
  *eligibility*. The repair page is built in Rust from a fixed fifteen-kind constant the renderer
  never reaches (§5.3). The correction narrows the consequence too — the Perch kinds still ride the
  re-sent verbatim filter, so the hole is bounded by `limit` rather than total — and both halves are
  written out, because a review that only recorded the alarming half would have justified a different
  and worse fix.

### 15.2 Still unverified

- `max_filters: 10` is advertised (`nip11.rs:133`) but I found no enforcement site (C6). I searched
  `handlers/req.rs`, `connection.rs` and `protocol.rs`; a filter-count check may exist somewhere I did
  not look. Treated as a contract, not a fence.
- The exact 206-vs-205 distinct-literal difference. My regex takes the first quoted string after the
  paren and cannot see a command name passed as a variable, so 206 is a floor and says nothing about
  dynamic invokes. I found none, but I did not prove there are none.
- **None of the skeleton files has been compiled.** `node_modules` is not installed in this checkout
  and the Tauri crate has no `target/` dir, so neither `tsc --noEmit` nor `cargo check` ran on any of
  the eleven. Every symbol, line number and signature they cite was read at the line; expect `tsc` to
  settle a few exact types and expect rustfmt to reflow. `check-route-tree.mjs` is the one exception
  and it was **executed**, four times, with its transcript in §3.5.
- `perch_verdict.rs`'s test `the_generic_signer_refuses_what_this_command_publishes` calls
  `identity_perch_gate::perch_sign_gate`, which is `16-INVARIANT-TESTS.md`'s file. The two agree on
  the marker grammar by reading; they have not been compiled together.

### 15.3 Blocked on someone else

- `15-FILE-SPLIT-PLAN.md` is a hard prerequisite. `MessageRow.tsx` has 1 gate-line of headroom and
  `AppShell.tsx` has 2. Nothing in this document can land first.
- `17` §8's `ViewLoadingFallback` re-skin must land before the nine lazy route files, or their
  `Suspense` fallbacks reference union members that do not exist (§3.6).
- `19-TOKENS.md`'s `perch-tokens.css` and `tailwind.perch.js` must land before
  `PerchSurfaceBoundary.tsx`, which now reads `--perch-*` classes exclusively (decision 29). A
  `bg-perch-card` with no token behind it renders transparent, which is a visible failure rather than
  a silent one — but it is still a sequencing constraint.
- `13-WIRE-SCHEMAS.md` owns `card-swarm-verdict-v1.schema.json`'s `leg2.state` enum. §7.6 proposes
  `superseded` + `superseded_by`; the render rule holds without it.
- `perchEphemeralStore`'s admitted-issuer set has no source until the bridge publishes one and someone
  decides the operator-id → Nostr-pubkey mapping. `OperatorPrincipalConfig` carries no pubkey field
  and is `#[serde(deny_unknown_fields)]`, so it is a typed field addition (task B0), not a free config
  key. Until then every `26xxx` frame is dropped and counted — the correct fail-closed behaviour and a
  completely blank Watchfloor.
- Gap detection detects loss between the bridge and this client only, until B6 supplies a `seq` the
  daemon itself stamps (§5.7).
- The `26006` disclosure stays open until `P_GATED_KINDS` gains one line. Decided (§5.2.1); not
  written.
- The three-kind extension to `CHANNEL_REPAIR_KINDS` is a Buzz Rust edit that must ride the fork's PR
  (§5.3). Decided; not written.

### 15.4 On the CI gates this document leans on

`tools/check-copy-banned-terms.sh`, `check-perch-write-allowlist.sh` and
`check-perch-grant-affordance.sh` exist in neither **repository**. A peer has landed real,
self-tested implementations as build artifacts under `build/skeleton/tools/`; those are artifacts to
apply, not gates that run. Every AMBUSH-side guard is a two-part change — the script *and* its
workflow `run:` step, in the same PR — because `tools/check-gates-wired.sh` (`:19-56`) enumerates
`tools/check-*.sh` and `tools/verify-*.sh` and fails on any not named by a real `run:` command.

`desktop/scripts/check-route-tree.mjs` is the exception in both directions: it is written and it
runs, and it is a one-part change, because that gate's scope is the Ambush repository's `tools/`
directory and a Buzz-side `desktop/scripts/*.mjs` is outside it. It rides `desktop/package.json`'s
`check` chain into `just check`, `just ci` and the pre-push lane.

Two of the copy gate's own inputs are paths this document owns and §14 fixes: its Perch feature roots
are the six directories in §2.1, and it parses `src/features/perch/lib/perchKeymapRegistry.ts` as
data for INV-31/INV-32 — which is where `17` §6.1 puts it, so the three artifacts already agree.

### 15.5 Copy check

Every rendered string this document introduces — `PERCH_NAV`'s nine labels and
`PerchSurfaceBoundary`'s four — was checked against `build/skeleton/tools/copy-ban-list.tsv`'s
thirteen rows: no `approve`/`approval`, no capital-D `Deny`, no `verified by`/`trusted`/`proof`, no
shield or lock glyph, no quorum fraction, no bare source count, no reassurance phrase, no `hunt` as a
noun, no `clowder`, no legacy codename, no bare `lease` (the nav item is "Containments"), no bare
`lane`, and no exclamation mark. The crash fallback deliberately states what is **not** known rather
than that anything is fine, which is voice law L6 rather than a lucky miss.
