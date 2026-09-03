# Upstream PR bodies — `block/buzz`

**Two PRs, not one.** They touch three disjoint files with no shared import and
no shared test, so they can be opened together and reviewed independently. If
one stalls, the other still lands. Paste each body as its PR description.

| | Title | Files | Commits |
|---|---|---|---:|
| **PR A** | `refactor(desktop): split AppShell and MessageRow below the size ratchet` | `AppShell.tsx`, `MessageRow.tsx` | 6 |
| **PR B** | `refactor(desktop): split HomeView below the size ratchet` | `HomeView.tsx` | 4 |

Every commit on both branches is signed off (`git commit -s`) — the required
**DCO Check** fails a PR with any commit missing a `Signed-off-by` trailer, and
`git rebase` onto `main` needs `--signoff` explicitly. No screenshots on either:
no rendered pixel changes, so `scripts/post-screenshots.sh` has nothing to post.

A note on the test-project names used below, because it is easy to get wrong:
`desktop/playwright.config.ts` declares exactly two projects, `smoke` (line 20)
and `integration` (line 171), each with an explicit `testMatch` array and no
catch-all. `pnpm test:e2e:smoke` runs the first; `pnpm test:e2e:integration`
runs the second against a live relay. A spec in neither array never runs.

---

# PR A — `AppShell.tsx` + `MessageRow.tsx`

```
refactor(desktop): split AppShell and MessageRow below the size ratchet
```

## Summary

- extract `MessageThreadGuides` and `MessageBody` out of `MessageRow.tsx`
- extract `useAppShellBackgroundSync`, `useCommunityDestinationRestore`,
  `useChannelCreationHandlers` and `AppShellSettingsSurface` out of `AppShell.tsx`
- no behaviour change, no DOM change, no `data-testid` change, no public export
  change
- `MessageRow.tsx` 999 → 705 gate-lines; `AppShell.tsx` 998 → 780

## Why

Both files sit one and two gate-lines under the differential ratchet's 1000-line
ceiling:

| File | gate-lines | cap in force | headroom |
|---|---:|---:|---:|
| `desktop/src/features/messages/ui/MessageRow.tsx` | 999 | 1000 | **1** |
| `desktop/src/app/AppShell.tsx` | 998 | 1000 | **2** |

(`scripts/check-file-sizes-core.mjs:24-29` counts `content.split(/\r?\n/).length`
— `wc -l` plus one for a newline-terminated file — so `wc -l` reporting 998/997
understates the number the gate sees by one.)

`allowedLineCount` at `scripts/check-file-sizes-core.mjs:31-33` grandfathers a
file that is *already* over the ceiling but never grants headroom to one under
it. So these two are, practically, frozen: the next feature that needs a body
renderer, a shell effect or a route branch has to either land its change
somewhere unnatural or split the file under time pressure in the same PR as the
feature. This PR does the split on its own, with nothing else in it, so the
diff is reviewable as a move.

`MessageRow.renderBody`'s `default:` arm is the sharper case. It is the only
extension point for a new message-body renderer, it is 48 lines, and there is
exactly one line of room above it. Anyone adding a body renderer today is
blocked before they start.

## What moved, exactly

Nothing is rewritten. Every extracted statement is the same expression it was,
in the same order, with its comment. The only edits inside moved code are
renames of closure reads to parameter reads (`identityQuery.data?.pubkey` →
`pubkey`, `communitiesHook.communities` → `communities`, and so on).

### `MessageRow.tsx` → 705

| Commit | New file | Moved from | out | in |
|---|---|---|---:|---:|
| 1 | `features/messages/ui/MessageThreadGuides.tsx` | `:67-72`, `:319-377`, `:466`, `:734-884` | 226 | 22 |
| 2 | `features/messages/ui/MessageBody.tsx` | `:174-197`, `:268-281`, `:296-308`, `:315-316`, `:414-461` | 111 | 21 |

`ThreadDepthGuideAction` becomes `MessageThreadGuides`' type and `MessageRow`
re-exports it, so `MessageThreadPanel.tsx:42` and
`MessageThreadSummaryRow.tsx:8` do not change.

Both new components render inside `MessageRow`'s existing `React.memo` boundary
and neither is memoized again. The 46-clause comparator at `MessageRow.tsx:935-995`
is **untouched** — every prop the two children receive is either already compared
there (`message.*`, `profiles`, `searchQuery`, `collapseDepthGuideActions`,
`depthGuideDepths`, `highlightThreadLineDepths`, `connectDescendants`,
`highlightDescendantRail`, `highlightReplyConnector`, `collapseDescendantsLabel`,
the four `onCollapse*` callbacks, `huddleMemberPubkeys*`, `videoReview*`) or
already read uncompared inside the same closure today (`channelId`, `onEdit`,
`showDepthGuides`). The extraction neither adds a comparator clause nor changes
which props are compared.

One correctness detail worth a reviewer's eye: `MessageBody` takes `profiles` as
a prop because `resolveSnapshotSharedBy(message, profiles)`
(`features/messages/lib/snapshotSharedBy.ts:8-11`) declares that second
parameter **optional** (`profiles?: UserProfileLookup`). Dropping it in the move
is not a type error — it just returns the raw pubkey instead of the resolved
label, on every wave attachment. No test in the suite would fail on that.

### `AppShell.tsx` → 780

| Commit | New file | Moved from | out | in |
|---|---|---|---:|---:|
| 3 | `app/useAppShellBackgroundSync.ts` | `:144`, `:181`, `:191-221`, `:223-227` | 60 | 11 |
| 4 | `app/useCommunityDestinationRestore.ts` | `:277-324` | 53 | 9 |
| 5 | `app/useChannelCreationHandlers.ts` | `:504-506`, `:537-620` | 89 | 12 |
| 6 | `app/AppShellSettingsSurface.tsx` | `:174-180`, `:647-654`, `:785-823` | 56 | 8 |

`AppShell` has exactly one importer — `app/routes/root.tsx:3` — so none of this
is reachable from outside the shell.

Commits 3–5 follow the existing `use*` sibling pattern — `AppShell.tsx` already
imports **fifteen** of them from `@/app/` (`AppShell.tsx:5,15-28`), of which
`useAppShellDesktopNotifications.ts` came out of this same file in #1248.
Commit 6 follows the existing component-and-provider sibling pattern —
**eleven** more modules from `@/app/` (`AppShell.tsx:6-14,101,103-106`):
`AppShellProvider`, `AppShellOverlays`, `AppShellChannelSurface`,
`AppHuddleShell`, `AppTopChrome`, `TerminalContextOverrideProvider`,
`RelayConnectionOverlay`, `AppShellTrayMenu`, `AppProfilePanelProvider`,
`AppWorkflowEditorOverlayProvider`, `LazySettingsScreen`.

Commit 5 returns `isCreatingChannel` / `isCreatingForum` booleans rather than
the two mutation objects, because a React Query result is a new object every
render and handing one across the boundary would make `AppSidebar`'s props
unstable. Four same-line reads change with it (`AppShell.tsx:837`, `:838`,
`:963`, `:964`); a missed one is a `tsc` error, not a silent bug.

## The one ordering change, called out

Commit 3 moves fifteen effect-only hooks into `useAppShellBackgroundSync`.
`useProfileQuery` (`AppShell.tsx:222`) sat in the middle of that block and stays
in `AppShell`, so it now runs *after* the block rather than between
`useAgentMetricArchiveSeed` and `useRelayAutoHeal`. React only requires hook
order to be stable across renders, not to be any particular order, and none of
the fifteen reads or writes the profile query's cache entry. Covered by
`tests/e2e/boot-splash.spec.ts` and `tests/e2e/badge.spec.ts` in the **smoke**
project, and by `tests/e2e/profile.spec.ts` and `tests/e2e/onboarding.spec.ts`
in the **integration** project.

Commit 5 similarly moves `useCreateChannelMutation` ×2 and `useApplyTemplate`
below `useOpenDmMutation`/`useHideDmMutation`. Same argument; covered by
`tests/e2e/channel-browser.spec.ts` and `tests/e2e/channels.spec.ts`, both smoke.

## Validation

```
just ci
cd desktop && pnpm test:e2e:smoke
cd desktop && pnpm test:e2e:integration   # for the two shell specs above
```

Per-commit, the checks that matter:

- `just file-size-check` — the point of the PR; run it on every commit, not just
  the last, so no intermediate commit is over the ratchet.
- `just desktop-typecheck` — the re-export of `ThreadDepthGuideAction` and the
  six new prop types are what this catches.
- `just desktop-test` — `messageRowEquality.test.mjs`, `useMessageEmoji.test.mjs`,
  `configNudgeAuthPubkey.test.mjs`, `AppShell.helpers.test.mjs` all still pass
  unchanged; none of them imports either split file. Three new `.test.mjs` files
  arrive with the commits that need them (see below).
- `pnpm test:e2e:smoke` — the real coverage. `thread-unread.spec.ts`,
  `thread-reply-anchor-roleplay.spec.ts` and `messaging.spec.ts:2994` assert
  `thread-collapse-guide` / `thread-collapse-rail` / `data-thread-head-id`, which
  commit 1 moves; `thread-head-stale-edit.spec.ts`, `mentions.spec.ts`,
  `custom-emoji.spec.ts`, `spoiler.spec.ts`, `entity-link-recipient-cards.spec.ts`
  and `image-attachment-gallery.spec.ts` exercise the `default:` body arm commit 2
  moves; `channels.spec.ts`, `navigation.spec.ts`, `channel-browser.spec.ts` and
  `boot-splash.spec.ts` exercise the shell commits.

New tests in this PR, each closing a gap rather than re-testing a move:
`MessageThreadGuides.test.mjs` (guide/rail counts by depth — the E2E assertions
are "at least one exists"), `waveMessage.test.mjs` (the `parseWaveMessageContent`
predicate, which nothing pins today), `useChannelCreationHandlers.test.mjs` (the
forum-vs-stream branch, which today has only end-to-end coverage). All three use
the repository's existing component-unit pattern — `.test.mjs` importing a
`.tsx` through `desktop/test-loader-hooks.mjs` and asserting on
`renderToStaticMarkup`, per `features/sidebar/ui/MoreUnreadButton.test.mjs:1-12`.

Build E2E with `pnpm test:e2e:smoke` (it runs `pnpm build:e2e` for you). A plain
`pnpm run build` strips the mock Tauri bridge and every spec fails with
`Cannot read properties of undefined (reading 'invoke')`, which reads as a
product bug rather than a build mistake. Kill port 4173 before re-running:
`reuseExistingServer: true` will otherwise serve the previous build.

## Not in this PR

- No unification of the near-duplicate guide rendering in
  `MessageThreadSummaryRow.tsx:104-210`, which emits the same
  `thread-collapse-guide` testid. It is a genuine follow-up; folding it in would
  make this diff stop being a move.
- No change to `AppShell.tsx:173` / `:784`'s settings-vs-outlet branch. Commit 6
  extracts the surface where it stands; where it renders is a separate question.
- No fix for the comparator's uncompared row props (`channelId`, `onEdit`,
  `showDepthGuides`, the action callbacks). They are uncompared before and after.

---

# PR B — `HomeView.tsx`

```
refactor(desktop): split HomeView below the size ratchet
```

## Summary

- extract `HomeMessagesDetail`, `HomeInboxAuxiliaryPane`,
  `useHomeInboxFilterChange` and `HomeFeedUnavailable` out of `HomeView.tsx`
- no behaviour change, no DOM change, no `data-testid` change
- `HomeView.tsx` 994 → 736 gate-lines

## Why

`HomeView.tsx` is the third file inside six gate-lines of the ratchet, and it is
the one with the most composition left in it: a single component holding the
list pane, the messages detail pane, the drafts/reminders detail pane, the
profile and channel-management auxiliary panes, the filter-change selection
logic and the feed-unavailable state.

| File | gate-lines | cap in force | headroom |
|---|---:|---:|---:|
| `desktop/src/features/home/ui/HomeView.tsx` | 994 | 1000 | **6** |

Its own siblings show the intended shape: **twelve** `use*` hooks sit in
`features/home/` and **twelve** more components in `features/home/ui/`, and
`useInboxSelectionAnchor.ts:48-51` says in its own doc comment that it exists to
"own three layers of anchor resolution so HomeView.tsx stays under its
 file-size ceiling". This PR continues that, four blocks at a time.

## What moved, exactly

| Commit | New file | Moved from | out | in |
|---|---|---|---:|---:|
| 1 | `features/home/ui/HomeMessagesDetail.tsx` | `:263-267`, `:293`, `:306-309`, `:485-491`, `:505-511`, `:608-613`, `:782-918` | 187 | 42 |
| 2 | `features/home/ui/HomeInboxAuxiliaryPane.tsx` | `:31-39`, `:153-158`, `:199-214`, `:935-983` | 82 | 18 |
| 3 | `features/home/useHomeInboxFilterChange.ts` | `:535-581` | 48 | 15 |
| 4 | `features/home/ui/HomeFeedUnavailable.tsx` | `:587-606` | 22 | 6 |

Each moved derivation was checked for readers outside the block before it moved.
`latchedDefaultParentId` is read only at `:799`; `unreadBoundaryEventId` only at
`:803`; `selectedItemReplies` only at `:916`; `toggleReactionMutation` only at
`:898`; `editMessage`/`isEditingMessage` only at `:822`/`:793`; and the four
values `getHomeMessageCapabilities` returns only at `:785`, `:787`, `:791`,
`:814`, `:834`, `:896` — all inside the detail block. `profilePanelTab`,
`profilePanelView` and the two `handleProfilePanel*Change` callbacks are read
only inside the auxiliary block. `handleCloseProfilePanel` is read at `:819`
*and* `:948`, so it stays in `HomeView` and is passed to both children.

`HomeView` has one importer — `features/home/ui/HomeScreen.tsx:7` — and
`HomeScreen` is what `app/routes/index.tsx:6,94` imports and renders.

## Ordering

No hook-order change in commits 1, 2 and 4: they move JSX and the derivations
below the last hook. Commit 3 replaces a `React.useCallback` with a call to a
hook that wraps the same `useCallback`, in the same position.

## Validation

```
just ci
cd desktop && pnpm test:e2e:smoke
```

- `just file-size-check` on every commit.
- `just desktop-typecheck` — the four extracted prop types are what this catches.
- `just desktop-test` — `lib/inbox.test.mjs`, `lib/inboxViewHelpers.test.mjs`,
  `lib/inboxSelection.test.mjs`, `lib/inboxListRows.test.mjs`,
  `useHomeInboxReadState.test.mjs`, `ui/inboxReopenNavigation.test.mjs` all pass
  unchanged; none imports `HomeView`.
- `pnpm test:e2e:smoke` — the coverage that matters. The home inbox surface is
  exercised by the smoke specs that navigate to `/` and open a detail pane.

## Not in this PR

- No extraction of the list-pane call site (`:692-758`) or the pane resize
  handle (`:759-780`). Those are the blocks a future home-inbox change is most
  likely to rewrite in place; extracting them now would mean extracting them
  twice.
- No change to `lib/inbox.ts`'s category machinery. `matchesInboxFilter`
  (`lib/inboxViewHelpers.ts:41`) and `buildInboxItems` (`lib/inbox.ts:462`) are
  already exported pure functions with their own tests; this PR does not touch
  them.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
