# 15 — The unblocking refactor: `AppShell`, `MessageRow`, `HomeView`

**Status:** buildable artifact. Wave 2, revised after red-team review. Owns the
file-split mechanics for every capped Buzz file on Perch's path, and the
marker-renderer registry *extraction step*.
**Binds to:** `APPENDIX-NORMATIVE.md` §3 (wire registry — seven markers, one
forked kind), §6 (shared constants and verified counts), §7 (vocabulary).
**Does not own:** the registry's *types and presenters* (`17-COMPONENT-SPECS.md`
§3 — this file owns the seam they plug into and the commit that opens it),
route wiring and query keys (`14-CLIENT-ARCHITECTURE.md`), token values
(`19-TOKENS.md`), invariant test bodies (`16-INVARIANT-TESTS.md`), sequencing
across the whole programme (`20-TASK-BREAKDOWN.md`).

Paths are absolute-from-repo-root under `BUZZ = /Users/connor/Medica/backbay/buzz`.
Every Buzz claim below was read from source at `eed74bde2` (clean tree) this
session. Every line count was produced by the gate's own counting function, not
by `wc -l`.

**What changed in this revision.** The red team's systemic finding was
*unarbitrated disagreement between artifacts* — two producers each verify a fact,
each write a correct local decision, and nobody holds the tiebreak. Three of
those collisions land in this file's scope. §11 is a new section that settles
them, with the evidence and an owner for each. The load-bearing one: **this file
was wrong about `HomeView.tsx`.** Its previous §7.1 verdict said The Watch is a
new file and `HomeView` should never be edited; `00-BRIEF.md` §3 surface 1 and
`04-SURFACES-AND-UX.md` §2.1 both make The Watch a *re-skin of that file*, and
`20-TASK-BREAKDOWN.md` task P0-13 was right to add it as a third split. It is
now planned here as HV-1…HV-4, measured, with 264 gate-lines of headroom at the
end. Two smaller corrections also came out of re-running everything: three E2E
specs this file cited as "smoke" are not (§8.1), and the ledger script now
refuses to print a number computed against ranges that have moved (§1.1).

Two runnable artifacts sit beside this file and are the reason its numbers are
not estimates:

| File | What it does |
|---|---|
| `build/refactor/line-ledger.mjs` | Applies each planned commit's line edits to an in-memory copy of the real file and prints the gate-line count afterwards. Read-only. Every edit carries an `anchor`; a mismatched anchor exits 2 rather than printing a number. `--self-test` proves the anchor guard fires. |
| `build/refactor/near-cap-survey.mjs` | Enumerates every governed file at or above a threshold across desktop, web and mobile, with the cap the ratchet would actually apply. Self-verifies its rule roots against the three check scripts. |

Six more are the extraction itself, written out so the diff can be reviewed as a
move rather than described: `MessageThreadGuides.tsx`, `MessageBody.tsx`,
`useAppShellBackgroundSync.ts`, `useCommunityDestinationRestore.ts`,
`useChannelCreationHandlers.ts`, `AppShellSettingsSurface.tsx`, plus
`upstream-pr.md`, which now carries **two** PR bodies (§8).

---

## 1. The gate, verified

**Who runs it, in what process, what it does to the data.**

`runFileSizeCheck` (`BUZZ scripts/check-file-sizes-core.mjs:116-180`) is a Node
script invoked three times by the `file-size-check` recipe
(`BUZZ justfile:106-110`) — once per project, each with its own rule table. It
runs in three places, all as a plain child process, and it mutates nothing: it
sets `process.exitCode = 1` and prints violations.

1. **CI**, unconditionally, inside the `changes` job — `.github/workflows/ci.yml:98-99`
   (`- name: File size policy` / `run: just file-size-check`). That job checks
   out with `fetch-depth: 2` (`:32-33`), which is why `resolveBaseRef`
   (`check-file-sizes-core.mjs:44-66`) uses `HEAD^1` when `GITHUB_ACTIONS` is
   `"true"`. It runs *before* `dorny/paths-filter` gates anything, so a desktop
   size regression cannot be filtered out.
2. **Pre-push**, unconditionally and deliberately unfiltered
   (`BUZZ lefthook.yml`, the `file-size-check` command under `pre-push`, whose
   own comment says path filtering "would only duplicate policy and create
   another place for coverage drift").
3. **`just check` → `just ci`** (`BUZZ justfile:96`).

The two functions that decide everything:

```js
// BUZZ scripts/check-file-sizes-core.mjs:24-29
export function countLines(content) {
  if (content.length === 0) return 0;
  return content.split(/\r?\n/).length;
}

// BUZZ scripts/check-file-sizes-core.mjs:31-33
export function allowedLineCount(baseLines, maxLines) {
  return baseLines == null || baseLines <= maxLines ? maxLines : baseLines;
}
```

Three consequences, each load-bearing:

- **A newline-terminated file counts `wc -l` plus one.** The split on `/\r?\n/`
  produces a final empty string for the trailing newline. So `wc -l` under-reports
  the gate's number by exactly one for every normal file in the tree.
- **The ratchet grandfathers, it never grants.** A file already over 1000 is
  pinned at *its own* size — it may hold or shrink, never grow by one line. A
  file under 1000 gets 1000 and no more. There is no "it was nearly full so give
  it slack" path.
- **A new file gets a hard 1000.** `changedProjectFiles` (`:88-108`) marks
  untracked files status `"A"`, and `runFileSizeCheck:145` passes `baseLines: null`
  for them, which `allowedLineCount` turns into `maxLines`.

The desktop rule table (`BUZZ desktop/scripts/check-file-sizes.mjs:10-55`,
matched by `relativePath.startsWith(root + "/")` at
`check-file-sizes-core.mjs:40-42`) governs nine roots:

`src-tauri/src` and `src-tauri/crates` (`.rs`); `src/app`, `src/features`,
`src/shared/api`, `src/shared/context`, `src/shared/lib`, `src/shared/ui`
(`.ts`/`.tsx`); `src/shared/styles` (`.css`).

Ungoverned, and therefore free for Perch to grow: `src/shared/constants`
(`kinds.ts`, 176 gate-lines), `src/shared/hooks`, `src/shared/theme`,
`src/testing` (`e2eBridge.ts`, **14,621** gate-lines). **Correction to a claim
circulating in the ground notes:** `desktop/src-tauri` Rust *is* governed, by
two roots. What is ungoverned is the workspace `crates/` at the repository root
— no rule table names it, and `crates/buzz-relay/src/handlers/ingest.rs` is
5,524 lines.

**`src/testing` being ungoverned settles a live question three peer artifacts
each answered separately.** `16-INVARIANT-TESTS.md` proposes one delegating line
in `e2eBridge.ts`'s `default:` arm; `14-CLIENT-ARCHITECTURE.md` proposes one
`command.startsWith("perch_")` guard in the same place; `22-DEMO-FIXTURE.md`
commits that its seed "edits nothing" and rides five existing `window` seams.
The file-size ratchet is silent on all three: `src/testing` appears in no rule
table (`desktop/scripts/check-file-sizes.mjs:10-55`), so a one-line edit to a
14,621-line file is legal and always was. **Which** of the three mock-bridge
designs ships is not this file's call — it belongs to `14-CLIENT-ARCHITECTURE.md`,
which owns the renderer↔Rust surface — but no producer needs to design around a
size gate that does not apply. Recorded in §11 as an arbitration input, not an
arbitration.

### 1.1 The ledger refuses to pass silently

Every number in §5 comes from `build/refactor/line-ledger.mjs`, and the red team
observed that wave 2's most common measurement failure was *a number measured
against a file that is not the one in the tree*. The script now defends against
exactly that. Each planned edit carries an `anchor` — the text that must start
its `from` line — and, where the anchor is not discriminating, an `anchorTo` for
the `to` line. A mismatch prints the expected and actual line and exits **2**
("the plan's line numbers are stale") instead of printing a plausible-looking
count.

```
$ node build/refactor/line-ledger.mjs --self-test
  EXCLUDED (blank-line anchor)  MR-2 desktop/src/features/messages/ui/MessageRow.tsx:296-308
  EXCLUDED (blank-line anchor)  MR-2 desktop/src/features/messages/ui/MessageRow.tsx:315-316
self-test: 62 of 62 anchored edits reported against a one-line-shifted tree
self-test passed: the guard fires on a shifted tree
```

The self-test inserts one line at the top of each file and requires every
anchored edit to report. It earned itself on its first run: 58 of 62 fired, and
the four silent ones all had the anchor `import {`, which matches dozens of
lines and therefore still matched after the shift. Those four (and three more
like them) now carry an `anchorTo`, and the script rejects a bare `import {`
anchor with no `anchorTo` as a plan defect. Two MessageRow edits whose only
anchor is "this line is blank" cannot report against a one-line shift; the
self-test names them as EXCLUDED rather than counting them as passes.

---

## 2. The measured state, and why this is a prerequisite

```
$ node build/refactor/line-ledger.mjs
desktop/src/features/messages/ui/MessageRow.tsx
  base                                      999 gate-lines  (cap in force 1000)
desktop/src/app/AppShell.tsx
  base                                      998 gate-lines  (cap in force 1000)
desktop/src/features/home/ui/HomeView.tsx
  base                                      994 gate-lines  (cap in force 1000)
```

**Headroom is 1 line, 2 lines and 6 lines.** `APPENDIX-NORMATIVE.md` §6's row
`AppShell.tsx / MessageRow.tsx | 997 / 998 against a hard 1000 cap | wc -l` is
the `wc -l` figure, understates both by one, and names only two of the three
files; §9 below files that as a proposed brief amendment, converged with
`20-TASK-BREAKDOWN.md`'s A-1 so there is one amendment row and not two.

Perch cannot start on any of the three:

- **`MessageRow`.** The seven `swarm:*:v1` markers ride `kind:9` and reach the
  screen through `renderBody`'s `default:` arm, which already content-sniffs
  (`parseWaveMessageContent` at `MessageRow.tsx:415`, predicate
  `content.trimStart().startsWith(WAVE_MESSAGE_MARKER)` at
  `features/messages/lib/waveMessage.ts:15-19`). That arm is 48 lines with one
  line of room above it. `17-COMPONENT-SPECS.md` §3 specifies a registry to put
  there; there is nowhere to put it.
- **`AppShell`.** Every Perch shell change lands here: a new `AppView` member and
  `deriveShellRoute` branch (`AppShell.helpers.ts:5-12`, `:217-268`), the
  governance strip, the `Escape` surface acquisition, the keymap. Two lines.
  `14-CLIENT-ARCHITECTURE.md` commits that "`AppShell.tsx`'s net line delta must
  be ≤ 0 in the commit that adds the chrome conditional (it has 2 gate-lines of
  headroom)". That commitment is measured against the *unsplit* file and is
  correct as written. After AS-1…AS-4 the file has **220** gate-lines of
  headroom, so the constraint is satisfiable without contortion — but it stays
  binding as a fallback if the upstream split has not landed when the chrome
  conditional is written. Both readings are compatible; §11 records which one is
  in force at which point in the build order.
- **`HomeView`.** `/` becomes The Watch, and The Watch is a re-skin of this file,
  not a replacement for it. `00-BRIEF.md` §3 surface 1 gives its Buzz origin as
  "`desktop/src/features/home` (HomeView two-pane, `lib/inbox.ts`,
  `useFeedItemState.ts`, `useResizableInboxListWidth`)" with "four lanes remapped
  from `FeedItemCategory`", and `04-SURFACES-AND-UX.md` §2.1 is explicit:
  "Perch keeps that priority function unchanged; only the labels, sources and
  per-row state change." Six lines does not survive one remapped queue header.

All three files are also the *worst* place to be doing a split under feature
pressure, which is why the splits are their own PRs, offered upstream, before
any Perch code exists.

---

## 3. `AppShell.tsx` — section outline

997 source lines / **998 gate-lines**. One importer in the whole tree:
`BUZZ desktop/src/app/routes/root.tsx:3` (`import { AppShell } from "@/app/AppShell";`),
which is the router's root-route component. Nothing else can observe an internal
change.

| Lines | Count | Section | Disposition |
|---:|---:|---|---|
| 1-106 | 106 | Imports (26 from `@/app/`, 44 from `@/features/`, 9 from `@/shared/`) | shrinks with each extraction |
| 107 | 1 | `const EMPTY_CHANNELS: Channel[] = []` | stays |
| 108-111 | 4 | `export function AppShell()` + three webview hooks | stays |
| 112-128 | 17 | `useCommunities` + the 12-value `useHuddlePresentation` destructure | stays |
| 129-143 | 15 | seven `useState`, one `useRef`, `useLocation`, `useQueryClient` | stays |
| 144 | 1 | `useManagedAgentRuntimeReconciliation` | **→ AS-1** |
| 145-158 | 14 | `useAppNavigation` destructure + `useBackForwardControls` | stays |
| 159-171 | 13 | `deriveShellRoute` memo + `useCommunityNavigationTransitions` | stays |
| 172-180 | 9 | `settingsOpen` + the `settingsSection` derivation | `:174-180` **→ AS-4** |
| 181-190 | 10 | `useDeferredStartup`, identity, mutes, stars | `:181` **→ AS-1** |
| 191-227 | 37 | fifteen background-sync hooks (persona, agents, observer, archive ×4, autoheal, presence, status, emoji, membership) + `useProfileQuery` at `:222` | **→ AS-1** except `:222` |
| 228-249 | 22 | presence session, self status, home feed, channels query, reminders, live feed | stays |
| 250-276 | 27 | error message, relay connection card, `memberChannels`, `sidebarChannels` | stays |
| 277-324 | 48 | the community-destination restore effect + its ref | **→ AS-2** |
| 325-347 | 23 | terminal context override, `useTerminalContext`, `managedChannel` | stays |
| 348-367 | 20 | desktop notifications, thread follows | stays |
| 368-428 | 61 | `useUnreadChannels` (23 destructured values) + `useChannelActivityProjection` | stays |
| 429-471 | 43 | `markAllChannelsRead`, home-feed notification state, reminder badge | stays |
| 472-502 | 31 | `isNotifiedForThread`, follow/unfollow handlers | stays (see §8 follow-up) |
| 504-506 | 3 | two create mutations + `useApplyTemplate` | **→ AS-3** |
| 507-535 | 29 | DM mutations, browse dialog, search focus, join handler | stays |
| 537-620 | 84 | `handleCreateChannel`, `handleCreateForum`, `handleBrowseChannelCreate` | **→ AS-3** |
| 622-646 | 25 | `handleHideDm`, `handleOpenSettings`, `handleCloseSettings` | stays |
| 647-654 | 8 | `handleSettingsSectionChange` + its comment | **→ AS-4** |
| 656-697 | 42 | search-result handler, lifecycle effects, deep links, three shortcut hooks | stays |
| 698-783 | 86 | return JSX down to `AppTopChrome` | stays |
| 784-824 | 41 | the `settingsOpen ? (…) : (` branch | `:785-823` **→ AS-4** |
| 825-953 | 129 | the sidebar + outlet + overlay branch | stays |
| 954-996 | 43 | dialogs, `AppShellOverlays`, feedback controller, closing tags | stays |

**Precedent.** `AppShell.tsx` already delegates to **fifteen** `use*` siblings
under `@/app/` (`:5`, `:15-28`) and **eleven** component/provider siblings
(`:6-14`, `:101`, `:103-106`). Both patterns are house practice; the ground
notes' "the house pattern in `desktop/src/app/` is extracting hooks, not
components" is half right and §9 records the correction. The closest single
precedent is `a9ce477a0 fix(desktop): split AppShell notification effects
(#1248)` — 177 lines out of `AppShell.tsx`, 188 into
`useAppShellDesktopNotifications.ts`, two files touched, nothing else.

---

## 4. `MessageRow.tsx` — section outline

998 source lines / **999 gate-lines**. Four importers, all inside
`features/messages/ui/`:

| Importer | Imports |
|---|---|
| `MessageThreadRow.tsx:3` | `MessageRow` (value) |
| `TimelineMessageRow.tsx:10` | `MessageRow` (value) |
| `MessageThreadPanel.tsx:42` | `ThreadDepthGuideAction` (type) |
| `MessageThreadSummaryRow.tsx:8` | `ThreadDepthGuideAction` (type) |

| Lines | Count | Section | Disposition |
|---:|---:|---|---|
| 1-65 | 65 | imports + two `React.lazy` diff components | shrinks |
| 67-72 | 6 | `export type ThreadDepthGuideAction` | **→ MR-1**, re-exported |
| 74-167 | 94 | `React.memo(function MessageRow({…}: {…})` — 31 props, full type | stays |
| 168-173 | 6 | `isDisplayedAsContinuation`, `expandedDiffId` state | stays |
| 174-197 | 24 | `linkPreviewsSuppressed` + `removeLinkPreviewsForEveryone` | **→ MR-2** |
| 198-243 | 46 | burst emoji, entrance handler, reactions, reminders, send-to-channel | stays |
| 244-247 | 4 | `resolveMentionProps` memo | stays |
| 248-267 | 20 | `useKnownAgentPubkeys`, `isKnownAgentPubkey`, `profilePopoverRole` | stays |
| 268-281 | 14 | `agentMentionPubkeysByName` | **→ MR-2** |
| 282-295 | 14 | `addressedAgentPubkeys`, `agentAddressPrefix` | stays |
| 296-308 | 13 | `imetaByUrl`, `snapshotSharedBy` | **→ MR-2** |
| 310-314 | 5 | `useMessageEmoji`, `bodyOffsetClass` | stays (both values drilled) |
| 315-316 | 2 | `useChannelNavigation` → `channelNames` | **→ MR-2** |
| 318 | 1 | `indentRem` | stays |
| 319-377 | 59 | `descendantGuideOffsetRem`, `replyConnector`, `depthGuideItems`, four collapse handlers, `collapseDepthGuideActionsByDepth` | **→ MR-1** |
| 378-379 | 2 | `getTag` | stays |
| 381-463 | 83 | `renderBody` — `case KIND_STREAM_MESSAGE_DIFF:` `:383`, `case KIND_HUDDLE_STARTED:` `:406`, **`default: {` `:414` … `}` `:461`** | `:414-461` **→ MR-2** |
| 465-467 | 3 | `isThreadReplyLayout`, `guideBleedRem`, avatar radius | `:466` **→ MR-1** |
| 469-549 | 81 | respond-to indicator, avatar node, continuation gutter, avatar gutter | stays |
| 551-602 | 52 | author node, agent owner, action bar | stays |
| 604-678 | 75 | status/inline/persona/continuation metadata, header row | stays |
| 680-723 | 44 | `messageBodyNode` (calls `renderBody()` at `:683`) | stays |
| 725-733 | 9 | outer `<div className="relative">` + indent style | stays |
| 734-884 | 151 | the three guide blocks: depth guides, descendant rail, reply connector | **→ MR-1** |
| 886-931 | 46 | the `<article data-testid="message-row">` | stays |
| 932-934 | 3 | the "callbacks intentionally excluded" comment + closing brace | stays |
| 935-995 | 61 | the `React.memo` comparator | stays, untouched |
| 998 | 1 | `MessageRow.displayName` | stays |

### 4.1 The comparator, counted

**Correction, adjudicated.** The ground notes say "60 explicit prop clauses";
`17-COMPONENT-SPECS.md` §1.5 says 46 clauses over "16 `message.*`, 30 row props".
Measured this session:

```
$ awk 'NR>=935 && NR<=995' MessageRow.tsx | grep -o '&&' | wc -l          → 45   (46 clauses)
$ awk 'NR>=936 && NR<=995' … | grep -oE 'prev\.[A-Za-z.]+' | sort -u | wc -l → 46
$ awk 'NR>=936 && NR<=995' … | grep -oE 'prev\.message\.[A-Za-z]+' | sort -u | wc -l → 18
```

**46 clauses over 46 distinct prop paths, of which 18 are `message.*` and 28 are
row props.** 17's total is right; its 16/30 split is off by two in each direction
because `message.reactions` and `message.tags` appear only inside
`reactionsEqual(…)` and `tagsEqual(…)` (`MessageRow.tsx:956-957`) rather than as
bare `===` clauses. 60 is wrong.

### 4.2 Which props the comparator does *not* compare

Measured, not assumed. Uncompared row props that the split forwards to a child:
`channelId`, `onEdit` (both → `MessageBody`), `showDepthGuides` (→
`MessageThreadGuides`). Also uncompared: `onDelete`, `onReply`,
`onToggleReaction`, `onMarkUnread`, `onMarkRead`, `onFollowThread`,
`onUnfollowThread`, `actionBarPlacement` — the first seven deliberately, per the
comment at `MessageRow.tsx:932-933`.

All three forwarded-but-uncompared props are **already read inside the same
memoized closure today** (`channelId` at `:409`/`:176`/`:449`, `onEdit` at
`:176`, `showDepthGuides` at `:734`/`:829`/`:866`). The extraction therefore
neither introduces nor repairs the gap. Repairing it is a behaviour change and
belongs in a different PR (§8).

### 4.3 Why exactly those five ranges go to `MessageBody`

Each moved derivation's readers, from `grep -n '\b<name>\b' MessageRow.tsx`:

| Value | Defined | Read at | All readers inside `default:`? |
|---|---:|---|:-:|
| `linkPreviewsSuppressed` | 174 | 176, 446 | yes (`:176` is inside `removeLinkPreviewsForEveryone`, which also moves) |
| `removeLinkPreviewsForEveryone` | 175-197 | 449 | yes |
| `agentMentionPubkeysByName` | 268-281 | 452 | yes |
| `imetaByUrl` | 297-300 | 451 | yes |
| `snapshotSharedBy` | 301-308 | 456 | yes |
| `channelNames` | 316 | 430 | yes |
| `customEmoji` | 310 | 450 | yes — but its sibling `emojiOnly` is read at `:314`, so `useMessageEmoji` stays and both values are drilled rather than the hook being called twice |
| `mentionNames` | 244 | 453 | yes — but `mentionPubkeysByName` from the same call is read at `:286`/`:288`, so `resolveMentionProps` stays |
| `isKnownAgentPubkey` | 253-262 | 265, 275, 281, 285, 288, 442 | no — stays and is drilled |

---

## 5. The split — ten commits, each green

Every count below comes from `build/refactor/line-ledger.mjs`, run against BUZZ
at `eed74bde2` this session with every anchor matching — 62 anchored edits, 69
assertions counting the seven `anchorTo` pairs (§1.1). Re-run it after
each commit; a divergence larger than Biome's reflow (±3 gate-lines) means the
extraction departed from the plan, and a non-zero exit means the plan's line
numbers did.

```
$ node build/refactor/line-ledger.mjs

desktop/src/features/messages/ui/MessageRow.tsx
  base                                      999 gate-lines  (cap in force 1000)
  MR-1 extract MessageThreadGuides            795 gate-lines  (-204; 226 lines out of the host file)
  MR-2 extract MessageBody (marker seam)      705 gate-lines  (-90; 111 lines out of the host file)
  headroom after the split                  295 gate-lines

desktop/src/app/AppShell.tsx
  base                                      998 gate-lines  (cap in force 1000)
  AS-1 extract useAppShellBackgroundSync      949 gate-lines  (-49; 60 lines out of the host file)
  AS-2 extract useCommunityDestinationRestore   905 gate-lines  (-44; 53 lines out of the host file)
  AS-3 extract useChannelCreationHandlers     828 gate-lines  (-77; 89 lines out of the host file)
  AS-4 extract AppShellSettingsSurface        780 gate-lines  (-48; 56 lines out of the host file)
  headroom after the split                  220 gate-lines

desktop/src/features/home/ui/HomeView.tsx
  base                                      994 gate-lines  (cap in force 1000)
  HV-1 extract HomeMessagesDetail             849 gate-lines  (-145; 187 lines out of the host file)
  HV-2 extract HomeInboxAuxiliaryPane         785 gate-lines  (-64; 82 lines out of the host file)
  HV-3 extract useHomeInboxFilterChange       752 gate-lines  (-33; 48 lines out of the host file)
  HV-4 extract HomeFeedUnavailable            736 gate-lines  (-16; 22 lines out of the host file)
  headroom after the split                  264 gate-lines

all anchors matched; the ranges above are the ranges in BUZZ.
```

New-file sizes. The six for MR/AS are measured with the same counting function
on the drafts in `build/refactor/`; the four for HV are **budgets, not
measurements**, because those drafts are deliberately not written (§5.5):

| New file | gate-lines | budget | evidence |
|---|---:|---:|---|
| `features/messages/ui/MessageThreadGuides.tsx` | 293 | 1000 | draft written |
| `features/messages/ui/MessageBody.tsx` | 193 | 1000 | draft written |
| `app/useAppShellBackgroundSync.ts` | 96 | 1000 | draft written |
| `app/useCommunityDestinationRestore.ts` | 88 | 1000 | draft written |
| `app/useChannelCreationHandlers.ts` | 121 | 1000 | draft written |
| `app/AppShellSettingsSurface.tsx` | 102 | 1000 | draft written |
| `features/home/ui/HomeMessagesDetail.tsx` | ~200 | 1000 | 187 moved + props/imports |
| `features/home/ui/HomeInboxAuxiliaryPane.tsx` | ~100 | 1000 | 82 moved + props/imports |
| `features/home/useHomeInboxFilterChange.ts` | ~70 | 1000 | 48 moved + signature |
| `features/home/ui/HomeFeedUnavailable.tsx` | ~35 | 1000 | 22 moved + signature |

The six drafts are pre-Biome. Run `just desktop-fix` after each extraction — the
moved JSX in `AppShellSettingsSurface.tsx` in particular carries its old
20-space indentation and will reflow.

---

### MR-1 — `MessageThreadGuides.tsx`

**Responsibility.** The three absolutely-positioned thread-guide layers rendered
under `MessageRow`'s outer `<div className="relative">`: ancestor depth guides
with their optional collapse buttons, the descendant rail with its collapse
button, and the reply connector. Nothing else.

**Exports.** `MessageThreadGuides` (component, 14 props) and
`ThreadDepthGuideAction` (type, moved from `MessageRow.tsx:67-72`).

**Moved out of `MessageRow.tsx`:** `:67-72`, `:319-377`, `:466`, `:734-884` —
226 lines. **Inserted:** 22 (a trimmed `threadTreeLayout` import block, one new
import, one re-export line, a 15-line JSX call). **Net −204.**

**Imports that change.**

| File | Change |
|---|---|
| `MessageRow.tsx:21-29` | the `threadTreeLayout` block drops `getThreadReplyAvatarCenterRem`, `getThreadReplyAvatarCenterYRem`, `getThreadReplyDescendantRailStartYRem`, `getThreadReplyConnectorLayout`, `THREAD_REPLY_LINE_WIDTH_REM`; keeps `getThreadReplyIndentRem` (`:318`) and `threadReplyLength` (`:730`) |
| `MessageRow.tsx` (new) | `import { MessageThreadGuides } from "./MessageThreadGuides";` |
| `MessageRow.tsx` (new) | `export type { ThreadDepthGuideAction } from "./MessageThreadGuides";` |
| `MessageThreadPanel.tsx:42`, `MessageThreadSummaryRow.tsx:8` | **unchanged** — the re-export keeps their specifier valid |

**Tests that move.** None. No `.test.mjs` in the tree imports `MessageRow.tsx`.
`features/messages/lib/threadTreeLayout.test.mjs` tests the geometry helpers and
is untouched.

**Behavioural risk, and what covers it.**

| Risk | Reality | Coverage |
|---|---|---|
| The three blocks stop rendering, or render in the wrong order | The component returns a fragment, so the DOM under the outer `div` is byte-identical | `tests/e2e/thread-unread.spec.ts:137,142,372,377,383,399` and `tests/e2e/thread-reply-anchor-roleplay.spec.ts:210,261,347` assert `thread-collapse-rail`/`thread-collapse-guide` presence *and count*; `tests/e2e/messaging.spec.ts:2994` asserts a guide by `data-thread-head-id`. All in the **smoke** project (`playwright.config.ts` `testMatch`) |
| A collapse click stops reaching its handler | `handleCollapseDepthGuide` and `handleCollapseDescendants` move *with* the JSX; the `preventDefault`/`stopPropagation` pair is unchanged | `thread-unread.spec.ts:108,264` and `thread-reply-anchor-roleplay.spec.ts:147` click by `data-thread-head-id` and assert the row set changes |
| Hover/focus highlight breaks | The four hover callbacks move with the JSX | `thread-unread.spec.ts:137-142` (rail + guide scoped to a hovered summary) |
| Memo defeated by an unstable prop | Every forwarded prop is either already comparator-compared or already read uncompared in the same closure — §4.2 | **Nothing executing.** `virtualization.spec.ts` is smoke and would catch a gross rendering regression only; `typing-latency.perf.ts` is registered in **neither** Playwright project (§8.1) and never runs. No spec in the suite asserts render counts. This is the one risk the plan argues rather than tests, and it says so |

**New test needed.** One, and it is cheap. The repository already has a
component-unit pattern: `.test.mjs` importing a `.tsx` through
`desktop/test-loader-hooks.mjs` (a TypeScript-transpiling ESM loader) and
asserting on `renderToStaticMarkup` output — see
`BUZZ desktop/src/features/sidebar/ui/MoreUnreadButton.test.mjs:1-12`.
`MessageThreadGuides` is pure (no context, no Tauri, no query client), so:

`BUZZ desktop/src/features/messages/ui/MessageThreadGuides.test.mjs` — assert
that for `depth: 3` with one `collapseDepthGuideActions` entry the markup
contains exactly two non-interactive guide `div`s plus one
`data-testid="thread-collapse-guide"` button carrying the action's
`data-thread-head-id`; that `showDepthGuides: false` renders empty; and that
`connectDescendants: false` renders no `thread-collapse-rail`. ~90 lines. This
is the only *new* mechanical protection the split adds, and it is worth having
because the E2E assertions are all "at least one exists" rather than "the right
number exist".

---

### MR-2 — `MessageBody.tsx` (the seam)

**Responsibility.** The body of one conversation row for every kind
`renderBody` has no explicit `case` for: today, the wave-marker sniff and the
markdown fallthrough, plus the five derivations only they read.

**Exports.** `MessageBody` (component, 15 props).

**Moved out of `MessageRow.tsx`:** `:174-197`, `:268-281`, `:296-308`,
`:315-316`, `:414-461` — 111 lines. **Inserted:** 21 (one replacement import,
a 19-line JSX call, `default:` without a block). **Net −90.**

**Imports that change.**

| `MessageRow.tsx` line | Symbol | Action |
|---:|---|---|
| 34 | `getConfigNudgeAuthorPubkey` | delete |
| 38 | `useChannelNavigation` | delete |
| 39 | `parseImetaTags` | delete |
| 41 | `parseWaveMessageContent` | delete |
| 42 | `resolveSnapshotSharedBy` | delete |
| 45 | `VideoReviewCommentMarkdown` | delete |
| 47 | `editMessage` | delete |
| 48 | `hasLinkPreviewSuppression` | delete |
| 49 | `toast` | delete |
| 58 | `WaveMessageAttachment` | replace with `import { MessageBody } from "./MessageBody";` |

`import type { VideoReviewContext }` at `:44` and `cn` at `:35` stay — both
still have readers in `MessageRow`.

**One correctness trap, and the reason the draft file exists.**
`resolveSnapshotSharedBy(message, profiles)`
(`features/messages/lib/snapshotSharedBy.ts:8-11`) declares its second parameter
**optional** — `profiles?: UserProfileLookup` at `:10`. It is a pure lookup
helper called from the message body inside the renderer; with the argument it
resolves a pubkey to a display label, without it it returns the raw pubkey. So
dropping it in the move is **not** a `tsc` error, produces no warning, and
silently degrades attachment provenance on every wave attachment — and *nothing
in the suite would fail*. `profiles` is therefore a `MessageBody` prop. This is
the single reason the six drafts are written out rather than described.

**Tests that move.** None move. Two need a comment update, not a code change:

- `features/messages/ui/configNudgeAuthPubkey.test.mjs` — tests
  `getConfigNudgeAuthorPubkey`, whose production caller moves from
  `MessageRow.tsx:440-443` to `MessageBody.tsx`. The test does not import
  `MessageRow`; only its doc comment names it.
- `features/messages/lib/useMessageEmoji.test.mjs` — same shape.

**Behavioural risk, and what covers it.**

| Risk | Reality | Coverage |
|---|---|---|
| A wave message stops rendering as an attachment | `parseWaveMessageContent` + `WaveMessageAttachment` move verbatim; the only producer is `features/profile/ui/useProfileInteractionActions.ts:18` | No dedicated spec exists. **Gap** — see below |
| Markdown body loses a prop (18 props are threaded) | All 18 survive; `profiles` is added as a 19th input so `snapshotSharedBy` still resolves | `tests/e2e/mentions.spec.ts` (mention chips, `mentionNames`/`mentionPubkeysByName`/`agentMentionPubkeysByName`), `custom-emoji.spec.ts` (`customEmoji`), `spoiler.spec.ts`, `entity-link-recipient-cards.spec.ts` (`channelNames`), `image-attachment-gallery.spec.ts` (`imetaByUrl`), `config-bridge-screenshots.spec.ts` (`configNudgeAuthorPubkey`), `thread-head-stale-edit.spec.ts` (`message-body` content) — all in **smoke** |
| Emoji-only large-render breaks | `emojiOnly` drives both `bodyOffsetClass` (stays) and the `text-4xl` class (moves); both read the same value | `custom-emoji-ui.spec.ts:77`, `custom-emoji.spec.ts:206,259,513,566` |
| "Remove previews for everyone" stops working | The callback and its `toast.error` move together | No dedicated spec. **Gap** |
| `useChannelNavigation` moves one level down, so `MessageRow` stops subscribing to that context and `MessageBody` starts | Fewer `MessageRow` re-renders on a channel-name change — an improvement, but a render-count change, not a no-op | `entity-link-recipient-cards.spec.ts:124,427,491` renders channel-link chips inside message rows |

**New tests needed.** Two, both small, both closing a real gap rather than
re-testing the move:

1. `features/messages/lib/waveMessage.test.mjs` — a table test over
   `parseWaveMessageContent`: exact marker at line 0, marker after leading
   whitespace, marker mid-body (must not match today's predicate — it does,
   because `startsWith` runs after `trimStart`, so record the current behaviour
   honestly), empty trailer → the default fallback string. ~60 lines. It exists
   for the same reason the registry hardens the sniff (§6): the predicate is a
   `startsWith` over adversary-reachable body text and today nothing pins it.
2. A `message-body` assertion in the existing
   `tests/e2e/message-feedback-snapshots.spec.ts` covering the
   remove-previews-for-everyone control, if a mock fixture makes it reachable.
   Optional; if it is not cheap, record the gap rather than faking coverage.

---

### AS-1 — `useAppShellBackgroundSync.ts`

**Responsibility.** Mount every community-scoped background sync the shell owns
and return the startup-deferred pubkey. Fifteen hooks, none of which returns a
value the shell's JSX reads except `deferredPubkey`.

**Exports.** `useAppShellBackgroundSync({ communities, pubkey, relayUrl })
→ { deferredPubkey }`.

**Moved out:** `:144` (`useManagedAgentRuntimeReconciliation`), `:181`
(`useDeferredStartup`), `:191-221` (persona sync, agents refresh, auto-restart,
observer ingestion, observer archive reconciliation, archive sync, archive
metrics bridge, `deferredPubkey`, metric archive seed — with all five explanatory
comment blocks), `:223-227` (relay auto-heal, presence subscription, user-status
subscription, community emoji live updates, membership notifications) — 60 lines.
**Inserted:** 11 (5-line call + 6 net import lines). **Net −49.**

**Imports that change.** Fifteen import statements leave `AppShell.tsx`
(`:39`, `:48-52`, `:64-68`, `:93-94`), two shrink (`:55-58` → one line keeping
`usePresenceSession`; `:59-63` → four lines keeping `useSetUserStatusMutation`
and `useUserStatusQuery`), one arrives.

**Behavioural risk.**

| Risk | Reality | Coverage |
|---|---|---|
| **Hook-order change.** `useProfileQuery` (`:222`) stays in `AppShell` and now runs *after* the block instead of inside it | React requires order stability across renders, not a particular order. None of the fifteen reads or writes the profile query's cache entry | `tests/e2e/boot-splash.spec.ts` (**smoke**, per-commit) plus `tests/e2e/profile.spec.ts` and `tests/e2e/onboarding.spec.ts` (**integration** — needs a live relay; §8.1) |
| An effect stops mounting | All fifteen move as a contiguous block in their original order | `tests/e2e/local-archive-screenshots.spec.ts` (archive sync), `tests/e2e/observer-feed-screenshots.spec.ts` (observer ingestion), `tests/e2e/relay-reconnect.spec.ts` + `relay-connectivity.spec.ts` (auto-heal), `tests/e2e/custom-emoji.spec.ts` (emoji live updates), `tests/e2e/profile-active-turn.spec.ts` (observer liveness) — all smoke |
| `deferredPubkey` becomes `undefined` for its three shell readers (`:228`, `:230`, `:232`) | It is the hook's return value, computed identically | `tests/e2e/badge.spec.ts` (**smoke**); `tests/e2e/profile.spec.ts` (**integration**, self status) |

**New test needed.** None. This is the shape `useAppShellDesktopNotifications.ts`
(#1248) landed in with no unit test; the coverage is the smoke suite.

---

### AS-2 — `useCommunityDestinationRestore.ts`

**Responsibility.** Restore the channel a community was last viewed on, exactly
once per mount, only for an explicit community transition.

**Exports.** `useCommunityDestinationRestore({ activeCommunityId, channelsQuery,
goChannel, goHome, selectedView, sidebarChannels })`.

**Moved out:** `:277-324` (the `hasRestoredCommunityDestinationRef` ref, the
effect, and its three comment blocks) — 48 lines plus the 5-line import block
`:84-88`. **Inserted:** 9. **Net −44.**

**Imports that change.** `consumePendingCommunityRestore`,
`loadCommunityDestination`, `saveCommunityDestination` leave `AppShell.tsx`;
one import arrives.

**Behavioural risk.**

| Risk | Reality | Coverage |
|---|---|---|
| The one-shot ref resets, so restore fires on every render | The ref moves *with* the effect into the same hook; a `useRef` in a custom hook has the same per-mount lifetime | `tests/e2e/community-rail.spec.ts`, `tests/e2e/navigation.spec.ts:212,242,265,327` |
| Restore fires on cold boot instead of only on a community switch | `consumePendingCommunityRestore` is unchanged and is still the gate | `tests/e2e/boot-splash.spec.ts` (**smoke**); `tests/e2e/onboarding.spec.ts` (**integration**) |
| The dependency array drifts | It moves verbatim; the only renamed identifier is `communitiesHook.activeCommunity?.id` → `activeCommunityId` | `just desktop-check` runs Biome's `useExhaustiveDependencies` |

**New test needed.** None new for the move. Worth noting for `20-TASK-BREAKDOWN.md`:
this hook is the natural home for a future `.test.mjs`, because after extraction
its whole contract is expressible as a fake `channelsQuery` plus spy `goChannel`/
`goHome` — which it was not while it lived inside a 998-line component.

---

### AS-3 — `useChannelCreationHandlers.ts`

**Responsibility.** Stream/forum creation, template application, and the
browse-dialog fan-out between the two.

**Exports.** `useChannelCreationHandlers({ browseDialogType, getCreateSuccess,
goChannel }) → { handleBrowseChannelCreate, handleCreateChannel,
handleCreateForum, isCreatingChannel, isCreatingForum }`.

**Moved out:** `:504-506` (two `useCreateChannelMutation` calls and
`useApplyTemplate`), `:537-620` (`handleCreateChannel`, `handleCreateForum`,
`handleBrowseChannelCreate` and the routing comment at `:598-599`) — 87 lines,
plus one import line. **Inserted:** 12. **Net −77.**

**Same-line edits, zero line delta, easy to forget:** `AppShell.tsx:837`,
`:838`, `:963`, `:964` read `createChannelMutation.isPending` /
`createForumMutation.isPending` and become `isCreatingChannel` /
`isCreatingForum`. Returning booleans rather than the mutation objects is
deliberate — a React Query result is a **new object every render**
(`BUZZ CLAUDE.md` gotcha 6), so handing one across the boundary would make
`AppSidebar`'s props unstable.

**Imports that change.** `useCreateChannelMutation` leaves the
`@/features/channels/hooks` block (`:33`); `useApplyTemplate` (`:90`) is replaced
by the new hook's import.

**Behavioural risk.**

| Risk | Reality | Coverage |
|---|---|---|
| **Hook-order change.** The two create mutations and `useApplyTemplate` now run after `useOpenDmMutation`/`useHideDmMutation` and after `useChannelBrowserDialog` | All are React Query mutations or ref-holding hooks with no cross-dependency; the new hook must be called *after* `useChannelBrowserDialog` because it consumes `browseDialogType` and `getCreateSuccess` | `tests/e2e/channel-browser.spec.ts`, `tests/e2e/channels.spec.ts:419,555,808` |
| A create no longer applies its canvas/agents template | `applyCanvas`/`applyAgents` move with the handlers, in order, `await` semantics unchanged (`applyCanvas` awaited, `applyAgents` fired with `void`) | `tests/e2e/channel-add-screenshots.spec.ts`, `tests/e2e/channel-browser.spec.ts` |
| The forum-vs-stream routing at `:600-620` inverts | Moves verbatim, including the comment explaining it | `tests/e2e/channel-browser.spec.ts` covers both sections |
| Pending spinners stop showing | Four same-line substitutions; a missed one is a `tsc` error, not a silent bug | `just desktop-typecheck` |

**New test needed.** One, cheap, and it pays for itself: a
`app/useChannelCreationHandlers.test.mjs` asserting that
`handleBrowseChannelCreate` routes to `handleCreateForum` when
`browseDialogType === "forum"` and to `handleCreateChannel` otherwise, and that
the latter passes `getCreateSuccess()`'s callback through. Pure logic over spies;
~80 lines. Today that branch has only end-to-end coverage.

---

### AS-4 — `AppShellSettingsSurface.tsx`

**Responsibility.** The full-window Settings surface the shell swaps in for
`/settings`, plus the `?section=` derivation and the replace-navigation that
keeps one history entry per visit.

**Exports.** `AppShellSettingsSurface({ currentPubkey, fallbackDisplayName,
locationSearch, notificationSettings, onClose })`.

**Moved out:** `:174-180` (the `settingsSection` derivation), `:647-654`
(`handleSettingsSectionChange` + its two-line comment), `:785-823` (the JSX,
including the `React.Suspense` boundary and `LazySettingsScreen`'s fourteen
props) — 54 lines, plus one import line and one import-block member.
**Inserted:** 8. **Net −48.**

What stays in `AppShell`: `settingsOpen` (`:173`, read at `:455`, `:678`,
`:689`, `:775`, `:784`), `handleOpenSettings` (`:636-642`, passed to
`AppShellProvider:744`, `AppSidebar:891` and `useSettingsShortcuts:688`) and
`handleCloseSettings` (`:643-646`, also read by `useSettingsShortcuts:687`).

**Imports that change.** `isSettingsSection` leaves the `SettingsPanels` block
(`:74`); `DEFAULT_SETTINGS_SECTION` and the `SettingsSection` type stay because
`handleOpenSettings`'s signature still uses them. `LazySettingsScreen` (`:106`)
is replaced by the new component's import.

**Behavioural risk.**

| Risk | Reality | Coverage |
|---|---|---|
| Settings renders at the wrong place in the tree | `AppShellSettingsSurface` renders exactly where the extracted `div` was, inside the same `AppWorkflowEditorOverlayProvider`; the outlet is still unmounted for `/settings` | `tests/e2e/hosted-communities-settings-screenshots.spec.ts`, `tests/e2e/invites-settings-screenshots.spec.ts`, `tests/e2e/voice-settings.spec.ts`, `tests/e2e/doctor-cta-screenshots.spec.ts` — all smoke, all screenshot-diffing the surface |
| Section switching starts stacking history entries | `{ replace: true }` moves with the callback | `tests/e2e/navigation.spec.ts` back/forward assertions |
| The retired `?section=doctor` rewrite breaks | That lives in `routes/settings.tsx:24-27`'s `validateSearch`, not here — untouched | `tests/e2e/doctor-cta-screenshots.spec.ts` |
| `notificationSettings` is passed as one object, so its identity churns | It is already a single object from `useHomeFeedNotifications` (`AppShell.tsx:233`); `LazySettingsScreen` is not memoized, so identity was never load-bearing | — |

**New test needed.** None. The four settings screenshot specs are the coverage,
and they diff pixels.

**Why this commit matters beyond the line count.** `APPENDIX-NORMATIVE.md` §1
marks `/settings` Phase 0 with "must become a real route before the first new
surface." **Correction:** `/settings` *is* already a real route
(`app/routes.ts:8`, `app/routes/settings.tsx:24-27`). The unfinished work is
that it does not render through the router outlet — `AppShell.tsx:173` and
`:784-823` unmount the outlet and render the surface at shell level, which is
why `routes/settings.tsx:33-35` returns `null`. After AS-4, moving that surface
into the outlet is an edit to one 102-line file plus a route file, not a shell
rewrite. AS-4 does **not** do the move; it makes it a small change instead of a
large one. Perch's Phase 0 owns the move, and `20-TASK-BREAKDOWN.md` owns its
sequencing.

---

### 5.5 `HomeView.tsx` — HV-1 … HV-4

**This section is the correction the red team's systemic finding asked for.**
The first draft of this file put `HomeView.tsx` in §7.1 with the verdict "new
file — The Watch is not an edit to `HomeView`", while `20-TASK-BREAKDOWN.md`
task **P0-13** independently added a 0.5-ew task to split it. Neither producer
read the other. Re-checking the brief settles it against this file: `00-BRIEF.md`
§3 surface 1 gives The Watch's Buzz origin as `desktop/src/features/home` and
says its four queues are "remapped from `FeedItemCategory`"; `04-SURFACES-AND-UX.md`
§2.1 says "Perch keeps that priority function unchanged; only the labels, sources
and per-row state change." **P0-13 is right and §7.1 was wrong.** The split is
planned here so that the plan and the task card describe the same work.

**993 source lines / 994 gate-lines** — the ordinary `wc -l` + 1 of §1. One
importer:
`BUZZ desktop/src/features/home/ui/HomeScreen.tsx:7`, and `HomeScreen` is what
`app/routes/index.tsx:6,94` renders for `/`.

#### The ordering principle

The four steps are ordered by **what F1 does to each block**, not by size. That
is what makes the split worth doing before the rewrite rather than during it:

| Step | Block | What F1 (`20-TASK-BREAKDOWN.md` P1-14) does to it |
|---|---|---|
| HV-1 | messages detail pane | **deletes** — the Verdict Row is a different component in a different feature directory |
| HV-2 | auxiliary pane (profile + channel management) | **keeps unchanged** |
| HV-3 | filter-change selection logic | **rewrites** — four Buzz categories become four Perch queues |
| HV-4 | feed-unavailable pane | **rewrites** — `06` §5.3's copy replaces it |

#### The scope analysis, measured

Every value below was checked for readers outside its block before being
planned into it (`grep -n '\b<name>\b' HomeView.tsx`, whole file):

| Value | Defined | Read at | Verdict |
|---|---:|---|---|
| `latchedDefaultParentId` | 263-267 | 799 | → HV-1 |
| `toggleReactionMutation` | 293 | 898 | → HV-1 |
| `editMessage` / `isEditingMessage` | 306-309 | 822 / 793 | → HV-1 |
| `unreadBoundaryEventId` | 485-491 | 803 | → HV-1 |
| `selectedItemReplies` | 505-511 | 916 | → HV-1 |
| `canDelete` / `canReact` / `canReply` / `disabledReplyReason` | 608-613 | 785, 787, 791, 814, 834, 896 | → HV-1 |
| `profilePanelTab` / `profilePanelView` | 153-158 | 955 / 957 | → HV-2 |
| `handleProfilePanelViewChange` / `…TabChange` | 199-214 | 952 / 951 | → HV-2 |
| `handleCloseProfilePanel` | 192-198 | **819** and 948 | **stays** — read by both children, passed as a prop to each |
| `isDeletingMessage` / `isSendingReply` / `editTargetId` | 215-218 | 792 / 794 / 804 | **stays** — their setters are read by the reset effect at `:527-533` and the delete dialog at `:650-652`, so the state cannot move without them |
| `contextMessages` | 492-504 | 509, 511, 800 | **stays** — also feeds `selectedItemReplies`' dependency list |

Imports that become unused, per step, computed the same way: HV-1 nine
(`formatInboxFullTimestamp`, `useInboxEditMessage`, `getHomeMessageCapabilities`,
`useToggleReactionMutation`, `formatTime`, `splitOutgoingTags`,
`getThreadReference`, `resolveUserLabel`, `sendChannelMessage`) plus
`InboxDetailPane`; HV-2 five (`RightAuxiliaryPane`, `ChannelManagementSheet`,
`UserProfilePanel`, `profilePanelTabFromSearch`, `profilePanelViewFromSearch`)
plus the two `ProfilePanel*` types in the same block; HV-3 one
(`resolveInboxFilterSelection`); HV-4 two (`RefreshCcw`, `Button`).

#### Behavioural risk

| Risk | Reality | Coverage |
|---|---|---|
| The detail pane stops rendering, or renders with a stale conversation | The `{showDetailPane && detailMode === "messages" ? … : null}` guard moves with the block; the component is rendered in the same grid cell | The smoke specs that navigate to `/` and open a detail row |
| A reply/edit/delete/react handler loses its closure | The five inline handlers move with the JSX; the four pieces of state they set stay in `HomeView` and arrive as setter props, which is what keeps the reset effect at `:527-533` correct | `just desktop-typecheck` catches a dropped setter; the handlers themselves are covered end to end |
| The profile panel stops opening from a message row | `ProfilePanelProvider` and `handleOpenProfilePanel` stay in `HomeView` (`:647`); only the *pane* moves | `entity-link-recipient-cards.spec.ts`, `profile-active-turn.spec.ts` (both smoke) |
| Filter change stops preserving the selected row | `resolveInboxFilterSelection` is unchanged and moves with the callback; the hook wraps the same `useCallback` in the same position | `lib/inboxSelection.test.mjs` tests the pure function directly and does not move |
| The four inbox queues change meaning | They do not: `matchesInboxFilter` (`lib/inboxViewHelpers.ts:41`) and `buildInboxItems` (`lib/inbox.ts:462`) are untouched | `lib/inboxViewHelpers.test.mjs`, `lib/inbox.test.mjs` |

#### Two corrections to P0-13's acceptance criteria

1. **"The four inbox queues are produced by a pure function in `lib/` that takes
   feed items and returns queue membership."** That already exists.
   `matchesInboxFilter(item, filter, ownedAgentPubkeys)` is exported at
   `BUZZ desktop/src/features/home/lib/inboxViewHelpers.ts:41` and tested at
   `lib/inboxViewHelpers.test.mjs`; `buildInboxItems` (`lib/inbox.ts:462`) sets
   `isActionRequired: categories.includes("needs_action")` at `:615` and is
   tested at `lib/inbox.test.mjs`. The only piece that is *not* exported is
   `categoryPriority` (`lib/inbox.ts:326-337`, a module-private `function`), and
   `04` §2.1 says Perch keeps it unchanged, so it does not need to be. P0-13's
   second acceptance criterion asks for work that is done; the honest remaining
   criterion is the line count plus the four seams above.
2. **"`HomeView.tsx` is under 700 gate-lines."** The measured four-step split
   lands at **736**, with 264 lines of headroom — more than `AppShell` gets
   (220) and comparable to `MessageRow` (295). Reaching 700 needs a fifth
   extraction, and the only block big enough is the list-pane call site
   (`:692-758`, 67 lines) or the pane resize handle (`:759-780`, 22). Those are
   precisely the blocks F1 rewrites in place, so extracting them now means
   extracting them twice. **Proposed replacement criterion: `HomeView.tsx` is at
   or below 750 gate-lines and the four seams above exist.** 700 is a round
   number; 264 lines of headroom is an argument.

---

## 6. Step MR-3 / P-1 — the marker-renderer registry extraction

This is the step Perch depends on, and it is deliberately **not** in the upstream
PR. MR-1 and MR-2 are pure-refactor changes that block/buzz benefits from on
their own merits. MR-3 adds Perch code and lands in the Perch branch, after the
upstream split has merged (or after it is cherry-picked, if upstream is slow —
§8).

### 6.1 What MR-2 leaves behind

After MR-2, `MessageBody.tsx` has this shape:

```tsx
// 1. derivations                       (moved from MessageRow, verbatim)
// 2. const waveMessage = parseWaveMessageContent(message.body);
//    if (waveMessage) return <WaveMessageAttachment … />;
// ◀── THE SEAM
// 3. return <VideoReviewCommentMarkdown … />;
```

The seam is one insertion point between the wave sniff and the markdown
fallthrough. It is where `default:` already content-sniffs today, which is the
shipped precedent that makes seven `kind:9` markers cost **zero** of
`APPENDIX-NORMATIVE.md` §3's four client registration points — those four are
the cost of the `46010` fork, not of a marker.

### 6.2 The interface — the three symbols that cross the seam

`17-COMPONENT-SPECS.md` §3 owns the registry's types, its seven presenters, its
four refusal cards and its `AmbushCardContext`. **This file owns the seam, and
therefore pins exactly three symbols.** Both peers — `17-COMPONENT-SPECS.md` and
`14-CLIENT-ARCHITECTURE.md` — bind to these names and signatures; nothing else
crosses.

```ts
// The parse. Pure, no React, no context, no I/O.
//   BUZZ desktop/src/features/perch-evidence/lib/parseAmbushMarker.ts
import type { AmbushMarkerParse } from "./markerTypes";

export function parseAmbushMarker(args: {
  /** The raw event content. Adversary-reachable text; treat as hostile. */
  body: string;
  /**
   * The RAW EVENT SIGNER — `TimelineMessage.signerPubkey`, never `pubkey`.
   * `pubkey` may be a relay-delegated display author; admission is a signature
   * question. Buzz already draws this distinction for the same reason in
   * `features/messages/ui/configNudgeAuthPubkey.ts`.
   */
  signerPubkey: string | undefined;
  /** Content-equality-cached membership test; see the memo note below. */
  isAdmittedIssuer: (signerPubkey: string) => boolean;
  /** The `h` tag, for the INV-13 channel check the dispatcher performs. */
  channelTag: string | null;
  createdAt: number;
}): AmbushMarkerParse;
```

```tsx
// The render. One component, one dispatch.
//   BUZZ desktop/src/features/perch-evidence/ui/ambushCardRegistry.tsx
export function AmbushEvidenceCard(args: {
  card: AmbushMarkerCard;
  ctx: AmbushCardContext;
}): React.ReactElement;
```

The third symbol is a convenience hook this file **decides**, because the seam is
where it is consumed. `useAmbushCardSurface()` is a thin read over the two
contexts `17-COMPONENT-SPECS.md` §3.3/§3.7 already specify —
`AmbushCardContext` (the five-field presenter context) and its sibling
`AmbushAdmissionContext` (which holds `isAdmittedIssuer`) — plus one derivation,
`channelTagOf`, which reads the `h` tag off `message.tags`:

```ts
//   BUZZ desktop/src/features/perch-evidence/AmbushCardContext.tsx
export function useAmbushCardSurface(): {
  ctx: AmbushCardContext;
  isAdmittedIssuer: (signerPubkey: string) => boolean;
  channelTagOf: (message: TimelineMessage) => string | null;
} | null;
```

**It returns `null` when neither provider is mounted.** That is what makes MR-2
upstream-safe as a permanent no-op in a plain Buzz build: the seam compiles, the
branch is never taken, and there is one `if` between the wave sniff and the
markdown path. Nothing about `17`'s two-context design changes; this hook exists
so `MessageBody` performs one context read rather than three.

And the seam itself, which is the whole of MR-3's edit to Buzz-owned code —
**one import, one hook read, eleven lines**:

```tsx
  // ── the Perch seam ──────────────────────────────────────────────────────
  const ambush = useAmbushCardSurface();          // null outside Perch builds
  if (ambush) {
    const parsed = parseAmbushMarker({
      body: message.body,
      signerPubkey: message.signerPubkey,
      isAdmittedIssuer: ambush.isAdmittedIssuer,
      channelTag: ambush.channelTagOf(message),
      createdAt: message.createdAt,
    });
    if (parsed.status !== "not-a-marker" && parsed.status !== "unadmitted-issuer") {
      return <AmbushEvidenceCard card={parsed.card} ctx={ambush.ctx} />;
    }
  }
```

### 6.3 Five rules the seam imposes, and why each is here and not in `17`

1. **`MessageRow` gains zero props.** Everything the registry needs arrives
   through `useAmbushCardSurface()`, a context read inside `MessageBody`.
   `MessageRow`'s 46-clause comparator (`MessageRow.tsx:935-995`) is never
   touched — which is the difference between the timeline staying memoized and
   every row in an open case re-rendering on every streamed event
   (`BUZZ CLAUDE.md` gotcha 6). A presenter that needs a sixth context field is
   a one-file `useMemo` widening; a presenter that needs a `MessageRow` prop is a
   spec bug.
2. **`isAdmittedIssuer` must be reference-stable.** It comes from a `useMemo`
   over the admitted-issuer set keyed on that set's own version counter, wrapped
   in `BUZZ desktop/src/shared/hooks/useStableReference.ts` — the content-equality
   ref cache `CLAUDE.md` gotcha 6 names for exactly this class. A fresh function
   per render defeats `agentMentionPubkeysByName`'s memo in the same file, which
   already depends on `isKnownAgentPubkey`.
3. **The sniff is hardened relative to the wave precedent.**
   `parseWaveMessageContent` matches `content.trimStart().startsWith(MARKER)`
   (`waveMessage.ts:15-19`) — leading whitespace is tolerated and nothing checks
   the author. `parseAmbushMarker` requires the marker to be **the entire first
   line** and requires `isAdmittedIssuer(signerPubkey)` to hold. Both tightenings
   are here rather than in `17` because they are properties of the *seam* — the
   thing an adversary reaches — not of any one card.
4. **An unadmitted issuer renders nothing of its own.** `parseAmbushMarker`
   returns `unadmitted-issuer`, the seam falls through to the prose path, and a
   counter increments. It must not render a refusal card, because a refusal card
   is a signal an adversary can plant at will.
5. **An admitted, well-formed marker never reaches the markdown pipeline.**
   Falling through would push a payload containing host ids, file paths and
   command lines into `shared/ui/markdown.tsx`'s remark pipeline — which is
   1,906 gate-lines and **frozen** (§7), so it could not be hardened in response
   even if someone wanted to.

### 6.4 The build order that follows

MR-3 is the **first** Perch client commit. It cannot precede MR-2, and no
evidence-card work — no presenter, no `EvidenceCardFrame`, no refusal card — can
precede MR-3, because until the seam exists there is nothing to register with.
`20-TASK-BREAKDOWN.md` owns the rest of the ordering; this is the one edge it
must not reorder.

**HV-1…HV-4 are not on this edge.** They are PR B (§8), they contain no Perch
code, and nothing in the registry path depends on them. The only work that
blocks on them is F1 (`20-TASK-BREAKDOWN.md` P1-14), the rewrite of `HomeView`
into The Watch. So the two upstream PRs can be reviewed in either order, and a
stall on PR B delays one Phase-1 surface rather than the whole evidence path.
That separation is the reason §8 splits them.

---

## 7. Everything else near the cap

Re-runnable:

```
$ node build/refactor/near-cap-survey.mjs --threshold 950
governed files at or above 950 gate-lines: 86  (FROZEN 22 · AT-CAP 7 · TIGHT 57)
```

86 files across desktop, web and mobile. The survey script self-verifies its
rule roots against all three check scripts and throws if a project adds a
governed root it does not know about, so this number can be re-derived rather
than taken on faith.

### 7.1 The ones on Perch's path

Only these matter. Everything else at 950+ is somebody else's problem until
Perch touches it.

| File | gate-lines | State | Why Perch touches it | Verdict |
|---|---:|---|---|---|
| `features/messages/ui/MessageRow.tsx` | 999 | TIGHT (1) | the marker seam | **split — MR-1/MR-2** |
| `app/AppShell.tsx` | 998 | TIGHT (2) | governance strip, keymap, `Escape` surface, `AppView` | **split — AS-1…AS-4** |
| `shared/ui/markdown.tsx` | 1906 | FROZEN | evidence cards render prose through it | **never edit.** Any Perch change to the shared markdown renderer must be net-negative, which in practice means: don't. Render evidence payloads with dedicated components, never by extending remark |
| `shared/api/tauri.ts` | 1108 | FROZEN | the renderer↔Rust command surface Perch's five write commands join | **new sibling file.** `tauriPerch.ts` (the name `14-CLIENT-ARCHITECTURE.md` ships a skeleton for) imports `invokeTauri` from `./tauri`; eight existing siblings do exactly this (`tauriEvents.ts`, `tauriMesh.ts`, `tauriChannelHeadCache.ts`, `tauriAcpDiscovery.ts`, `tauriManagedAgentMessageMarkers.ts`, `communityProfile.ts`, `forum.ts`, `osIdle.ts`). **The command count is `14-CLIENT-ARCHITECTURE.md`'s to state, not this file's** — its amendment A12 measures 256 distinct literals (206 `invokeTauri` + 56 raw `invoke`, 6 shared) across 57 files, correcting the appendix's 205. An independent sweep here with a broader regex (one that also opens `src/testing`) lands higher; the two disagree on scope, not on the disposition, and shipping a third number is how the wave got sixteen private registries. Cite A12. |
| `shared/api/relayClientSession.ts` | 1084 | FROZEN | the `26000`–`26006` ephemeral subscriptions | **new sibling file.** `perchSubscriptions.ts` (`14-CLIENT-ARCHITECTURE.md`'s skeleton name) wraps the public `subscribeLive` (`:410-417`); do not add a method to the class |
| `shared/api/types.ts` | 1000 | AT-CAP | Perch's shared types | **new sibling files.** `perchKeys.ts` and `perchEphemeralStore.ts` per `14-CLIENT-ARCHITECTURE.md`; **wire** types (the decoders and their zod schemas) do not land here at all — `13-WIRE-SCHEMAS.md` commits them to `features/perch/wire/`, and this row is the reason |
| `shared/ui/sidebar.tsx` | 1011 | FROZEN | `05` §9 lists it reuse-verbatim; `SIDEBAR_WIDTH_DEFAULT = 300` at `:31` | **reuse only.** Perch may not add a variant here |
| `features/search/ui/TopbarSearch.tsx` | 1000 | AT-CAP | the `Cmd-K` omnibox is the Ledger overlay's host | **new file.** `PerchOmnibox.tsx`. This one is not in any plan document's frozen list and would have been discovered at the worst moment |
| `features/channels/useUnreadChannels.ts` | 999 | TIGHT (1) | The Watch's row read-state (`M`/`U` are localStorage-only, never a decision record) | **do not edit.** Perch's row read-state is its own module |
| `features/channels/readState/readStateManager.ts` | 999 | TIGHT (1) | same | **do not edit** |
| `features/channels/hooks.ts` | 998 | TIGHT (2) | case channels are Buzz channels | **new sibling.** `features/perch-cases/hooks.ts` |
| `features/channels/ui/ChannelPane.tsx` | 998 | TIGHT (2) | the Case surface reuses the channel pane | **wrap, don't edit.** If a Perch-specific pane behaviour is unavoidable, it is a new component that composes this one |
| `features/channels/ui/ChannelScreen.tsx` | 996 | TIGHT (4) | same | **wrap, don't edit** |
| `features/profile/ui/UserProfilePanel.tsx` | 999 | TIGHT (1) | `PubKey` `full` variant on security-decision surfaces | **do not edit** |
| `features/home/ui/HomeView.tsx` | 994 | TIGHT (6) | `/` becomes The Watch, and The Watch is a **re-skin of this file** (`00-BRIEF.md` §3 surface 1, `04-SURFACES-AND-UX.md` §2.1) | **split — HV-1…HV-4 (§5.5).** A previous draft of this row said "new file, do not edit `HomeView`". That was wrong, and it contradicted `20-TASK-BREAKDOWN.md` P0-13, which was right. 994 → 736 |
| `features/messages/ui/MessageComposer.tsx` | 977 | TIGHT (23) | the case composer | **new file if anything is needed;** 23 lines is one small prop, not a feature |
| `shared/styles/globals/theme.css` | 968 | TIGHT (32) | the Perch palette | **32 lines is not a palette**, and `19-TOKENS.md` already routes around it: the tokens land as a new governed stylesheet at `src/shared/styles/globals/perch.css` (664 gate-lines, well inside the cap) with one `@import` line added to `globals.css` (38 gate-lines). This row exists to record *why* that indirection is not optional — 32 gate-lines covers a pillar triple in both themes and nothing more. Deleting `--huddle-*` frees exactly **20** lines of `theme.css` (`grep -c -- "--huddle-"` = 20) but edits `adaptive-theme.ts`'s `createThemeVars` (`:244-253`), which `19` correctly puts out of scope |
| `shared/styles/globals.css` | 38 | TIGHT (962) | the one `@import` that pulls in `perch.css` | **one line, and its position is load-bearing.** `globals.css:32-33`'s own comment says the `@custom-variant` rules "must stay below every `@import`: CSS requires `@import` to precede other at-rules, so placing this above them silently drops the rest of the sheet". The `perch.css` import therefore goes in the `@import` block (`:4-20`, after `./globals/theme.css` at `:10`), **above** `@config` at `:22` and above both `@custom-variant` lines (`:34`, `:37`). Placed below any of the three, the whole Perch palette is dropped with no error |
| `features/sidebar/ui/AppSidebar.tsx` | 952 | TIGHT (48) | the rail's Perch destinations | **48 lines is real but thin.** Budget it; if the rail needs more, extract `AppSidebarPerchSection.tsx` rather than growing this file |

### 7.2 The pattern, stated once

**Perch adds files. Perch does not grow Buzz files.** The only three exceptions
in the whole programme are the three this document splits, and it splits them
first precisely so they stop being exceptions. Where a Perch change genuinely
must land inside an existing file, the sequence is: measure with
`near-cap-survey.mjs`, split that file in its own commit, then make the change.
Never both in one commit — that is how a 999-line file becomes a 1,400-line file
with a "had to, the gate was in the way" commit message.

### 7.3 A new Perch file is not free of the token rule

Adding a file gets past the size ratchet. It does not get past `ThemeProvider`,
and this is worth stating here because §7.1's dispositions are the moment a
producer decides where new styling lives.

`createThemeVars` (`BUZZ desktop/src/shared/theme/adaptive-theme.ts:191-290`) is
a pure function called by `applyTheme` inside the **renderer** process; it
returns a record of exactly **38** custom-property names, counted this session,
including `--background`, `--card`, `--card-foreground`, `--foreground`,
`--muted-foreground`, `--popover`, `--ring`, `--border` and `--input`.
`applyTheme` then walks that record and writes each one with
`root.style.setProperty(key, value)` (`ThemeProvider.tsx:443-446`), and the
synchronous cached-boot path does the same at `:404-406`. Those are **inline
declarations on the root element**: no normal-priority stylesheet rule can beat
one, whatever its specificity or import order.

The consequence for anything this file routes into a new sibling: a Perch
component or stylesheet that reads a bare Buzz shadcn name is repainted by
whichever syntax theme the operator has selected. `19-TOKENS.md` owns the fix
and states it as a binding commitment — Perch-authored code reads only
`--perch-*` — and this file's dispositions assume it. A new `perch.css` under
`shared/styles/globals/` and a new component under `features/perch*/` are both
subject to it; neither the size gate nor `tsc` will say so.

**One fact for `19-TOKENS.md`, found while checking the `@import` placement in
§7.1 and not otherwise recorded anywhere.** `globals.css:37` declares
`@custom-variant dark (&:where(.dark, .dark *))`. Buzz's Tailwind `dark:`
utilities therefore key on the **`.dark` class only** — not on
`[data-theme="dark"]`, and not on `prefers-color-scheme`. `19-TOKENS.md`'s dark
selection is `:root.dark, :root[data-theme="dark"], .dark` plus a guarded media
block, which is right for its own custom properties; a root carrying
`data-theme="dark"` **without** the class would get Perch's dark tokens and
Buzz's light `dark:` utilities at the same time. `ThemeProvider.tsx:449-450` and
`:408-409` do stamp the class on every path that runs today, so the two agree in
practice — but a Perch bootstrap that sets the attribute before first paint and
lets `applyTheme` catch up would not. Flagged to `19-TOKENS.md`, whose call it
is; not decided here.

---

## 8. Sequencing, and what happens if upstream is slow

The ten commits are **two** PRs to `block/buzz`, not one
(`build/refactor/upstream-pr.md` carries both descriptions):

| | Commits | Files |
|---|---:|---|
| **PR A** | MR-1, MR-2, AS-1…AS-4 | `MessageRow.tsx`, `AppShell.tsx` |
| **PR B** | HV-1…HV-4 | `HomeView.tsx` |

They are split because the three files share no import and no test, so the two
PRs can be reviewed in parallel by different people, and a stall on one does not
hold the other. PR A is the one Perch's client work blocks on; PR B blocks only
F1 (`20-TASK-BREAKDOWN.md` P1-14).

Perch does **not** wait for either to merge:

1. Two branches are created off `main` and the commits land on them.
2. Perch's own branch is created off *both* branches merged, not off `main`.
3. MR-3 (§6) is Perch's first client commit, on the Perch branch.
4. If upstream merges, Perch rebases onto `main` and the ten commits vanish from
   its diff. If upstream declines, they stay in Perch's diff as ten clean
   commits at the base of the branch — which is exactly where a reviewer wants
   them.

Either way the work is done once. The failure mode this avoids is Perch
carrying an ad-hoc split entangled with feature code because upstream review
took three weeks.

### 8.1 Which E2E project actually runs a spec — a correction

`desktop/playwright.config.ts` declares exactly two projects — `smoke` (`:20`)
and `integration` (`:171`) — each with an explicit `testMatch` array and **no
catch-all**. A spec in neither array is never executed by `pnpm test:e2e:smoke`
or `pnpm test:e2e:integration`, which is the failure mode `16-INVARIANT-TESTS.md`
names as a commitment ("an unregistered spec is silently never run").

Every spec this document cites was re-checked against those two arrays this
session. Of 32: **29 are smoke, 2 are integration, 1 is registered nowhere.**

| Spec | Project | Consequence for this plan |
|---|---|---|
| `tests/e2e/profile.spec.ts` | **integration** | AS-1's hook-order risk row previously called it smoke. It is real coverage, but it needs a live relay (`pnpm test:e2e:integration`), so it is not part of the per-commit loop |
| `tests/e2e/onboarding.spec.ts` | **integration** | same |
| `tests/e2e/typing-latency.perf.ts` | **neither** | The file exists at that path but appears in no `testMatch`. Only `cold-switch-longtask.perf.ts` (`:113`) is registered. MR-1's memo-risk row cited it as the thing that "would surface a regression as timing" — it would not, because nothing runs it |

The corrected reading of MR-1's memo risk: the claim that the extraction cannot
defeat `MessageRow`'s memo is argued from the comparator's contents (§4.2) and
is **not** covered by any executing test. `virtualization.spec.ts` is smoke and
would catch a gross rendering regression; nothing measures render counts. That
was the one risk this document already recorded as unproven, and the project
audit makes it more unproven, not less. It is recorded, not papered over.

**Every commit is signed off** (`git commit -s`). The required **DCO Check**
fails a PR with any commit missing a `Signed-off-by` trailer, and `git rebase`
onto `main` needs `--signoff` explicitly. If the branch already has unsigned
commits: `git rebase --signoff main`, then force-push.

**Run before every push, not just the last one:**

```
. ./bin/activate-hermit
just file-size-check          # the point of the exercise
just desktop-typecheck
just desktop-test
just desktop-check
cd desktop && pnpm test:e2e:smoke
node build/refactor/line-ledger.mjs   # from the plan checkout: exits 2 if the ranges moved
```

Activate Hermit first so `./bin` leads `PATH`; the pre-push hook self-pins via
`bin/.lefthookrc`, but the non-hook commands do not.

Once per PR, not per commit, because it needs a live relay:

```
cd desktop && pnpm test:e2e:integration   # profile.spec.ts, onboarding.spec.ts (§8.1)
```

### Follow-ups this refactor deliberately does not do

| Follow-up | Why not now |
|---|---|
| Unify the near-duplicate depth-guide rendering in `MessageThreadSummaryRow.tsx:104-210` (same `thread-collapse-guide` testid, same geometry helpers, different React keys and inline rather than memoized handlers) | Unifying is not a move — the key strings and handler identities differ. It is a real follow-up with real risk and it would stop this diff being reviewable as a move |
| Add `channelId`, `onEdit`, `showDepthGuides` and `actionBarPlacement` to the memo comparator | A behaviour change (more re-renders, correctly), measurable, and orthogonal |
| Extract `isNotifiedForThread` + the follow/unfollow handlers (`AppShell.tsx:472-502`) | Blocked on hook order: `useThreadFollows` (`:362-367`) must run *before* `useUnreadChannels` (`:368-406`, which consumes `followedRootIds` at `:404`), and the handlers consume `useUnreadChannels`' output. Splitting the pair across the boundary is the one AppShell extraction that is not obviously safe. 31 lines, not worth the risk |
| Move Settings into the router outlet | Perch Phase 0, after AS-4 makes it small |
| Extract `HomeView`'s list-pane call site (`:692-758`) or pane resize handle (`:759-780`) | They are the blocks F1 rewrites in place. Extracting them before the rewrite means extracting them twice — §5.5's second correction to P0-13 |
| Register `tests/e2e/typing-latency.perf.ts` in a Playwright project | A real gap (§8.1) but not this refactor's: the spec predates it, and deciding whether a latency assertion belongs in the per-commit loop is a suite-owner call |

---

## 9. Corrections, and one proposed brief amendment

Departures from the plan set, each verified against source this session.

**Proposed brief amendment (APPENDIX-NORMATIVE.md §6, verified counts).** This
is **the same amendment `20-TASK-BREAKDOWN.md` files as A-1**, converged here so
the registry gets one row and not two — that convergence is the point of §11.
Replace the row

> `AppShell.tsx` / `MessageRow.tsx` | **997** / **998** against a hard 1000 cap | `wc -l`

with

> `AppShell.tsx` / `MessageRow.tsx` / `HomeView.tsx` | **998** / **999** / **994** gate-lines against a hard 1000 cap — headroom **2**, **1** and **6** | `content.split(/\r?\n/).length`, the gate's own count (`scripts/check-file-sizes-core.mjs:24-29`), which is `wc -l` **plus one** for a newline-terminated file

Three changes in one row: the counting function, the numbers it produces, and
the third file. The values circulating are the `wc -l` figures; the gate does not
use `wc -l`, which is the difference between "three lines of room" and "one".
`HomeView.tsx` is not in the appendix at all, and it is the file `20`'s F1
rewrites.

Other corrections, no amendment needed:

- **This file's own §7.1, previous draft: "`HomeView.tsx` — new file. The Watch
  is not an edit to `HomeView`."** Wrong, and it collided with
  `20-TASK-BREAKDOWN.md` P0-13. `00-BRIEF.md` §3 surface 1 gives The Watch's
  Buzz origin as `desktop/src/features/home` with "four lanes remapped from
  `FeedItemCategory`", and `04-SURFACES-AND-UX.md` §2.1 says "Perch keeps that
  priority function unchanged; only the labels, sources and per-row state
  change." The split is now §5.5. See §11 for how the collision happened.
- **`20-TASK-BREAKDOWN.md` P0-13, acceptance criterion 2** ("the four inbox
  queues are produced by a pure function in `lib/`"). Already true:
  `matchesInboxFilter` is exported at
  `BUZZ desktop/src/features/home/lib/inboxViewHelpers.ts:41` with its own test
  file, and `buildInboxItems` at `lib/inbox.ts:462` with its own. §5.5 proposes
  the replacement criterion.
- **`20-TASK-BREAKDOWN.md` P0-13, acceptance criterion 1** (`HomeView.tsx` under
  700 gate-lines). The measured four-step split lands at 736. §5.5 argues for
  750 and the four named seams instead of a round number.
- **E2E project membership.** Three specs this document cited as smoke coverage
  are not: two are `integration` and one is registered nowhere. §8.1 has the
  measurement and the consequence for MR-1's memo risk.
- **`00-BRIEF.md` §3, surface 1's purpose column, uses the wrong ruled word.** It
  reads "Four **lanes** remapped from `FeedItemCategory`: `needs_action` …,
  `mention` …, `activity` …, `agent_activity` …". Those four are The Watch's
  inbox categories, which `APPENDIX-NORMATIVE.md` §7 rules is what **queue**
  means; *lane* is reserved for the twelve standing threat-class channels, which
  is what `00-BRIEF.md` surface 4 correctly calls them. `04-SURFACES-AND-UX.md`
  §2.1 already says "queue" throughout, and `build/prototypes/watch.html` renders
  the four headers as words — `Holds` ×8, `Case activity` ×7, `Findings to
  review` ×5, `Named you` ×5, counted this session — with no occurrence of
  *lane* in that role. The brief's own sentence would fail the ban list it
  mandates. Quoted verbatim in §2 and §11.1 because it is the *evidence* for the
  HomeView ruling; flagged here so the quotation is not read as this file
  adopting the word. **Proposed one-word amendment: `00-BRIEF.md` §3 surface 1
  says "four queues remapped".**
- **Vocabulary note, for whoever wires `tools/check-copy-banned-terms.sh`.** This
  document and `refactor/useChannelCreationHandlers.ts` use the word *stream*
  five times, always as Buzz's own channel type — `channelType: "stream"` is a
  wire value read from `AppShell.tsx:537-620`'s moved code. `APPENDIX-NORMATIVE.md`
  §7 rules *stream* to mean one of the bridge's four transport classes; naming an
  upstream project's own domain object is not a use of the ruled word, which is
  the same precedent `10-RELAY-FORK.md` establishes for `channel_type: "stream"`
  in its E2E helper. No Perch-rendered string this file owns uses the word.
  Re-swept this session for every other ruled and banned term
  (`lane`, `queue`, `track`, `family`, `approve`, `quorum`, bare `lease`, `hunt`
  as a noun, `clowder`, the legacy codename, trust-claim words, `!`): zero hits
  across `15-FILE-SPLIT-PLAN.md` and all nine files in `build/refactor/`, other
  than this sentence's own enumeration of the list and the ruled-sense uses of
  *queue* (The Watch's four inbox categories) and *track* (quoting `20`'s task
  field). The `!` characters in the six drafts are all the logical-negation
  operator, checked line by line; none is in a string.

- **`APPENDIX-NORMATIVE.md` §1, `/settings` Phase 0.** `/settings` is already a
  real route (`app/routes.ts:8`, `app/routes/settings.tsx:24-27`, including a
  `validateSearch` that rewrites the retired `?section=doctor`). The unfinished
  work is outlet rendering, not route declaration — `AppShell.tsx:173` and
  `:784-823` unmount the outlet, which is why `routes/settings.tsx:33-35`
  returns `null`. §5's AS-4 makes that a one-file change. The route table's
  *phase* is right; its *reason* is wrong.
- **Ground notes, "the house pattern in `desktop/src/app/` is extracting hooks,
  not components (15 sibling files already extracted from AppShell)".** Half
  right. `AppShell.tsx` imports **15** `use*` siblings from `@/app/` (`:5`,
  `:15-28`) *and* **11** component/provider siblings (`:6-14`, `:101`,
  `:103-106`). Both are house practice, which is why AS-4 (a component
  extraction) is not novel.
- **Ground notes, "`crates/` Rust is covered by no file-size gate."** True of the
  workspace `crates/` at the repository root. `desktop/src-tauri/src` and
  `desktop/src-tauri/crates` **are** governed
  (`desktop/scripts/check-file-sizes.mjs:11-19`), and at a 950-line threshold the
  survey finds **16** `.rs` files at or over the cap and **20** more inside it. A
  Perch Tauri command lands under a governed root.
- **`17-COMPONENT-SPECS.md` §1.5, "46 clauses over 16 `message.*`, 30 row
  props".** 46 is right; the split is **18 / 28** (§4.1). `message.reactions` and
  `message.tags` are compared inside `reactionsEqual`/`tagsEqual`
  (`MessageRow.tsx:956-957`) rather than as bare clauses. The ground notes' 60 is
  wrong.
- **`17-COMPONENT-SPECS.md` §2.5, "replacing that arm with a single
  `<MessageBody … />` call returns ~40 gate-lines… before counting the nine
  imports that leave with it".** Measured: the arm alone returns **29**
  (48 out, 19 in) and **ten** imports leave, not nine (`:34`, `:38`, `:39`,
  `:41`, `:42`, `:45`, `:47`, `:48`, `:49`, `:58`). The *complete* MR-2
  extraction returns **90**, because four derivations whose only readers are
  inside the arm move with it (§4.3). 17's conclusion — that this is what makes a
  Perch marker landable — is right and the real number is better than its
  estimate.
- **`17-COMPONENT-SPECS.md` §3.2 budgets `MessageBody.tsx` at 200 gate-lines
  including the ambush registry call.** The upstream-safe version measures
  **193**; the seam adds ~14 (§6.2). That lands at ~207, so the budget is right
  to within a rounding of Biome's reflow. No change needed, but a producer should
  not treat 200 as slack.

---

## 10. What is in `build/refactor/`

| File | What it is | Evidence level |
|---|---|---|
| `line-ledger.mjs` | The arithmetic in §5, re-runnable, with the anchor guard of §1.1 and a `--self-test` for the guard itself. Read-only against BUZZ. | **run this session**, exit 0, all 62 anchors matched; self-test 62/62 |
| `near-cap-survey.mjs` | The survey in §7, re-runnable across desktop, web and mobile; self-verifies its rule roots against the three check scripts. | **run this session**, 86 files at ≥ 950 |
| `MessageThreadGuides.tsx` | MR-1's new file, written out. 293 gate-lines. | draft, pre-Biome, not compiled |
| `MessageBody.tsx` | MR-2's new file, written out, upstream-safe (no Perch code) with the seam marked in a comment. 193 gate-lines. | draft, pre-Biome, not compiled |
| `useAppShellBackgroundSync.ts` | AS-1's new file. 96. | draft, pre-Biome, not compiled |
| `useCommunityDestinationRestore.ts` | AS-2's new file. 88. | draft, pre-Biome, not compiled |
| `useChannelCreationHandlers.ts` | AS-3's new file. 121. | draft, pre-Biome, not compiled |
| `AppShellSettingsSurface.tsx` | AS-4's new file. 102. | draft, pre-Biome, not compiled |
| `upstream-pr.md` | The two `block/buzz` PR descriptions (§8). | text |

The six `.ts`/`.tsx` drafts are **pre-Biome**. They are written to be diffable
against the source ranges they came from, not to be format-final; run
`just desktop-fix` after moving each one into the tree.

**HV-1…HV-4 have no drafts, deliberately.** The four MR/AS drafts exist because
their moved code is *load-bearing and easy to get subtly wrong* — the
`resolveSnapshotSharedBy(message, profiles)` two-argument trap in `MessageBody`
is the case that justified writing them out. HomeView's four blocks are
different: three of them are rewritten or deleted by F1 within weeks of landing,
so a verbatim draft would be reviewed once and then replaced. What has to be
right *now* is the seam list and the scope analysis, and those are measured in
§5.5 — every moved value checked for readers outside its block, every import
that becomes unused enumerated. A producer executing HV-1…HV-4 has the ranges,
the readers and the ledger to check the result against. Saying so is more useful
than four drafts that would be stale before they were read.

---

## 11. The arbitration record

The red team's systemic finding across wave 2 was not credulity about behaviour
— it was **unarbitrated disagreement**: two artifacts each verify a fact, each
write a correct local decision, and no producer holds the tiebreak, so the one
who owns the file wins regardless of who is right. Four such collisions touch
this file's scope. Each is settled below, with the owner, the evidence, and what
the loser should change.

### 11.1 `HomeView.tsx` — split it, or leave it alone? — **SETTLED: split**

- **The two positions.** This file's §7.1 (previous draft) said The Watch is a
  new file and `HomeView.tsx` must never be edited. `20-TASK-BREAKDOWN.md` T2 /
  P0-13 said it is a third capped file and must be split in Phase 0.
- **Who owns it.** Split mechanics are this file's; task sizing is `20`'s. So
  this file holds the tiebreak on *whether* and *how*, and `20` holds it on
  *when* and *how much it costs*.
- **The evidence, which is not in either artifact.** `00-BRIEF.md` §3's surface
  table gives The Watch's Buzz origin as `desktop/src/features/home` with "four
  lanes remapped from `FeedItemCategory`", and `04-SURFACES-AND-UX.md` §2.1 says
  in as many words: "Perch keeps that priority function unchanged; only the
  labels, sources and per-row state change."
- **Ruling.** `20` is right; this file was wrong. HV-1…HV-4 are §5.5.
- **What changes for `20`.** Nothing about the task's existence, its track, or
  its dependency edge. Two acceptance criteria change (§9): criterion 2 asks for
  work already done, and criterion 1's "under 700" becomes "at or below 750 plus
  the four named seams", because the measured split lands at 736 and the fifth
  extraction that would reach 700 is churn.

### 11.2 `AppShell.tsx`'s remaining headroom — **SETTLED: both readings, in order**

- **The two positions.** `14-CLIENT-ARCHITECTURE.md` commits "`AppShell.tsx`'s
  net line delta must be ≤ 0 in the commit that adds the chrome conditional (it
  has 2 gate-lines of headroom)". This file says AS-1…AS-4 leave 220 lines of
  headroom.
- **Ruling.** Not a contradiction — the two statements are about different
  points in the build order, and both are true at theirs. Before PR A lands,
  `14`'s constraint is binding and correct as written. After it lands, the
  constraint is trivially satisfiable and stops being a design pressure.
  `14`'s commitment stays in force as the fallback: if the chrome conditional is
  written while the split is still in upstream review, it must still be
  net-negative. Neither artifact needs an edit; this row exists so a producer
  reading `14` alone does not design a contortion the split already removed.

### 11.3 The Perch mock bridge — **NOT MINE; the size gate does not constrain it**

- **The three positions.** `16-INVARIANT-TESTS.md` (one delegating line in
  `e2eBridge.ts`'s `default:` arm → `src/testing/perch/e2ePerchBridge.ts`);
  `14-CLIENT-ARCHITECTURE.md` (one `command.startsWith("perch_")` guard before
  the same default throw, fixtures in `src/testing/perchBridgeFixtures.ts`);
  `22-DEMO-FIXTURE.md` (edits nothing; rides five existing `window` seams).
- **What this file can settle.** Only the size question, and it settles it
  clearly: `src/testing` is governed by **no** rule table
  (`desktop/scripts/check-file-sizes.mjs:10-55`), so `e2eBridge.ts` at 14,621
  gate-lines can take a line and a new sibling can be any length. No mock-bridge
  design needs to be shaped around the ratchet.
- **Owner for the rest.** `14-CLIENT-ARCHITECTURE.md`, which owns the
  renderer↔Rust surface the mock stands in for. Flagged, not decided.

### 11.4 Where Perch's new `shared/api` siblings land, and what they are called — **SETTLED: peers' names win**

- **The collision.** A previous draft of §7.1 invented `perchDaemon.ts`,
  `perchSubscriptions.ts` and `perchTypes.ts`. `14-CLIENT-ARCHITECTURE.md` ships
  actual skeletons named `tauriPerch.ts`, `perchSubscriptions.ts`,
  `perchKeys.ts` and `perchEphemeralStore.ts`; `13-WIRE-SCHEMAS.md` commits the
  wire types to `features/perch/wire/`, explicitly *not* `shared/api/`.
- **Ruling.** This file owns "which existing file may not grow"; it does not own
  "what the new file is called". §7.1 now cites the peers' names. `perchTypes.ts`
  is withdrawn: it would have put wire decoders in the one directory `13`
  forbids them in.
- **The one name this file still proposes.** `PerchOmnibox.tsx` for the ⌘K
  Ledger overlay, because `TopbarSearch.tsx` is exactly at cap and no peer has
  named its replacement. Marked PROPOSED; `14-CLIENT-ARCHITECTURE.md` should
  adopt or rename it.

### 11.5 What this file does *not* arbitrate

Three collisions the red team named fall outside this file's scope and are listed only
so nobody mistakes silence for agreement: render law 2's `distinct_sources`
reading (six producers against two, and the two own the schemas); the 26006
disclosure hole being closed twice, by `13-WIRE-SCHEMAS.md`'s `h`-tag and ADR
0017's `P_GATED_KINDS`, which together close the subscription entirely; and the
five different `case-0042` fixtures. None of the three is a file-size or
file-layout question. They need a registry pass on `APPENDIX-NORMATIVE.md`, and
that pass has no owner.
