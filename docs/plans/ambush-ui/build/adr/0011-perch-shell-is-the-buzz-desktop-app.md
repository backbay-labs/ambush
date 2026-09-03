# ADR 0011: Perch's Shell Is The Buzz Desktop Application, Not A New One And Not The Review Workbench

## Status

Proposed on 2026-08-30. Perch, Phase 0 (`docs/plans/ambush-ui/09-ROADMAP-AND-RISKS.md` §2).

Supersedes nothing. Depends on nothing already accepted. ADRs 0012–0018 all assume
this one; if it is refused, they are moot rather than wrong.

### A note on this file's path, its number, and its status word

These eight ADRs (0011–0018) were drafted in `docs/plans/ambush-ui/build/adr/` because
the plan set that forced them is not yet adopted and `docs/decisions/` holds accepted
decisions. They are written to be moved into `docs/decisions/` **verbatim** on adoption,
taking the next eight free numbers after `0010-containment-release-goes-through-the-daemon.md`.
Nothing in either repository was modified to produce them.

"Proposed" is deliberate and is the only honest status word: every ADR here decides
something about a project that has not started. Accepting the plan set accepts these
eight; the status line becomes `Accepted on <date>` and the phase is filled in then.

**Path prefix convention.** An unprefixed path is this repository. A path prefixed
`BUZZ ` is `block/buzz` at `eed74bde2`, read directly this session. The plan set uses
the same convention.

## Context

Perch needs a shell: a window, a navigation rail, a two-pane list/detail, a keyboard
layer, a search overlay, a settings surface, a theme engine, an update channel, and a
transport that survives a laptop lid closing. There were three candidates and only one
of them has ever run.

### Fact 1: Ambush's shipped operator UI is a server-rendered page with no client

`crates/swarm-runtime-http/src/http/render.rs` (599 lines) is a set of `pub(super)`
helpers that `format!` an HTML document — `render_review_layout` at `:25` emits a
complete `<!DOCTYPE html>` with an inlined `<style>` block — consumed by
`crates/swarm-runtime-http/src/http/pages.rs` (1,523 lines, 15 functions) and by
`error.rs:1`. It is served by `swarmctl serve`'s `LocalOperatorSurface` at exactly one
registered route, `GET /v1/operator/review` (`http/state.rs:311`). It has no JavaScript,
no client code anywhere in the workspace, no live update path, and its own visual
identity is light and warm (`render.rs:39` sets `body{background:#f4efe5}`) — the
opposite of the dark documentation identity every asset in `docs/assets/` uses.

It is a good thing and it should keep existing. It is not a console.

### Fact 2: the operator surface cannot enumerate, and that is not a small gap

The 49 routes of `LocalOperatorSurface::router()` (`http/state.rs:292-488`, `grep -c
'\.route('` = 49, of which 48 sit behind `require_bearer_auth` and `/metrics` is merged
unprotected at `:484-487`) are a status-and-artifact surface, not a query surface. The
`limit_*` helpers in `http/helpers.rs` truncate in memory and overwrite `total_count`
with the truncated length, so a header reading "50 of 4000" is not implementable against
them. `/v1/operator/replay`, `/investigation` and `/incident` accept exactly one
selector each. None of the 49 accepts analyst feedback — the finding this whole project
exists to fix.

A console needs: enumeration with a server-authoritative "there are more", keyset
pagination, full-text search over bodies, resumable live delivery after a reconnect, and
per-compartment authorization re-checked on every single delivery. Building those is a
backend project of its own. ADR 0012 records the decision to rent them instead.

### Fact 3: the fork's cost is measured, and the entry price is a refactor

`BUZZ desktop/src` is 322,393 LOC moving at 20.7 commits a day, and the repository
maintains three hand-synced event-kind registries. That is the contrarian's argument and
it is adopted as a constraint list, not rejected as a conclusion
(`docs/plans/ambush-ui/00-BRIEF.md` §2.3, §6).

One part of the cost is not a running total but a gate that must be paid before the first
line of Perch renders. `BUZZ scripts/check-file-sizes-core.mjs:24-29` counts
`content.split(/\r?\n/).length` — which is `wc -l` **plus one** for a newline-terminated
file — and `allowedLineCount` at `:31-33` sets the limit to `max(baseLines, 1000)`
against the branch's merge-base, so an over-cap file is frozen at its current size and a
newly added file gets a hard 1000. Measured with `node` at `eed74bde2`:

```
998   BUZZ desktop/src/app/AppShell.tsx                     2 lines of headroom
999   BUZZ desktop/src/features/messages/ui/MessageRow.tsx  1 line of headroom
994   BUZZ desktop/src/features/home/ui/HomeView.tsx        6 lines of headroom
1011  BUZZ desktop/src/shared/ui/sidebar.tsx                frozen
1108  BUZZ desktop/src/shared/api/tauri.ts                  frozen
1084  BUZZ desktop/src/shared/api/relayClientSession.ts     frozen
1000  BUZZ desktop/src/shared/api/types.ts                  frozen
```

`APPENDIX-NORMATIVE.md` §6 records 997 / 998 for the first two files. Those are `wc -l`
values; the gate's own arithmetic makes them 998 and 999, so the real headroom is two
lines and one line, not three and two.

**`HomeView.tsx` is a third capped file and the appendix does not name it at all** — 994
gate-lines, six of headroom, and it is the file `F1` (The Watch) rewrites. Re-measured with
`node -e 'fs.readFileSync(f,"utf8").split(/\r?\n/).length'` at `eed74bde2` for this
revision: 998 / 999 / 994. `20-TASK-BREAKDOWN.md` found it independently and split it as task
P0-13; `15-FILE-SPLIT-PLAN.md` records it in its near-cap survey. Proposed amendment
**AD-A1** below now carries all three files, absorbing the two identical amendments those
artifacts raise.

## Decision

**Perch is a hard fork of `block/buzz`'s `desktop/` — the Tauri 2 + React 19 application
— re-skinned and cut by roughly a third, organized as a shift-shaped verdict queue.**

Four clauses make that operational.

**1. Fourteen surfaces across eleven routes, and the set is closed.** The route table is
`APPENDIX-NORMATIVE.md` §1 and it is the countable artifact. Adding a surface requires
deleting one, in writing, as a brief amendment. This is the only mechanism that has ever
stopped a console from growing a tab per stakeholder.

**2. The review workbench is neither extended nor deleted.** It stays exactly where it
is, in `swarmctl serve`'s process, as the zero-dependency fallback an operator can reach
when the relay, Postgres and Redis are not running. Perch does not render it, proxy it,
or claim to replace it. `docs/plans/ambush-ui/00-BRIEF.md` §9 non-goal 10 states the same
rule for `swarmctl` itself: roughly 124 of 126 subcommands have no HTTP surface, so the
console hosts a terminal honestly rather than pretending to have absorbed them.

**3. The two capped files are split before the first Perch surface exists.** Not as
cleanup afterwards. `AppShell.tsx` and `MessageRow.tsx` cannot absorb even a small edit,
and the marker-renderer registry has to come out of `MessageRow`'s `renderBody` default
arm (`BUZZ desktop/src/features/messages/ui/MessageRow.tsx:381-459`, `default:` at
`:414`) before the first evidence card can be rendered at all. The house pattern in
`BUZZ desktop/src/app/` is extracting hooks: eighteen `use*` hooks and four non-test
`AppShell*` siblings (`AppShell.helpers.ts`, `AppShellChannelSurface.tsx`,
`AppShellContext.tsx`, `AppShellOverlays.tsx`) already sit beside it in that directory,
counted this session. There is no in-tree precedent for splitting a memoized
component with a 60-clause comparator (`MessageRow.tsx:935-995`), which is why
`docs/plans/ambush-ui/build/15-FILE-SPLIT-PLAN.md` is a separate artifact rather than a
paragraph here.

**4. New Perch code lands in new files, never by growing a frozen one.** Every Perch
`invokeTauri` wrapper, subscription helper and shared type goes in a new sibling under
`BUZZ desktop/src/shared/api/`. Eight in-tree precedents already do this
(`tauriEvents.ts`, `tauriMesh.ts`, `tauriChannelHeadCache.ts`, `tauriAcpDiscovery.ts`,
`tauriManagedAgentMessageMarkers.ts`, `communityProfile.ts`, `forum.ts`, `osIdle.ts`),
each importing `invokeTauri` from `./tauri`. A patch that edits `tauri.ts`,
`relayClientSession.ts` or `types.ts` fails `just check`, `just ci` and pre-push.

## Alternatives Considered

**Build a console from scratch (~6k LOC).** The estimate is the contrarian's and it is
plausible *for the pixels*. It is not plausible for the substrate: it silently excludes
enumeration, keyset pagination, FTS, resumable live fan-out, per-compartment
re-authorization, a signed-identity transport, an update channel, and a mock-IPC test
harness that 162 Playwright spec files already exercise. Rejected on the ground that the 6k
number prices the half of the problem that is easy. Its real merit — that year-two rebase
cost is unbounded — is adopted as kill criterion K2
(`docs/plans/ambush-ui/09-ROADMAP-AND-RISKS.md` §8) rather than argued away.

**Extend the review workbench.** A `format!`-built page with no client, no live path and
one route would have to grow a build system, a client framework, a state layer, a
transport and a test harness before it could render the first hold. That is the
"build from scratch" option with a worse starting point and a 1,523-line file to keep
compiling. Rejected.

**Ship Buzz's browser client (`BUZZ web/`) instead of the desktop app.** 49 files /
4,259 LOC including CSS on a `web/src/**` basis — the figure reproduces exactly at
`eed74bde2`, and the basis is worth stating because a naive `find` over `web/` returns
52 / 4,671 by also counting the Playwright and Vite configs. Rejected for v1 and
explicitly preserved as an option (`00-BRIEF.md` §10 Q12): a browser build cannot hold an
OS-keyring bearer token for the daemon, which is the whole of leg 2 (ADR 0014), and
would turn that into a same-origin gateway design.

## Consequences

### Positive

- The substrate arrives finished. ADR 0012 records what specifically.
- The delete list is the design work. Cutting a third of an application that works is a
  cheaper and far more reviewable act than writing a third of one that does not.
- The mock Tauri bridge (`BUZZ desktop/src/testing/e2eBridge.ts`, 14,620 lines) lets the
  entire frontend develop against Ambush fixtures while the daemon-side hold store is
  built — which is what makes question 1's answer ("hold store first") affordable rather
  than merely correct.

### Negative

- Entry costs a refactor of two files that upstream also edits frequently, and the
  refactor has no in-tree precedent for one of them.
- The rebase is forever. K2 exists to make "we are now a hard fork" a decision rather
  than a drift.
- Six `BUZZ desktop/src/shared/ui/` files that render adversary-controlled remote content
  (the link-preview and attachment surfaces) are inherited by default and need a
  deliberate disposition. `docs/plans/ambush-ui/build/17-COMPONENT-SPECS.md` owns it;
  this ADR records that inheriting them silently is not acceptable in a console whose
  trust argument is that it renders nothing it did not receive over an authorized path.
- A Buzz brand cascade selects on `data-testid` values across ~780 lines of
  `BUZZ desktop/src/shared/styles/globals/theme.css`. Renaming a Buzz concept without
  updating them breaks theming with no compile error, so the `data-testid` values survive
  even where the concept is renamed.

## Verification

Three checks, all mechanical, none of which exists today:

1. `BUZZ scripts/check-file-sizes-core.mjs` already fails the build if either capped file
   grows. It is the gate that makes clause 3 a fact rather than an intention — it is
   simply already installed and must not be relaxed. **A split that raises a cap or adds
   an override to slip under it fails the intent of this ADR even while passing the
   gate**, which is why `BUZZ CLAUDE.md`'s own rule is "split the file — never bump the
   limit".
2. **PROPOSED** `tools/check-perch-surface-count.sh`: asserts exactly fourteen surfaces
   across the eleven routes of `APPENDIX-NORMATIVE.md` §1, by parsing
   `BUZZ desktop/src/app/routes.ts` and the view union. Wired as a workflow step in the
   same PR, per ADR 0009's `tools/check-gates-wired.sh` rule.
3. **PROPOSED** a `just` recipe that re-measures the six file sizes above with the gate's
   own arithmetic and prints them, so nobody re-derives `wc -l` and concludes there are
   three spare lines.

## Follow-On Work

- `15-FILE-SPLIT-PLAN.md` owns the two splits and must land before any Perch surface.
- Decide the disposition of the six adversary-content components named above.
- Proposed brief amendment **AD-A1**: `APPENDIX-NORMATIVE.md` §6's row
  "`AppShell.tsx` / `MessageRow.tsx` — **997** / **998** against a hard 1000 cap | `wc -l`"
  becomes "`AppShell.tsx` / `MessageRow.tsx` / **`HomeView.tsx`** — **998** / **999** /
  **994** against a hard 1000 cap | the gate's own `content.split(/\r?\n/).length`,
  `BUZZ scripts/check-file-sizes-core.mjs:24-29`". The `wc -l` basis is off by one for every
  newline-terminated file, the row's purpose is to state remaining headroom, which it
  currently overstates by 50%, and it omits the third capped file — the one The Watch
  rewrites. **Absorbs the identical amendments raised by `15-FILE-SPLIT-PLAN.md` and
  `20-TASK-BREAKDOWN.md` (its A-1 and A-7): file one row.**
