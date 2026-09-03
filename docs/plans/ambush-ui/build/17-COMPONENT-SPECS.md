# 17 — Component specification sheet

**Status:** buildable artifact. Wave 2. Owns the component layer.
**Binds to:** `APPENDIX-NORMATIVE.md` (route table §1, key map §2, wire registry §3, hold path §4,
bill labels §5, constants §6, vocabulary §7, render laws §8) and `00-BRIEF.md` §13.
**Does not own:** token *values* (`19-TOKENS.md`), chart components (`18-DATAVIZ.md`), marker
*payload* schemas (`13-WIRE-SCHEMAS.md`), the `AppShell`/`MessageRow` split *mechanics*
(`15-FILE-SPLIT-PLAN.md`), route wiring and query keys (`14-CLIENT-ARCHITECTURE.md`), the
invariant test bodies (`16-INVARIANT-TESTS.md`), sequencing (`20-TASK-BREAKDOWN.md`).

Every path below is absolute-from-repo-root under `BUZZ = /Users/connor/Medica/backbay/buzz` or
`AMB = /Users/connor/Medica/backbay/standalone/swarm-team-six`. Every Buzz claim was read from
source at `eed74bde2` this session, not inherited.

**Revision 2 (red-team pass).** §14 is the change log: what a critic proved wrong, what was
corrected, and the one claim held after re-verification. The two changes that alter what a producer
builds are §1.9 (every Perch token reference is `--perch-*`) and §4.8 (`SourceCount`'s mechanism was
stated backwards in revision 1 and is corrected against source). §6.13 and §6.14 close two surfaces
that had no owner in wave 2.

---

## 0. How to read a spec block

Each new component carries: **path · props (full TS) · states · `data-testid` contract · keyboard ·
ARIA + focus · tokens consumed · gate-line budget · governing plan section**. Where a field would
restate `APPENDIX-NORMATIVE.md`, it cites instead. Where I decided something the plan left open, the
line is marked **DECIDED** and appears in this file's commitments.

`[V]` = verified against source this session. `[P]` = proposed by this document.

---

## 1. Conventions, read from Buzz source — not invented

These are the rules a new Perch component obeys. Each was measured, not assumed.

### 1.1 File layout

`BUZZ desktop/src/features/home/` is the shape every Perch feature copies `[V]`
(`find desktop/src/features/home -type f`, 44 files this session):

| Kind | Location | Case |
|---|---|---|
| Component | `features/<f>/ui/PascalCase.tsx` | PascalCase |
| Pure function / type | `features/<f>/lib/camelCase.ts` | camelCase |
| Hook | `features/<f>/useCamelCase.ts` (feature root) | `use…` |
| React Query hooks | `features/<f>/hooks.ts` | — |
| Unit test | colocated `*.test.mjs` beside its module, `node:test` | — |

**There are no barrel files.** `find desktop/src/features -name index.ts` returns exactly one hit,
`features/huddle/index.ts`, on the delete list `[V]`. Perch adds none — a barrel over
`features/perch/**` would make the file-size ratchet's per-file diff useless and would import every
surface into every route.

**DECIDED — the Perch feature tree.** No plan document names one (`grep -rn 'features/perch'` over
all twelve returns nothing `[V]`). Perch is **six** feature directories plus shared additions, not
one:

```
BUZZ desktop/src/features/perch/            shell-level: governance strip, keymap registry, density
BUZZ desktop/src/features/perch-watch/      S1 The Watch, S2 the Verdict Row
BUZZ desktop/src/features/perch-evidence/   the marker registry + the seven cards  (§3)
BUZZ desktop/src/features/perch-containment/ S6 Containments
BUZZ desktop/src/features/perch-policy/     S7 Policy, S10 Tuning bench, S12 Gaps
BUZZ desktop/src/features/perch-shift/      S11 Handoff, S9 Ledger result rows
BUZZ desktop/src/shared/ui/perch/           cross-surface primitives (§5) — new subdirectory
```

Six directories, not one, because `features/<f>` must not import from another `features/<f>`
(mobile's rule at `BUZZ CLAUDE.md`; desktop's tree observes it) — a single `features/perch` would
make every cross-surface primitive an intra-feature import and hide the coupling the ratchet is
supposed to surface. Cross-surface primitives live under `shared/ui/perch/`, which every feature may
import.

### 1.2 Props style

Three real forms exist in `shared/ui`; use the one that matches the component's class.

| Form | When | Precedent |
|---|---|---|
| `interface XProps extends React.HTMLAttributes<E>, VariantProps<typeof xVariants> {}` | a cva primitive that forwards DOM props | `shared/ui/badge.tsx:27-29` `[V]` |
| `type XProps = { … }` above the function | a component with a closed prop set | `features/messages/ui/WaveMessageAttachment.tsx:19-25` `[V]` |
| inline object type on the destructure | small leaf components | `features/agents/ui/AgentStatusBadge.tsx:10-24` `[V]` |

Named exports only. `export function X(…)`, or `React.forwardRef` + `X.displayName = "X"` when a ref
is needed (`shared/ui/button.tsx:44-58`, `shared/ui/progress.tsx:10-45`) `[V]`. `cn` comes from
`@/shared/lib/cn`; variant groups from `class-variance-authority`.

### 1.3 `data-testid` — the real convention

Measured across `BUZZ desktop/src` this session: **1,362 occurrences, 1,162 distinct** `[V]`.
Playwright selects with `page.getByTestId("…")` — **8,135** call sites across
`BUZZ desktop/tests/e2e/`, against 246 raw `[data-testid=` CSS selectors `[V]`. So:

- **kebab-case, feature-prefixed, no camelCase, no colons.**
- Per-row ids are template literals: `` data-testid={`channel-unread-${channelName}`} `` `[V]`
  (36 such patterns in the tree).
- **Every Perch testid begins `perch-`.** The Buzz brand cascade in `theme.css` selects on Buzz's
  own testid values (`app-sidebar`, `stream-list`, `dm-list`, `community-rail`), which is why
  `00-BRIEF.md` §5.2 warns against renaming them; a `perch-` prefix guarantees a Perch id can never
  collide with a themed Buzz id. **DECIDED.**

### 1.4 `data-perch-role` — a second attribute, for the CI guards

`INV-11` already names `data-perch-role="grant"` and `INV-10`/`INV-07`/`INV-09` are greps over
source. Testids churn (1,162 of them, renamed freely); a security grep must not.

**DECIDED:** `data-perch-role` is a **closed** attribute with exactly these values, asserted
exhaustive by `tools/check-perch-grant-affordance.sh` **(PROPOSED — the script does not exist;
neither repo has `tools/check-copy-banned-terms.sh` either, see §2.6)**:

`grant` · `refuse` · `verdict-slot` · `blast-radius` · `provenance-row` · `derived` ·
`source-count` · `evidence-card` · `adversary-string` · `containment-release` ·
`containment-extend-disabled` · `empty-state` · `gap-link`

Testids are for Playwright. `data-perch-role` is for grep gates. Never overload one for the other.

### 1.5 The memo contract — the reason the registry's props are small

`MessageRow` is `React.memo(fn, comparator)` at `BUZZ desktop/src/features/messages/ui/MessageRow.tsx:74`,
comparator at **`:935-995`** `[V]`. **Correction to the ground notes:** the comparator has **46**
`&&`-joined clauses over **46** distinct prop paths (16 `message.*`, 30 row props), not 60
(`awk 'NR>=935&&NR<=996' … | grep -o '&&' | wc -l` → 45) `[V]`.

The clauses that already exist and that a marker renderer needs: `message.id`, `message.pubkey`,
`message.body`, `message.kind`, `message.tags` (value-compared via `tagsEqual`), `message.createdAt`,
`searchQuery` `[V]`. **A renderer derived only from those needs no new comparator clause.** Any new
prop drilled into `MessageRow` for Perch must be added to the comparator *and* be reference-stable,
or every row in an open case re-renders on every streamed event — the failure mode
`CLAUDE.md` gotcha 6 documents. This is why §3's registry takes a five-field context object from a
provider, not MessageRow's 21-value body prop bag.

### 1.6 The gate-line budget, arithmetic included

`BUZZ scripts/check-file-sizes-core.mjs:24-29` counts `content.split(/\r?\n/).length` — **`wc -l`
plus one** for a newline-terminated file. `allowedLineCount` at `:31-33` is
`baseLines <= maxLines ? maxLines : baseLines`, so an over-cap file is **frozen at its current
size**, never granted headroom `[V]`. Governed roots that matter here, from
`BUZZ desktop/scripts/check-file-sizes.mjs:10-55`: `src/app`, `src/features`, `src/shared/api`,
`src/shared/context`, `src/shared/lib`, `src/shared/ui` (`.ts`/`.tsx`), `src/shared/styles` (`.css`)
`[V]`. `src/shared/hooks`, `src/shared/theme`, `src/shared/constants` and `src/testing` are
**ungoverned** `[V]`.

Measured with `content.split(/\r?\n/).length` this session `[V]`:

| File | Gate-lines | Cap in force | Headroom |
|---|---:|---:|---:|
| `features/messages/ui/MessageRow.tsx` | **999** | 1000 | **1** |
| `app/AppShell.tsx` | **998** | 1000 | **2** |
| `shared/ui/sidebar.tsx` | 1011 | 1011 (frozen) | **0** |
| `shared/ui/markdown.tsx` | 1906 | 1906 (frozen) | **0** |
| `shared/api/tauri.ts` | 1108 | 1108 (frozen) | **0** |
| `shared/api/relayClientSession.ts` | 1084 | 1084 (frozen) | **0** |
| `shared/api/types.ts` | **1000** | 1000 | **0** |
| `shared/styles/globals/theme.css` | 968 | 1000 | 32 |
| `features/home/ui/HomeView.tsx` | 994 | 1000 | 6 |
| `features/home/ui/InboxDetailPane.tsx` | 924 | 1000 | 76 |

**Every new Perch file budgets against 1000 gate-lines = 999 `wc -l` lines.** Every budget below is
stated in gate-lines. A component whose spec would exceed ~600 is split at spec time, not at review.

### 1.7 ARIA, read from the tree

`role="status"` 34 uses, `aria-live="polite"` 32, `role="alert"` 28, `aria-live="assertive"` 2 `[V]`.
Perch's rule, **DECIDED**: a value that changes on a timer (`ContainmentTimer`, `HoldTtlClock`,
`InstrumentationStrip`) is `aria-live="off"` with an `aria-label` refreshed at most once a minute —
a 1 Hz `polite` region reads a countdown aloud forever. A write-state transition
(`WriteStateRow`) is `role="status"` + `aria-live="polite"`. A refusal or an expired-and-still-held
containment is `role="alert"` — the only two `assertive` cases in Perch.

### 1.8 The registry precedent already in the tree

`BUZZ desktop/src/features/agents/ui/activityRenderClasses/TranscriptActivityItem.tsx:16-37` `[V]` —
an exhaustive `satisfies Record<AgentActivityRenderClass, ActivityRenderClassPresenter>` map (15
classes → 7 presenters) plus a three-line dispatcher that indexes it. The presenter type is
`React.ComponentType<ActivityRenderClassItemProps>` at
`activityRenderClasses/types.ts:12-18`, and the props are a **four-field** object
(`agentAvatarUrl`, `agentName`, `agentPubkey`, `item`, `profiles`) — deliberately far smaller than
the transcript view's own props. §3 is this shape with a decode step added.

### 1.9 Token namespace — a Perch component names `--perch-*` and nothing else

**Revision 2 correction.** Revision 1 of this sheet named bare Buzz shadcn variables (`--card`,
`--muted-foreground`, `--border`, `--foreground`, `--surface-raised`, `--border-strong`,
`--pillar-*`, `--danger-mark`). That is unbuildable, and the reason is a mechanism, not a
convention.

**The mechanism, read this session `[V]`.** `createThemeVars(bg, fg, comment, gitColors)`
(`BUZZ desktop/src/shared/theme/adaptive-theme.ts:191-289`) returns a `Record<string,string>` of
**exactly 38** variables — counted, `awk '/return \{/,/^\}/' … | grep -c '"--'` → 38 — and the set
includes every name revision 1 used: `--background`, `--card`, `--card-foreground`, `--foreground`,
`--muted-foreground`, `--popover`, `--popover-foreground`, `--border`, `--input`, `--ring`,
`--destructive`, the six `--sidebar-*`, the ten `--huddle-*`, `--status-added|deleted|modified`,
`--ui-warning`, `--ui-warning-bg`.

`ThemeProvider`'s `applyTheme` — the renderer-process function that runs on every theme change and
on boot — calls it at `:439-444` and then writes **every returned key inline on the root element**:

```ts
// BUZZ desktop/src/shared/theme/ThemeProvider.tsx:444-446
const root = document.documentElement;
for (const [key, value] of Object.entries(vars)) {
  root.style.setProperty(key, value);
}
```

`applyCachedVars` does the identical write on the synchronous no-FOUC boot path at `:404-406`, and
`applyAccentColor` writes six more (`--primary`, `--primary-foreground`, `--sidebar-primary`,
`--sidebar-primary-foreground`, `--sidebar-active`, `--sidebar-active-foreground`) at `:213-218`
and `:231-236` `[V]`.

An inline declaration on `:root` outranks every normal-priority stylesheet rule, at any layer, with
any selector specificity. So a Perch stylesheet that redefines `--card` **loses silently**, and the
loss is invisible in review: the component compiles, renders, and repaints in whatever Buzz syntax
theme the operator last chose.

**The contract, binding on every component in this sheet.** A Perch-authored component reads only
`--perch-*` names, which `19-TOKENS.md` owns and `tokens/perch-tokens.css` defines. The name map for
every token this sheet cites:

| Revision-1 name (wrong) | Revision-2 name | Note |
|---|---|---|
| `--card` | `--perch-card` | |
| `--background` | `--perch-background` | |
| `--foreground` | `--perch-foreground` | |
| `--muted-foreground` | `--perch-foreground-muted` | **word order differs** — not a prefix-only rename |
| — | `--perch-foreground-secondary` | no Buzz equivalent; the second ink step |
| — | `--perch-foreground-faint` | disabled only, never text — `19-TOKENS` "NEVER TEXT" |
| `--surface-chrome` | `--perch-surface-chrome` | |
| `--surface-raised` | `--perch-surface-raised` | |
| `--border` | `--perch-border` | |
| `--border-strong` | `--perch-border-strong` | |
| `--ring` | `--perch-ring` | |
| `--pillar-<x>` | `--perch-pillar-<x>-mark` | the rail; `-ink` is the text member |
| `--border-pillar-<x>` | `--perch-border-pillar-<x>` | decoration only |
| `--danger-mark` | `--perch-danger-mark` | never text (dark measures 3.70 on raised) |
| severity hues | `--perch-sev-{low,medium,high,critical}` | |

**The bridge is not an escape hatch.** `tokens/perch-tokens.css` §9 ships a Buzz-name bridge in two
halves for the **47 inherited `shared/ui` files** Perch keeps — a permanent plain block, and a
hardened `:root[data-perch-theme-pin]` block using `important` (`perch-tokens.css:615-647`) which
does outrank inline, and which `19-TOKENS.md` commits to deleting in the same change that stops
`applyTheme`/`applyAccentColor` writing app-chrome vars. A **new** Perch component must not depend
on either half: the plain half is defeated by the same inline write, and the hardened half has a
scheduled deletion date. Inherited files use the bridge; authored files use `--perch-*`.

**Mechanically checkable.** After the rename this is a grep: no file under the six Perch feature
roots or `shared/ui/perch/` may contain `var(--` followed by anything but `perch-` or `buzz-type-`.
That regex is one row in `check-perch-chart-tokens.sh` (`18-DATAVIZ.md` §13, PROPOSED) widened from
charts to the whole Perch tree; this sheet records the rule and the scope, and `18` owns the script.

### 1.10 The readable-text tier — a floor, not a preference

The wave-2 design review measured the drawn prototypes and found `≥14px` at 3–6% of visible text
nodes on three of five surfaces, with the primary hierarchy step everywhere being 11px→12px. That
is a component-contract failure as much as a drawing one, because a component that specifies
`text-2xs` for its body text makes every surface built from it small. This sheet fixes it at the
contract.

**The ramp, read from source `[V]`** (`BUZZ desktop/tailwind.config.js:11-31`,
`BUZZ desktop/src/shared/styles/globals/typography.css:16-41`). Every token derives from
`--buzz-type-rem`, and the Font-size preference scales that rem: `smaller` = 13/14, `larger` = 15/14
(`typography.css:44-52`). So each token has a **worst case** at the `smaller` preference:

| Token | Multiplier | Default | At `smaller` | Buzz uses | Perch may use it for |
|---|---:|---:|---:|---:|---|
| `text-base` | 1.0 | 16.0px | 14.9px | — | a surface's one primary line |
| `text-sm` | 0.875 | 14.0px | 13.0px | — | **card bodies, the ACTION sentence, row line 1, lane values, host names** |
| `text-message` | 0.875 | 14.0px | 13.0px | — | anything rendered inside the case timeline, for parity with Buzz prose |
| `text-xs` | 0.75 | 12.0px | 11.1px | — | secondary row lines, field labels, help text |
| `text-eyebrow` | 0.75 `[P]` | 12.0px | 11.1px | — | SCREAMING slot labels and eyebrows only (`19-TOKENS`) |
| `text-2xs` | 0.6875 | 11.0px | **10.2px** | 152 sites | timestamps, count badges, tracking labels, chart tick labels |
| `text-badge` | 0.625 | 10.0px | 9.3px | 8 sites | a numeral inside a pill |
| `text-3xs` | 0.5 | 8.0px | **7.4px** | 15 sites | **glyph adornments only — never a word an operator must read** |

**Three rules, binding on every spec in this sheet.**

1. **A component's primary content line is `text-sm` or larger.** For the Tier A safety components
   that means: `VerdictSlot`'s slot body, `GrantControl`'s label, `SourceCount`'s own sentence,
   `WriteStateRow`'s sentence, `ProvenanceRows`' chain and state words, `RollbackStepList`'s five
   status words, `ContainmentTimer`'s remaining figure, `VerdictQueueRow`'s line 1. Meta-text
   tokens carry meta text; a safety string is not meta text.
2. **`text-3xs` renders no word.** At the `smaller` preference it is 7.4px — smaller than any
   readable floor, and it does not survive being read across a room on `/watch-floor`. Buzz itself
   spends it 15 times in ~1,600 files. Perch's only permitted uses are a glyph adornment and a
   superscript marker.
3. **A hierarchy step is one full token, not 1px.** `text-2xs` → `text-xs` is 11→12px, which a
   fatigued reader at 03:00 does not resolve. Where two lines must differ, the step is
   `text-2xs` → `text-sm` (11→14px) or the difference is carried by weight, case, or the mono
   stack — never by a single pixel.

**The check.** A headless computed-`font-size` census over each surface's visible, non-developer
text nodes, asserting `≥ text-sm` on at least a quarter of them on any decision surface and **zero**
`text-3xs` word nodes. It is not a shipped gate; it is the acceptance criterion a surface's own
Playwright spec carries, and it is written here so a reviewer has a number to hold a screen to.

---

## 2. Corrections this sheet acts on

The ground pass's corrections are inherited. These are **new**, found this session, and they change
what a producer builds.

### 2.1 `card.tsx`, `dialog.tsx`, `popover.tsx` and `alert-dialog.tsx` are coupled to the deleted card texture

`05` §9 and the design ground both list `card.tsx`, `dialog.tsx` and `popover.tsx` as **reuse
verbatim** and list `card-texture.css` + four PNGs (3,424,707 B) as **delete**. Both cannot hold:

| File | Coupling | Verdict per `05` §9 |
|---|---|---|
| `BUZZ desktop/src/shared/ui/card.tsx` | `import "./card-texture.css";` at **`:6`**; `TEXTURED_SURFACE_CLASS` at `:11-12`; `texturedSurfaceClasses()` at `:14-26`; `cardVariants` `textured` arm at `:55-60`; `textureSize`/`textureTone` props at `:72-73`; `buzz-card-textured-*` classes at `:96,:99` | reuse verbatim |
| `BUZZ desktop/src/shared/ui/dialog.tsx` | `import "./card-texture.css";` at **`:9`**; `surface?: "default" \| "none" \| "textured"` at `:59`; textured arms at `:96`, `:104-107`, `:122-123` | reuse verbatim |
| `BUZZ desktop/src/shared/ui/popover.tsx` | imports `CardTextureSize`, `CardTextureTone`, `texturedSurfaceClasses` from `@/shared/ui/card` at **`:5-9`**; applied at **`:65-68`**; `sideOffset` branches on `surface === "textured"` at `:58` | reuse verbatim |
| `BUZZ desktop/src/shared/ui/alert-dialog.tsx` | same import at **`:8-11`**; applied at **`:78-81`** | re-skin |

`[V]` on every line, `grep -n 'texturedSurfaceClasses\|card-texture'` this session.

**Consequence.** Deleting the texture is a **four-file `shared/ui` edit**, not an asset deletion.
The `textured` arm's ten consumers are all in `features/communities/` and `features/onboarding/`
(`WelcomeSetup.tsx` ×5, `HostedCommunityOnboarding.tsx` ×4, `InviteRedeemForm.tsx`, `BackupStep.tsx`,
`SetupStep.tsx`, `IdentityKeyHelpDialog.tsx`, `BackupTestFlow.tsx`, `NostrKeyImportForm.tsx`,
`MachineOnboardingFlow.tsx` ×2) `[V]` — every one inside a surface `00-BRIEF.md` §5.4 already cuts
or reduces, so no Perch surface loses anything. But the four `shared/ui` files move from **reuse
verbatim** to **re-skin (net-negative edit)** in §8.

### 2.2 `ViewLoadingFallback.tsx` is not reusable verbatim either

`BUZZ desktop/src/shared/ui/ViewLoadingFallback.tsx:2` imports `BuzzLoadingState` (delete list,
`05` §9) and renders it at `:407`; its `ViewLoadingFallbackKind` union at `:8-14` is literally Buzz's
routes — `agents | channel | forum | projects | pulse | workflows` — **none of which is a Perch
route** `[V]`. It is a re-skin: the union becomes Perch's view ids and the `projects` branch that
calls `BuzzLoadingState` is deleted.

### 2.3 `sidebar-action-card.tsx` imports a deleted provider

`BUZZ desktop/src/shared/ui/sidebar-action-card.tsx:16` imports from `@/shared/ui/PoofBurstProvider`
`[V]`. The design ground's `[P]` disposition ("reuse verbatim") cannot stand; it is a re-skin whose
delta is removing the poof call.

### 2.4 The shield ban touches twelve files at fifteen sites, not nine

`grep -rln 'Shield' desktop/src --include='*.tsx'` this session `[V]`:
`features/agents/ui/activityRenderClasses/LifecycleActivity.tsx:66` ·
`features/channels/ui/MembersSidebarMemberCard.tsx:409,:453` ·
`features/community-members/ui/CommunityMembersCard.tsx:58,:60,:220` ·
`features/community-members/ui/CommunityMembersSettingsCard.tsx:155` ·
`features/moderation/ui/MessageModerationMenuItems.tsx:120` ·
`features/onboarding/ui/BackupStep.tsx:272` ·
`features/onboarding/ui/IdentityRecoveryPairing.tsx:178` ·
`features/onboarding/ui/MembershipDenied.tsx:110` ·
`features/projects/ui/ProjectRepositoryManagement.tsx:203` ·
`features/settings/ui/ModerationQueueCard.tsx:317` ·
`features/settings/ui/PrivateKeyBackupRow.tsx:181` ·
`features/settings/ui/SettingsPanels.tsx:214`.

**Four** are on Perch's reuse path, not two: `ModerationQueueCard` (the tuning-bench card pattern,
`04` §2.10), `MembersSidebarMemberCard` (the case members panel), `LifecycleActivity` (one of the 15
agent activity render classes `00-BRIEF.md` §5.4 explicitly keeps), and `SettingsPanels`
(`/settings`, which `APPENDIX-NORMATIVE.md` §1 makes Phase 0). Replacements in §8.

### 2.5 The `MessageRow` `default:` arm is 48 lines, and that is the split's arithmetic

`renderBody` is `:381-463`; `switch` `:382-462`; `case KIND_STREAM_MESSAGE_DIFF:` `:383`;
`case KIND_HUDDLE_STARTED:` `:406`; **`default: {` `:414`, closing `}` `:461`** `[V]`. Replacing that
arm with a single `<MessageBody … />` call returns **~40 gate-lines** to a file with 1 to spare,
before counting the nine imports that leave with it. This is the only reason a Perch marker can land
at all.

### 2.6 Guards this sheet depends on — status, owner, and what fails without each

BUZZ has **no `tools/` directory at all** `[V]`; `AMB tools/` holds 14 `check-*.sh` and one
`verify-*.sh`, none of them a Perch guard (this corrects revision 1's "23 other `check-*.sh`", which
counted a stale figure inherited from a ground note). Every guard this sheet's contracts feed is
therefore **PROPOSED**. Enumerated so nobody re-discovers the hole:

| Guard | Status | Owner | What this sheet contributes | What is unenforced without it |
|---|---|---|---|---|
| `AMB tools/check-copy-banned-terms.sh` | **written** in `skeleton/tools/`, not landed | `16` | the rendered strings in §3.6, §4.4, §5.10, §6.x | every vocabulary ban in `APPENDIX` §7 |
| `AMB tools/copy-ban-list.tsv` | **written**, not landed | `16` | — | — |
| `BUZZ desktop/scripts/check-copy-banned-terms.mjs` | **MISSING** | `16` (its D2 parity test needs it) | the Perch feature roots it must scan | the Buzz half of the copy gate: the `.sh` scans a Buzz checkout via `PERCH_DESKTOP_ROOT`, and `16` D2's byte-for-byte parity test over `tools/fixtures/copy-corpus/` has no second implementation to compare against |
| `AMB tools/check-perch-grant-affordance.sh` | **written**, not landed | `16` | §1.4's closed 13-value `data-perch-role` set; §4.4's grant contract | render law 6 and INV-10/INV-11 |
| `AMB tools/check-perch-adversary-strings.sh` | **written**, not landed | `16` | §4.1's `AdversaryString` as sole consumer | INV-14's four escape hatches |
| `AMB tools/check-perch-write-allowlist.sh` | **written**, not landed | `16` | — | INV-01 |
| `BUZZ scripts/check-csp-pin.mjs` | **written**, not landed | `16` | — | INV-30 |
| `AMB tools/check-perch-notification-fields.sh` | **MISSING** | `14` (owns the notification module's shape) | — | INV-20 |
| `AMB tools/check-perch-chart-tokens.sh` | **MISSING** | `18` §13 | **§1.9 widens its scope** from chart files to the whole Perch tree: no `var(--` outside `--perch-*` / `--buzz-type-*` | §1.9's whole contract; a bare `--card` reference reverts to Buzz's theme with no symptom |
| `BUZZ desktop/scripts/check-svg-font-size.mjs` | **MISSING** | `18` §13 (G1) | §7 rule 1 | an SVG `font-size="11"` attribute and a JSX `fontSize={11}` prop both pass the shipped px-text guard |
| `AMB tools/check-perch-surface-count.sh` | **MISSING** | `21`/ADR set | — | the fourteen-surface closure |
| `BUZZ desktop/scripts/check-route-tree.mjs` | **MISSING** | `14` | — | `routeTree.gen.ts` drift |

**Two-part landing rule, verified `[V]`.** `AMB tools/check-gates-wired.sh:19-56` enumerates every
`check-*`/`verify-*` script — tracked or untracked — and fails if it is not named by a real workflow
`run:` command, rejecting any `if:` other than `always()`/`!cancelled()`. So each guard above and its
`.github/workflows/ci.yml` step must land in the **same commit**;
`skeleton/tools/ci-wiring.snippet.yml` currently carries steps for five of the twelve. The seven
without a step are a `20-TASK-BREAKDOWN.md` row, not a note in this sheet.

### 2.7 A deposit path that writes an **unscoped** source id — and what it does to render law 2

Found this session while re-verifying §4.8's mechanism. It is not in any plan document.

`apply_providence_feedback` (`AMB crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:294`,
`pub(crate)`, the function the daemon's analyst-feedback handler calls inside the
`swarm_detect --serve` process — the same handler **B3** extends) builds a `PheromoneDeposit` through
`signed_providence_feedback_deposit` at `:497` and writes it straight into the substrate
(`state.current_substrate().deposit(deposit)` at `:317` for Confirm, `:349` Dismiss, `:416`
Investigate) `[V]`.

That deposit's `agent_id` is set at `:536` to
`AgentId::from_verifying_key(&state.signing_key.verifying_key())` — which
`AgentId::from_public_key_hex` (`AMB crates/swarm-core/src/types.rs:16-18`) formats as
`swarm:ed25519:{64hex}` `[V]`. **Three colon-segments, the daemon's own key, no agent slug, no
strategy segment.** `concentration_for` then inserts that string into the sources set at
`substrate.rs:1295` like any other.

Four consequences the components in this sheet must render, none of them cosmetic:

1. **A Confirm makes the operator a source.** Confirm passes `confidence: 1.0` (the argument at
   `:310`; Dismiss passes `0.0` at `:342` and Investigate `0.0` at `:409`), so
   `strength_at` returns a positive value and `concentration_for`'s `if strength <= 0.0 { continue }`
   guard at `substrate.rs:1291-1293` does not skip it. On a class carried by one detector, one
   Confirm takes `distinct_sources` from 1 to 2 and satisfies `min_sources_for_escalation: 2`.
   Dismiss and Investigate are skipped by that same guard, so **only Confirm** does this.
2. **Every feedback deposit in the deployment shares one id** — the daemon key — so N Confirms by M
   operators collapse to exactly one source, forever.
3. **It never evaporates.** The deposit's `timestamp` is `recorded_at_ms` (milliseconds) while
   `concentration_for`'s `now` is unix **seconds**, so `strength_at`'s `if now <= self.timestamp`
   early return at `AMB crates/swarm-core/src/pheromone.rs:282-284` returns full confidence forever
   `[V]`. `22-DEMO-FIXTURE.md` F-4 found the same thing independently from the fixture side.
4. **The naive agent derivation corrupts it.** `18-DATAVIZ.md:364` derives the agent half of
   `N sources / M agents` as `id.split(":").slice(0, -1).join(":")`, which turns
   `swarm:ed25519:{64hex}` into the literal `swarm:ed25519` — one fabricated "agent" absorbing every
   operator-feedback deposit in the system. §4.8 specifies the derivation that handles both shapes
   and offers it as the shared helper `18` should import.

**This is the "what would still pass?" answer for render law 2.** The law's own mechanism is
strategy-scoping, and six wave-2 producers verified it correctly. But the law is *also* satisfiable
by an id that carries no strategy at all, produced by the operator's own keystroke, on the exact
route `B3` is being built to call. `SourceCount` renders that row differently or the screen claims
corroboration that does not exist.

---

## 3. The marker-renderer registry

The extension point for all seven `kind:9` `ambush:*:v1` cards (`APPENDIX-NORMATIVE.md` §3). Its
shape decides whether an eighth marker is a two-file change or a seven-file one. Governing sections:
`03` §3/§4.4/§13, `04` §2.3, `05` §9, `08` §7.7 control 2, INV-13, INV-15.

### 3.1 What it replaces, exactly

Today `MessageRow.renderBody`'s `default:` arm at `MessageRow.tsx:414-461` `[V]` does two things in
the renderer process, inside the memoized `MessageRow` closure, on every timeline row Buzz does not
have a `case` for: it calls `parseWaveMessageContent(message.body)` at `:415` — whose predicate is
`content.trimStart().startsWith(WAVE_MESSAGE_MARKER)` over arbitrary body text
(`features/messages/lib/waveMessage.ts:15-19` `[V]`) — and, when that returns `null`, renders
`VideoReviewCommentMarkdown` at `:429-458` with **eighteen** props threaded from the row closure
(counted from source `[V]`).
`VideoReviewCommentMarkdown` is on `05` §9's delete list, so the fallthrough changes regardless.

Perch does **not** add seven `if` branches there. It replaces the whole arm with one call.

### 3.2 The file set

| File | Contents | Budget (gate-lines) |
|---|---|---:|
| `BUZZ desktop/src/features/messages/ui/MessageBody.tsx` | the extracted `default:` arm: wave sniff → ambush registry → markdown fallthrough | 200 |
| `BUZZ desktop/src/features/perch-evidence/lib/markerTypes.ts` | the closed kind union, the parse result union, `AmbushCardEntry`, `defineAmbushCard` | 160 |
| `BUZZ desktop/src/features/perch-evidence/lib/parseAmbushMarker.ts` | the line-0 + admission parse (INV-15) | 120 |
| `BUZZ desktop/src/features/perch-evidence/lib/parseAmbushMarker.test.mjs` | the parse table test | 220 |
| `BUZZ desktop/src/features/perch-evidence/ui/ambushCardRegistry.tsx` | the `satisfies Record<>` map + `AmbushEvidenceCard` dispatcher | 110 |
| `BUZZ desktop/src/features/perch-evidence/ui/EvidenceCardFrame.tsx` | rail, eyebrow, provenance slot, expand | 190 |
| `BUZZ desktop/src/features/perch-evidence/ui/RefusalCards.tsx` | the four refusal states (§3.6) | 140 |
| `BUZZ desktop/src/features/perch-evidence/ui/cards/*.tsx` | seven presenters | 140–280 each |
| `BUZZ desktop/src/features/perch-evidence/AmbushCardContext.tsx` | the five-field provider | 90 |

All under `src/features`, all governed at 1000, all comfortably inside it.

### 3.3 The types — written out

```ts
// BUZZ desktop/src/features/perch-evidence/lib/markerTypes.ts
import type * as React from "react";

/**
 * The seven marker slugs, closed. The registry is APPENDIX-NORMATIVE.md §3;
 * an eighth needs `03` §4.4's justification shape before this union grows.
 */
export type AmbushMarkerKind =
  | "finding"
  | "escalation"
  | "hold"
  | "verdict"
  | "receipt"
  | "lease"
  | "rollback";

export const AMBUSH_MARKER_KINDS = [
  "finding",
  "escalation",
  "hold",
  "verdict",
  "receipt",
  "lease",
  "rollback",
] as const satisfies readonly AmbushMarkerKind[];

/** The only admitted schema version. A `v2` card renders as §3.6's refusal, never as prose. */
export const AMBUSH_MARKER_VERSION = 1;

/**
 * `<!-- ambush:finding:v1 -->`. Built here so no call site concatenates the
 * string; `check-perch-adversary-strings.sh` (PROPOSED) treats a hand-built
 * marker literal outside this module as a failure.
 */
export function ambushMarkerComment(kind: AmbushMarkerKind): string {
  return `<!-- ambush:${kind}:v${AMBUSH_MARKER_VERSION} -->`;
}

/** Which Perch surface is rendering. Decides `homeSurface` admission. */
export type AmbushCardSurface = "case" | "lane" | "ledger" | "export-preview";

/**
 * The three-hue taxonomy (brief A9). Values live in 19-TOKENS.md. Each pillar ships
 * as a PAIR of tokens — `--perch-pillar-<x>-ink` (text and glyphs, >=4.5:1) and
 * `--perch-pillar-<x>-mark` (fills, rails, chart strokes, >=3:1) — because on a light
 * surface all three Ambush hues fail even the 3:1 non-text bar (measured: #4ade80
 * 1.49:1, #f59e0b 1.84:1, #22d3ee 1.55:1 against light chrome). A component takes
 * the pillar name and picks the pair member; it never takes a hex, and never a
 * bare Buzz shadcn name (§1.9 — ThemeProvider writes 38 of those inline on :root).
 */
export type PerchPillar = "substrate" | "authority" | "evidence";

/** A marker that passed line-0 + admission. `rawBody` is never trimmed. */
export type AmbushMarkerCard = {
  kind: AmbushMarkerKind;
  version: typeof AMBUSH_MARKER_VERSION;
  /** Everything after the first newline, byte-for-byte. Interior whitespace is load-bearing. */
  rawBody: string;
  /** The signer whose admission was checked. Lowercased 64-hex, asserted by the parser. */
  issuerPubkey: string;
  /** The `h` tag on the carrying event, for INV-13's case-channel equality check. */
  channelTag: string | null;
  /** The carrying event id, so a refusal state can name it and a verify affordance can refetch. */
  eventId: string;
};

/** Five outcomes. Only `ok` reaches a presenter; the rest are §3.6. */
export type AmbushMarkerParse =
  | { status: "not-a-marker" }
  | { status: "unadmitted-issuer"; slug: string; issuerPubkey: string | null }
  | { status: "unknown-kind"; slug: string; version: number; card: Omit<AmbushMarkerCard, "kind" | "version"> }
  | { status: "unsupported-version"; kind: AmbushMarkerKind; version: number; card: Omit<AmbushMarkerCard, "kind" | "version"> }
  | { status: "ok"; card: AmbushMarkerCard };

/** A decoder owns one marker's payload shape. 13-WIRE-SCHEMAS.md owns the shapes. */
export type AmbushCardDecodeResult<T> =
  | { ok: true; value: T }
  | { ok: false; reason: string };

export type AmbushCardDecoder<T> = (rawBody: string) => AmbushCardDecodeResult<T>;

/**
 * Everything a presenter may read. Five fields, all reference-stable, supplied by
 * `AmbushCardProvider`. Deliberately NOT MessageRow's props: a presenter that could
 * reach `onReply`, `profiles` or `videoReviewContext` would make marker #8 a
 * MessageRow edit, and MessageRow has one gate-line of headroom (§1.6).
 */
export type AmbushCardContext = {
  surface: AmbushCardSurface;
  /** The open case's channel UUID when `surface === "case"`, else null. INV-12/INV-13. */
  caseChannelId: string | null;
  /** Highlight terms, threaded through unchanged. */
  searchQuery: string;
  /** `comfortable | compact` — read once at the provider, never per card. */
  density: "comfortable" | "compact";
  /** Refetch this card's artifact from the daemon by id. Returns a byte-diff verdict. */
  verifyAgainstDaemon: (card: AmbushMarkerCard) => Promise<DaemonVerifyResult>;
};

export type DaemonVerifyResult =
  | { status: "match" }
  | { status: "diverged"; summary: string }
  | { status: "absent" }            // INV-35: FORGED
  | { status: "unreachable"; reason: string };

export type AmbushCardProps<T> = {
  card: AmbushMarkerCard;
  payload: T;
  ctx: AmbushCardContext;
};

export type AmbushCardRenderArgs = {
  card: AmbushMarkerCard;
  ctx: AmbushCardContext;
};

/**
 * Erased registry entry. The payload type never escapes `defineAmbushCard`,
 * which is the one place decoder output and presenter input are checked against
 * each other. That is what keeps the map a plain `Record`.
 */
export type AmbushCardEntry = {
  pillar: PerchPillar;
  /** Refuses to render outside these surfaces. A `hold` card in a lane is a bug, not a view. */
  homeSurface: readonly AmbushCardSurface[];
  render: (args: AmbushCardRenderArgs) => React.ReactElement;
};

export function defineAmbushCard<T>(spec: {
  pillar: PerchPillar;
  homeSurface: readonly AmbushCardSurface[];
  decode: AmbushCardDecoder<T>;
  Presenter: React.ComponentType<AmbushCardProps<T>>;
}): AmbushCardEntry {
  const { decode, Presenter, pillar, homeSurface } = spec;
  return {
    pillar,
    homeSurface,
    render: ({ card, ctx }) => {
      const decoded = decode(card.rawBody);
      if (!decoded.ok) {
        return <UndecodableCard card={card} reason={decoded.reason} />;
      }
      return <Presenter card={card} ctx={ctx} payload={decoded.value} />;
    },
  };
}
```

`UndecodableCard` is imported from `../ui/RefusalCards`; `defineAmbushCard` therefore lives in a
`.tsx` file (`lib/markerTypes.tsx`) or the helper moves to `ui/`. **DECIDED:** the helper moves —
`lib/markerTypes.ts` stays pure types plus `ambushMarkerComment`, and `defineAmbushCard` lives in
`ui/ambushCardRegistry.tsx` beside the map that consumes it. Pure `lib/` files stay testable under
`node:test` without a JSX transform, matching `features/home/lib/*.test.mjs` `[V]`.

### 3.4 The parse contract — INV-15, written as code

```ts
// BUZZ desktop/src/features/perch-evidence/lib/parseAmbushMarker.ts
import {
  AMBUSH_MARKER_KINDS,
  AMBUSH_MARKER_VERSION,
  type AmbushMarkerKind,
  type AmbushMarkerParse,
} from "./markerTypes";

const MARKER_RE = /^<!--\s+ambush:([a-z][a-z-]*):v(\d{1,3})\s+-->$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

/**
 * Buzz's own sniff is `content.trimStart().startsWith(WAVE_MESSAGE_MARKER)`
 * (features/messages/lib/waveMessage.ts:15-19) over arbitrary body text. That is
 * safe for a wave and unsafe here: `ProcessStartEvent.command_line` and
 * `DetectionFinding.evidence` reach this renderer. Perch's sniff is
 * line-0-exact AND admitted-issuer-only. INV-15.
 */
export function parseAmbushMarker(args: {
  content: string;
  /** `event.pubkey` — the raw signer, NOT a delegated display author. */
  signerPubkey: string | undefined;
  /** `h` tag on the carrying event, or null. */
  channelTag: string | null;
  eventId: string;
  /** Resolves an admitted bridge identity. Reference-stable; see §3.7. */
  isAdmittedIssuer: (pubkey: string) => boolean;
}): AmbushMarkerParse {
  const { content, signerPubkey, channelTag, eventId, isAdmittedIssuer } = args;

  // 1. Line 0 only. No trimStart: a leading space is a producer bug we want to see.
  const newlineAt = content.indexOf("\n");
  const line0 = (newlineAt === -1 ? content : content.slice(0, newlineAt)).trimEnd();
  const matched = MARKER_RE.exec(line0);
  if (!matched) return { status: "not-a-marker" };

  const slug = matched[1];
  const version = Number.parseInt(matched[2], 10);

  // 2. Admission. A well-formed marker from an unadmitted signer is counted and
  //    rendered as prose — APPENDIX-NORMATIVE.md §3's admitted-issuer rule.
  const issuer = signerPubkey?.toLowerCase();
  if (!issuer || !HEX64_RE.test(issuer) || !isAdmittedIssuer(issuer)) {
    return { status: "unadmitted-issuer", slug, issuerPubkey: issuer ?? null };
  }

  // 3. rawBody is byte-exact after the first newline. Never trimmed.
  const base = {
    rawBody: newlineAt === -1 ? "" : content.slice(newlineAt + 1),
    issuerPubkey: issuer,
    channelTag,
    eventId,
  };

  if (!(AMBUSH_MARKER_KINDS as readonly string[]).includes(slug)) {
    return { status: "unknown-kind", slug, version, card: base };
  }
  const kind = slug as AmbushMarkerKind;

  if (version !== AMBUSH_MARKER_VERSION) {
    return { status: "unsupported-version", kind, version, card: base };
  }

  return { status: "ok", card: { ...base, kind, version: AMBUSH_MARKER_VERSION } };
}
```

**Four decisions recorded here.**

1. **`line0.trimEnd()`, never `trimStart()`.** Strictest reading of INV-15 ("the marker is the
   entire first line"), and free.
2. **A well-formed marker from an *admitted* issuer never falls through to markdown.** An unknown
   kind or an unsupported version renders §3.6's refusal card. Falling through would push a JSON
   payload containing `host_id`, `file_path` and `command_line` into `shared/ui/markdown.tsx`'s
   remark pipeline — the exact composition `08` §7.7 control 1 forbids.
3. **`signerPubkey`, not `pubkey`.** `TimelineMessage` carries both
   (`features/messages/types.ts:20-27` `[V]`): `pubkey` may be a delegated author on a
   relay-signed event; `signerPubkey` is the raw event signer. Admission is a signature question.
   Buzz already makes this distinction for exactly this reason in
   `features/messages/ui/configNudgeAuthPubkey.ts`, consumed at `MessageRow.tsx:440-443` `[V]`.
4. **Version is parsed, not pattern-pinned.** `v(\d{1,3})` so a `v2` producer gets the honest
   "this console is older than this card" state instead of silent prose.

### 3.5 The dispatcher — the `TranscriptActivityItem` shape

```tsx
// BUZZ desktop/src/features/perch-evidence/ui/ambushCardRegistry.tsx
export const AMBUSH_CARD_REGISTRY = {
  finding:    findingCardEntry,     // pillar: substrate  · case | lane | ledger
  escalation: escalationCardEntry,  // pillar: authority  · case | lane | ledger
  hold:       holdCardEntry,        // pillar: authority  · case | ledger
  verdict:    verdictCardEntry,     // pillar: authority  · case | ledger | export-preview
  receipt:    receiptCardEntry,     // pillar: evidence   · case | ledger | export-preview
  lease:      leaseCardEntry,       // pillar: evidence   · case | ledger
  rollback:   rollbackCardEntry,    // pillar: evidence   · case | ledger | export-preview
} satisfies Record<AmbushMarkerKind, AmbushCardEntry>;

export function AmbushEvidenceCard({ card, ctx }: AmbushCardRenderArgs) {
  const entry = AMBUSH_CARD_REGISTRY[card.kind];
  if (!entry.homeSurface.includes(ctx.surface)) {
    return <MisplacedCard card={card} surface={ctx.surface} />;
  }
  // INV-13: a verdict card whose `h` tag is not this case refuses to render.
  if (ctx.surface === "case" && card.channelTag !== ctx.caseChannelId) {
    return <MisplacedCard card={card} surface={ctx.surface} reason="channel-mismatch" />;
  }
  return entry.render({ card, ctx });
}
```

**Vocabulary note on the `lease` slug.** `"lease"` is the normative marker identifier from
`APPENDIX-NORMATIVE.md` §3 (`ambush:lease:v1`) and stays verbatim on the wire and in the union. Its
**rendered heading is `CONTAINMENT LEASE`**, never bare "lease" — `APPENDIX-NORMATIVE.md` §7 bans the
bare word in a label, heading, nav item or badge because three unrelated objects carry it. The
registry key and the card's `EyebrowLabel` are deliberately different strings, and
`tools/check-copy-banned-terms.sh` (PROPOSED) must scope its ban to rendered strings or it will fail
on the union.

The `satisfies Record<AmbushMarkerKind, AmbushCardEntry>` is the exhaustiveness gate: adding a
member to `AmbushMarkerKind` without an entry fails `tsc --noEmit`, which the pre-push hook already
runs `[V]` (`BUZZ CLAUDE.md`: pre-push runs desktop TypeScript typechecking). Same mechanism as
`TranscriptActivityItem.tsx:32` `[V]`.

**Pillar assignments, per the design ground's §2.1 table.** finding → substrate; **escalation →
authority** (a threshold crossing is an authority event, not a detection event — `[P]` there, adopted
here); hold and verdict → authority; receipt, containment-lease and rollback → evidence. The rail is
the **classifying** channel at 8.58–10.57:1 against `--perch-card`; the tinted 1px border is
decoration at 1.42–1.49:1 and **no card's classification may depend on it**.

**The `homeSurface` field is not decoration.** `04` §2.5 says a lane is the durable home for
escalation cards; `04` §2.3 says a case holds holds, verdicts, receipts, containment-lease and
rollback cards. A `hold` card appearing in a lane means either a bridge routing bug or a forged
`h` tag, and it renders as a named refusal rather than a card an operator might act on.

### 3.6 The four refusal states — one file, `RefusalCards.tsx`

Each renders in the **destructive register**, names the event id, and offers no verdict control.
None uses `<AdversaryString>` for anything but the slug, which is regex-bounded to `[a-z][a-z-]*`.

| Component | Fires when | Copy shape | `data-testid` |
|---|---|---|---|
| `UndecodableCard` | the decoder returned `ok:false` | "This `<kind>` card did not decode: `<reason>`. The daemon holds the record. [verify against the daemon]" | `perch-evidence-undecodable` |
| `UnknownMarkerCard` | admitted issuer, unknown slug | "This console does not know how to render an `ambush:<slug>:v<n>` card. It was published by an admitted bridge at `<time>`. [open in Ledger]" | `perch-evidence-unknown-kind` |
| `UnsupportedVersionCard` | admitted issuer, known kind, `version !== 1` | "This `<kind>` card is version `<n>`; this console reads version 1. Nothing is rendered rather than rendering it wrong. [open in Ledger]" | `perch-evidence-unsupported-version` |
| `MisplacedCard` | `homeSurface` miss, or INV-13 channel mismatch | "A `<kind>` card arrived on a surface that does not hold them (`<surface>`). It is not rendered here. [open in Ledger]" | `perch-evidence-misplaced` |

All four carry `data-perch-role="evidence-card"` and `role="status"`. None carries `aria-live` — a
timeline replay would otherwise read every refusal aloud.

The fifth outcome, `unadmitted-issuer`, renders **nothing of its own**: `MessageBody` falls through
to the prose path and increments `perch_marker_unadmitted_total` (a bridge-parity counter,
`07` §12). It must not render a refusal card, because a refusal card is a signal an adversary can
plant at will.

### 3.7 What the registry must not take — the memo contract restated

`isAdmittedIssuer` is the one function the parser needs and the one that will silently defeat the
memo if drilled carelessly. **DECIDED:**

- `isAdmittedIssuer` lives on `AmbushCardContext`'s sibling `AmbushAdmissionContext`, produced by a
  `useMemo` over the admitted-issuer set, keyed on the set's own version counter, using
  `BUZZ desktop/src/shared/hooks/useStableReference.ts` — the content-equality ref cache
  `CLAUDE.md` gotcha 6 names for exactly this class `[V]`.
- `MessageBody` reads it from context, **not** from a prop. `MessageRow` therefore gains **zero**
  new props and its 46-clause comparator (`MessageRow.tsx:935-995` `[V]`) is untouched.
- A presenter that needs anything outside `AmbushCardContext`'s five fields is a spec bug. The
  correct fix is to widen the context (one file, one `useMemo`) — never to widen `MessageRow`.

**Cost of an eighth marker, by construction:** one union member, one decoder + presenter file, one
registry line. `tsc` fails until the entry exists. Nothing in `MessageRow`, nothing in
`kinds.ts`, nothing in the relay — kind:9 is already in `CHANNEL_EVENT_KINDS`
(`shared/constants/kinds.ts:100-113`), `CHANNEL_TIMELINE_CONTENT_KINDS` (`:137-149`) and
`isTimelineContentEvent` (`features/messages/lib/formatTimelineMessages.ts:52-66`), and the
`default:` arm already content-sniffs `[V]`. The four client registration points
`APPENDIX-NORMATIVE.md` §3 names are the cost of the **46010** fork, not of a marker.

### 3.8 The E2E bridge obligation, in the same breath

`BUZZ desktop/src/testing/e2eBridge.ts` is 14,620 lines with a `default:` that throws
`Unsupported mocked Tauri command` at `:14593-14594`; a missing case breaks **every** mock-mode
Playwright spec with a "Community connection failed" render `[V]`. The registry itself adds no Tauri
command — `verifyAgainstDaemon` is the one call that leaves the renderer, and it goes through the
Perch daemon-client wrapper `14-CLIENT-ARCHITECTURE.md` owns. **The obligation this sheet records:**
whichever file adds `perch_verify_artifact` must add its `case` to `e2eBridge.ts` in the same commit,
and the seven card fixtures must land as a **delegated module** the bridge imports — never as an
edit that grows the 14,620-line switch.

### 3.9 `MessageBody` — the seam

```tsx
// BUZZ desktop/src/features/messages/ui/MessageBody.tsx
export type MessageBodyProps = {
  message: TimelineMessage;
  channelId: string | null;
  searchQuery?: string;
  emojiOnly: boolean;
  // …the remaining sixteen values MessageRow currently threads into
  // VideoReviewCommentMarkdown at MessageRow.tsx:429-457, unchanged.
};

export function MessageBody(props: MessageBodyProps) {
  const admission = useAmbushAdmission();      // context, not a prop
  const cardCtx = useAmbushCardContext();      // context, not a prop

  const parsed = parseAmbushMarker({
    content: props.message.body,
    signerPubkey: props.message.signerPubkey,
    channelTag: props.message.tags?.find((t) => t[0] === "h")?.[1] ?? null,
    eventId: props.message.id,
    isAdmittedIssuer: admission.isAdmittedIssuer,
  });

  switch (parsed.status) {
    case "ok":
      return <AmbushEvidenceCard card={parsed.card} ctx={cardCtx} />;
    case "unknown-kind":
    case "unsupported-version":
    case "not-a-marker":
    case "unadmitted-issuer":
      break;
  }
  // …then Buzz's wave sniff, then the prose renderer.
}
```

`15-FILE-SPLIT-PLAN.md` owns the mechanics of moving the arm; this sheet owns that the seam is a
**single component call taking props already in `MessageRow`'s closure**, so the extraction is a
pure move and the diff is reviewable.

---

## 4. New components — Tier A, safety-critical

Ten components. Every one is named by an invariant.

### 4.1 `AdversaryString`

**Path** `BUZZ desktop/src/shared/ui/perch/AdversaryString.tsx` · **budget** 170 · **governs**
`08` §7.7 control 1, INV-14 · **PROPOSED guard** `tools/check-perch-adversary-strings.sh`

```ts
export type AdversaryStringProps = {
  /** The untrusted value, verbatim. Never pre-formatted by the caller. */
  value: string;
  /** What field this is, rendered as the rail label. A trusted constant. */
  field: string;
  /** Rendered characters before the expand control. Default 512. */
  cap?: number;
  /** `inline` for a value inside a sentence; `block` for a field row. */
  layout?: "inline" | "block";
  className?: string;
};
```

**Behaviour, all mandatory.** Renders a **plain text node** — not `react-markdown` with plugins
disabled, not `dangerouslySetInnerHTML`. `font-mono`, `whitespace-pre-wrap`, `break-all`. Wrapped in
typographic quotes that are part of the component, not the string. C0/C1 control characters, U+200B–
U+200F, U+202A–U+202E, U+2066–U+2069 and U+FEFF are replaced with a visible `␀`-class glyph plus a
`title` naming the codepoint. Truncated at `cap` **rendered** characters (grapheme-segmented, so a
cap cannot split a surrogate pair) with an explicit `[show all N characters]` control. Sits inside a
1px rail labelled `ADVERSARY-CONTROLLED` in `text-eyebrow`.

**States** `short` · `capped` · `expanded` · `empty` (renders the literal token `EMPTY`, never a
blank) · `contains-escapes` (the rail label gains `· CONTAINS ESCAPED CHARACTERS`).

**testids** `perch-adversary-string` on the wrapper; `perch-adversary-string-expand` on the control;
`data-perch-role="adversary-string"` (§1.4).

**Keyboard / ARIA** The expand control is a real `<button type="button">` in tab order.
`aria-label` on the wrapper is `${field}, adversary-controlled value` — the *label* is trusted, the
*value* is not read into any aria attribute, because a screen reader announcing a bidi-overridden
string defeats the visual escaping.

**Tokens** `--perch-surface-raised`, `--perch-border-strong`, `--perch-foreground`,
`--perch-foreground-muted`; `text-eyebrow` for the rail label, the mono stack (`19-TOKENS.md` §5.5 —
note the stack must include `'SF Mono'` and `Consolas`, which `05` §3.3 drops). **The value itself
is `text-sm`** (§1.10 rule 1) — a command line, a file path or an AWS key an operator is deciding
against is primary content, not meta text.

**Refuses to** autolink · run any remark/rehype pass · accept a `ReactNode` · accept `children` ·
render into a `title`/`alt`/`aria-*` attribute · be nested inside itself.

---

### 4.2 `VerdictPane`

**Path** `BUZZ desktop/src/features/perch-watch/ui/VerdictPane.tsx` · **budget** 260 · **governs**
`04` §2.2, `08` §3.3, render law 1, INV-02

```ts
/** Fixed order. A `const` array, never JSX order — INV-02 asserts DOM order. */
export const VERDICT_SLOT_ORDER = [
  "action",
  "blast-radius",
  "if-you-undo",
  "why-we-are-asking",
  "what-granting-opens",
] as const;
export type VerdictSlotId = (typeof VERDICT_SLOT_ORDER)[number];

export type VerdictPaneProps = {
  /** The hold, or the finding rendered through the same five slots. */
  subject: HoldSubject | FindingSubject;
  /** Per-slot content, keyed. A missing key renders the slot's absence copy — never nothing. */
  slots: Partial<Record<VerdictSlotId, React.ReactNode>>;
  /** Absence copy per slot; defaults from `06`'s copy module. */
  absence?: Partial<Record<VerdictSlotId, string>>;
  /** Fires when BLAST RADIUS's last child has been fully visible. Feeds GrantControl's gate. */
  onBlastRadiusRead: () => void;
  writeState: VerdictWriteState;
  className?: string;
};
```

**The order is enforced structurally.** The component maps `VERDICT_SLOT_ORDER` and renders a
`VerdictSlot` per id whether or not `slots` has the key. There is no branch that can omit one.
INV-02 snapshots all 15 `ResponseAction` variants and asserts five `[data-perch-role="verdict-slot"]`
elements in that DOM order.

**States** `hold` · `finding` (BLAST RADIUS → "none — this is a detection, not an action"; WHAT
GRANTING OPENS → "nothing — feedback opens no capability lease") · `expired` (whole card dims, action
bar replaced; **note `WorkflowApprovalCard.tsx:10-12` returns `null` for exactly this case today**
`[V]` — that hole is what this component fills) · `corrupt` (no typed action → red error row,
never a blank ACTION slot) · `submitting` · `recorded` · `daemon-dispatched` ·
`daemon-refused` · `refused-late` · `refused-late-governance` (rendered **dashed in the pane's own
legend** until B2g lands, because today it cannot fire) · `forged` (INV-35).

**testids** `perch-verdict-pane`; per slot `` `perch-verdict-slot-${slotId}` ``;
`perch-verdict-pane-expired`; `perch-verdict-pane-forged`.

**Keyboard** The pane owns no chords. `C`/`D`/`I`/`G`/`R`/`S`/`E` are registered once by the Perch
keymap registry (§6.1) and dispatched by row type — INV-32's table test runs over that registry, not
over this component.

**ARIA / focus** `<section aria-labelledby>` pointing at the ACTION slot's heading. On `hold_id`
change the pane moves focus to its own container (`tabIndex={-1}`) so a keyboard operator's next
`Tab` starts at ACTION, and the arming state resets (INV-11). It acquires an escape surface for its
lifetime via `acquireEscapeSurface()` (`BUZZ desktop/src/shared/hooks/escapeSurfaces.ts:26-33` `[V]`)
so bare `Escape` cannot mark the queue read (`useMarkAsReadShortcuts.ts:33` already yields on
`hasActiveEscapeSurface()` `[V]`) — **and releases it on unmount**, because a leaked acquire
disables Escape-to-mark-read for the session.

**Tokens** `--perch-card`, `--perch-border`, `--perch-border-pillar-authority` (decoration only —
1.42:1 against `--perch-card`, see the design ground's C4), the `--perch-rail-pillar-thickness`
(2.5px) `--perch-pillar-authority-mark` rail as the *classifying* channel, `--perch-foreground`,
`--perch-foreground-muted`, `text-eyebrow` for slot labels, **`text-sm` for every slot body**
(§1.10 rule 1 — the ACTION sentence is the one string on the screen an operator must not misread).

**A copy-gate collision this component owns.** The WHY WE ARE ASKING slot renders the daemon's own
`HoldRationale.reason`, which today is the literal string `authorized but held for human approval`
for all twelve action kinds (`12-BACKEND-BILL-API.md`'s `static.human_gate` commitment). That string
contains `approval`, which `copy-ban-list.tsv`'s `approve` row (P0, case-insensitive, **no
exemption**) rejects. Two ways out and this sheet takes the second: (a) adopt
`22-DEMO-FIXTURE.md`'s proposed exemption **C-A2** (`static\.human_gate|policy_decision\.reason|
rationale\.reason`); or (b) **render the reason as a quoted wire value** — a `<code>` node fed from
`payload.rationale.reason`, never a string literal in a `.tsx` file — so the extractor, which reads
source literals, never sees it. (b) is correct independently of the gate: the reason is a daemon
field, it is quoted because it is quoted, and a future daemon reason cannot break the build. C-A2
should still land for the surfaces that cannot do (b), and `16-INVARIANT-TESTS.md` owns that row.

**States** additionally include `superseded` — see §4.12's `VerdictWriteState`. A superseded pane
keeps the five slots, dims the action bar, and replaces the write-state row with the sentence naming
the winning decision. It never re-enables the grant control.

**Refuses to** collapse a slot · reorder for "simple" actions · offer approve-with-modifications ·
render a governance quorum fraction · claim the receipt names who decided (until B2o) · render a
recorded verdict as *the* decision when the daemon says another console's was (INV-12's
neighbourhood, §4.12).

---

### 4.3 `VerdictSlot`

**Path** `…/perch-watch/ui/VerdictSlot.tsx` · **budget** 110 · **governs** render law 1

```ts
export type VerdictSlotProps = {
  id: VerdictSlotId;
  /** SCREAMING label, rendered literally. A trusted constant from `06`'s copy module. */
  label: string;
  children?: React.ReactNode;
  /** Rendered when `children` is null/undefined. Required — a slot cannot be silently empty. */
  absence: string;
  /** BLAST RADIUS only: the last child is observed at threshold 1.0. */
  onFullyVisible?: () => void;
};
```

`onFullyVisible` mounts an `IntersectionObserver` at `threshold: 1.0` on the slot's **last child**
node, per INV-11. It fires once per `hold_id`; the observer is torn down and rebuilt on subject
change.

**testids** `` `perch-verdict-slot-${id}` `` + `data-perch-role="verdict-slot"`; the BLAST RADIUS
slot additionally carries `data-perch-role="blast-radius"` so INV-11's gate is greppable.

---

### 4.4 `GrantControl`

**Path** `…/perch-watch/ui/GrantControl.tsx` · **budget** 220 · **governs** render law 6,
`APPENDIX-NORMATIVE.md` §2, INV-10, INV-11, INV-33

```ts
export type GrantControlProps = {
  holdId: string;
  /** True once BLAST RADIUS's last child has been fully visible on THIS holdId. */
  blastRadiusRead: boolean;
  /** ms the pane has held this holdId. The gate is >= 1500. */
  dwellMs: number;
  armed: boolean;
  onArm: () => void;
  onRecord: () => void;
  writeState: VerdictWriteState;
  disabledReason?: string;
};
```

**The control cannot be a primary action, structurally.** It renders through a `verdict` variant of
`shared/ui/button.tsx`'s cva that has **no `bg-primary` path**. `AlertDialogAction` today is
`cn(buttonVariants(), className)` at `BUZZ desktop/src/shared/ui/alert-dialog.tsx:149` — i.e.
`buttonVariants()` with no variant, which resolves to the `default` arm `bg-primary
text-primary-foreground shadow` at `button.tsx:12-13` `[V]`. Perch's alert-dialog re-skin (§8) makes
`variant` a **required** prop on `AlertDialogAction`, so the default can never be reached by
omission. INV-10 then greps for `variant="default"` and `bg-primary` inside
`data-perch-role="grant"` subtrees.

**Label** exactly `Record my decision and send it to the daemon`. Never `Approve`, never `Grant`
alone (`APPENDIX-NORMATIVE.md` §7 bans `Approve`/`Approved` as a control label outright).

**States** `blocked-unread` (disabled; reason "read the blast radius first") · `blocked-dwell`
(disabled; reason names the remaining time, no progress bar) · `ready` · `armed` (label gains
`— press Enter to record`; a second `G` does **not** record) · `sending` · `recorded` ·
`daemon-dispatched` · `daemon-refused` · `absent` (Observation and Maintenance-only projected modes
render **no** grant control at all, per `04` §2.14).

**Keyboard, exactly.** `G` arms. `Enter` or a click records. `event.repeat` is ignored — Buzz already
guards `!event.repeat` at `BUZZ desktop/src/app/useAppShellKeyboardShortcuts.ts:60` before any of its
six bindings fire `[V]`, so this is inherited house practice, not invention. Arming resets on
`holdId` change and on unmount. The control is **not reachable from a multi-select context** — it
renders `null` when the pane's selection cardinality is > 1, and INV-11 asserts no
`[data-perch-role="grant"]` element exists in that DOM.

**ARIA** `<button type="button" aria-disabled>` — `aria-disabled` rather than `disabled`, so the
control stays in tab order and its `disabledReason` is reachable by a screen reader; the click
handler early-returns. `aria-describedby` points at the reason node. The arming transition announces
through `WriteStateRow`'s `role="status"`, not through the button.

**Refuses to** be `variant="default"` · carry a confirm-and-remember checkbox · offer undo ·
appear in a context menu · render optimistically as recorded before the relay OK (INV-33).

---

### 4.5 `VerdictChipBar`

**Path** `…/perch-watch/ui/VerdictChipBar.tsx` · **budget** 190 · **governs**
`APPENDIX-NORMATIVE.md` §2, INV-32, INV-34

```ts
export type VerdictVerb = "confirm" | "dismiss" | "investigate" | "refuse";

export type VerdictChipBarProps = {
  rowType: "finding" | "hold";
  /** Finding rows: confirm/dismiss/investigate. Hold rows: refuse only (grant is separate). */
  onVerb: (verb: VerdictVerb) => void;
  /** `S` renders DISABLED WITH THE REASON on a hold — never omitted. INV-34. */
  snooze: { enabled: boolean; reason?: string; onOpen: () => void };
  /** `E` — promote to a case. One meaning, always. */
  onPromote: () => void;
  dismissStage: "idle" | "armed";
  writeState: VerdictWriteState;
};
```

Chips are ink-on-neutral with a leading glyph, never filled buttons. Refuse and the grant control are
**asymmetric by construction** — Refuse is a chip in this bar, the grant control is a full-width
outlined control whose label is a sentence.

**testids** `` `perch-verdict-chip-${verb}` ``, `perch-verdict-snooze`, `perch-verdict-promote`.
Refuse carries `data-perch-role="refuse"`.

**Refuses to** bind `A` to anything (INV-31) · bind one key to two verbs across row types (INV-32) ·
omit the snooze chip on a hold (INV-34) · offer multi-select Dismiss.

---

### 4.6 `DismissArithmetic`

**Path** `…/perch-watch/ui/DismissArithmetic.tsx` · **budget** 200 · **governs** render law 5,
`04` §2.2

```ts
export type DismissArithmeticProps = {
  /** Deposits that would leave the sum. Keyed (threat_class, event_id) — the real key. */
  affected: DepositPreview[];
  strengthBefore: number;
  strengthAfter: number;
  /** From config, never hardcoded. rulesets/default.yaml:58 ships 2.0. */
  alertThreshold: number;
  /** True when before >= threshold and after < threshold. Drives the modal. */
  crossesThreshold: boolean;
  onCommit: () => void;
  onCancel: () => void;
};
```

Expands **inline in the row** on the first `D`. A modal fires **only** when `crossesThreshold`.
Renders the arithmetic as three numbers with two decimals in `tabular-nums`, and names the
suppression key literally: `FeedbackSuppressionKey { threat_class, event_id }`
(`AMB crates/swarm-pheromone/src/substrate.rs:345-348` `[V]`).

The copy must state the blast radius honestly: `findings_to_deposits` copies `finding.event_id` into
every deposit's indicator (`AMB crates/swarm-whisker/src/stream.rs:35-37`), so one Dismiss reaches
**every detector that fired on that telemetry event**, including detectors the operator never
reviewed. The row previews that count.

**testids** `perch-dismiss-arithmetic`, `perch-dismiss-commit`, `perch-dismiss-threshold-modal`.

---

### 4.7 `ProvenanceRows`

**Path** `BUZZ desktop/src/shared/ui/perch/ProvenanceRows.tsx` · **budget** 230 · **governs**
`05` §2.6, brief A8, render law 3, INV-25

```ts
export type AmbushRecordTier =
  | { state: "signed-subject-bound"; /** the check that did NOT run — mandatory */ limit: string }
  | { state: "unattested"; byDesign: boolean }
  | { state: "attestation-failed"; error: string }
  | { state: "no-signature-of-its-own"; onVerify: () => Promise<DaemonVerifyResult> }
  | { state: "signed-deposit" };

export type ProvenanceRowsProps = {
  ambushRecord: AmbushRecordTier;
  /** Row 2. The publishing bridge key. Rendered FULL, never truncated. */
  relayEnvelopePubkey: string;
  className?: string;
};
```

**Two rows, always both, never merged.** Row 1 `AMBUSH RECORD  ed25519 · <state>`; row 2
`RELAY ENVELOPE  secp256k1 · <full npub> · transport only`. Merging them is how "trust the bridge"
silently replaces "trust the receipt".

Row 2 uses `<PubKey variant="full" />` — required, because `PubKey`'s own doc comment says a
truncated key is forgeable by vanity grinding and security decisions are made against the whole key
(`BUZZ desktop/src/shared/ui/PubKey.tsx:21-31` `[V]`).

`signed-subject-bound` **must** render its `limit` line. `verify_release_attestation`'s own doc
comment says do not read `attestation_verified: true` as "a governor we trust authorized this"
(`AMB crates/swarm-runtime/src/containment.rs:227-230`); the console prints that limit beside the
badge or it prints nothing.

**Banned in every string this component emits:** `verified by`, `trusted`, `proof`, any shield or
lock glyph, and `signed`/`verified` on a finding, escalation, hold, containment-lease or bare
response-receipt card (`APPENDIX-NORMATIVE.md` §7). INV-25 asserts every result names its chain
**and** its tier.

**testids** `perch-provenance-ambush-record`, `perch-provenance-relay-envelope`,
`perch-provenance-verify`; both rows carry `data-perch-role="provenance-row"`.

**Refuses to** render one row · render a glyph as the tier · style `unattested` in a success
register · truncate the envelope key.

---

### 4.8 `SourceCount`

**Path** `BUZZ desktop/src/shared/ui/perch/SourceCount.tsx` · **budget** 190 · **governs** render
law 2, INV-16

> **REVISION 2 — REVISION 1 OF THIS SECTION WAS WRONG, AND THE AMENDMENT IT FILED IS WITHDRAWN.**
> Revision 1 asserted that `distinct_sources` counts the agent instance id, so four detectors on one
> Whisker yield `distinct_sources == 1`, and proposed rewriting `APPENDIX-NORMATIVE.md` §8 law 2's
> gloss. **That is false.** The error was reading `whisker_agent.rs:148-149` and stopping before the
> strategy scoping applied one call deeper. The appendix's gloss is correct as written and needs no
> amendment. Six peer producers verified this independently and this sheet was one of the two that
> got it wrong; because this sheet owns the component contract, the wrong reading would have been
> compiled into `SourceCount`. The full chain is below so the objection cannot recur.

#### The mechanism, traced end to end `[V]`

Four links, each read this session, each naming who calls it, what process it runs in, and what it
does to the data:

1. **`WhiskerAgent::tick`** (`AMB crates/swarm-agents/src/whisker_agent.rs:140-160`), the agent loop
   inside the `swarm_detect --serve` process, builds
   `scoped_agent_id = AgentId(format!("{}:{}", derived_identity.0, self.id.0))` at `:148-149` and
   passes it as the `agent_id` argument to `detect_and_deposit_with_role`. `derived_identity` is
   `AgentId::from_verifying_key(…)` = `swarm:ed25519:{64hex}` (`swarm-core/src/types.rs:16-22`), so
   this is a **four-segment** id: `swarm:ed25519:{64hex}:{agent-slug}`. **This is the BASE, not the
   deposit id.**
2. **`detect_and_deposit_with_role`** (`AMB crates/swarm-runtime/src/detection/pipeline.rs:60-91`)
   calls `resolve_deposits(substrate, &findings, event, agent_id, agent_role, pheromone)` at `:80`,
   then signs and writes each returned deposit to the substrate in the loop at `:82-85`.
3. **`resolve_deposits`** (`pipeline.rs:543-580`, `pub(crate)`) builds one `PheromoneDeposit` per
   finding and sets, at **`:573`**, `agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id)`.
   `strategy_scoped_agent_id` (`AMB crates/swarm-whisker/src/stream.rs:20-22`) is
   `AgentId(format!("{}:{strategy_id}", base.0))`. So the id that reaches the substrate is
   **five segments**: `swarm:ed25519:{64hex}:{agent-slug}:{strategy_id}` — **one per detector**.
4. **`concentration_for`** (`AMB crates/swarm-pheromone/src/substrate.rs:1268-1304`), the reducer the
   monitor tick and the escalation path both call, does `sources.insert(deposit.agent_id.0.clone())`
   at `:1295` over that string and reports `sources.len()` as `distinct_sources` at `:1301`.

The workspace asserts it itself: `substrate.rs:2105` is a test literally named
`query_counts_strategy_scoped_agent_ids_as_distinct_sources`, asserting `distinct_sources == 2` at
`:2125`, and `:2129` is its sibling `query_collapses_repeated_strategy_scoped_agent_ids_to_one_source`
asserting `== 1` at `:2153` `[V]`.

The second production deposit builder, `findings_to_deposits` (`stream.rs:25-50`, called by
`canary.rs:785` and `promotion.rs:892`), applies the same scoping at `:46` `[V]`. **So on every
detector path, one agent running four detectors is four distinct sources and clears
`min_sources_for_escalation: 2` alone.** That is exactly what render law 2's expansion exists to make
visible, and the copy must lean into it, not away from it.

#### The third id shape — the one the law does not anticipate

§2.7's finding. `signed_providence_feedback_deposit` (`providence_handlers.rs:497-560`) writes
`agent_id: AgentId::from_verifying_key(&state.signing_key.verifying_key())` at `:536` — a
**three-segment** `swarm:ed25519:{64hex}` with no agent slug and no strategy segment, the daemon's
own key, deposited on the Confirm path at `:317`. So the id space this component renders has two
shapes, and the derivation must not assume one.

#### Props

```ts
/**
 * Render law 2. Never a bare source count.
 *
 * The two arms are a discriminated pair so a caller CANNOT supply a count
 * without also declaring, in the type, that the ids are unavailable and why.
 * There is no `sources: number` prop and no way to synthesise one.
 */
export type SourceCountProps = {
  /** Threshold from config; rulesets/default.yaml:57 ships 2. Never hardcoded. */
  minSourcesForEscalation: number;
  className?: string;
} & (
  | {
      /** The strategy-scoped ids, verbatim from B4. */
      sourceIds: readonly string[];
      distinctSources?: never;
      idsUnavailable?: never;
    }
  | {
      /**
       * Phase 1: RuntimeEvent::Escalation carries a COUNT and no ids
       * (runtime_events.rs), so every escalation card ships `source_ids: null`.
       * The component renders a named absence, never a bare number.
       */
      sourceIds: null;
      distinctSources: number;
      /** Why the ids are absent. A closed union, so the absence is typed. */
      idsUnavailable: "not-on-this-card" | "daemon-unreachable" | "route-not-built";
    }
);
```

#### The agent derivation — one exported helper, not four copies

```ts
/**
 * The agent instance behind a strategy-scoped source id.
 *
 * Detector deposits are `swarm:ed25519:{64hex}:{slug}:{strategy_id}`
 * (pipeline.rs:573 over whisker_agent.rs:148-149). Operator-feedback deposits
 * are `swarm:ed25519:{64hex}` with no strategy segment at all
 * (providence_handlers.rs:535). Stripping the last segment unconditionally —
 * which is what 18-DATAVIZ.md:364 does today — turns the second shape into the
 * literal "swarm:ed25519", collapsing every operator Confirm in the deployment
 * into one fabricated agent. Guard on the shape instead.
 */
const BARE_KEY_ID_RE = /^swarm:ed25519:[0-9a-f]{64}$/;

export function agentIdOfSource(sourceId: string): string {
  if (BARE_KEY_ID_RE.test(sourceId)) return sourceId;   // a whole agent already
  const cut = sourceId.lastIndexOf(":");
  return cut === -1 ? sourceId : sourceId.slice(0, cut);
}

export function isOperatorFeedbackSource(sourceId: string): boolean {
  return BARE_KEY_ID_RE.test(sourceId);
}
```

`18-DATAVIZ.md` §5's `SourceAttribution` helper should import `agentIdOfSource` from here rather
than inline `split(":").slice(0, -1).join(":")`; that is the reconciliation this sheet proposes, and
`18` owns accepting it. A four-row table test covers the two real shapes plus a colonless id plus an
empty string.

#### Rendering

**Ids present.** `N sources / M agents`, `text-sm` (§1.10 rule 1 — this is the single most-repeated
safety string in the product and it is not meta text). Pluralised at the call site by one function,
never by string concatenation at each caller: `1 source / 1 agent`, matching `06` §5.2's own
`laneQuiet` string. Expandable to the ids **grouped under their real agent**, so
`5 sources / 2 agents` opens to two groups of detector names.

**The expansion's job is to make the law's own point visible.** When `M < N` — the common case,
because one agent's own detectors each get an id — the expansion header states it in words:
`3 of these 5 sources are detectors on whisker-7a3f — one agent's detectors agreeing with each
other`. That is the sentence `min_sources_for_escalation: 2` cannot make on its own, and it is why
the law forbids the bare number.

**An operator-feedback source renders as itself.** A source id matching `BARE_KEY_ID_RE` is grouped
under a labelled row `operator feedback · recorded through the daemon key`, never under a detector
agent and never counted toward the "independent detectors" reading. §2.7's four consequences are the
reason; a Confirm that silently reads as a second detector is the failure this component exists to
prevent.

**Ids absent (Phase 1).** Renders the count with its absence named, in one sentence that still
carries the word `agent` so the shape is unmistakable and the `bare-source-count` ban row's
exemption matches:

- `not-on-this-card` → `5 strategy-scoped sources · the agent ids are not on this card`
  plus a `<DerivedMarker fn="B4 GET /v1/operator/pheromone/deposits" />`-style served-absence note.
- `daemon-unreachable` → `5 strategy-scoped sources · the agent ids could not be fetched`.
- `route-not-built` → `5 strategy-scoped sources · the agent ids need B4, which is Phase 2`.

It never renders `5 sources` alone, and it never fabricates an agent count.

#### The Phase-1 sequencing this resolves

`grep source_ids schemas/*.json` returns hits only in `card-ambush-escalation-v1.schema.json`, where
the field is `null` and the example is `null`; no finding, hold, verdict, receipt, lease or rollback
schema carries source ids at all. B4 — the only route that can serve them — is **Phase 2** in
`APPENDIX-NORMATIVE.md` §5. So in Phase 1 **every** call site takes the second arm. That is a real
constraint, not a defect: the absence form is the honest render, the type makes it impossible to
skip, and §12's build order lands the id-carrying form after B4.

It also narrows `18-DATAVIZ.md`'s **CR-5** ("no component accepts a `sources: number`") rather than
breaking it: no arm of this type accepts a lone number, and the count-carrying arm is reachable only
together with `sourceIds: null` and a typed reason. Proposed to `18` as the CR-5 wording that
survives Phase 1.

#### Two corrections owed to `13-WIRE-SCHEMAS.md` — **BOTH LANDED**

Filed here because this sheet is the other artifact that carried the wrong reading. Both were
one-token changes in files `13` owns, and **`13` applied both**; re-verified by the integration pass:

- `schemas/card-ambush-escalation-v1.schema.json` now `$ref`s
  `common.schema.json#/$defs/SourceCountMechanism`, whose `const` is `strategy_scoped_agent_id`.
  `skeleton/perch-wire/ts/zod.ts`, `ts/types.ts` and `rust/src/cards.rs` carry the same value, and
  the golden vector and its pinned hash were regenerated — `GOLDEN.sha256` reproduces exactly.
- `common.schema.json`'s `x-note` on `distinct_sources` and its `x-source` on `FactIssuer` now state
  the four-link chain correctly and name the upstream doc comment that must not be trusted
  (`crates/swarm-core/src/pheromone.rs:323`, `:325`, which say "distinct agents" and are wrong about
  the unit).

Amendment **W-6** (`13` §9) is withdrawn, as is this sheet's own SourceCount amendment: the
expansion stays `N sources / M agents` and does not become `{n} distinct agent instances`. The
ratified value lives in `00-REGISTRY.md` R-2, which carries the re-verification and records that
ground-agent correction C-5 (which argued the opposite) is rejected.

**States** `below-threshold` (renders the threshold beside the count) · `at-threshold` ·
`above-threshold` · `collapsed` · `expanded` · `single-agent-multi-source` (the law's own case;
carries the "one agent's detectors agreeing with each other" line) · `ids-absent` (three reasons) ·
`includes-operator-feedback`.

**testids** `perch-source-count`, `perch-source-count-expand`, `perch-source-count-absent`,
`perch-source-count-operator-feedback`; `data-perch-role="source-count"` for INV-16's grep.

**Refuses to** accept a lone `number` · render one number · round · derive an agent by stripping the
last segment unconditionally · count an operator Confirm as a detector.

---

### 4.9 `DerivedMarker`

**Path** `BUZZ desktop/src/shared/ui/perch/DerivedMarker.tsx` · **budget** 100 · **governs** render
law 4, INV-17

```ts
export type DerivedMarkerProps = {
  /** The producing function, path-qualified. e.g. "alert_tuning.rs:build_alert_tuning_report" */
  fn: string;
  /** Present when the runtime also serves this value and the two disagree. */
  disagreement?: { servedValue: string; derivedValue: string; toleranceNote: string };
  className?: string;
};
```

Renders `derived · <fn>` in `text-2xs` `--perch-foreground-muted` — meta text about a value, which
is the one class §1.10 reserves `text-2xs` for. When `disagreement` is present the
display **snaps** to the served value and inserts a reason row — it never eases, never interpolates
between them.

`data-perch-role="derived"` so INV-17's CI arm can assert the export's `DERIVED.json` is non-empty
iff any such element rendered.

---

### 4.10 `ContainmentTimer`

**Path** `BUZZ desktop/src/shared/ui/perch/ContainmentTimer.tsx` · **budget** 180 · **governs**
`04` §2.6, `08` §4.1, INV-06

```ts
export type ContainmentTimerProps = {
  /** Saturates at zero by construction — swarm-response/src/containment.rs:276. */
  remainingMs: number;
  /** A SEPARATE fact. True on a still-listed lease means the sweep tried and failed. */
  expired: boolean;
  /** For the "self-releases at" sentence. Rendered as a wall clock, not a delta. */
  expiresAtMs: number;
  daemonReachable: boolean;
};
```

**Two facts, two DOM elements, never one bar.** `ContainmentLeaseView`'s own doc comment at
`AMB crates/swarm-runtime-http/src/http/containment.rs:76-81` says `remaining_ms` cannot distinguish
"expires in an instant" from "expired an hour ago and the sweep failed", which is why `expired` is a
separate field `[V]`. INV-06 asserts the two render as different DOM and occupy separate elements.

**States** `open` · `expiring` (`remainingMs < 15_000`) · `expired-still-listed` (the loudest state
on the board; `--perch-danger-mark` as the **mark only** — `19-TOKENS` measures dark
`--perch-danger-mark` at 3.70 on raised and rules it never-text, so the word beside it carries the
meaning in `--perch-foreground`; `role="alert"`) · `daemon-down-open` · `daemon-down-expired`.
The remaining figure is `text-sm` with `tabular-nums` (§1.10 rule 1).

**The TTL number is a trap the plan set already fell into.** The object counted down here is a
`ContainmentLease`, whose TTL is `runtime.containment.lease_ttl_ms`, default **900,000 ms / 15
minutes** (`AMB crates/swarm-core/src/config/defaults.rs:23-27`), **not** the `lease_ttl_ms: 60000`
at `rulesets/default.yaml:94`, which is `policy.lease_ttl_ms` — a `CapabilityLease` authorization
window read by `StaticApprovalGate::issue_lease` at `static_gate.rs:320`. A surface rendering 60 s
beside a `ContainmentLeaseView` is wrong by 15×. This component takes `expiresAtMs` from the view
and never derives from a config constant.

**testids** `perch-containment-remaining`, `perch-containment-expired`.
**ARIA** `aria-live="off"`; the `expired-still-listed` transition raises a separate `role="alert"`
node once, not on every tick.

**Refuses to** render a progress bar · merge the two facts · offer extend (INV-07 — the disabled
row-menu item with its reason stays visible, carrying `data-perch-role="containment-extend-disabled"`).

---

### 4.11 `RollbackStepList`

**Path** `BUZZ desktop/src/shared/ui/perch/RollbackStepList.tsx` · **budget** 160 · **governs**
`08` §4, INV-03, INV-04

```ts
/** Exactly five. AMB crates/swarm-response/src/rollback.rs:209-223. `restored()` is true only for Reversed. */
export type RollbackStepStatus =
  | "reversed" | "simulated" | "irreversible" | "unsupported" | "failed";

export type RollbackStepListProps = {
  steps: readonly { label: string; status: RollbackStepStatus; reason?: string }[];
  /** From ContainmentReleaseResponse's BODY, never the HTTP status. */
  fullyReversed: boolean;
};
```

The five words render **pairwise distinct** (INV-04). An enabled Undo affordance requires `Ok` from
`resolve_inverse` for **every** step (INV-03) — this component renders no Undo at all; it is a
read-only outcome list, and the release control lives on `ContainmentRow` (§6.7).

`irreversible` renders the runtime's own quotable reason verbatim through `<AdversaryString>` when
it names a target (`rollback.rs:183-189` for `TerminateUserSession`) `[V]`.

**testids** `` `perch-rollback-step-${index}` ``, `perch-rollback-fully-reversed`.

---

### 4.12 `WriteStateRow`

**Path** `BUZZ desktop/src/shared/ui/perch/WriteStateRow.tsx` · **budget** 170 · **governs**
`04` §2.2, INV-28, INV-33

```ts
export type VerdictWriteState =
  | { phase: "idle" }
  | { phase: "sending" }
  /** Leg 1 only: the relay OK'd the intent card. NOTHING is authorized yet. */
  | { phase: "recorded"; atMs: number }
  | { phase: "daemon-dispatched"; atMs: number }
  | { phase: "daemon-refused"; ruleName: string; reason: string }
  | { phase: "refused-late"; ruleName: string; reason: string }
  /** Cannot fire until B2g lands; drawn dashed in the legend until then. */
  | { phase: "refused-late-governance"; reason: string }
  | { phase: "daemon-unreachable"; reason: string }
  /**
   * REVISION 2, NEW. Two consoles legitimately hold the same open hold; the
   * daemon's compare-and-set picks one and answers the other 409. This is the
   * loser's terminal state. See below — it is not an error phase.
   */
  | {
      phase: "superseded";
      /** The winning console's leg-1 card id, from the 409 body. 64 lowercase hex. */
      winningIntentEventId: string;
      /** What the winning operator decided, so this row does not have to guess. */
      winningDecision: "grant" | "refuse";
      decidedAtMs: number;
    };

export type WriteStateRowProps = { state: VerdictWriteState; onRetry?: () => void };
```

**Three distinct states minimum, no optimistic success** (INV-33). `refused-late` renders as a
**normal outcome naming the rule**, not as a client error: "The daemon re-evaluated and refused:
`<reason>`. Your decision is recorded; the action did not run." The row does not turn green.

`daemon-unreachable` says the intent record was published and the decision was **not** delivered,
and offers retry. It never queues silently.

#### `superseded` — the state nothing in wave 2 rendered

A wave-2 critic found a real hole and this is the component-layer half of the fix.

**The setup, verified.** `APPENDIX-NORMATIVE.md` §4 layer 1 `p`-tags **every** principal holding
`OperatorScope::Approve` (`AMB swarm-core/src/config/operator.rs:153-168`), and `00-BRIEF.md` §13's
declined-amendment note confirms the watch claim does not narrow that set. So in any deployment with
more than one Approve principal, two consoles can legitimately open the same hold and both press
Enter. `12-BACKEND-BILL-API.md` §4.4 resolves the **daemon** side — the compare-and-set into
`deciding` happens before policy evaluation and the loser gets `409 hold_already_deciding` /
`409 hold_already_decided`.

**What the daemon's CAS does not resolve.** Leg 1 is published to the relay **before** leg 2 is
POSTed (`13-WIRE-SCHEMAS.md`'s publish order — the decide body needs the card id as its idempotency
key). The relay has no compare-and-set, a `kind:9` event is immutable, and both cards are genuinely
signed by real operators. Without this state the case channel keeps two unqualified
`ambush:verdict:v1` records for one hold, forever, with nothing marking which one executed — and the
Ledger export's `holds/` directory contains two "human intent records" for one decision.

**What this component does about it.** On a 409, the losing console:

1. renders `superseded` — *not* an error register. The operator did nothing wrong; two people
   answered the same page. Copy: `Another operator's decision was the one that ran: <verb> at
   <time>. Your decision is recorded on this case and did not run.`
2. publishes a **leg-1 update card** carrying the winning `nostr_intent_event_id`, which is the only
   thing that can qualify the immutable original — and the losing console is the only party that
   knows both ids.
3. leaves the grant control absent, not disabled-with-retry.

**Two things this needs from peers, filed not assumed.**
`13-WIRE-SCHEMAS.md` owns `schemas/card-ambush-verdict-v1.schema.json`, whose `leg2.state` enum is
`sending | recorded | acknowledged | refused_late` — there is no value meaning "another operator's
decision executed". It needs a fifth, `superseded`, carrying the winning event id.
`16-INVARIANT-TESTS.md` owns the reconciliation rule that belongs beside INV-12/INV-35 as a P0: **a
verdict card with no matching daemon decision record renders as not-the-decision, never as a
decision** — which is also the only thing that covers the case where the losing console is closed
before it can publish its update card. Its test is two mock consoles against one hold.

**ARIA** `role="status"` `aria-live="polite"` for every phase except `daemon-refused` /
`refused-late`, which are `role="alert"`. `superseded` is `role="status"` — it is an outcome, not an
alarm.

**testids** `` `perch-write-state-${phase}` ``, plus `perch-write-state-superseded-winner` on the
node naming the winning event id.

**`hold_id` is opaque, everywhere.** Every component in this sheet that takes a `holdId` treats it as
a token: it is never parsed, split, sorted lexically for meaning, or rendered as anything but a
monospace label. `card-ambush-hold-v1.schema.json`, `card-ambush-verdict-v1.schema.json` and
`frame-26006-hold-alarm.schema.json` all declare it a bare `"type": "string"` today, and the six
formats in circulation across wave 2's artifacts (`hold_a1f4…`, `hold:01K3…`, `hold-9c1e…`,
`h_a07aeacf`, …) are a `13`-owned schema gap, not a component contract. Two of those use the `hold:`
colon prefix the schema's own description warns against as the forbidden derived form. This sheet's
components are correct under any of them **because none of them reads the id**; the `$defs/HoldId`
pattern belongs in `common.schema.json`.

---

## 5. New components — Tier B, display primitives

All under `BUZZ desktop/src/shared/ui/perch/`. Every one consumes `--perch-*` tokens `19-TOKENS.md`
owns (§1.9); none hardcodes a hex and none names a bare Buzz shadcn variable. Type sizes follow
§1.10: the value a primitive exists to show is `text-sm`; its label is `text-eyebrow` or
`text-2xs`; `text-3xs` appears only inside `PillarRail`, `SeverityBar` and `ConfidenceMeter`, none
of which renders a word.

| # | Component · file | Props | States | testid | Budget |
|---|---|---|---|---|---:|
| 5.1 | `SeverityChip.tsx` | `{ severity: "LOW"\|"MEDIUM"\|"HIGH"\|"CRITICAL"; showBar?: boolean; className? }` | four, plus `unknown` (renders the raw string through `<AdversaryString>`) | `` `perch-severity-${severity.toLowerCase()}` `` | 90 |
| 5.2 | `SeverityBar.tsx` | `{ severity; className? }` | four | `perch-severity-bar` | 70 |
| 5.3 | `ConfidenceMeter.tsx` | `{ confidence: number; pillar: PerchPillar }` | five dot steps + `absent` | `perch-confidence` | 110 |
| 5.4 | `PillarRail.tsx` | `{ pillar: PerchPillar; className? }` | three | `perch-pillar-rail` | 50 |
| 5.5 | `EyebrowLabel.tsx` | `{ children: string; className? }` | one | `perch-eyebrow` | 40 |
| 5.6 | `RoleGlyph.tsx` | `{ role: AgentRole; size?: 16\|20 }` | eight, closed | `` `perch-role-${role}` `` | 90 |
| 5.7 | `NotchedRegion.tsx` | `{ label: string; annotation?: string; pillar: PerchPillar; children }` | `default` \| `core` | `perch-notched-region` | 130 |
| 5.8 | `ThreatClassLabel.tsx` | `{ threatClass: string; custom?: boolean }` | twelve + `custom` | `` `perch-threat-${slug}` `` | 90 |
| 5.9 | `HoldTtlClock.tsx` | `{ expiresAtMs: number; nowMs: number }` | `live` \| `under-5m` \| `expired` | `perch-hold-ttl` | 110 |
| 5.10 | `EmptyState.tsx` | see below | five | `perch-empty-state` | 150 |
| 5.11 | `icons.perch.ts` | nine `createLucideIcon` marks | — | — | 220 |

**5.1 `SeverityChip` — three channels in priority order.** Word first (it *is* the serialisation:
`Severity` is `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` at
`AMB crates/swarm-core/src/types.rs:407-414`), then the four-segment bar, then hue. It reuses
`badge.tsx`'s base string verbatim — `inline-flex items-center rounded-full px-2 pb-[3px] pt-[5px]
text-2xs font-semibold uppercase leading-none tracking-[0.18em]` at
`BUZZ desktop/src/shared/ui/badge.tsx:7` `[V]`. The asymmetric `pb-[3px] pt-[5px]` is deliberate
optical centring for uppercase and must survive the re-skin.

**5.6 `RoleGlyph` — eight marks that do not exist.** `05` §5 implies `colony.svg` supplies them; it
does not — none of the twenty Ambush SVGs contains a glyph, and `colony.svg` assigns hues to labelled
138×42 rounded rectangles. All eight (plus the nine domain icons in `icons.perch.ts`) are original
artwork with no source and no named author. This sheet cannot draw them. It specifies only the
extension pattern, which **is** verified: `createLucideIcon(name, [[tag, attrs], …])` on a 24×24
grid, exactly the three custom icons at `BUZZ desktop/src/shared/ui/icons.ts:3,12,21` `[V]`, so the
marks inherit stroke width, size and `currentColor`. **Blocker, carried forward from the design
ground's B1 — this is the one place in the component layer with no owner.**

**5.10 `EmptyState` — the component that makes INV-24 mechanical.**

```ts
export type EmptyStateProps = {
  /** Which state. Decides whether the /gaps link renders at all. */
  kind:
    | "swarm-produced-nothing"   // links /gaps AND names the 18/11 counts
    | "governing-number";        // names its own number; MUST NOT link /gaps
  /** The sentence. Passes through the banned-phrase assertion at build time. */
  body: string;
  /** `governing-number` only: the number this state is explaining. */
  governingNumber?: { label: string; value: string; source: string };
  action?: { label: string; onClick: () => void };
};
```

The `/gaps` link is rendered **by the component**, only for `kind: "swarm-produced-nothing"`, and
carries `data-perch-role="gap-link"`. A caller cannot add one. `04` A14's scoping table becomes a
type: The Watch's no-findings, a quiet lane, and a promoted case with no evidence are
`swarm-produced-nothing`; The Watch's no-holds, `/leases`, `/tuning`, `/ledger`, `/policy` and
`/handoff` are `governing-number`. `data-perch-role="empty-state"` gives INV-24's grep a scope.

---

## 6. New components — Tier C, surface composites

### 6.1 `perchKeymapRegistry.ts` + `usePerchKeymap`

**Path** `BUZZ desktop/src/features/perch/lib/perchKeymapRegistry.ts` (pure) and
`features/perch/usePerchKeymap.ts` · **budget** 180 + 160 · **governs**
`APPENDIX-NORMATIVE.md` §2, INV-31, INV-32

```ts
export type PerchRowType = "finding" | "hold" | "case" | "lane" | "containment";
export type PerchVerdictVerb = "confirm" | "dismiss" | "investigate" | "grant" | "refuse";

export type PerchBinding = {
  key: string;                      // a single character, or "Enter" / "Escape"
  rowTypes: readonly PerchRowType[];
  /** Present only for a verdict binding. INV-32 tables over this field. */
  verb?: PerchVerdictVerb;
  meaning: string;
  /** Rendered disabled-with-reason instead of omitted, on these row types. */
  disabledOn?: readonly PerchRowType[];
};

export const PERCH_BINDINGS: readonly PerchBinding[] = [ /* the §2 table, verbatim */ ];
```

The registry is data, so INV-32's assertion — no single key bound to two verdict verbs across row
types in the same list — is a table test over `PERCH_BINDINGS`, not a UI crawl. INV-31 asserts no
binding's `key` lowercases to `"a"`.

`usePerchKeymap` registers **one** bubble-phase window listener. It must not use capture:
`useAppShellKeyboardShortcuts.ts:35-38`'s comment forbids putting any other shortcut in capture phase
`[V]`. Buzz's six surviving chords (`Cmd-F` `:67`, `Cmd-K` `:73`, `Cmd-Shift-K` `:79`, `Cmd-Shift-N`
`:85`, `Cmd-Shift-O` `:91`, `Cmd-Shift-A` `:97`; handler closes `:101`) keep their bindings with
remapped targets `[V]`; `Ctrl-Shift-Space` (huddle, the separate capture listener at `:39-54`) is
deleted.

**Correction carried into this component.** `APPENDIX-NORMATIVE.md` §2's last row says
`` Cmd-` `` toggles the terminal. The shipped chord is **⌘/Ctrl-J** —
`BUZZ desktop/src/features/terminal/TerminalBootstrap.tsx:146-168`, capture phase on both `keydown`
and `keyup`, matching `event.code === "KeyJ"`, calling `stopImmediatePropagation`, toggling only on
`keyup` `[V]`. Perch's registry documents ⌘J. **Proposed brief amendment, filed in commitments.**

### 6.2 `WatchQueueSection` + `VerdictQueueRow`

**Path** `features/perch-watch/ui/WatchQueueSection.tsx` (220) and `VerdictQueueRow.tsx` (280) ·
**governs** `04` §2.1

```ts
export type PerchQueueId = "holds" | "named-you" | "findings" | "case-activity";

export type WatchQueueSectionProps = {
  queue: PerchQueueId;
  /**
   * REVISION 2: bound to `04` §2.1's words — "Holds" | "Named you" |
   * "Findings to review" | "Case activity". See below; `06` §5.1's
   * QUEUE_LABELS is the set that changes.
   */
  label: string;
  /** ABSENT, not zero, when the count is unavailable. `number | "unavailable" | null`. */
  count: number | "unavailable" | null;
  items: readonly PerchQueueRow[];
  /** queue 1 only: the C9 strip lives in this header (brief A6). */
  headerSlot?: React.ReactNode;
  emptyState: React.ReactNode;
  /** Hidden entirely when empty AND queue === "named-you" (a solo deployment has no mentions). */
  hideWhenEmpty?: boolean;
};
```

**The four header strings, ratified here.** Revision 1 of this sheet cited `06` §5.1's
`QUEUE_LABELS` (`Waiting on you` / `Named you` / `Swarm` / `Your cases`); `prototypes/watch.html`
renders `04` §2.1's (`Holds` / `Named you` / `Findings to review` / `Case activity`) and files an
amendment against `06`. Three of four differ, and `16-INVARIANT-TESTS.md`'s INV-24 empty-state
assertions plus `perch-queue-lifecycle.spec.ts` key off whichever set ships, so leaving both in play
breaks a test nobody has run.

**This sheet takes `04` §2.1's set** and joins the prototype's amendment against `06` §5.1, for one
substantive reason and one structural one. Substantive: `Swarm` names the *producer* of the rows,
not the *job* the operator does with them, and `04` §2.1 makes that queue carry a
`reviewed / total` shift target — a number that reads as a target only under a job-shaped heading.
Structural: `queue` is a ruled word meaning one of The Watch's four inbox categories
(`APPENDIX-NORMATIVE.md` §7), and three of the four `04` headings name the row type they hold, which
is what makes `PerchQueueId`'s four members and the four strings a one-to-one map a reader can hold.
`06` §5.2's empty-state title `Nothing is waiting on you` is unaffected and renders verbatim.

**Copy-gate note.** `Holds` and `Case activity` are clean against `copy-ban-list.tsv`.
`Findings to review` is clean. A **sidebar nav heading** reading `Lanes`, however, fails the
`bare-lane` row (P1) — its exemption ERE requires `threat|twelve|12|lateral|…` in the *same*
extracted string, and a standalone nav label carries none of them, even though
`APPENDIX-NORMATIVE.md` §1's own route-table label ("Lanes — twelve fixed threat-class channels")
passes. That is a gate defect, not a copy defect: `16-INVARIANT-TESTS.md` should add a `bare-lane`
exemption for a standalone one-or-two-word nav label, or the label becomes `Threat classes`. This
sheet does not rename the appendix's own word on a gate's behalf.

The four queues map onto Buzz's `FeedItemCategory` (`BUZZ desktop/src/shared/api/types.ts:206-210`:
`mention | needs_action | activity | agent_activity` `[V]`) and Perch keeps
`inbox.ts`'s priority function unchanged — only labels, sources and per-row state change.

`VerdictQueueRow`'s anatomy is fixed at **three** lines, and revision 2 pins each line's type step
(§1.10): **line 1** action verb or detector (typed, mono) · who · target · when · TTL if held —
`text-sm`, the line an operator triages on; **line 2** agent · confidence numeral + five-dot meter ·
review status — `text-xs`; **line 3** `N sources / M agents` · threat-class slug — `text-xs`, and
the `SourceCount` element inside it is `text-sm` per §4.8, because it is the safety string. Two lines
does not fit without truncating the agent id, which is load-bearing —
`prototypes/watch.html` reaches the same three-line result from the 365px inbox width.

Row height is a Perch-only CSS variable (`--perch-row-height`) keyed off Buzz's existing
`data-conversation-density` root attribute, **not** an edit to `typography.css` — whose comfortable
and compact row padding are both `0.25rem`
(`BUZZ desktop/src/shared/styles/globals/typography.css:37-40`, `:54-59`) `[V]`, which is exactly why
Perch needs its own rule. Three `text-sm`/`text-xs` lines plus padding do not fit
`19-TOKENS`' `--perch-row-height` of `calc(var(--buzz-type-rem) * 2.5)` (40px); the queue row's own
height is `* 2.875` comfortable / `* 2.125` compact (46 / 34px at the default rem), which is a
proposed second geometry row for `19-TOKENS` rather than a hardcoded px in this component.

**testids** `` `perch-queue-${queue}` ``, `` `perch-queue-row-${itemId}` ``,
`` `perch-queue-count-${queue}` ``.

**Row states** `unreviewed` · `reviewed` · `not-yet-correlated` (verdict controls **visible and
disabled** with the reason on the row; `E` promotes and enables them) · `held` · `expired-undecided`
· `forged` · `done` (localStorage only, never a decision record) · `snoozed-due`.

### 6.3 `InstrumentationStrip`

**Path** `features/perch-watch/ui/InstrumentationStrip.tsx` · **budget** 180 · **governs** brief A6,
`09` §13

```ts
export type InstrumentationStripProps = {
  /** One home: The Watch's queue-1 header. Elsewhere `readOnly` and linking back. */
  readOnly?: boolean;
  medianSecondsPageToVerdict: number | null;
  measurementsWrittenThisWeek: number | null;
  fractionOfRecommendationsFromThisWeek: number | null;
  promoted: number | null;
  suppressed: number | null;
};
```

Reuses `shared/ui/AnimatedCount.tsx` (`{ className?, value: number }` at `:19-22` `[V]`) — but
**only** where the value changes on a human action, never on a 1 Hz tick. `null` renders the literal
token `UNMEASURED` with the reason; it never renders `0`.

`measurementsWrittenThisWeek` is **unmeasurable today**: `operator_review_status` computes both
`false_positive_tracking` and `alert_tuning` from `incident_store.recent(recent_decisions_limit)`
with `default_recent_decisions_limit() = 20`, over an in-memory-by-default store
(`AMB crates/swarm-runtime/src/service/runtime_service.rs:1134-1136`,
`crates/swarm-core/src/config/defaults.rs:3-5`, `config/storage.rs:63,:69-71`). The strip renders
`UNMEASURED — the daemon's evidence window is the 20 newest incidents and does not survive a
restart` until B3r plus a durable measurement store land. **Do not ship a zero here.**

### 6.4 `GovernanceStrip`

**Path** `features/perch/ui/GovernanceStrip.tsx` · **budget** 300 · **governs** `04` §1.2, §2.14

Fixed **28px**, above everything, two lines. `04` says 28px and `05` §12 says 18px; 28 wins — 18px
cannot hold `text-eyebrow` at 12px with any padding. A fixed-px height here is house practice, not a
violation: `BUZZ desktop/src/shared/layout/chromeLayout.ts:5` sets
`TOP_CHROME_HEIGHT_DEFAULT = "40px"` with an explicit comment calling fixed px a deliberate exception
to the rem-first rule `[V]`.

```ts
export type GovernanceStripProps = {
  partitionState: "healthy" | "degraded" | "partitioned" | "healing";
  totalGovernors: number;
  healthyGovernors: number;
  /** Renders `committee of N (solo transport)`. NEVER a fraction. INV-09. */
  soloTransport: boolean;
  /** From GovernanceStatusReport.last_transition_at_ms — the staleness clock's source. */
  lastTransitionAtMs: number | null;
  receivedAtMs: number | null;
  bridgeShedding: boolean;
  watchClaim: { holder: string; sinceMs: number; stale: boolean } | null;
  swarmMode: "normal" | "alert" | "incident";
  /** Projection, marked derived. `derivePerchGovernanceMode()`. */
  projectedMode: PerchGovernanceMode;
};
```

`GovernanceStatusReport` has exactly **eight** fields at `AMB crates/swarm-policy/src/governance.rs:62-71`
— two more than `APPENDIX-NORMATIVE.md` §3's 26004 payload lists; `last_transition_at_ms` is the
natural source for the staleness clock and is used here.

**Debounce, inherited.** Non-healthy states must persist **2 s** before painting; healthy clears
instantly — the rule `shared/api/useRelayConnection.ts` already implements. A strobing strip teaches
operators to ignore the one row that matters at decision time.

**`totalGovernors > 1` switches to the fail-closed register, not a healthier one** — this is the one
place Perch's copy is more alarming than the raw numbers, and it is correct.

**Mode must render de-escalation.** `SwarmModeState::transition_down` exists on the same type as
`transition_to` (`AMB crates/swarm-core/src/agent.rs:148-155`, mirror guard) `[V]`, so `Incident` is
not terminal. A band that can only appear is one an operator learns to ignore.

**testids** `perch-governance-strip`, `perch-governance-mode`, `perch-governance-watch-claim`.
**ARIA** `role="status"` `aria-live="polite"`, one region; the `partitioned` transition additionally
raises a single `role="alert"`.

### 6.5 `StreamGapRow`

**Path** `features/perch-watch/ui/StreamGapRow.tsx` · **budget** 120 · **governs** `04` §2.1,
brief §8.1

Full-width amber row **above queue 1**, never a toast: `gap in the evidence stream: sequence
4471→4478 · 6 events not received · [verify with daemon]`.

**Honest caveat this component must carry.** `/v1/events/stream` sets
`.id(event.emitted_at_ms().to_string())` (`AMB crates/swarm-ingest-runtime/src/ingest/demo.rs:1703`)
— a millisecond timestamp that collides at the concentration monitor's 10 Hz cadence and is not
monotonic across issuers — and `RuntimeEvent` has no `seq` field
(`crates/swarm-runtime/src/runtime_events.rs:214-305`). Until B6 supplies a sequence, the number in
this row is the **bridge's own receive-side counter**, which detects nothing the daemon dropped
before the bridge. The row therefore carries a `<DerivedMarker fn="perch-bridge:receiveSeq" />` and
its copy says "sequence assigned by the bridge on receipt".

### 6.6 `GapCard`

**Path** `features/perch-policy/ui/GapCard.tsx` · **budget** 130 · **governs** `04` §2.12

One row per technique: technique id · threat class · rationale **verbatim** through
`<AdversaryString>`? — **no**: the catalogue is a checked-in ruleset, not adversary input, so it
renders as plain trusted text. `18` techniques across `11` detectors, from
`AMB rulesets/evasion/attack-technique-catalog.yaml`.

**Refuses to** editorialize a rationale · show a coverage percentage.

### 6.7 `ContainmentRow`

**Path** `features/perch-containment/ui/ContainmentRow.tsx` · **budget** 260 · **governs**
`04` §2.6, INV-05, INV-06, INV-07

Composes `ContainmentTimer` (§4.10), `RollbackStepList` (§4.11), `ProvenanceRows` (§4.7).

**Ordering is the server's.** Sorted by `expires_at_ms` then `lease_id`; the handler comments that a
listing whose order depends on the store makes two operators' screens disagree
(`AMB crates/swarm-runtime-http/src/http/containment.rs:177-183`). **Perch does not re-sort.**

**Release reads the body, never the status.** `lease_closed` is computed by re-listing open leases
(`containment.rs:219-226`); `fully_reversed` comes from `receipt.fully_reversed()`, which is
deliberately strict — non-empty steps AND every step `Reversed` (`rollback.rs:288-296`). A 200 with
`lease_closed: false` renders in the **error register** (INV-05).

**The extend affordance is absent and its explanation is present.** `ContainmentLease` has private
fields, one constructor, and derives expiry from a `ContainmentTtl` newtype that cannot represent
"no expiry" (`AMB crates/swarm-response/src/containment.rs:74-95`, persisted form re-checks at
`:157-172`) `[V]`. The disabled row-menu item stays visible carrying
`data-perch-role="containment-extend-disabled"`.

**A state nothing in the plan set renders.** `ContainmentSettings.lease_store_path` defaults to
`None` (`AMB crates/swarm-core/src/config/runtime.rs:94-95`), and with no store
`prepare_containment` returns `RuntimeError::ContainmentRefused` for all four containment actions
(`crates/swarm-runtime/src/lib.rs:836-844`). **DECIDED:** `/leases` renders
`no-containment-lease-store-configured` as a first-class empty state naming the config key, and the
verdict pane renders a typed refusal for a granted `isolate_host` under that config rather than a
500. **Revision 2 renamed this token** from `no-lease-store-configured`, which failed
`copy-ban-list.tsv`'s `bare-lease` row: the pattern `(^|[^a-z])leases?([^a-z]|$)` matches
`-lease-`, and the exemption ERE lists `lease_store` with an underscore, which a kebab-case state
token does not carry. `no-containment-lease-store-configured` contains `containment` and is exempt —
and it is also the more honest name, since three unrelated objects share the word and only the
containment lease has a store.

### 6.8 `PolicyRuleRow` + `PolicyTripleEvaluator`

**Paths** `features/perch-policy/ui/PolicyRuleRow.tsx` (200) and `PolicyTripleEvaluator.tsx` (240) ·
**governs** `04` §2.7

**Shadowing is evaluated, never dimmed.** `selector_matches` consumes exactly
`(threat_class, severity, action)` and `evaluate` returns on the first match in file order
(`AMB crates/swarm-policy/src/configurable_gate.rs:44-56`, `:143-180`), so shadowing is only
computable per triple. Static dimming would assert a containment relation the type system does not
have. The evaluator takes a triple and every rule renders `decides` / `not matched` / `not reached`.

**The request-carried-selector warning banner is permanent, not conditional.**
`threat_class_from_request` reads `request.evidence["escalation"]["threat_class"]` falling back to
`request.evidence["threat_class"]` (`configurable_gate.rs:34-41`), and `severity` is a plain field on
`ActionRequest` set by the requester (`crates/swarm-policy/src/lib.rs:47-58`). An agent chooses which
rule judges its own destructive action. Both fields render marked **request-carried**.

### 6.9 `TuningRecommendationCard`

**Path** `features/perch-policy/ui/TuningRecommendationCard.tsx` · **budget** 240 · **governs**
`04` §2.10

Every field of `AlertTuningRecommendation` renders: `summary`, `next_step`, `strategy_id`, `host_id`,
`reviewed_findings`, `false_positive_findings`, `false_positive_rate`, `supporting_signals`. Each
card links through to the underlying verdicts in the Ledger.

The empty state names its own numbers from `AMB crates/swarm-runtime/src/alert_tuning.rs:6-15`:
host exclusion 2/2/0.75, detector threshold 4/2/0.50, detector rule 3/2/0.34, capped at 6.

Reuses `features/settings/ui/ModerationQueueCard.tsx`'s grouped-card pattern — **with its
`ShieldAlert` at `:317` removed** (§2.4). **Refuses to** auto-apply · ship a disabled Apply button ·
own the C9 numbers.

### 6.10 `WatchClaimPanel`

**Path** `features/perch-shift/ui/WatchClaimPanel.tsx` · **budget** 220 · **governs** `04` §2.11

The claim is the **topic of a standing `#watch` ops channel** — zero new kinds, one relay-signed
durable `kind:40099` `topic_changed` row per shift change. Takeover is explicit and logged: a second
operator overwrites the topic, producing one more row naming both times. Perch does not gate it; it
records it.

**The panel must state what the claim does not do:** it does not change who is `p`-tagged on a hold
(that is settled at every `OperatorScope::Approve` principal —
`AMB crates/swarm-core/src/config/operator.rs:153-168`). It is a client-side paging filter for wake
classes 1–3.

**Blocked state (INV-19):** `/handoff` cannot complete while `expired_undecided > 0` without an
explicit acknowledgement — an unignorable row, **not** a blocking modal.

### 6.11 `LedgerResultRow` + `LedgerExportDialog`

**Paths** `features/perch-shift/ui/LedgerResultRow.tsx` (190), `LedgerExportDialog.tsx` (230) ·
**governs** `04` §2.9

The export dialog states two constraints as body copy, not fine print: it answers "a human was
asked", **not** "who decided", until B2o lands; and its horizon is the relay's configured
audit-retention window, not the case TTL.

**Refuses to** export a PDF (a human-readable artifact is generated **from** the bundle, alongside
it, never instead of it) · offer saved searches in v1 · offer a SQL box.

### 6.12 `CaseTtlClock`

**Path** `features/perch-evidence/ui/CaseTtlClock.tsx` · **budget** 110 · **governs** `04` §2.3

Renders `channels.ttl_deadline` as a **clock, not a bar**. Carries the honest caveat: the
`refresh_channel_ttl_after_event_insert` trigger's `EXCEPTION WHEN OTHERS` arm downgrades a failed
refresh to `RAISE WARNING` (`BUZZ schema/schema.sql:984-988`), so a case can archive under an active
investigation — which is why `/handoff` reads open cases from the **daemon**, not from the channel
row.

### 6.13 `PerchOmnibox` — the `Cmd-K` surface

**Path** `BUZZ desktop/src/features/perch-shift/ui/PerchOmnibox.tsx` · **budget** 320 · **governs**
`APPENDIX-NORMATIVE.md` §1 (`/ledger` "also the `Cmd-K` overlay") and §2 (`Cmd-K`: "Omnibox: query
mode; `>` switches to command mode"), `04` §2.9, §3.1

**Revision 2, new.** A wave-2 critic found this surface had a binding in the normative key map, a
home in the normative route table, two drawn overlays in `prototypes/watch.html`, and a filename
assigned by `15-FILE-SPLIT-PLAN.md` — and **no spec, no task card, no fixture** anywhere in wave 2
(`grep -ci omnibox` returns 0 in this sheet's revision 1, in `18`, `14`, `20` and `22`). That is
correct and this section closes it.

**It is a new file, not an edit.** `15-FILE-SPLIT-PLAN.md` pins this: `TopbarSearch.tsx` is
**exactly at cap** — 999 `wc -l` = 1000 gate-lines, re-measured this session `[V]` — so it cannot
take one line. `PerchOmnibox` is a sibling that reuses `TopbarSearch`'s *modules*, not its file.

**What it inherits, verified `[V]`.** `TopbarSearch.tsx` composes
`Dialog`/`DialogContent`/`DialogTitle` (`:25`), `useDeferredModalOpen` (`:26`),
`useSearchMenuKeyboardNavigation` (`:21`), `parseSearchOperators` (`:6`) and
`buildSearchResultPreview` (`:7`, called at `:699`). `parseSearchOperators`
(`features/search/lib/parseSearchOperators.ts:78`, `OPERATOR_RE` at `:37`) extracts exactly four
operators — `from:` / `in:` / `after:` / `before:` — and deliberately leaves them in the text so
they still participate in FTS (`:5-7`). Perch reuses all five modules verbatim; only the result
shapes and the command mode are new.

```ts
export type PerchOmniboxMode = "query" | "command";

export type PerchOmniboxProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Query mode results. Ledger rows, already admitted (§3.4) and decoded. */
  results: readonly LedgerResultRowModel[];
  resultsState: "idle" | "loading" | "ready" | "degraded" | "empty";
  /** Command mode. A CLOSED registry — see below. Never a free-text passthrough. */
  commands: readonly PerchCommandSpec[];
  onRunCommand: (spec: PerchCommandSpec, args: readonly string[]) => void;
  onOpenResult: (row: LedgerResultRowModel) => void;
};

/**
 * One command. `run` is NOT here: the omnibox emits an intent and the surface
 * that owns the write performs it, so a command can never become a sixth
 * un-audited write path (INV-01's five-call allowlist).
 */
export type PerchCommandSpec = {
  /** e.g. "release containment". Words, not a slug — this is the rendered grammar. */
  verb: string;
  /** Positional argument labels, rendered as ghost text. */
  args: readonly string[];
  /** Which route the command navigates to, or which write it requests. */
  effect:
    | { kind: "navigate"; view: PerchView }
    | { kind: "request-write"; write: "release-containment" };
  /** Rendered beside the verb. Required — a command with no consequence line is a spec bug. */
  consequence: string;
};
```

**Two modes, one input, one switch character.** `>` as the **first character** switches to command
mode; deleting it returns to query mode. Any other position is literal query text. The mode is
visible as a persistent prefix chip, never as a colour change — a mode an operator can be in without
seeing is how a query becomes a command.

**The command grammar is closed and small.** `prototypes/watch.html` commits
`> release containment cnt-4b19e7`, correcting `04` §3.1's `> release cap-77f3a2`: a release acts on
a **containment lease**, and `cap-` names the capability lease, a different object with a different
TTL (60,000 ms vs 900,000 ms — `19-TOKENS`' "TWO TTLs, NEVER CONFLATED"). This sheet adopts the
prototype's form. **The v1 registry is exactly two entries**: `release containment <lease_id>`
(`request-write`) and `open <view>` (`navigate`). Everything else is query mode. A third command is
a written argument, not a convenience — the omnibox is one keystroke from every surface, and a
destructive verb reachable that way is the shape render law 6 exists to prevent.

**A command never bypasses a gate.** `release containment` emits `{kind: "request-write"}`, which
navigates to `/leases` with the row focused and its release control armed — it does **not** POST.
The blast-radius/dwell contract belongs to the surface that owns the object, and the omnibox has no
BLAST RADIUS block to observe. `data-perch-role="grant"` never appears in this file, which
`check-perch-grant-affordance.sh` R2 (exactly one file may declare it) already asserts.

**Escape.** Acquires an escape surface for its open lifetime via `acquireEscapeSurface()`
(`BUZZ desktop/src/shared/hooks/escapeSurfaces.ts:26-33` `[V]`, whose returned release is idempotent)
and **releases it in the same effect's cleanup**, asserted by an unmount test — a leaked acquire
disables Escape-to-mark-read for the whole session (`useMarkAsReadShortcuts.ts:33` yields on
`hasActiveEscapeSurface()` `[V]`). Escape closes the overlay and never marks read.

**Keyboard.** `Cmd-K` opens — the chord Buzz already owns at
`useAppShellKeyboardShortcuts.ts:73-77` (`key === "k" && !event.shiftKey` under
`hasPrimaryShortcutModifier`, with `event.repeat` already guarded at `:60`) `[V]`, retargeted from
`onSearchEverything` to this overlay. Arrow keys and Enter come from
`useSearchMenuKeyboardNavigation`. `Cmd-Shift-K` (Buzz's new-message chord at `:79`) is **not**
reused; it goes with the DM surface. The binding is a row in `PERCH_BINDINGS` (§6.1) with
`rowTypes: []` and no `verb`, so INV-31/INV-32's table tests cover the chord without treating it as
a verdict key.

**States** `closed` · `query-idle` (recent Ledger rows, no query) · `query-loading` ·
`query-results` · `query-empty` (an `EmptyState` of kind `governing-number`, naming the FTS-only
constraint — `strategy_id`, `host_id`, `receipt_id`, `lease_id` and `hunt_id` are reachable through
NIP-50 only, `APPENDIX-NORMATIVE.md` §3) · `query-degraded` (relay unreachable; says so, does not
show a stale page as fresh) · `command-idle` (the two-entry registry with consequence lines) ·
`command-armed` (a complete command with its arguments; Enter runs the *effect*) ·
`command-unknown` (an unmatched verb renders the registry, never an error toast).

**testids** `perch-omnibox`, `perch-omnibox-input`, `perch-omnibox-mode`,
`` `perch-omnibox-result-${rowId}` ``, `` `perch-omnibox-command-${slug}` ``,
`perch-omnibox-empty`.

**ARIA** `<Dialog>` with a real `DialogTitle` (visually hidden), `role="combobox"` +
`aria-expanded` + `aria-activedescendant` on the input, `role="listbox"` on the result list. The
mode chip is inside the input's `aria-describedby`.

**Type** input `text-base`; result line 1 `text-sm`; the operator/tier line `text-xs`; the FTS-cost
note `text-2xs` (§1.10).

**Refuses to** run a write · accept a free-text command not in the registry · offer a SQL box ·
offer saved searches in v1 · render a result whose issuer was not admitted (§3.4) · stay open across
a route change.

### 6.14 `CaseCanvasTab`

**Path** `BUZZ desktop/src/features/perch-evidence/ui/CaseCanvasTab.tsx` · **budget** 210 ·
**governs** `APPENDIX-NORMATIVE.md` §1 (the Case Canvas is a *tab* of `/cases/$caseId`, not a
route), `04` §2.4

**Revision 2, new — and it takes an owner.** Revision 1 filed the seeded canvas template as
"UNRESOLVED, NO OWNER"; so did `prototypes/case.html`; so does `20-TASK-BREAKDOWN.md`'s single
`canvas` row, which points at `14` and `11`, neither of which owns it either. Three wave-2 artifacts
handed the same item to each other. This sheet takes it, at the minimum viable shape, because the
Canvas is a **component** of a surface this sheet already specs and nothing else about it needs a
new mechanism.

**The mechanism it must not need.** `BUZZ desktop/src/features/channels/ui/ChannelCanvas.tsx` is
**152 gate-lines** — 151 `wc -l` lines, per §1.6's arithmetic; the "151 lines" three plan documents
quote is the `wc -l` figure `[V]`. It is a renderer-process component that reads one channel's canvas and writes it
back: `useCanvasQuery(channelId, channelId !== null)` at **`:28`** (imported `:5`) fetches, and
`useSetCanvasMutation(channelId)` at **`:29`** (imported `:6`) writes the `<Textarea>` draft; the
content renders through `<Markdown>` behind `React.useDeferredValue` at **`:41`** because the canvas
is one large markdown parse. It has **no template mechanism** — no seed, no default, no
per-channel-type branch anywhere in the file — and `canvasQuery.data?.content ?? null` at **`:38`**
is `null` on a fresh channel. It already takes `canEdit` and `isArchived` (`:19-20`, gating the edit
control at `:137`) and already renders `RELAY_UNREACHABLE_SHORT` (`:14`, used `:66`) on a failed
read `[V]`.

**DECIDED:** the template is **written by the console on first open**, not by a Buzz mechanism.
`CaseCanvasTab` wraps `ChannelCanvas` unchanged. When `canvasQuery.isSuccess && content === null`
**and** the operator has edit rights, it calls `setCanvasMutation.mutateAsync(PERCH_CASE_TEMPLATE)`
exactly once per `caseChannelId`, guarded by a module-level `Set<string>` of channel ids already
seeded. That guard is a colony-scoped singleton and therefore a `ColonyScopedSingleton` member with
a resetter (`14-CLIENT-ARCHITECTURE.md`'s registry) — without it, switching colonies re-seeds a case
whose canvas an operator deliberately emptied.

```ts
/**
 * Five fixed markdown headings and nothing else. No prose, no placeholders,
 * no examples: an operator must not have to delete a machine's guesses at
 * 03:00, and a template with sample text becomes a template nobody edits.
 * The headings are `04` §2.4's four plus Handoff notes, which /handoff reads.
 */
export const PERCH_CASE_TEMPLATE = [
  "## Timeline",
  "",
  "## Hypothesis",
  "",
  "## Actions taken",
  "",
  "## Open questions",
  "",
  "## Handoff notes",
  "",
].join("\n");
```

**What the tab adds around it.** A `CaseTtlClock` (§6.12) in the tab header, because a canvas is the
one place an operator writes prose they will lose when the channel archives; and the `swarm-produced-
nothing` guard — the Canvas is **not** where a `CorrelatedIncident` renders. `prototypes/case.html`
and `03` §4.2 agree and this sheet binds to them: `CorrelatedIncident` is a recomputed Ambush
artifact, it reaches the timeline as a **system row** linking here, and its included/rejected member
graph renders on this tab as a read-only figure `18-DATAVIZ.md` owns (`KillChainGraph`, whose
`rejected` prop is required — a graph showing only inclusions is an argument, not evidence).

**States** `loading` · `empty-seeding` (the one-shot write is in flight; the five headings render
immediately from the constant, not after the round trip) · `ready` · `editing` ·
`read-only` (no edit rights, or the case is archived — `ChannelCanvas` already takes `canEdit` and
`isArchived` at `:19-20` and gates its edit control on both at `:137` `[V]`) · `relay-degraded`
(`ChannelCanvas` already renders `RELAY_UNREACHABLE_SHORT` at `:66` `[V]`; the tab does not
duplicate it) ·
`seed-failed` (the mutation rejected: the tab renders the five headings as *uncommitted* text with a
retry, and never silently shows an empty canvas as if it were saved).

**testids** `perch-case-canvas`, `perch-case-canvas-seeded`, `perch-case-canvas-seed-retry`.

**Type** headings inherit `<Markdown>`'s ramp; the tab header's TTL clock is `text-xs` with the
figure `text-sm`.

**Refuses to** seed a canvas that has ever had content · seed on every mount · seed without edit
rights · render a `CorrelatedIncident` as a card · edit `ChannelCanvas.tsx`.

**If the template is cut**, the consequence is stated rather than left implicit: `/handoff`'s
"Handoff notes" read has no heading to find, and `04` §2.4's four-heading canvas becomes an empty
`<Textarea>`. Cutting it is a one-line change (delete the seeding effect); cutting the *tab* is not,
because `APPENDIX-NORMATIVE.md` §1 counts it in the fourteen surfaces.

---

## 7. Deferred to `18-DATAVIZ.md`

`ConcentrationChart` · `HostHeatList` · `KillChainGraph` · `EventTimeline` · `Sparkline` ·
`DistributionBar` · `ContainmentBoard`. This sheet asserts only three things about them, because they
are component-layer contracts rather than chart contracts:

1. Every chart label uses `className="text-2xs"` (tick labels, axis labels) or `className="text-sm"`
   (a value a reader must take away, per §1.10), never an SVG `font-size` attribute or a `fontSize`
   JSX prop. **The px-text guard cannot see either**: `FONT_SIZE_PX_RE` at
   `BUZZ scripts/check-px-text-core.mjs:32` requires a `font-size` **colon**, and
   `TEXT_ARBITRARY_RE` at `:29` only matches a Tailwind arbitrary class `[V]`. A third regex is
   needed and does not exist; `18` §13's G1 (`check-svg-font-size.mjs`) is its owner (§2.6).
2. Every chart ships a `<table>` equivalent behind the same data, per `05` §8.4.
3. No chart component may take a bare source count. **Revision 2 narrows this** so it survives
   Phase 1: a chart takes `SourceCountProps` (§4.8) — the discriminated pair — not
   `sourceIds: string[]`. `18`'s **CR-5** as written forbids the count arm outright, but B4 is
   Phase 2 and **no Phase-1 card carries source ids at all** (`source_ids` is `null` on the only
   schema that has the field, and no other schema has it), so a CR-5 that admits no count arm makes
   both `SourceCount` and every lane row unbuildable until B4. The pair keeps CR-5's actual
   guarantee — a lone `sources: number` is unrepresentable — while giving Phase 1 a typed absence.
4. Chart colour reaches SVG through a class or style object as `hsl(var(--perch-viz-series-N))`,
   never a presentation attribute, and never a bare Buzz shadcn name (§1.9 + `19-TOKENS`' ONE COLOUR
   FORM commitment). `18`'s own prototype notes its `fill="var(--x)"` attribute pattern as a
   standalone-file deviation; this sheet agrees it must not reach a component.
5. `agentIdOfSource` (§4.8) is imported from `shared/ui/perch/SourceCount.tsx`, not reimplemented.
   `18-DATAVIZ.md:364`'s inline `id.split(":").slice(0, -1).join(":")` is wrong for the
   operator-feedback id shape (§2.7).

---

## 8. Re-skinned components — the delta

**forks** = a new Perch file is created and the two diverge. **themes** = the Buzz file stays and
Perch keeps importing the same path.

| Component · path | Delta | Forks / themes |
|---|---|---|
| `shared/ui/badge.tsx` | add `severity` / `pillar` / `verdict` / `state` variant groups to the cva. **Remove `warning` / `success` / `info`** (`:16-18` `[V]`) — stock Tailwind hexes outside the palette, and a "success green" contradicts substrate-green-means-detection. Base string at `:7` is untouched. | **themes** |
| `shared/ui/alert-dialog.tsx` | (a) make `variant` a **required** prop on `AlertDialogAction`, so `buttonVariants()` with no variant at `:149` `[V]` can never be reached by omission; (b) drop the `texturedSurfaceClasses` import at `:8-11` and the arm at `:78-81` (§2.1). | **themes**, net-negative |
| `shared/ui/button.tsx` | add a `verdict` variant with **no `bg-primary` path**. Existing variants untouched. | **themes** |
| `shared/ui/card.tsx` | **§2.1.** Remove `import "./card-texture.css"` `:6`, `TEXTURED_SURFACE_CLASS` `:11-12`, `texturedSurfaceClasses` `:14-26`, the `textured` cva arm `:55-60`, the `textureSize`/`textureTone` props `:72-73`, and the class applications `:96,:99`. ~55 gate-lines removed. | **themes**, net-negative |
| `shared/ui/dialog.tsx` | **§2.1.** Remove `import "./card-texture.css"` `:9`; narrow `surface` at `:59` to `"default" \| "none"`; remove the three textured arms `:96`, `:104-107`, `:122-123`. | **themes**, net-negative |
| `shared/ui/popover.tsx` | **§2.1.** Remove the `card` import `:5-9`, the `sideOffset` branch `:58`, the textured arm `:65-68`. | **themes**, net-negative |
| `shared/ui/ViewLoadingFallback.tsx` | **§2.2.** Replace the `ViewLoadingFallbackKind` union `:8-14` with Perch's view ids; delete the `projects` branch `:406-408` that renders `BuzzLoadingState`; delete the `BuzzLoadingState` import `:2`. | **themes**, net-negative |
| `shared/ui/sidebar-action-card.tsx` | **§2.3.** Remove the `PoofBurstProvider` import `:16` and its call. | **themes**, net-negative |
| `shared/ui/PubKey.tsx` | extend to two chains (secp256k1 `npub`, `swarm:ed25519:<64 hex>`) and **label which one is shown**. Keep the compact/full doctrine `:21-31` `[V]` unchanged. `desktop/scripts/check-pubkey-truncation.mjs` extends to Ed25519 ids — note its `overrides` set is keyed `path:line` (`:20-31`, six entries) `[V]`, so Perch's entries are line-fragile and must be re-checked on every edit to those files. | **themes** |
| `shared/ui/tooltip.tsx` | `DEFAULT_TOOLTIP_DELAY_MS = 500` `:9` + `skipDelayDuration: 0` `:10` + `disableHoverableContent` `:25` `[V]` is a chat policy. Perch adds a **scoped** `PerchDataTooltipProvider` at 150/300 ms, wrapping data surfaces only. The global provider is untouched. | **themes** + one new file |
| `shared/ui/markdown.tsx` | 1,906 gate-lines, frozen. Perch's edits must be **net-negative**. It imports `MarkdownVideoPlayer` at `:133-135` (used `:1502`) and `VideoReviewMarkdownContext` (`:1875-1892`) `[V]`; removing the video path is the net-negative budget that pays for any Perch change. | **themes**, net-negative only |
| `features/agents/ui/AgentStatusBadge.tsx` | drop `motion-safe:animate-pulse` at `:58` `[V]`; keep `PRESENCE_GRACE_MS = 15_000` at `:8` and its `setTimeout` at `:27-30`. Also drop the `warning` arm (type at `:39`, value at `:42` `[V]`) once badge's `warning` is removed — re-map to a `state` variant. | **themes** |
| `features/workflows/ui/WorkflowApprovalCard.tsx` | **replaced entirely** by `VerdictPane` (§4.2). Its sole caller is `WorkflowRunTrace.tsx:120` (imported `:5`) `[V]`, which is inside the Buzz workflow surface Perch deletes. Note `:10-12` returns `null` when status ≠ pending **or expired** — the "hold expired mid-read" state is exactly what it discards today. | **forks** |
| `features/settings/ui/ModerationQueueCard.tsx` | the tuning-bench card pattern. Remove `ShieldAlert` (`:2` import, `:317` render) → `AlertTriangle`, already imported at `:2` `[V]`. | **forks** into `TuningRecommendationCard` |
| `features/channels/ui/MembersSidebarMemberCard.tsx` | the case members panel. Remove `Shield` `:409` → `UserRound` + the role word; remove `ShieldCheck` `:453` → `Check` `[V]`. | **themes** |
| `features/agents/ui/activityRenderClasses/LifecycleActivity.tsx` | one of the 15 render classes `00-BRIEF.md` §5.4 keeps. Remove `ShieldCheck` (`:1` import, `:66` render) → `CircleDot` `[V]`. | **themes** |
| `features/settings/ui/SettingsPanels.tsx` | `/settings`, Phase 0. Remove `ShieldAlert` (`:16` import, `:214` icon field) `[V]`. Carries the honest-disclosure copy (`OperatorScope::Read` is enforced on no `/v1/operator/*` handler; the theme is pinned; the accent picker is deleted). | **themes** |
| `shared/ui/markdown/CodeBlock.tsx` | keep; retarget the Shiki theme to the pinned Perch pair via `resolveShikiThemeName`'s existing alias indirection. | **themes** |
| `shared/theme/terminal-palette.ts` | keep; it derives the 16-colour ANSI set from the syntax theme, which is why the syntax machinery survives at all. | **themes** |
| `shared/theme/adaptive-theme.ts` | **engine edit.** Remove the 10 `--huddle-*` at `:244-253`; rebind or delete `--status-added`/`--status-deleted`/`--status-modified`/`--ui-warning`/`--ui-warning-bg` at `:281-287` — unlike `--chart-1..5` these **are** mapped in `tailwind.config.js:128-136`, so `bg-warning`, `text-warning`, `bg-warning-bg` and `text-status-*` are live utilities today `[V]`. | **themes** |
| `shared/theme/ThemeProvider.tsx` | delete the 10-swatch accent picker (`:44-55`) and `applyAccentColor` (`:198`, `:213-218`, `:231-236`) — it writes six theme vars **inline on the root**, unbeatable by any stylesheet layer, and its palette includes Green, Orange and Red, which would make a CRITICAL badge meaningless `[V]`. | **themes** |

---

## 9. Components whose Buzz semantics mislead in a security context

Flagged because reusing them *as they read* would ship a false claim. Each needs a deliberate
disposition, not a token swap.

| Component | The chat semantic | Why it misleads here | Disposition |
|---|---|---|---|
| `WorkflowApprovalCard.tsx` | heading `Approval Required` `:19`, body `Approval actions are not yet available in Desktop.` `:26-28` `[V]` | both strings use the control label `APPENDIX-NORMATIVE.md` §7 bans outright; and its `WorkflowApproval` is a projection of a `workflow_approvals` **DB row** (`shared/api/workflowTypes.ts:56`, re-exported at `types.ts:863`), not a `kind:46010` event — an operator reading "Approval Required" would believe a hold exists where none does | replaced by `VerdictPane`; both strings deleted |
| `AgentStatusBadge.tsx` | `motion-safe:animate-pulse` while working `:58` `[V]` | eight roles × N instances is dozens of simultaneously pulsing badges — a photosensitivity hazard on a 24/7 wall screen, and "working" is not a security state | pulse dropped; grace period kept |
| `badge.tsx` `success` variant `:17` | emerald "success" | green is the **substrate** pillar (detection), not success. A green badge next to a finding reads as "this is fine" | variant removed |
| `alert-dialog.tsx` `AlertDialogAction` `:149` | defaults to `bg-primary` `[V]` | a hold decision styled as the primary action is exactly what render law 6 forbids | `variant` made required |
| `useMarkAsReadShortcuts.ts:24,:33` | bare `Escape` marks the active channel read `[V]` | in a queue where *read* and *decided* are different facts, an accidental `Escape` clears a queue | unchanged file; Perch surfaces hold an `acquireEscapeSurface()` for their lifetime (`escapeSurfaces.ts:26-33` `[V]`), which the shortcut already yields to at `:33`. **A leaked acquire disables mark-read permanently — every Perch surface's release is asserted in its own unmount test.** |
| `MessageReactions` / reaction chips | emoji reactions on a message | a reaction on an evidence card is an unsigned, unattributable pseudo-verdict | deleted from the case timeline; verdicts are `ambush:verdict:v1` cards |
| `UnreadPill.tsx`, `useFeedItemState.ts` done/unread | localStorage `buzz-home-feed-done.v1` / `.unread.v1`, 500-item cap `[V]` | "done" reads like a disposition | kept, relabelled, and every surface that renders it carries the copy "local to this workstation, never a decision record" (`APPENDIX-NORMATIVE.md` §2, `M`/`U`) |
| `attachment.tsx` + the five `*link-preview*` files | unfurls remote URLs | renders adversary-controlled remote content into a console whose trust argument is that it renders nothing it did not receive over an authorized path; also egress from an analyst workstation | **deleted** (§10) |
| `features/terminal` PTY | a developer tool | a real shell reachable from a surface that also renders adversary text | kept, but the PTY is **the operator's tool, not an agent's** (`08` §7.7 control 4); the banner is permanent |
| `sonner` toasts | ephemeral notice | a gap in the evidence stream must not be a toast — it disappears unread at 03:00 | `StreamGapRow` (§6.5) is a persistent row above queue 1; toasts are reserved for local, reversible actions |

---

## 10. Dispositions for the sixteen `shared/ui` files `05` §9 leaves unassigned

`05` §9 assigns no verdict to sixteen files. The design ground proposed dispositions; this sheet
**decides** them, with two changes forced by §2.

| File | Decision | Reason |
|---|---|---|
| `attachment.tsx` | **delete** | renders adversary-controlled remote content; also the container `WaveMessageAttachment` uses, which goes with the wave |
| `compact-link-preview-attachment.tsx` | **delete** | remote unfurl |
| `link-preview-attachment.tsx` | **delete** | remote unfurl |
| `link-preview-controls.tsx` | **delete** | remote unfurl |
| `link-preview-list.tsx` | **delete** | remote unfurl |
| `rich-link-preview-attachment.tsx` | **delete** | remote unfurl |
| `config-nudge-attachment.tsx` | **delete** | an agent-authored actionable card outside the marker registry — a second, unaudited card path |
| `markdown.tsx` | **keep, net-negative edits only** | 1,906 gate-lines, frozen |
| `markdownFileCard.ts` | reuse verbatim | pure helper |
| `markdownUtils.ts` | reuse verbatim | pure helper |
| `mentionChip.ts` | reuse verbatim | `InlineChip` depends on it (`InlineChip.tsx:4-9` `[V]`) |
| `modalSearchStyles.ts` | reuse verbatim | class constants |
| `deferredModalOpen.ts` | reuse verbatim | scheduling helper |
| `UnreadPill.tsx` | reuse, relabelled | see §9 |
| `UserAvatar.tsx` | reuse verbatim | `MessageRow.tsx:37` depends on it `[V]` |
| `sidebar-action-card.tsx` | **re-skin, not reuse** — changed from the ground's `[P]` | imports `PoofBurstProvider` at `:16` `[V]` (§2.3) |

Deleting the seven attachment/preview files requires editing `shared/ui/markdown.tsx` (imports
`attachment` `[V]`) and `features/messages/ui/ComposerAttachments.tsx` and
`useComposerLinkPreviews.tsx` — all net-negative, all inside Perch's own composer reduction.

---

## 11. File-size budget ledger

Every new file, against 1000 gate-lines. Totals are estimates; the rule is that any spec above 600
splits before it is written.

| Area | Files | Est. gate-lines |
|---|---:|---:|
| Marker registry (§3) — types, parse, registry, frame, refusals, provider, `MessageBody` | 8 | ~1,110 |
| Marker registry — seven card presenters | 7 | ~1,300 |
| Tier A (§4) | 12 | ~2,110 |
| Tier B (§5) | 11 | ~1,150 |
| Tier C (§6) | 19 | ~3,770 |
| Colocated `.test.mjs` for `lib/` modules | ~10 | ~1,540 |
| **New Perch component layer** | **~67** | **~10,980** |

Revision 2's deltas: `SourceCount` 140 → **190** (§4.8's discriminated pair, `agentIdOfSource` and
the absence forms), plus its new `sourceCount.test.mjs` (~140 — the four-row derivation table and the
plural forms); `PerchOmnibox` **320** and `CaseCanvasTab` **210**, both new (§6.13, §6.14).

Files that **cannot absorb one line** and are therefore prerequisites, not follow-ups:
`MessageRow.tsx` (999/1000, headroom 1), `AppShell.tsx` (998/1000, headroom 2),
`sidebar.tsx` (1011, frozen), `markdown.tsx` (1906, frozen), `tauri.ts` (1108, frozen),
`relayClientSession.ts` (1084, frozen), `types.ts` (1000, headroom 0) `[V]`.

**Consequence for this sheet:** every Perch Tauri wrapper goes in a **new sibling file** under
`src/shared/api/` importing `invokeTauri` from `./tauri` — the pattern **39** files under
`src/shared/api/` already follow besides `tauri.ts` itself (`tauriEvents.ts`, `tauriMesh.ts`,
`tauriChannelHeadCache.ts`, `tauriAcpDiscovery.ts`, `tauriManagedAgentMessageMarkers.ts`,
`communityProfile.ts`, `forum.ts`, `osIdle.ts`, …) — measured
`grep -rl invokeTauri src/shared/api/ | grep -v api/tauri.ts$ | wc -l` `[V]`. The ground pass's
"8 precedents" counts only the six that use the relative `from "./tauri"` form. Every
Perch shared type goes in a new file, never in `types.ts`.

---

## 12. Dependency-ordered build order

Each step is buildable and testable before the next. Steps 1–4 are the housekeeping the brief calls
prerequisites; nothing renders until step 5.

**Phase 0 — unblock (nothing Perch-visible ships)**

1. **Split `MessageRow.tsx`.** Extract the `default:` arm `:414-461` into
   `features/messages/ui/MessageBody.tsx`. Net −40 gate-lines on a file with 1. Owned by
   `15-FILE-SPLIT-PLAN.md`; §3.9 is the seam contract. *Gate:* `just file-size-check` passes,
   `pnpm test:e2e:smoke` unchanged.
2. **Split `AppShell.tsx`** (998/1000). The house pattern in `desktop/src/app/` is extracting
   **hooks**, not components — **18** `use*.ts`/`use*.tsx` sibling files already sit beside it
   (`ls src/app/use*.ts src/app/use*.tsx | grep -v test | wc -l` → 18) `[V]`. Owned by `15`.
3. **Texture excision** (§2.1): four `shared/ui` files edited net-negative, `card-texture.css` +
   four PNGs (3,424,707 B) deleted, ten `features/{communities,onboarding}` call sites removed with
   their surfaces. *Gate:* `pnpm build:e2e` succeeds; the ten call sites are gone, not stubbed.
4. **`shared/ui/perch/` created empty; `data-perch-role` attribute contract landed** (§1.4) with its
   PROPOSED guard **and** the guard's workflow step in the same PR — `AMB tools/check-gates-wired.sh`
   enumerates every `tools/check-*.sh` and fails on any not named by a real workflow `run:` step
   `[V]`.
4b. **`globals/perch.css` landed and the `--perch-*` grep gate wired** (§1.9). This is a Phase-0
   step, not a Phase-1 one: every component from step 5 down names `--perch-*`, and landing the
   stylesheet after them means every one of them renders against undefined variables — which paints
   as *inherited* rather than as an error, so nothing fails. `19-TOKENS.md` owns the file;
   `18-DATAVIZ.md` owns the widened `check-perch-chart-tokens.sh` that polices the names (§2.6).

**Phase 1 — primitives with no Perch dependencies**

5. `EyebrowLabel` · `PillarRail` · `SeverityBar` · `SeverityChip` (needs `badge.tsx`'s new variant
   groups) · `ConfidenceMeter` · `ThreatClassLabel` · `icons.perch.ts` **(blocked: no artwork
   source, §5.6)**.
6. `AdversaryString` (§4.1) — **before any component that renders a daemon field.** Its guard is
   PROPOSED; the component ships regardless, because the guard is the ratchet and the component is
   the control.
7. `DerivedMarker` · `SourceCount` · `EmptyState`. **`SourceCount` ships with only its
   `sourceIds: null` arm reachable**, because no Phase-1 card carries source ids (§4.8). The
   id-carrying arm is written and typed from day one — so the absence is a state and not a
   permanent shape — but its first real call site lands with **B4**, which is Phase 2. Its test
   table covers both arms immediately.

**Phase 2 — the registry**

8. `markerTypes.ts` + `parseAmbushMarker.ts` + its `.test.mjs`. *Gate:* the parse table test covers
   all five outcomes, plus `\r\n`, plus a marker on line 2, plus an unadmitted signer.
9. `AmbushCardContext` provider + `EvidenceCardFrame` + `RefusalCards`.
10. `ambushCardRegistry.tsx` with **one** entry (`finding`) and six `TODO` entries that fail `tsc` —
    proving the exhaustiveness gate fires before the other six exist.
11. The remaining six presenters, one per PR. Each needs `13-WIRE-SCHEMAS.md`'s decoder for its kind.
12. `MessageBody` wired to the registry; `e2eBridge.ts` fixtures land as a **delegated module**.

**Phase 3 — the Verdict Row (the product's reason to exist)**

13. `ProvenanceRows` · `RollbackStepList` · `ContainmentTimer` · `WriteStateRow`.
14. `VerdictSlot` → `VerdictPane` (INV-02 snapshot test over all 15 `ResponseAction` variants).
15. `perchKeymapRegistry` + `usePerchKeymap` (INV-31, INV-32 table tests).
16. `GrantControl` (INV-10, INV-11) · `VerdictChipBar` (INV-34) · `DismissArithmetic`.
    **Everything from step 13 down is dead until B1 lands** (`RequireHuman` is a refusal, not a
    queue: `AMB crates/swarm-runtime/src/lib.rs:1133-1146` records `AuditResponseRecord::Skipped`
    `[V]`). Develop against the E2E mock bridge with Ambush fixtures; if B1 slips, the queue ships
    labelled "not yet wired" and the grant control is **absent**, never mocked.

**Phase 4 — The Watch**

17. `VerdictQueueRow` → `WatchQueueSection` → `InstrumentationStrip` → `StreamGapRow`.
18. `GovernanceStrip` (chrome; lands with the shell, not with a route).

**Phase 5 — Phase-2 surfaces, parallelizable**

19. `ContainmentRow` (needs `ContainmentTimer`, `RollbackStepList`, `ProvenanceRows`).
20. `PolicyRuleRow` + `PolicyTripleEvaluator`; `GapCard`; `TuningRecommendationCard`
    (needs `ModerationQueueCard`'s fork).
21. `WatchClaimPanel`; `LedgerResultRow` + `LedgerExportDialog`; `CaseTtlClock`.
22. `CaseCanvasTab` (§6.14) — needs `CaseTtlClock` and the case route; no new mechanism.
23. `PerchOmnibox` (§6.13) — **after** `LedgerResultRow`, whose row model it renders, and after
    `PERCH_BINDINGS` (step 15), which owns its chord. Not before: an omnibox that opens onto a
    surface with no result renderer is a keystroke to an empty box.
24. `SourceCount`'s id-carrying arm wired, with **B4** (`GET /v1/operator/pheromone/deposits`,
    Phase 2 in `APPENDIX-NORMATIVE.md` §5). Every lane row, escalation card and chart switches from
    the absence form to the expansion in one change, because the type already had both arms.

**Phase 6** — the chart set, per `18-DATAVIZ.md`.

---

## 13. What this sheet decided, and what it could not

**Decided** (bound in commitments): the six-directory Perch feature tree; the `perch-` testid prefix;
the closed `data-perch-role` value set; the registry's erased-entry shape and its five-field context;
`line0.trimEnd()` with no `trimStart`; that a well-formed marker from an admitted issuer never falls
through to markdown; `signerPubkey` not `pubkey` for admission; the four refusal cards; that
`AlertDialogAction`'s `variant` becomes required; the sixteen unassigned-file dispositions;
`ViewLoadingFallback`, `sidebar-action-card`, `card`, `dialog`, `popover` moving from reuse to
re-skin; `no-containment-lease-store-configured` as a first-class `/leases` state; that
`InstrumentationStrip` renders `UNMEASURED`, never `0`, for the this-week counter.

**Decided in revision 2:** every Perch token reference is `--perch-*` and the Buzz-name bridge is not
an escape hatch for authored components (§1.9); the readable-text floor, with `text-3xs` rendering no
word (§1.10); `SourceCount`'s discriminated pair, its `agentIdOfSource` derivation, and its typed
Phase-1 absence (§4.8); the `superseded` write state and the losing console's obligation to publish
the qualifying update card (§4.12); `04` §2.1's four queue headers over `06` §5.1's (§6.2); the
three-line queue row with its type steps (§6.2); `PerchOmnibox`'s two modes and **two-entry** closed
command registry (§6.13); and the case-canvas template, which revision 1 filed as ownerless and
which this sheet now owns as a five-heading constant the console writes once per case (§6.14).

**Could not decide — no owner exists.**

1. **The seventeen marks** (nine domain icons, eight role glyphs). No source, no author, no roadmap
   line. `RoleGlyph` and `icons.perch.ts` are specified to their extension pattern and cannot be
   built. This blocks the case timeline's agent rows and the Watchfloor's colony panel. **Still
   open after revision 2** — it is the one item in this sheet with no path.
2. **`BUZZ desktop/scripts/check-copy-banned-terms.mjs`** — the Buzz half of the copy gate.
   `16-INVARIANT-TESTS.md`'s D2 states the ban list is read "byte for byte" by it and that a parity
   test asserts identical verdicts in both directions; that test cannot exist until the file does.
   `16` owns it; this sheet names it (§2.6) because every rendered string specified here is
   unenforced without it.
3. **Light mode.** `19-TOKENS.md` has since ratified replacements for the three tokens revision 1
   named (light muted ink `#55695f`, ring `#5f8f78`/`#40564c`, severity HIGH `#a94e08` and MEDIUM
   `#825b12`), so this is **narrower than revision 1 recorded**: 23 of the 36 light colour tokens
   are `[PROPOSED]` with measured ratios and none ratified. Every Tier B component is drawable in
   both themes against `perch-tokens.css` today; what is missing is ratification, not values.
4. **A `$defs/HoldId` pattern** in `common.schema.json` (`13`'s), without which six `hold_id`
   formats stay in circulation across the artifact set. No component in this sheet reads the id
   (§4.12), so nothing here breaks — but the export bundle and the fixtures do not agree.

---

## 14. Revision 2 — what the red-team pass changed

Four critics audited this sheet against source. Their findings, each verified before acting.

### 14.1 Confirmed and fixed

| # | Finding | Verified how | Fix |
|---|---|---|---|
| 1 | **Render law 2's mechanism was stated backwards.** Revision 1 read `whisker_agent.rs:148-149`, concluded `distinct_sources` counts the agent instance id, and filed an amendment against the appendix. | Read the four-link chain end to end: `whisker_agent.rs:148-149` builds the **base**; `pipeline.rs:80` → `resolve_deposits`; `pipeline.rs:573` applies `strategy_scoped_agent_id`; `stream.rs:20-22` formats `{base}:{strategy_id}`; `substrate.rs:1295` inserts it. The workspace's own test at `substrate.rs:2105` is named `query_counts_strategy_scoped_agent_ids_as_distinct_sources`. | **Amendment withdrawn.** §4.8 rewritten with the chain, the appendix's gloss restored, and the expansion copy pushed the *other* way — it must make a single agent's own detectors satisfying the minimum visible. Two one-token corrections filed to `13` (§4.8). |
| 2 | **Every token reference was a bare Buzz shadcn name**, which `ThemeProvider` overwrites inline. | Counted `createThemeVars`' return: 38 vars, including all nine names this sheet used. Read the two inline write loops at `ThemeProvider.tsx:404-406` and `:444-446`, and `applyAccentColor`'s six more at `:213-218`/`:231-236`. | §1.9 added; every token reference outside §1.9's own name map, §8's Buzz-engine edits and this log renamed to `--perch-*`, matching `tokens/perch-tokens.css`'s actual names (`--perch-foreground-muted`, not `--muted-foreground`). Verified by grep. |
| 3 | **`SourceCount` had no Phase-1 data source.** `source_ids` is `null` on the only schema that carries it, and B4 is Phase 2. | `grep source_ids schemas/*.json`; `APPENDIX-NORMATIVE.md` §5's phase column. | §4.8's discriminated pair with three typed absence reasons; §7 narrows `18`'s CR-5 so it survives Phase 1; §12 step 24 wires the id arm with B4. |
| 4 | **Nothing handled two operators deciding one hold.** | `APPENDIX` §4 layer 1 `p`-tags every Approve principal; `12` §4.4 resolves the daemon side but leg 1 publishes first and a `kind:9` is immutable; `card-ambush-verdict-v1`'s `leg2.state` enum has no value for it. | §4.12's `superseded` phase, the losing console's update-card obligation, and two named asks (a fifth enum value from `13`, a P0 reconciliation invariant from `16`). |
| 5 | **The Cmd-K omnibox had a binding, a route-table home, two drawn overlays and no spec.** | `grep -ci omnibox` → 0 in revision 1 and in `18`/`14`/`20`/`22`. | §6.13, with its modes, its **two-entry** closed command registry, the escape-surface contract, and a keymap-registry row so INV-31/32 cover the chord. |
| 6 | **The Case Canvas was handed between three artifacts and owned by none.** | Revision 1's own UNRESOLVED entry; `20`'s single `canvas` row points elsewhere; `prototypes/case.html` files it PROPOSED with no owner. | §6.14 takes it: five headings, written by the console once per case, no `ChannelCanvas.tsx` change. |
| 7 | **Queue headers were specified two incompatible ways**, and this sheet cited the losing source. | `04` §2.1 vs `06` §5.1; `prototypes/watch.html` renders the former. | §6.2 ratifies `04` §2.1's set with the argument, and joins the amendment against `06`. |
| 8 | **The type ramp collapses to an 11px/12px pair** across the drawn set. | The design review's headless census; re-derived the ramp from `tailwind.config.js:11-31` and `typography.css:16-52`, including the `smaller` preference's 13/14 scale that puts `text-3xs` at **7.4px**. | §1.10: a readable floor, three binding rules, and the census as an acceptance criterion. Applied to `AdversaryString`, `VerdictPane`, `ContainmentTimer`, `SourceCount`, Tier B and the queue row. |
| 9 | **`no-lease-store-configured` fails the copy gate's own `bare-lease` row.** | The pattern matches `-lease-`; the exemption lists `lease_store` with an underscore, which a kebab-case token does not carry. | Renamed to `no-containment-lease-store-configured`, which is exempt and more honest. |
| 10 | **Eleven CI gates are cited as the enforcement mechanism and are not delivered.** | Enumerated each against both repos and the delivered skeleton. | §2.6 rewritten as a twelve-row table with status, owner, and what goes unenforced — including `check-copy-banned-terms.mjs`, on which a *delivered* artifact's test depends. |

### 14.2 The copy gate's own collisions, recorded rather than worked around

Running `skeleton/tools/copy-ban-list.tsv`'s thirteen rows over this sheet's **rendered** strings —
component labels, absence copy, refusal-card copy, state tokens — found one genuine hit (item 9
above) and two structural collisions that are the gate's to resolve, not this sheet's:

- **`approve` (P0, no exemption) vs the daemon's own verbatim reason.** Every hold today carries
  `reason: "authorized but held for human approval"`. `VerdictPane`'s WHY WE ARE ASKING slot renders
  it. §4.2 takes the structural fix — render it as a quoted wire value, never a source literal — and
  supports `22-DEMO-FIXTURE.md`'s exemption **C-A2** for surfaces that cannot.
- **`bare-lane` (P1) vs the appendix's own nav label.** A standalone `Lanes` heading fails because
  the exemption ERE needs `threat|twelve|12|…` in the same string, while
  `APPENDIX-NORMATIVE.md` §1's full label passes. §6.2 names it; `16` owns the exemption row.

Two further collisions the critics found on the prototypes — U+26A0 (the warning-sign glyph, the
fourth alternate in the `shield-glyph` row's pattern) opening the render-law-2 evidence warning, and
the literal `ambush:lease:v1` marker comments — do not occur in this sheet's rendered strings, and
the `shield-glyph` pattern's four codepoints appear in this document only inside §14.2's own
discussion of the row. But both bear on this sheet's contracts. On the first: `SeverityChip` (§5.1)
already carries the rule — severity is a word plus a four-segment bar and **never** a glyph — so the
question the gate must settle is whether U+26A0 is banned everywhere or only beside an attestation;
`APPENDIX-NORMATIVE.md` §7's own wording scopes the ban to "a shield or lock glyph **beside an
attestation**", which the delivered pattern does not encode. On the second: §3.5 already requires the
ban to be scoped to rendered strings so the `"lease"` **union member and marker literal** do not fail
it, and the marker literal is built only by `ambushMarkerComment()` (§3.3), which is one function in
one file — the natural allowlist unit. That scoping is now load-bearing for three artifacts.

### 14.3 Held after re-verification

Nothing a critic raised against this sheet survived re-checking as wrong. Two of revision 1's own
claims were re-measured rather than assumed and both stand:

- **The comparator is 46 clauses, not 60** (`MessageRow.tsx:935-995`). Re-counted this session.
- **`shared/api` has 39 sibling precedents for `invokeTauri`, not 8.** Re-run this session. The
  smaller figure counts only the six using the relative `from "./tauri"` form.

One revision-1 figure was **corrected downward**: §2.6 said `AMB tools/` holds "23 other
`check-*.sh`". It holds **14** `check-*.sh` and one `verify-*.sh`. The 23 came from a ground note;
this sheet should have counted, and now has.

### 14.4 The systemic note this sheet accepts

The set-wide finding was *unarbitrated disagreement*: producers who each verified independently and
shipped opposite contracts, with artifact ownership deciding the outcome rather than evidence. This
sheet was the clearest instance — six producers read `pipeline.rs:573` correctly and two did not,
and the two owned the schema and the component sheet, so the wrong reading was the one that would
have compiled. The lesson taken here is narrower than "read more carefully": **a claim about a
mechanism is not verified until you have followed it to the line that writes the data**, which for
render law 2 is `pipeline.rs:573` and not `whisker_agent.rs:149`. §2.7 applies the same test in the
other direction and finds a third id shape nobody had traced, on the exact route B3 will call.
