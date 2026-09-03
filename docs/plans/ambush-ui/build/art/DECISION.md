# DECISION — the art direction is Quiet

**Chosen:** Quiet, with Night Bridge's guarded-throw treatment adopted for the grant control.
**Decided by:** the client, on the studio's recommendation (`COMPARE.html`, "The recommendation" —
signed "Studio recommendation · yours to overrule").
**Status:** ratified. The five other directions are closed. `desktop` on `block/buzz`
(`rebrand/ambush`) ships Quiet's tokens today.

---

## The direction

Of the six boards in `COMPARE.html` — Gallery, Night Bridge, Quiet, Substrate, The Record,
Colony — the one built is **Quiet**: the darkened bridge and the one lamp on the chart table,
achromatic room, one warm lamplit plate, one chromatic mark. Its own signature, the index
line, is not decoration laid over a product — it is the same object doing three jobs at once:
the brand mark, the destructive-action control, and the countdown (`quiet/PLAN.md` §5). That
is the reason it won: every other direction picked a palette and then found a control to put
it on; Quiet's palette *is* the control.

One piece was not native to Quiet's own board and was taken anyway. `COMPARE.html`'s
recommendation names the gap directly — "Quiet's grant is the strongest idea in the set and
still the least physical thing on its own board" — and pairs it with Night Bridge's hinged
guard: a cover that lies flat over the throw's own footprint when closed, turns past vertical
on a knuckled hinge when armed, and only then reveals the lit lantern behind it, so armed and
live differ by a fact about a physical object rather than a change of tint. Quiet ships that
mechanism for `IsolateHost` and every card like it; its own board's grant — an open channel
that fills and then closes at both ends — is superseded by the hinged guard for the one
control on the pane where "is this thing actually going to fire" cannot be answered by a
lightness ramp.

## Why

`COMPARE.html`'s readout gives Quiet the largest measured margin from the banned fence of any
direction but Gallery (ΔE₀₀ 10.55 against the nearest banned hex, 11.07 restricted to
chromatic tokens), the tightest chromatic budget after Gallery (four values, two per theme),
and the only light mode on the sheet built as "a second considered artefact rather than an
inversion." None of that is why it won on its own — Substrate measures better on some of the
same axes and the readout says so in the same breath it recommends against building it. Quiet
won because the physiology and the product logic land on the same fact rather than two
different ones: a watch keeps its bridge dark to hold night vision, and rod vision is
achromatic, so the room being a true, measured chroma-0.000 grey is not a style choice, it is
what the eye is actually doing at 3am (`quiet/PLAN.md` §1). Inside the one lamp's throw, cones
work again, so the record — the sentence an analyst is asked to judge — sits on the only warm
surface in the room. And the index line that marks an undecided, irreversible hold is not a
badge: its inked length *is* the fraction of the hold's hour remaining, so a fifteen-row queue
triages itself — at the fixture's reference timestamp, four holds read 97.71 / 97.71 / 63.11 /
13.89% — before a word is read (`quiet/PLAN.md` §5). The colour leaves the record the moment a
human decides; nothing permanent is ever inked. That is a design built around the one thing
the product does, not a mood applied to a screen that would have worked in five other palettes.

## What was not chosen, and what to keep from each

**Night Bridge** — direction not chosen; mechanism taken. Its board is the closest runner-up:
a warm-graphite panel where colour never lands on a word, only on light falling on a surface,
so the only two lit things on screen are the only two that can hurt you. What Quiet keeps is
the **guarded throw** itself — the hinged cover whose two positions are a fact about geometry,
not a tint, and which therefore survives colour removal by construction. That is the one
mechanism this decision actually imports; see above.

**Gallery** is the true chromatic zero on the sheet — not one coloured pixel in either product
screen. Its worth-keeping idea is the **two-lamp tally**: a PVW lamp burning white-hot the
whole time a hold waits on a human and a dark PGM lamp beside it, so a lit lens is identified
by its 14.02:1 white-hot core against an unlit lens rather than by the red field, which alone
manages only 1.96:1. It is the other two-position control on the sheet, built the same way
Night Bridge's is: geometry that colour-removal cannot take away.

**Substrate** is, in the readout's own words, "the better idea, and it is not close" — the
only direction whose self-audit moved colour off the dark ground entirely onto a lit bone
plate, so its chroma runs dark-on-light instead of the stock look every other dark direction
risks. What is worth keeping is the **decay ladder**: a base-2 axis where the hold's 3600s TTL
and the substrate's 3600s half-life turn out to be one axis, so an undecided hold expires at
the exact moment the concentration that opened it has halved. The readout calls it the most
beautiful object in the exercise, and it is not attached to Quiet's control because it answers
a different product question — decay of evidence, not consequence of a pending decision.

**The Record** renders the grant as a blank signature line rather than a button: 570px of
which 400px is empty stock, ruled once you arm it, filled in your own ink, dominant even at
thumbnail scale. What is worth keeping is that the loudest object on the most dangerous screen
in the product is an absence — the thing the product is waiting for is a signature, not a
click.

**Colony** draws a hold as a pin with five fixed labels, and an unfillable slot as a printed,
hollow pin head rather than a closed gap — the same five heads collapse into a five-dot key
that rides in every queue row, so "this action has no mapped undo" is legible before the row
is opened. What is worth keeping is that pattern: an absence rendered in place, with its slot
still numbered, rather than the row simply closing up around the missing field.

## Where the shipped tokens live

`block/buzz` at `rebrand/ambush` already carries Quiet as the desktop app's theme, applied in
the commit titled "Apply the Quiet design system and the Ambush mark." The token values match
`COMPARE.html`'s Quiet swatches exactly (index `#E05E28`/`#943106`, night `#171717`/`#BCB5AD`,
steel, rule, grad, plate, plate-hi, and the three-step ink ramp, dark then light). Three files
carry the package:

- **`desktop/src/shared/theme/quiet.ts:14-38`** — `QUIET_NIGHT` and `QUIET_DAY`, the two
  `ThemeSurfaces` records (`index`, `night`, `steel`, `rule`, `grad`, `plate`, `plateHigh`,
  `inkDim`, `inkMid`, `ink`) that are Quiet's entire chromatic and achromatic palette, one
  record per lighting condition rather than per "theme" — Ambush Night and Ambush Day are the
  same material under two lights, not two designs. The file also carries the syntax/terminal
  ink split (`CodeInks`, `:44-` on) that keeps code legible with hue stripped out, the same
  achromatic-structure/warm-literal argument the product screens make.
- **`desktop/src/shared/styles/globals/theme.css:1-16, 84-92`** — the same ten values as real
  CSS custom properties, `--ambush-index` through `--ambush-ink`, set once under `:root` for
  Day and again under `.dark` for Night, each block headed by its own "Quiet — Ambush Day/Night"
  comment. `--radius: 2px` — the machined chamfer — is set in the same two blocks. The
  shadcn-derived semantic tokens (`--background`, `--foreground`, `--card`, `--border`, and the
  rest) are HSL triples derived from this palette rather than a separate design.
- **`desktop/tailwind.config.js:66-77, 160-174`** — wires the `--ambush-*` variables into
  Tailwind's scale: `borderRadius` reads `var(--radius)` for every size token so the chamfer is
  uniform everywhere circles do not live, and `colors.index` / `.night` / `.steel` / `.rule` /
  `.grad` / `.plate.DEFAULT|hi` / `.ink.DEFAULT|mid|dim` expose the Quiet palette directly for
  the roles shadcn's own vocabulary has no name for — the index mark, the plate's raised head,
  graduations, mid ink.

The guarded-throw grant control itself is not yet a component in that commit — this rebrand
lands the room, the lamp and the mark; the two-position hold control is Perch surface work,
scoped in `build/17-COMPONENT-SPECS.md` and `build/20-TASK-BREAKDOWN.md`, not yet built. The
tokens above are what it will be built on.
