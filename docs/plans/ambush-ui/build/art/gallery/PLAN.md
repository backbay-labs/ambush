# PERCH — DIRECTION "GALLERY"

**The live control room.** Rack metal, black-glass under-monitor displays, and one lamp.

Board: `board.html` — self-contained, no network requests, dark by default
(`<html data-theme="dark">`), light mode live on the toggle.

---

## 0. What changed in this pass, and why

The review found one thing that was true and one thing that was wrong, and the
true one was more useful.

**True:** all three of my chromatic values sat just outside the fence rather
than somewhere the fence was not. The critique's prescription — *sample the
world instead of the fence; if the number lands at 15 dE instead of 9, that is
the evidence the derivation was real* — is exactly the right test, so I ran it.

**Wrong:** the prescription assumes the fence is drawable around the object. For
this object it is not, and the arithmetic says so plainly.

I derived the PVW lamp physically, three ways, and measured each result:

| Physical object | Result | dE2000 to nearest banned |
|---|---|---|
| Lit amber signal lens, SAE dominant λ 590 nm, tungsten source, L\* 64.6 | `#EC8101` | **4.24** from `#d97706` |
| Bare tungsten filament, 2000 K, L\* 59.9 | `#DB7611` | **1.30** |
| Bare tungsten filament, 2850 K, L\* 63.2 | `#CA8C4E` | **8.51** |

Every warm lamp colour at a luminance high enough to read as *lit* falls between
1.3 and 9.8 dE2000 of `#d97706`. My old `#C98A24` was not near the fence because
I walked away from the banned hex and stopped when the number cleared. It was
near the fence because **Tailwind's amber ramp is the tungsten locus.** There is
nothing to sample there that is not already occupied. Nudging it further only
makes it a worse lamp.

So the fix was not another hex. It was to ask what a lit lamp actually *is* on a
screen at 3am — and the answer changed the direction:

> **A lit lamp in a dark room is not a hue. It is white-hot.**
> Photograph a driven tally lamp at exposure for the gallery and the lens core
> clips to white. Luminance, not hue, is what says *lit* — and luminance is the
> one channel that survives colour blindness, a bad monitor and a greyscale
> print absolutely.

PVW became a **luminance** (`#FFEEE3`, C\*ab 8.4). The undo-path ink — the
third value, the one I could not name a material for — was **cut**, not moved;
a value chosen by subtraction from a banned list has no job, and the undo path
was already carrying a rule, a verdict badge and a word. That leaves the system
with exactly **one chromatic value**: the red PGM lens. And that produced the
law the whole direction now turns on (§5).

---

## 1. The world, and why it is true to Perch

A broadcast gallery solves Perch's hardest problem and solved it a century ago:
**many simultaneous states, one operator, a hard hierarchy, and an unambiguous
signal for what is happening right now.** Being wrong in a gallery is immediate
and public — the same stake as isolating a production host at 3am.

It also owns the exact distinction the two-stroke grant turns on. A source on
**preview** is lined up and waiting for the director's take. A source on
**program** is going out to everyone, now. Two lamps, never both lit, and the
only thing the take bar does is move the light from one to the other.

Perch's own vocabulary already lives here. *Take the watch. End watch. The
watchfloor.* That is a shift on a desk in front of a wall of monitors. The queue
is a monitor wall. A hold is a source, cued. A containment lease is a source on
air with a clock running. The five fixed verdict fields are five numbered
channels that are always present, because a monitor wall with a dark monitor
still has that monitor.

**What I refused to take from the world:** the busy-ness. Control rooms
*photograph* as chaos. The discipline here is the opposite — hard hierarchy,
nearly silent surface. A room where the lamp is always lit is a room where
nobody looks at the lamp.

**What I took from the world this pass, having under-drawn it last pass.** The
review was right that stripping the two lamps left a competent warm-graphite
dashboard. The world is now in the material, not only in the lamps:

- **Lamp assemblies.** A black-anodised housing bolted to the panel, carrying
  two lenses over two *engraved* legends. The legend never changes; only the
  lamp does. Recessed unlit lenses, hot cores when lit.
- **UMD strips.** Every bay is headed by a real under-monitor display: black
  glass in *both* themes, hard cell dividers, tracked lettering — and its right
  cell names the source of what is under it. In Perch that source is a fixture
  or wire path (§8).
- **Rack frames with ears.** Every screen is a unit bolted into a rack, with
  mounting holes down both rails.
- **Blanking panels.** Where a column genuinely runs out of things to say, it
  gets stacked 1U blanks with screw marks — which is what a real rack does with
  empty units. It does not leave a hole. This is the mechanism, not a promise,
  behind *a column either carries content for its full height or it does not
  exist.*
- **Machined lips and recesses** on every panel face, trough and meter, so the
  hairlines read as edges of metal rather than as CSS borders.

---

## 2. The palette

**One chromatic value. One luminance. One paint under two lights.**
Every token below prints its own C\*ab and its own dE2000 to the nearest banned
value in the board's footer, computed live from the tokens.

### The equipment — theme-invariant, because a lamp is a lamp

| Token | Hex | C\*ab | dE00 | What it means — one sentence |
|---|---|---|---|---|
| `--lens-pgm` | `#A50002` | **74.8** | **12.92** | **The one colour.** A 2900 K tungsten filament through a 620 nm signal-red lens — it means an irreversible action is running in production right now. |
| `--lens-hot` | `#FFEEE3` | 8.4 | 11.95 | The same filament with no lens in front of it, clipped: it means something is cued and waiting on your take. |
| `--lens-off` | `#242221` | 1.2 | 11.25 | An unlit lens — grey plastic sitting in a dark recess. |
| `--housing` | `#13100E` | 1.6 | 12.35 | Black-anodised lamp bezel; it does not change with the theme, because a bezel is bolted to the panel whatever colour the panel is painted. |
| `--umd` | `#191919` | 0.0 | 11.18 | Under-monitor display glass — black in a dark room and black in a lit one. |

`--lens-pgm` derivation, in full: Planckian 2900 K white point xy(0.4438, 0.4055)
mixed toward the 620 nm spectral locus at purity 0.785, luminance Y 0.0800 →
xy(0.6382, 0.3292) → `#A50002`, L\* 34.0. The luminance is not arbitrary either:
a red signal lens passes roughly a quarter of the luminous flux an amber one
does from the same tungsten source, which is why a real PGM lamp is visibly
*heavier* than a preview lamp at the same drive — a physical fact that happens
to give exactly the hierarchy this product needs.

### The room — one paint, two lights

Black-anodised rack metal at hue_ab **62°**. In the dark the only light is a
dimmed tungsten, so the paint reads warm at C\*ab **5.5**. With the work lights
up the illuminant is neutral, so the same paint reads cooler at C\*ab **3.4**.
The monitor wells are **achromatic**, because a grade-1 monitor is calibrated.

| Token | Dark | Light | What it means |
|---|---|---|---|
| `--room` | `#1D150F` | `#C1BAB6` | The field the equipment stands in. |
| `--rack` | `#241D18` | `#CCC5C1` | Console and screen bodies. |
| `--panel` | `#2C241F` | `#D7D0CC` | A raised rack-panel face. |
| `--glass` | `#141414` | `#E8E8E8` | The monitor well, where content is read. |
| `--edge` / `--edge-lit` | `#372F29` / `#49403B` | `#A69F9B` / `#86807C` | Machined hairline and lit lip. |
| `--ink` / `--ink-mid` / `--ink-dim` | `#E8DAD1` / `#B7ACA4` / `#998F88` | `#25211D` / `#403A37` / `#504A47` | Three legible inks; the floor clears 4.5:1 on every surface it lands on, in both themes. |

**Light mode is a second considered artefact, not an inversion.** With the work
lights up, the room becomes the bright thing and the instruments become the dark
things: the lamp housings and the UMD glass stay black, so a lit console reads
as *equipment in a lit room*. It also loses range — the ink ramp compresses,
which is true of a real room and is stated rather than hidden.

### The floor, and where I stop applying it

**Every chromatic token (C\*ab > 10) clears 10 dE2000 against all 36 banned
values. There is one, and it clears by 12.92.**

I do **not** apply that floor to low-chroma neutrals, and I want the reason on
the record so the objection cannot recur. At L\* 84–92 every near-white in
existence is within 10 dE2000 of `#e2e8f0`, because `#e2e8f0` is itself a
near-white; the only way to "clear" it is to add chroma the room does not have,
which is precisely the failure this exercise is about. My light `--panel` sits
at 7.52 from `#e2e8f0` and I am leaving it there rather than making a control
console pink to satisfy a number.

The evidence that the warm hue was not aimed at anything: **the dark ramp, where
there genuinely is room to stand, clears 14.55–15.88 without anyone trying**, and
the light `--room` clears the banned list by 11.42 and the banned *cream* by
12.91. Nobody searched for those. They fell out of one hue angle and one
illuminant.

---

## 3. Type — engraved, said, shown

| Role | Family | Fallback |
|---|---|---|
| **Engraved** — panel legends, UMD strips, lamp legends, keycaps, headings | **Archivo Narrow** | `"Arial Narrow", "Helvetica Neue", Arial, sans-serif` |
| **Said** — prose the room says to you | **Archivo** | `"Helvetica Neue", Helvetica, Arial, system-ui, sans-serif` |
| **Shown** — every value the machine emitted | **IBM Plex Mono** | `ui-monospace, "SF Mono", Menlo, Consolas, monospace` |

All three are Google Fonts / Fontsource families, self-hostable, offline,
CSP-safe. The board loads nothing and is designed so the fallback rendering is
the one that has to look right.

**Why these, and what changed.** The reflex pairing is Inter plus a neutral
mono, which says "software" and nothing else. Archivo was drawn for signage —
high-performance lettering meant to be read fast and from a distance, which is
what a panel legend is; its condensed cut is the DIN-adjacent engraved-plate
voice a control room speaks in.

The review's real complaint was not the family. It was that a superfamily at two
widths does not *by itself* read as signage — and that was fair, because I had
argued the split as "human layer vs machine layer", which is a software
distinction, not a room one. The law is now the room's own:

> **Anything engraved is permanent and cannot be wrong. Anything displayed
> arrived from somewhere and can be.**

`BLAST RADIUS` is cut into the metal above the slot. `network.egress` came over
the wire into it. `PVW` is engraved on the housing; whether the lamp is lit is
displayed. That is a *safety* distinction, not a stylistic one — and it now has
a treatment: engraved text carries a real emboss (a dark lip above, a lit lip
below), so it reads as cut rather than printed, at every size.

Type is rem-only, derived from a single `--rem`. There is no px and no
arbitrary-rem text size in the file; the board's own audit confirms it.

---

## 4. Layout concept — the rack

Every block on every screen is a **bay**: a rack panel with a machined lip, an
UMD strip on top, and content in the well beneath. Same anatomy at three scales.
There is no second system.

**Screen A — the verdict pane** is a gallery in physical section: monitors
above, desk below.

- The **tally** across the top: the lamp assembly, the action, the severity, and
  the shot clock on its own recessed plate.
- Five **numbered slots** — 01 ACTION, 02 BLAST RADIUS, 03 IF YOU UNDO, 04 WHY
  WE ARE ASKING, 05 WHAT GRANTING OPENS — in fixed order, always five. The
  numbering is what makes the fixed order visible, so the ordinals are set in
  the machine face at `0.6875rem` in `--ink-dim` on the UMD glass at **5.21:1**
  (they were at 1.89:1 last pass; that was a real defect and it is fixed).
  A slot that cannot be filled renders a hatched NO SIGNAL plate under its own
  number rather than vanishing.
- A right-hand **instrument rail**: the threat lane, provenance, the relay
  envelope, who answered, the ladder — and a **blanking panel** where it runs
  out, so the column is full to the floor by construction.
- **The desk** at the bottom: refuse, promote, snooze, the three legs of the
  write path, and the take bar.

**Screen B — the Watch** is the monitor wall: sidebar, the four-category inbox
as one dense rack, and a preview column — program and preview side by side,
which is the room's own arrangement.

**Specification is not interface.** Every explanatory paragraph that described
something the reader can already see has been moved out of the card and into the
plate's margin — including the whole "what the take bar does" paragraph and the
FRICTION IS ASYMMETRIC table, which is gone. Once the grant is a two-stroke
object and refuse is one stroke, the table restates in prose what the controls
say in form. On a 3am bench every sentence between the operator and the blast
radius is a cost.

---

## 5. THE SIGNATURE — the two-lamp tally, and the law it produces

**A hold carries a lamp assembly: a black-anodised housing with two lenses over
two engraved legends. PVW burns white-hot the whole time the hold is waiting on
you. PGM is dark. The only thing the take bar does is move the light from one
lamp to the other.**

The identity appears at three scales — full size on the verdict tally, small in
the queue gutter on every action row, and in the preview column — and it is
drawn in situ in all three of its states in plate A′: not armed, armed and
gated, live. It is the safety argument made physical: you cannot confuse *armed*
with *running*, because armed and running are two different lamps in two fixed
positions with two different words engraved under them, and they are never both
lit.

Because PVW is a luminance and PGM is the only lens in the room, the signature
produces the direction's law:

> **There is exactly one colour in Perch, and it is a lens over a lamp. If you
> can see any colour on the screen, an irreversible action is running in
> production right now.**

The board audits its own law at load and prints the count in the footer:
**0 lit PGM lenses inside the 2 product screens.** Screens A and B contain no
colour at all — not as a stylistic decision, but because nothing is running at
09:16:05.

**And it survives colour removal by construction, which plate C proves rather
than asserts.** A lit PGM lens is identified by its **white-hot core at 14.02:1
against an unlit lens** — not by the red field, which alone manages only 1.96:1.
The core is the encoding; the red is the confirmation. Greyscale the whole
assembly and cued, live and clear are still three different objects.

**The take bar is not part of the signature, on purpose.** In a gallery the
tally lamps are on the monitors and the take bar is a bare machined lever on the
desk. That gives the rule the review was reaching for, taken from the world
rather than from the critique:

> **A control never carries a lamp.**

So the take bar has no lamp, no fill and no colour anywhere in it. Its state is
a **position**: the hatched interlock stands in the throw's path when unarmed,
lifts clear when armed, and the throw sits hard left / mid-travel / hard right.
That is why it can never resolve to a friendly primary button, and why "is this
armed" reads at arm's length in greyscale.

---

## 6. The risk I took

**The product is achromatic until it is dangerous.**

A 3am authorization console for isolating a production host, drawn with no
colour in it at all — the countdown is neutral, CRITICAL is a word and four
meter segments, the undo path is a rule and a verdict badge, and the lamp that
says the decision is still yours is white light, not a hue. The single
chromatic value in the entire system appears only while something irreversible
is running.

Justified in one sentence: **an alarm colour on a decision you have not made yet
is a lie about the state of the world** — and the corollary is worth more than
the restraint, because it makes the presence of colour anywhere on the screen a
one-bit safety signal that costs the reader nothing to learn.

Last pass my stated risk was an absence ("no red"), which is a decision not to do
something. This one is a positive property the product can be held to, and the
board tests it in JavaScript.

---

## 7. What I caught as a default, and revised

**The default I caught this pass: I had been treating "lit" as a hue.** Every
indicator I have ever drawn is a coloured chip, so I drew a coloured chip, and
then spent the palette budget defending which colour it was. That is why all
three values ended up hugging the fence: I was solving for *which amber* when
the question was *what does lit mean*. Replacing hue with luminance killed the
problem at the root, took the system from three chromatic values to one, freed
the whole neutral ramp to be derived from a single illuminant, and produced the
law in §5 — which is a better idea than anything the three-value palette was
going to buy.

**The accessory I removed before shipping.** The sidebar carried four threat-lane
meters. Three of them were reading values off the *wrong clock* — the fixture's
lane table is snapshotted at 09:20:00 and both screens are drawn at 09:16:05 —
and I had kept them because four small meters looked like a system. Cut to the
one lane the fixture can actually give at this instant, at full precision, plus
one honest line: `11 more lanes — none above 2.0`, which is provably true at
either clock.

**Three strings that could not name a fixture path, removed in the same pass:**
`3 open` cases (the fixture has one case channel), `T1059.001` on three finding
rows (no ATT&CK technique appears anywhere in the fixture), and
`reconciled with the daemon 4 s ago` (the interval was invented). If a board is
going to make an argument about traceability it does not get to keep its own
decorative fabrications.

**What I am not claiming as a differentiator.** Hatching for adversary-controlled
strings, an unfilled outline for the destructive control, and severity as a
segmented meter plus the word are moves that all six directions made
independently. They are properties of the brief, not points of view, and last
pass I presented the severity one as a hard-won self-catch. It was not. The
parts of this direction that are actually its own are the two-lamp tally, the
white-hot-not-a-hue derivation, the law it produces, and the engraved/displayed
type split.

---

## 8. Fixture fidelity

**Every string a product surface prints names its source in the right cell of
the UMD strip above it.** That is not decoration — it is the mechanism that
caught the review's most damaging finding. `network_connectivity` and
`remote_management` are hardcoded at `prototypes/verdict-hold.html:1250` and
appear **nowhere in the fixture**; the fixture says
`holds.a.rehearsal.blast_radius.affected_capabilities = ["network.egress",
"network.ingress"]`, and that is what slot 02 prints. A value that cannot name a
path does not belong on the screen.

**One clock, stated.** Both product screens are drawn at
`clock.timestamps.open_row_ms` = 1773738965000 = **09:16:05 UTC**. At that
instant hold A has not been decided (that lands at 09:16:19.8) and no finding
has been dismissed (09:18:44), so the queue resolves to **2 holds, 3 unreviewed
findings, 1 case event, and one category that is absent rather than empty** —
six rows, and the shift counter reads `0 / 3`.

**The lane-strength wobble, resolved by printing both.** The rail shows
`concentration.at_open_row.total_strength = 2.653617` (measured now) and
`holds.a.rationale.concentration_at_hold.total_strength = 2.696884` (at
09:14:42), both at full precision with their paths. They are the same measured
quantity 83 seconds apart under a 3600 s half-life. Neither is rounded and
neither can be mistaken for the other.

**Density: the brief's two instructions conflict, and I am saying so instead of
resolving it silently.** The fixture has four queue rows; "identical fixture
content" and "a dense list" cannot both be honoured. I did not invent rows.
Plate C answers the real question — *does the encoding work across a range* —
with the fixture's **own twelve-lane table**, which spans a 17.6× magnitude
range and contains one explicit absence (`discovery`, hatched, because no
shipped detector emits that threat class — a zero-length bar would be a lie
about coverage). Beside it, a four-step severity strip **labelled as a specimen,
not a screen**, with the `human_gate_severity` policy boundary ruled between
MEDIUM and HIGH. It appears on no product surface in the document.

---

## 9. Functional floor — measured, in the artefact

The board computes all of this live from its own tokens on load and again on
every theme change, so no number in it can drift from the token it describes.

- **Contrast.** Zero failures in dark and zero in light. Worst text pair on the
  whole board: **4.81:1** dark, **4.55:1** light. Slot ordinals 5.21:1; engraved
  legends on the housing 10.52:1; UMD source cells 5.21:1.
- **dE2000.** Chromatic tokens: 1. Worst chromatic distance to any of the 36
  banned values: **12.92**. No banned hex appears as a colour value anywhere in
  the stylesheet.
- **Severity without colour** — the word, a count (`4 of 4`), and four segments
  in a recessed trough. **Confidence without colour** — a two-decimal numeral and
  five segments. **Verification tier without colour** — the tier number, the word
  `UNATTESTED`, and a hatched NO SIGNAL plate. Hatching means one thing
  everywhere: *absent, or forbidden*.
- **Armed state without colour** — lamp position plus throw position, drawn in
  all three states side by side in plate A′ and again in greyscale in plate C.
- **Type** is rem-derived from a single `--rem`; the audit finds no non-token
  font size.
- **Fonts** are named families with real fallback stacks. The file contains no
  `<link>`, no `@import`, no `url()`, and no external reference of any kind.
- **Light mode** is a full palette on `:root[data-theme="light"]` and in a
  guarded `prefers-color-scheme` block. Dark is declared on `<html>`, so the
  board opens dark on every machine regardless of OS preference.
- **The destructive control** carries no fill, no lamp and no chromatic value.
