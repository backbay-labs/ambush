# QUIET — design plan (revision 2)

**Direction:** Quiet
**World:** The darkened bridge and the one lamp on the chart table.
**One line:** The room has no colour because at 3am the eye has none to give it; the lamp has
some, and the lacquer on the thing that can hurt you has all the rest.

**Board:** `build/art/quiet/board.html` · **Fixture:**
`build/fixtures/perch-demo-fixture.json` at `clock.timestamps.open_row_ms` = 2026‑03‑17
09:16:05 UTC

---

## 0. The fatal, answered first

The review's fatal finding was correct and I reproduced it before touching anything.
Revision 1's single hue `#D85248` measures **ΔE₀₀ 3.99 from `#ef4444`** — perceptually
Tailwind red‑500 with the chroma pulled back — and its `alarm-ink` measured 6.41 from
`#f87171`. Revision 1's headline claim, *"minimum ΔE76 from any of the 36 banned values:
8.3 … nothing is within a hair of anything on the list"*, was arithmetically right and
epistemically worthless: ΔE76 is at its most non‑uniform in exactly the saturated‑red region
where the direction's only colour lived. I chose a metric that could not see the problem and
then reported it as proof. That is the rejected pass's failure one level up, and it is mine.

Everything below is measured in **CIEDE2000**, with a floor of 10 applied to every token in
both modes — neutrals included, because "not near the banned palette" and "the banned palette
with different digits" are the same picture.

**Result: the smallest ΔE₀₀ from any of the 36 banned hexes, or the banned cream, across all
20 tokens in the file, is 10.55.** The table is printed on the board (§ IV) rather than
asserted here, and the verification script is reproducible from the hexes alone.

### What re-picking the hue actually taught me

I did not nudge red‑500 until the number cleared. I went to the material, and the material
had a lesson in it. Measured in ΔE₀₀ against the banned list:

| pigment | hex | Lab h | nearest banned | ΔE₀₀ |
|---|---|---|---|---|
| vermilion / cinnabar | `#E34234` | 36.0 | red‑500 | **4.25** |
| RAL 2002 vermilion | `#CB2821` | 36.3 | red‑600 | **3.48** |
| lacquer *shu* | `#D9401F` | 41.8 | red‑600 | **5.58** |
| red lead / minium | `#CB4B24` | 44.4 | red‑600 | **7.57** |
| International orange (aero) | `#C0362C` | 35.3 | red‑600 | **5.03** |
| RAL 2009 traffic orange | `#DE5307` | 50.3 | amber‑700 | **9.07** |
| **RAL 2004 pure orange** | `#E75B12` | 50.5 | amber‑600 | **11.02** |

The whole vermilion family — the pigment the direction had been citing — sits *inside* the
fence. The banned reds occupy Lab h 26–35° and the banned ambers h 56–89°; the only corridor
that clears is **h 44–52**, and the named material that lives there is the machine‑guard
lacquer: RAL 2004 / 2009, the orange painted on the moving part, and on the inside of a guard
so that an open guard is visible from across a workshop. That is a better reference for this
product than a UI red ever was — it is not the colour of an error, it is the colour of *a
thing that can move while you are near it*.

The shipped value is that lacquer **seen under a dim hooded lamp** rather than as a fresh coat
in daylight: chroma pulled from 81 to 72, luminance set so it is a mark and never a light
source.

---

## 1. The world, and why it is true to this product

A ship's watch keeps the bridge dark. Not for atmosphere — to hold the watchkeeper's dark
adaptation, because a lit bridge costs you the horizon. One hooded lamp burns over the chart
table, and everything outside its throw is left dark on purpose.

Two facts follow, and they are the whole design:

**Rod vision is achromatic.** In the dark parts of that room the eye is not seeing muted
colour; it is seeing *no* colour, because rods carry no chromatic signal at all. So the room
in this product is a **true grey — chroma 0.000, measured, not approximately** — on `night`,
`steel`, `rule` and `grad`. Every framework neutral ramp is tinted (slate sits at C 13–14.5
at every step, stone is warm at every step), which means an exact neutral is the one thing
none of them is. It is also the only value in the low‑chroma dark band that clears ΔE₀₀ 10
from slate at all: I swept it, and cold‑tinted greys top out at 8.8–9.8. The geometry and the
physiology agreed, which is when you know the argument is real rather than convenient.

**Inside the lamp's throw, cones work again.** So the record — the thing you are reading —
sits on the one warm surface in the room (`plate`, C 9.2 dark / 16.1 light), and on the Watch
that warm surface **moves to the row you have open**. Lamplight marks attention. The index
marks consequence. Two dimensions, two jobs, and neither is hue alone: the lit surface is also
lighter, so it survives a monochrome monitor.

And the single saturated mark on the whole bridge is the lacquer on the thing that can hurt
you. Because it means one thing, nobody has to be trained what it means, and it is still
legible at hour nine.

**Why this is not banned look #2.** The ban is on a picture: a near‑black ground with one
bright accent. This picture has three surface families in play at full size — a colourless
room, a lamplit plate that carries the majority of the verdict pane, and the ink — and the
mark is a 3px line at the plate's edge that is never a fill, never a button, and never a word.
Revision 1 could not have made that defence honestly; it was dark‑plus‑one‑accent with a
safety argument attached. This revision changed the composition, not the sentence.

---

## 2. Palette — 10 tokens per mode, one of them a colour

Every value below clears **ΔE₀₀ 10** from all 36 banned hexes and from the banned cream, in
its own mode. Contrast is computed against all four of its real surfaces; the full tables are
on the board.

### The one chromatic value

| token | dark | light | what it means — one sentence |
|---|---|---|---|
| `index` | `#E05E28` | `#943106` | **A destructive action is held here, undecided, and this much of its hour is left.** |

That is the entire chromatic budget: one value per mode, the same material at two lighting
conditions. It is never text, never a fill, never a button, and it never appears on anything
decided. Its floor is 3:1 because it is a graphical mark (dark 3.52–4.95, light 3.83–5.69),
and the rule that lets it stay a mark is that it is never asked to be read as a word.

Revision 1 carried a second value, `alarm-ink`, so the hue could be set as type. Cutting it was
the review's own prescription and it restored the direction's own law. The `NO UNDO` badge now
carries its meaning in the **word**, inside a box drawn at **2px against its opposite's 1px** —
weight, not hue — so it survives greyscale on its own.

### The room — achromatic

| token | dark | light | job |
|---|---|---|---|
| `night` | `#171717` | `#BCB5AD` | The room outside the lamp's throw; the darkest surface anywhere. |
| `steel` | `#1F1F1F` | `#C7C0B8` | Instrument chrome: bars, sidebar, rails, unselected queue row. |
| `rule` | `#3E3E3E` | `#9C9893` | A hairline that separates without asserting. |
| `grad` | `#727272` | `#7A7672` | Graduations, ticks, and the *spent* part of the index — a track, never information. |

Dark `night`, `steel`, `rule` and `grad` have chroma **0.0000**.

### The lamp — warm

| token | dark | light | job |
|---|---|---|---|
| `plate` | `#33281E` | `#ECCFB9` | The lamplit surface: the record, and the row you are reading. |
| `plate-hi` | `#3D3025` | `#F4D7C4` | The raised band inside the plate — its head and its controls. |
| `ink-dim` | `#A49B90` | `#51443A` | Engraved labels, provenance detail, graduation numerals. |
| `ink-mid` | `#BAB2A8` | `#3E332A` | Body, key/value, every daemon‑emitted string. |
| `ink` | `#C9C1B7` | `#292019` | The sentence you are asked to judge. |

**Nothing on this screen reaches white.** Dark `ink` is capped at L\* 78.4, because nothing
under a hooded lamp is paper‑white, and because above L\* 80 a warm ink starts closing on the
banned cream (measured: L\* 87 warm is 5.42 away, L\* 78.4 is 11.12). The constraint and the
truth pointed the same way again.

**The light mode is a considered second artefact, not an inversion,** and it is bounded by
arithmetic I can show. Above L\* 72 the low‑chroma light greys are all inside ΔE₀₀ 10 of
`#cbd5e1` / `#e2e8f0` / the cream — that region is fully occupied. So the light room stays a
stone grey at L\* 74/78 and the plate carries the top of the range as a **tinted card stock**
at C 16. I tried buff (h 70–75, the obvious card colour) and it fails at 9.3–9.7. The honest
escape is a warmer, more chromatic stock, and it happens to keep both modes recognisably the
same object (dark plate h 69, light plate h 65).

---

## 3. Type

**IBM Plex Sans** and **IBM Plex Mono** — two cuts of one superfamily, both on Fontsource,
both self‑hostable inside a CSP‑locked offline app with no network request.

**Why these and not my reflex.** My reflex pairing is Inter with JetBrains Mono, which is the
most common combination in generated interface design and therefore not a choice. The argument
here is *kinship*: Perch needs three voices — an engraved panel label, a read sentence, and a
daemon‑emitted value — and in a well‑made instrument those are not three products bolted
together, they are one housing machined three ways. Plex is one of very few superfamilies with
a Mono drawn on its Sans's skeleton, so the mono value and the sentence above it are visibly
the same object. It was drawn for a technology company's machine interfaces, and its numerals
are unambiguous at 11px, which is the job. The third voice is made **without a third family**:
case, tracking, and a right‑aligned label gutter — which is how a Braun legend is actually set.

**Fallback stack:** `"IBM Plex Sans", "Helvetica Neue", Helvetica, Arial, sans-serif` and
`"IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace`. With no network and no Plex
installed the board renders in **Helvetica Neue and SF Mono** — the face of the Swiss
timetable. The fallback is the same argument in a different accent, and it is what the board
was actually designed against.

**Scale.** Rem only, verified: there is not one `font-size` in px or em anywhere in the file.
`0.625 / 0.6875 / 0.75 / 0.875 / 1 / 1.3125 / 2.25 / 5.25rem`. **The 13px step is deleted** —
revision 1 ran 11/12/13/14/16 and the middle three were not distinguishable steps, they were a
smear. Nothing carrying a daemon field is below 0.875rem. Tabular numerals everywhere a figure
can change.

---

## 4. Layout

**A page ruler.** The whole document opens onto a 6rem engraved scale down its left margin.
Every band on the page claims a cell on it — the index specimen at the masthead, a section
numeral below — so the column always carries something. A column either carries content for
its full height or it does not exist; this one earns its width on every band, and the same
rule was applied to all four rails on the two screens (they are measured, and each fills to
its foot).

**A fixed label gutter.** Panel labels are right‑aligned against a 9.5rem gutter; values start
at one left edge that runs unbroken down the whole card. Right‑aligning the keys is the
timetable move and the opposite of the dashboard default: it produces one hard optical edge
instead of two ragged ones, which is what lets the eye drop a column of values at speed. Label
baseline, graduation numeral baseline and lead baseline are aligned to the pixel — measured in
the DOM, not eyeballed.

**Screen A** is one record on the plate plus a 21.5rem margin. **Every explanatory sentence
lives in that margin**, never inside the card: on a 3am bench each sentence between the
operator and the blast radius is a cost. **Screen B** is sidebar 17.5rem · queue · rail
21.75rem, all three carrying content to the foot.

Radii are a uniform 2px — a machined chamfer. Zero radius plus hairlines plus dense columns is
the broadsheet look, and this is not that.

### Encoding without colour

Verified by DOM audit on the rendered page in all three theme states (dark / light / system),
compositing every semi‑transparent layer: **zero text runs below their WCAG floor.**

- **Severity** — four stops filled from the left, *and* the word. Filled stops are `ink-mid`
  (6.08–8.56:1); unfilled are hairline outlines, because the count of filled stops is the
  information and the empty track is not.
- **Confidence** — a two‑decimal numeral first, then five stops **drawn at half the height of
  the severity stops and sitting on the baseline**, so the two meters can never be read as one
  instrument. (Revision 1 drew them identically; on the render they blurred into
  `▮▮▮▮ CRITICAL 0.90 ▮▮▮▮` and I only saw it in a screenshot.)
- **Verification tier** — a numeral in a hairline box and the word: `0 · UNATTESTED`. There is
  no shield, lock or tick anywhere in this direction; a tick would imply a check Ambush does
  not run.
- **Reversibility** — the word, in a box drawn at 2px for `NO UNDO` against 1px for `UNDO`.
- **Adversary‑controlled** — a recessed inset with a hatched left ruling, in mono, achromatic
  on purpose: an amber that appears on every value field is not a warning, it is wallpaper.
  The board uses the settled term **adversary‑controlled** throughout; revision 1 renamed it
  "subject‑written", which was softer and less accurate — the string was written by an
  attacker, not a subject.
- **Absence** — an unfillable field renders its absence *in place*, with the reason, and its
  graduation tick goes hollow. **This applies to queue rows too**: a finding carries no
  severity field, so the row prints `severity — not carried on a finding` in the position where
  severity would be rather than closing the gap. The field order of a row never varies either.

---

## 5. THE SIGNATURE — the index line

A 3px vertical rule at the left edge of anything irreversible and undecided. Four jobs, one
element:

1. **It is the only chromatic mark on the screen.** Four of fifteen queue entries carry one,
   and they are exactly the four that can reach a production host. The scan question is
   answered before a word is read.
2. **It runs out.** The line is `index` from the top for the fraction of the hold's hour that
   remains and `grad` below. *The amount of colour on screen is the time you have left.* At
   09:16:05 the four holds read **97.71 / 97.71 / 63.11 / 13.89 %** — two nearly full, one at
   two‑thirds, and one 7× shorter than the others, visible from across the room with no badge
   and no blink. The numeral is always beside it, so the encoding is redundant, not clever.
3. **It carries the graduations.** On the verdict pane the five fixed slots hang off it as
   engraved ticks numbered 1–5. The mandated field order stops being a rule in a document and
   becomes a scale you can see. Slot 4 contains an absence, so **its tick is hollow** — the gap
   is legible from the scale alone.
4. **It is the grant control.** This is the change the review asked for and it is the best
   thing in the revision. The grant has no fill and no frame: **its left edge is the index
   line at double weight**, and it is drawn as an *open channel* until armed.

### The three states, drawn

Revision 1 rendered only the armed state — on the one screen whose job is certainty about what
you are about to do. The distinction the entire two‑stroke contract turns on was asserted in
prose and never drawn. It is now a three‑up strip beside the control, and the live control
shows **NOT ARMED**, which is the true state on arrival:

| | channel | dwell | reads |
|---|---|---|---|
| **1 · not armed** | hollow, outlined, empty | empty | *G arms. Enter is inert, and says so.* |
| **2 · armed, gated** | filled to 97.71% | 0.9 of 1.5 s | *Enter is still inert.* |
| **3 · will record** | filled, **closed at both ends** | full, with an end‑stop | *Enter records.* |

The difference is **geometry, not tint** — an open tube against a filled one, and a closed
circuit against an open one. The board prints the same strip a second time under
`filter: grayscale(1)`, so the claim is on the page rather than in this sentence. With colour
stripped, the grant is still the heaviest‑drawn object on the pane: a 6px channel against the
Refuse chip's 1px edge.

That asymmetry **is** the friction argument, which is why the "friction is asymmetric, on
purpose" table is gone. Once Refuse is a 1px chip taking one stroke and the grant is a 6px
channel taking two, the table restates in prose what the controls already say in form.

5. **The colour leaves when you decide.** A decided hold's index renders in `grad`. The hue is
   the colour of a decision not yet made about something that cannot be unmade. Nothing in the
   permanent record is ever inked.

---

## 6. The risk

**One hue, and it is an orange on a safety control.** Every operator alive expects red for
danger, and I am spending my entire chromatic budget on the machine‑guard lacquer instead —
because red in this product would have to compete with the reader's memory of every error
state they have ever seen, and this mark does not mean *error*, it means *undecided and
irreversible*. If that fails it fails completely: there is no accent system to fall back on
and no secondary hue to carry a state I did not anticipate. I take that trade, because the
alternative is what the rejected pass produced — 66 values, each locally reasonable, and a red
competing with an amber and a cyan at the exact moment it mattered most.

---

## 7. What I revised — the default I caught in my own plan

**The split‑toned graphite ramp.** Revision 1's ramp was "cold shadows, warm highlights,
crossing over near `rule-strong` — that is what a metal instrument looks like under a single
warm lamp, and no framework ramp does it." That paragraph is a *photographic mannerism*
dressed as an observation. It is a split‑tone, which is a darkroom effect, and it produced a
ramp that was invisible at a glance and a composition that still resolved to dark‑plus‑one‑
accent. Worse, when I measured it, the cold half of the near‑neutral dark band is exactly
where the banned slate ramp lives — cold‑tinted greys in that range top out at ΔE₀₀ 8.8–9.8,
so the mannerism could not even clear the fence.

I replaced it with something that changed the **shape** of the design rather than its hex
digits: **the room has no colour at all, and every bit of warmth is confined to the lamp's
throw.** That is not a style; it is what dark adaptation is — rods are achromatic, so a
watchkeeper on a dark bridge genuinely sees no colour outside the one lit surface. It gives me
a claim that is checkable to four decimal places (C = 0.0000), a figure/ground that is the
brief's own subject (the record is the lit thing; on the Watch the light moves to the row you
are reading), and a composition with three surface families in it instead of two.

Two smaller catches from the same pass: **the metric** (see § 0), and the **type ladder** —
11/12/13/14/16 was five names for three distinguishable sizes, so the 13px step is gone.

## 8. What I cut

- **The "friction is asymmetric, on purpose" table** — the controls now demonstrate it. (§ 5)
- **`alarm-ink`**, the second chromatic value, which existed only so the hue could be set as
  type. Cutting it restored the law it was violating.
- **"The lamp"**, a margin note explaining the two‑temperature composition. It was the only
  element on the board whose job was to praise the board. If the composition reads, the
  paragraph is redundant; if it does not, the paragraph does not save it. The argument lives
  here, in the plan, which is what a plan is for.

---

## 9. Where I hold my position, with evidence

**The queue rows are not invented.** The review recorded that four directions "invented rows"
including `quarantine_file`, `revoke_credential`, `dns_exfiltration`, `credential_dump_lsass`,
`beacon_jitter` and `scheduled_task_persist`. Those are not mine: they are
`prototypes/watch.html`'s own published `canon:false` extension at **lines 1085–1160**, with
their hold ids (`h_d5ee16b4`, `h_81c8137f`), hosts, confidences, techniques, finding ids, case
UUIDs and held‑at offsets given verbatim in that file, which states its reason — *"a queue with
one row is not a queue."* The brief instructs taking the prototypes' structure and their words.
I have kept them unchanged and the board now **labels every row CANON or EXT** and names the
lines, so a reader can check rather than take my word for it. The underlying conflict in the
brief (identical fixture content *and* a dense queue) is real and I have made my resolution
visible rather than silent.

**The clock: I moved, and here is what it cost.** Revision 1 rendered `clock.demo_now_ms`
(09:20:00Z) while five boards rendered `clock.timestamps.open_row_ms` (09:16:05Z). The review
was right that I resolved this silently. I have moved to **09:16:05Z**, and not to match the
field — it is the instant `watch.html` declares as its own now at line 914, quoting the fixture:
*"the operator's queue shows the open hold row"*, which is exactly this screen.

The review suspected my signature needed the later clock. It did not:

| | 09:16:05 (open_row) | 09:20:00 (demo_now) |
|---|---|---|
| `isolate_host` | 58m 37s · **97.71%** | 54m 42s · 91.18% |
| `block_egress` | 58m 37s · **97.71%** | 54m 42s · 91.19% |
| `quarantine_file` | 37m 52s · **63.11%** | 33m 57s · 56.58% |
| `revoke_credential` | 8m 20s · **13.89%** | 4m 25s · 7.36% |

The device reads on the *spread between rows*, and 97.71 against 13.89 is a 7× ratio — if
anything the middle step is more distinct at the earlier clock. It is stated on the board, with
both figures, rather than resolved quietly.

The move also buys something no other board can claim: at 09:16:05 hold A is **still
undecided** — its decision lands at `clock.timestamps.decide_ms`, fourteen seconds later — so
the row selected in the Watch *is* the hold open in the verdict pane. The two screens are the
same moment, and the board says so.

**Two numbers, not one wobbly number.** The review flagged lane strength disagreeing across
boards (2.65 / 2.6536 / 2.70 / 2.696884). They are two different quantities and I print both,
each with its path: `holds.a.rationale.concentration_at_hold.total_strength` = **2.696884**,
recorded on the hold and clock‑independent; `concentration.at_open_row.total_strength` =
**2.653617**, the live lane at 09:16:05. Revision 1's `2.70` was a rounding of the first, which
was defensible but not checkable. A single rounded figure for both is an average of two facts.

**The blast radius.** `network.egress` / `network.ingress`, from
`holds.a.rehearsal.blast_radius.affected_capabilities`. `network_connectivity` /
`remote_management` appear nowhere in the fixture; they are hardcoded at
`prototypes/verdict-hold.html:1805` and five boards inherited them. The board names both the
fixture path and the prototype line, and every string inside a blast‑radius slot can name the
path it came from.

---

## 10. The floor, re-verified on the shipped file

| check | result |
|---|---|
| Banned hexes present | **none** |
| Minimum ΔE₀₀ from the 36 banned values or the cream, all 20 tokens | **10.55** (`#3E3E3E` vs slate‑700) |
| Chromatic values | **1 per mode, 2 in the file** |
| Chroma of dark `night` / `steel` / `rule` / `grad` | **0.0000** |
| Text below its WCAG floor, DOM audit, dark / light / system, alpha composited | **0 runs** |
| `font-size` in px or em | **none** |
| Network requests (`@import`, `<link>`, `src=`, `url()`, remote hosts) | **none** |
| Tokens defined only inside a media query | **none** |
| Horizontal page overflow | **none** |
| Severity / confidence / tier / reversibility legible with colour removed | **yes**, and the grant's three states are printed in greyscale on the board |

---

## 11. Fixture trace

Clock `clock.timestamps.open_row_ms` = `1773738965000` = 2026‑03‑17 09:16:05 UTC; shift start
`clock.shift_start_ms` = 08:00:00 UTC. Hold `holds.a` (`h_a07aeacf`, `isolate_host`,
`host-ops-1`, CRITICAL, held 09:14:42.600, TTL `constants.perch_hold_ttl_ms` 3600000).
Absences drawn from `holds.a.action_request.evidence.decoded_command_segments` (empty),
`.command_line_transforms` (empty), `holds.a.rationale.governance_receipt_present` (false) and
`queue.named_you.absent_reason`. Double‑absence specimen from `holds.b.inverse_resolution`
(`Unmapped`). Keys from `cast.operator` and `cast.bridge`. Constants from `constants.policy`.
CANON rows: `h_a07aeacf`, `h_1c28ae79`, the three `suspicious_*` findings, case
`27799e23-…`, incident `incident:hunt-evt-1:1773738882400`. EXT rows: `watch.html` lines
1085–1160, unchanged.
