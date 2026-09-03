# Perch — direction **Substrate**

**One line.** Colour is a measurement: one permanganate ladder, meaning position on the decay
axis, drawn dark-on-light on a bone plate — and a plate is where a thing becomes true, so the
control that isolates a production host is a plate too.

Files: `board.html` (this folder). Plate I is the verdict pane drawn once, whole, at its real
scroll length (4 391 px of card). Plate I·ii is the grant in all three of its states. Plate II
is the shift. Plate III is the light theme. Self-contained, no network — verified offline with
zero non-`file:` requests.

---

## 0. What the review changed

Everything below is the direction as it now stands. This section exists so the changes are
findable rather than buried.

| Finding | What I did |
|---|---|
| **FATAL** — the signature's type was 25 SVG `font-size="9"` presentation attributes, i.e. px | Every SVG label is now set in CSS in rem. Three sizes only: `.6875rem`, `.8125rem`, `1.5rem`. Proof: at root 16 px they measure 11 / 13 / 24 px; at root 20 px they measure **13.75 / 16.25 / 30 px**. Nothing in the file carries a px or arbitrary-rem font size — `grep 'font-size:[^v]*px\|font-size="'` returns nothing. The 9 px floor is gone; the floor is now the app's own `text-2xs`. |
| **MAJOR** — the plate was `#E2E4E5`, ΔE2000 **3.53** from `#e2e8f0` | The plate is now `#E8E4D0`, glazed-porcelain bone: ΔE2000 **13.17** from the nearest banned value, and 6.12 from the banned-look cream `#F4F1EA`. Same L\* (90.4), decisively warm (b\* +10.2) rather than sitting on the slate axis. Every ramp step re-verified against it. |
| **MAJOR** — recompute in ΔE2000, floor at 10, re-derive from material | Done, and the ramp was replaced rather than nudged — see §2. Closest chromatic value to the banned list is now **15.29**. The whole system's closest value of any kind is **8.03** (light card vs slate-200), against the critic's stated neutral floor of 6. |
| **MAJOR** — bottom of the ladder invisible: D1 1.52:1, D2 2.20:1 on its own plate | The ramp is compressed to L\* 54 → 24. **D1 now clears 3.04:1**, D2 3.98, D3 5.26, D4 6.91, D5 9.03. And every cell — lit or unlit — is outlined at **3.05:1**, so a faint lit cell and an empty cell are different objects by construction. The band below the first octave is now a hatched *trace* cell rather than blank, so a lane holding something faint never reads as a lane holding nothing. |
| **MAJOR** — the destructive control carried no marking and was furniture | It is now **the plate bed**, and it is the direction's second signature. See §5. |
| **MAJOR** / minor — only the armed state was drawn | **Plate I·ii** is a three-up state strip: empty bed / plate seated and hatched over / plate clean and live. The pane itself now renders the **unarmed** state, which nobody drew. |
| **MAJOR** — severity had no pane-scale encoding | A four-segment rail runs the full 4 391 px height of the card at `--ink` on `--void`, **17.9:1**, filled from the top. Same four cells as the header chip, at the scale of the screen. |
| **MAJOR** — the pane was cut into Plate I and Plate I·b | Drawn once, whole, with an internal scroll rail. All annotation moved to a margin column. |
| **MAJOR** — slot ordinals at 1.64:1; disabled keycaps likewise | Ordinals and disabled keycaps are `--ink-3` — **5.41:1** on the card. A full DOM audit reports **zero** text pairs below 4.5:1 anywhere on the board, dark or light. |
| **MAJOR** — light-preference machines painted a white bar | `:root` carries the dark tokens with no media query on it, and `html` is painted explicitly. Verified under `colorScheme: 'light'`: html and body both resolve to `rgb(13,10,7)`. |
| **MAJOR** — `network_connectivity` / `remote_management` are not in the fixture | Corrected to `network.egress` / `network.ingress`. Every slot now prints its fixture path on the card. See §8. |
| **MAJOR** — dead columns | The verdict screen is one column; the marginalia beside it runs 2 → 4 488 px against a 4 541 px screen and is aligned note-by-note to the thing it annotates. The Watch is a real viewport with three filled columns and two scroll rails. |
| minor — the signature inverts out of existence in light mode | The light bench is grounded at **L\* 77–84**, not 95–99. See §6, and an honest statement of what does not survive. |
| minor — the friction table | Cut. Its one load-bearing line is a caption above Refuse. |
| minor — lane strength disagreed across boards | Both fixture values are printed, each with its path: `concentration_at_hold = 2.696884` and `concentration.at_open_row.total_strength = 2.653617`. They are different quantities at different instants and the board says which is which. |
| minor — stop claiming the convergent moves as your own | §7 no longer claims the hatch or the outlined control. It claims the two things that are actually this direction's: dark-on-light chroma on an inset plate, and the plate bed. |

Two further corrections I found myself, in the same spirit: the previous board printed
`+25m 52s` for the alert crossing (measured from `held_at`) beside a countdown measured from
`now`, and it invented a thirteenth threat lane (`execution · bg`) that is not in the fixture.
Both are gone. The crossing is **+24m 28s from now**; the sidebar lists the fixture's twelve.

---

## 1. The world, and why it is true to Perch

**A glazed porcelain spot plate, and the reagent read on it.**

Ambush detects by accumulation. Signed observations are *deposited* into a substrate; each
decays on a **3 600-second half-life**; **concentration** is the sum of what is still live;
below an **evaporation floor of 0.01** a deposit stops counting; at **2.0** with **2 distinct
sources** the posture escalates.

That is a titration. And the instrument for a titration — the one a person reads by eye, at
speed, in bad light, and has read the same way for a century and a half — is a white porcelain
tile with a coloured solution on it, where **depth of colour is concentration**. The reagent
is permanganate: a faint rose when dilute, an intense magenta at working strength, a near-black
violet when concentrated.

So the world hands the identity a rule that is not a metaphor but an audit:

> **If the swarm did not measure it, it is grey.**

Almost nothing else on a Perch screen is a measurement. `severity` and `threat_class` are read
out of the requesting agent's own request — the pane's own copy says so and calls it "its own
problem". `confidence` is a detector's assertion. Urgency is a clock. Danger is a judgement.
Colour appears when, and only when, a number was reduced from signed, decaying, multi-source
evidence. A tired person learns one ramp on their first shift and it never lies to them again.

---

## 2. Palette — 5 chromatic values, 1 plate ramp, 1 bench

### The permanganate ladder (theme-invariant)

Base 2: each step is one doubling of live strength, which on a 3 600 s half-life is also one
hour of age. Evenly spaced in L\* (54 → 24, seven and a half steps apart), so the ladder is a
legible ramp in greyscale as well as in colour.

| Token | Hex | Band | What it means, in one sentence |
|---|---|---|---|
| `--d1` | `#A37488` | 0.125 – 0.25 | A trace has become a reading: live, four doublings under the alert threshold. |
| `--d2` | `#9B597F` | 0.25 – 0.5 | Three doublings under the alert threshold. |
| `--d3` | `#8F3E78` | 0.5 – 1 | Two doublings under — roughly one deposit's worth of live evidence. |
| `--d4` | `#7A2970` | 1 – 2 | One doubling under: the last band before the swarm would escalate. |
| `--d5` | `#601964` | ≥ 2 | At or above the alert threshold — the substrate is arguing, and this is the only band that opened a hold. |

### The plate it is drawn on (theme-invariant, one hue, C\* 3–10)

| Token | Hex | What it means |
|---|---|---|
| `--plate` | `#E8E4D0` | The porcelain tile: the one lit instrument face in the room, and the only surface a colour is ever drawn on. |
| `--plate-ink` | `#373430` | Figures, thresholds and rules on the plate. |
| `--plate-ink-2` | `#65625D` | Secondary annotation and the trace hatch. |
| `--plate-edge` | `#848179` | The plate's rim and every cell outline — 3.05:1, so an unlit cell is still a cell. |

### The bench (nine neutrals, C\* < 2.8, faintly warm)

Dark — the product default and this board's lock:
`--void #0D0A07 · --surface #161411 · --card #1D1B18 · --inset #252220 · --line #2F2D2A ·
--line-2 #44423E · --ink-3 #93908C · --ink-2 #BBB8B4 · --ink #F8F3EC`

Light — the same bench under work light:
`#C1BEBA · #CBC8C4 · #D5D2CE · #CFCCC8 · #ABA8A3 · #8E8B87 · #4E4B47 · #3B3835 · #1F1D1B`

**Six values by the strictest count, of a budget of eight** — five ladder steps plus the plate,
if a reader insists on counting a C\* 10 tinted neutral as chromatic. Twenty-seven distinct
hexes exist in the file and all twenty-seven are named above; there are no strays.

**The dark is specific.** Not a blue-black and — deliberately, given what the client rejected —
not a green-black. It is a matte benchtop, every step faintly warm (b\* +1.4 to +4.0, a\* < 1),
which is what puts it 12–13 ΔE clear of the slate family in the opposite direction from the
one a framework would drift in. The bone plate belongs to that same warm family; the ladder is
the only thing in the room that is not.

---

## 3. Type

**Source Serif 4** (Fontsource, self-hosted) for every sentence a human reads. Fallback
`"Iowan Old Style", Charter, Palatino, "Times New Roman", serif` — the board renders entirely
on that fallback, which is the point of choosing a sturdy low-contrast text serif rather than a
display face.

**IBM Plex Mono** (Fontsource, self-hosted) for every identifier, figure, label, eyebrow and
control. Fallback `ui-monospace, "SF Mono", Menlo, Consolas, monospace`.

**There is no sans-serif anywhere in Perch.** That is the argument, not an omission. This
product is exactly two kinds of text: a **record** — the verdict, the reason, the rationale,
prose a court would recognise — and a **measurement** — hex, decimals, timestamps, event ids,
enum values. A record is set in a text face and a measurement is set in a machine face. Perch
has no marketing voice, no onboarding, no persuasion; there is nothing left for a neutral
grotesque to do, and dropping it removes a whole axis of arbitrary decision.

Why not what I would otherwise reach for: Inter + JetBrains Mono is the reflex pairing for any
dark technical UI and would have made this look like every other dark technical UI. Plex Mono
is an engineering face drawn for instrumentation, with flat terminals and an unmistakable
`0`/`O`; Source Serif is a screen-first text serif whose wedge serifs survive light-on-dark at
15 px, where a Didone would smear.

Six steps, all rem, genuinely distinct: `.6875 / .8125 / .9375 / 1.125 / 1.5 / 2.25`. Body
prose is 15 px, one step up from the previous pass, because this is read at 3am. **The SVG
figures use the same scale** — `.6875rem`, `.8125rem`, `1.5rem`, set in CSS on the `text`
elements, so the plate's labels scale with Cmd +/− along with everything else.

---

## 4. Layout

**Plate I — the verdict pane.** One column, one screen, drawn whole at 4 391 px of card with an
internal scroll rail; the marginalia runs alongside it in the board's own margin, aligned
note-by-note to the plate (2 258 vs 2 270), the absence (2 905 vs 2 906), the provenance block
(3 487 vs 3 489) and the controls (4 070 vs 4 074).

The queue is **not on this screen**, and that is a product decision rather than a drawing
convenience: adjudication takes the whole working surface, because the queue is the thing that
makes you hurry and hurry is the failure mode this pane exists to prevent. `Esc` brings it back.

Field order, fixed, never varying by action type: **ACTION · BLAST RADIUS · IF YOU UNDO · WHY
WE ARE ASKING · WHAT GRANTING OPENS**, numbered `01`–`05` in a mono gutter at 5.41:1, so the
*position* of a fact is itself a fact. A slot that cannot be filled prints `ABSENT` and its
reason in a dashed frame; slot 04 carries one.

**The plate sits inside slot 04, not under the header.** An earlier draft put it directly below
the header because it is the most beautiful object on the page and that is where a designer
puts one. It inverted the safety hierarchy — the cost of an action has to be read before its
justification. The header now carries the *reading* at chip scale; slot 04 carries the
*argument* at full scale, in the slot it is evidence for.

**Plate II — the watch.** A real 1 188 px viewport: sidebar 288 · queue 512 · selection detail
560, all three filled to the frame, two with scroll rails. Four inbox categories, one of which
is absent and says so. Twelve threat lanes, sorted by concentration, each with its own ladder
chip — a descending staircase of stain that keeps the substrate visible when the queue is
quiet, and that reads correctly in greyscale.

Rhythm: hairline `--line` between structural blocks, `--ink-3` for anything a hand can touch.
**Nothing in this system has a border radius** except the five confidence dots, which are
dots. The room is square and the plate is a square tile; the previous pass gave the plate 2 px
of radius and it made it read as a chip in a dashboard rather than a piece of glazed ceramic.

---

## 5. The signature — **a plate is where a thing becomes true**

One instrument, at two sizes and nowhere else: **66 px** as a six-cell chip on a queue row, a
lane and the pane header; **812 units** across the verdict pane. The axis is base 2 from the
evaporation floor `0.01` to `8`, so **one octave is one half-life** and distance along the axis
is elapsed time. `ALERT 2.0` is a cell boundary because the threshold is a power of two; `5.0`
is not, so it is ruled explicitly rather than faked into the ramp. Below the first band the
substrate is live but not yet worth a step, so that region is hatched rather than coloured;
beneath the floor the plate is blank, the one place in this system where absence of mark means
absence of fact.

What earns it the name is what it can say that nothing else on the screen can. Perch's hold TTL
is **3 600 000 ms**. The substrate's half-life is **3 600 s**. *They are the same number.* So
the countdown and the decay are one axis:

> concentration now **2.653617** → back under `ALERT 2.0` in **+24m 28s** → this hold expires
> in **+58m 37s**, at which moment the concentration that opened it — **2.696884** — will read
> exactly **1.348442**

A hold left undecided expires at the exact moment the concentration that opened it has halved,
and will have stood beneath its own alert threshold for the final **34m 08s** of that hour.
That is a true, load-bearing and slightly unnerving fact about the product, and this direction
is the only one whose colour system can state it.

### And the second plate

The review's hardest and most correct finding was that the control which isolates a production
host was drawn at the same weight as the friction table above it. The fix is not more colour —
colour is spoken for. It is to notice that this direction's own rule has a consequence it had
not yet been made to pay:

> **A plate is where a thing becomes true.** Two objects in Perch may be lit — the measurement,
> and the irreversible act. There is never a third.

So the grant is a **plate bed**, and its three states are three physical conditions of an
object rather than three tints:

- **Not armed** — a recess: void ground, an inset shadow, a hazard-hatched floor and the
  plate's own seat line dashed into it. The footprint of the plate that is not there. Nothing
  on the screen is darker. This is how the pane opens.
- **Armed, gate held** — the plate has seated. Bone, lit, a hazard rule hatched along its top
  edge, and hatched over as a whole because the second stroke is interlocked. The condition
  holding the gate is printed on it: *"Armed, and waiting on the blast radius. Read for 1.1 of
  1.5 s."* A frozen gate with no stated reason reads as a broken button, and that is exactly
  how friction gets routed around.
- **Armed, live** — clean bone, with `isolate host-ops-1` set at the size of the action.

The three differ by roughly **85 L\*** over the same 700 square units. That is a change you can
see across a room, in greyscale, on a bad monitor, and it cannot be mistaken for a friendly
primary: a friendly primary is a small tinted pill, and this is a slab of instrument face with
a hazard rule and a host name on it. *Is this armed* is the question the product's entire safety
argument rests on, and it is now answered by the position of an object.

---

## 6. Light mode, and the one thing that does not survive

The nine bench neutrals move and nothing else does. The plate is the same bone, so the ladder
is byte-identical in both themes — the strongest possible answer to *no colour may exist only
inside a media query*, because there is only one set of chromatic hexes in the system and no
second danger hex to get wrong at 3am.

The light bench is grounded at **L\* 77 – 84**, not 95 – 99. A theme that goes to paper white
puts the plate at the same value as the page, and the direction's central picture inverts out
of existence. At this grounding the tile is still the lightest and warmest thing on the bench,
it still has a rim and a specular highlight, and it still reads as an object lying on a surface.

**What does not survive, said plainly:** in the dark, the plate is *the one lit object in an
unlit room*, and that is the whole image. Under work light nothing can be the one lit object.
So in the light theme the plate stops being identified by luminance and is identified by
temperature and edge — the warm glazed thing on a cold matte bench. That is a translation, not
the same picture, and it is worth saying out loud rather than pretending otherwise.

---

## 7. What I caught as a default this pass, and what I replaced it with

**The default: I had treated "the plate is the one lit object" as a picture rather than a
rule.** In the previous pass it bought me exactly one thing — a beautiful figure near the top
of the pane — and cost me two: the measurement sat above the blast radius (safety hierarchy
inverted in service of the drawing), and the control that isolates a production host got
nothing, because colour was spoken for and I had no other currency. A conceit that only ever
pays out in one place is decoration with a rule attached.

**Replaced with a rule that has consequences:** *a plate is where a thing becomes true* — so
the measurement is a plate, the irreversible act is a plate, and there is never a third. That
one move produced the plate bed, produced the three-state strip, moved the figure down to slot
04 where its argument actually lives, and gave the direction a second identifiable object
without spending a single additional hex.

**The second default: I had derived the ramp by nudging.** Madder is a real dye, but I chose
it by hue-family and then walked the values until the ΔE cleared — which is the reflex the
client already rejected once, at higher resolution. The honest test is *can I name the material
and does its actual behaviour match the quantity I am encoding*. Permanganate does: its colour
depth **is** its concentration, over exactly the range this ramp needs, and it deepens toward
violet rather than toward red — which is why the gravest value in this system is `#601964` and
not something that has to be defended against `#dc2626`. Every step landed 15+ ΔE clear without
anyone aiming for it.

**Third: the plate itself was the framework's colour.** `#E2E4E5` is a near-achromatic light
grey chosen because "instrument faces are pale". Porcelain is not pale-grey; it is bone. The
plate is now `#E8E4D0`, and it is 13.17 clear.

**What I am not claiming.** The diagonal hatch for adversary strings and the unfilled outline
for a destructive control are moves all six directions made independently. They are properties
of the brief, not a point of view, and this plan no longer presents them as catches.

**Removed before shipping.** Two things beyond the friction table: the `--plate-line` token
(one hairline value that did nothing `--plate-edge` did not do better at 3:1), and the three
decorative window dots in the app chrome — a skeuomorph that carried no information on a
screen whose whole argument is that everything on it is a fact with a path.

---

## 8. Fidelity to the fixture

Both plates are set at `clock.timestamps.open_row_ms` = **2026-03-17 09:16:05 UTC**, the moment
the operator opens the row and before either decision is recorded. That is the only instant at
which `isolate_host` is genuinely awaiting a human.

**Every slot prints its fixture path on the card.** The one that matters:

```
holds.a.rehearsal.blast_radius.affected_capabilities = ["network.egress", "network.ingress"]
```

The previous pass printed `network_connectivity` / `remote_management` beside a paragraph
arguing that this list must never truncate because it is the real cost of the action. That is
the most damaging thing a board can do — be most eloquent exactly where it is least accurate —
and it is corrected.

For the record, because the objection should not have to recur: those two strings are not a
bug in the prototype. `prototypes/verdict-hold.html:1244-1265` documents a deliberate departure
— `build_rehearsal_preview` (`preview.rs:165-197`) emits them, the fixture carries paraphrases,
and the prototype filed the discrepancy as fixture correction **F-P1**. I render the fixture
anyway, for two reasons: the brief made identical content the basis of comparison across six
boards, and a slot that argues it must never truncate has no business printing a value it
cannot cite. If F-P1 is resolved the other way, this slot changes and the argument does not.

Two derivations, both stated on the board:

- The eleven background lane strengths are the fixture's `lanes` array (observed at
  `demo_now`) carried back 235 s to `open_row` by one multiplication of `2^(235/3600)` =
  1.046286. `execution` is taken from `concentration.at_open_row.total_strength` = **2.653617**
  instead, because the fixture's `lanes` entry for execution is the post-dismissal world at
  `demo_now` and the dismissal has not happened at this instant. I re-derived 2.653617 from
  `deposits[].timestamp` against `open_row_ms` and it agrees to five decimals.
- `0 of 3 reviewed` follows from `findings[1].reviewed_at_ms = 1773739124200`, which is later
  than `open_row_ms`. The fixture's `queue` block is recorded at `demo_now`, where the count is
  1 of 3; the board states its instant.

**The queue is six entries and not one more.** The fixture's `queue` object contains one hold
row, two findings-to-review rows, one case-activity row and an absent *Named you*; at
`open_row` all three findings are unreviewed and both holds are pending, which is what is
drawn. I did not pad it. The brief asks for a dense list and the fixture does not contain one;
where those two instructions conflict I obey the fixture, and put the density in the **anatomy
of a row** — verb, kind, target, id, threat class, sources, severity word and cells, confidence
dots and figure, ladder chip, concentration, escalation level, key legend — and in the twelve
threat lanes, which are twelve real measurements. This is a brief defect rather than a design
choice, and it should be resolved explicitly before the next pass.

---

## 9. The functional floor, measured on the rendered page

Not asserted — read back out of the DOM with a script that walks every element carrying a text
node, resolves its effective background, and computes the ratio.

- **Text pairs below 4.5:1 anywhere on the board, dark or light: 0.**
- **SVG labels below 4.5:1 against the plate: 0.** 52 label nodes, minimum **4.75:1**.
- SVG font sizes: **11 / 13 / 24 px** at root 16 px; **13.75 / 16.25 / 30 px** at root 20 px —
  rem, and it scales.
- Non-text floor: the ladder on its own plate — D1 **3.04**, D2 3.98, D3 5.26, D4 6.91,
  D5 **9.03**; every cell outlined at **3.05**.
- Severity rail: `--ink` on `--void`, **17.9:1**.
- ΔE2000 to the nearest banned value: chromatic minimum **15.29** (D2); plate 13.17;
  whole-system minimum **8.03** (light card vs slate-200). No neutral carries slate's blue
  cast — every bench value is C\* < 2.8 where the slate family runs C\* 4–13.
- No banned hex appears in the file in any case. 27 distinct hexes, all named in §2.
- Zero non-`file:` requests with the network disabled. Both themes are declared in plain rules;
  the media query only chooses between them. `:root` and `html` are painted dark, so a
  light-preference machine cannot render a white band behind a dark board.

**Redundant encoding, everywhere:**
- *Severity* — four cells in the header, four segments down the full height of the card, the
  word, and the note `claimed`.
- *Confidence* — five dots, plus the figure to two decimals.
- *Verification tier* — three named checks, the count `0 of 3`, the number `tier 0`, and the
  sentence "unattested — no ed25519 signature of its own", hatched the way adversary strings
  are. No shield, no lock, no tick.
- *Concentration* — a printed figure, ruled thresholds, outlined cells, and — because the ramp
  is evenly spaced in L\* — a legible ramp in greyscale.
- *Adversary-controlled text* — a hatch. *Agent-written text* — the words `request-carried`.
  Two different problems, two different marks, neither of them a colour.
- *Absence* — a dashed frame and the word, never a collapse and never a zero.

**Shading is not colour.** The only non-token fills in the document are black and white at low
alpha: an inset shadow in the bed, a specular highlight along the top of every plate. No
gradient is used as an accent.

---

## 10. The risk

**The alarm colour is not a warning colour, and the one lit chromatic object is not the
severity.** A permanganate ladder on a bone tile is a titration chart, not a klaxon: no red, no
amber, nothing a security tool is supposed to look like — and the thing it measures is
concentration, which has already done its work by the time a hold exists.

I take it because in a field with no other chroma the *presence* of the stain is already the
alarm, so the hue is free to be chosen for meaning instead of for volume; because a hue chosen
for volume is the one a person stops seeing in their eleventh hour; and because severity is a
claim by the party requesting the action, and a claim cannot be allowed to borrow the encoding
that measurement earned. The hedge the review asked for is structural rather than chromatic:
severity now owns the only full-height object on the pane, and the ladder's own board says in
the margin what it cannot do —

> Concentration is a measurement, and it is the only one on the screen. It does not know
> whether this host matters, whether it is 3am, or whether the last four holds were false. The
> ladder is deliberately not a priority score.

That sentence is the direction's actual exposure, stated on the artefact rather than only in
this document. If the client wants the loudest object on the pane to be an opinion rather than
a fact, this is the wrong direction, and they should be able to see that before they choose.
