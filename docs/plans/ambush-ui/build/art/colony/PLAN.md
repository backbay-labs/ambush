# COLONY — a design direction for Perch

**Board:** `build/art/colony/board.html` — 1440 wide, self-contained, zero network requests
(verified with the network disabled: 0 non-`file:` requests in dark, light and greyscale passes).
**Fixture:** `build/fixtures/perch-demo-fixture.json`, scenario `hellcat-office`.
**Instant:** both plates render `clock.timestamps.open_row_ms` = `1773738965000` =
**2026-03-17 09:16:05 UTC**. One clock, one board.

---

## 1. The world, and why it is true here

**The entomological collection.** Not the insect — the *apparatus*. The cabinet, the drawer, the
unit tray, the pin, the taxonomic key, and the small slip of paper a curator writes, signs, and
ties under the specimen.

Ambush is a colony that coordinates by leaving traces. Taken seriously rather than cutely, that
puts Perch in a naturalist's world, and the mapping is structural rather than decorative:

| Perch | The collection |
|---|---|
| A finding — an observation with a collector, a confidence, a date | A **collected specimen** with its locality label |
| Twelve threat classes, fixed, closed, standard order | A **taxonomy** |
| The pheromone substrate — strength accumulating, decaying | **Patina** — what builds on a surface over time |
| Five fixed hold fields in an order that never varies | The **label stack on a pin**, which never varies by taxon |
| A verdict — typed, signed, permanent, never edited | The **determination slip**: `act.` `det.` `sig.` `date` |
| Change your mind → a *second* record, never an edit | You never remove a determination. **You pin a new one under it.** |
| `human_gate_severity` — the line above which a person must decide | The **red type label**: this one is irreplaceable, there is no second |

The last two rows settled the direction. The product's hardest rule — *if you change your mind,
request the action again; that produces a new hold and a second, separately recorded decision,
rather than editing this one* — is word for word how a museum handles a re-determination. And the
red label in an entomological drawer does not mean "danger"; it means **there is only one of these
and it cannot be replaced**, which is exactly what irreversible means on a production host. The
metaphor was not applied to the product. It was found in it.

**The failure mode of this world is preciousness** — a museum instead of an instrument. The guard
is that every device below has a job at 3am, and every one that did not has been cut.

---

## 2. Answers to the review

Each finding, verified before it was fixed. Numbers are from
`scratchpad/perch-art/colony_verify.py`, which parses the shipped file rather than the plan.

### FATAL — "light mode is banned look #1 shipped intact"

**Confirmed and fixed.** `--pc-raise` was `#F2F0EA`, **0.63 dE2000** from the banned cream. The
whole light ramp was paper. The dark theme had been taken off parchment and onto the drawer; the
light theme had not been re-examined at all. That is the ritual performed, and the critic is right
that it is worse than never having looked.

The light theme is now a second considered artefact, not an inversion. Its material is **the drawer
pulled out onto the bench under a lamp**: museum board and tray liner, warm-olive, low chroma,
capped well below paper. Measured against the cream and against slate-200:

| token | hex | L\* | dE2000 to cream | dE2000 to slate-200 |
|---|---|---|---|---|
| `--pc-raise` | `#D1CDC2` | 82.4 | **8.30** | 11.44 |
| `--pc-card` | `#C9C5B9` | 79.5 | 10.34 | 12.95 |
| `--pc-ground` | `#BFBBAF` | 75.9 | 12.85 | 14.71 |
| `--pc-shell` | `#B5B0A4` | 71.9 | 15.72 | 17.01 |
| `--pc-mat` | `#9D988B` | 62.9 | 22.76 | 23.28 |

No surface in either theme is inside 8 dE2000 of the cream, and the lightest is 12.9 L\* below it.
The masthead is **Archivo 700**, not a display serif — Caslon now appears at text size only, in
italic, for one job (§3). And the terracotta is gone: madder is a dull crimson at hue 14°, used
only as printed label stock. Warm cream ground, high-contrast serif display, terracotta accent —
all three ingredients removed, in the half of the product that shipped them.

### FATAL — "severity does not survive colour removal and its ramp inverts"

**Confirmed and rebuilt.** The old glyph always drew four bars and encoded rank only by which bars
took a hue, so in greyscale MEDIUM (grey 164) outranked CRITICAL (grey 123). That is a wrong-read
path into a wrong grant and it was the correct call to fail it.

Severity now carries **four independent encodings, and the hue is the least of them**:

1. **A rank of engraved ticks filled by count *and* widening with rank** — 1 tick at LOW through
   4 at CRITICAL, at widths 7 / 10 / 13 / 16 px. Filled ticks are `--pc-ink` (grey 219); unfilled
   ticks are hollow 1px outlines. Total ink is strictly monotonic in rank and the silhouette is a
   different shape at every grade.
2. **A graduation protruding at the human-gate line**, between rank 2 and rank 3, so *above the
   gate* is a position on a scale rather than a colour.
3. **A printed label** — coloured stock with near-black print — which exists at or above
   `human_gate_severity` and **does not exist below it**. Presence, not hue, is the encoding.
4. **The word, on every row without exception**, findings included. The old board printed a bare
   glyph on finding rows; that is fixed.

Plate III now carries an *Explanation of the marks* showing all four grades side by side, plus the
confidence and tier ramps and the pin key, so the ramps can be checked against a greyscale print
rather than taken on trust. The greyscale capture is in the review folder.

### MAJOR — "the type-as-provenance claim is not true in the file"

**Confirmed.** Italic Caslon was doing four jobs: the taxon, the masthead, plate captions and slip
labels. An operator cannot read *italic means closed vocabulary* off a page where italic also means
"this is a caption".

Italic Caslon is now reserved for `.taxon` **and nothing else** — the twelve threat classes, and
only those. The masthead is Archivo. Slip field labels are Archivo letterspaced caps. Plate
captions are Archivo with a hanging indent and a rule, which is where their editorial voice now
comes from. The claim in §3 is now checkable with one grep.

### MAJOR — "every board still ships a value inside dE00 10 of a banned hex"

**Confirmed for the old palette** (madder-mark `#C85A4E` was 7.04 from red-500, madder-ink
`#DD8E85` 8.45 from red-400). The instruction was right: re-derive from the material, do not step
away from the framework hex.

So each pigment's **hue and chroma come from the material** and only its lightness was solved for:

- **Yellow ochre**, natural iron-oxide earth — hue 80°, chroma 40.
- **Madder** — a *lake*, and lakes are cool. Genuine madder is a crimson with a blue cast, hue 14°,
  not the orange-leaning 31–35° where every framework red sits. The framework reds are also
  chroma 58–82; a printed card is chroma 40.
- **Verdigris**, basic copper acetate — the blue-green of oxidised copper, hue 186°, chroma 30.
  Framework emerald sits at 161°; framework cyan at 218°.
- **Mauveine**, Perkin's aniline violet, 1856 — hue 320°, chroma 34–38. Period-correct for a
  natural-history plate and for a rubber date-stamp.

Measured in **CIEDE2000**, against the full banned list:

| value | role | dE2000 | nearest banned |
|---|---|---|---|
| `#C26572` madder | stock | **12.14** | red-400 |
| `#53AFA5` verdigris, dark | ink | 13.58 | emerald-500 |
| `#B6904F` ochre | stock | 14.21 | amber-600 |
| `#CEA1D9` mauveine, dark | ink | 14.56 | pink-400 |
| `#5E3066` mauveine, light | ink | 18.50 | slate-700 |
| `#0E4A45` verdigris, light | ink | 19.31 | cyan-700 |

Minimum **12.14**, floor 10, and the same set measures 22.89 in dE76 — the metric agrees with
itself either way, which the previous pass could not say. Zero banned hexes appear anywhere in the
file, including inside comments and citation text: the audit paragraph on the board names
"red-400" and "slate-200" rather than printing their hexes.

*One value is worth naming before someone finds it.* `--pc-ink-bright` `#F5EEE1` is 2.83 dE2000
from the brief's cream. It is a bone **ink on a near-black ground**, it is not on the banned hex
list, and it is never a surface — in light mode `--pc-ink-bright` is `#1E1B17`. The banned look is
a cream *ground*; the nearest ground in this file is 8.30 away.

### MAJOR — "grant and refuse are marked with the same colour"

**Confirmed and fixed exactly as directed.** Madder now marks only the direction that touches
production: it appears on the determination slip's tab and on the CRITICAL type label, nowhere
else. Refuse is a neutral chip whose consequence is stated in words, and it carries **mauveine** —
the operator's own name — because what refusal shares with granting is that a human signed it, and
what it does not share is production. The two controls now differ by exactly one pigment, and that
pigment is the one that names the difference.

### MAJOR — "large voids in the three-column verdict layout"

**Confirmed and restructured.** The old right rail sat at fixed anchors (`margin-top: 19rem`,
`15rem`) and ran empty for hundreds of pixels; the pin's own left margin ran empty for most of its
height. Both are gone:

- The pane is **one measure with an outer margin**. Provenance hangs in that margin beside the line
  it annotates — a numeral, an adversary tag where the slot is adversary-controlled, and the
  `served ·` chip naming the function that produced the slot. Every slot populates it, and a
  continuous hairline runs its full height, so it reads as a margin rather than a hole.
- The clock, tier, action and undo moved into a **header band**; provenance moved into a **foot
  band** of three equal columns that fills.
- The queue column's own footer is pinned to the bottom and a **keyboard legend** now occupies the
  space above it, which the brief asked for anyway.

### MAJOR — "only two directions render the fixture's actual queue"

**Confirmed.** The old board invented `revoke_credential`, `quarantine_file`, `dns_exfiltration`,
`scheduled_task_persist` and two extra cases. All of it is gone.

The tension the critic identified is real, so here is the resolution, stated rather than fudged:
the fixture's `queue` object is defined at `demo_now_ms` (09:20:00), by which time hold A has been
granted and executed — so deliverable A, *a hold on IsolateHost awaiting a human*, does not exist
at that instant. Deliverable A exists only at `open_row_ms` (09:16:05), which is also the instant
whose 58m 37s countdown five of the six boards already render. **Both plates therefore render
`open_row_ms`, and every count is derived from the fixture with the path named:**

| row | count at 09:16:05 | fixture path |
|---|---|---|
| Holds | 2 — `h_a07aeacf`, `h_1c28ae79` | `holds.{a,b}.held_at_ms < open_row < expires_at_ms`; `holds.a.decision.decided_at_ms` = 09:16:19, later |
| Named you | absent | `queue.named_you.present: false` + `absent_reason` |
| Findings to review | 3 | `findings[].emitted_at_ms` all < open_row; the only `reviewed_at_ms` is 09:18:44, later |
| Case activity | 1 | `queue.case_activity.rows` |
| Lanes | 12 | `standard_threat_classes()` order |

Six rows. It is not a long queue, because the fixture's shift is not long. The board says so on
its own face. Density is carried by row anatomy — four lines a row, four severity encodings, the
five-head key riding into every hold row — not by filler.

### MAJOR — "five of six print fabricated blast-radius strings"

**Confirmed, fixed, and worth a note.** The board now prints `network.egress` and `network.ingress`
from `holds.a.rehearsal.blast_radius.affected_capabilities`, and `network.egress` alone for hold B.
The caption names the path. The verification script asserts the fixture strings are present and
that `network_connectivity` / `remote_management` are absent.

For the record, those two strings were not invented from nothing: `prototypes/verdict-hold.html`
documents them as a deliberate departure, filed as fixture correction **F-P1** — they are the
daemon's own `preview.rs` strings, and the fixture carries paraphrases. That is a real open
question about which artefact is authoritative. It is not a reason for a *design* board to print a
string the comparison fixture does not contain, so the board follows the fixture and the argument
is recorded here, in the margin, where it belongs.

The same audit caught a second fabrication the review did not: the old board printed
"41s median page-to-verdict · 9 measurements this week · 1 of 4 recommendations". The fixture says
`median_page_to_verdict_state: UNMEASURED` with a reason. The strip now prints **UNMEASURED** and
its reason, which is also the direction's own law about absence.

### MINOR — chromatic budget

**Confirmed: 16 chromatic hexes was twice any rival.** The fix is a design idea rather than
accounting. In a collection, colour arrives as one of two things: **a printed label** or **ink**.
A piece of red card does not change when you move it into daylight; ink on paper does, because the
paper does. So:

- **Ochre and madder are stock** — one value each, both themes, always a filled block with
  near-black print on it and a cut edge.
- **Verdigris and mauveine are ink** — two values each, one per theme.

**Six declared chromatic values in the file.** Four pigments, four jobs, and the discipline is
visible in the CSS rather than asserted in prose.

### MINOR — sub-threshold text

**Confirmed.** `--pc-rule-strong` was being used as text for the slot numerals (1.81:1) and for the
disabled Snooze chip, in the same file whose own comment said that token is never text. Both fixed:
numerals are `--pc-ink` (10.78:1 on the card), and the disabled control is `--pc-ink-muted`
(6.11:1) with a dashed frame and a struck keycap. The verification script now walks every text
token against every surface it appears on, in both themes: **0 failures**, minimum 4.64:1.

### MINOR — the friction table, and the explanatory paragraphs

Cut. Both instances. Once the grant is a two-stroke object and refuse is one stroke, the table
restates in prose what the controls say in form. Long paragraphs were pulled out of the card and
either deleted or moved into the plate captions and this document.

### MINOR — only one grant state drawn

**Plate III** now draws three at the same size: *not armed* (four dashes, hollow state dot,
`G` named in the corner), *armed and gate-holding* (four values written, filled dot, `Enter`
named, the condition holding the gate stated), and *armed and ready* (gate satisfied). The
difference is what is written on the slip, not a tint — legible at arm's length and in greyscale.

### MINOR — lane strength disagreement, and the convergent moves

Lane strengths are now stated with their derivation on the board itself:
`execution` = `concentration.at_open_row.total_strength` = **2.653617**; the eleven background
lanes are `lanes[].total_strength` carried back 235 s on the fixture's own 3600 s half-life, a
factor of exactly 2^(235/3600) = 1.046286. The escalation paragraph prints **2.696884** and says
that it is the value *when the hold opened*, and 2.653617 *now* — two instants, both named.

On the convergent moves: the hatched adversary rail, the unfilled destructive control and the
segmented severity meter are properties of the brief, not inventions of this direction, and this
plan does not claim them.

---

## 3. The palette — four pigments, six values, and a neutral ramp

The law: **colour is a printed label or it is ink. It is never a border, a rail, a glow, or a fill
behind text of its own colour.**

| Pigment | Value(s) | Form | What it means, in one sentence |
|---|---|---|---|
| **Ochre** | `#B6904F` | stock, both themes | **The human gate** — the severity that requires a person, and the two request-carried fields that trip it. |
| **Madder** | `#C26572` | stock, both themes | **Irreversible** — the type-label red, which in a collection means *there is no second one of these*. |
| **Verdigris** | `#53AFA5` / `#0E4A45` | ink, dark / light | **The substrate** — accumulated, decaying evidence: strength, thresholds, an executable inverse. |
| **Mauveine** | `#CEA1D9` / `#5E3066` | ink, dark / light | **The human hand** — what a person determined, signed, or is being asked to sign. |

Plus `--pc-stock-ink` `#17130E`, a neutral: what is printed *on* stock, and the label's cut edge.

**Neutral ramp — the cabinet.** Warm, hue ≈ 65°, no blue cast, nothing glowing: stained oak, felt
and low lamplight, which is the specific dark this world has and is not a black-green ground with a
bright accent. Dark `#171412 · #1E1A17 · #241F1B · #2C2622 · #362F29`, rules `#423A33 / #574D44`,
inks `#E3DACC / #B0A496 / #F5EEE1`. Light, capped at L\* 82.5: `#9D988B · #B5B0A4 · #BFBBAF ·
#C9C5B9 · #D1CDC2`, rules `#A29E90 / #858173`, inks `#2E2923 / #484139 / #1E1B17`.

Every colour is defined on bare `:root`; light is a full redefinition under `[data-theme="light"]`
plus a guarded `prefers-color-scheme` block. **No colour exists only inside a media query** —
verified.

**What gets no pigment, deliberately:** absence (a hollow pin head and a broken rule), adversary
authorship (a hatched rail), selection (an elevation and a bright shaft), verification tier (a
bracketed numeral, a word and a frame whose stroke tells you the rest), confidence (an achromatic
stipple beside its two-decimal numeral), and the dwell gate. A measurement and a claim cannot share
an encoding, so confidence takes no pigment while severity takes stock.

---

## 4. Type — three hands, and each names a level of trust

| Token | Family | Fallback stack | Job |
|---|---|---|---|
| `--f-taxon` | **Libre Caslon Text** | `"Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif` | the **taxon**, italic — and nothing else |
| `--f-key` | **Archivo** | `"Helvetica Neue", Helvetica, "Segoe UI", system-ui, sans-serif` | Perch's own prose and every label |
| `--f-rec` | **IBM Plex Mono** | `"SFMono-Regular", "SF Mono", Menlo, Consolas, monospace` | machine-written literals |

All three are self-hostable via Fontsource or Google Fonts. The board ships no `@font-face` and
makes no request, so **the fallback stack is what renders**, and each was chosen so that the
fallback is good: Palatino and Georgia are genuinely fine old-style italics that ship on every
machine, so a CSP-locked offline Perch degrades to something still handsome rather than to Times.

**Why these and not the ones I reach for on any project.** Not Inter, because the workhorse here is
setting letterspaced small caps in tray labels at 11px and Archivo is drawn for exactly that; it
also has the weight range to give the masthead authority without a display serif. Not a Playfair or
a didone, because that is banned look #1 arriving through the front door — Caslon is here on a
historical argument (Linnaean-era natural history was set in it) and it is used at text size, in
italic, for one job.

**The real argument: type carries provenance, and provenance is a safety control.** Three registers,
learnable in ten seconds and now actually true of the file:

1. *Italic serif* → a term from **Perch's own closed vocabulary**, the twelve threat classes.
   Taxonomy is set in italic. It is set in italic here, and nothing else is.
2. **Sans** → **Perch's own prose**, written by us, to you.
3. `Mono` → a **machine-written literal**: ids, keys, timestamps, field names, enum values.
4. `Mono` + a hatched rail → a literal **the adversary wrote**.

On the ACTION line, all four registers appear at once: `isolate_host` is mono, `host-ops-1` is mono
under a hatch, the sentence around them is sans, and `execution` in the header is italic Caslon. No
legend is needed after the first read.

**Scale is rem-only, six genuinely distinct steps.** `--ts-display 2 / --ts-title 1.5 /
--ts-lead 1.125 / --ts-body 0.9375 / --ts-meta 0.8125 / --ts-label 0.6875`. There is not one `px`
font-size in the file; the only non-token values are `.94em` and `1.05em`, both relative. Everything
an operator decides on is `--ts-body` (15px) or larger; `--ts-label` (11px) is tracking labels and
chips, and nothing smaller exists.

---

## 5. Layout — the drawer and the plate

**Screen B, The Watch, is the drawer.** Left is the **index**, a taxonomic key: all twelve threat
classes, complete, in `standard_threat_classes()` order, each with a strength bar whose graduation
is the alert threshold of 2.0. A taxonomy has a constant length, so the operator learns its shape
and a lane can be quiet and still be counted — `discovery` reads an em dash rather than `0.00`,
because no shipped detector emits it and unobserved is not the same as quiet. Centre is the drawer:
four **unit trays**, each with a stamped label, a rule that runs the gap, and a count; *Named you*
is empty and says `absent` with its reason. Right is the selected specimen — deliberately the
*other* hold, `block_egress`, because its key carries the hollow third head and this is what an
absence looks like once opened.

**Screen A, the Verdict Pane, is the plate.** A single figure at one measure, with **marginalia in
the outer margin**, each note set beside the part of the figure it annotates — which is what a
margin is for and why the column is populated for the figure's full height. Card facts (id, action,
severity, tier, undo, countdown) sit in a header band; what the card can and cannot prove about
itself sits in a foot band; the controls run beneath.

**Selection is a pin, not a fill.** A selected row lifts to the raised surface, takes a bright shaft
at its edge, and shows its keys. No highlight colour is spent on it.

---

## 6. THE SIGNATURE — the pin, and the determination slip

One shaft. Five heads. Five labels in an order that never varies by action type — the way the
labels on a pinned specimen never vary by taxon: **ACTION, BLAST RADIUS, IF YOU UNDO, WHY WE ARE
ASKING, WHAT GRANTING OPENS**, numbered I–V in the plate-figure convention, the shaft tapering to a
point below the last.

Three things make it a mechanism rather than an ornament.

**A filled head is a slot this hold can fill; a hollow head is an absence** — printed, never
collapsed, in the plate-book convention where a broken outline means *not observed*.
`block_egress` has a hollow III: no containment lease, so nothing plans a rollback, *and* no
inverse is mapped, so nothing could run one. Both halves render, because either alone misleads in
the opposite direction.

**The five heads become a five-dot key that rides in every queue row.** *This action has no mapped
undo* is legible before the row is opened. That is the single most useful thing the metaphor bought
and it is in no prior drawing of this product.

**Slot II is the one block mounted** — raised onto `--pc-raise` with a visible edge, its pinhead
enlarged and ringed. It is the specimen under the lens, and the scale bar beneath it is the dwell
gate, which fills only while the block is fully visible and the window is in front, with a readout
that names the condition holding it.

**And the grant control is a determination slip being written.** Not a button: a slip with ruled
lines and four field labels — `act.` `det.` `sig.` `date` — a madder tab reading IRREVERSIBLE, and
the operator's name and Ed25519 key set in mauveine, the hand's own colour and the only cool thing
on a warm screen. **Unarmed the slip is blank**: a dash on every line, a hollow state dot, and the
line *"Not armed. Press G to arm — the slip stays blank until it is."* **Arming writes it.** The
second stroke pins it, and it is never unpinned; a change of mind pins a new slip below.

Refuse is deliberately not a slip: one neutral chip, one key, no dialog, no undo, and no madder,
because refusing touches nothing in production. It carries mauveine, because a person signed it.
The asymmetry is a fact about the shape of two objects, not a table explaining that it is.

**In one sentence:** *the pin is the fixed field order made physical, and the determination slip is
a signature you write rather than a button you click.*

---

## 7. The risk

**There is not one coloured line, border, rail, glow or gradient anywhere in the system. All alarm
is carried by a small printed label and by a count.** In a 3am security console that is close to
heresy: the reflex is a red left rail down every critical row.

The sentence that justifies it: **in a collection the red label is not paint on the drawer, it is a
piece of stock tied to the pin — so making Perch work the same way means the only saturated colour
on screen is physically attached to the exact object it describes, and nothing else can borrow the
alarm.** A row does not become critical because a rail near it is red; it is critical because a
label says so, in ink, on card, at a fixed position. It also has a second effect I did not expect
until I drew it: with no coloured rails competing, the determination slip's madder tab is the only
production-touching mark on the entire verdict pane, and the eye goes to it.

The supporting risk, kept from the first pass and now earned: **the twelve threat classes are set
in italic Caslon inside a 3am operator console.** It is justifiable because the threat classes are
a closed vocabulary the system owns, and setting them in the italic that taxonomy is always set in
tells an operator without reading which strings are ours and which came from the attacker's process
tree. That claim is now true of the file — italic appears nowhere else.

---

## 8. What I removed before shipping

- The **severity glyph in the card header**, beside `isolate_host` in both panes. The chip, the
  word and the tier already sat on that line; the rank keeps its one fixed position, the left edge
  of a row, where the eye learns to find it.
- Six **editorial margin chips** ("typed ResponseAction", "the block under the lens", "3 of 12
  actions reach this state", "two objects, two clocks", "daemon reason, verbatim"). The margin
  carries provenance — who wrote this and which function served it — and nothing else.
- Both copies of the **FRICTION IS ASYMMETRIC** table, and the paragraphs restating what the
  controls already demonstrate.
- The vertical `COLONY` wordmark on the rail, cut in the first pass and still cut: the prettiest
  thing on the board that did no work.

## 9. What the board leaves out on purpose

- Not one literal insect. The metaphor is in the system — the pin, the key, the trays, the labels,
  the taxonomy — and never in a mascot.
- No gradient used as an accent. No glow, no glass, no neon. Every surface is flat and every edge
  is a rule.
- No pigment on selection, absence, adversary authorship, tier or confidence. Colour is reserved
  for the four things that must be right at 3am, and each of them is a printed label or a signature.
