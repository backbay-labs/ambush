# Perch — direction **THE RECORD**  ·  revision 2

**Board:** `board.html` — one self-contained file, 1440 wide, three plates.
No `@font-face`, no stylesheet link, no CDN, no image, no `url()`. Loaded in an
offline browser context it issues **zero** non-`file:` requests; the render log is in
§9.

**Instant:** every figure on both screens is `clock.timestamps.open_row_ms` =
`1773738965000` = **2026-03-17 09:16:05 UTC**, the same instant the rest of the set uses.

---

## 0. What the critics found, and what I did

Three findings were fatal or major. All three were **measured, confirmed, and fixed**.
I am not disputing any of them.

| Finding | Verified? | What changed |
|---|---|---|
| **FATAL — the console ramp is Tailwind slate with the digits nudged.** `--ink` #D2D7E0 ΔE2000 **2.23** from `#cbd5e1`; `--ink-2` #98A0AE **3.22** from `#94a3b8`; `--rule-2` #3C434F **3.87** from `#334155`. | **Yes — worse than reported.** I measured my whole ramp at Lab hue 270–274°, C\* 2–8. Slate runs hue 255–283°, C\* 1–14.5. It was the same ramp with the chroma pulled back, and it carried two of the console's three inks. | **The console ramp was deleted and rebuilt as a categorical position rather than a distance** — see §2. |
| **FATAL — armed and unarmed are almost identical.** ΔL 0.0165; the only high-contrast change was a 20px ✕ at 1.90:1. | **Yes.** An 11 %-alpha wash and a 1px rule-weight change. It would have caused one wrong grant. | **Arming now rules the page** — a change in *quantity of ink*, drawn in three states, proven in greyscale on the board itself. See §5. |
| **MAJOR — the seal #E96A5C is ΔE00 5.41 from `#f87171`.** | **Yes.** L\*60 C\*58 h33 — a bright coral sitting where the framework red sits. | Re-derived from the material. `--wax #9E2833` — lac/madder sealing wax, **ΔE00 14.23**. See §2. |
| **MAJOR — five of six boards print fabricated blast-radius strings.** | **Yes, mine did.** Line 796–797 read `network_connectivity` / `remote_management`. | Corrected to the fixture's `network.egress` / `network.ingress`, **and** every slot on the board now prints the fixture path it came from. See §7. |
| **MAJOR — the CRITICAL badge composites to 3.96:1.** | **Yes.** Seal text on a 13 %-alpha seal wash. | The wax is now **a mark, never a word**. It is only ever a fill or a rule, so no chromatic value ever has to fight a contrast floor. Measured: 5.76:1, and there is no wash behind any badge. |
| **MAJOR — only Gallery and Substrate render the fixture's real queue.** | **Yes, mine invented eight rows.** | Every one of the docket's **22 entries is a fixture object with its own timestamp**. Nothing is padded. See §7. |
| **MINOR — the signature is undersized against its own claim.** | **Yes.** ~100–200px of blank against a claim of "the largest element". | Measured now: the signature block is **570px**, of which **400px is blank**; the tallest recital is **518px**. The claim and the drawing agree. See §5. |
| **MINOR — the ✕ is 1.90:1.** | Yes. | `--page-ink2`, **6.44:1** unarmed, and it takes `--indelible` when armed. |
| **MINOR — light mode's palette legend prints the dark hexes.** | Yes. | The legend reads its hex **out of the live custom property** via `getComputedStyle`, re-stamped by a `MutationObserver` on `data-theme`. It cannot disagree with the swatch by construction. |
| **MINOR — lane strength disagrees across boards (2.65 / 2.6536 / 2.70).** | Yes, mine printed 2.65 in one place and 2.696884 in another. | The board now prints **2.696884** — `holds.a.rationale.concentration_at_hold.total_strength` — and nothing else, anywhere. The sidebar's lane index is a **different measurement** (`lanes[]`), labelled and cited as such, with one sentence in the marginalia saying so. Neither figure is rounded. |
| **MINOR — a full-height empty column in the verdict pane.** | Yes: the collapsed queue spine ran 84px wide and empty for ~4 000px. | The spine is gone. Both screens now measure within 11 % on every column: verdict pane is a three-column grid where the marginalia is anchored per recital; the Watch's three columns end 11 / 82 / 24 px from the bottom of a 1 535px body. |
| **MINOR — the convergent moves are not differentiators.** | Fair. | §8 says so plainly, and names what is actually mine. |

---

## 1. The world, and why it is true here

**Adjudication and the permanent record** — the docket, the exhibit, the chain of
custody, the seal, and the ruled line where a name goes.

Perch is not a monitor and not a hacking tool. It is a **bench**. A tired professional
sits a shift, works entries, and renders judgments that are typed, signed, permanent,
verifiable by someone else offline, and fed back into next week's detector tuning. The
product's own settled vocabulary already lives here: *the watch, the ledger, the case, the
verdict, the record, the hold, containment, blast radius.* Those are court words and
bridge words.

So the interface is not a dashboard of cards. It is a **document on a bench**, and the
console is the bench. That one move settles most of what the brief asks:

| What the product needs | What a document already has |
|---|---|
| A fixed field order that never varies by action type | Numbered recitals on a pre-printed form — **I ACTION · II BLAST RADIUS · III IF YOU UNDO · IV WHY WE ARE ASKING · V WHAT GRANTING OPENS** |
| An unfillable slot rendering an explicit absence | A **VOID** — a hatched box carrying the word and the reason. A form with a missing box is a different document from a form with no box |
| Card types that carry no signature | A **blank signature rule**, hatched. Signed and unsigned records differ in shape, not in hue |
| A judgment recorded permanently under your own key | A **signature**, not a submit button |
| Asymmetric friction — refuse cheap, grant expensive | A **stamp** is one motion; a **signature** is two |
| Evidence with provenance | A **chain of custody**, ruled and ordered, ending in an unwritten line |
| A queue of what happened on your watch | A **docket** — one chronological record, numbered, not four inboxes |

The trap this world sets is cream paper + a high-contrast serif + terracotta, which is
banned outright and which I am also forbidden to ground in. So the problem became: **make
evidence read as DOCUMENT inside a dark console.** A document is not defined by being
white. It is defined by margin, by rule, by measure, by where a seal sits and by what a
signature block looks like when it is empty. All of that survives a dark ground. What does
not survive is paper's *whiteness* — so the record keeps paper's **warmth** and loses its
brightness.

---

## 2. Palette

### 2.1 The neutral system is two materials, and the console has no hue at all

This is the fix for the fatal finding, and it is a **category, not a distance**.

> **The console is graphite: R = G = B on every single step, in both themes.
> a\* = b\* = 0. There is no hue in the console anywhere.**

Every value on the banned list carries chroma — the slate ramp runs C\* 1 → 14.5 at Lab
hue 255–283°. An achromatic ramp therefore cannot land on one *however the digits fall*.
The previous pass failed because it chose a colour by stepping away from a forbidden
hex; a value chosen that way has no job and no material. This one is chosen by naming the
material: graphite, lead, steel, ash — the substances of writing and filing are all
genuinely colourless.

It is also better design than what it replaced. The record is now **the only coloured
material in the room**, including in its greys, which is a stronger sentence than "warm
versus cold" and a stronger picture: a document under a lamp on a steel bench. And a
zero-chroma UI is not a thing any reflex produces — every dark technical interface I have
ever seen has a blue-grey ramp. The console reads cool anyway, by simultaneous contrast
with the warm page, without one drop of blue in it.

| | dark | light | job |
|---|---|---|---|
| `--board` | `#070707` | `#949494` | the board itself |
| `--frame` | `#0D0D0D` | `#ACACAC` | app well |
| `--chrome` | `#141414` | `#B0B0B0` | rails, sidebar, marginalia |
| `--raised` | `#1E1E1E` | `#B3B3B3` | raised console surfaces |
| `--rule` / `--rule-2` | `#2B2B2B` / `#404040` | `#8E8E8E` / `#6E6E6E` | hairlines |
| `--ink` / `--ink-2` | `#B2B2B2` / `#949494` | `#131313` / `#3A3A3A` | 8.69:1 and 6.07:1 on chrome dark; 8.57 and 5.24 light |

**The console's ink is deliberately capped below the record's.** `--ink` is L\*72.6;
`--page-ink` is L\*89.7. The console never speaks louder than the document, and that law
survives greyscale — *the record is where the bright type is*.

**The record — warm stock.** Dark: `#241E17` well · `#2D261E` page · `#423A2E` feint rule ·
`#5C5041` structural rule · `#B4A997` secondary ink · `#EEE0CA` ink.
Light: `#D8C7A8` · `#E4D4B8` · `#C7B48F` · `#A08D6A` · `#574B36` · `#241D12`.

Light mode's page is a **buff stock at L\*85.5, not paper and not cream** — deliberately
capped below white, both because #F4F1EA-family cream is banned look #1 and because the
honest light-mode picture is the same picture at a different exposure: a warm document,
still the brightest object, on a mid-grey bench.

### 2.2 Four chromatic values. One job. One sentence.

Down from five: `--high` was cut when severity stopped being a hue (§4).

| Name | dark | light | ΔE2000 to nearest banned | What it means, in one sentence |
|---|---|---|---|---|
| `--wax` | `#9E2833` | `#9E2833` | **14.23** | The seal — the only hue that ever means *this can hurt*: CRITICAL rank, and the destructive direction. |
| `--indelible` | `#BCA5E0` | `#4A2F80` | 14.21 / 12.95 | Copying-pencil violet: the operator's own hand, and nothing the machine writes is ever this colour. |
| `--adversary` | `#D0AC71` | `#6A4E0A` | 12.37 / 20.26 | The manila exhibit tab: a string the attacker wrote, quoted and never executed. |
| `--custody` | `#87BFAA` | `#0E4535` | 12.31 / 22.18 | Verdigris on an old seal: a check that actually ran and agreed. |

**The wax is a mark, never a word.** It is only ever a fill or a rule — never text. That is
both materially true (a seal is an impression, not a sentence) and structurally useful: it
removes the whole class of failure the critics found, because a colour that is never set as
type never has to clear a text contrast floor. Cream on wax measures **5.76:1** and is the
same in both themes, because **wax does not change colour when you turn the lights on**.

`#9E2833` was not derived by stepping away from `#dc2626`. It is lac/madder sealing wax:
L\*36, C\*54, hue 25°. I checked seventeen named historical reds (oxblood, falu, carmine,
burgundy, venetian, pompeian, minium…) — sixteen of them clear ΔE00 10 without anyone
aiming for it. The only one that failed was minium, the *bright* one. That is the test the
systemic critique asked for: name the material, and the distance takes care of itself.

**Absence gets no hue, by law.** An unfillable field is a **hole** — hatched fill, the word
VOID, and the reason — because colouring an absence makes it look like a state rather than
a gap. It appears five times across the two screens.

### 2.3 The measurement, honestly reported

Every hex literal in `board.html` — all 35, both themes, 16 of them achromatic —
computed in **ΔE2000** against all 36 banned values:

```
MINIMUM  10.16   (#2B2B2B vs #1e293b)      MAXIMUM  22.26   (#574B36 vs #334155)
```

One caveat I will state rather than hide: in the L\* 14–24 band an achromatic grey sits at
ΔE00 **10.1–11.0** against `#1e293b` *no matter which value I pick*, because the entire
distance is the chroma term (their C\* 13 against my C\* 0). I did not tune digits to clear
the floor there and there is nothing to tune — that band's floor is structural. Chasing
10.5 would be exactly the theatre the review condemned.

---

## 3. Type

**IBM Plex Mono** (the record) + **Public Sans** (the console). Both self-hostable via
Fontsource. Declared fallbacks are designed, not defaulted, and are what this board
actually renders on with no network:

```
--mono: "IBM Plex Mono", ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
--sans: "Public Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
```

**Why these and not the ones I would reach for on any project.** The reflex is Inter plus
JetBrains Mono. Inter is the house sans of everything ever described as "clean", and
JetBrains Mono is a *coder's* face — precisely the register the client rejected.

- A court record is a **typed** record. Transcripts, docket entries and exhibit stamps are
  typewritten, and Perch has to set hex keys, event ids, UTC timestamps and command lines
  in monospace anyway. So the mono is not a code accent here — **it is the document's own
  voice**, carrying the headline, the countdown, the recital numerals, the field labels and
  the folio. That inverts the usual hierarchy on purpose. Plex Mono is documentary rather
  than IDE-flavoured: humanist, slightly narrow, and it sets a 64-hex key without looking
  like a terminal.
- **Public Sans** is the USWDS face, drawn for United States government forms and records.
  A gothic, not a geometric, so it reads as *forms and signage* rather than SaaS. It speaks
  the annotation.

**The record is typed; the console annotates.**

All type is **rem**; there is not one `px` font-size in the file. The steps are seven and
genuinely distinct — verified against the rendered DOM, these are the only sizes present:

```
10 · 12 · 14 · 16 · 22 · 28 · 36        (0.625 / 0.75 / 0.875 / 1 / 1.375 / 1.75 / 2.25 rem)
 ↑ marks   ↑ annotation   ↑ the record's reading size   ↑ leads   ↑ action   ↑ mast  ↑ clock
```

---

## 4. Layout — the annotated record

One grid governs the verdict pane: **gutter 140 · measure · marginalia 430**. The margin
rule is the measure's left border, so it is continuous for the document's whole height.
Rows are grid rows, which means the marginalia is anchored to the recital it annotates and
**neither column can run out before the other** — the structural answer to the dead-column
finding.

- **The gutter carries everything the record says *about itself*:** the recital numeral,
  the wax seal naming the rule that caused the hold, the `TIER 0 · UNSIGNED` stamp, the
  *adversary-controlled* / *read register* / *agent-written* notches.
- **The measure carries what the record *says*** — the lead sentence at 16px and the typed
  field table beside it.
- **The marginalia carries the annotation**, set in the console's sans at 12px on graphite,
  ending in a **citation** naming the fixture path the slot's values came from.
- **Exactly one element crosses both rules: the signature.** Signing is the one act that
  binds the margin to the body.

That structure is also the answer to the review's "specification versus interface" note.
Every explanatory paragraph that used to sit inside the card is now outside the record's
measure entirely, in the annotation column, where a critical edition puts it.

**Severity without a hue.** Rank is **how much wax**: CRITICAL is inked (filled), HIGH is
struck dry (2px wax outline), MEDIUM is ruled (1px ink outline), LOW is nothing but the
word — plus the word, plus a four-tick register. Three redundant encodings, monotone
decreasing in greyscale. The board renders the whole ramp with the colour removed so the
claim can be checked rather than believed.

**Screen B — the Watch.** Sidebar · docket · rail.
The docket is **one chronological list, newest first, 001–022**, with holds, findings,
observations, notices, the threshold crossing and the incident interleaved on one row
anatomy. A court docket is not four inboxes; it is one record of everything that happened,
in order, each entry typed and numbered. That is truer to the world *and* better for a
shift, because what an analyst needs is *what happened on my watch, in order* — and it is
what let me reach real density without inventing a single row (§7).

The four inbox categories keep their counts in the sidebar index, above the lane index and
the **watch bill** — the colony roster, where three of eight typed agents are registered and
the other five are gated off by default and drawn with the same hatch every absence gets.

---

## 5. THE SIGNATURE

> **Every record ends in two ruled lines: the record's own, and yours.**

The first is **hatched, and it stays hatched.** `swarm:hold:v1` carries no Ed25519
signature in Ambush today under any condition, so the document arrives at your bench
unsigned and says so in its *shape*, above the sentence explaining it. Tier 0 is a hatched
stamp in the margin and a hatched rule in the body. When a card does carry an attestation
the same rule takes ink. Signed and unsigned differ consequentially, not decoratively, and
the difference is legible from across the room with the colour off.

The second is **empty, and waiting.**

**The grant is not a button.** It is a blank signature line under a tall field of stock,
with your operator id, your full 64-hex key and the exact tuple you are signing over set
small beneath it, and nothing else in that band. Measured in the rendered page: the block
is **570px tall, of which 400px is blank**; the tallest recital is **518px**. It is the
largest single element in the pane and most of it is nothing.

### Arming rules the page

This is the fix for the second fatal, and it is the direction's best idea.

A ledger is ruled, and the ruling is what tells you where a name goes. So **arming rules
the page.** The three states differ by a *quantity of ink*, never by a tint:

| | the field | the head | the ✕ | the words |
|---|---|---|---|---|
| **1 · Not armed** | bare stock | 3px stock rule | `--page-ink2`, **6.44:1** | `NOT ARMED — THIS LINE IS BLANK` |
| **2 · Armed, held** | ruled, and **broken** — the rules are dashes | 3px ink rule | `--page-ink2` | `ARMED · ENTER IS HELD` |
| **3 · Armed, Enter writes** | ruled **solid in your own ink, twice as dense** | 10px indelible bar | `--indelible` | `ARMED · ENTER WRITES` |

The state is printed **in the field, at reading size**, not only in a caption. The three
states are drawn side by side on the board as a required deliverable, and then drawn
**again with `filter: grayscale(1)`** so the separation can be checked rather than asserted.
None of the three contains a filled path anywhere, so none of them can be mistaken for a
primary button.

**Refuse is a stamp** — a double-ruled block, one key, no arming, no dialog, no undo, with
*Promote to a case* beside it and *Snooze* struck through rather than hidden. Asymmetric
friction stops being a written rule and becomes a physical fact of the desk: **a stamp is
one motion; a signature is two.** That is why the "friction is asymmetric" table is not on
this board and was not on the last one.

---

## 6. The risk

**The loudest element on the most dangerous screen in the product is empty.** 400px of
blank warm stock, one rule, one waiting ✕. At thumbnail scale — which is where a client's
judgment actually starts — the largest object on the board is a void.

I will defend it in one sentence: *the thing this product is waiting for is not a click, it
is a signature, and the honest picture of waiting for a signature is a blank space with your
name printed underneath it.*

---

## 7. Fixture fidelity

### 7.1 The blast radius — and a correction filed the other way

The review's sharpest finding was that five boards print
`network_connectivity` / `remote_management`, which appear nowhere in the fixture.

For the record, the prototype is not buggy there. `prototypes/verdict-hold.html:1240-1262`
carries an explicit, argued **DEPARTURE** note: the daemon's own
`build_rehearsal_preview` `IsolateHost` arm emits those two strings, the fixture carries
paraphrases, and the prototype chose the runtime's sentence and filed **fixture correction
F-P1** against 22-DEMO-FIXTURE. I inherited the strings from that decision, not from a bug.

**I have nonetheless changed to the fixture's values**, because this exercise pins the
fixture as the basis for comparing six directions, and a board that argues "this list must
never truncate, it is the real cost of the action" beside values the fixture does not
contain is eloquent exactly where it is least accurate. The board prints
`network.egress` · `network.ingress` from
`holds.a.rehearsal.blast_radius.affected_capabilities`.

And I adopted the policy the director asked for: **every slot on the verdict pane names the
fixture path its values came from**, printed on the board in the annotation column. In this
world that is not a debug affordance — it is a citation, which is what an exhibit in a
record carries anyway.

### 7.2 The docket — density without invention

The last pass invented eight queue rows. This one invents none. **All 22 docket entries are
fixture objects with their own timestamps**, ordered newest first:

- 14 `background.deposits[]` (strategy, threat class, host, confidence — 08:10 → 09:16)
- 2 ingested events (`hunt-evt-1`, `hunt-evt-2`, with the real command lines)
- 3 `findings[]` (all CRITICAL, all `confidence 0.90`, all unreviewed at this instant)
- 1 sub-threshold tick (`crossing.below`, 1.799653 < 2.0)
- 1 escalation (`crossing.crossing`, 2.696884 ≥ 2.0, level `alert`)
- 1 incident (`incident_id`)
- 2 holds (`h_a07aeacf`, `h_1c28ae79`)
- 2 kind-46010 notices (`nostr_event_ids.notice_46010_a` / `_b`)

Reading the fixture's own timeline as a docket is what made density and truth the same
thing. It is available to this direction and not to a four-inbox one, which is the kind of
payoff a point of view is supposed to have.

### 7.3 The instant, stated out loud

`queue.*` in the fixture is stated at `demo_now_ms` (09:20:00), where hold A has already
left the queue and one finding is reviewed. This board renders **09:16:05**, where both
holds are open and none of the three findings has been reviewed — so the sidebar reads
`Holds 2 · Named you — · Findings to review 3 · Case activity 1`. That is the same fixture
at the instant the whole set agreed to use, and the rail says so in as many words.

### 7.4 Other numbers

`58m 37s` is computed, not typed: `expires_at_ms − open_row_ms` = 3 517 600 ms.
Concentration is **2.696884** everywhere, unrounded. The sidebar's lane index prints
`lanes[].total_strength` to four places, labelled as the different measurement it is.
`median page to verdict` and `promoted / suppressed` render as **VOIDs** with the fixture's
own `UNMEASURED` reasons — which is the most on-brief fact in the whole file.

---

## 8. What I caught as a default this round — and what is not mine to claim

**Revised.** My first revision of the ramp kept the warm-versus-cold thesis and just moved
the cold hue: away from slate's ~265° toward a green-grey pewter. I got as far as writing it
down before noticing what I was doing. A warm page's mathematical complement *is* blue —
that is exactly why everyone lands on slate — so "pick a different cold" is the same move
one notch along, and the green-black variant would have walked straight into the
"green-tinted near-blacks" the client already rejected. **I replaced a different-distance
answer with a different-kind answer: zero chroma.** Not a cold hue — no hue. That is a
position a critic can verify in one line (`R === G === B`) rather than a number I could have
tuned, and it made the identity sharper rather than safer, because it leaves the record as
the only coloured material in the room.

**Not mine to claim.** Three moves appear on all six boards, which makes them properties of
the brief and not points of view: an unfilled outline for the destructive control, a
segmented meter for severity, and diagonal hatching for adversary-controlled strings. I am
not presenting any of them as a hard-won catch. On the third I have gone the other way on
purpose — **adversary strings here get a manila exhibit tab, not a hatch**, because in this
system hatching means **absence** and only absence, and an attacker's string and a missing
field must never be confusable at a glance. What is actually this direction's own is the
docket-as-chronology, the chain of custody ending in an unwritten line, the stamp/signature
asymmetry, and arming as a change in the ruling of the page.

---

## 9. The functional floor, verified

- **Contrast.** A script walks every text-bearing element in the rendered DOM, composites
  its real background through the ancestor chain, and computes the WCAG ratio.
  **Dark: 0 failures. Light: 0 failures.** Selected values: record ink 11.47 / 11.44 ·
  record secondary 6.44 / 5.85 · console ink 8.69 / 8.57 · console secondary 6.07 / 5.24 ·
  cream on wax 5.76 both · indelible 6.82 / 7.17 · adversary 6.98 / 5.32 · custody 7.15 / 7.50.
- **No banned hex, and no near miss.** Minimum ΔE2000 over all 35 hex literals in the file:
  **10.16**. 16 of the 35 are achromatic.
- **Four chromatic values**, against a cap of eight, plus two neutral ramps. The warm ramp
  is declared as a neutral material, not a chromatic value: it has no semantic job, it is
  what the document is made of.
- **Severity without colour**: how much wax + the word + a four-tick register — drawn in
  greyscale on the board.
- **Verification tier without colour**: a hatched stamp and a hatched rule — drawn in
  greyscale on the board.
- **Confidence without colour**: a two-decimal numeral first, a five-cell meter second.
- **Arming without colour**: the quantity of ruling — three states drawn in greyscale on the board.
- **Type**: rem only. Verified against the rendered DOM: exactly seven sizes, 10/12/14/16/22/28/36.
- **Light mode** is a first-class sibling. Every token is declared on bare `:root`, overridden
  under `:root[data-theme="light"]`, with a guarded `prefers-color-scheme` block for the
  untagged case. **No colour exists only inside a media query.** The board carries a working toggle,
  and the palette legend prints the live computed value in whichever theme is showing.
- **No network.** Rendered in an offline browser context: `external: []` on every load, both themes.

---

## 10. What I removed before shipping

Two things, and both were the same fault:

1. **The left rail** — a 52px column of two square chips that carried no information on
   either screen. Pure furniture.
2. **A sentence inside the product chrome**: *"The queue is not on the bench. While you are
   deciding, the only thing on the desk is the thing you are deciding."* It is a good
   sentence and it is true, but it describes what the reader can already see, which makes it
   caption and not interface — and on a 3am bench every sentence between the operator and
   the blast radius is a cost. The strip now carries the hold id and the two times instead.
   The sentence lives here, where it belongs.

The "FRICTION IS ASYMMETRIC, ON PURPOSE" table was cut in the previous pass and stays cut,
for the same reason: once refusal is a stamp and granting is a signature, the page shows it.
