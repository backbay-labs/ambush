# NIGHT BRIDGE — Perch art direction · revision 2

**Board:** `board.html` — self-contained, 1440 wide, zero non-file requests (measured in both
themes), dark by default with a light mode and a three-position theme control.

Revision 1 was judged *costume*: "the guarded switch is narrated at length and drawn as a
rectangle with a border." That judgment was correct. This revision draws the object, and the
audit that produced it changed the shape of the palette rather than its hex digits.

---

## 1. The world

**Night watchkeeping — the darkened bridge, and the log written on it.**

Perch's one job is to let a tired person read correctly, in the dark, at speed, and be certain
about the severity of what they are about to do. Nav instrumentation solved that about a
century ago, and every choice it made can be justified twice — once aesthetically, once
ergonomically. It painted the panel a colour that does not glare. It burned as few lamps as it
could, because every lamp costs dark adaptation. It wrote the log in ink, because the record has
to survive the shift. And it put a hinged cover over the switches you must not throw by
accident.

The product's own settled vocabulary already lives there — *the watch, take the watch, end
watch, the watchfloor, the ledger, the case, the verdict, the record, the hold, containment,
blast radius.* Bridge and court-record words. Not hacking words.

The organising law, which is new in this revision and is the thing everything else falls out of:

> **Colour never lands on a word. Chroma exists only as light falling on a surface.**
>
> Every glyph in the system is bone, body or dim on warm graphite. Two lanterns burn. The panel
> is warm and unlit; the night outside the glass is colder and darker than anything on it.

That is not a slogan. It is enforced in the file and it is greppable: **no chromatic hex is ever
a text colour.** Every chromatic value paints a surface, a glow or a bezel. (`--port-ink`, the
one colour token that appears in a `color:` declaration, resolves to `#F2ECDD` in dark and
`#D2CDC4` in light — both neutral ramp steps, aliased so the text inside a lit recess stays
legible when the surface under it changes.) Two consequences follow for
free — the entire console survives colour-blindness, a bad monitor and a greyscale print by
construction, and the two lit things on the screen are the only two things that can hurt you.

---

## 2. Palette — derived, not picked

Revision 1's accent set was **blue = observation, violet = policy, amber = caution, red =
danger**: the standard semantic four with the hexes nudged until they cleared a fence, two of
them close enough to the fence to be caught (`#86A9C8` was ΔE00 **5.82** from `#94a3b8`;
`#D9A445` was **7.53** from `#eab308`; `#E8705C` was **6.48** from `#f87171`). The critics were
right on every measured value, and my own plan's claimed margin was wrong — I had reported ΔE
8.10 for the blue and never re-ran the audit on the chromatic tokens after re-cutting the
neutrals.

So I threw the accent set away and derived the replacement from optics. The method: a signal
lantern's **dominant wavelength**, mixed toward **CIE Illuminant A** (2856 K — the incandescent
source marine signal lanterns are specified against), then **added to the graphite panel in
linear light**, because at night you never see the lamp, you see the panel under the lamp.

### What the derivation refused to give me

| Step | Result |
|---|---|
| Take the cold light first | The dark-adapted eye peaks at **507 nm**. Rendered on graphite at any usable luminance it produces `#009368`, `#00A877`, `#00BE86` — ΔE00 **1.10–4.98** from `#059669` and `#10b981`. The rod peak *is* emerald. Physics does not excuse a banned look. |
| So try any cold hue | A sweep of 470–495 nm across every purity and every irradiance that clears 4.5:1 on the panel returns **nothing** at ΔE00 ≥ 10. Slate-500/400, sky, cyan and blue-600 carpet the entire cold half of the wheel at instrument lightness. The honest reading of the banned list is that **it is the saturated hue circle** — so a console's cold cannot be a hue. |
| So the cold became value | The ground is `--night` at L\* 3.9, the coldest and darkest value in the file, against a warm graphite panel at L\* 11.5. The temperature split is now a fact about the two largest areas on screen instead of a hue applied to text, and it reads at thumbnail size — and it survives into light mode, where the deck is grey-painted steel and the plates are pale stone. |
| Two lanterns remain | A darkened bridge burns red and amber and nothing else, for the same reason this console does. |

### The palette

Five chromatic values in the entire file — the cap is eight — plus a nine-step warm graphite ramp
in each theme. Every value is on bare `:root` for light; dark is declared twice, identically,
under `[data-theme="dark"]` and inside a guarded `prefers-color-scheme` query. No colour exists
only inside a media query.

| Name | Hex | What it means — one sentence |
|---|---|---|
| **The night** | `#04100F` | What is outside the glass: the only cold value in the system, the darkest, and the ground every instrument is set into. |
| **Panel graphite** | `#211E1A` | The painted plate everything is silkscreened onto — one material, lit two ways, which is why light mode is not a second theme. |
| **Silkscreen bone** | `#F2ECDD` | Every word a human wrote or must read; the log is written in ink, and ink is never coloured. |
| **Binnacle · 578 nm** | `#AB8200` | A clock is running against you — the countdown and the dwell, and nothing else. |
| **Port · 615 nm** | `#F5703F` | The throw: the irreversible act, in the one place you can commit it and nowhere else in the product. |
| **Port well** | `#571D19` | The same lantern at low irradiance — the panel at the edge of the lit recess. |
| **Binnacle glass** (light) | `#5B4D35` | The compass lamp's filter seen unlit: in daylight you do not see the light, you see the glass. |
| **Port glass** (light) | `#663737` | The sidelight's filter in daylight — and the live throw, which in a bright room is the darkest, most saturated object on the screen. |

Full ramps. **Dark:** `#04100F #181613 #211E1A #2B2721 #332E27 #4A443A #9B9486 #CAC3B3 #F2ECDD`.
**Light:** `#969084 #AFA89A #C7C0B3 #D2CDC4 #B4ADA1 #878074 #413D35 #312E27 #1A1712`.

**23 hex values are declared in CSS in the whole file and no others.** The banned hexes appear in
the document exactly 28 times as *printed citations* inside the §D and §E measurement tables, and
zero times inside a `<style>` block or a `style=` attribute — verified by script.

### Three laws that keep it at five

1. **Colour is light, never ink.** No chromatic hex is ever a text colour. Chroma paints the
   countdown's glow, the dwell bar, the lit throw and its bezel. That is the list.
2. **Severity is not a colour scale.** It is the word, a four-segment bar, and a rail whose
   weight, pattern and luminance all move together — solid bone at CRITICAL, a 5/4 dash in body
   at HIGH, a 2/3 dot in dim at MEDIUM, a hairline at LOW. The rail's luminance is monotonic, so
   the ramp cannot invert. **There is no hue anywhere in the queue.**
3. **A mark across a glyph means absence, and only that.** An adversary-written value is ruled
   *underneath*; a value that cannot exist is struck *through*. Revision 1 hatched over the
   glyphs and it read as strikethrough in the render — caught by looking at the picture, not the
   code.

### The floor, measured

- **Minimum ΔE2000 from any banned value, across every declared hex: 10.78** (`#D2CDC4`, the
  light selection surface). Dark theme minimum 11.40; light theme minimum 10.78.
- The light ground is **ΔE00 25.16 from the cream at `#F4F1EA`**. Revision 1's light `--lit` was
  **ΔE00 0.58** from it — banned look #1 sitting in my own file, which no critic caught and I
  found by auditing the light ramp against the *look* as well as the list. Light mode is now a
  grey-painted deck at L\* 60–83, with no display serif and no terracotta.
- **Zero text runs below 4.5:1 in dark; zero in light.** Measured by walking every text node in
  the rendered page, resolving each one's real painted background, in both themes. The three
  light-mode hits my walker reports are its own blind spot — it cannot see a `::before`
  background — and pixel sampling of the live throw gives **6.12–6.59:1** there.
- `--rule` measures 1.72:1 and is therefore **never text**; it draws the spine, the ticks, the
  unlit cells and the hairlines, all bounded shapes. Revision 1 used it for the section index
  glyph and the mid-dots. Both moved.
- Graphical values are held to 3.0:1 and neither lantern is ever drawn on the deck.
- **Zero `font-size` declarations in px.** Two `font-size:.94em` relative multipliers exist, which
  optically match Plex Mono to Barlow at the same step and inherit the rem, so zoom holds.
- **Zero non-file network requests**, logged in both themes.

---

## 3. Type

| Role | Family | Fallback stack |
|---|---|---|
| Silkscreen — every label, header, badge, key | **Barlow Semi Condensed** 600/700, uppercase, `.135em` | `Barlow Condensed, Roboto Condensed, Arial Narrow, Helvetica Neue` |
| Reading — prose a tired person must parse | **Barlow** | `Helvetica Neue, Helvetica, Arial, system-ui` |
| Dial — anything the machine emitted verbatim | **IBM Plex Mono** | `ui-monospace, SF Mono, Menlo, Consolas` |

All three are self-hostable (Fontsource / Google Fonts). Nothing is fetched: the board declares
stacks only, and the fallbacks are chosen so a machine with nothing installed still renders a
condensed silkscreen silhouette — Arial Narrow ships on macOS and Windows.

**Why Barlow and not Inter.** Barlow is a transport-signage grotesque, drawn for the flat, wide,
low-contrast lettering on vehicles and public infrastructure, and it ships a genuine condensed
cut *in the same family*. That is exactly what a real instrument panel does: the placard and the
silkscreen come off one type drawing at two widths. Inter is what I reach for by default on any
dark UI; it has no condensed cut with this character and no reason to be here beyond habit.

**Why IBM Plex Mono.** One rule makes the pane checkable: **mono means the machine's own bytes;
Barlow means English.** Ids, keys, times, thresholds, strengths, rule names and the daemon's
verbatim strings are mono, and nothing else is. Plex Mono has the flat-topped 1, the unambiguous
0 and tabular figures that let a 64-hex key and a six-decimal concentration sit in a column
without wobbling.

**The ramp is re-cut.** Revision 1 had `.9375 / .875 / .8125` crowded together. Seven steps now,
each a real step: `3.5 / 2.375 / 1.375 / 1.0625 / .9375 / .8125 / .6875 rem` — 56 / 38 / 22 / 17
/ 15 / 13 / 11 px at a 16 px rem.

---

## 4. Layout

**Screen A — the verdict pane is one measure.** Revision 1 ran a dead black column down its left
third for roughly 60 % of the pane's height. The rule I adopted is the reviewer's: *a column
carries content for its full height or it does not exist.* The queue is gone from this screen —
it belongs to screen B — and the card sits at full measure under a full-width annunciator strip.

Inside the card, the five slots are ruled entries on a continuous **spine**: each hangs a
numbered tick on it (solid when filled, hollow when struck), the label is silkscreened in the
margin, and the body sits to the right of the rule. The fixed order is therefore *visible as a
structure* — you can see there are five and which one is empty. The chronometer is a large
tabular readout with the binnacle glowing behind it and the derivation stated beneath. No dial,
no arc: a countdown is a number.

**Every explanatory sentence that describes what the reader can already see is out of the card
and on the board.** On a bench at 3am, a sentence between the operator and the blast radius is a
cost. The "FRICTION IS ASYMMETRIC, ON PURPOSE" table is gone — with the guard drawn large it
restated in prose what the controls say in form.

**Screen B — the watch is the chart table.** Sidebar · inbox · handover, three columns that all
fill. Rows are four lines with one anatomy for holds and findings alike; line 2 is the subject,
is adversary-controlled, is ruled, owns its line and never truncates. **Selection is the plate
lifting under a lamp** — the surface rises to `--lit`, a hairline outlines it, and the keys you
can press appear. It is not a coloured row, because a coloured row on this console would mean a
lantern was lit.

---

## 5. The signature — the guarded throw

The grant control is a **hinged cover over a lit recess**, and this revision actually builds it.

- **Closed** — the plate lies flat over the throw's own footprint and occludes it. The throw is
  not on the screen. There is no disabled button to habituate to and nothing to mis-click.
- **Lifted** — the plate turns about a knuckled hinge along its top edge, past vertical, and
  leans back above the throw. You see it foreshortened, from underneath, with its stencil facing
  you and its shadow falling down the well. The throw is exposed and inert.
- **Live** — the 615 nm lantern behind the throw is burning: a lit well with a bloom along its
  bottom bezel, the raised plate catching the bounce on its underside, and the words at full
  strength.

Transform, shadow, occlusion, two faces, an axis. **The cover has exactly two positions**, and
arming is what moves it — the dwell does not, because what separates *armed* from *live* is the
lantern, which is the thing that actually differs. Position and light are two independent facts
with two states each, and the board draws all three combinations that exist, at 2× scale,
**directly under the masthead, before the verdict pane**. The reader meets the object before the
document it lives in.

It is the signature because it *is* the brief. The two-stroke contract stops being a line in a
keymap and becomes a fact about the thing in front of you: there is a cover, and you took it off.
The control can never read as a friendly primary because there is no filled path in the
component — the throw is a recess, the cover is a plate, and the only fill that ever appears is
lamplight. Refuse sits beside it as a plain outline chip with one key cap, because refusing is
the safe direction and making it expensive produces grants by exhaustion.

**It survives greyscale.** `board.html` renders the three-state strip through `grayscale(1)` on
demand and I checked the picture: with every colour removed, at arm's length, the three states
are still unmistakable. That is the property the whole safety argument rests on, and it is a
property of the geometry, not of a tint.

---

## 6. Every finding, answered

| Finding | What changed |
|---|---|
| **The signature does not exist in the pixels** | Built: hinge with knuckles, a plate that occludes the throw when closed, rotation past vertical about that axis, a distinct underside face, a cast shadow down the well, and a lantern you can only see once the cover is off. Verified by render and by greyscale render. |
| **The accent set is the standard semantic four, two near the fence** | Deleted. The four inks are gone; chroma moved from ink to light. What remains is two lanterns derived from lantern optics, ΔE00 15.67 and 12.99, with the derivation and its failed branches printed on the board. |
| **Port Red has three jobs and paints the queue** | Red has one job: the throw. It appears in exactly one component in the product. CRITICAL, "no undo mapped" and every rail in the Watch are achromatic. There is now **no hue at all** in the queue. |
| **Every board ships a value inside ΔE00 10; floor at 10 and re-derive from the world's material** | Minimum across all 23 declared hexes is **10.78**. Every chromatic value is derived from a named material (a dominant wavelength through a lantern filter against Illuminant A) rather than by stepping away from a framework hex. The values that failed that test — the 507 nm rod peak, every cold hue — were **cut**, and the board says so. |
| **Dead left column, ~60 % of the pane's height** | The verdict pane is a single measure. The rule is stated on the board and applied everywhere; note bands and the colophon are two-column so they fill. |
| **The signature appears twice, both weakly, 3 000 px down** | It is now the first thing after the masthead, at 2×, three-up. |
| **Cut the friction table** | Cut. |
| **Amber and red rails compete down the queue's left edge** | No coloured rails exist. The rail is bone / body-dash / dim-dot / hairline. |
| **`.idx` and `.sep` below the floor** | `--rule` is off text duty entirely — zero `color:var(--rule)` declarations remain. Zero text runs below 4.5:1 in either theme. |
| **Deck Blue near slate-400** | Gone. |
| **Fabricated blast-radius strings** | Corrected to `network.egress` / `network.ingress`. See §7. |
| **Invented queue rows** | Removed. See §7. |
| **Lane strength disagrees across boards** | One instant for the whole board, named on the masthead. Both fixture values are printed with their distinct paths and their distinct instants. See §7. |
| **Only one grant state drawn (adopt the three-up convention)** | Adopted, at 2×, above the fold, with a greyscale proof. |
| **Stop claiming the convergent moves as differentiators** | Done. The under-ruling, the outline destructive control and the segmented severity meter are properties of this brief that six independent passes found. They are described in this plan as what they are and are not offered as catches. What is particular to this direction is the temperature split, chroma-as-light, and the guard. |

---

## 7. Three places I changed my position, with the evidence

**The blast radius now renders the fixture, not the daemon.** Revision 1 followed
`prototypes/verdict-hold.html:1250`, which prints `network_connectivity` / `remote_management`
and argues in its own margin that these are `preview.rs`'s strings and the fixture's are
paraphrases. That argument is not wrong about the runtime, and it is wrong about this exercise.
The fixture is the contract that makes six boards comparable, and a board that prints one pair
while arguing at length beside it that this list must never be truncated is eloquent exactly
where it is inaccurate. This board renders
`holds.a.rehearsal.blast_radius.affected_capabilities`. The prototype line should be corrected at
source so the next pass does not inherit it; I have not touched it, because it is outside this
task's write scope.

**The queue is the fixture's queue, and the density is the fixture's too.** Revision 1 invented
`quarantine_file`, `revoke_credential`, `dns_exfiltration`, `scheduled_task_persist`,
`beacon_jitter`, two extra cases and four hosts to reach the density the brief asked for. All
removed. The four categories now render exactly what `queue` contains: **one** hold
(`h_1c28ae79`), **absent** rather than zero for *Named you*, **three** findings with their real
review states, and **one** case.

The brief's two instructions — identical fixture content, and a dense list — are in genuine
conflict, and the reviewer is right that it is a brief defect. My resolution invents nothing: the
Watch carries a fifth section, **"Accumulating · not asking for you"** — the fixture's own
`background.deposits[]`, fourteen rows across seven hosts, under the twelve `lanes[]` with their
strengths in the sidebar. That is real accumulated substrate, below the alert threshold on every
lane, and it is what a watchfloor actually shows: not only what crossed, but what is about to.
The screen is dense, and **§F of the board names the fixture path of every string on it.**

**Both concentration figures render, with their instants.** `2.696884` is
`holds.a.rationale.concentration_at_hold` — what the hold card carries, measured at 09:14:41 when
the lane crossed. `2.653617` is `concentration.at_open_row.total_strength` — the lane at the
instant this board renders. They are two instants of one measured quantity, not a wobble, and the
fix is not to pick one but to say which is which. So the board adopts the log-keeper's rule:
**no figure appears without the time it was taken.** Everything is rendered at
`clock.timestamps.open_row_ms` = 2026-03-17 09:16:05 UTC, printed on the masthead.

---

## 8. What I revised, and the accessory I removed

**The revision that changed the shape.** My first pass this round did what revision 1 did — it
went hunting for a better blue, a better violet, a better amber. I ran the distance metric on
every candidate and the metric told me something I did not want to hear: at any lightness a
console can use, *there is nowhere cold to stand.* The banned list is the saturated hue circle,
and the cold half of it is fully occupied. I could have kept nudging until a number cleared —
which is precisely the reflex that got the first pass rejected, at higher resolution. Instead I
took the result seriously and **moved colour off ink entirely**: the four semantic inks became
two lanterns that light surfaces, the cold became a value rather than a hue, and the temperature
split stopped being a claim about accents and became a fact about the two largest areas on the
screen. That is a change to the shape of the system, and it is the only reason this revision is
worth reading.

The same audit found something no critic did: my light-mode selection surface was **ΔE00 0.58**
from `#F4F1EA` — banned look #1 sitting inside a file whose plan asserted compliance. The light
theme was rebuilt as a grey-painted deck.

**The accessory removed.** The dwell had two indicators — a bar inside the throw and a bar in the
gate block on the card face. Two bars counting the same 1500 ms is one bar too many, and the one
inside the throw was the wrong place for it: the recess should hold the act, not the arithmetic.
Cut. The throw now carries words and a lamp, and nothing else. (Revision 1's removed accessory,
the masthead's amber gradient hairline, stays removed.)

**The optical corrections nobody would name.** The mono is `.94em` against Barlow so the two
faces sit on one x-height. The slot spine stops at the last tick rather than running past it. The
adversary ruling clears the baseline by `.3em` so it never touches a descender. Section index
letters moved from `--rule` to `--dim`. The swatch labels moved out from inside the swatches,
where the darkest three were unreadable on their own colour.

**The risk.** There is no green in this system and nothing positive gets a colour at all — not
"reversible", not "attested", not "reconciled", not "governance healthy". In a console that can
isolate a production host, a green light is a reassurance an operator learns to trust without
reading, and this product's whole thesis is that the human must read. The system spends its two
lamps on a clock and on an irreversible act, and it gives a tired person nothing else to look at.
