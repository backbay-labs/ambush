# Visual identity and design system

Perch inherits a complete, CI-guarded design system from Buzz and a complete,
hand-authored visual identity from Ambush's 19 documentation SVGs — and the two
do not agree about anything except that rounded rectangles are fine. This
document reconciles them: it pins Ambush's three-hue semantic palette into
Buzz's HSL-token/Tailwind plumbing, adds the security ramps Buzz has never
needed (severity, confidence, posture, containment state, verdict, rollback
outcome, **signature provenance**), specifies the data-visualization language
from nothing, and itemizes all 119 `shared/ui` files as reuse / re-skin / build.

**This revision.** Six things changed under review and are called out where they
land: (1) the three-hue taxonomy is renamed **pillar**, because "lane" was
carrying four incompatible meanings across the doc set and one of them is an
operator-visible nav label (§2.1); (2) a new §2.6 states, per card type, which
Ambush artifacts actually carry an Ed25519 signature — four of the seven marker
card types (finding, escalation, hold, lease) do not, and the attestation badge is respecified around that fact;
(3) the verdict keymap is corrected to `04-SURFACES-AND-UX.md`'s `C`/`D`/`I` and
`G`/`R`; (4) density modes are renamed to Buzz's own `comfortable` / `compact`
and given their inherited values; (5) the Watchfloor route is `/watch-floor`;
(6) a citation audit (§13) answers *who calls this, in what process, and what
does it do to the data* for every load-bearing reference in the document.

---

## Decisions made here

1. **Two encoding axes, never one.** Hue encodes *pillar* (substrate green /
   authority amber / evidence cyan / neutral). A separate 4-step ramp encodes
   *severity*. They never share a swatch. `--destructive` keeps its Buzz meaning
   ("this control deletes things", `theme.css:29,95`) and is never reused for
   CRITICAL.
2. **The word is "pillar", not "lane".** `docs/assets/pillars.svg` is the source
   of the trio and the file's own name; "lane" is spent on the twelve
   threat-class channels whose sidebar heading is literally `LANES`
   (`04-SURFACES-AND-UX.md:78-80`). Bare "lane" outside that nav sense goes on
   the CI ban list `06-COPY-AND-VOICE.md` owns.
3. **Every pillar hue ships as an `-ink` and a `-mark`.** Ambush's `#4ade80`
   scores **1.49:1** against a light chrome surface — physically unusable as
   light-mode text. Ink (text, AA) and mark (fill/rail/stroke, ≥3:1) are
   separate tokens per pillar per theme.
4. **Perch pins one theme pair and deletes the theme picker.** `createThemeVars`
   (`desktop/src/shared/theme/adaptive-theme.ts:191`) stays alive for the *code
   and terminal* palette only; app chrome is a hand-authored `:root` / `.dark`
   pair. The 10-swatch accent picker is deleted outright.
5. **Dark is default; light is first-class, not a courtesy.** Ambush's identity
   is dark-only across all 19 SVGs; a shift desk at 14:00 is not a wallboard.
6. **The type ramp is Buzz's rem contract, unmodified**, plus one new size token
   (`text-eyebrow`) and one new family token (`fontFamily.mono`) — JetBrains Mono
   already ships (`desktop/package.json:34`) but is bound only inside
   `terminal.css:7`, so §3.3's mono discipline is currently inexpressible in
   Tailwind.
7. **Motion means production changed.** Four allowed motion classes, all
   state-driven. `animate-pulse` on status is banned. No looping ambient motion
   anywhere except `/watch-floor`, which is opt-in and reduced-motion-off by
   default.
8. **Data-viz is hand-authored SVG on named CSS custom properties**, seven chart
   forms only, no library. `--chart-1..5` are deleted, not reused.
9. **Signature provenance is a rendered field with four states, not a badge with
   two.** Four of the seven `ambush:*:v1` card types — finding, escalation, hold,
   lease — carry no signature of their own today (§2.6). The design system renders that as a named state with a
   daemon verify affordance — never as a missing badge, never as a shield.
10. **Two badge families, not one.** 12 destructive/human-gated, 3 reversible.
    The panel's "3 receipt-gated actions" is false; see §2.7.
11. **Density is two modes** (`comfortable`, `compact`) reusing Buzz's existing
    `data-conversation-density` mechanism and its existing values. Buzz's
    `spacious` is dropped.
12. **WCAG 2.2 AA, with three commitments above it**: severity and containment
    state carry a non-color encoding; no information is conveyed by hue alone;
    every verification surface renders *two* rows naming *both* chains it did
    and did not check.

---

## 1. Brand direction: what Perch should feel like

Ambush's docs argue with themselves in public. `EVOLUTION.md` opens a section
"Read this before filing 'promotion is broken'". `README.md` has a section
called "What we do not catch, and why". ADR 0009 is subtitled "stated as
negative space". The visual system has the same posture: `stigmergy.svg:56`
labels its own escalation point `3 distinct sources ≥ 2` — the diagram shows
you the predicate, not a verdict.

**The feeling: an instrument, not a dashboard.** A dashboard tells you it is
fine. An instrument tells you what it measured and lets you conclude. Every
Perch surface should read as though it expects to be checked.

Three inherited moves carry that feeling and are non-negotiable:

| Motif | Source | Perch use |
|---|---|---|
| **2.5px colored pillar accent** on the top edge of a card | `pillars.svg:28,47,65` — green/amber/cyan rails on identical `#0c1613` cards | The cheapest recognizable Ambush cue. Every evidence card, verdict pane and lane-channel header carries one. Hue = pillar, never severity. |
| **Corner crosshair ticks** | `hero-v2.svg:95-96`, `pillars.svg:17-20` | Framing device on the Watchfloor and on any "this is a measured region" container. Decorative, `aria-hidden`. |
| **Dashed trail with growing dots** | `pillars.svg:30-34` — dashed `2 5` rule, radius 2.2→5.4, opacity 0.4→1.0 toward the target | The visual grammar for *accumulating evidence over time*. Reused literally in the concentration timeline (§8.1). |

And one inherited move is **rejected**: the travelling `<animateMotion>` dot.
`hero-v2.svg` runs exactly eight of them (`:21,30,39,48,57,66,75,84`, durations
4.4s–7.3s, `repeatCount="indefinite"`, seven green and one amber at `:39`). It
is beautiful on a README and wrong in a console, because in Perch a moving dot
must mean a deposit actually landed. See §7.

**The tension to name explicitly.** Ambush's shipped operator workbench is
*light and warm*: `:root{color-scheme:light;…}` and
`body{margin:0;background:#f4efe5;color:#1d2433;}` with a cream-to-blue hero
gradient (`crates/swarm-runtime-http/src/http/render.rs:38-40`). Its
documentation identity is dark and green. Perch resolves this in favor of the
documentation identity, because that is the one a reader has already associated
with the product's claims, and because the workbench CSS was written to be
legible in a browser tab, not to be a brand. Nothing depends on it: `render.rs`
is a `concat!` of style strings inside one server-rendered HTML page, consumed
by no client code.

Buzz's own brand layer is thin enough to excise cleanly: a two-stop gradient
whose stops are defined at `theme.css:51-54` and painted at `theme.css:320-321`
only under `:root[data-buzz-sidebar]`, a bee mark, a poof sprite, an
emoji-confetti canvas, and 3.3 MB of baked card texture across four PNGs
(`src/shared/ui/assets/card-texture*.png`, measured). None of it is
load-bearing.

---

## 2. Color

### 2.1 The two-axis rule, and why the axis is called a "pillar"

Ambush's palette is *already fully spoken for* as a three-way taxonomy:

| Hue | Meaning in Ambush's own assets | Evidence |
|---|---|---|
| Green `#4ade80` | swarm, detection, deposits, trails, substrate | **308** occurrences across `docs/assets/*.svg` (counted); `colony.svg:8-9` draws and labels the substrate rail `PHEROMONE SUBSTRATE` in it; `pillars.svg:28` is the SWARM card's rail |
| Amber `#f59e0b` | authority, the gate, destructive action, thresholds | **79** occurrences; `colony.svg:43,46` boxes Tom and Pouncer in it and `:52` puts `SIGNED RECEIPT` in it; `pillars.svg:47` is the GOVERNANCE card's rail; `stigmergy.svg:48-49` draws the `alert_threshold 1.20` rule in it |
| Cyan `#22d3ee` | proof, evidence, audit, evolution | **77** occurrences; `security-v2.svg:8,10` wraps every other layer in a cyan `SIGNED EVIDENCE` band; `pillars.svg:65` is the EVOLUTION card's rail; `colony.svg:22,28,33,38` marks the four substrate *readers* |

There is no red in the palette at all — zero occurrences of any red-ish hex
across all 19 assets (grepped). The only red in the product is `#e05252`, from
the `response-fail--closed` badge at `README.md:14` — where red means *good*.

So a naive "green=low, amber=medium, red=critical" severity ramp would collide
with the taxonomy on every screen: a CRITICAL `command_and_control` finding
would want amber for severity and amber for the C2 channel's authority rail, on
the same row.

**Why "pillar" and not "lane".** The earlier draft of this document called the
three hues *lanes*. That word was doing four incompatible jobs across the plan
set at once: the twelve threat-class channels (`04:406`, `03:473`, and the
sidebar heading `LANES` at `04:78-80`), the four inbox categories (`04:130-149`,
`06:322-326`), this hue taxonomy, and the bridge's four transport classes with
per-lane spool budgets (`07:17,187-205`). "The evidence lane" was simultaneously
a colour token and a 256 MiB disk spool. `06-COPY-AND-VOICE.md:31-35,172-182`
bans exactly this pattern for `lease`; the set was applying its own rule to the
domain's word and not to its own invention.

The word "lane" belongs to the operator-visible nav label, because that is the
one a human reads at 02:41. The hue taxonomy takes **pillar**, which is not an
invention either — `docs/assets/pillars.svg` is the file the trio comes from,
its three cards are drawn as three columns, and its aria-label at `:1` names
them as the product's three structural divisions. `04` §6.2 and `06` §2.4 first
proposed *family* for this axis and have been amended to *pillar*, because
*family* is already spent on the two badge families. Token names follow:

```
axis 1  PILLAR    hue        substrate | authority | evidence | neutral
axis 2  SEVERITY  ramp       LOW → MEDIUM → HIGH → CRITICAL
                             + a mandatory non-color encoding
```

Severity gets its own four-step ramp that runs sage → gold → amber → red, and
is used **only** on the severity chip and the 4px leading rail of a finding
row. The pillar hue is used on the card's *top* rail, on icons, and on chart
strokes. They are never adjacent on the same edge.

The alternative rejected: encoding severity by *fill opacity of the pillar hue*.
It reads beautifully on the Watchfloor and is illegible in a 32px-tall inbox
row at 02:41.

**Non-color encoding for severity is mandatory.** `Severity` serializes
`SCREAMING_SNAKE_CASE` (`crates/swarm-core/src/types.rs:407-414`) — Perch
renders the literal word `CRITICAL`, plus a four-segment bar with 1/2/3/4
segments filled. Hue is the third signal, never the first.

### 2.2 Ink and mark

Measured (WCAG 2.x relative luminance, computed against the exact surface hexes
below):

| Hue | vs dark canvas `#0a1210` | vs light chrome `#e9efeb` |
|---|---|---|
| `#4ade80` | **10.89:1** | **1.49:1** |
| `#f59e0b` | **8.83:1** | **1.84:1** |
| `#22d3ee` | **10.50:1** | **1.55:1** |

The bright Ambush hues fail even the 3:1 non-text bar (WCAG 1.4.11) on a light
surface. This is not a taste question. **Every pillar hue therefore ships as a
pair**: `--pillar-<x>-ink` (text and glyphs, ≥4.5:1 on every surface in its
theme) and `--pillar-<x>-mark` (fills, rails, chart strokes, ≥3:1). In dark mode
they happen to be the same value; in light mode they are not.

### 2.3 Dark palette (default)

Every hex below appears in `docs/assets/*.svg` except where noted. Contrast
figures are computed against `--background` `#0a1210` unless stated.

**Surfaces and text** — HSL triplets, because Buzz's Tailwind maps
`hsl(var(--token))` (`desktop/tailwind.config.js:82-137`):

| Token | Hex | HSL triplet | Note |
|---|---|---|---|
| `--surface-chrome` | `#070a09` | `160 17.65% 3.33%` | sidebar / colony rail. `hero-v2.svg:3` gradient start; 33 uses |
| `--background` | `#0a1210` | `165 28.57% 5.49%` | app canvas; 14 uses |
| `--card` | `#0c1613` | `162 29.41% 6.67%` | `pillars.svg:27` card fill, verbatim; 19 uses |
| `--popover` | `#10201b` | `161.3 33.33% 9.41%` | elevated; darker than card, inverting Buzz's `elevate(+0.08)` |
| `--surface-raised` | `#163027` | `159.2 37.14% 13.73%` | inline code, chips, terminal gutter |
| `--border` | `#1e3a2e` | `154.3 31.82% 17.25%` | `pillars.svg:27` card stroke |
| `--border-strong` | `#26463a` | `157.5 29.63% 21.18%` | focus ring base, table rules |
| `--foreground` | `#eaf3ee` | `146.7 27.27% 93.53%` | **16.76:1**. The wordmark color, `hero-v2.svg:99` |
| `--foreground-secondary` | `#9db3a8` | `150 12.64% 65.88%` | **8.53:1**. `pillars.svg:37` body ink |
| `--muted-foreground` | `#7f9c8d` | `149 12.78% 55.49%` | **6.36:1**. Meta, timestamps; `pillars.svg:23` eyebrow |
| `--foreground-faint` | `#718b80` | `154.6 10.32% 49.41%` | **5.16:1**. Disabled controls only |

`#5d7269` (16 occurrences in the assets, Ambush's faintest label ink — e.g.
`stigmergy.svg:56`) scores **3.68:1** and is *not* promoted to a token: it is
below AA and Perch has no text that is allowed to be unreadable. Named and
rejected on purpose. `#7c9187` (27 occurrences, the role-subtitle ink in
`colony.svg:13,19,24`) scores 5.13:1 and is folded into `--foreground-faint`
rather than kept as a fifth step.

**Pillar hues (dark: ink == mark):**

| Token | Hex | Contrast |
|---|---|---|
| `--pillar-substrate` | `#4ade80` | 10.89:1 |
| `--pillar-substrate-dim` | `#34d399` | 9.87:1 — `security-v2.svg:18,20,23,25` uses this for the two *inner* layers |
| `--pillar-authority` | `#f59e0b` | 8.83:1 |
| `--pillar-evidence` | `#22d3ee` | 10.50:1 |

**Severity ramp (dark):**

| Step | Token | Hex | Contrast | Bar |
|---|---|---|---|---|
| LOW | `--sev-low` | `#83a094` | 6.70:1 | ▮▯▯▯ |
| MEDIUM | `--sev-medium` | `#d9aa55` | 8.88:1 | ▮▮▯▯ |
| HIGH | `--sev-high` | `#f59e0b` | 8.83:1 | ▮▮▮▯ |
| CRITICAL | `--sev-critical` | `#f07171` | 6.60:1 | ▮▮▮▮ |

HIGH deliberately *is* the authority hue: `policy.human_gate_severity: HIGH` in
the shipped default (`rulesets/default.yaml:93`), i.e. HIGH is exactly the
severity at which a human is asked. The color coincidence is the meaning.

`--sev-critical` is `#f07171`, a lightened `#e05252`, because `#e05252` scores
only **4.42:1** on `--popover` and **3.70:1** on `--surface-raised`. `#e05252`
survives as `--danger-mark` (fills and rails only) and keeps its README meaning
where it appears as a state word.

### 2.4 Light palette

| Token | Hex | HSL | Contrast |
|---|---|---|---|
| `--surface-chrome` | `#e9efeb` | `140 15.79% 92.55%` | — |
| `--background` | `#f2f6f3` | `135 18.18% 95.69%` | — |
| `--card` | `#ffffff` | `0 0% 100%` | — |
| `--border` | `#d3dfd8` | `145 15.79% 85.10%` | — |
| `--foreground` | `#0f1c18` | `161.5 30.23% 8.43%` | **16.05:1** on canvas. `pillars.svg:8` spine gradient stop |
| `--foreground-secondary` | `#40564c` | `152.7 14.67% 29.41%` | 7.26:1 |
| `--muted-foreground` | `#5d7269` | `154.3 10.14% 40.59%` | 4.72:1 |

**Pillar ink / mark split (light).** The `-700` family fails AA on
`--surface-chrome` (green 4.30, amber 4.31); the `-800` family passes on all
three surfaces:

| Pillar | `-ink` (text) | canvas / chrome / card | `-mark` (fill, ≥3:1) |
|---|---|---|---|
| substrate | `#166534` | 6.54 / 6.12 / 7.13 | `#15803d` (4.60 / 4.30 / 5.02) |
| authority | `#92400e` | 6.50 / 6.08 / 7.09 | `#b45309` (4.60 / 4.31 / 5.02) |
| evidence | `#155e75` | 6.66 / 6.23 / 7.27 | `#0e7490` (4.91 / 4.60 / 5.36) |

Light severity: LOW `#4f6b5e` (5.35), MEDIUM `#8a6114` (5.07), HIGH `#b45309`
(4.60), CRITICAL `#b3261e` (5.99), all vs canvas.

**Alternative rejected:** keeping Ambush's dark-only identity and shipping no
light mode. Rejected because Buzz's `dark:` variant is bound to the root class,
not `prefers-color-scheme`
(`@custom-variant dark (&:where(.dark, .dark *));`, `globals.css:36-37`), so a
dark-only build still carries the whole two-theme machinery; and because a SOC
analyst on a laptop in a lit room is a real user. Ambush loses nothing: the dark
theme is the default and the one every screenshot uses.

### 2.5 The security-semantic ramps

These are the tokens Buzz has no analogue for. Each is a *closed* set matching a
Rust enum, and each has a non-color encoding.

**Posture — `SwarmMode`** (`crates/swarm-core/src/agent.rs:112-119`):

| Mode | Chrome treatment | Non-color |
|---|---|---|
| `Normal` | no rail | word `NORMAL` |
| `Alert` | 2.5px amber rail on the governance strip | word `ALERT` |
| `Incident` | amber rail + persistent header band | word `INCIDENT` |

Never animated. A mode transition to Incident is one of exactly four
notification classes allowed to wake someone.

**Correction to an earlier draft, which mattered:** this document previously
described `SwarmMode` as monotonic. It is not. `transition_to`
(`agent.rs:137-146`) does reject any non-upward move (`if mode <= self.current
{ return false; }`), but a separate `transition_down` (`agent.rs:148`) exists on
the same type. So the chrome must render de-escalation as a first-class
transition — Incident is not a terminal state, and a header band that can only
appear is a band an operator will learn to ignore once it is wrong.

**Containment state** (`ContainmentLeaseView`,
`crates/swarm-runtime-http/src/http/containment.rs:71-88`). The struct's own doc
comment at `:78-81` is the spec: *"`ContainmentLease::remaining_ms` SATURATES AT
ZERO, so this field alone cannot distinguish 'expires in an instant' from
'expired an hour ago and the sweep has not managed to release it'."* The
saturating method itself is `swarm-response/src/containment.rs:276`.

| State | Derivation | Token | Non-color |
|---|---|---|---|
| open | `!expired && remaining_ms > 0` | `--pillar-evidence` | countdown `mm:ss` |
| expiring | `remaining_ms < 15_000` | `--sev-high` | countdown + `EXPIRING` |
| **expired, still listed** | `expired == true` | `--danger-mark` | `EXPIRED — HOST STILL CONTAINED` |
| released | absent from listing | `--muted-foreground` | `RELEASED` |
| release failed | `lease_closed == false` on a 200 | `--danger-mark` | `RELEASE FAILED` |

`remaining_ms` and `expired` render as **two separate facts on two lines**. A
single progress bar that reaches zero is forbidden. `lease_closed` and
`fully_reversed` are read from the response body
(`ContainmentReleaseResponse`, `containment.rs:129-145`), never from the HTTP
status — the handler at `:239-246` returns 200 with `lease_closed: false` when
the inverse failed, deliberately.

**Rollback outcome — `RollbackStepStatus`**
(`crates/swarm-response/src/rollback.rs:211-223`): five variants, five
renderings, never collapsed to success/failure.

| Variant | Rendering | Hue |
|---|---|---|
| `Reversed` | `REVERSED` | `--pillar-evidence` |
| `Simulated` | `SIMULATED — no real target touched` | `--muted-foreground` + hatched fill |
| `Irreversible` | `IRREVERSIBLE — no inverse exists` | `--sev-high` |
| `Unsupported` | `UNSUPPORTED — adapter cannot execute` | `--sev-high` |
| `Failed` | `FAILED` | `--danger-mark` |

`RollbackStepStatus::restored()` is strict — `matches!(self, Self::Reversed)`
(`rollback.rs:227-229`) — so the header badge reads from `fully_reversed` and
the step list reads from the variants, and they are allowed to disagree visibly.

**Verdict — the human act.** `ProvidenceFeedbackAction` is exactly
`Confirm | Dismiss | Investigate` (`crates/swarm-core/src/types.rs:112-116`),
plus Grant / Refuse on a hold. These render as a distinct family: **ink-on-neutral
chips with a leading glyph, never a filled primary button.** The grant control is
a `verdict` variant that has no `bg-primary` path at all — it is structurally
impossible to style it as a primary action, which is how the brief's render law
6 gets mechanized rather than remembered. See §2.8 for the CI guard.

**Confidence** is continuous `0.0..1.0`. It is *never* a hue. It renders as a
five-dot meter in the pillar hue at 0.25/0.5/0.75/1.0 opacity steps, plus the
numeral to two decimals. Reason: `min_confidence` / `max_confidence` are literal
policy-rule fields (`rulesets/default.yaml:65-66,76-77`), so an operator
comparing a finding to a rule needs the number, not a vibe.

### 2.6 Signature provenance: what is actually signed

A red-team pass found that this document, and four of its peers, rendered
"verify the Ed25519 chain" as though every card had a signature to check. It
does not. This section is the ground truth, verified artifact by artifact, and
the badge design that follows from it.

| Rendered artifact | Signature of its own? | Where, verified |
|---|---|---|
| `PheromoneDeposit` | **Yes** — `signature: Vec<u8>` + `agent_key: Vec<u8>` over a canonical `DepositSigningPayload` | fields `swarm-core/src/pheromone.rs:231-234`; payload `swarm-pheromone/src/substrate.rs:99`; hot-path signer `swarm-runtime/src/detection/pipeline.rs:265-293`; also `sphinx_agent.rs:640-641`, `stalker_agent.rs:237-238`, `providence_handlers.rs:557-558`. **Constructed unsigned** by `findings_to_deposits` (`swarm-whisker/src/stream.rs:48-49` sets both to `Vec::new()`) and signed one layer up. Never published to the relay (`03 §4.1`) |
| `ConsensusGovernanceReceipt` (a governance attestation) | **Yes** — detached Ed25519 over canonical JSON, plus a signer-identity derivation check | `swarm-consensus/src/lib.rs:426-449` |
| Approval-ledger vote | **Yes** — a detached vote signature plus a hash-chained spine envelope | `swarm-runtime/src/approval.rs:1783-1830`. This is the **only** non-test, non-vendor caller of `build_signed_envelope` (`swarm-spine/src/envelope.rs:71`) in the entire workspace |
| `RollbackReceipt` | **No signature of its own.** Carries `governance_attestation: Option<Value>` (an opaque `ConsensusGovernanceReceipt`) plus id links back to the origin and governance receipts | `swarm-response/src/rollback.rs:242-278` |
| `ResponseReceipt` | **No.** `audit.governance.receipt` is an untyped `Option<serde_json::Value>` that *may* hold an attestation | `swarm-response/src/lib.rs:98-142`; populated at `:242-246` |
| `DetectionFinding` | **No** — seven fields, none a signature | `swarm-whisker/src/detector.rs:50-59` |
| `SwarmFindingEnvelope` (the payload of `RuntimeEvent::Finding`) | **No** — eight fields | `swarm-response/src/siem.rs:17-27` |
| `AuditTrail` | **No** | `swarm-spine/src/lib.rs:113-121` |
| The hold | Does not exist yet | — |

Two further facts kill the "verify the chain linkage" affordance as written:
`verify_chain_link` and `ChainLinkVerdict` (`swarm-spine/src/chain.rs:20,75`)
have **zero** consumers anywhere outside `chain.rs`'s own test module and the
re-export at `swarm-spine/src/lib.rs:67` (grepped). And the one real
verification path, `verify_release_attestation`
(`swarm-runtime/src/containment.rs:234-268`), runs **two** checks — signature,
and subject binding via `proposal_id == sha256(canonical(receipt minus
attestation))` — and explicitly does **not** run a third. Its own doc comment
and `docs/decisions/0010-containment-release-goes-through-the-daemon.md:125-138`
say so in the same words: there is no trust anchor, a full re-attestation
passes, and `attestation_verified: true` means *"this attestation matches this
body"*, not *"a governor we trust authorized this"*.

**So the AttestationBadge is respecified.** It is not a badge with two states.
It is a two-row provenance block, always both rows, on every evidence card,
verdict pane and export:

```
AMBUSH RECORD   ed25519 · <one of five states below>
RELAY ENVELOPE  secp256k1 · signed by <npub, full> · transport only
```

Row 1 states, in `--pillar-evidence` ink except where noted:

| State | When | Rendering |
|---|---|---|
| `SIGNED · SUBJECT-BOUND` | a `ConsensusGovernanceReceipt` verified, and its `proposal_id` matched the derived digest | the sentence `attestation matches this body`, plus a mandatory second line naming the absent third check (ADR 0010:125-131). No shield, no lock, no green check. |
| `UNATTESTED` | `governance_attestation: None` | `--sev-high`. Absence is a state, not a default. |
| `ATTESTATION FAILED` | `verify_release_attestation` returned `Err` | `--danger-mark`, with `attestation_error` printed verbatim |
| `NO SIGNATURE OF ITS OWN` | finding, escalation, hold and bare-receipt cards | `--muted-foreground`, with the sentence `this card is a copy; the daemon holds the record` and a **verify** affordance that re-fetches the artifact from the daemon by id |
| `SIGNED DEPOSIT` | the one artifact that is routinely signed end to end | only reachable on a deposit detail, which the console reads via the deposits route, never from a published card |

Row 2 is never omitted and never merged into row 1. A relay envelope signature
proves the bridge published the bytes; it proves nothing about Ambush. Merging
the rows is how "trust the bridge" silently replaces "trust the receipt", which
is the failure this whole taxonomy exists to prevent.

**The branch this document does not own.** `03-DOMAIN-EVENT-MAPPING.md` §11 owns
the Ambush backend bill. If a sixth item lands there — wrapping each published
fact in `build_signed_envelope` before it leaves the daemon, which is the same
one-call pattern `approval.rs:1810` already uses — then the finding, escalation,
hold and receipt cards move from `NO SIGNATURE OF ITS OWN` to
`SIGNED · SUBJECT-BOUND` and nothing else in this design system changes: the two
rows, the five states and the verify affordance are the same components. That is
the point of specifying it as a state machine rather than a badge. Until that
item lands, **no Perch surface, screenshot, hero mock or exit criterion may
claim an Ed25519 verification it cannot run.**

### 2.7 Two badge families, and the count that is wrong

The panel asserted "3 receipt-gated actions". It is false and must not
propagate. `crates/swarm-policy/src/static_gate.rs:37-53`
(`StaticApprovalGate::destructive_action`),
`crates/swarm-runtime/src/dispatcher.rs:1276-1292`
(`response_action_requires_governance_receipt`) and
`crates/swarm-agents/src/tom_agent.rs:1276` (`destructive_action_kinds() ->
[&'static str; 12]`) each enumerate the **same twelve** destructive actions out
of fifteen `ResponseAction` variants (`crates/swarm-core/src/types.rs:419-468`);
the three non-destructive are `TriggerEdrScan`, `DeployDecoy`, `Escalate`.
Separately, `ContainmentInverse` has exactly **three** variants —
`ReleaseQuarantinedFile`, `ResumeProcess`, `RestoreHostConnectivity`
(`crates/swarm-response/src/rollback.rs:66-78`).

So Perch ships **two badge families and they mean different things**:

| Family | Set | Badge | Token |
|---|---|---|---|
| Destructive / human-gated / receipt-required | 12 of 15 | `DESTRUCTIVE` | `--sev-high` outline |
| Reversible | 3 (by inverse, not by action) | `REVERSIBLE` | `--pillar-evidence` outline |

The mapping is non-obvious and must be shown, not inferred: `SuspendProcess` is
reversible, `KillProcess` is not. A third axis — *which rule decided* — is a
text line, not a badge, because it names a rule from `policy.rules` in file
order. `08-TRUST-AND-GOVERNANCE-UX.md` owns the full 15-row matrix; this
document owns only the two visual families and the rule that they must be
visually unrelated, so no operator can read one as a stronger version of the
other.

`README.md:217-218` still says "Three are destructive — `BlockEgress`,
`IsolateHost`, `RevokeCredential`". That is a documentation defect the console
corrects, and `01-POSITIONING.md` uses the correction as positioning.

### 2.8 What Perch deletes from Buzz's color layer

| Deleted | Why | Cost |
|---|---|---|
| 10-swatch accent picker (`ThemeProvider.tsx:44-55`, incl. Green `#22c55e`, Orange `#f97316`, Red `#ef4444`) | `applyAccentColor` (`:198`) writes `--primary`, `--sidebar-primary` and `--sidebar-active` **inline on `document.documentElement`** at `:213-218` and `:231-236`, on every theme or accent change (`:417`, `:460`, `:633`). Inline root styles beat every stylesheet layer, so a red primary button makes a red CRITICAL badge meaningless and no token file can defend against it. | Users lose personalization. Named in the settings page. |
| 62-theme Shiki picker (`SYNTAX_THEMES`, `theme-loader.ts:64-129`, 62 entries) | `createThemeVars` sets `--muted-foreground: hexToHsl(syntaxComment)` (`adaptive-theme.ts:259`), so a theme choice changes how faint a severity label is. The security ramp cannot be derived from three syntax colors. | Keep 2–3 syntax themes for the *code block and PTY* only, which is what `terminal-palette.ts` derives its 16-color ANSI set from. |
| `--chart-1..5` | Defined at `theme.css:34-38` (light) and `:100-104` (dark), never emitted by `createThemeVars`, never mapped in `tailwind.config.js`'s `colors`, and consumed by exactly one decorative cold-boot gradient (`animations.css:715,719,727`). They would silently stay Catppuccin under the Perch theme. | None — see §8.3 for the replacement. |
| 10 `--huddle-*` vars | Huddle is deleted; the vars are emitted by `createThemeVars` (`adaptive-theme.ts:244-253`, derived from `:217-232`) so the theme engine itself must be edited, not just a stylesheet. | One editing pass in `adaptive-theme.ts`. |
| `badge.tsx`'s `warning` / `success` / `info` variants | `bg-amber-500/15`, `bg-emerald-500/15`, `bg-blue-500/15` (`badge.tsx:16-18`) are stock Tailwind hexes outside the Ambush palette, and "success green" directly contradicts pillar-green-means-detection. | Callers migrate to the `severity` / `pillar` / `verdict` / `state` variant groups. |

---

## 3. Typography

### 3.1 The rem contract, inherited whole

Buzz derives every text size from a virtual rem:
`--buzz-type-rem: calc(1rem * var(--buzz-type-scale))`
(`desktop/src/shared/styles/globals/typography.css:16-17`). Cmd +/- scales the
*real* root font-size while pinning the native webview zoom to 1.0; the
Font-size preference nudges only `--buzz-type-scale` (the 13/14/15px contract at
`typography.css:44-52`).

**Why this matters more for Perch than it did for Buzz.** A console that runs on
a 55" wallboard eight feet from the analyst *and* on a 13" laptop is the exact
case rem-based zoom exists for. A hardcoded `13px` timestamp is frozen at 13px
on the wallboard — which is the regression Buzz already shipped and fixed
(PR #891, per the repo CLAUDE.md and the guard's own header comment).

The guard is real and Perch adopts it verbatim. `desktop/scripts/check-px-text.mjs`
is a thin config over a shared engine at `scripts/check-px-text-core.mjs`, whose
two regexes (`:29`, `:32`) reject `text-[NNpx]`, `text-[N.NNrem]`, `text-[N.NNem]`
and `font-size: NNpx` across every `.ts`/`.tsx`/`.css` file under `src`, with a
four-entry allowlist (`check-px-text.mjs:26-31`, all `text-[6rem]`/`text-[4rem]`
avatar glyphs). **This guard will fire on hand-authored SVG chart labels** unless
axis text uses named tokens — which is the constraint that shapes §8, and a good
one.

### 3.2 Mapping Ambush's SVG ramp onto Buzz tokens

Ambush's assets use a five-step ramp — 13.5 / 11.5 / 10.5 / 9.6 / 8.8 — plus a
102px wordmark (`hero-v2.svg:99`). Mapped onto real tokens (no new arbitrary
literals):

| Ambush SVG | Perch token | Value at 16px rem | Use |
|---|---|---|---|
| 20 (`SWARM`, `pillars.svg:36`) | `text-xl` | 20px | Page titles via `PageHeader` |
| 13.5 (`Whisker`, `colony.svg:12`) | `text-sm` | 14px | Body, agent names, conversation |
| 12.5, tracking 5.2 (`hero-v2.svg:98`); 12, tracking 4.4 (`pillars.svg:23`) | **`text-eyebrow`** (new) | 12px / `0.34em` | System state labels, section identity |
| 10.5 (`concentration`, `stigmergy.svg:54`) | `text-2xs` | 11px | Chart axis, meta rows |
| 9.5–9.6 (machine values, `colony.svg:52`) | `text-2xs` mono | 11px | IDs, hashes, thresholds |
| 8.8 (`hot-path detect`, `colony.svg:13`) | `text-3xs` | 8px | Tracking labels, count glyphs only |

**One new size token.** `text-eyebrow` is added to `desktop/tailwind.config.js`
`theme.extend.fontSize` (which already carries `2xs`, `3xs`, `badge`, `message`,
`message-timestamp`, `title` and `nsec-key` at `:11-35` — this is the
established extension point, not a new mechanism). It is rem-based, because the
uppercase wide-tracked eyebrow is Ambush's single most identifiable typographic
gesture and Buzz's closest match (`Badge`'s `text-2xs uppercase
tracking-[0.18em]`, `badge.tsx:7`) is a *pill*, not a label. The existing
`badge` token (0.625 rem, 10px) is a different size for a different job and is
not reused. Adding a token rather than a literal is exactly what the px-text
guard's failure hint instructs.

```js
// desktop/tailwind.config.js — theme.extend.fontSize
eyebrow: [
  "calc(var(--buzz-type-rem) * 0.75)",           // 12px at a 16px type rem
  { lineHeight: "1", letterSpacing: "0.34em", fontWeight: "600" },
],
```

### 3.3 The mono discipline

Ambush's SVGs are rigorous about this and Perch codifies it as a rule:

> **Sans for prose, mono for anything a machine produced or a human must
> compare character by character.**

Mono is mandatory for: `agent_id`, `hunt_id`, `lease_id`, `receipt_id`,
`rollback_id`, hashes, `strategy_id`, host ids, thresholds, `remaining_ms`,
IP/domain indicators, ATT&CK technique ids, and the RFC 8785 canonical bytes on
any signature surface. `colony.svg` follows exactly this split: agent names in
sans-700 13.5 (`:12,18,23`), roles in mono 8.8 (`:13,19,24`).

**One new family token.** `tailwind.config.js:73-80` declares `fontFamily.sans`
(Inter Variable, shipped as `@fontsource-variable/inter`, `package.json:33`) and
**no `mono` family at all**. JetBrains Mono is already a dependency
(`@fontsource/jetbrains-mono`, `package.json:34`) but is bound only inside
`terminal.css:7,190-191` and one `ui-monospace` fallback at `markdown.css:277`.
So the rule above is currently inexpressible in Tailwind and would be enforced
by ad-hoc CSS. Perch adds `fontFamily.mono: ['"JetBrains Mono"', "ui-monospace",
"SFMono-Regular", "Menlo", "monospace"]`, which is exactly the stack Ambush's own
SVGs specify. `font-variant-numeric: tabular-nums` is mandatory on every
countdown, every concentration value and every count, or a 1 Hz lease timer will
shimmer horizontally.

---

## 4. Space, radius, elevation, border

**Spacing.** Tailwind's default scale plus Buzz's `4.5` (`1.125rem`) and the
four conversation gap variables (`tailwind.config.js:66-72`). No additions.
Perch's density modes reuse those four variables (§10).

**Radius.** One token, inherited: `--radius: 0.625rem` (10px), mapped to
`rounded-lg` / `md` (−2px) / `sm` (−4px) (`theme.css:4`,
`tailwind.config.js:61-65`). This is *already* Ambush's radius: `pillars.svg:27`
uses `rx="10"` on cards, `colony.svg:11,17,22` uses `rx="7"` on agent chips (=
Buzz's `rounded-sm`, 6px, close enough), `security-v2.svg:8,13,18` uses `rx="9"`.
The two systems agree by accident; do not disturb it.

**Squircle smoothing.** Buzz applies runtime corner smoothing at
`SMOOTH_CORNER_SMOOTHING = 0.6` (`desktop/src/shared/ui/smoothCorners.ts:36`).
Perch keeps it on media and code surfaces and **removes it from data surfaces** —
a smoothed corner on a chart frame costs a DOM mutation per resize on a surface
that resizes constantly, and buys nothing at 10px radius.

**Elevation.** Perch uses **four** levels and they are borders-and-value, not
shadows. Ambush's assets contain zero drop shadows; the workbench's
`box-shadow:0 10px 25px rgba(29,36,51,.06)` (`render.rs:49`) is a Material tic
that does not survive on `#0a1210`.

| Level | Surface | Border |
|---|---|---|
| 0 canvas | `--background` | — |
| 1 card | `--card` | `--border` 1px |
| 2 popover / dialog | `--popover` | `--border-strong` 1px |
| 3 raised chip / inline code | `--surface-raised` | none |

Buzz's `shadow-panel-left` (`tailwind.config.js:50-59`) is retained for the
auxiliary panel only — it solves a real geometry problem its own comment
documents (a left-facing edge casts nothing from a y-offset shadow) that no
border can.

**Borders carry meaning.** `pillars.svg:27,46,64` gives each pillar card a
*differently colored* 1px stroke — `#1e3a2e` green, `#3a3020` amber, `#1d3740`
cyan — on an identical `#0c1613` fill. Perch adopts this:
`--border-pillar-substrate`, `--border-pillar-authority`,
`--border-pillar-evidence` at exactly those values, on evidence cards. It reads
as tint at a glance and as classification on inspection, which is the correct
information density for a triage list.

---

## 5. Iconography

Buzz uses `lucide-react` in **338 files** (counted) with exactly three custom
icons built via `createLucideIcon` so they inherit stroke width and size
(`desktop/src/shared/ui/icons.ts:3,12,22`). Perch keeps lucide as the base and
follows that extension pattern.

**What lucide covers well:** shell/terminal, file, search, filter, clock,
bell/bell-off, check, x, chevrons, alert-triangle, lock, key, network, server,
activity, git-branch.

**What a security domain needs that lucide lacks** — nine custom icons, all
`createLucideIcon`, 24×24, 2px stroke, all `aria-hidden` with a text label
beside them:

| Icon | Depicts | Why not lucide |
|---|---|---|
| `pheromone-deposit` | dot on a dashed trail | Nothing in lucide means "signed observation on a decaying substrate" |
| `concentration-crossing` | curve crossing a dashed line | The single most important event in the product |
| `containment-lease` | bracket with a countdown notch | `lock` implies permanence; a containment expires |
| `inverse-plan` | mirrored arrow with a break | Distinguishes *reversible* from *undo* |
| `receipt-chain` | three linked hash blocks | `link` is a hyperlink everywhere else |
| `hold` | pause bar inside a gate | `pause` is a media control |
| `evaporation` | fading dot stack | Suppression and decay are different and both need glyphs |
| `blast-radius` | concentric arcs from a host | `radius`/`target` both read as "aim" |
| `gap` | dashed outline of a covered region | For `/gaps`; an empty state that is a *fact*, not an absence |

**Explicitly not built: a shield.** `docs/decisions/0010-…:125-138` is
unambiguous that `attestation_verified` is not a trust statement, and §2.6 shows
that most cards have nothing to verify at all. A shield glyph asserts
protection. Perch has no shield anywhere, including in the icon set, so it
cannot be reached for.

**Agent and role identity.** Eight roles, closed enum
(`crates/swarm-core/src/agent.rs:17-34`), plus N instances each. Three layers:

1. **Role glyph** — eight hand-drawn 20×20 marks, one per role, tinted by the
   role's pillar. `colony.svg` already assigns them: Whisker and Calico green
   (writers, `:11,17`), Stalker/Weaver/Sphinx/Kitten cyan (readers,
   `:22,28,33,38`), Tom and Pouncer amber (`:43,46`). Perch uses that assignment
   verbatim; it is a real architectural fact rendered as color, and the file's
   own aria-label at `:1` states it in prose.
2. **Instance identicon** — `BotIdenticon` (jdenticon) seeded on the *Ed25519*
   key, so `Whisker-7a3f` and `Whisker-b210` are distinguishable in a dense
   list without reading hex.
3. **Key** — `<PubKey>` (`desktop/src/shared/ui/PubKey.tsx:21-31`), `compact` in
   lists, **`full` on every security-decision surface** — a doctrine the
   component's own doc comment already states, for the right reason ("a
   truncated key is forgeable by vanity grinding"). Perch extends
   `check-pubkey-truncation.mjs` — itself a thin config over
   `scripts/check-pubkey-truncation-core.mjs` — to Ed25519
   `swarm:ed25519:<64 hex>` ids, per the brief's C6. Note that six of its
   current overrides point at `features/huddle` and `features/projects`, which
   Perch deletes; the allowlist shrinks rather than grows.

The two-chain rule applies to the icon layer too: an agent row shows *which* key
it is showing. `ed25519` and `npub` are visually distinct affixes, never
interchangeable, never both truncated to the same eight characters.

---

## 6. The verdict control and its guards

The brief's render law 6 says the grant control must say "record my decision and
send it to the daemon", never "approve", *in a component that cannot be styled
as a primary action without failing a check*. That sentence is a design-system
obligation, so it is mechanized here.

**Keys.** `04-SURFACES-AND-UX.md` §3.0 settles the keymap and this document
follows it: `C` / `D` / `I` for Confirm / Dismiss / Investigate on a finding,
`G` / `R` for record-Grant / Refuse on a hold, `S` snooze, `E` escalate/open
case, `J`/`K` to move, `Enter` to open. The brief's `A`/`D`/`E`/`S` is **not**
used: `A` for "approve" is the exact word render law 6 forbids, and `D` cannot
mean both Dismiss and Deny when holds and findings interleave in the same lane
and the same detail pane. Under the old map, `D` on one row refused a
destructive action and `D` on the adjacent row retroactively deleted deposits
from the concentration sum (§8.2 law 3). `A` goes on the CI ban list alongside
"Approve".

**Three guards, all cheap:**

1. `tools/check-copy-banned-terms.sh` (owned by `06-COPY-AND-VOICE.md`) gains
   `Approve` as a control label, bare `lane` outside the nav sense, and the
   literal key binding `"A"` in any verdict keymap constant.
2. A CI check fails when the grant control's component is rendered with
   `variant="default"` or any class matching `bg-primary`. The `verdict` variant
   group has no primary path, so this catches only deliberate override.
3. `check-px-text` already prevents the control from being enlarged into
   prominence by an arbitrary literal.

**Asymmetric friction is a visual property, not only a behavioural one.**
`08-TRUST-AND-GOVERNANCE-UX.md` owns the interaction (Refuse is one keypress,
Grant is scroll-gated). This document owns the consequence: the two controls
must not be a matched pair. Refuse is a chip; Grant is a full-width outlined
control in a modal, secondary-styled, with the sentence as its label rather than
a verb. They should not look like siblings, because they are not.

---

## 7. Motion

Buzz's motion system is already tokenized and restrained: four durations
(120 / 180 / 240 / 500ms), two eases, a 0.75rem arrival distance and a 2px
arrival blur, each primitive paired with a `prefers-reduced-motion` block
(`desktop/src/shared/styles/globals/motion.css:8-22`).

**The Perch principle:** *motion is a claim that production changed.* Buzz can
afford decorative motion because a message arriving is a message arriving. In
Perch, a thing that moves is asserting that a host was contained, a deposit
landed, or a containment is running out. Ambient motion that means nothing
trains an operator to ignore motion that means something.

**Four allowed motion classes.** Everything else is static.

| Class | Trigger | Duration | Reduced-motion |
|---|---|---|---|
| `arrival` | a new row lands in a live list | `--motion-duration-arrival` 500ms, one-shot | 1ms (inherited pattern) |
| `state-change` | a badge, chip or rail changes value | `--motion-duration-fast` 180ms crossfade | 1ms |
| `crossing` | concentration crosses a threshold | one 3s pulsing ring, **fires once**, then the point is static | no ring; the point renders 1.5× with a static halo |
| `countdown` | containment `remaining_ms` | continuous numeric, 1 Hz | unchanged — this is data, not decoration |

The `crossing` ring is `stigmergy.svg:52` (`r: 5→15`, `stroke-opacity:
0.75→0`, `dur=3s`) with one change: `repeatCount="indefinite"` is dropped. In
the README it loops forever because it is illustrating a concept. In Perch,
looping it would mean "this host is crossing the threshold, continuously", which
is false three seconds after it happened.

**Banned.**

- `animate-pulse` on any status indicator. `AgentStatusBadge` applies
  `motion-safe:animate-pulse` whenever an agent is working
  (`desktop/src/features/agents/ui/AgentStatusBadge.tsx:58`). With 8 roles × N
  instances that is dozens of simultaneously pulsing badges — a photosensitivity
  hazard and an attention sink. Perch's fork of that component keeps the 15s
  presence grace period (`AgentStatusBadge.tsx:8,26-31`, which correctly stops a
  restart from flapping the UI) and drops the pulse.
- Looping `animateMotion`. The eight travelling dots are the brand's signature
  and they stay on the marketing site.
- Any animation above 3 flashes/second, anywhere, ever.
- `motion` v12 spring physics on data surfaces. Retained only for panel and
  dialog entrances, via the existing `modalMotion.ts` / `popoverSurface.ts`
  class constants.

**One deliberate exception: `/watch-floor`.** The Watchfloor is a wall screen
(route per `04-SURFACES-AND-UX.md` §1.1, renamed from the brief's `/watch` because
that collided with The Watch at `/`). It may run one continuous animation — the
decay field's 1 Hz refresh — because its entire purpose is to be a physics view
of a live system. It is opt-in (not the homepage, by explicit decision in the
brief), it respects `prefers-reduced-motion` by snapping to 1 Hz discrete steps
with no tweening, and it carries a visible `LIVE · 1 Hz` label so a frozen
screen is detectable.

Screenshot specs must call `waitForAnimations` (`desktop/tests/helpers/animations.ts`)
before any capture, which races `document.getAnimations()` against a 1s ceiling
precisely because looping animations never settle — a second reason Perch has
almost none.

---

## 8. Data-visualization language

This is net-new. Buzz has **no charting library** in any `package.json`
(grepped for recharts, chart.js, d3, victory, nivo, visx, echarts, plotly,
apexcharts — none present), no data grid (the only `<table>` is a 20-line
`MarkdownTable.tsx`), and its `--chart-1..5` tokens are consumed by exactly one
decorative gradient. Perch builds all of it.

**Decision: hand-authored SVG, no library.** Rationale, in order: (1) the Tauri
CSP is tight and asset-specific — `default-src 'self'` with `script-src 'self'
'wasm-unsafe-eval' https://cdn.jsdelivr.net/npm/@mediapipe/`
(`src-tauri/tauri.conf.json:39`), so every CDN-delivered chart library needs a
fresh CSP edit and a bundled one needs an audit; (2) a security product should
not add a transitive dependency graph to draw seven shapes; (3) chart libraries
inject px font sizes, which fails `check:px-text`; (4) every one of Perch's
seven forms is domain-specific enough that a generic library's defaults would
have to be fought. The cost is real — roughly 1,200–1,800 LOC of SVG components
and no free tooltips, legends or brushing — and it is stated in
`09-ROADMAP-AND-RISKS.md`'s sizing, not hidden here.

### 8.1 The seven forms

**(a) Concentration / decay curve** — the flagship. `stigmergy.svg` *is* the
spec: a green area fill on a `0.30 → 0.02` vertical opacity gradient
(`stigmergy.svg:4`, painted at `:46`), a 2px solid stroke (`:47`), a dashed
amber threshold rule at `stroke-dasharray="5 5"` (`:48`) labelled with the
literal value (`alert_threshold 1.20`, `:49`), a vertical drop-line (`:50`) and
a ring at the crossing (`:51-52`).

Three hard requirements the illustration already satisfies and Perch must not
lose:

1. **The curve is labelled as interpolation.** `strength(t) = confidence ·
   0.5^((t − timestamp) / decay_half_life)` is evaluated client-side between
   server-supplied samples. The header shows the runtime's own `total_strength`
   from the deposits route; the curve carries an `interpolated · runtime says
   N.NN` caption. If they disagree, the caption turns amber and states the
   delta. (Brief risk 3.)
2. **Deposit ticks are drawn above the curve, not under it** — `stigmergy.svg`
   draws each detector's deposit train as a separate dotted row above the chart
   with the indicator inline (`198.51.100.20:4444`, `WINWORD → powershell`).
   That layout is the correct one: it shows *which* detector contributed each
   step, which is exactly what the escalation predicate cares about.
3. **Suppression is a drawn region, not an absent one.** Verified:
   `is_suppressed_by_feedback` (`crates/swarm-pheromone/src/substrate.rs:1367-1380`)
   returns true when a `Dismiss` marker sharing the deposit's suppression key
   carries a timestamp `>=` the deposit's — so a Dismiss retroactively removes
   every earlier matching deposit from the sum computed at `:1286-1295`, and
   from the deposit listing at `:1325`. The chart renders the suppressed region
   as a hatched fill with a `DISMISSED @ <time> by <operator>` marker line, and
   the curve visibly steps down at the marker. A dismissal that silently
   flattens a curve is the single easiest way to make this product untrustworthy.

**Unit trap, called out because it will bite:** the pheromone lane is unix
**seconds** (`PheromoneDeposit::timestamp`, `decay_half_life`, both documented
as seconds at `swarm-core/src/pheromone.rs:219-222`) while everything else is
unix **milliseconds** (`*_at_ms`). A shared TS time helper produces 1000×-wrong
decay curves. Perch's chart layer takes a branded `PheromoneSeconds` type, never
a bare number. (`07-REALTIME-AND-DATA.md` owns the branded-type contract; this
document owns the chart API's obligation to demand it.)

**A dependency worth naming:** `filter_deposits` (`substrate.rs:1306-1334`)
applies suppression but **not** evaporation, while `concentration_for`
(`:1268-1304`) applies both. So the deposit ticks and the curve are computed by
two functions with different filters. `03 §11` item 4 and `07 §…` require the
deposits route to return the post-suppression *and* post-evaporation slice; if
it does not, the tick train and the curve will disagree on screen and the
disagreement will look like a rendering bug rather than an API one.

**(b) Host heat** — a sorted bar list, not a treemap and not a heatmap grid.
Rows are hosts, bar length is post-suppression `total_strength`, bar hue is the
dominant threat class's pillar, and the row carries `N sources / M agents`.
Sorted lists beat 2-D encodings for "which three hosts do I look at" and they
virtualize with the `VirtualizedList` Perch already inherits.

**(c) Kill-chain / correlation graph** — a left-to-right DAG over
`CorrelatedIncident`'s `included_members` and `rejected_members`, with edges
typed by `IncidentEvidenceLink`'s Temporal / Causal / Entity / Semantic
dimensions rendered as four distinct dash patterns (solid / 4-2 / 2-2 / 6-3),
*not* four colors — the pillar hues are already spoken for.
**`rejected_members` are drawn**, dimmed and below a rule, with their rejection
reason. An incident graph that only shows what was included is an argument, not
evidence.

**(d) Timeline** — vertical, single column, one row per typed event. Ambush's
own workbench already does this with a 4px colored left rail per event kind
(`render.rs:65-70`: a `#9fb2c8` default plus `.timeline-item.escalation`,
`.mode_transition`, `.agent_health`, `.response_execution`, `.ingest`). Perch
keeps the rail, restates the colors on the pillar taxonomy, and adds the
mandatory rows: a suppression row, a hold row, a decision row, and a
containment-open and containment-close row.

**(e) Sparkline** — 60px × 16px, no axes, one series, `stroke-width: 1.5`, last
point marked. Only ever adjacent to the number it summarizes. Used in lane
channel headers and the tuning bench.

**(f) Distribution** — a horizontal stacked bar for `AlertTuningRecommendation`
supporting-signal breakdowns, capped at five segments plus `other`.

**(g) Containment board** — not a chart, a table with one live column. Listed
here because it shares the tabular-numerals and 1 Hz-tick rules.

### 8.2 Three render laws, mechanized

**Law 1 — never a bare source count.** `findings_to_deposits` sets
`agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id)`
(`crates/swarm-whisker/src/stream.rs:46`), and that helper is literally
`AgentId(format!("{}:{strategy_id}", base.0))` (`:19-21`). `concentration_for`
then counts `sources.insert(deposit.agent_id.0.clone())`
(`crates/swarm-pheromone/src/substrate.rs:1295`) and reports
`distinct_sources: sources.len()` (`:1301`). So `distinct_sources` counts
*strategy-scoped* ids: one Whisker running four detectors registers as four
sources, and `pheromone.min_sources_for_escalation: 2`
(`rulesets/default.yaml:57`) is defeated by a single agent.

Every source count therefore renders as **`N sources / M agents`**, expandable
to the ids grouped by real agent. This is a component contract, not a
convention: the chart layer exposes no `sources` prop, only
`{ sourceIds: string[] }`, and derives both numbers itself.

**Law 2 — derived vs served.** Anything Perch computes that the runtime does not
carries a marker naming the function that computed it
(`derived · strength_at()`). The runtime's snapshot is authoritative.
Disagreement snaps to the served value visibly, with a reason row — never
silently.

**Law 3 — the operator identity is derived until the daemon carries it.** A
granted destructive action is, today, byte-indistinguishable in Ambush's own
records from an autonomous one except that `policy.verdict` reads
`require_human`: `ResponseReceiptAudit` carries only `ResponsePolicyAudit`
(verdict / rule_name / reason) and `ResponseGovernanceAudit`
(`governing_agent_id: AgentId` — Tom, not the human) at
`swarm-response/src/lib.rs:120-142`, and `AuditTrail`
(`swarm-spine/src/lib.rs:113-121`) has no approver field either. So until
`03 §11` threads an `approved_by` through, **the operator's name on a verdict
row is a Perch-side record and must carry the `DerivedMarker` treatment**, with
the marker naming its source (the relay's `ambush:verdict:v1` intent card, or
the daemon's hold store) rather than implying the audit chain answers "who approved
this". It answers "a human was asked". Rendering that honestly costs one line
and is the difference between an audit artifact and a claim.

### 8.3 The categorical palettes

Two closed sets, both needing more than three hues, both of which must not
collide with the pillar taxonomy.

**Twelve threat classes** (`standard_threat_classes()`,
`crates/swarm-runtime/src/escalation.rs:315-330`). Twelve categorical hues are
past the limit of reliable color discrimination, so: **threat class is encoded
by position and label, not hue.** The twelve lane channels are a fixed, ordered
list in the sidebar; a chart series is labelled inline at its endpoint (the way
`stigmergy.svg` labels each deposit row). Where a hue is genuinely needed (a
stacked bar), Perch uses a **6-hue rotation with a paired dash pattern**, so
twelve series are distinguished by hue×pattern and any two adjacent ones differ
on both channels. `ThreatClass::Custom(String)` lands in the nearest standard
lane and says so in text.

**Eight agent roles.** Encoded by the three-pillar color from `colony.svg` plus
the role glyph (§5). Eight distinguishable glyphs are easy; eight
distinguishable hues on a dark green ground are not.

**Replacing `--chart-1..5`:** Perch defines `--viz-series-1..6` in *both* theme
blocks — the defect in Buzz's tokens is that they are declared in `theme.css`
but never emitted by `createThemeVars` and never mapped in `tailwind.config.js`'s
`colors`, so a themed build silently keeps the Catppuccin values. Every SVG
sources color exclusively via `fill="var(--viz-series-2)"`. No hex ever appears
in a chart component.

### 8.4 Data-viz accessibility

- **Color is never the only channel.** Severity: word + 4-segment bar + hue.
  Series: label + dash pattern + hue. Containment: word + countdown + hue.
- **Deuteranopia is the design constraint**, because green and amber are the two
  most-used hues (308 and 79 uses) and they are the classic confusion pair. This
  is why the pillar hue never encodes severity: a deuteranope reading
  `--pillar-substrate` vs `--pillar-authority` as similar loses "detection vs
  authority", which is recoverable from position and label, rather than "MEDIUM
  vs CRITICAL", which is not.
- Every chart has a `<title>` and a full-sentence `aria-label`, following
  Ambush's own convention — all 19 SVGs carry `role="img"` plus a sentence-long
  `aria-label` (e.g. `stigmergy.svg:1`, `colony.svg:1`, `pillars.svg:1`).
- Every chart has a **`table` toggle** rendering the same data as a real
  `<table>`. This is also the screen-reader path and the copy-paste path.
- Axis labels use `text-2xs`/`text-3xs` tokens applied as CSS classes on
  `<text>`, never an SVG `font-size` attribute — the px-text guard scans `.tsx`
  and `.css` and would flag a `font-size:` literal, correctly.

---

## 9. Component inventory

`desktop/src/shared/ui` holds 69 `.tsx` + 15 `.ts` + 35 files under `markdown/`
(counted). Verdicts:

### Reuse verbatim (no edits)

`alert.tsx`, `avatar.tsx`, `button.tsx`, `checkbox.tsx`, `context-menu.tsx`,
`dialog.tsx`, `dropdown-menu.tsx`, `input.tsx`, `popover.tsx`,
`popoverSurface.ts`, `modalMotion.ts`, `modalBackdrop.ts`,
`OverlayPanelBackdrop.tsx`, `PortalledScrollArea.tsx`, `separator.tsx`,
`sheet.tsx`, `Shimmer.tsx`, `skeleton.tsx`, `sonner.tsx`, `spinner.tsx`,
`switch.tsx`, `tabs.tsx`, `textarea.tsx`, `toggle.tsx`, `card.tsx`,
`InlineChip.tsx`, `HoverCopyIndicator.tsx`, `PanelSectionGroup.tsx`,
`PageHeader.tsx`, `sidebar-menu-label.tsx`, `TopChromeBackdrop.tsx`,
`StartupWindowDragRegion.tsx`, `DrawerPanelIcon.tsx`, `TerminalPanelIcon.tsx`,
`VirtualizedList.tsx`, `AnimatedCount.tsx` + `animatedCountParts.ts`,
`segmented-control.tsx`, `progress.tsx`, `step-progress.tsx`,
`ViewLoadingFallback.tsx`, `identity-card-skeleton.tsx`,
`import-status-icon.tsx`, `chooser-dialog-content.tsx`, `smoothCorners.ts`,
`icons.ts`. — **44 files.**

`sidebar.tsx` is reused verbatim and is one of the highest-value inheritances:
resizable rail, collapsible groups, menu badges, skeletons. Note it is
**1,010 lines** (measured) and grandfathered by the differential file-size
ratchet — it may not grow by one line.

### Re-skin (token swap + semantics, no structural change)

| Component | Change |
|---|---|
| `badge.tsx` | Add `severity`, `pillar`, `verdict`, `state` variant groups to the `cva`. The base string (`text-2xs uppercase tracking-[0.18em]`, `badge.tsx:7`) is already exactly Ambush's chip. **Remove `warning`/`success`/`info`** (`:16-18`), whose Tailwind-palette hexes are outside the Ambush palette. |
| `alert-dialog.tsx` | Its action button is `buttonVariants()` with no variant (`alert-dialog.tsx:149`) — i.e. `bg-primary`. For a hold decision that must not read as a primary action, Perch passes an explicit `verdict` variant, and §6 guard 2 fails the build if it does not. |
| `PubKey.tsx` | Extend to two chains; label which one. Keep the compact/full doctrine (`PubKey.tsx:21-31`) unchanged — it is already the right security posture, for the right stated reason. |
| `tooltip.tsx` | `DEFAULT_TOOLTIP_DELAY_MS = 500` + `skipDelayDuration: 0` (`:9-10`) + `disableHoverableContent` (`:25`) is a chat policy. In a dense telemetry grid where the tooltip *is* the inspection affordance, Perch sets 150ms/300ms **on the data surfaces only**, via a scoped `TooltipProvider`, not globally. |
| `AgentStatusBadge.tsx` | Drop `motion-safe:animate-pulse` (`:58`); keep the 15s grace period (`:8`). |
| `WorkflowApprovalCard.tsx` | Today a 30-line stub whose body literally reads `"Approval actions are not yet available in Desktop."` (`:27`) inside an `amber-500/30` box (`:16`). Becomes the fixed-field-order verdict pane. |
| `markdown/CodeBlock.tsx` | Keep; retarget the Shiki theme to the pinned Perch pair. |
| `terminal-palette.ts` | Keep; it derives the 16-color ANSI set from the syntax theme, which is why the syntax-theme machinery survives at all. |

### Delete

`EmojiBurstProvider.tsx` (19,588 bytes), `PoofBurstProvider.tsx` (7,179),
`SpoilerParticles.tsx`, `VideoPlayer.tsx` (78,719 — the largest single file in
`shared/ui`), `VideoReview*` (5 files), `useVideoContextMenu.tsx`,
`videoAspectRatio*`, `videoDownload*`, `videoPlayerState.ts`, `carousel.tsx`,
`card-texture.css` + four PNGs totalling **3.3 MB** (measured), `buzz-logo/`,
`BuzzLoadingState.tsx`, `styled-qr-code.tsx`, `SimpleImageLightbox.tsx`, all GIF
and custom-emoji surfaces, the 10 `--huddle-*` vars. **Provider surgery
required**: `EmojiBurstProvider` and `PoofBurstProvider` wrap the whole tree at
`desktop/src/main.tsx:93-94`, inside `ThemeProvider` and `TooltipProvider`; this
is not a CSS deletion. Deleting huddle is 45 `.rs` files (counted) plus the 10
theme vars.

### Build new

| Component | Notes |
|---|---|
| `VerdictPane` | Fixed field order: ACTION → BLAST RADIUS → IF YOU UNDO → WHY WE ARE ASKING → WHAT GRANTING OPENS. Order is a `const` array, not JSX, so it cannot vary by action type. |
| `SeverityChip` / `SeverityBar` | Word + 4 segments + hue |
| `PillarRail` | The 2.5px top accent |
| `SourceCount` | Enforces `N sources / M agents`; takes `sourceIds`, not a number |
| `DerivedMarker` | The `derived · fn()` caption. Also carries law 3's operator-identity case. |
| `ProvenanceRows` | The two-row, five-state block from §2.6. Replaces the single "AttestationBadge" the earlier draft specified. |
| `ContainmentTimer` | Two facts, tabular numerals, 1 Hz |
| `RollbackStepList` | Five distinct statuses |
| `ConcentrationChart`, `HostHeatList`, `KillChainGraph`, `EventTimeline`, `Sparkline`, `DistributionBar` | §8 |
| `InstrumentationStrip` | The C9 counters (median seconds page-to-verdict, measurements written this week, fraction of recommendations from this week's verdicts, promoted/suppressed). **One home: The Watch (`/`), queue-1 header** — the only Phase-1 surface. `/tuning`, `/handoff` and `/watch-floor` render read-only restatements that link back to it. |
| `EyebrowLabel` | `text-eyebrow` wrapper |
| `RoleGlyph` | Eight marks |
| `GapCard` | The `/gaps` empty-state target |

### Housekeeping that must land first

`AppShell.tsx` is **997/1000** and `MessageRow.tsx` is **998/998** against the
hard cap (both measured this session). Split both before the first Perch
surface, and lift the renderer registry out of `MessageRow` before the first
evidence card, per the brief. `markdown.tsx` is **1,905 lines** and
grandfathered — **Perch's edits to it must be net-negative.**

---

## 10. Density

Two modes, reusing Buzz's existing mechanism (`data-conversation-density` on the
root, `typography.css:54-67`) rather than inventing one — and reusing its
existing **values**, so `typography.css` needs no edit:

| Variable | `comfortable` (default, `:36-39`) | `compact` (`:54-59`) |
|---|---|---|
| `--conversation-row-padding-block` | `0.25rem` | `0.25rem` |
| `--conversation-body-gap` | `0.125rem` | `0rem` |
| `--conversation-paragraph-gap` | `0.5rem` | `0.375rem` |
| `--conversation-list-item-gap` | `0.375rem` | `0.25rem` |

Two Perch-only additions live in Perch's own component CSS keyed off the same
root attribute, not in `typography.css`: inbox row height (~40px / ~30px) and
chart height (180px / 120px).

The mode names are Buzz's own attribute values and `04-SURFACES-AND-UX.md`'s
own words. An earlier draft of this document called the second mode `dense`,
which matched neither. `compact` is the wallboard and the 40-row containment
board. It changes **spacing only** — never type size, which is the Font-size
preference's job, and never what is shown, because render law 1 is positional.
Buzz's existing `spacious` mode (`typography.css:61-66`) is dropped; three
densities on a console is a settings page nobody reads.

---

## 11. Accessibility commitments

**Target: WCAG 2.2 level AA**, with three commitments beyond it.

1. **Contrast.** Every text token in §2 is measured, not asserted. Body text
   ≥4.5:1 on every surface it can land on; non-text UI (rails, chart strokes,
   focus rings, borders that carry meaning) ≥3:1. `#5d7269` was rejected at
   3.68:1 rather than allowlisted.
2. **Keyboard.** Every verdict is reachable without a pointer, using the keymap
   settled in `04-SURFACES-AND-UX.md` §3.0: `C`/`D`/`I` on a finding, `G`/`R`
   on a hold, `S` snooze, `E` escalate, `J`/`K` to move, `Enter` to open. Focus
   is always visible — Buzz's `focus-visible:ring-1 focus-visible:ring-ring`
   (`button.tsx:8`) is retained, with `--ring` (`theme.css:33,99`) rebound to
   `--border-strong` so it is visible on `--card`. No keyboard trap; the PTY
   panel's keyboard-ownership chord is Buzz's existing modeled transaction, not a
   new one. No key-repeat on the grant key, ever.
3. **Screen reader.** Every chart has a table equivalent. Every badge has its
   state in text, not only in an `aria-label`. Live regions are used for exactly
   three things: a new needs-action item (`polite`), a mode transition to
   Incident (`assertive`), and a containment that failed to release
   (`assertive`). Nothing else announces, because a console that narrates every
   telemetry tick is unusable with a screen reader.
4. **Color-blind safety** (beyond AA). No information by hue alone, anywhere.
   Deuteranopia is the explicit design case (§8.4).
5. **Reduced motion** (beyond AA). `prefers-reduced-motion: reduce` removes all
   four motion classes except `countdown`, which is data. The Watchfloor snaps
   to discrete 1 Hz steps.
6. **Zoom** (beyond AA). The rem contract means Cmd +/− from 0.75× to 1.5× is
   supported natively, enforced by `check:px-text` in CI. This exceeds AA's 200%
   reflow requirement on the text axis and is the reason the guard is adopted
   into Ambush's `tools/check-*.sh` rather than merely inherited.

**Two honest limits.** Glass/vibrancy is macOS-only and degrades silently to
opaque (`ThemeProvider.tsx:380-391`, which warns and continues on failure) —
Perch does not design around it. And no role-based UI gating is claimed until
`OperatorScope::Read` is actually enforced; it is checked on no
`/v1/operator/*` handler today, and the settings page says so.

---

## 12. Three hero screens

**The Watch (`/`) — dark, 1440×900.** Left: a 256px sidebar on `#070a09` with
the twelve threat lanes as a fixed ordered list under the heading `LANES`, each
with a one-line topic (`strength 1.87 · 3 sources / 2 agents · thr 2.00`) in
`text-2xs` mono. Center: a 420px inbox column, four queues (`needs_action`,
`mention`, `activity`, `agent_activity`), with the C9 instrumentation strip in
the first queue's header. The top row has a `--sev-critical` 4px leading rail, a
`CRITICAL ▮▮▮▮` chip, the word `isolate_host`, the host in mono, and
`held 4m 12s` counting up. Right: the verdict pane on `#0c1613` with a
`--pillar-authority` 2.5px top rail and five fixed sections in fixed order —
ACTION, BLAST RADIUS, IF YOU UNDO (`IRREVERSIBLE — no inverse exists`,
`--sev-high`), WHY WE ARE ASKING (`no rule matched → static gate ·
human_gate_severity HIGH`), WHAT GRANTING OPENS (`CapabilityLease · 60s TTL ·
minted at decision`). Below those, the two provenance rows: `AMBUSH RECORD
ed25519 · NO SIGNATURE OF ITS OWN — this card is a copy; the daemon holds the
record [verify]` and `RELAY ENVELOPE secp256k1 · signed by npub1… · transport
only`. At the bottom, a single wide chip: *record my decision and send it to the
daemon* — outlined, never filled, keyed `G`. Along the top, an 18px governance
strip: `GOVERNANCE HEALTHY · committee of 1 (solo transport)` in `text-eyebrow`
on `--pillar-authority`. Nothing on this screen is moving.

**Case (`/cases/case-0042`) — dark.** A channel timeline. Agent messages carry
role glyphs and pillar-tinted 1px borders: two green Whisker deposit cards, a
cyan Weaver correlation card that is the root of a four-reply NIP-10 thread
reading `4 agents corroborated`. Mid-column, a hold card with an amber top rail
and the `hold` glyph. Below it, an operator's verdict row — an outlined `GRANT`
chip, the full npub, a mono `receipt:9f2c…` link, and a `derived · hold store`
marker on the operator name (law 3). Right, a 320px members sidebar: eight
agents with health dots, no pulsing. Above the composer, a TTL strip:
`case archives in 6h 12m unless there is activity`. Bottom, a collapsed PTY
strip labelled `swarmctl · scoped to case-0042 · --replay-results-dir
data/replay-runs`.

**Watchfloor (`/watch-floor`) — dark, 3840×2160 wallboard, `compact`.**
Full-bleed `#070a09` with the dot-field pattern from `hero-v2.svg:5` at 10% and
corner crosshair ticks. Center-left, 60% width: the concentration field — twelve
stacked decay curves, one per lane, green area fill on the `0.30→0.02` gradient,
dashed amber `alert_threshold` rules with literal values, one crossing ring on
`execution` that will stop in three seconds. Caption: `interpolated · runtime
says 2.14 · agrees`. Right column: agent colony health as eight role glyphs in
three pillar-colored groups exactly as `colony.svg` lays them out; below it
`MODE: ALERT` in `text-eyebrow` amber; below that a four-row containment board
with live `mm:ss` countdowns in tabular numerals, one row red reading
`EXPIRED — HOST STILL CONTAINED`. Bottom strip: `LIVE · 1 Hz`,
`ingest 12,481/s`, a read-only restatement of the C9 counters linking back to
`/`, and — because the queue is quiet — a link reading `18 ATT&CK techniques
across 11 detectors are intentionally uncovered → /gaps` (both counts verified
from `rulesets/evasion/attack-technique-catalog.yaml`), which is what a quiet
queue is allowed to say instead of "Everything looks good!".

---

## 13. Citation audit

The red-team pass observed that this doc set was rigorous about *existence* and
credulous about *behavior*. This table closes that gap for every citation this
document leans on. Each row answers: who calls it, in what process, and what it
does to the data.

| Citation | Who calls it | Process | What it actually does |
|---|---|---|---|
| `swarm-spine/src/envelope.rs:71` `build_signed_envelope` | exactly one non-test, non-vendor caller: `swarm-runtime/src/approval.rs:1810` | daemon | Signs one approval-vote envelope. **It does not sign findings, receipts, holds or audit trails.** The "chain" it builds exists only in the approval ledger. |
| `swarm-spine/src/chain.rs:75` `verify_chain_link` | zero callers outside `chain.rs`'s own tests + the `lib.rs:67` re-export | — | Nothing. A "chain linkage" check has no chain to run against outside the ledger. |
| `swarm-runtime/src/containment.rs:234` `verify_release_attestation` | `swarm-runtime-http/src/http/containment.rs:219`, on release | daemon | Two checks (signature, subject binding). No trust anchor, no chain check. A full re-attestation passes. This is the *only* verification a Perch surface can honestly claim. |
| `swarm-whisker/src/stream.rs:24` `findings_to_deposits` | the detection pipeline | daemon | Builds deposits with `signature: Vec::new()`; `detection/pipeline.rs:265` signs them afterward. So "signed deposit" is true of the persisted object and false of the constructor's output. |
| `swarm-pheromone/src/substrate.rs:1268` `concentration_for` | escalation + the deposits path | daemon | Filters evaporated **and** suppressed deposits, then counts strategy-scoped ids. `filter_deposits` (`:1306`) filters suppressed but **not** evaporated — two different filters feeding one chart. |
| `desktop/src/shared/theme/adaptive-theme.ts:191` `createThemeVars` | two callers: `ThemeProvider.tsx:438`, `useThemePreviewVars.ts:28` | webview | Emits the syntax-derived vars including `--muted-foreground` (`:259`) and the 10 `--huddle-*` (`:244-253`). Does **not** emit `--chart-1..5`. |
| `ThemeProvider.tsx:198` `applyAccentColor` | `:417`, `:460`, `:633` | webview | Writes `--primary` and five siblings **inline on the root element** (`:213-218`, `:231-236`). No stylesheet can override it. |
| `theme.css:34-38,100-104` `--chart-1..5` | one consumer: `animations.css:715,719,727` | webview | A decorative cold-boot gradient. Not in Tailwind's `colors` map, so no utility class reaches them. |
| `check-px-text.mjs` | `scripts/check-px-text-core.mjs:29,32` | CI | Two regexes over `.ts`/`.tsx`/`.css` under `src`. It scans CSS, so an SVG `font-size:` in a stylesheet is caught; an SVG `font-size=` **attribute** in TSX is not — which is why §8.4 mandates classes, not attributes. |
| `agent.rs:137` `transition_to` | escalation | daemon | Rejects non-upward moves — but `transition_down` (`:148`) exists, so the mode chrome must render de-escalation. |
| `web/tailwind.config.js` + `web/src/shared/styles/globals.css` | the browser client | — | **Verified drift**: `--radius` and `--chart-1..5` are duplicated (`globals.css:9,29`; `tailwind.config.js:6-8`) but the `2xs`/`3xs`/`message` fontSize tokens are absent entirely. The two configs already disagree on the type scale. Perch does not add surfaces to `web/` in v1, so this is noted, not fixed. |

---

## 14. Boundaries with the rest of the set

This document owns tokens, type, motion, iconography, chart *language*, the
verdict control's visual guards, and the component inventory. It does not own:

- which surfaces exist, their routes, their behaviour, or the keymap it follows
  — `04-SURFACES-AND-UX.md`;
- the exact wording of every badge, empty state and ban list —
  `06-COPY-AND-VOICE.md`;
- the trust-badge *semantics* argument beyond its visual form, and the 15-row
  action matrix — `08-TRUST-AND-GOVERNANCE-UX.md`;
- the wire format, the seven markers, and the Ambush backend bill that decides
  whether §2.6's cards ever become signable — `03-DOMAIN-EVENT-MAPPING.md`;
- the 1 Hz coalescing, spool and render-budget mechanics behind the Watchfloor,
  and the branded time types §8.1 demands — `07-REALTIME-AND-DATA.md`;
- the sizing of the ~1,500 LOC chart layer and the phase in which each token
  lands — `09-ROADMAP-AND-RISKS.md`.

Where this document previously restated a peer's decision and drifted from it —
the keymap, the density mode names, the Watchfloor route — it now cites the
owner instead. Numbers that appear in more than one document (the twelve/three
badge counts, the 18/11 gaps counts, the file-size ceilings) should move to the
normative appendix the coherence review asks for; until that exists, this
document's versions are the ones measured in §13.
