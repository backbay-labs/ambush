# 18 — Data-visualization component specs

**Status:** build artifact, revision 2 (post red-team).
**Companion artifacts, all runnable:**

| Path | What it is | Runs today |
|---|---|---|
| `prototypes/dataviz.html` | the specimen — six primitives, nine states × two data regimes × two themes, self-contained, opens by double-click | yes |
| `viz/dataviz-fixture.mjs` | binds the specimen to `fixtures/perch-demo-fixture.json` and **asserts** the five canonical concentration checkpoints reproduce to six decimals | `node viz/dataviz-fixture.mjs` |
| `viz/render-audit.mjs` | headless-Chrome render sweep: 36 combinations, copy lint against the peer's ban list, SVG-attribute scan, computed-font-size census | `node viz/render-audit.mjs` |
| `viz/check-svg-font-size.mjs` | **G1**, the guard that closes the SVG hole in `check-px-text` | `node viz/check-svg-font-size.mjs src` |
| `viz/check-perch-chart-tokens.sh` | **G2**, the four lexical chart rules, self-testing | `bash viz/check-perch-chart-tokens.sh <root>` |

**Cites, never restates:** `APPENDIX-NORMATIVE.md` §3 (wire), §6 (constants and verified counts),
§7 (vocabulary), §8 (render laws). Where this file proposes changing an appendix value it says so
explicitly and files a brief amendment.

Charts are net-new. Buzz's desktop `package.json` declares 61 runtime and 17 dev dependencies and
**none** of them is a charting library (`recharts|chart.js|d3|victory|nivo|visx|echarts|plotly|apexcharts`
returns zero matches), there is no grid component, and `--chart-1..5` are consumed by three `var()` calls in
one decorative gradient. Everything below is built.

---

## 0. How to read this file, and what revision 2 changed

Six primitives, numbered **VIZ-1 … VIZ-6**. The numbers are a registry key, not a sequence — peer
artifacts (`17-COMPONENT-SPECS.md`, `20-TASK-BREAKDOWN.md`, `22-DEMO-FIXTURE.md`) reference them by
number, and the prototype's plate labels match.

| Id | Component | Surfaces that embed it | Phase |
|---|---|---|:-:|
| **VIZ-1** | `ConcentrationCurve` | `/lanes/$laneId`, Case Canvas, `/watch-floor` (×12) | 2 |
| **VIZ-2** | `HostHeat` | `/lanes/$laneId`, `/watch-floor` | 2 |
| **VIZ-3** | `KillChainGraph` | Case Canvas | 2 |
| **VIZ-4** | `IncidentTimeline` | `/cases/$caseId`, Case Canvas | 1–2 |
| **VIZ-5** | `ContainmentLeaseTimer` | `/leases`, Verdict Row, `/watch-floor` | 2 |
| **VIZ-6** | `RateSparkline` | `/` (C9 strip), lane headers, `/tuning`, `/watch-floor` | 2 |

Every one of the six is Phase 2 except the timeline, which The Watch needs in Phase 1. That ordering
matters for §12's sizing: **no chart is on the Phase-1 critical path except VIZ-4**, and VIZ-4 is the
only one of the six that needs no arithmetic.

### 0.1 What revision 2 changed, and why

Four critics audited revision 1 against real source. Six of their findings land on this artifact.
All six are answered here in the body — not in an appendix nobody reads — and §17 records the
evidence for each, including the two places I hold my position.

| # | Finding | Where it is answered |
|---|---|---|
| 1 | The prototype's palette was authored against **bare Buzz shadcn variable names**, which `ThemeProvider` writes inline on the root element. Every colour on every plate would silently revert. | §3.2 — rewritten to `--perch-*`, and **G2 rule R4** now makes it a gate rather than a memo |
| 2 | Light severity `#b45309` measures **4.31:1** — below AA — after `19-TOKENS` measured and replaced it | §3.2 — amendments **T2/T2b applied**; the specimen ships `#a94e08` / `#825b12`, and I re-measured every value myself |
| 3 | Render law 2's `M agents` half **has no Phase-1 data source**, yet CR-5 forbade any component accepting a count | §3.3 — **CR-5 is revised**: `SourceAttribution` is a two-arm union whose absent arm renders a *named absence* |
| 4 | Five mutually incompatible "canonical" fixtures | §3.4 — the specimen now **binds to `fixtures/perch-demo-fixture.json`**, and `viz/dataviz-fixture.mjs` asserts the binding |
| 5 | No readable-text tier: 93% of the specimen's text at ≤11px | §3.5 — re-tiered and **measured**: 43.4% of product text is now ≥14px, 0 nodes at 8px |
| 6 | Theme architecture inverted relative to the token package | §3.2 — light on bare `:root`, dark under class + attribute + guarded media, matching `tokens/perch-tokens.css` exactly |
| 7 | Three tokens specified as required that `19-TOKENS` ships none of | §3.2 — the **paste-ready block with recomputed ratios** and the test extension, filed as one change |
| 8 | The same curve drawn twice with a 4× different disagreement threshold | §2.4 — the **arbitration** is stated, with one computation site, and the reversal instruction if A11 is rejected |
| 9 | Eleven CI gates named across the set and not delivered | §13 — **G1 and G2 are delivered and run**; G3's scope is stated and handed back |
| 10 | Nothing handles two operators deciding one hold | §7.6 — the timeline's **superseded decision row**, and the wire ask filed against `13-WIRE-SCHEMAS` |

---

## 1. The implementation decision: hand-authored SVG, no library, no Canvas

`05` §8 already decided "hand-authored SVG, no library" and gave four reasons. One of them is wrong
and the strongest one is missing. Restating the decision with the real argument:

### 1.1 The reason `05` gives that does not survive checking

> `05` §8: "(1) the Tauri CSP is tight and asset-specific … so every CDN-delivered chart library needs
> a fresh CSP edit and a bundled one needs an audit"

The CSP at `BUZZ desktop/src-tauri/tauri.conf.json:39` — applied by Tauri to the webview at launch,
so it governs every script the renderer loads — is
`script-src 'self' 'wasm-unsafe-eval' https://cdn.jsdelivr.net/npm/@mediapipe/`. A **bundled** npm
library is compiled into the app bundle and is therefore `'self'`. It needs no CSP edit at all. The
CSP argument bites only against CDN delivery, which nobody was proposing. Do not use it.

### 1.2 The reason that actually decides it: a JS dependency lands outside every supply-chain gate

Ambush runs three supply-chain gates and **all three are Rust-only**:

- `tools/check-supply-chain.sh:11-18` runs `cargo deny check advisories licenses bans sources` and
  then `cargo audit --deny warnings`, with a comment stating both must run because "`cargo deny`
  honours features and targets; `cargo audit` reads the whole lockfile, so the two see different
  graphs". Neither reads `package.json`.
- `tools/generate-sbom.sh:11` runs `cargo cyclonedx --manifest-path Cargo.toml --format json
  --spec-version 1.5`, emitting one CycloneDX document **per Rust crate** into `artifacts/sbom`, and
  exits 1 if it produced none (`:25-28`). The desktop's npm graph appears in no SBOM the project ships.
- `tools/check-gates-wired.sh` enumerates every `tools/check-*.sh` and fails on any not named by a real
  workflow `run:` step — so the gate set is closed and auditable, and a JS dependency is simply not in it.

And Buzz's side has nothing to catch it either: grepping `.github/workflows/` and the `justfile` for
`pnpm audit|npm audit|cyclonedx|sbom` returns **zero** matches, and there is no `.github/dependabot.yml`.

So: adding a charting library to Perch adds a transitive dependency graph to a security console that
**no gate in either repository inspects**, in the one artifact whose entire product argument is that
it renders nothing it did not receive over an authorized path. That is the decision. It is a
supply-chain decision, not a convenience one, and it does not depend on the CSP or on line counts.

The honest counter-argument, recorded so it is not re-litigated as though it were unexamined:
`d3-shape` alone (path generators, no DOM, no scales) would replace roughly 60 lines of the
arithmetic below and is a small, stable package. The rebuttal is not "it is too big"; it is that the
first npm dependency establishes the precedent and the second one is argued against a weaker
baseline. **PROPOSED policy:** the chart layer takes no runtime dependency. If a future need is real,
it is argued as a bill item with an SBOM plan, not merged as a convenience.

### 1.3 SVG over Canvas

Canvas is not new to Buzz — twenty files under `desktop/src` call `getContext`, including
`features/terminal/terminalBannerPainter.ts` (a real per-frame painter with a documented
reduced-motion path), `shared/ui/SpoilerParticles.tsx`, `features/communities/lib/downscaleIcon.ts`
and `features/agents/ui/snapshotAvatarPng.ts`. So "Buzz has no canvas precedent" would be false. The
argument is narrower and it is about three contracts Canvas cannot satisfy:

| Contract | SVG | Canvas |
|---|---|---|
| Text scales with `--buzz-type-rem` (Cmd +/− zoom and the font-size preference, `BUZZ typography.css:16-17,46-52`) | `<text class="text-2xs">` inherits the CSS ramp | `ctx.font` takes an absolute size; a chart label freezes exactly the way PR #891's message timeline did |
| Colour comes only from a Perch token and re-themes with no repaint bookkeeping | a CSS class resolves `hsl(var(--perch-viz-series-N))` natively | requires a `getComputedStyle` read per token per paint, or a cached palette that goes stale on theme change |
| Screen-reader path is the DOM plus a `<table>` toggle | `role="img"` + `<title>` + `aria-label` on real nodes | one opaque bitmap; the `<table>` becomes the *only* path, not the alternate one |

Volume does not force the issue either way: the budget is 12 curves × ≤120 sampled points = 1,440
nodes rebuilt at 1 Hz (`07` §9), which is inside SVG's comfortable range on the Watchfloor's 3840×2160
frame. **Decision: SVG. Canvas is reconsidered only if a measured `ScriptDuration` per tick exceeds
the 4 ms budget on the Watchfloor**, and that measurement is the trigger, not a preference.

---

## 2. The concentration mathematics

This section exists because VIZ-1 is the only chart in Perch that computes a number the operator will
act on, and because `APPENDIX-NORMATIVE.md` §6 (line 191) records its tolerance as **invented**.

### 2.1 The closed form, exactly as the runtime evaluates it

```rust
// AMB crates/swarm-core/src/pheromone.rs:280-287
/// `strength(t) = confidence * 0.5^((t - timestamp) / half_life)`
pub fn strength_at(&self, now: i64) -> f64 {
    if now <= self.timestamp {
        return self.confidence;
    }
    let elapsed = (now - self.timestamp) as f64;
    self.confidence * (0.5_f64).powf(elapsed / self.decay_half_life)
}
```

Who calls it, in what process, and what it does to the data: `concentration_for`
(`AMB crates/swarm-pheromone/src/substrate.rs:1268-1304`) calls it inside `swarm_detect --serve` on
every tick of the concentration monitor — `run_until_shutdown(CONCENTRATION_MONITOR_INTERVAL_MS)`
drives `evaluate_all` (`escalation.rs:105-207`) at 10 Hz — and reduces the deposit set of one threat
class to a `PheromoneConcentration { total_strength, distinct_sources, peak_confidence }`. The
reduction, read line by line:

```rust
// substrate.rs:1268-1304, in order
let suppression = latest_feedback_suppression_states(deposits);   // :1274
for deposit in deposits.iter().filter(|d| &d.threat_class == threat_class) {   // :1281
    if deposit.is_evaporated(now, policy.evaporation_threshold) { continue; }   // :1283
    if is_suppressed_by_feedback(deposit, &suppression)          { continue; }   // :1286
    let strength = deposit.strength_at(now);
    if strength <= 0.0                                            { continue; }   // :1290
    total_strength += strength;                                                   // :1293
    peak_confidence = peak_confidence.max(deposit.confidence);                    // :1294
    sources.insert(deposit.agent_id.0.clone());                                   // :1295
}
// distinct_sources: sources.len()                                                // :1301
```

Five things the chart layer inherits from those lines:

1. **The class filter at `:1281` runs before the sum.** This is what makes the specimen's fixture
   extension arithmetically safe: every extension deposit is in a threat class other than the
   canonical one, so it cannot move a canonical number. `viz/dataviz-fixture.mjs` asserts it.
2. **Evaporation is applied before summation**, against `policy.evaporation_threshold` resolved
   per threat class (`PheromoneConfig::resolve_threat_class_policy`,
   `AMB swarm-core/src/pheromone.rs:295-318`). A client that omits the floor produces a slightly
   higher curve, permanently.
3. **Suppression is retroactive and keyed on `(threat_class, event_id)`** —
   `FeedbackSuppressionKey` at `substrate.rs:345-348`, built by `deposit_suppression_key`
   (`:1412-1421`) from `indicator["event_id"]`, and fired by `is_suppressed_by_feedback` (`:1367-1380`)
   when a `Dismiss` marker sharing the key carries `timestamp >= deposit.timestamp`.
4. **`distinct_sources` counts `deposit.agent_id.0`**, which is strategy-scoped. See §2.2 — one
   ground note says otherwise and it is wrong, and §17 records the two peers who compiled the wrong
   reading into a `const`.
5. **`strength_at` returns `confidence` unchanged when `now <= timestamp`.** Harmless in the runtime,
   because a snapshot at time *t* only ever sees deposits that exist at *t*. Fatal in a chart that
   replays a series: including a future deposit at every sample paints the entire history flat at full
   confidence. See render rule **CR-4** in §3.1.

### 2.2 Correction, re-verified in revision 2: `distinct_sources` **is** strategy-scoped

The ground note `ambush-touchpoints.md` correction **C-5** asserts the opposite — that
`WhiskerAgent::tick` derives one id per agent and therefore "four detectors agreeing FAILS to
escalate", and that render law 2's `N sources / M agents` expansion "collapses to one number and the
explanatory copy must be rewritten". **That correction is wrong.** Every hop re-read at the line this
session, naming who calls what, in which process, and what it does to the data:

- `WhiskerAgent::tick` (`AMB crates/swarm-agents/src/whisker_agent.rs:148-149`), the agent loop inside
  the daemon, builds `scoped_agent_id = AgentId(format!("{}:{}", derived_identity.0, self.id.0))` —
  the *agent instance* id — and passes it as the `agent_id` argument at `:154`.
- `detect_and_deposit_with_role` (`AMB crates/swarm-runtime/src/detection/pipeline.rs:60-91`), the
  production deposit path, hands that same `agent_id` to `resolve_deposits` at `:80`, then signs and
  writes each returned deposit to the substrate at `:82-85`.
- `resolve_deposits` sets, per finding,
  `agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id)`
  (`pipeline.rs:573`) — i.e. `"{identity}:{instance}:{strategy_id}"`. The strategy scoping is applied
  **after** the instance scoping, not instead of it.
  `strategy_scoped_agent_id` is `AgentId(format!("{}:{strategy_id}", base.0))`
  (`AMB crates/swarm-whisker/src/stream.rs:20-22`).
- `concentration_for` inserts that whole string into the source set (`substrate.rs:1295`).
- The workspace asserts it twice, in the same test module:
  `query_counts_strategy_scoped_agent_ids_as_distinct_sources` (`substrate.rs:2104-2126`) deposits
  `whisker-primary:suspicious_process_tree` and `whisker-primary:dns_exfiltration` and asserts
  `distinct_sources == 2`; `query_collapses_repeated_strategy_scoped_agent_ids_to_one_source`
  (`:2128-2153`) asserts `1` for two deposits sharing an id. A third pair exists at
  `crates/swarm-pheromone/tests/multi_instance.rs:353,393`.

So render law 2 stands exactly as `APPENDIX-NORMATIVE.md` §8 writes it, including its gloss that one
Whisker with four detectors clears `min_sources_for_escalation` alone. `05` §8.2 is right. C-5's
proposed copy rewrite must **not** be acted on.

**This does not resolve §3.3's problem.** The two numbers really are different — and in Phase 1 the
console cannot compute the second one from a card. That is a separate fact about the wire, not about
the runtime, and it is the subject of the CR-5 revision.

### 2.3 Interpolation between snapshots is **exact**, so the tolerance is not an error budget

`07` §8 has the client interpolate the curve between authoritative `ConcentrationSnapshot` samples and
snap when the next sample "differs from the interpolation by more than 2% of `alert_threshold`". The
appendix marks that 2% **invented**. Working out what it should be shows it is not measuring what it
was meant to measure.

For a fixed deposit set, the sum is itself a single exponential:

```
S(t) = Σᵢ cᵢ · 2^(−(t − tᵢ)/H)  =  2^(−t/H) · Σᵢ cᵢ · 2^(tᵢ/H)
```

so `S(t₁) = S(t₀) · 2^(−(t₁ − t₀)/H)` **identically**, for any t₀, t₁, provided every live deposit
carries the same `decay_half_life` H and the set does not change. Evaluated in double precision over
the canonical fixture, the worst disagreement between exponential interpolation and the direct sum over
300 one-second steps is **4.44 × 10⁻¹⁶** — two ULP at that magnitude. There is no interpolation
error to be tolerant of. (Measured by `tune.mjs`, an implementation written from the Rust rather than
from the specimen, precisely so a shared misreading would not agree with itself.)

What the tolerance is really detecting is therefore **an unmodelled change to the deposit set** — a
new deposit the client has not seen, or a retroactive suppression. That reframing gives a derived
value.

### 2.4 The tolerance, derived — brief amendment A11, and the arbitration it needs

> **Replace** `APPENDIX-NORMATIVE.md` §6's row at line 191
> *Interpolation tolerance · 2% of `alert_threshold` · invented*
> **with**
> *Snapshot-disagreement tolerance ε · `policy.evaporation_threshold` for that threat class · derived*

The derivation:

- A deposit **leaves** the sum when `strength_at(now) < evaporation_threshold`
  (`is_evaporated`, `AMB swarm-core/src/pheromone.rs:290-292`). The largest discontinuity an
  evaporation can cause is therefore strictly less than `evaporation_threshold` — and evaporation is
  fully predictable client-side, because the client holds `timestamp`, `confidence` and
  `decay_half_life` per deposit and applies the same floor. It should never trip a snap.
- A deposit **enters** the sum contributing `confidence · 2^(−age/H)`. A contribution below
  `evaporation_threshold` would be evaporated on arrival, so **any deposit the client did not see
  moves the sum by at least `evaporation_threshold`.**
- A **suppression** removes at least one deposit, so it moves the sum by at least the same amount.

Therefore ε = `evaporation_threshold` is exactly "one deposit's worth": every single-deposit
unmodelled change trips it, and no modelled change does. Two further properties make it the right
constant rather than merely a defensible one:

- **It is served, not chosen.** `07` §8's deposits route already returns
  `policy.evaporation_threshold` from the same `resolve_threat_class_policy` call that supplies
  `half_life_secs` and `alert_threshold`. The client hardcodes nothing and no percentage is invented.
- **It is not coupled to an unrelated dial.** `alert_threshold` is a policy decision about when to
  escalate. Raising it from 2.0 to 20.0 — a config change an operator can make — silently widened
  the old tolerance tenfold and stopped the console reporting real divergences. `evaporation_threshold`
  is the runtime's own definition of "too small to matter", which is the question being asked.

With the shipped ruleset (`AMB rulesets/default.yaml:56`, `evaporation_threshold: 0.01`) ε = **0.01**,
against the invented rule's 0.04.

#### The arbitration (finding 8)

`prototypes/watchfloor-ledger.html` draws VIZ-1 too, and sets `TOLERANCE = 0.02 * alert_threshold`
= 0.04, saying in its own spec notes that it uses the invented constant knowingly. Two drawings of
one component cannot hold two snap thresholds: the threshold is what decides whether an operator sees
a divergence at all, and 4× is the difference between "one unseen deposit is reported" and "four are
not".

**Resolution, and it is a decision rather than a preference.** ε wins, for the two properties above,
and it wins *mechanically*: there is exactly one place in this specimen where the value is computed —

```js
// prototypes/dataviz.html
function snapshotEpsilon(served) {
  return Math.max(FX.policy.evaporation_threshold, 1e-9 * Math.abs(served));
}
function snapshotDisagrees(derived, served) {
  return Math.abs(served - derived) >= snapshotEpsilon(served);
}
```

and one place in the shipped code (`desktop/src/shared/viz/concentration.ts`, `snapshotDisagrees`).
**If A11 is rejected, that one function changes and nothing else does.** The registry row is the
tiebreak, not this file: A11 is filed against `APPENDIX-NORMATIVE.md` §6 line 191, and whoever
ratifies or rejects it should also strike the 2% figure from the Watchfloor's spec notes in the same
change, because leaving both in circulation is the defect, not either value.

The `>=` rather than `>` is deliberate and commented at the call site: a deposit contributing exactly
the floor is the smallest real event, and it must trip.

### 2.5 Two regimes, and the one place linear interpolation would actually break

**Regime A — deposit-backed.** The surface holds `deposits[]` from the B4 route. It re-evaluates
`Σ strength_at(t)` per deposit, using **each deposit's own `decay_half_life`** (the field is
per-deposit, `AMB swarm-core/src/pheromone.rs:222`, stamped from the resolved policy at deposit time,
`pipeline.rs:572`). Exact by construction; no interpolation, no tolerance needed except as a
cross-check against the served `concentration.total_strength`. Used by `/lanes/$laneId` and the Case
Canvas. **Regime A carries `sourceIds`.**

**Only VIZ-1 and VIZ-4 have two regimes.** VIZ-2, VIZ-3 and VIZ-5 read objects the runtime serves
whole — a deposit list, an incident record, a containment-lease listing — and none of the three has
an ephemeral form to fall back to. The specimen says so on each of those plates when the regime
toggle is set to B, rather than ignoring the toggle, because a control that silently does nothing
leaves a reviewer wondering whether it should have.

**Regime B — snapshot-only.** The surface holds only 1 Hz `26001` samples (12 classes, no deposit
list). It draws the segment with `S(t) = S(t₀) · 2^(−(t − t₀)/H)` using the resolved policy's `H`.
Exact **only if** every live deposit in that class carries that half-life. Used by `/watch-floor` and
lane headers, and its caption must name the assumption. **Regime B does not carry `sourceIds`** — see
§3.3. The specimen makes the regime a first-class toggle for exactly this reason: it is the axis
along which the honest rendering changes, not a footnote.

**Linear interpolation is forbidden in both regimes.** Its maximum chord error against the true
exponential is `S · (ln2 · Δt / H)² / 8`, computed:

| H | Δt | bound at S = 3.41 | vs ε = 0.01 |
|---:|---:|---:|---|
| 3600 s (shipped default) | 1 s | 1.6 × 10⁻⁸ | irrelevant |
| 3600 s | 60 s (stale telemetry) | 5.7 × 10⁻⁵ | irrelevant |
| 300 s | 10 s | 2.3 × 10⁻⁴ | irrelevant |
| **45 s** (a per-class override; the value `stigmergy.svg:9` itself advertises) | **10 s** | **1.01 × 10⁻²** | **exceeds ε** |
| 45 s | 60 s | 3.6 × 10⁻¹ | 36× ε |

So at the shipped half-life linear interpolation is harmless, and under a short per-class override —
a **config** change, reachable through `ThreatClassConfig.half_life_secs`
(`AMB swarm-core/src/pheromone.rs:35-46`) with no code change — it manufactures false divergences
faster than real ones. Use the exponential form; it is one `Math.pow` and it is always right.

**Extrapolation past the last sample** (the live "now" marker) is a lower bound, not an estimate:
decay only subtracts and a new deposit only adds, so the drawn forward segment can under-state and
cannot over-state — *except* after a suppression, which subtracts retroactively. The caption states
that asymmetry rather than implying precision.

### 2.6 The history is never recomputed — render rule CR-3

Because a `Dismiss` removes every matching deposit **at or before** the marker, recomputing the
historical curve from the *current* deposit list would erase the evidence that the threshold was ever
crossed: the curve would show a threat class that never escalated, next to a timeline row that says it
did.

**Rule.** The drawn past comes from received snapshots (Regime B) or from the deposit list *as it was
at each sample* (Regime A, with the suppression applied only from the marker forward). The
suppression renders as a hatched region, a marker line and a visible step. It is never a redraw.
This is render law 5 made mechanical, and the specimen's `suppressed` state draws all three channels.

---

## 3. The shared chart layer

### 3.1 Ten rules, each a constraint rather than a convention

Every one is a component-API constraint or a CI failure, not a code-review note.

| # | Rule | Mechanism |
|---|---|---|
| **CR-1** | Time is branded. Chart props take `UnixSeconds` or `UnixMillis`, never `number`. | `07` §8's `desktop/src/shared/time/domains.ts`; no converter is exported, so crossing domains is named at the call site |
| **CR-2** | Colour comes only from a `--perch-*` token, applied through a **CSS class or a style object — never through an SVG presentation attribute.** **No hex literal in a chart component. No bare Buzz shadcn variable, ever.** | **G2 rules R1, R2, R4** (§13), delivered and self-testing |
| **CR-3** | History is drawn from what was received, never recomputed. | §2.6 |
| **CR-4** | A series sample at *t* excludes deposits with `timestamp > t`. | `strength_at`'s `now <= timestamp` guard returns full confidence; see §2.1 item 5 |
| **CR-5** | **No component accepts a `sources: number`.** It accepts a `SourceAttribution` — either the ids, or a **named absence** carrying the count and the reason the ids are not on the received object. It never fabricates the agent half. | type (§3.3); **G2 rule R3** bans the prop name |
| **CR-6** | Text is `className="text-2xs"` / `"text-3xs"`. Never a `font-size` attribute, never a `fontSize` prop. | **G1** (§13), delivered and self-testing |
| **CR-7** | Every chart carries `role="img"`, a `<title>`, a full-sentence `aria-label`, and a **table toggle** rendering the same rows as a real `<table>`. | §10 |
| **CR-8** | Anything the console computes that the runtime does not carries a derived marker naming the function. Anything the runtime served carries a served marker naming the route. | `<DerivedMarker fn="strength_at()" />` / `<ServedMarker route="…" />` |
| **CR-9** | Charts do not fetch. They take data and a `state`. | the `VizState` union in §3.3 |
| **CR-10** | **A chart's plot ground is `--perch-card`, in both themes.** | measured, §3.2 — `--perch-chart-rule-label` clears AA on `--perch-card` with margin and clears it by 0.01–0.05 on `--perch-surface-raised`, which is inside one-decimal HSL rounding. The one string carrying the policy number does not get to be marginal. |

CR-10 is new in revision 2 and it came out of re-measuring rather than out of a review finding. It is
the rule `17-COMPONENT-SPECS` asked this file to carry in a different form ("charts must be capped at
their viewBox width"), and both halves are now in the specimen: `.figure .cap960 { max-width: 960px }`
caps the coordinate scaling, and the plate ground is `--perch-card`.

### 3.2 Tokens — the namespace rule, the three additions, and the measurements

#### The namespace rule, and why it is a gate and not a memo

Perch components read `--perch-*` **only**. Not `--card`, not `--muted-foreground`, not `--border`.

The mechanism, verified this session: `createThemeVars`
(`BUZZ desktop/src/shared/theme/adaptive-theme.ts:191-240`, a pure function called by the renderer)
returns a `vars` record containing **exactly 38** Buzz shadcn variable names — I enumerated them:
`--background --foreground --card --card-foreground --popover --popover-foreground --primary
--primary-foreground --secondary --secondary-foreground --muted --muted-foreground --accent
--accent-foreground --destructive --destructive-foreground --border --input --ring --status-added
--status-deleted --status-modified --ui-warning --ui-warning-bg --sidebar-background
--sidebar-foreground --sidebar-accent --sidebar-accent-foreground --sidebar-border --sidebar-ring`
plus the nine `--huddle-*` control variables. `applyTheme`
(`ThemeProvider.tsx:427-446`, in the renderer, on every theme or accent change) then does

```ts
const root = document.documentElement;
for (const [key, value] of Object.entries(vars)) {
  root.style.setProperty(key, value);      // ThemeProvider.tsx:443-446
}
```

and the cached-boot path `applyCachedVars` (`:398-412`) writes the same set before first paint. Those
are **inline declarations on the root element**. No normal-priority stylesheet rule can beat one. A
chart authored against the bare names repaints with whatever Buzz syntax theme is active, silently,
and the measured contrast ratios stop being the ones anybody checked.

Revision 1 of this file and its specimen were authored against the bare names — 97 uses of them, zero
`--perch-` uses. That was the review's blocking finding and it was correct. Revision 2:

- the specimen declares **only** `--perch-*` names, matching `tokens/perch-tokens.css` name for name
  and value for value (bare HSL triplets, no hex duplicates);
- **G2 rule R4** fails the build on `var(--<any of the 38>)` inside a Perch chart file, with the
  38-name alternation written out in the script so nobody has to remember the list;
- the specimen's `viz/check-perch-chart-tokens.sh` run is green, and the planted-violation fixture
  proves R4 fires.

This closes the loop the review named: `19-TOKENS`'s binding commitment now has a mechanical half, so
the drawings and the token package can no longer disagree about the one thing the token package was
written to settle. **The `data-perch-theme-pin` question is not this file's to answer** — it belongs to
`19-TOKENS`, and G2 makes it moot for charts either way, because a chart that never reads a Buzz name
does not need a bridge.

#### Theme arrangement, copied rather than invented

`tokens/perch-tokens.css` puts the complete light palette on bare `:root` (`:66`), redefines dark
under `:root.dark, :root[data-theme="dark"], .dark` (`:217-219`), and repeats the identical
declaration set under `@media (prefers-color-scheme: dark) { :root:not(.light):not([data-theme="light"]) }`
(`:342-343`). The specimen now does exactly that, and — unlike two peer prototypes — sets **nothing**
on `<html>`, so `prefers-color-scheme` actually reaches the palette. `viz/render-audit.mjs` renders
every state under `--blink-settings=preferredColorScheme=1` and `=2` and the light palette is
reachable in both, which is the check the review found two peers had skipped.

#### Severity: amendments T2 and T2b, applied and independently re-measured

I recomputed every ratio from the sRGB triplets rather than copying the peer's table:

| Light token | Revision 1 value | on `--perch-surface-chrome` `#e9efeb` | on `--perch-surface-raised` `#e2eae5` | Revision 2 value | chrome | raised |
|---|---|---:|---:|---|---:|---:|
| `--perch-sev-high` | `#b45309` | **4.307** ✗ | **4.097** ✗ | `#a94e08` | **4.764** ✓ | **4.533** ✓ |
| `--perch-sev-medium` | `#8a6114` | 4.739 ✓ | **4.508** (inside rounding) | `#825b12` | **5.214** ✓ | **4.960** ✓ |

AA body text needs 4.5:1. `#b45309` fails on both raised surfaces, and it is the **classification
channel on a security console**. `#8a6114` clears raised by 0.008, which one-decimal HSL rounding can
erase. `19-TOKENS` found this and shipped the replacements; revision 1 of the specimen did not carry
them. It does now, and it carries no other severity value.

`#b45309` survives in the specimen in exactly two non-text roles, both above the 3:1 bar:
`--perch-pillar-authority-mark` and `--perch-chart-rule` (the dashed threshold rule, 4.31 on chrome
and 5.02 on card — a rule, not a word).

**Proposed forbidden-literal test, handed to `19-TOKENS`:** add `#b45309` and `#8a6114` to
`perch-tokens.test.mjs` as literals that must not appear in a `--perch-sev-*` declaration. A
replacement that is not policed can recur, and this one already did once across five files.

#### The three tokens this layer asks for, with recomputed ratios

`grep -c 'perch-viz-suppressed-hatch\|perch-viz-grid\|perch-viz-track' tokens/perch-tokens.css`
returns **0**. The review is right that revision 1 specified them as required and neither artifact
filed the addition against the other. Filing it now, as a paste-ready change.

The important thing about these three is that **each is an alias of a token the package already
ships**, so adding them costs no new colour decision and no new measurement round — only a name that
says what the value is for. Ratios below are recomputed from the sRGB triplets this session:

| Token | Light value | vs `--perch-card` | Dark value | vs `--perch-card` | Bar it must clear |
|---|---|---:|---|---:|---|
| `--perch-viz-grid` | `= --perch-border` `#d3dfd8` | 1.37 | `= --perch-border` `#1e3a2e` | 1.49 | none — a gridline is decoration, and the axis numerals carry the reading |
| `--perch-viz-track` | `= --perch-surface-raised` `#e2eae5` | 1.23 | `= --perch-surface-raised` `#163027` | 1.30 | none — the unfilled remainder of a bar; the filled part carries the value |
| `--perch-viz-suppressed-hatch` | `= --perch-foreground-muted` `#55695f` | 5.88 solid / **1.65** at α 0.35 | `= --perch-foreground-muted` `#7f9c8d` | 6.18 solid / **1.81** at α 0.35 | none — see below |

**Why none of the three carries a contrast bar, stated rather than assumed.** A hatch at 45°, 1px, 6px
pitch and α 0.35 covers roughly a sixth of its region; composited it measures 1.65–1.81 against the
card. That is far under 3:1, and it is correct that it is: the hatch is the *fourth* channel on the
suppression state, behind a marker line, a visible step in the curve and a full sentence naming the
operator and the time. Making it a classification channel would be the mistake. This is the same
argument `19-TOKENS` amendment T5 makes about the pillar borders, applied one object over, and the
specimen's `suppressed` state draws all four channels so a reviewer can check the claim.

Paste-ready, for `tokens/perch-tokens.css` — light block after `:149`, dark block after `:322`:

```css
/* light, in §1 after --perch-chart-axis-ink */
  --perch-viz-grid:             145 15.8% 85.1%;  /* = --perch-border          1.37 on --perch-card */
  --perch-viz-track:            142.5 16% 90.2%;  /* = --perch-surface-raised  1.23 on --perch-card */
  --perch-viz-suppressed-hatch: 150 10.5% 37.3%;  /* = --perch-foreground-muted 5.88 solid,
                                                     1.65 composited at alpha .35 - the fourth
                                                     channel on suppression, never a classifier */

/* dark, in §2 and again in §3's byte-identical block */
  --perch-viz-grid:             154.3 31.8% 17.3%; /* = --perch-border          1.49 */
  --perch-viz-track:            159.2 37.1% 13.7%; /* = --perch-surface-raised  1.30 */
  --perch-viz-suppressed-hatch: 149 12.8% 55.5%;   /* = --perch-foreground-muted 6.18 solid, 1.81 at .35 */
```

Three things must land with it, or the addition is decorative:

1. `perch-tokens.test.mjs`'s **dark-block parity assertion (T-A)** covers them automatically once they
   are in both dark blocks — that is the whole point of writing them into §2 and §3 together.
2. Its **CSS↔TS parity assertion** needs the three names added to `severity.ts`'s token union, or the
   union stops being exhaustive and T-G goes green while missing them.
3. The **3:1 assertion must deliberately omit all three**, the way it already omits every
   `--perch-border*`. A test that asserts a bar these tokens are not meant to clear would either fail
   correctly and get switched off, or get "fixed" by darkening a gridline until it competes with the
   data.

`--perch-alpha-hatch: 0.35` is also proposed, beside the existing `--perch-alpha-*` family
(`perch-tokens.css:167-178`), so the composited ratio above is derivable from the stylesheet rather
than from this table.

#### Series palette, measured minima corrected

Revision 1 claimed "every `--viz-series-N` clears 6.7:1 (dark) / 4.2:1 (light) against every surface".
Both numbers were wrong, in the safe direction for the claim but wrong. Recomputed:

| | minimum across `--perch-card` / `-surface-raised` / `-surface-chrome` | which |
|---|---:|---|
| dark | **5.19** | series 4 `#a78bfa` on `--perch-surface-raised` |
| light | **4.02** | series 6 `#a16207` on `--perch-surface-raised` |

All six clear the 3:1 non-text bar on every surface in both themes, which is the bar that applies to a
stroke or a fill. None of them is text and none of them should become text. The corrected minima are
what §10 now states.

Paired dash patterns for series 1–6, so twelve series differ on two channels:
`solid`, `4 2`, `2 2`, `6 3`, `8 2 2 2`, `1 3`.

**Threat class is never a hue.** Twelve categorical colours are past reliable discrimination, and the
pillar hues are spoken for. Threat class is encoded by fixed position in the twelve-lane sidebar order
(`standard_threat_classes()`, `AMB crates/swarm-runtime/src/escalation.rs:315-330` — a `Vec` the
escalation path builds once and iterates when computing per-class concentration) and by an inline
endpoint label. `ThreatClass::Custom(String)` lands in the nearest standard lane and the row says so
in text.

#### How colour reaches an SVG node — and the deviation revision 1 recorded, now deleted

```css
/* desktop/src/shared/viz/viz.css — the only place a chart names a colour */
.viz-series-1 { fill: hsl(var(--perch-viz-series-1)); stroke: hsl(var(--perch-viz-series-1)); }
/* … 2..6 … */
.viz-threshold { stroke: hsl(var(--perch-chart-rule)); fill: none; }
.viz-grid      { stroke: hsl(var(--perch-viz-grid));   fill: none; }
```

Revision 1 recorded a deliberate deviation: the specimen painted through
`fill="var(--viz-series-1)"` presentation attributes "so it renders from a `file://` URL with no build
step". **That deviation was wrong twice over** and is deleted. It was wrong because Perch's tokens are
bare HSL triplets — a triplet does not resolve in an attribute, so the form renders black — and it was
wrong because a drawing whose paint mechanism differs from the shipped one is not a drawing of the
component. The specimen now paints through classes exclusively, and
`bash viz/check-perch-chart-tokens.sh prototypes/dataviz.html` proves the file contains no
`fill=`/`stroke=` attribute other than the one paint-server reference `url(#perchHatch)`.

One live bug this change surfaced, recorded because no lint would have caught it: a `<stop>` inside a
gradient takes `stop-color`, **not** `fill`. A class setting `fill` on a gradient stop is silently
ignored and the area paints in the UA default. It was invisible against the dark ground and showed as
a grey wash in light. Screenshot review caught it; the render audit did not, and could not. `viz.css`
therefore needs `.stop-series-N { stop-color: hsl(var(--perch-viz-series-N)); }` as a separate class
family, and §16's `defs.tsx` is where the gradient lives.

### 3.3 The types, and the CR-5 revision

```ts
// desktop/src/shared/viz/types.ts   (new file — shared/api/* is at or over the size cap)
import type { UnixSeconds, UnixMillis } from "@/shared/time/domains";

/** The one state union every chart switches on. Exhaustive; no default arm. */
export type VizState =
  | { kind: "loading" }
  | { kind: "empty"; reason: EmptyReason }
  | { kind: "populated" }
  | { kind: "stale"; sinceMs: number }        // last frame age, rendered as a number
  | { kind: "degraded"; detail: DegradedDetail }
  | { kind: "error"; detail: ErrorDetail };

/** Which empty-state copy applies. Law 7: an empty state names what is not covered. */
export type EmptyReason =
  | "decayed_below_floor"    // CORRECT_ZEROS.concentrationZero
  | "no_findings"            // EMPTY.watchNoFindings  → /gaps
  | "no_open_containments"   // EMPTY.containmentsNone → /ledger
  | "no_incident";           // EMPTY.casesNone        → /settings#case-promotion

export type DegradedDetail =
  | { kind: "gap"; expectedSeq: number; receivedSeq: number; missing: number; issuer: string }
  | { kind: "coalesced"; from: number; to: number; windowStart: UnixMillis; windowEnd: UnixMillis }
  | { kind: "shedding"; droppedInWindow: number }
  | { kind: "disagrees"; derived: number; served: number; reason: string };

export type ThreatClassPolicy = {
  half_life_secs: number;
  evaporation_threshold: number;    // ALSO the snapshot-disagreement tolerance — §2.4
  min_sources_for_escalation: number;
  alert_threshold: number;
  incident_threshold: number;
};
```

#### CR-5, revised — render law 2 needs an absence, because the wire has one

Revision 1 declared `sourceIds: readonly string[]` non-optional and forbade any component accepting a
count. The review's blocking finding is that **no Phase-1 object carries the ids**, so the two
components that render `N sources / M agents` could not be built until B4, which is Phase 2. Verified
at the line:

- `RuntimeEvent::Escalation` (`AMB crates/swarm-runtime/src/runtime_events.rs:288-297`) has exactly
  eight fields — `emitted_at_ms, threat_class, level, total_strength, distinct_sources: usize,
  peak_confidence, mode_changed, current_mode`. A count. No ids.
- `grep source_ids schemas/*.json` hits one file: `card-swarm-escalation-v1.schema.json`, where the
  field is `{"type": "null"}` at `:94` and the example is `null` at `:234`, with the description
  saying so outright. No finding, hold, verdict, receipt, lease or rollback schema carries source ids
  at all.
- `13-WIRE-SCHEMAS.md` §9 states the reason: the escalation event has a count and no ids, and only B4
  can serve them.
- B4 (`GET /v1/operator/pheromone/deposits`, `openapi/perch-operator-v1.yaml:439`) returns the deposit
  list, each row carrying its `agent_id`. So the ids **do** exist — on one Phase-2 route, in one
  regime.

So the honest contract is not "always ids" and it is certainly not "invent the second number". It is
**a union whose absent arm is a named absence**, which is render law 1's grammar applied to render
law 2's phrase:

```ts
/** Render law 2 as a type. There is no shape that carries a bare count, and no
 *  shape that fabricates an agent count the wire did not send. */
export type SourceAttribution =
  | { kind: "ids";        sourceIds: string[] }
  | { kind: "count-only"; distinctSources: number;
      reason: "escalation-card" | "concentration-frame" };

export function sourceCounts(a: Extract<SourceAttribution, { kind: "ids" }>) {
  return {
    sources: new Set(a.sourceIds).size,
    // strategy_scoped_agent_id appends ":{strategy_id}" to the base, so the
    // agent is everything before the LAST colon (stream.rs:20-22).
    agents: new Set(a.sourceIds.map((id) => id.split(":").slice(0, -1).join(":"))).size,
  };
}
```

**The rendered strings**, both of which the specimen emits from one function so render law 2 is
enforced at the call site rather than by review:

| Arm | Rendered | Notes |
|---|---|---|
| `ids` | `5 sources / 3 agents` (singular forms handled: `1 source / 1 agent`) | unchanged |
| `count-only` | `5 sources / agent count not carried`, followed by a marker naming the reason and the route | passes the copy gate's `bare-source-count` rule, whose exemption is the substring `agent` |

The reason text, verbatim from the specimen:

- `escalation-card` → *"the escalation event carries a count and no ids (runtime_events.rs:288-297),
  and only GET /v1/operator/pheromone/deposits (B4) serves the ids"*
- `concentration-frame` → *"the 26001 concentration frame carries a count and no ids, and only
  GET /v1/operator/pheromone/deposits (B4) serves the ids"*

**Consequences filed against peers, because this is not a wording change:**

- **`17-COMPONENT-SPECS.md` §…'s `SourceCount`** declares `sourceIds: readonly string[]` non-optional.
  It should take a `SourceAttribution` instead. One prop, one union, and the absent arm becomes
  unfabricatable rather than merely discouraged.
- **`16-INVARIANT-TESTS.md` INV-16** asserts every `data-perch-role="source-count"` element matches
  `/\d+ sources? \/ \d+ agents?/`. That regex fails the honest absence. Proposed replacement:
  `/\d+ sources? \/ (\d+ agents?|agent count not carried)/`, with a second assertion that an element
  matching the absence form also carries `data-source-ids="absent"` — which the specimen sets, so the
  DOM hook exists.
- **`13-WIRE-SCHEMAS.md`**'s `card-swarm-escalation-v1.schema.json` should keep `source_ids: null`
  and gain nothing; the schema is already correct and the *client* was wrong. What it should change is
  the `distinct_sources_counts` `const`, for the separate reason in §17.

This is the shape the review asked for — "give `SourceCount` a typed `sourceIds: string[] | null` with
a named absence state" — with one refinement: a discriminated union rather than a nullable field, so
the reason travels with the absence and a `null` cannot reach a renderer that forgot to check.

**B4 does not need to move to Phase 1.** With this union, Phase 1's escalation rows and lane headers
render honestly against the wire they have, and B4 upgrades them in place. That is the cheaper of the
two options the review offered, and it is also the more honest one: a console that says "the ids are
not on this card" is telling the operator something true about the evidence chain.

### 3.4 The fixture: one canonical scenario, bound and asserted

Revision 1 invented its own `case-0042`. So did four peers. Five canonical fixtures is zero canonical
fixtures, and the review is right that nothing could be demonstrated together.

**`fixtures/perch-demo-fixture.json` is the fixture.** It is the only machine-validated one, and
`fixtures/derive-ids.mjs` regenerates every id from a public label, so no id was chosen to make a
screenshot look good. The specimen now binds to it:

| Bound, verbatim | Value |
|---|---|
| case channel | `27799e23-ab25-4659-b381-3de47ea7ca4d` |
| threat class / host | `execution` / `host-ops-1` |
| deposits | three, two strategies, one agent id (`swarm:ed25519:18085f16…:{strategy}`) |
| concentration checkpoints | 1.799653 / 2.696884 / 2.653617 / 2.573610 / 0.858696 |
| holds | `h_a07aeacf` (`isolate_host`, leases a containment) and `h_1c28ae79` (`block_egress`, leases nothing) |
| containment lease / rollback / receipt | `cl_9b3645fc` / `rb_81c4a588` / `resp:hunt-evt-1:lease:hunt-evt-1:isolate_host:1773738979300` |
| incident | `incident:hunt-evt-1:1773738882400` |
| clock | shift 08:00:00Z, demo now 09:20:00Z, 2026-03-17 |

`viz/dataviz-fixture.mjs` reads that JSON, re-derives all five checkpoints from `strength_at`'s closed
form and asserts they match to six decimals. Its output:

```
canonical checkpoints (execution threat class, canonical deposits only):
  below             1.799653  2 sources / 1 agent  peak 0.90
  crossing          2.696884  2 sources / 1 agent  peak 0.90
  at_open_row       2.653617  2 sources / 1 agent  peak 0.90
  before_dismiss    2.573610  2 sources / 1 agent  peak 0.90
  after_dismiss     0.858696  1 source  / 1 agent  peak 0.90
OK — 5 canonical checkpoints reproduced; extension perturbs none of them.
```

#### The extension, and why it cannot lie

The canonical scenario is single-host, single-threat-class and two-detector **by design** — that is
what makes its arithmetic checkable. VIZ-2 is a *ranked* host list, VIZ-3 needs a refused half, VIZ-6
needs a source distribution: none of the three is drawable from it. Rather than invent a sixth
fixture, the specimen carries a labelled **extension**, and it is safe for a reason that is checked
rather than asserted:

- every extension id is derived by the **same public function**,
  `sha256("perch-demo-fixture/v1/" + label)`, under an `ext/` label prefix that cannot collide with a
  canonical label. `node viz/dataviz-fixture.mjs` prints the table;
- every extension deposit sits in a threat class **other than** `execution`, and `concentration_for`
  filters by threat class at `substrate.rs:1281` *before* it sums — so it is arithmetically impossible
  for the extension to move a canonical number;
- assertion **A5** in `dataviz-fixture.mjs` recomputes all five checkpoints with the extension loaded
  and fails if any differs.

What the extension adds, offered to `22-DEMO-FIXTURE.md` §1 as a request rather than a fork:

| Label | What | Why the canonical scenario lacks it |
|---|---|---|
| `ext/ed25519/whisker-1`, `ext/ed25519/stalker-1` | two agent identities | the canonical cast has one agent id, so `M agents` is always 1 and the plural never exercises |
| 7 deposits in `credential_access`, `command_and_control`, `lateral_movement`, `persistence`, `data_exfiltration` on `host-ops-2/3/4` and one with **no `host_id`** | VIZ-2's ranked list and its D2 unattributed row | one host cannot be ranked |
| `ext/containment-lease/host-ops-{2,3,4}` | three containment leases in the `expiring`, `expired-still-listed` and `no-inverse` states | the canonical fixture has one containment lease, in one state; four of VIZ-5's five states are undrawable without them |
| `ext/finding/rejected/{beacon-jitter,lsass-handle}` | two refused incident members, with reason strings in the runtime's own grammars | the canonical incident has no rejections, and `rejected` is VIZ-3's whole point |

The rejection reasons are not invented prose. They are built to the shapes
`no_supporting_evidence_reason` (`AMB crates/swarm-runtime/src/correlation.rs:468-479`) and
`insufficient_weighted_score_reason` (`:481-493`) emit, from `shared_keys_summary` (`:447-453`) and
`score_breakdown` (`:455-466`), which is what the correlation stage writes onto a rejected
`IncidentMemberDecision`.

### 3.5 Type: the tier, and the census that proves it

The review measured revision 1's specimen at 93% of text ≤11px. That is a wall of meta-text, and on a
console read at 3am it is the decision that has to be re-made before anything else is worth polishing.

The ramp, at a 16px virtual rem:

| Token | px | What it carries |
|---|---:|---|
| `t-base` / `t-lg` | 16 / 18 | plate question, headline numbers |
| **`t-sm`** | **14** | **primary content**: chart captions, host names, values, timeline row line 1, containment-board cells, sparkline labels, node line 1 |
| `t-xs` | 12 | second lines, axis time ticks, threshold-rule label, strategy-id gutter |
| `t-2xs` | 11 | genuine meta: derived/served markers, y-axis numerals, table headers and captions, deposit indicators |
| `t-3xs` | 8 | **not used on any product surface on this page** |

Measured, not claimed. `viz/render-audit.mjs` walks every visible text node inside the plates
(excluding the spec-notes panel and the control dock, which are page chrome, and the code listings,
which are not drawn copy) and reads its **computed** font-size:

```
TYPE CENSUS over visible product text nodes (populated / regime A, both themes):
      11px   164   27.6%
      12px   172   29.0%
      14px   240   40.4%
      16px     6    1.0%
      18px    12    2.0%
  total 594 nodes; >=14px 258 (43.4%); <=8px 0
```

The audit **fails the build** if ≥14px falls below 25% or if any product node lands at 8px. That is
the review's own bar, turned into a gate rather than a promise.

---

## 4. VIZ-1 — `ConcentrationCurve`

**Purpose.** Answer, in one glance: *is this threat class climbing toward the bar, and which detector
put each step there?* It is the only chart whose numbers an operator acts on, and the only one whose
arithmetic the console reproduces rather than reads.

### 4.1 Data contract

```ts
export type DepositView = {
  agent_id: string;              // STRATEGY-SCOPED "{identity}:{instance}:{strategy_id}"
  strategy_id: string;
  threat_class: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;            // 0.0..1.0
  timestamp: UnixSeconds;        // NOT _ms
  decay_half_life: number;       // SECONDS, per deposit — may differ from policy.half_life_secs
  indicator: unknown;            // host_id lives at .host_id or /evidence/host_metadata/host_id
  event_id: string | null;       // the suppression key's second half
};

export type SuppressionMarker = {
  event_id: string; at: UnixSeconds; by: string; threat_class: string;
};

export type ConcentrationSample = {          // one 26001 frame, one class
  at: UnixSeconds;
  total_strength: number; distinct_sources: number; peak_confidence: number;
};

export type ConcentrationCurveProps = {
  threatClass: string;
  policy: ThreatClassPolicy;                  // served; every literal on the chart comes from here
  samples: ConcentrationSample[];             // regime B; authoritative
  deposits: DepositView[] | null;             // regime A when present; null on /watch-floor
  suppressions: SuppressionMarker[];
  now: UnixSeconds;
  nowFromDaemon: UnixSeconds | null;          // deposits route's now_seconds; drives the skew warning
  attribution: SourceAttribution;             // CR-5 — ids, or a NAMED absence
  state: VizState;
};
```

Source route: `GET /v1/operator/pheromone/deposits` — **backend bill B4, Phase 2, does not exist
today.** The route must return the post-suppression **and** post-evaporation slice, because
`filter_deposits` (`AMB swarm-pheromone/src/substrate.rs:1306-1334`, the function `query_deposits`
uses) applies suppression but **not** evaporation and takes no `now` argument at all, while
`concentration_for` (`:1268-1304`) applies both. If B4 ships the raw `filter_deposits` output, the
deposit ticks and the curve are computed by two functions with different filters and will visibly
disagree — and the disagreement will read as a rendering bug. `03` §11 item 4 and `07` §8 already
require this; it is repeated here because it is the single most expensive thing to get wrong.

### 4.2 Geometry, axes, scales

Transcribed from `AMB docs/assets/stigmergy.svg`, which is the spec for this chart, with the
reference's proportions preserved at a 960-unit viewBox:

| Element | Value | Reference |
|---|---|---|
| label gutter | ends at x = 174; plot origin x = 186 | `:54` |
| plot | x 186 → 940 | `:46-53` |
| deposit trains | rows above the plot, 32 apart | `:10-45` |
| area fill | vertical gradient, hue @ **0.30** → hue @ **0.02** | `:4`, painted `:46` |
| curve stroke | 2px, `stroke-linejoin="round"`, `fill: none` via a class | `:47` |
| threshold rule | 1.2px, `stroke-opacity 0.60`, `stroke-dasharray="5 5"` | `:48` |
| threshold label | 8px above the rule, left-anchored at the plot origin, **the literal config value** | `:49` |
| drop-line | 1px, `stroke-opacity 0.45`, crossing-x down to the baseline | `:50` |
| crossing point | `r=5` solid + one-shot ring, `transform: scale(1→3)`, opacity `0.75 → 0`, 3s | `:51-52` |
| baseline | 1px, hue @ `stroke-opacity 0.20` | `:53` |

- **x** is linear in time over the window; ticks at 0 / ¼ / ½ / ¾ / 1 labelled `HH:MM` in the
  operator's display zone. The window is the surface's own (lane detail: 90 min; Watchfloor: 60 min;
  the specimen draws 10 min because the canonical scenario is a 9-second burst).
- **y** is linear in `total_strength` from 0 to `max(alert_threshold × 1.35, peak) × 1.08`. **Never
  zero-suppressed** — this axis carries a threshold comparison, so a non-zero origin would make
  "above the bar" a drawing decision.
- **Sampling:** ≤ 120 points, rebuilt in a `useMemo` keyed on the newest sample's `emitted_at_ms`.
- **The SVG is capped at its viewBox width** (`max-width: 960px`). An `<svg>` at `width: 100%` scales
  its own coordinate system, so rem-sized `<text>` upscales with it and the `text-2xs` contract
  silently stops holding. This is the rule `17-COMPONENT-SPECS` asked this file to carry.

**Perch never renders the reference's numbers.** `stigmergy.svg:49` says `alert_threshold 1.20` and
`:9` says a 45 s half-life; the shipped values are 2.0 and 3600.0 (`AMB rulesets/default.yaml:58,55`).
The console reads config, always.

**The crossing is a step, not a slope, and that is the honest picture.** In the canonical scenario the
sum goes 0 → 1.799653 → 2.696884 in nine seconds, because a threshold crossing *is* a deposit
arrival. A drawing that smooths it into a rising curve is drawing a different mechanism. The specimen
draws the step.

### 4.3 Deposit trains — one row per strategy-scoped source, above the curve

The reference draws each detector's deposit train as a dotted row **above** the plot with the
indicator inline. That layout is load-bearing: it shows *which* detector contributed each step, which
is exactly what `exceeds_threshold` (`AMB swarm-core/src/pheromone.rs:331-337`) cares about, since it
requires `total_strength >= threshold` **and** `distinct_sources >= min_sources`.

Row: a `2 5` dashed rule at hue @ 0.10 from the first deposit to the right edge; the strategy id
right-anchored in the x<174 gutter in `t-xs` mono; the indicator inline, 14px right of the first
dot and 9px above the row, in `t-2xs`.

**Departure D8, recorded.** The reference decays each row's dot radius `4.26 → 2.79` and its opacity
`0.73 → 0.40` left to right — a fixed ramp that encodes nothing, and it fades the *freshest* deposit most.
Perch binds both channels to real values instead: **radius = `2.6 + 2.2 × confidence`**, **opacity =
`0.35 + 0.55 × (strength_at(now) / confidence)`**, i.e. the fraction of the deposit still standing.
An old, weak deposit is small and faint; a fresh, confident one is large and bright; and the picture
of "why is this threat class loud" is readable without the table. The dashed-rule grammar and the row
layout are unchanged.

A deposit suppressed by a `Dismiss` keeps its dot at `--perch-viz-suppressed-hatch` @ 0.30 with a
`--perch-danger-mark` cross over it. It is not removed: removing it is exactly the silent edit render
law 5 forbids.

### 4.4 Colour

| Element | Token | Why |
|---|---|---|
| area, curve, baseline, deposit dots | `--perch-viz-series-1` (= substrate mark) | deposits are substrate artifacts |
| `alert_threshold` rule, drop-line, crossing ring | `--perch-chart-rule` | a threshold is a policy object |
| the threshold's literal value | `--perch-chart-rule-label` | AA on `--perch-card` (5.53 light / 5.94 dark); see CR-10 |
| `incident_threshold` rule | `--perch-sev-critical` | the next state is an incident, not an alert |
| suppression hatch + marker | `--perch-viz-suppressed-hatch` + `--perch-sev-medium` | Dismiss is a *medium* act with a large consequence; it is not an error |
| axis text, indicators | `--perch-chart-axis-ink` / `--perch-foreground-muted` | |

An off-scale threshold is **named, never omitted**: when `incident_threshold` exceeds the y range, a
`2 6` dashed rule is drawn at the top of the plot and labelled
`incident_threshold 5.00 — above this view`. A threshold that is simply absent reads as a threshold
that does not exist. The specimen renders this case, because the canonical `incident_threshold` of
5.00 is above the canonical peak of 2.70.

### 4.5 States

| State | Rendering |
|---|---|
| **populated** | curve, trains, thresholds, crossing, caption `total_strength N.NN · <attribution> · peak_confidence N.NN`, derived + served markers |
| **empty** | `CORRECT_ZEROS.concentrationZero`: *"Concentration 0.00 / Every deposit in this threat class has decayed below the evaporation floor of {evaporationThreshold}. Nothing was deleted; strength approached zero."* No `/gaps` link — a decayed threat class is not a coverage claim. |
| **loading** | `LOADING.deposits` plus three skeleton bars. `role="status"`, `aria-live="polite"`. |
| **stale** | curve drawn from the last received samples; a warn note with the literal age; the forward segment labelled as an extrapolation and as a lower bound, with the suppression asymmetry named |
| **degraded** | the segment spanning a sequence gap is **dashed**, and a note names `expectedSeq → receivedSeq` and the missing count, with *"This is a gap in what Perch received, not a gap in what the daemon recorded."* |
| **error** | `DEGRADED.daemonUnreachable` — history readable, no decision recordable |
| **high-volume** | trains fold to the top contributor with a row saying how many are folded; the curve still includes all of them, and the caption says so |
| **suppressed** | hatched span from the earliest suppressed deposit to the marker, marker line `DISMISSED HH:MM by <operator>`, visible step down, crossed-out dots, and the arithmetic preview (§4.6) |
| **disagrees** | curve snaps to the served value; the caption states the delta against ε and prints `snapshotDisagrees → true`. Consecutive snaps within one second fold into one row with a count, so a flapping value cannot strobe |
| **regime B** (orthogonal to all nine) | the attribution's second half becomes the named absence; the caption names the half-life assumption |

The specimen renders all 9 × 2 × 2 = 36 combinations and the audit asserts every one is error-free.

### 4.6 The Dismiss arithmetic preview — render law 5, in words

The row previews what the dismissal will retroactively suppress **before** it is committed. Over the
canonical fixture the numbers are the fixture's own:

> **Dismiss previews its arithmetic.** Dismissing `hunt_id hunt-evt-1` removes 2 deposits from every
> sum at or before the marker, 1 of them from a detector you did not review, because one telemetry
> event fanned out to 2. `2.57 − 1.71 → 0.86`, now **below** `alert_threshold 2.00`. The suppression
> key is `(threat_class, event_id)`, so it reaches every detector that fired on that event. The dots
> stay on the trail with a cross over them; removing them would be the silent edit render law 5
> forbids.

The three clauses that must survive editing are *"a detector you did not review"*, the
before → after → threshold arithmetic, and the statement that the dots stay. Everything else is
phrasing. The canonical scenario makes this stronger than revision 1's invented one did: the dismissal
takes the threat class from above the bar to below it, which is the case where an operator most needs
to see the arithmetic first.

### 4.7 Accessibility

- `role="img"`, `<title>Concentration decay — {threat-class}</title>`, and a sentence-long
  `aria-label` naming the class, the window, the value and the threshold.
- Table toggle: one row per contributing deposit — agent, `strategy_id`, `host_id`, timestamp,
  confidence, `strength_at` — with the caption carrying the attribution.
- Colour is never the only channel: the crossing is a ring **and** a drop-line **and** a labelled
  caption; suppression is a hatch **and** a marker line **and** a step **and** a sentence.
- Deuteranopia is the design case, which is why the two most-used hues (green 308 uses, amber 79)
  never encode two values on the same element: green is always the series, amber is always a threshold.
- Reduced motion removes the crossing ring entirely (`@media (prefers-reduced-motion: reduce)
  { .crossring { display: none } }`). Nothing else on this chart moves.

### 4.8 Budget

12 curves × ≤120 points, rebuilt at **1 Hz**, ≤ **4 ms** `ScriptDuration` per tick measured by
`measureAction` (`BUZZ desktop/tests/e2e/perf/metrics.ts:42-68`, which opens a CDP session, reads
`Performance` metrics either side of the action and waits two rAFs). The interpolated "now" marker
moves via a CSS transform on a single `<g>`, so 59 frames in 60 touch no React and no layout.

---

## 5. VIZ-2 — `HostHeat`

**Purpose.** *Which three machines do I look at first?* A sorted bar list — not a treemap, not a
heatmap grid. Rank is the question; a 2-D encoding answers a different one and virtualizes worse.

### 5.1 Data contract, and the honesty problem it carries

```ts
export type HostHeatRow = {
  host_id: string | null;          // null is legal and is rendered, not dropped
  total_strength: number;          // Σ strength_at(now) over that host's surviving deposits
  attribution: SourceAttribution;  // CR-5
  depositCount: number;
  dominantThreatClass: string;
};
export type HostHeatProps = {
  rows: HostHeatRow[]; policy: ThreatClassPolicy; now: UnixSeconds;
  threatClass: string | null;      // null = estate-wide; see below
  state: VizState;
};
```

**Per-host concentration does not exist in the runtime.** `concentration_for` sums by threat class
only; there is no host axis anywhere in `swarm-pheromone`. Every number on this chart is therefore
derived, and the plate carries **one** derived marker for the whole chart rather than per-row ones:
`derived · per-host sum of strength_at(); the runtime has no per-host concentration`.

**Estate-wide by default, and the prop says so.** The question "which machine do I open first" is not
a per-class question, so `threatClass: null` sums across every class and the caption names the scope.
The per-class variant is the same component with the prop set, used on `/lanes/$laneId`.

**Decision D2 — the unattributed row.** `deposit_host_id`
(`AMB swarm-pheromone/src/substrate.rs:1336-1348`) resolves `indicator["host_id"]`, falls back to
`indicator./evidence/host_metadata/host_id`, and returns `None` otherwise. Deposits with neither are
rendered as a final row reading `host unattributed · no host_id on N deposits`, always sorted last
regardless of strength. Dropping them silently under-states exposure, and a short bar list is the
kind of wrong that looks right.

### 5.2 Geometry and colour

Row 46px at the specimen's density (28px compact / 36px comfortable in the shipped component). Host id
`t-sm` mono; the attribution plus the dominant threat class in `t-xs` beneath it; bar 8px tall
`rounded-sm`; value right-aligned `t-sm` mono `tabular-nums`.

**Decision D1 — bar hue.** `05` §8.1(b) says "bar hue is the dominant threat class's pillar", but the
pillar taxonomy assigns hues to *substrate / authority / evidence* (appendix §7), not to threat
classes, and `05` §8.3 itself rules that threat class is encoded by position and label. Resolution:
the bar is **`--perch-viz-series-1`** (the substrate mark — a deposit is a substrate artifact); the
segment beyond `alert_threshold` is **`--perch-viz-series-3`** (the authority mark); the threshold
tick is a 1px `--perch-chart-rule` vertical drawn across every bar at the same x. Threat class is the
label. No hue is spent on twelve categories, and "over the bar" is legible at a glance without
reading a number.

### 5.3 States

| State | Rendering |
|---|---|
| empty | *"Concentration 0.00 on every host"* + the evaporation floor + the 18/11 gaps sentence + a `/gaps` link (this **is** a swarm-produced-nothing state) |
| loading | `LOADING.deposits`, skeleton rows |
| stale | *"Bars are the last received values; the ranking may already have changed."* |
| degraded | *"The bridge is shedding the evidence stream to protect the alarm stream. Deposits still arrive on the daemon read; the cards do not."* |
| error | the partial-attribution case: *"41 of 58 deposits carry no `host_id` at either `indicator.host_id` or `/evidence/host_metadata/host_id`. The bars below cover 17 deposits."* |
| high-volume | all rows, virtualized through the inherited `VirtualizedList` (`BUZZ desktop/src/shared/ui/VirtualizedList.tsx`, whose migration contract requires rows to tolerate unmount/remount — these do, being pure functions of a row object); ordering computed once per snapshot, never per frame |
| suppressed | affected rows drop together, with a note naming the shared telemetry event and the `(threat_class, event_id)` key |
| disagrees | **there is nothing to disagree with**, and the plate says so: the runtime publishes no per-host concentration, which is why the derived marker sits on the plate rather than on the rows |

### 5.4 Accessibility and budget

`role="img"` on the figure with an `aria-label` naming the row count, the leading host, its value and
the threshold. Table toggle gives `host_id / total_strength / attribution / dominant threat class /
deposits`. Budget: ≤200 rows unvirtualized, ≤1 ms per 1 Hz recompute; above 200 the `VirtualizedList`
path.

---

## 6. VIZ-3 — `KillChainGraph`

**Purpose.** *What did the swarm join together, and what did it refuse to join?* A left-to-right DAG
over one `CorrelatedIncident`'s members.

### 6.1 Data contract

```ts
// AMB crates/swarm-spine/src/incident.rs:114-132, :99-111, :135-170
export type IncidentGraphDimension = "temporal" | "causal" | "entity" | "semantic";  // closed, 4
export type IncidentEvidenceLink = {
  dimension: IncidentGraphDimension; explanation: string;
  shared_values: string[]; weight: number;
};
export type IncidentMemberDecision = {
  investigation_id: string; hunt_id: string; finding_id: string;
  reason: string;                       // rendered verbatim on a rejected node
  shared_keys: string[];                // a "host:<id>" key here is what makes a later
  evidence_links: IncidentEvidenceLink[]; // HostExclusionReview reachable at all
  confidence_score: number;
};
export type KillChainProps = {
  incidentId: string;
  included: IncidentMemberDecision[];
  rejected: IncidentMemberDecision[];   // REQUIRED. The prop has no default and no optional marker.
  dimensions: IncidentGraphDimension[];
  state: VizState;
};
```

`rejected` being non-optional is the whole component. An incident graph that shows only what was
included is an argument, not evidence.

### 6.2 Encoding

Edges are typed by dimension and rendered as **four dash patterns, not four colours** — the pillar
hues are spoken for and four more hues would collide with the series rotation:

| Dimension | `stroke-dasharray` |
|---|---|
| `temporal` | solid |
| `causal` | `4 2` |
| `entity` | `2 2` |
| `semantic` | `6 3` |

Node: 232 × 56 `rounded-md`, `--perch-card` fill, 1px `--perch-pillar-evidence-mark` stroke, a 2.5px
evidence top rail, three lines — `strategy_id` in `t-sm` mono, then `host · finding_id · confidence`
in `t-xs`, then the reason in `t-2xs`, **truncated to 33 characters**. The truncation is not a
cosmetic choice: at 11px in a 232px box the third line overflows the node at 44 characters, which
screenshot review caught and no lint would have. The whole reason is always reachable in the table.

Rejected members are drawn **below a 1px `--perch-border-strong` rule**, at 62% opacity with a `3 3`
dashed border, each with its `reason` printed beside it in full.

The seed member's reason is the literal `"seed investigation"` at confidence 1.0, which the
correlation stage mints at `AMB crates/swarm-runtime/src/correlation.rs:120`.

### 6.3 States

| State | Rendering |
|---|---|
| empty | this case was promoted by hand, so the correlation stage has produced no graph; a verdict recorded now attaches to the single-member incident record minted at promotion (**B3i**, which does not exist) |
| error | `POST /v1/providence/feedback → 404 incident_not_found` — the wall B3i exists to remove; `providence_feedback_handler` loads by `incident_id` and 404s when it misses (`AMB crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:129-137`, in `swarm_detect --serve`), and `resolve_feedback_target` then requires `included_members` to contain the `finding_id` |
| stale | the record's assembly time, stated — this is a snapshot taken when the stage assembled it, not a live view |
| degraded | the async correlation stage's queued/running counts, **plus the sentence that matters**: a candidate not yet scored is absent from both halves, and absent is not the same as refused |
| high-volume | above 12 nodes the drawing shows the seed plus its direct links and the rest moves to the table — a 41-node DAG is a picture of a picture |
| suppressed | a member resting on a dismissed event **stays on the graph** (the record is what it was when assembled) and carries the dismissal as a member note |
| disagrees | nothing on this plate is derived, so nothing can disagree; every field is read from the incident record, and the plate says so rather than leaving the state blank |

### 6.4 Accessibility and budget

`role="img"` + `<title>` + a sentence naming the counts; the table toggle emits one row per member
with an included/rejected column and the **full** `finding_id`, so the rejected set is reachable
without reading a diagram and no decision is made against a truncation
(`BUZZ desktop/src/shared/ui/PubKey.tsx:21-31` states the reason: a truncated key is forgeable by
vanity grinding). Layout is a fixed column/row grid computed once — no force simulation, no animation,
no layout thrash. Budget: ≤12 drawn nodes, one render per incident change.

---

## 7. VIZ-4 — `IncidentTimeline`

**Purpose.** *What happened, in what order, and where did the number cross the bar?* One column, one
row per typed event, a 4px left rail per kind.

### 7.1 Row kinds — six inherited, five added, union closed

Ambush's own workbench already draws this shape: `.timeline-item` with a `#9fb2c8` default rail plus
five modifiers, inside a server-rendered review page built by `format!` in
`AMB crates/swarm-runtime-http/src/http/render.rs:66-71` (served under `swarmctl serve`, read by no
client code). Perch keeps the rail, restates the colours on the pillar taxonomy, and adds five kinds
the workbench has no analogue for:

| Kind | Workbench rail | Perch rail | Source |
|---|---|---|---|
| `ingest` | `#15803d` | substrate | `RuntimeEvent::Ingest` (tallied, §9) |
| `finding` | — | substrate | `swarm:finding:v1` |
| `escalation` | `#c2410c` | authority | `RuntimeEvent::Escalation` |
| `mode_transition` | `#0f4f8a` | authority | `RuntimeEvent::ModeTransition` / `26003` |
| `agent_health` | `#2563eb` | evidence | `26002` |
| `response_execution` | `#7c3aed` | evidence | `swarm:receipt:v1` |
| **`suppression`** | — | `--perch-sev-medium` | a `Dismiss` marker deposit |
| **`hold`** | — | authority | `kind:46010` / `swarm:hold:v1` |
| **`decision`** | — | `--perch-foreground` | `swarm:verdict:v1` |
| **`containment_open`** | — | evidence | `swarm:lease:v1` |
| **`containment_close`** | — | evidence | `swarm:rollback:v1` |

The union is closed and the renderer switch is exhaustive with no `default:` arm, so a twelfth row
kind fails to compile rather than rendering as a grey line. The specimen renders the ledger as a table
so the closure is inspectable.

### 7.2 The crossing row

A threshold crossing is **a row with its own arithmetic**, never a tick on someone else's axis:

```
09:14:41  ESCALATION · ALERT   [CRITICAL ▮▮▮▮]
          total_strength 2.70 crossed alert_threshold 2.00
          2 sources / 1 agent · peak_confidence 0.90
          ├─ a 620×30 detail of the real curve either side of the crossing
```

The inline detail is computed from the same `concentrationAt()` the flagship uses — never a
decorative squiggle. It carries the baseline, the dashed `alert_threshold` rule and one crossing dot,
and nothing else.

A second crossing type is rendered and is easy to miss: **the diversity threshold**, the moment
`distinct_sources` first reached `min_sources_for_escalation` while `total_strength` was still below
`alert_threshold`. `exceeds_threshold` needs both axes, and an operator watching only strength cannot
see the other one arrive.

```
09:14:32  DIVERSITY THRESHOLD
          distinct_sources 2 sources / 1 agent reached min_sources_for_escalation 2.
          total_strength 1.80 is still below alert_threshold 2.00 — exceeds_threshold needs both axes.
```

The row label is `DIVERSITY THRESHOLD` and not `SOURCE DIVERSITY` for a mechanical reason found by
running the copy gate: `bare-source-count`'s pattern `(^|[^a-z])sources?([^a-z]|$)` matches the word
"SOURCE" in a two-word heading, and its exemption is the substring `agent`, which a heading has no
business carrying. See §17's guard-scope note.

**The 10 Hz problem, and the dedupe that fixes it.** `evaluate_threat_class`
(`AMB crates/swarm-runtime/src/escalation.rs:61-103`) is a pure level comparison with no memory of
prior state: it returns `Some(EscalationEvent)` on *every* evaluation while over threshold, and
`evaluate_all` publishes one `RuntimeEvent::Escalation` per over-threshold class per tick (`:148`) at
the monitor's 100 ms cadence. Twelve classes over threshold is up to 120 events per second.
`11-BRIDGE-CRATE.md` owns the mitigation and has corrected an earlier reading of it: the ten ticks in
one second are **not** byte-identical, because `escalation.rs:253` and `:288` stamp a fresh
`emitted_at_ms`, so the fix is **edge-triggering on `(threat_class, level)` with a bounded heartbeat**,
not deduplication on a timestamp. The timeline renders one row per crossing either way; the client
must not implement its own dedupe and assume the bridge did not.

### 7.3 States

| State | Rendering |
|---|---|
| empty | `EMPTY.watchNoFindings` — 18 techniques across 11 detectors declared uncovered → `/gaps`; an empty case is a claim about what was looked for, not about what is there |
| loading | `LOADING.case` with the case id |
| stale | a `LATE-PUBLISHED` divider naming the spool delay: *"held in the bridge spool 22 min · `created_at` is a transport timestamp"* |
| degraded | two in-place dividers, never toasts: the gap row (`sequence 4,118 → 4,393 … 275 envelopes not delivered`) with a **re-fetch from the daemon** affordance, and the coalescing row (`340 finding cards coalesced into 12`) with the sentence that a coalesced block is not a gap and never renders as one |
| error | partial-record note naming what closed the subscription, and stating that no row is a claim that nothing else happened |
| high-volume | virtualized; a footer row states how many further rows exist and the 500-row page size |
| suppressed | an additional detail row naming how many detectors the Dismiss reached and how many were never reviewed |

Ordering is `emitted_at_ms` with `seq` breaking ties within an issuer; `created_at` is used only when
a body carries no domain time, because `created_at` is stamped at publish and is a transport
timestamp (forced by `MAX_TIMESTAMP_DRIFT_SECS` = 900 s, which *rejects*).

### 7.4 Honest badges on this surface

- A receipt row carries **`NO SIGNATURE OF ITS OWN`** and the sentence *"this card is a copy; the
  daemon holds the record"*, with a verify affordance that re-fetches by id and compares canonical
  bytes. It never says "signed" or "verified": four of the seven marker card types carry no Ed25519
  signature under any condition (brief A8).
- A decision row carries the **derived** marker naming the hold store, because a granted destructive
  action is byte-indistinguishable in Ambush's own records from an autonomous one until **B2o** threads
  `approved_by` through `ResponseReceiptAudit` — which today has exactly two fields, `policy` and
  `governance`, and whose `governing_agent_id` is Tom, not a human
  (`AMB crates/swarm-response/src/lib.rs:118-142`).
- A containment-close row reads `lease_closed` and `fully_reversed` from the body, never from the
  HTTP status, and renders one of exactly five `RollbackStepStatus` values —
  `Reversed | Simulated | Irreversible | Unsupported | Failed`
  (`AMB crates/swarm-response/src/rollback.rs:209-223`), never collapsed, with `restored()` true only
  for `Reversed` (`:225-229`).
- A **hold row for a non-containment destructive action** states the absence in place:
  `no containment lease — is_containment_action matches four of the twelve destructive actions and
  this is not one of them, so there is no TTL, no countdown and no rollback receipt`. The canonical
  fixture's `block_egress` hold exists to make this row real rather than hypothetical.

### 7.5 The two-operator case — a `superseded` decision row (review finding 10)

The review found that nothing in the wave-2 set handles two operators deciding one hold. The
mechanism is real and I verified the halves that touch this component:

- `APPENDIX-NORMATIVE.md` §4 layer 1 `p`-tags **every** `OperatorScope::Approve` principal, so more
  than one console legitimately holds the same open hold, and §13's declined-amendment note confirms
  the watch claim does not narrow it.
- `12-BACKEND-BILL-API.md` §4.4 resolves the *daemon* side with `409 hold_already_deciding`.
- But leg 1 — the signed human-intent card — is published to the relay **before** leg 2 hits the
  daemon (`13-WIRE-SCHEMAS.md`'s publish order), the relay has no compare-and-set, and a `kind:9`
  event is immutable. So both cards land in the case channel, both are signed by real operators, and
  `leg2.state`'s enum in `schemas/card-swarm-verdict-v1.schema.json` is
  `sending | recorded | acknowledged | refused_late` — **no value means "another operator's decision
  was the one that executed"**.

That is a wire gap, and `13-WIRE-SCHEMAS.md` owns the fix. What this file owns is **what the timeline
draws when it happens**, and it needs to be drawn or the Ledger export contains two "human intent
records" for one hold with nothing distinguishing them.

**The rendering, specified.** A `decision` row is not a new kind; it gains a state:

| `leg2.state` | Row renders |
|---|---|
| `recorded` / `acknowledged` | as today |
| `sending` | the four-phase write state, no outcome claimed |
| `refused_late` | the existing late-refusal treatment |
| **`superseded`** *(proposed)* | the row keeps its rail and its operator attribution, drops to the muted ink, and carries the literal `NOT THE DECISION THAT EXECUTED` plus a link to the winning card by its `nostr_intent_event_id`. It is never deleted and never hidden. |
| **no matching daemon record** | the reconciliation case: a verdict card the daemon has never confirmed renders `UNCONFIRMED AGAINST THE DAEMON — this is a signed intent, not a decision`, with the same re-read affordance the receipt row uses |

Both are render law 3's grammar, and the second is the important one: it is a *client-side* rule that
needs no wire change and closes the hole even if `superseded` is never ratified. A signed intent card
with no daemon decision record behind it is exactly the object that must not be allowed to read as a
decision.

**Filed against peers, not decided here:**
- `13-WIRE-SCHEMAS.md`: add `superseded` to `card-swarm-verdict-v1.schema.json`'s `leg2.state` enum,
  carrying the winning `nostr_intent_event_id`, and specify that the console receiving the `409`
  publishes it.
- `16-INVARIANT-TESTS.md`: a P0 invariant in INV-12/INV-35's neighbourhood, with a two-console E2E —
  two operators, one hold, one 409, and an assertion that the losing card renders as not-the-decision.
- `22-DEMO-FIXTURE.md`: the second card, if the demo is ever run with two consoles.

### 7.6 Budget

Rows are pure functions of a typed event, so the timeline reuses `VirtualizedList` directly. Budget
follows the case-scroll target: ≥55 fps with 500 evidence cards, no frame over 33 ms
(`case-scroll.perf.ts`).

---

## 8. VIZ-5 — `ContainmentLeaseTimer`

**Purpose.** *What is still contained, and is the sweep keeping up?* Not a chart — a table with one
live column. It is specified here because it shares the `tabular-nums` and 1 Hz-tick rules, and
because it is the one surface where a progress bar is forbidden by name.

### 8.1 Data contract

```ts
// AMB crates/swarm-runtime-http/src/http/containment.rs:71-95, produced by
// containment_lease_list_handler from sweep.open_leases() inside `swarm_detect --serve`.
export type ContainmentLeaseView = {
  lease: {
    lease_id: string;
    action: ResponseAction;              // the TYPED variant, never its name
    origin_receipt_id: string;
    governance_receipt_id: string | null;
    blast_radius: ResponseBlastRadiusPreview;
    rollback: ResponseRollbackPreview;
    issued_at_ms: UnixMillis;
    expires_at_ms: UnixMillis;
  };
  remaining_ms: number;   // SATURATES AT ZERO
  expired: boolean;       // the field that answers what remaining_ms cannot
};
export type ContainmentLeaseListResponse = {
  schema_version: number; observed_at_ms: UnixMillis; open_leases: ContainmentLeaseView[];
};
```

### 8.2 Two facts, two lines, never one bar

The struct's own doc comment is the design spec and is worth quoting because it is the reason for the
whole component:

> `ContainmentLease::remaining_ms` SATURATES AT ZERO, so this field alone cannot distinguish
> "expires in an instant" from "expired an hour ago and the sweep has not managed to release it".
> `Self::expired` is the field that answers that, which is why both are here rather than one.
> — `AMB crates/swarm-runtime-http/src/http/containment.rs:76-81`

The saturating method is `expires_at_ms.saturating_sub(now_ms).max(0)`
(`AMB crates/swarm-response/src/containment.rs:276`) and `is_expired` is a pure `now_ms >=
expires_at_ms` (`:271`). So the row renders `remaining_ms` on one line and `expired` on the next.
**A single progress bar reaching zero renders the two states identically, which is precisely what the
API refused to do.**

| State | Derivation | Token | Non-colour channel |
|---|---|---|---|
| open | `!expired && remaining_ms > 0` | `--perch-pillar-evidence-ink` | countdown `mm:ss` + the word `OPEN` |
| expiring | `remaining_ms < 15_000` | `--perch-sev-high` | countdown + the word `EXPIRING` |
| **expired, still listed** | `expired == true` | `--perch-sev-critical` | `EXPIRED, HOST STILL CONTAINED · the sweep tried and failed` |
| released | absent from the listing | `--perch-foreground-muted` | `RELEASED` |
| release failed | `lease_closed == false` on an HTTP 200 | `--perch-sev-critical` | `RELEASE FAILED · the containment is still in place` |

The specimen draws four rows covering open, expiring, expired-still-listed and no-inverse, at the
canonical clock, with the expired one issued 74 minutes before "now" so it is unmistakably not a
countdown that just finished.

### 8.3 Two numbers that must not be confused, and one that was

**Correction to `APPENDIX-NORMATIVE.md` §6 (line 214).** The row *`lease_ttl_ms` 60,000 — mint at
decision time, never hold time · `rulesets/default.yaml:94`* is correct **for the capability lease** —
the object `StaticApprovalGate::issue_lease` mints as `context.now_ms + self.lease_ttl_ms`
(`AMB crates/swarm-policy/src/static_gate.rs:307-324`) and `ensure_active_lease` later checks
(`swarm-runtime/src/lib.rs:1369-1379`). The object an operator watches count down on this board is a
**containment lease**, whose TTL is `runtime.containment.lease_ttl_ms`, default **900,000 ms /
15 minutes** (`AMB crates/swarm-core/src/config/defaults.rs:23-27`, whose own doc says "Fifteen
minutes. Long enough for an analyst to look at an alert"). `rulesets/default.yaml` cannot set it — the
file is digest-signed and the block is absent by design. **A board rendering 60 s beside a
`ContainmentLeaseView` is wrong by 15×.** The vocabulary rule (appendix §7: never bare "lease" in a
label) exists for exactly this collision, and this is the artifact where it would have gone wrong.
Three peers have now filed the same amendment; it should be one row split in two, not three notes.

### 8.4 Only four of the twelve destructive actions ever appear here

`is_containment_action` (`AMB crates/swarm-runtime/src/containment.rs:54-63`, called by
`prepare_containment` before execute in the daemon) matches only `QuarantineFile | SuspendProcess |
IsolateHost | TerminateUserSession`. The other eight destructive actions mint no containment lease,
have no TTL, no countdown and no rollback receipt — **their row renders no timer slot at all**, rather
than an empty one. Of the four, `TerminateUserSession` resolves to `InverseGap::Irreversible`
(`AMB crates/swarm-response/src/rollback.rs:181-189`, whose own comment says re-permitting login is
not the inverse of ending a session), leaving three with executable inverses:
`ReleaseQuarantinedFile`, `ResumeProcess`, `RestoreHostConnectivity`. The honest ladder is
**12 destructive → 4 leased → 3 reversible**, and the `IF YOU UNDO` column states which rung a row is
on. The specimen makes the absent case visible by naming the canonical `block_egress` hold in a note
beneath the board.

### 8.5 States, ordering, and the one that is a configuration

- **error → "No containment lease store is configured."** `ContainmentSettings.lease_store_path`
  defaults to `None`, and with no store `prepare_containment` returns
  `RuntimeError::ContainmentRefused` (`AMB crates/swarm-runtime/src/lib.rs:836-844`) for all four
  containment actions — so a granted `isolate_host` fails **at the decide route**. This is a
  first-class state on this board, not a 500, and the copy says which four actions it disables and
  that the other eight are unaffected.
- **stale** — the board's countdowns derive from `observed_at_ms` plus local elapsed time. A
  containment lease that lapsed inside the staleness window still shows as open, and the note says so.
- **degraded** — daemon unreachable: readable, not releasable, and *"An open containment lease's own
  TTL is the only backstop while this lasts."*
- **disagrees** — Perch lists 4 open containment leases, `swarmctl quarantine list` against the same
  daemon returns 3. Neither number is treated as right until the read repeats, and the disagreement is itself
  reportable (it is one of the C9 counters).

**Ordering is the daemon's** (`expires_at_ms`, then `lease_id`) and is **never re-sorted client-side**,
so two operators looking at two screens are looking at the same list in the same order.

The release affordance is an outlined chip carrying its own scope requirement
(`Release — requires Maintenance scope`), never a filled button —
`require_operator_api_scope(Maintenance)` is checked in the handler body at
`AMB crates/swarm-runtime-http/src/http/containment.rs:197`, and a control that looks enabled and is
not is worse than one that states its precondition.

### 8.6 Budget

One `useLeaseClock()` tick at the board level publishing a single `nowMillis`; each row derives from a
scalar prop, never from a per-row interval. A colony with more than 200 open containments is an
incident, not a scrolling problem, so this list is plain — no virtualization.

---

## 9. VIZ-6 — `RateSparkline`

**Purpose.** *Is the estate still talking to us, and are we dropping any of it?* Three 1 Hz series
plus one capped distribution.

### 9.1 Data contract

```ts
// Ephemeral kind 26000, 1 Hz — appendix §3. Built by the bridge from
// RuntimeEvent::Ingest { emitted_at_ms, correlation_id, event_id, source, host_id, accepted,
// reason } (AMB crates/swarm-runtime/src/runtime_events.rs:215-223), tallied and dropped at source.
export type IngestGauge = {
  emitted_at_ms: UnixMillis;
  accepted: number;                       // per second
  rejected: number;                       // the daemon refused the telemetry
  by_source: Record<string, number>;      // capped at 5 + "other" AT THE BRIDGE
};
export type RateSparklineProps = {
  values: number[];                       // 60 samples; the component never fetches
  seriesClass: "viz-series-1" | "sev-medium" | "sev-high";
  stale?: boolean;                        // stops the line rather than drawing a flat one
  label: string; value: string;           // the number the sparkline summarizes
};
```

**`shed` is not on the wire.** It is the bridge's own counter
(`perch_bridge_dropped_events_total`), read from the same process that publishes the gauge, and it is
a **different fact** from `rejected`: rejected means the daemon refused the telemetry; shed means the
bridge dropped a frame it had already accepted. They are two series and are never merged into one
line.

### 9.2 Geometry and the scale decision

60 × 16 (inline) or 220 × 22 (in a labelled row), no axes, one series, `stroke-width: 1.5`, last point
marked with an `r=1.5` filled dot in the same hue. **Only ever adjacent to the number it summarizes.**

**Scale is the window's own min–max, not zero-based**, and the caption says so. A 12,400/s rate drawn
against a zero baseline is a flat line that tells an operator nothing, and the absolute value sits
beside it, so the zoom cannot mislead. A flat series (a genuine constant, e.g. zero shed) is drawn as
a centred flat line rather than pinned to an edge.

The distribution beneath is a horizontal stacked bar for `by_source`, **capped at five segments plus
`other`**, 10px tall, endpoint labels in `t-2xs`, one `--perch-viz-series-N` per segment. The cap is
applied **at the bridge**, not in the component, so the wire payload is bounded.

### 9.3 The stream Perch refuses to carry

`RuntimeEvent::Ingest` is emitted once per accepted telemetry event, and the hot path sustains
3,645/s over HTTP. Publishing one relay event per ingested event exceeds the per-pubkey write quota by
roughly 1,800×, fills the case channel with rows no operator reads, doubles Postgres write volume, and
is already recorded in the `ReplayBundle`. The console shows a **rate**; the drill-down is the
case-scoped `swarmctl` terminal, which is where the raw record actually lives. A 1-in-N sample is
worse than a rate, because it looks like a record. That paragraph belongs on the surface, and it is on
the plate.

### 9.4 States

| State | Rendering |
|---|---|
| empty | *"No telemetry in this window"* — and the honest reading: zero accepted **and** zero rejected means the daemon is not receiving input, not that it is refusing it |
| loading | `LOADING.watch`, skeletons |
| stale | the line **stops** rather than flat-lining, because a drawn flat line is a claim that the rate was zero |
| degraded | `bridge: shedding` — the evidence stream shedding oldest-first so the alarm stream keeps its budget, with the window's shed count and the counter name |
| error | per-frame relay rejection (`rate-limited: shared admission unavailable`), with the load-bearing reassurance: held actions still arrive, because the alarm stream has its own identity and its own budget and is never coalesced or shed |
| high-volume | sustained above the 3,645/s hot-path measurement; shedding starts at the pacer, is counted, and is drawn |
| suppressed | a dismissal is a pheromone-substrate act and does not touch ingest; the gauge is unchanged and says so, which is cheaper than letting an operator wonder |
| disagrees | the bridge's tally vs the daemon's own `/metrics` counter. Neither is wrong: the bridge counts what it received on a broadcast channel whose lagged receivers drop silently, so the difference is **a lower bound on the drop** |

### 9.5 Accessibility and budget

The sparkline itself is `aria-hidden` — it is a redundant encoding of the number beside it, and
announcing a path is noise. The row is a definition-list entry, and the table toggle gives the last
ten samples per series. Live regions are used for exactly three things across the whole console: a new
needs-action item (`polite`), a mode transition to Incident (`assertive`), and a containment that
failed to release (`assertive`). A gauge tick announces nothing.

Budget: 60 points × 3 series, recomputed at 1 Hz, path strings memoized on the newest sample.

---

## 10. Accessibility ledger

| Commitment | Mechanism | Status |
|---|---|---|
| Colour is never the only channel | severity = word + 4-segment bar + hue; series = endpoint label + dash + hue; containment = word + countdown + hue; crossing = ring + drop-line + caption; suppression = hatch + marker + step + sentence | specified, all six |
| Deuteranopia is the design case | green (308 asset uses) is always the series; amber (79) is always a threshold; the two never encode two values on one element | specified |
| Every chart has `role="img"`, `<title>`, a sentence `aria-label` | follows Ambush's own asset convention — all 20 SVGs carry both | specified, all six; the specimen renders them |
| Every chart has a table toggle | the screen-reader path **and** the copy-paste path | specified, all six; the specimen renders them |
| Axis labels are rem tokens | `className`, never an attribute | **enforced** by G1 (§13) |
| Product text is readable | ≥14px carries primary content; nothing at 8px | **measured**: 43.4% ≥14px, 0 at 8px (§3.5); the audit fails below 25% |
| Reduced motion | the crossing ring is the only chart animation and it is removed entirely under `prefers-reduced-motion: reduce` | specified and implemented |
| Focus | `--perch-ring` `#5f8f78` dark / `#40564c` light — 4.99 and 7.91 on `--perch-card`, against WCAG 2.2 SC 1.4.11's 3:1. `05` §11's rebinding to `--border-strong` measures 1.77 and fails | adopted (19-TOKENS amendment T3) |
| Series contrast | all six clear the 3:1 non-text bar on every surface in both themes; measured minima **5.19** dark (series 4 on raised) and **4.02** light (series 6 on raised) | measured — revision 1's "6.7 / 4.2" was wrong in both themes |
| Chart ground | CR-10: `--perch-card`. `--perch-chart-rule-label` is 5.53 light / 5.94 dark there, and 4.51 / 4.55 on `--perch-surface-raised` — inside HSL rounding | measured |

**One thing this layer cannot fix.** `applyAccentColor`
(`BUZZ desktop/src/shared/theme/ThemeProvider.tsx:198,213-218,231-236`) writes six theme variables
inline on the root element in the webview on every theme or accent change, and inline root styles beat
every stylesheet layer. With the accent picker alive, a red accent makes a `CRITICAL` badge
meaningless and no token file can defend against it. **The chart layer's contrast guarantees are
conditional on deleting the picker** (`05` §2.8's deletion, ten entries at `ThemeProvider.tsx:44-55`).
Recorded here because it is a dependency of an accessibility claim, not a cosmetic cleanup. Note that
this is the *same mechanism* as §3.2's namespace rule: the picker writes six of the 38, and G2's R4
prevents a chart reading any of them, so the charts are already defended even before the deletion —
which is a second reason the deletion is a Perch-wide cleanup rather than a chart blocker.

---

## 11. Rendering budget, and the tests that hold it

From `07` §9 and §12, restated as the chart layer's obligations:

| Budget | Value | Test |
|---|---|---|
| Substrate SVG per 1 Hz tick | ≤ **4 ms** `ScriptDuration`, 12 curves × ≤120 points | `watchfloor-busy.perf.ts` via `measureAction` |
| Telemetry burst while typing | quiet-vs-busy p95 keystroke delta ≤ 15 ms | `watchfloor-busy.perf.ts` |
| Case scroll, 500 evidence cards | ≥ 55 fps, no frame > 33 ms | `case-scroll.perf.ts` |
| Cold open of `/` with 200 queue rows | total longtask ≤ 200 ms, no single task > 100 ms | `watch-cold.perf.ts` |

Four `React.memo` traps apply to this layer specifically, and all four are the shapes Buzz's own
`AGENTS.md` gotcha 6 names:

| Offender | Fix |
|---|---|
| `Map<threatClass, Concentration>` rebuilt from each 1 Hz snapshot | `useStableMap` (`BUZZ desktop/src/shared/hooks/useStableReference.ts`) — 11 of 12 classes are usually unchanged, so 11 rows bail |
| `Map<agentId, AgentFrame>` from the telemetry stream | `useStableMap` |
| a `useMutation` result threaded into a chart | pass `mutateAsync` and a `status` string, never the mutation object |
| `remaining_ms` recomputed per second per containment row | one board-level clock publishing a scalar; rows derive from a prop |

Measurement discipline is Buzz's, verbatim: measure with DevTools **closed** and no per-keystroke
logging, and isolate by removing one suspect at a time.

---

## 12. Sizing

| Component | New LOC (impl) | New LOC (test) | Notes |
|---|---:|---:|---|
| shared layer (`desktop/src/shared/viz/types.ts` — a DESTINATION path, see §16; scales, markers, table toggle, hatch + gradient defs) | 280 | 200 | +20/+20 over revision 1: `SourceAttribution`'s two arms and the `stop-color` class family |
| VIZ-1 `ConcentrationCurve` | 380 | 260 | the only one with arithmetic to test |
| VIZ-2 `HostHeat` | 160 | 90 | |
| VIZ-3 `KillChainGraph` | 220 | 110 | |
| VIZ-4 `IncidentTimeline` | 250 | 160 | Phase 1; +10/+10 for the `superseded` and unconfirmed decision-row states |
| VIZ-5 `ContainmentLeaseTimer` | 190 | 140 | five states, all asserted |
| VIZ-6 `RateSparkline` | 120 | 70 | |
| **total** | **1,600** | **1,030** | inside `05` §8's 1,200–1,800 estimate for impl |

The two CI guards are no longer an estimate — they are written (§13) and measured:
`check-svg-font-size.mjs` is 256 lines and `check-perch-chart-tokens.sh` is 248, both including their
self-test fixtures and their "what this cannot see" headers, which are together roughly half of each.

Every file is new and under `desktop/src/shared/viz/` or `desktop/src/features/<surface>/ui/`, so none
of them touches the three frozen files in `desktop/src/shared/api/` (`tauri.ts` 1108,
`relayClientSession.ts` 1084, `types.ts` exactly 1000 — all at or over the 1000-line cap, which the
differential ratchet pins at their current size).

---

## 13. Guards — delivered, not proposed

Revision 1 named three guards. Two of them are now written, self-testing, and run. The review's
finding 9 — eleven gates named across the wave and not delivered — is answered for this artifact's
share of them.

### G1 — `viz/check-svg-font-size.mjs` → `BUZZ desktop/scripts/check-svg-font-size.mjs`

**The hole it closes.** `scripts/check-px-text-core.mjs` has exactly two regexes:
`TEXT_ARBITRARY_RE = /\btext-\[\d+(?:\.\d+)?(?:px|rem|em)\]/g` (`:29`) matches only a Tailwind
arbitrary utility, and `FONT_SIZE_PX_RE = /(?<!-)\bfont-size:\s*\d+(?:\.\d+)?px/g` (`:32`) **requires
a colon**. Neither can see `<text font-size="11">`, `<text fontSize={11}>` or
`style={{ fontSize: 11 }}`. Perch's entire chart layer is hand-authored SVG, so the hole sits directly
under the work.

**Three rules.** The attribute form and the JSX-prop form are forbidden **unconditionally, rem
included** — an `<svg>` at `width: 100%` rescales its own coordinate system, so a rem inside it is
multiplied by the viewBox scale and stops being the token it names. The style-object form is the one
rule with an allowance, for `var()` / `calc()` / `rem`, because a style object is sometimes the only
way to reach a computed token.

**It self-tests before it scans.** Seven planted shapes must all be caught (two of them rem-bearing,
which is what pins the attribute rules as unconditional rather than value-dependent) and six clean
controls must all pass. If the scanner is broken it exits 2 with `SELF-TEST FAILED` rather than
reporting a clean tree.

**Measured against the real Buzz tree at `eed74bde2`:**

```
$ node viz/check-svg-font-size.mjs desktop/src
check-svg-font-size: OK (1664 files, self-test 7 caught / 6 controls clean, 4 allowlisted glyph literal(s))
```

The first run flagged seven sites and reading them produced one real bug in the guard and four real
allowlist entries:

- **`typography.css:46` and `:50`** — `:root[data-font-size="smaller"]`. A CSS **attribute selector**,
  and in fact the very mechanism the zoom contract is built on. The guard was wrong; it now requires
  the character before `font-size` to be neither a word character nor `-`, the same way the shipped
  `FONT_SIZE_PX_RE` guards against `--font-size:`. Both lines are now clean controls in the fixture,
  so the false positive cannot recur.
- **`ProfileAvatarEditor.utils.ts:262`** — a 512×512 emoji-avatar SVG serialised to a `data:` URL and
  used as an `<img>`. A glyph sized to its box, rendered at a fixed size. Allowlisted, the same class
  `check-px-text` already exempts with its `text-[6rem]` avatar overrides.
- **`EmojiBurstProvider.tsx:457,486,510,549`** — emoji particle sizes in the burst animation. Not
  text. Allowlisted, and the entry is expected to be *removable* rather than permanent, because
  `17-COMPONENT-SPECS` §8 deletes that subsystem.

Product copy is never allowlisted. All four entries are glyphs.

**Wiring, two parts, same commit.** `desktop/package.json` gains
`"check:svg-font-size": "node ./scripts/check-svg-font-size.mjs src"` appended to the existing
`check` chain (`"biome check . && pnpm check:px-text && pnpm check:pubkey-truncation"`). BUZZ has no
`tools/` directory, so this rides `check` exactly as `check-px-text` does, and it is **not** an Ambush
gate — it does not appear in `tools/check-gates-wired.sh`.

### G2 — `viz/check-perch-chart-tokens.sh` → `AMBUSH tools/check-perch-chart-tokens.sh`

Four rules, each the mechanical half of a rule in §3.1:

| Rule | Forbids | CR |
|---|---|---|
| **R1** | a 3- or 6-digit hex colour literal outside a comment | CR-2 |
| **R2** | a `fill=` / `stroke=` presentation attribute other than `none` or `url(#…)` | CR-2 |
| **R3** | a prop named `sources` typed `number` | CR-5 |
| **R4** | `var(--<any of the 38 Buzz shadcn names>)` — the alternation is written out in the script | CR-2, §3.2 |

**R4 is the one that matters most**, and it is the answer to the review's blocking finding: it turns
`19-TOKENS`'s namespace commitment from a memo into a build failure, with the 38 names enumerated in
the file so nobody has to remember them.

**It self-tests before it scans**, following `tools/check-single-governor-key.sh`'s convention: ten
planted shapes across four rules must all fire, and thirteen clean controls must all pass — including
both allowed paint values, a `--perch-*` var, a `sourceIds: string[]` prop, a hex in a block comment,
a hex in a trailing comment, and a `https://…/#aabbcc` URL fragment (which is what forced the hex rule
to require a non-slash, non-word character before the `#`).

Comments are stripped in all three forms before any rule runs, with block-comment state tracked across
lines, because every one of these rules has to be *documented* somewhere — including inside the files
it governs. `perch-tokens.css` records each token's measured hex in a trailing `/* … */`; that is the
documentation of a measurement, not a colour a component reads.

**Runs, this session:**

```
$ bash viz/check-perch-chart-tokens.sh prototypes/dataviz.html
check-perch-chart-tokens: OK (1 file(s); self-test: 4 rules fired over 10 planted shapes, 13 clean controls passed)

$ bash viz/check-perch-chart-tokens.sh <a planted Curve.tsx>
check-perch-chart-tokens: violations in 1 chart file(s)
  Curve.tsx:1:R1-hex:const c = "#4ade80";
  Curve.tsx:2:R2-paint-attr:<rect fill="var(--perch-viz-series-1)" />
  Curve.tsx:3:R3-sources-number:type P = { sources: number };
  Curve.tsx:4:R4-buzz-var:const x = "hsl(var(--muted-foreground))";

$ PERCH_DESKTOP_ROOT=<buzz> bash viz/check-perch-chart-tokens.sh
check-perch-chart-tokens: no chart files under the scan roots.
The Perch chart layer does not exist yet. This gate lands with the first
file under desktop/src/shared/viz/ and refuses to pass silently until then.   [exit 2]
```

That last behaviour is deliberate and is the property the review praised elsewhere in the set: an
empty scan is an error, not a pass.

**Wiring, two parts, same commit.** Cross-repo, exactly as `16-INVARIANT-TESTS.md` decision D1
established for the copy gate: the gate lives in AMBUSH so `tools/check-gates-wired.sh` enumerates it,
and it scans a `block/buzz` checkout supplied in `PERCH_DESKTOP_ROOT`. The `gates` job in `ci.yml`
needs a second `actions/checkout`, and the workflow `run:` step must land in the same commit or
`check-gates-wired.sh` fails on the commit that adds the file. The step belongs in
`skeleton/tools/ci-wiring.snippet.yml` beside the five gates already there:

```yaml
      - name: Perch chart tokens
        run: tools/check-perch-chart-tokens.sh
        env:
          PERCH_DESKTOP_ROOT: ${{ github.workspace }}/buzz
```

### G3 — extend `check-pubkey-truncation.mjs` [PROPOSED, handed back]

Already required by `08`; noted here because chart tooltips and graph nodes are a place a truncated
`agent_id` would otherwise appear. `PubKey`'s own doc comment states the reason: *"a truncated key is
forgeable by vanity grinding, so decisions must be made against the whole key"*
(`BUZZ desktop/src/shared/ui/PubKey.tsx:21-31`). This one is **not** delivered here: the shipped
script's scope and allowlist belong to whoever owns `08`'s invariant set, and extending a guard I do
not own is how two owners of one file happens. What this artifact does instead is make the table
toggle mandatory on every chart (CR-7) and render the **full** `finding_id` in VIZ-3's table, so the
whole value is always reachable.

### Not delivered, and named so nobody assumes otherwise

`viz/render-audit.mjs` and `viz/dataviz-fixture.mjs` are **development harnesses, not CI gates**. They
require Google Chrome and the specimen, neither of which is in either repository's CI image. They are
listed at the top of this file because they run and because their output is quoted here, not because
they are wired anywhere.

---

## 14. Corrections this artifact issues

| # | Target | Correction |
|---|---|---|
| **X1** | `ambush-touchpoints.md` correction **C-5** | **Wrong**, re-verified at the line in revision 2 (§2.2). `resolve_deposits` applies `strategy_scoped_agent_id` *after* `WhiskerAgent::tick`'s instance scoping (`pipeline.rs:573`), and two workspace tests assert two strategies on one agent produce `distinct_sources == 2` (`substrate.rs:2104-2126`, `:2128-2153`). Render law 2 and `05` §8.2 stand unchanged; the "explanatory copy must be rewritten" instruction must **not** be acted on. |
| **X2** | `APPENDIX-NORMATIVE.md` §6 line 191, *Interpolation tolerance = 2% of `alert_threshold`, invented* | Replace with ε = `policy.evaporation_threshold`, derived (§2.4). Brief amendment **A11**. Whoever rules on it should strike the 2% figure from `prototypes/watchfloor-ledger.html`'s spec notes in the same change. |
| **X3** | `05` §8, rationale item (1) | The Tauri CSP argument applies only to CDN delivery; a bundled library is `'self'`. The decisive argument is supply-chain gate coverage (§1.2). |
| **X4** | `05` §8.1(b), "bar hue is the dominant threat class's pillar" | Threat classes have no pillar assignment. Decision D1: substrate green for the bar, authority amber past the threshold, threat class as a label (§5.2). |
| **X5** | `APPENDIX-NORMATIVE.md` §6 line 214, `lease_ttl_ms` = 60,000 | Correct for the **capability** lease. The containment board renders `runtime.containment.lease_ttl_ms`, default **900,000 ms**. Three peers have filed this; it is one row split in two. |
| **X6** | `05` §8.1(a), deposit-train dot ramp | The reference's fixed `4.26 → 2.79` radius decay encodes nothing and fades the freshest deposit. Perch binds radius to `confidence` and opacity to the surviving fraction after decay (§4.3, departure D8). |
| **X7** | `05` §8.1(d), "the workbench colours restated on the pillar taxonomy" | Correct, and the row-kind union must be **closed with no `default:` arm** — six inherited plus five added (§7.1). An open union is how a twelfth kind ships as a grey line. |
| **X8** | **this file's own revision 1, CR-5** | **Revised.** `sourceIds` cannot be non-optional in Phase 1: `RuntimeEvent::Escalation` (`runtime_events.rs:288-297`) has eight fields and no ids, and `grep source_ids schemas/*.json` hits one file where the value is `null`. `SourceAttribution` is now a two-arm union whose absent arm renders a named absence (§3.3). Consequences filed against `17-COMPONENT-SPECS` (`SourceCount`'s prop) and `16-INVARIANT-TESTS` (INV-16's regex). |
| **X9** | **this file's own revision 1 and its specimen, palette** | The palette was authored against the **bare Buzz shadcn names**, which `ThemeProvider.tsx:443-446` writes inline on the root element. Every colour on every plate would have reverted to the active Buzz syntax theme. Rewritten to `--perch-*`, and **G2 R4 makes it a gate** (§3.2). |
| **X10** | **this file's own revision 1, the "standalone deviation"** | Revision 1 recorded painting through `fill` presentation attributes as a deliberate deviation "so it renders from `file://`". Deleted. With HSL-triplet tokens that form does not resolve at all, and a drawing whose paint mechanism differs from the shipped one is not a drawing of the component. Colour now reaches every SVG node through a class and G2 R2 proves it. |
| **X11** | **this file's own revision 1, §10's contrast claim** | "Every `--viz-series-N` clears 6.7:1 (dark) / 4.2:1 (light) against every surface" is wrong in both themes. Recomputed minima: **5.19** dark (series 4 on `--perch-surface-raised`) and **4.02** light (series 6 on the same). All six still clear the 3:1 non-text bar, which is the bar that applies. |
| **X12** | **this file's own revision 1, severity** | The specimen shipped `#b45309` (4.31 on `--perch-surface-chrome`) and `#8a6114` (4.51 on raised) after `19-TOKENS` had measured and replaced both. Amendments T2 and T2b are applied and independently re-measured (§3.2). |
| **X13** | `06` §7.2's `bare-source-count` ban, guard scope | Its pattern `(^|[^a-z])sources?([^a-z]|$)` fires on the word "source" in the *data source* sense — it flagged this specimen's own honest absence string *"…is the only source"*, which contains no count at all. Rephrased to *"…serves the ids"*. Recorded for the copy-gate owner as a guard-scope note, alongside the same-shaped finding `proto-watch` filed. |

---

## 15. What is verified, what is measured, and what is proposed

**Verified this session, by reading the named lines:** the closed form and its `now <= timestamp`
guard; `concentration_for`'s reduction, its threat-class filter at `:1281` and its three `continue`s;
`filter_deposits` applying suppression but not evaporation and taking no `now`; the suppression key
and its `>=` predicate; `deposit_host_id`'s two lookups and its `None`; `strategy_scoped_agent_id`
applied in `resolve_deposits` after `WhiskerAgent::tick`'s instance scoping, and the two tests that
assert the consequence; `RuntimeEvent::Escalation`'s eight fields and its absence of ids;
`standard_threat_classes()` = 12; `IncidentGraphDimension` = 4; the three correlation reason builders
and the two helpers they call; `RollbackStepStatus` = 5 with `restored()` true only for `Reversed`
and `resolve_inverse`'s four arms including the `Irreversible` one; `is_containment_action` = 4;
`ContainmentLeaseView`'s two fields and the saturating `remaining_ms`; `createThemeVars` returning
exactly 38 vars and `applyTheme`/`applyCachedVars` writing them inline;
`check-px-text-core.mjs`'s two regexes and what they cannot match; `desktop/package.json`'s `check`
chain; zero charting dependencies in Buzz's 78-package desktop manifest; Buzz CI carrying no npm
audit, SBOM or dependabot config; Ambush's three supply-chain gates being Rust-only.

**Measured this session, by running something:** all 62 contrast ratios in §3.2 and §10, recomputed
from sRGB triplets (`viz/contrast.mjs` in scratch, method: WCAG 2.2 relative luminance); the five
canonical concentration checkpoints, reproduced to six decimals by `viz/dataviz-fixture.mjs`, plus
assertion A5 that the fixture extension moves none of them; 36 render combinations with no JS error,
no `undefined`/`NaN`, and six plates in every one; the copy lint over every rendered product string
against the peer's `copy-ban-list.tsv` (clean, with two filed exemptions bucketed and printed);
the computed-font-size census (594 nodes, 43.4% ≥14px, 0 at 8px); G1 against 1,664 real Buzz files;
G2's self-test and its three run modes.

**Proposed, and needing a decision from the integrator:** the three tokens in §3.2 and their
placement; the two forbidden-literal test entries; `--perch-alpha-hatch`; the dash-pattern rotation;
the hatch geometry; decisions D1, D2, D8 and CR-10; the `SourceAttribution` union and its two reason
strings; the `superseded` `leg2.state` value and the unconfirmed-verdict rendering (§7.5); the
`VizState` union's exact shape; the min–max sparkline scale; the diversity-threshold row as a
first-class timeline kind; brief amendment A11; the sizing table in §12; the wiring for G1 and G2.

**Blocked on backend work, and stated as such on the surface rather than faked:** VIZ-1 and VIZ-2 both
need **B4** (`GET /v1/operator/pheromone/deposits`, Phase 2) returning the post-suppression **and**
post-evaporation slice plus the resolved policy. Until it lands they render in regime B, where the
attribution's second half is a named absence rather than a number — which is the point of the CR-5
revision and is why B4 does **not** need to move into Phase 1. VIZ-3's error state is the wall **B3i**
removes. VIZ-4's decision row carries a derived marker until **B2o** lands. None of the four is a
reason to draw something that implies a working gate.

---

## 16. Files

```
desktop/src/shared/viz/
  types.ts                 VizState, ThreatClassPolicy, SourceAttribution, sourceCounts
  scales.ts                linear scale, exponential interpolation, sparkScale
  concentration.ts         strengthAt, concentrationAt, snapshotDisagrees   ← §2, THE one epsilon
  markers.tsx              DerivedMarker, ServedMarker
  TableToggle.tsx          the mandatory <table> path
  defs.tsx                 the hatch pattern and the area gradient, defined ONCE (see below)
  viz.css                  the paint classes, incl. the .stop-series-N family
desktop/src/features/lanes/ui/
  ConcentrationCurve.tsx   VIZ-1
  HostHeat.tsx             VIZ-2
desktop/src/features/cases/ui/
  KillChainGraph.tsx       VIZ-3
  IncidentTimeline.tsx     VIZ-4
desktop/src/features/containments/ui/
  ContainmentLeaseTimer.tsx  VIZ-5
desktop/src/shared/viz/
  RateSparkline.tsx        VIZ-6
desktop/scripts/check-svg-font-size.mjs      G1   (+ its package.json `check` entry, same commit)
tools/check-perch-chart-tokens.sh            G2   (+ its workflow run: step, same commit)

docs/plans/ambush-ui/build/
  prototypes/dataviz.html          the specimen
  viz/dataviz-fixture.mjs          the fixture binding, with its assertions
  viz/render-audit.mjs             the render / copy / type / attribute audit
  viz/check-svg-font-size.mjs      G1, as delivered
  viz/check-perch-chart-tokens.sh  G2, as delivered
```

`defs.tsx` exists because the gradient and the hatch have **document-scoped ids**. The specimen emits
its `<defs>` once per SVG, which is harmless there because the two definitions are identical, but a
component that did the same in a twelve-curve wall would emit twelve `id="perchAreaGrad"` and the
first would win by accident. One `<defs>`, mounted once, referenced by id.

---

## 17. The review, answered

Six findings landed on this artifact. Four are accepted and fixed above; two I hold, with the evidence
put here so the objection cannot recur.

### Accepted and fixed

**Tokens under bare Buzz names (blocking).** Correct, and the mechanism the critic cited is exactly
right — I re-derived it independently before acting: 38 vars from `createThemeVars`, written inline by
`applyTheme` at `ThemeProvider.tsx:443-446` and by `applyCachedVars` at `:398-412`. Fixed in §3.2 and,
more importantly, **made mechanical** by G2 rule R4, so this cannot recur through a memo being
forgotten.

**Light severity below AA (blocking).** Correct. I recomputed rather than trusting either side:
`#b45309` measures 4.307 on `#e9efeb` and 4.097 on `#e2eae5`; `#a94e08` measures 4.764 and 4.533.
Applied, with the two superseded hexes proposed as forbidden literals in `perch-tokens.test.mjs` so
the regression is policed rather than remembered.

**`M agents` has no Phase-1 source (blocking).** Correct, and it is a different fact from the
source-count reading — which is why both can be true at once and why §2.2 and §3.3 are separate
sections. Fixed by revising CR-5 to a two-arm union rather than by moving B4 into Phase 1.

**Five canonical fixtures (blocking).** Correct. Bound to `fixtures/perch-demo-fixture.json`, with the
binding asserted by a script rather than claimed, and the extension confined to non-canonical threat
classes so it is *arithmetically incapable* of moving a canonical number.

**No readable-text tier (major).** Correct. Re-tiered and measured; the audit now fails below the
review's own bar.

**Theme architecture inverted (major).** Correct for the arrangement. Note for the record that the
specific sub-finding — two prototypes hard-coding `data-theme="dark"` on `<html>` so the light block
is unreachable — was **not** true of this file, which set nothing on `<html>` in revision 1 either.
The arrangement is now `perch-tokens.css`'s, and the audit renders every state under both forced
`prefers-color-scheme` values.

**Three tokens specified and not shipped (major).** Correct, and the fault was mutual: revision 1
listed them under PROPOSED-NOT-VERIFIED and filed the addition nowhere. §3.2 now carries the
paste-ready block, the recomputed ratios, the reason none of the three carries a contrast bar, and the
three things that must land with them.

**Deep links in two of five prototypes, two mechanisms (major).** Correct that this file had neither.
Rather than adding a third convention, the specimen implements **one reader that accepts both**:
`readDeepLink()` reads `?state=&regime=&plate=&theme=` and falls back to a `#fragment` of the same
shape, and `writeDeepLink()` writes the query form. A link written in either peer's convention
resolves here. That is the cheapest reconciliation available to a producer who cannot edit a peer's
file, and it is stated in one place.

**Eleven CI gates named and not delivered (major).** Answered for this artifact's three: G1 and G2 are
written, self-testing and run, with their measured output quoted in §13; G3 is explicitly handed back
to the owner of `08`'s invariant set, with the reason.

**Two operators, one hold (major).** Not this artifact's decision, but it *is* this artifact's
rendering. §7.5 specifies the `superseded` decision-row state and — more useful, because it needs no
wire change — the reconciliation rule that a verdict card with no matching daemon decision record
renders as an unconfirmed intent rather than as a decision. The schema, the invariant and the E2E are
filed against their owners by name.

### Held, with evidence

**The interpolation tolerance (major, disagreement with a peer).** I hold ε =
`policy.evaporation_threshold`. The argument is in §2.4 and it is not a preference: exponential
interpolation over a fixed deposit set is exact to one ULP, so the constant is not an error budget,
and one deposit's worth is exactly the evaporation floor because anything smaller would be evaporated
on arrival. The 2%-of-`alert_threshold` rule is additionally coupled to a policy dial an operator can
turn, which silently widens it. What I accept from the finding is that **two files holding two values
is the defect**: A11 is filed against the appendix row, the value is computed in exactly one function
in the specimen and will be in exactly one function in the shipped code, and the reversal instruction
is written down so rejecting A11 is a one-line change.

**`distinct_sources` is strategy-scoped (systemic note).** I hold this, and I re-verified every hop
this session rather than restating revision 1 (§2.2). The systemic note is right that six producers
read it one way and the two who own the schemas read it the other, and that artifact ownership beat
correctness. **That is now fixed.** `13-WIRE-SCHEMAS.md` withdrew W-6 and applied the change:
`card-swarm-escalation-v1.schema.json` `$ref`s `common.schema.json#/$defs/SourceCountMechanism`,
whose `const` is `strategy_scoped_agent_id`; the `x-note` on `distinct_sources` now states what
`substrate.rs:1295` actually does; and `zod.ts`, `ts/types.ts`, `rust/src/cards.rs`, the golden
vector and its pinned hash all follow. `22-DEMO-FIXTURE.md`'s amendment W-A2 is satisfied. The
evidence that settles it — the two named tests at `substrate.rs:2104-2126` and `:2128-2153`, plus
`strategy_scoped_agent_ids_count_as_distinct_sources_across_instances` at
`crates/swarm-pheromone/tests/multi_instance.rs:352-388`, which asserts `distinct_sources == 2` for
ONE base agent with TWO strategy ids — is in the tree today. `00-REGISTRY.md` R-2 is the ratified
row.

Note that fixing that `const` does **not** make CR-5's absence unnecessary and vice versa. They are
independent: one is about what the number *means*, the other about whether the ids are *present*. A
reviewer conflating them would fix one and think both were closed.
