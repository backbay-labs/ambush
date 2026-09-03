# `fixtures/` — the one Perch scenario

Everything under this directory is **one scenario, told once**. A prototype, a
Playwright spec, a screenshot and the seven-minute demo all load from here, so
the product tells the same story on every surface and a number that appears
twice is the same number both times.

The narrative document is [`../22-DEMO-FIXTURE.md`](../22-DEMO-FIXTURE.md). This
file is the index and the operating instructions.

**This directory is the canonical Perch fixture corpus.** Not "a" fixture — the
one. Wave 2's red team found five of them: five channel UUIDs for `case-0042`,
six hold-id grammars, five different `total_strength` values for the same
incident, each declared canonical by its own producer.
`14-CLIENT-ARCHITECTURE.md` §7.4.1 clause 4 arbitrated in favour of this one,
on the ground that it is the only machine-validated corpus and the only one
whose every id regenerates from a public label rather than being transcribed.
`prototype/perch-fixture.js` exists so a self-contained drawing can bind to it
in two lines instead of retyping it.

---

## What is here

| Path | What it is | Generated? |
|---|---|---|
| `perch-demo-fixture.json` | **The canonical object.** Cast, clock, channels, deposits, the concentration arithmetic, the twelve lanes, the colony, both holds, the four queues, the instrumentation strip, the `contested` variant, and the mock-bridge command table. | yes — `build.mjs` |
| `derive-ids.mjs` | Every opaque id, derived as `sha256("perch-demo-fixture/v1/" + label)`. Run it to reproduce them. | source |
| `build.mjs` | Emits `wire/`, `http/`, `perch-demo-fixture.json`, `mock-bridge/perchFixtureData.ts`, `prototype/perch-fixture.js` and `SHA256SUMS` from one set of constants. | source |
| `validate.mjs` | Validates every `wire/` file against `../schemas/` **and recomputes every envelope hash from the file's own bytes** and every per-issuer chain. **No departure allowlist** — see below. Needs `ajv` 8 on the resolution path. | source |
| `SHA256SUMS` | Integrity over everything `build.mjs` wrote. | yes |
| `scenario/hellcat-office-demo.yaml` | A drop-in Ambush replay scenario. Copy to `scenarios/`. | source |
| `wire/card-*.json` | The eleven marker-card envelopes, in timeline order. | yes |
| `wire/event-46010-*.json` | The two queue notices. | yes |
| `wire/frame-26*.json` | The ephemeral frames at the demo's instants. | yes |
| `wire/variant-contested-*.json` | The two-operator variant: winner, loser, and the loser's `superseded` update card. | yes |
| `http/*.json` | Ten response bodies across eight routes — seven backend-bill items plus `GET /v1/operator/containment/leases`, which already ships. | yes |
| `prototype/perch-fixture.js` | `globalThis.PERCH_FIXTURE` — cast, clock, lanes, queues, colony, instrumentation, holds (~38 KB). What a self-contained `build/prototypes/*.html` binds to. | yes |
| `prototype/perch-fixture-wire.js` | `PERCH_CARDS` / `PERCH_NOTICES` / `PERCH_FRAMES` — the raw wire bodies (~34 KB). Load only on a page that renders a card's actual JSON. | yes |
| `mock-bridge/perchFixtureData.ts` | The same data as TypeScript. | yes |
| `mock-bridge/perchFixture.ts` | `seedPerchDemo(page)` seeds relay state through the five window seams Buzz already installs — **no `e2eBridge.ts` edit**. `perchDaemonRoutes(page, …)` is a *separate* export for the daemon half. | source |
| `demo/cue-card.txt` | The presenter's pocket card. | source |
| `demo/run-demo.sh` | Preconditions plus process start. Prints one `NOT WIRED` line per capability the demo must not claim. | source |
| `demo/check-strings.mjs` | Runs `../skeleton/tools/copy-ban-list.tsv` over the demo's spoken and on-screen strings. | source |

## Regenerating

```bash
cd docs/plans/ambush-ui/build/fixtures
node build.mjs                       # rewrites wire/, http/, the .json, the .ts, the .js
shasum -a 256 -c SHA256SUMS          # must be clean
node validate.mjs                    # must print 0 failure(s)
node demo/check-strings.mjs ../22-DEMO-FIXTURE.md demo/cue-card.txt
```

`build.mjs` recomputes the concentration arithmetic from the deposits every
time, using the same three filters `concentration_for` applies
(`AMB crates/swarm-pheromone/src/substrate.rs:1268-1304`, called by
`query_concentration` on every monitor tick inside `swarm_detect --serve`,
summing `strength_at(now)` and counting distinct `deposit.agent_id.0`). If a
constant moves in `rulesets/default.yaml`, change it at the top of `build.mjs`
and every derived number in every artifact follows.

### `validate.mjs` has no allowlist, deliberately

An earlier version carried six suppression predicates keyed on ajv's
`instancePath` + `keyword`, each pointing at a proposed schema amendment. It
printed `0 unexplained failure(s); 13 recorded departure(s)` and exited 0 —
which the red team correctly read as eleven failing files — twelve distinct
failures, since the escalation card failed on two grounds — with the failures
suppressed by the validator's own configuration. That is the worst possible
property for the one artifact every other artifact is built on.

The amendments have since landed in the peer schemas (`FactIssuer.role`
nullable-and-required; `SourceCountMechanism` fixed at
`strategy_scoped_agent_id`; the closed four-name `46010` tag set) and this
fixture was corrected to match the third. The allowlist has nothing left to
suppress and it is gone. If an amendment is ever genuinely pending again, the
right shape is a **second, named pass over an explicit overlay** — never a
predicate that turns a red line green in the default run.

`validate.mjs` also now (a) keys each file to its schema by `fact.schema` /
`kind` rather than by filename prefix, so a file it cannot place is a failure
rather than a `SKIP`; (b) recomputes every `envelope_hash` with a JCS port of
`AMB crates/swarm-crypto/src/canonical.rs`, self-tested against RFC 8785's own
ordering and number vectors; and (c) walks each per-`(issuer)` envelope chain
and asserts `seq` is 1..n with `prev_envelope_hash` linking correctly.

## Loading it

**A prototype (`build/prototypes/*.html`).** Bind to `prototype/perch-fixture.js`.
These pages open from a `file://` URL, where `fetch` of a sibling file is
blocked by the same-origin policy and a classic `<script src>` to a sibling is
blocked in Chrome — so paste the file's contents between two sentinels and let
`build.mjs` re-emit it when the fixture changes:

```html
<!-- perch-fixture:begin -->
<script>/* contents of fixtures/prototype/perch-fixture.js */</script>
<!-- perch-fixture:end -->
```

Then read `PERCH_FIXTURE.lanes`, `.queue`, `.findings`, `.colony`,
`.instrumentation` and `.holds` instead of declaring a local cast.

**A Playwright spec.**

```ts
import { installMockBridge } from "../helpers/bridge";
import { seedPerchDemo, perchDaemonRoutes } from "../helpers/perchFixture";

await installMockBridge(page);
await page.goto("/");
const handles = await seedPerchDemo(page);                   // whole arc
// or: await seedPerchDemo(page, { upTo: "holds" })          // stop before the grant
// or: await seedPerchDemo(page, { contested: true })        // two operators, one hold
```

Daemon reads (`perch_list_holds`, `perch_get_hold`, …) are answered by
`desktop/src/testing/perch/e2ePerchBridge.ts` from
`perch-demo-fixture.json`'s `mock_bridge.perch_read_commands`, reached through
the three-line `perch_` prefix guard `14-CLIENT-ARCHITECTURE.md` §7.4.1 puts in
`e2eBridge.ts`. Daemon **writes** are answered by `perchDaemonRoutes(page, …)`,
a separate call a spec has to make on purpose.

**A daemon-backed run.**

```bash
cp scenario/hellcat-office-demo.yaml "$AMBUSH/scenarios/"
BUZZ_DIR=… ./demo/run-demo.sh up
```

## Rules this fixture keeps

1. **One host, one incident, two holds, one containment lease.** Adding a
   second host to make a screenshot look busy breaks every peer artifact that
   cites `host-ops-1`. The two exceptions are named and quarantined:
   `background` (other hosts' deposits, so a twelve-lane wall is not eleven
   zeros — and *nothing* in it may become a card, a hold or a decision) and
   `variants.contested` (a second operator principal, and nothing else).
2. **No invented identifiers.** Every `strategy_id` is one of the fifteen real
   detector ids and is only ever paired with a threat class that detector can
   actually emit — `build.mjs` throws on an unreal pair. Every `action_kind` is
   a real `ResponseAction::kind`. Every receipt id uses the shipped
   `SandboxExecutor` format.
3. **Nothing here is signed.** The 64-hex values are shaped like keys and are
   not keys; the 128-hex values are shaped like signatures and are not
   signatures. The `envelope_hash` values ARE real and recomputable — and a
   keyless hash is still verification **tier 0**. No artifact built on this
   fixture may render a tier above 0.
4. **Milliseconds and seconds are not interchangeable.** `timestamp`,
   `decay_half_life`, `now_seconds` and `marker_timestamp` on the deposits route
   are **unix seconds**; everything else is **unix milliseconds**. Mixing them
   produces a decay curve wrong by a factor of 1000, silently.
5. **An absence is not a zero.** `queue.named_you.present` is `false` with a
   reason, not `count: 0`. `lanes.discovery.empty_reason` names a coverage gap,
   not a quiet hour. `instrumentation.median_page_to_verdict_state` is the
   literal token `UNMEASURED`. A surface that renders any of these as `0` has
   made a claim the fixture did not.
