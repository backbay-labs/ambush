# `perch-wire` — the same contract in two languages, with no codegen

Neither repository has a schema-to-code generator and this design does not add
one. What holds Rust and TypeScript together is **one directory of golden
vectors plus two test suites that both read it**, and one CI gate that compares
field sets across three files.

```
build/schemas/                     ← NORMATIVE. 17 JSON Schemas (2020-12):
                                      7 cards + 7 frames + the kind:46010 event
                                      + common + card-envelope.
build/skeleton/perch-wire/
  golden/                          ← the contract, EXTRACTED from the schemas'
    *.json                            own `examples`, so a schema and its vector
    GOLDEN.sha256                     cannot disagree. 16 vectors for 15
    manifest.json                     schemas-with-examples: `swarm:verdict:v1`
                                      has two.
  rust/                            → AMB  crates/swarm-perch-wire/
  ts/                              → BUZZ desktop/src/features/perch/wire/
  parity-gate.sh                   → AMB  tools/check-perch-wire-parity.sh
```

## Run it

Both commands work from this directory with **no environment variables**:

```bash
bash parity-gate.sh              # 312 declared field(s) across 17 schema(s)
bash parity-gate.sh --self-test  # 5 cases, each one a way the gate must fail
```

The gate probes two layouts — its destination (`crates/swarm-perch-wire/…`) and
this build tree — and **prints the one it resolved** before it reports anything.
An earlier revision hard-coded only the destination layout, so run as committed
it printed `VACUOUS: no schema directory at …/build/skeleton/crates/…` and exited
2; the "308 fields" figure that revision quoted was reachable only with three env
overrides. Exiting 2 was the right refusal. Pointing at a tree that existed in
neither layout was not.

## The four things that keep the two sides honest

**1. The golden vectors are the same bytes on both sides.**
`tests/golden.rs` reads them with `include_str!`, so a missing file is a build
error and no filesystem access happens at test time. `golden.test.mjs` reads them
from disk. **Both suites now assert `GOLDEN.sha256`** — `golden.rs`'s
`the_golden_corpus_matches_its_pinned_hash` and `golden.test.mjs`'s "the golden
corpus matches its pinned hash" — and `golden.test.mjs` additionally reads the
Rust constant out of the sibling checkout when it is reachable and asserts the
two suites pin the *same* corpus. Before this revision the hash was quoted in
`13-WIRE-SCHEMAS.md` §0 as a verification result while **no committed file
asserted it**: it had been computed at a shell prompt. That is the
"measured against a file that is not the one in the tree" pattern and the fix is
the same everywhere it appears — put the check in the artifact.

Vectors are **generated**, never hand-edited. `scripts/sync-perch-golden.sh`
(PROPOSED) re-extracts every `examples[i]` entry, writes it with
`sort_keys`+`indent=2`, rewrites the manifest and re-pins the hash. Editing a
vector to match a hash inverts the whole mechanism.

**2. Both suites assert the same serde traps.** Four shapes on this wire are
tagged in ways a hand-written TypeScript type gets wrong on the first try:

| Shape | Wire form | Why a guess is wrong | Source |
|---|---|---|---|
| `ThreatClass` | `"lateral_movement"` \| `{"custom":"…"}` | externally tagged with twelve unit variants and one newtype variant | `AMB crates/swarm-core/src/pheromone.rs:13-30` |
| `ResponseAction` | `{"type":"isolate_host","host_id":"web-04"}` | `#[serde(tag = "type")]` — internally tagged, payload beside the tag | `AMB crates/swarm-core/src/types.rs:416-467` |
| `AuditResponseRecord` | `{"kind":"success", …seven receipt fields}` | `#[serde(tag = "kind")]` over two NEWTYPE variants, flattened | `AMB crates/swarm-spine/src/lib.rs:102-110` |
| `Severity` | `"HIGH"` beside `"isolate_host"` | the only enum in the workspace with `rename_all = "SCREAMING_SNAKE_CASE"` while ~40 siblings are `snake_case`; it is also the `l` tag's value | `AMB crates/swarm-core/src/types.rs:406-414` |

A fifth is not a serde trap but a **decode-strictness** trap, and both suites
assert it: `FactIssuer.role` is **required and nullable**, never optional. A
missing key must be a decode error while a genuine absence is an explicit `null`.
Collapsing the two would let a truncated body pass as an unattributed fact —
which is the one thing an evidence card must never do quietly.

**3. A field-set gate, not a shape gate.**
`parity-gate.sh` reads every `schemas/*.schema.json`, extracts `properties` keys
per object, and asserts the same names appear in the Rust source and in the zod
module. It catches the failure a golden vector cannot: a field added to one side
and to no vector. It does **not** compare types; a schema plus two golden suites
already do that, and a type-comparing shell script is the kind of gate that gets
switched off.

Two defects were found in the gate itself while self-testing it, and both are
fixed:

- **String literals were counted as declarations.** The object-key regex's
  lookahead is `[:,}]`, so a field named inside a `.refine()` message —
  `"escalation.source_ids_absent_reason: exactly one must be null"` — satisfied
  the gate. Renaming the *real* key left it green. String literals are now
  stripped before extraction, with `z.literal("…")` values harvested first
  because a serde-tagged discriminator has no object key. Self-test case 4 is
  exactly this.
- **A flat `glob("*.rs")` would have gone silently vacuous on a module split.**
  `cards.rs` is 992 gate-lines and the obvious next move is a
  `cards/{mod,evidence,hold,verdict}.rs` split, which a flat glob would drop
  entirely from the Rust side. It is `rglob` now, and an empty result is exit 2.

**4. The OpenAPI file and the wire schemas are held together too.**
`build/openapi/perch-operator-v1.yaml` is normative for the HTTP shape and
`build/schemas/` for the wire shape. Six objects appear in both —
`HeldActionView`/`HoldCard.hold`, `HoldRationale`, `HoldDecisionRecord`,
`InverseResolution`, `ActionRequest`, `PolicyDecision` — and the gate covers
those names in both files.

## Landing this in two repositories that gate differently

**AMBUSH.** `tools/check-gates-wired.sh` enumerates every `tools/check-*.sh`,
tracked or untracked, and **fails on any not named by a real workflow `run:`
step**. `check-perch-wire-parity.sh` therefore lands with its `.github/workflows`
edit in the **same PR** or CI fails in a way that looks like the gate is broken.
The exact step, for `skeleton/tools/ci-wiring.snippet.yml` to absorb:

```yaml
      - name: perch wire parity
        run: bash tools/check-perch-wire-parity.sh
      - name: perch wire parity self-test
        run: bash tools/check-perch-wire-parity.sh --self-test
```

`tools/check-worktree-clean.sh` runs after the test job, so the golden sync
script must write only inside its configured output directory.

**BUZZ.** There is no `tools/` directory at all. The Buzz-side gate is a
`desktop/scripts/check-perch-wire.mjs` wired into `desktop/package.json`'s
`check` script beside the two that already live there —
`"check": "biome check . && pnpm check:px-text && pnpm check:pubkey-truncation"`
— which `just desktop-check` and `just ci` both run. The golden test rides
`pnpm test`, which is
`node --import ./test-loader.mjs --experimental-strip-types --test "src/**/*.test.mjs"`
and is one of lefthook's pre-push groups. The loader
(`desktop/test-loader-hooks.mjs`) transpiles `.ts` on import, which is why a
`.mjs` test can import `./zod.ts` directly.

## What was NOT executed while writing this

Honest ledger, so a reviewer knows which claims are checked and which are read.
Every number below was produced by running the **committed** file from its
**committed path**, which is the discipline the first revision missed twice.

- **Checked by running it.** All 17 JSON Schemas validate as Draft 2020-12 and
  all 16 `examples` entries validate against their own schema with cross-file
  `$ref` resolution. Twenty-five positive/negative mutations behave (the list is
  in `13-WIRE-SCHEMAS.md` §0). `bash parity-gate.sh` from this directory, with no
  env vars, prints `312 declared field(s) across 17 schema(s), all present on
  both sides`; `--self-test` passes 5/5; and deleting `dedupe_key` from
  `rust/src/cards.rs` or renaming `source_ids_absent_reason` in `ts/zod.ts` each
  produce exit 1 naming the field. The 23 wire fixtures in
  `build/fixtures/wire/` (22-DEMO-FIXTURE's, not this artifact's) were run
  through these schemas: **20 pass, 3 fail**, each failure with a one-line fix
  named in `13-WIRE-SCHEMAS.md` §11.
- **Read, not executed.** The Rust crate does not compile in this session — it is
  a skeleton with `todo!()` in seven `human_line` bodies and it names Ambush
  crates by path. The zod module was not run: `node_modules` is not installed in
  this checkout, so `z.strictObject`, `z.discriminatedUnion`, the two-argument
  `z.record` and readonly-tuple `z.enum` were checked against zod's resolved
  version (`4.4.3`, `BUZZ pnpm-lock.yaml:3737`) and its documented API, not
  against an interpreter. Both are exercised by the golden suites on first run,
  which is the point of them. **In particular** the `.refine()` on
  `escalationFact` is applied at the FACT level rather than on a
  `discriminatedUnion` branch, because a `.refine` wrapper is not an object
  schema and the union constructor will not accept one — reasoned from the API,
  not observed.
- **Not verified at all, and flagged in the artifact.** How `gpt_markdown`
  (`BUZZ mobile/pubspec.yaml:30`) renders an HTML comment. The package is not in
  the local pub cache and `flutter pub get` was not run. `13-WIRE-SCHEMAS.md` §8
  states the two possible outcomes and the one-line widget test that settles it.
