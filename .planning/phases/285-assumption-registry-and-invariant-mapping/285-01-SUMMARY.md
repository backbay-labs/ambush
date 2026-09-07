# Phase 285 Plan 01 Summary

Assumption Registry And Invariant Mapping (v1.79). The v1.79 "Assurance Foundation" floor — it
converts Ambush's "fail-closed" claim from a README assertion into an AUDITABLE, CI-gated table that
links each fail-closed invariant to the exact function enforcing it and the assumption beneath it,
with a machine-checked proof that every check actually fires. Executed 2026-09-07 with
subagent-driven-development as a sequential pipeline (T1→T2→T3→T4), each task task-reviewed. The
phase adds NO production behaviour change — it documents, marks (comment-only), tests, and gates.

## Delivered

- **Assumption registry + invariant map (MAPPING-01, MAPPING-02; 5c7800644):**
  `docs/assurance/assumptions.toml` — 8 named assumptions (`ASSUME-OS-CLOCK`,
  `ASSUME-JETSTREAM-DURABILITY`, `ASSUME-KEYSTORE-ATOMICITY`, `ASSUME-ED25519`, `ASSUME-SHA256`,
  `ASSUME-CANONICAL-JSON`, `ASSUME-NETWORK-TRANSPORT`, `ASSUME-SUBPROCESS-ISOLATION`), each with an
  `owner`, a one-line `statement`, and its `dependent_invariants`; parses as valid TOML.
  `docs/assurance/MAPPING.md` — 15 fail-closed invariant rows across `swarm-policy` (3),
  `swarm-runtime` (5), `swarm-spine` (4), `swarm-response` (3); each row names the exact
  `crate::module::function` that ENFORCES the invariant and the assumption ID beneath it, with a
  one-line statement of what it denies. All 15 paths were independently resolved against the tree at
  HEAD. Honest gap recorded: `ASSUME-JETSTREAM-DURABILITY` has 0 in-scope dependents — the durability
  substrate lives in the out-of-scope `swarm-pheromone` crate, and the in-scope `swarm-runtime`
  pheromone paths fail-OPEN by design (TCBOUND-04), so nothing in scope rests on it.
- **`// INVARIANT:` markers + mapping gate (MAPPING-03, MAPPING-04, MAPPING-05; c4470c860):**
  15 `// INVARIANT: <Name>` comment markers, one at each Rust call site `MAPPING.md` names
  (comment-only additions; no logic change, no compilation change). `tools/check-mapping.sh` enforces
  a three-way sync — every marker has a `MAPPING.md` row, and every row's `crate::module::function`
  path still resolves in the tree — and is proven NOT vacuous: it plants an unmapped marker AND a
  stale path in a temp copy and asserts the scan catches both before ever scanning the real tree.
  Wired into `ci.yml`.
- **Negative-falsifiability registry + broken-variant tests + gate (FALSIFY-01..04; 723466010):**
  `docs/assurance/negative-registry.toml` maps each of the 15 invariants to a
  `crates/*/tests/negative_*.rs` test and the production function it targets. Each test is a two-step
  proof: it calls the REAL enforcing function through a public path on an input it DENIES and asserts
  the denial, then calls a LOCAL deliberately-broken variant — the same guard with its fail-closed
  check weakened or removed — on the IDENTICAL input and asserts it PERMITS. Step two is what makes
  step one non-vacuous: it shows the real check does work a no-op stub would not have survived.
  `tools/check-negative-registry.sh` fails if any `MAPPING.md` row lacks a registry entry or names an
  absent test file/fn (five checks: MISSING/ORPHAN registry entry, DANGLING test file/fn, crate-path
  mismatch), proven non-vacuous by an internal six-scenario fixture plus a self-planted counterexample
  against a temp copy of the real tree. Wired into `ci.yml`.

## Success criteria (mirror ROADMAP)

1. **`assumptions.toml` parses, ≥8 assumptions each with owner + dependents** — met: 5c7800644, 8
   assumptions, `tomllib`-parsed.
2. **`MAPPING.md` ≥12 rows across the four crates, each an existing `crate::module::function`** —
   met: 5c7800644, 15 rows (policy 3 / runtime 5 / spine 4 / response 3), every path resolved.
3. **Mapping gate is a required CI step and fails on a deliberately unmapped `// INVARIANT:` marker**
   — met: c4470c860, `tools/check-mapping.sh` wired into `ci.yml`, non-vacuity proved by a planted
   unmapped marker and a planted stale path.
4. **Every row has a `negative_*.rs` test asserting a broken variant permits what the real denies;
   the negative-registry gate fails on any missing entry** — met: 723466010, 15 tests green, gate
   exit 0 on the real tree and non-zero against a planted missing entry / renamed test.

## Notes

- **Controller ruling (path slip):** both gates live in `tools/`, NOT `scripts/` as MAPPING-04/05 and
  FALSIFY-03/04 name them. Every gate in this repo is `tools/check-*.sh` and `tools/check-gates-wired.sh`
  only enumerates `tools/`; a gate in `scripts/` would be unenforced. Same slip as ARMSCI-02 (phase
  291) and the 283 TCB gate. Both new gates are wired into `ci.yml` in the tasks that add them, so
  `check-gates-wired.sh` stays green.
- **One honest deviation (FALSIFY-02, `SpineEnvelopeCanonicalizationRequired`):** the canonicalization
  guard denies a non-finite `f64`, but a non-finite `f64` cannot reach it through any public
  serde_json (1.0.149) path — `Number::from_f64(NAN/INFINITY)` returns `None` (the value silently
  becomes `Value::Null`), and an out-of-range numeric literal fails at `serde_json::from_str` before a
  `Value` ever exists. Verified empirically in both directions and against the pinned serde_json
  source (the task review independently re-checked the source and found no missed public path, incl. a
  hand-rolled `Deserializer` routing through the same finite-check). Rather than fabricate a
  real-call-chain test that never actually denies — the exact defect this phase exists to catch —
  the test falsifies the guard's LOGIC on a bare `f64` AND asserts the unreachability claims, so a
  future serde_json upgrade that changes this behaviour fails the test loudly. The registry row
  carries `status = "deviation"`. 14 of 15 invariants falsify through the real call chain.
- **No production code changed:** the diff is confined to `docs/assurance/`, `crates/*/tests/`,
  `tools/`, and `.github/workflows/ci.yml` — 0 edits under any crate's `src/`.
- **v1.79 "Assurance Foundation" progress:** Phase 284 (fixture determinism) and Phase 285 (this) are
  complete; Phases 286 (deterministic simulation testing) and 287 (fuzz, loom, supply-chain
  hardening) remain.
