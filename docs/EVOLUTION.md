# Evolution And Rollout Contract

This document is part of the active contract set defined in
`docs/REFERENCE-STATUS.md`.

It describes the bounded evolution lane that ships today: drift-aware mutation,
durable validation and ranking, optional solver proofs, canary admission,
promotion, and operator-visible evidence.

## Executive Summary

Ambush no longer treats evolution as a distant research track. The Rust
runtime already owns a bounded evolution lifecycle.

That lifecycle is intentionally narrow:

- the hot path stays deterministic
- only detection-side artifacts evolve
- every stage persists durable evidence
- proof, canary, promotion, and review surfaces stay explicit
- no step grants automatic fleet-wide or policy-bypassing autonomy

The purpose of this document is to define the lifecycle that later assurance
milestones will tighten, not to invent a broader self-modifying system.

## Current Lifecycle

| Stage | Runtime owner | Main outputs |
| --- | --- | --- |
| Drift and pressure detection | `KittenAgent` plus replay, feedback, deception, and evasion inputs | Pressure observations and candidate creation triggers |
| Drafting and mutation | Evolution drafting and mutation harnesses | Drafts, mutation specs, materialization batches |
| Validation and ranking | Replay, validation, and ranking harnesses | Validation bundles, ranking reports, review-ready candidates |
| Population and episode persistence | Evolution population and episode stores | Durable candidate state, fitness, lineage, adversarial episode reports |
| Formal proof | Proof harness, optional Z3 lane | Proof artifacts, solver results, counterexamples |
| Canary admission | Strategy proposal router and canary harness | Canary runs and admission outcomes |
| Promotion | Promotion harness | Bounded production-promotion artifacts and rollback records |
| Operator review and export | Runtime status, operator review, proof exports | Status summaries, evidence packets, review surfaces |

## What Evolves

The active runtime evolves detection-side artifacts only.

Shipped mutation inputs include:

- replay and validation outcomes
- analyst feedback penalties
- deception interaction fitness
- adversarial corpus pressure
- evasion coverage gaps
- memory-query enrichment when available

The active runtime does not evolve:

- response actions
- policy rules
- governance thresholds
- agent admission rules
- destructive authority

## Bounded State Machine

The current lifecycle should be read as one bounded state machine:

1. `Kitten` observes drift or pressure.
2. The runtime creates or refreshes mutation and validation artifacts.
3. Candidates enter durable ranking and population state.
4. Proof artifacts are attached where available.
5. A verified candidate may be admitted into the bounded canary lane.
6. A successful canary may enter the bounded promotion lane.
7. Operators inspect the resulting evidence through status, review, and export
   surfaces.

No step above implies automatic full deployment or automatic trust expansion.

## Queue-To-Rollout State Machine

The active operator contract is best understood as the following bounded flow:

| State | Meaning | Typical persisted artifacts |
| --- | --- | --- |
| Pressure observed | Drift, adversarial pressure, analyst feedback, deception interactions, or evasion gaps justify work | Status updates, pressure or episode records |
| Candidate materialized | Mutation and drafting produced one concrete detector candidate | Drafts, mutation specs, materialization batches |
| Candidate validated | Replay and validation harnesses produced comparable evidence | Validation bundles, ranking inputs, population records |
| Candidate proved | Safety and proof artifacts are attached where required | Proof records, solver output, counterexamples |
| Candidate ready for review | Candidate is durable and operator-visible, but not yet live | Review-ready ranking packets, queue state |
| Canary active | Candidate is live only inside the bounded canary lane | Canary runs, rollback reasons, canary summaries |
| Promotion active | Candidate is the bounded production subject under observation | Promotion runs, rollback lineage, observation summaries |
| Review and export | Operators inspect evidence and produce bounded review outputs | Status reports, review sessions, signed exports |

This contract is intentionally linear from the operator perspective even though
multiple stores and harnesses back it on disk.

## Automatic Versus Gated

### Automatic inside the bounded lane

These steps can happen without a human sitting in the loop:

- drift assessment
- mutation and materialization
- replay validation
- ranking and population refresh
- episode persistence
- status publication

### Gated or bounded

These steps stay explicitly bounded:

- proof results can block advancement
- canary admission is a distinct handoff, not silent replacement of the
  baseline
- promotion is a bounded observation window with rollback semantics
- destructive runtime behavior is still governed outside the evolution lane
- operator review remains advisory unless an explicit runtime action path
  already exists elsewhere

## Operator Actions And Advisory Boundaries

The active operator contract separates inspection from authority:

- operators can inspect queue, proof, canary, promotion, and status artifacts
- operators can launch the bounded workflows that already exist in the runtime
- review packets, review sessions, evidence exports, and handoffs remain
  evidence surfaces unless a separate runtime action path explicitly consumes
  them
- no browser or review action bypasses canary, promotion, governance, or policy
  gates

## Proof And Counterexample Contract

The runtime already persists proof artifacts and counterexample data.

Current contract:

- proof artifacts are durable and tied to candidate lineage
- the optional Z3 lane is feature-gated
- the solver lane fails closed when strict proof is expected but unavailable
- machine-readable counterexamples are preserved for later replay and assurance
  work

These artifacts exist now so later assurance milestones can promote them from
evidence into hard rollout gates.

## Canary And Promotion Contract

The rollout ladder that ships today is:

- verified candidate
- bounded canary
- bounded production promotion
- rollback to retained baseline when thresholds fail

Important boundaries:

- canary scope stays explicit
- promotion remains single-runtime and bounded
- evidence and lineage persist across canary and promotion artifacts
- the operator contract remains evidence-backed, not invisible automation

## Default Promotion Posture: No Proof, No Promotion

**Read this before filing "promotion is broken".** With `rulesets/default.yaml`
exactly as shipped, production promotion refuses every candidate. That is the
intended posture, not a defect, and it is deliberate: an evolved detector does
not reach production automatically unless a solver recorded a proof about it.

`promotion.require_solver_result_for_promotion` defaults to `true`, and the
shipped configuration cannot produce the `proved` status it asks for.

### The chain, each link measured rather than assumed

1. `rulesets/default.yaml` names one invariant bundle,
   `rulesets/safety/office-detector-admission.yaml`.
2. That bundle declares `coverage_floor` x2, `fp_ceiling`, `latency_budget`
   and `parameter_bounds` x2. It declares no `custom_z3` invariant.
3. Solver artifacts are produced ONLY by the `custom_z3` arms in
   `crates/swarm-runtime/src/evolution/formal_safety.rs`, so a curated run
   produces none.
4. No artifacts means `summarize_solver_artifacts` returns `None`, so the
   assurance lineage records `solver.status: null`.
5. The promotion gate treats an absent status as no evidence and refuses.

`evolution.safety_gate.enable_z3: false` in the same file closes the door a
second time: even with a `custom_z3` invariant present, the solver lane would
record `disabled`, and `disabled` is refused through the SAME error variant as
an absent status. A stub is not a proof.

Steps 1-5 are pinned by
`curated_ruleset_produces_no_solver_result_so_promotion_is_refused` in
`crates/swarm-runtime/src/mutation/tests_core.rs`. If that test fails, the
shipped posture changed and this section is stale.

### What an operator actually sees

`swarmctl promotion-start --canary-run-id <id>` fails with:

```text
canary run `<run-id>` cannot promote `<strategy-id>`: no solver result was
recorded (status=None)
```

and, when a `custom_z3` invariant exists but the solver lane is off,
`status=Some(Disabled)`. The two are refused identically; `recorded_status` is
there so the audit record can still tell a stub from an absence.

Every promotion report also carries an unconditional solver line -- either
`Solver result: <status> | required_for_promotion=<bool>` or the exact literal
`Solver result: NO SOLVER RESULT RECORDED` -- so a report can never be read as
"proved" when nothing was asked.

### Recipe: turning automated promotion on

Three changes are needed, and all three are in operator-owned territory. None of
them require editing `rulesets/default.yaml`.

**1. Add a `custom_z3` invariant to your admission bundle.** Copy
`rulesets/safety/office-detector-admission.yaml` to a deployment-owned file,
keep its existing invariants, and append one whose query is UNSAT exactly when
the property you want holds. The solver proves by refuting the negation, so the
query asserts the bad case:

```yaml
  - name: medium_confidence_upper_guardrail
    type: custom_z3
    query: |
      (declare-const medium_confidence Real)
      (assert (= medium_confidence {{/candidate/profile/medium_confidence_threshold}}))
      (assert (> medium_confidence 0.95))
```

`{{/json/pointer}}` placeholders are resolved against the candidate manifest
before the query reaches the solver, and a pointer that does not resolve to a
scalar is a bundle error rather than a silent skip.

**2. Point the config at your bundle and enable the solver.** In your own
config file (not the curated one):

```yaml
evolution:
  safety_gate:
    invariant_bundle_paths:
      - safety/your-detector-admission.yaml
    enable_z3: true
```

**3. Build with the `z3` feature.** `enable_z3: true` on a binary built without
it changes nothing: the `#[cfg(not(feature = "z3"))]` arm records `disabled`
whatever the config says, and promotion still refuses. The feature belongs to
`swarm-runtime`, and the two shipped binaries live in `swarm-runtime-http`, so
turn it on across the dependency edge:

```bash
cargo build --release -p swarm-runtime-http --features swarm-runtime/z3
```

The dependency uses `z3-sys`'s `gh-release` feature, so it downloads a prebuilt
solver at build time instead of needing a system libz3.

**What a passing result looks like.** The proof artifact records
`solver_summary.status: proved`, the proof stamps
`proof_system: formal_safety_gate_v2+z3_smt_v1`, and each solver artifact
carries a non-null `rlimit_count` -- the deterministic count of solver work,
which is what makes the verdict reproducible across machines. A proof whose
solver never ran stamps `formal_safety_gate_v2+z3_smt_v1_not_run` instead, so
the two are distinguishable in the durable record. The promotion report then
reads `Solver result: proved | required_for_promotion=true`.

Statuses that are NOT `proved` -- `counterexample`, `timeout`, `resource_limit`,
`error` -- are refused as `SolverResultNotProved`. Only `timeout` is
non-reproducible; it is the wall-clock backstop, and it decides nothing on its
own beyond refusing the promotion.

### What this repository cannot do, and who has to

The curated ruleset cannot be made to satisfy its own gate here. Shipping a
`custom_z3` invariant in `rulesets/safety/office-detector-admission.yaml`, or
flipping `enable_z3` in `rulesets/default.yaml`, would change the sha256 of a
file recorded inside the ed25519-signed `rulesets/attestation.json`, and the
signing key is deliberately absent from this repository. Startup verification
would then reject the config outright.

So "ship a curated bundle that can satisfy its own gate" is an action for
whoever holds that key. It needs, as one signed unit:

- a `custom_z3` invariant added to the curated admission bundle,
- `evolution.safety_gate.enable_z3: true` in `rulesets/default.yaml`,
- a regenerated `rulesets/attestation.json`,
- and a decision that the shipped binary is built with the `z3` feature.

Until then the posture above is the shipped one, and an operator who wants
automated promotion follows the recipe with their own config.

### Why `disabled` is still an allowed assurance status

`rulesets/default.yaml` lists `disabled` in
`evolution.assurance.allowed_solver_statuses`, which reads at first like a
contradiction of everything above. It is not, because the two lists govern
different questions:

- ASSURANCE asks "may this proposal continue through the evolution lane?" A
  deployment with no solver is not required to block every proposal at the
  queue, so `disabled` is allowed there.
- PROMOTION asks "may this candidate become production?" That gate hardcodes
  `proved` and never reads `allowed_solver_statuses` at all.

The gap between those two answers is the fail-closed margin, and it is where the
posture lives. It is only coherent while the promotion gate stays indifferent to
the assurance allow-list, so that is enforced rather than left as a convention:
`the_assurance_allow_list_cannot_authorize_a_promotion` in
`crates/swarm-runtime/tests/promotion_solver_gate.rs` hands the gate a lineage
whose recorded `allowed_statuses` includes `disabled`, with a config whose
allow-list includes it too, and requires the refusal anyway.

A third layer sits above both: a `custom_z3` invariant evaluated with the solver
off yields an `unproved` verdict, so the formal-safety report's `passed` is
`false` and the candidate is rejected before assurance is consulted. `unproved`
is not `refuted` -- no counterexample is synthesized for a solver that never ran.

## Artifact Families

The active evolution contract is anchored by durable artifact families rather
than transient control flow:

- replay, validation, and ranking artifacts
- proof and counterexample artifacts
- queue and review-state artifacts
- canary and promotion artifacts
- population, episode, and status artifacts
- review, export, and handoff artifacts

Later assurance milestones may strengthen how these artifacts gate promotion,
but they should not need to redefine where they live or what stage they
represent.

## Status And Operator Surfaces

The evolution lane is operator-visible today through:

- `evolution_status` runtime events
- runtime status summaries
- persisted ranking, proof, canary, promotion, population, and episode artifacts
- local operator review and export surfaces that reuse the same evidence stores

The operator surface is for inspection, triage, and bounded launch of existing
workflows. It is not a separate evolution engine.

## Config Areas That Define The Contract

The evolution lane is anchored by repo-owned config under:

- `evolution.*`
- `canary.*`
- `promotion.*`
- `deception.*`
- `memory.*`
- evasion corpus and technique catalog files under `scenario-suites/`,
  `scenarios/`, and `rulesets/evasion/`

`docs/CONFIGURATION.md` is the field reference for these paths.

## Explicit Boundaries

The active contract explicitly excludes:

- evolution of response behavior
- automatic distributed rollout
- hidden promotion without evidence
- proof-free widening of destructive autonomy
- replacing operator review with an autonomous governance path

Use `docs/ARCHITECTURE.md` for the lane map and `docs/CONSENSUS.md` for the
separate governance boundary that still controls destructive action.
