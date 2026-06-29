# Evolution And Rollout Contract

This document is part of the active contract set defined in
`docs/REFERENCE-STATUS.md`.

It describes the bounded evolution lane that ships today: drift-aware mutation,
durable validation and ranking, optional solver proofs, canary admission,
promotion, and operator-visible evidence.

## Executive Summary

Ambush Engine no longer treats evolution as a distant research track. The Rust
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
