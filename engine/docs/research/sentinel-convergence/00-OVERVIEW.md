# Sentinel Convergence Overview

This file is the entry point for the `sentinel-convergence` research set. The
series is intentionally design-heavy, but not every document is meant to drive
immediate implementation.

## Current Repo Posture

- The current Swarm Team Six roadmap remains focused on the single-node
  live-response path. Distributed governance is still deferred to Phase 6.
- Consequential actions follow the existing design principle from
  `docs/CONSENSUS.md`: the swarm observes freely but acts only with consensus.
- Under partition, detection, evidence capture, local buffering, and reporting
  should preserve availability. Destructive or environment-modifying response
  remains fail-closed unless a bounded contingency lease explicitly authorizes a
  narrow action set.
- The canonical proposed infrastructure telemetry schema for this series lives
  in [05-TELEMETRY-BRIDGE-ARCHITECTURE.md](05-TELEMETRY-BRIDGE-ARCHITECTURE.md)
  and uses three payloads:
  `InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion`.
- `swarm-edge` is exploratory research in this repo state. It is not part of
  the current near-term roadmap.

## How To Read The Series

| Doc | Role in the Series | Current Status | Best Use |
|---|---|---|---|
| `00` | Overview, reading order, canonical decisions | Active guide | Start here |
| `01` | BFT consensus design for STS | Proposed, Phase 6+ | Use when governance work starts |
| `02` | Detector logic and threat mapping for infra signals | Proposed, depends on `05` | Use for detector heuristics and validation design |
| `03` | Edge binary and deployment exploration | Exploratory, deferred | Use as option space for a later edge initiative |
| `04` | Partition authority model and bounded autonomy | Proposed, Phase 6+ | Use to shape contingency-lease rules |
| `05` | Canonical Sentinel bridge schema and transport design | Proposed canonical schema | Use as the wire-contract reference |
| `06` | Conceptual stigmergy and coordination background | Background research | Use for rationale, not interface decisions |
| `07` | Audit/reconciliation design for partitioned autonomy | Proposed, long-term | Use after `01` and `04` are real |
| `08` | Resilience patterns and runtime hardening | Near-term actionable | Use now for reliability improvements |
| `09` | Empirical validation plan for infra-signal claims | Proposed benchmark program | Use to replace estimates with measurements |
| `10` | ADR for telemetry-schema rollout in the monorepo | Proposed migration decision | Use before landing schema changes |
| `11` | Candidate partition authority defaults | Proposed future policy | Use only if contingency leases are adopted |
| `12` | Failure-injection experiment plan for resilience gaps | Proposed experimental supplement | Use to drive targeted hardening work |
| `13` | ADR for minimal partition-authority type changes | Proposed follow-on ADR | Use before implementing `11`-driven type changes |
| `14` | Detailed partition reconciliation and rollback study | Proposed follow-on protocol | Use with `07` and `11` when designing post-heal recovery |

## Canonical Decisions In This Revision

- `05` is the canonical proposed schema document for Sentinel-derived
  infrastructure telemetry.
- `02` should be read as detector logic over that schema, not as a competing
  wire contract.
- `10` should be read as the rollout decision record for any future telemetry
  schema extension in this monorepo.
- `04` does not imply "AP for everything." The intended split is:
  availability for detection/reporting, bounded fail-closed semantics for
  destructive response.
- `11` is a candidate future policy for partition-mode bounded authority. It is
  not current runtime behavior and does not override `docs/CONSENSUS.md`.
- `01` should not be read as endorsing an ad hoc signature-as-VRF design.
  Until an audited VRF is selected, deterministic proposer rotation is the safer
  default for an initial implementation.

## Quantitative Claims

- Unless a table or paragraph explicitly says `measured`, numbers in this
  series should be treated as design targets, estimates, or validation
  hypotheses.
- Proposed code blocks are interface sketches, not declarations that the
  current repo already exposes those types or endpoints.

## Source Layout Assumption

Many references in this series assume a sibling Sentinel checkout. In this
workspace that may be `../sentinel`; in other checkouts it may be vendored or
relocated. Update paths accordingly when using the docs as implementation input.
