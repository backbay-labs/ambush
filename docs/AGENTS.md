# Agent Contract

This document is part of the active contract set defined in
`docs/REFERENCE-STATUS.md`.

It describes the Rust runtime agents that ship today, how they are registered,
what lanes they operate in, and what boundaries constrain them.

## Executive Summary

Swarm Team Six ships eight runtime agent roles:

- `Whisker` drives hot-path detection and pheromone deposit.
- `Stalker` drives async investigation when investigation is enabled.
- `Weaver` drives async incident correlation when correlation is enabled.
- `Pouncer` translates approved response intent into routed response requests.
- `Tom` owns governance health, receipts, and partition-era control.
- `Kitten` owns bounded detector evolution and rollout preparation.
- `Sphinx` owns durable memory and memory-query answers when memory is enabled.
- `Calico` owns deception deployment and tripwire findings when deception is enabled.

All active roles are implemented in the Rust runtime under `crates/`. The old
Python-heavy archetype map is not the active contract.

## Registration Model

Serve mode uses the same registration model for every runtime-owned agent:

1. Load or create one persisted Ed25519 seed per role and slot from
   `identity.agent_key_dir`.
2. Derive the stable runtime identity as `swarm:ed25519:<hex>`.
3. Check the identity against the registry under `identity.registry_dir`.
4. Register the admitted identity with the dispatcher and the pheromone
   substrate.

An identity that is not admitted does not join the dispatcher, does not deposit
trusted pheromones, and does not participate in governance.

## Capability Matrix

| Role | Enabled when | Lane | Primary inputs | Primary outputs | Bounded by |
| --- | --- | --- | --- | --- | --- |
| `Whisker` | Always when admitted | Critical | Live telemetry, detector config, threat intel, pheromone policy | Signed pheromone deposits, agent findings, runtime events | Detector selection, pheromone thresholds, substrate admission |
| `Stalker` | `investigation.enabled` | Async | Pheromone leads, replay bundles, investigation queue | Persisted investigation bundles, published findings | Investigation queue limits and time budgets |
| `Weaver` | `correlation.enabled` | Async | Investigation bundles, incident store state | Correlated incidents, published findings | Correlation window, shared-key threshold, candidate limit |
| `Pouncer` | Always when admitted | Critical / governance edge | Escalated findings, response playbook matches, governance policy | `RequestResponse` or `GovernanceVeto` actions | Policy gate, governance receipt checks, partition authorization |
| `Tom` | Always when admitted | Governance | Agent health, destructive response requests, persisted governance state | Governance receipts, vetoes, contingency leases, partition reports | Quorum health, registry admission, persisted partition state |
| `Kitten` | `evolution.enabled` | Evolution | Drift signals, replay results, ranking state, memory answers, adversarial pressure | Strategy proposals, durable population state, evolution status | Replay validation, proof lane, canary and promotion gates |
| `Sphinx` | `memory.enabled` | Async / memory | Findings, incidents, deception assets, signed memory queries | Knowledge-graph persistence, signed memory answers | Memory retention policy and typed graph schema |
| `Calico` | `deception.enabled` | Async / deception | Repo-owned deception playbook, runtime mode, observed decoy interactions | Decoy lifecycle state, high-confidence tripwire findings | Playbook entries, lifecycle rotation, cleanup windows |

## Shared Runtime Contract

Every registered agent operates under the same dispatcher contract:

- agents tick on the bounded dispatcher loop instead of owning an unbounded
  private runtime
- each tick receives the current swarm mode, the last upward mode transition,
  recent peer findings, and visible agent health
- every role reports `healthy`, `degraded`, or `failed`
- role shifts are broadcast as `SwarmEvent::RoleShift`
- peer-visible findings are surfaced back into the dispatcher for bounded
  cross-agent coordination

This means the runtime contract is not "independent services per archetype." It
is one Rust runtime with typed role implementations sharing one substrate,
health model, and event surface.

## Governance And Approval Lineage

The current governance chain is intentionally simple:

1. An admitted runtime identity emits a finding or response proposal.
2. `Pouncer` asks `Tom` policy whether a response can proceed.
3. `Tom` returns either:
   - no extra governance artifact for non-destructive guarded response,
   - a signed governance receipt for destructive response, or
   - a veto or contingency lease path when partition handling applies.
4. The dispatcher re-validates destructive-governance artifacts before routing.
5. The response router and audit trail persist the final outcome.

This means:

- identity admission happens before agent participation
- destructive authority is attached as explicit evidence
- operator approval layers on top of governance, not beside it
- review and maintenance surfaces inspect and replay this lineage but do not
  invent a second approval path

## Role Definitions

### Whisker

`Whisker` is the hot-path detector. It consumes normalized telemetry, evaluates
the configured detector set, and writes signed pheromone deposits into the
configured substrate. It is the only role that must remain on the critical
latency path for every event.

Current scope:

- typed detector execution
- threat-intel enrichment
- distinct-source escalation inputs
- agent findings for peer visibility

`Whisker` does not own async investigation, correlation, or response execution.

### Stalker

`Stalker` is the bounded async investigation worker. It consumes lead pressure
from the substrate, claims investigation work, and persists investigation
bundles for later review and correlation.

Current scope:

- replay-backed investigation work
- bounded queue submission and completion
- persisted investigation artifacts
- publication of completed investigation findings back into the substrate

`Stalker` is optional and does not block the critical lane.

### Weaver

`Weaver` is the bounded async correlation worker. It consumes investigation
results and turns related evidence into durable incidents.

Current scope:

- time-windowed candidate search
- shared-key and evidence-based incident assembly
- durable incident persistence
- publication of correlated findings for downstream review

`Weaver` enriches operator context. It does not directly authorize response.

### Pouncer

`Pouncer` is the response-routing agent. It watches the current swarm mode,
matches escalated findings against the configured response playbook, and emits
typed response requests only after governance policy review.

Current scope:

- guarded response request creation
- receipt attachment for destructive requests
- contingency-lease attachment during partition when allowed
- veto emission when governance blocks execution

`Pouncer` does not bypass the policy gate, dispatcher checks, or response
adapter controls.

### Tom

`Tom` is the governance role. It tracks governance health, issues signed
receipts for destructive requests, stages contingency leases for partition
survival, and persists partition-era activity for later reconciliation.

Current scope:

- governance health observation
- receipt-backed approval and veto for destructive response actions
- persisted partition state and reconciliation reporting
- pre-staged contingency lease issuance while healthy

`Tom` is the bounded governance layer that ships today. It is not a general
fleet-wide control plane.

### Kitten

`Kitten` owns the bounded evolution lane. It reacts to drift, analyst feedback,
deception pressure, and evasion gaps, then materializes, validates, ranks, and
proposes candidate detector strategies.

Current scope:

- drift-driven and adversarially informed mutation cycles
- durable population and episode tracking
- replay validation and ranking
- proof-lane handoff and canary admission bridging
- evolution status persistence for operator surfaces

`Kitten` does not mutate response behavior or bypass rollout gates.

### Sphinx

`Sphinx` owns durable memory. It persists typed knowledge-graph nodes and edges,
registers long-lived threat context, and answers signed memory queries from the
rest of the runtime.

Current scope:

- file-backed typed graph persistence
- memory-query answer emission
- deception-asset registration
- retention and garbage collection

`Sphinx` is an enrichment lane, not a gate on hot-path execution.

### Calico

`Calico` owns deception. It deploys repo-owned decoys, rotates them through the
lifecycle window, and emits high-confidence findings when monitored tripwires
are touched.

Current scope:

- decoy inventory and lifecycle persistence
- monitored file, port, and credential tripwires
- deception asset registration into Sphinx
- live interaction pressure for Kitten fitness

`Calico` broadens detection coverage without widening destructive autonomy.

## Boundaries

The active contract intentionally excludes:

- a revived Python runtime for agent execution
- per-role autonomy tiers as the primary control vocabulary
- uncontrolled multi-node swarms or gossip-based agent coordination
- response execution that bypasses dispatcher routing, policy, or governance
- agent identity without persisted keys and registry-backed admission

Use `docs/ARCHITECTURE.md` for lane boundaries,
`docs/CONSENSUS.md` for governance semantics, and `docs/EVOLUTION.md` for the
bounded rollout contract.
