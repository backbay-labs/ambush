# Architecture

Canonical architecture for the Rust runtime that ships today.

This document is part of the active contract set described in
`docs/REFERENCE-STATUS.md`. It should describe current runtime behavior, current
lane boundaries, and current operator surfaces, not milestone history.

## Executive Summary

Ambush Engine ships as a Rust-first detection and controlled-response runtime.
The runtime already includes:

- a critical detection and response lane
- optional async investigation and correlation lanes
- optional memory, deception, and evolution lanes
- receipt-backed governance and identity-admission surfaces
- local operator, demo, and platform API surfaces

The active contract is no longer a comparison against the removed Python
control-plane design. The question for later milestones is how the current Rust
runtime evolves, not whether it still plans to become Rust-first.

## Source-Of-Truth Boundary

Read the runtime in this order:

1. `rulesets/default.yaml` and config types under `crates/swarm-core`
2. this document plus `docs/AGENTS.md`, `docs/CONSENSUS.md`,
   `docs/EVOLUTION.md`, and `docs/CONFIGURATION.md`
3. planning docs under `.planning/`

Historical material stays reference-only. `docs/INTEGRATION.md` is preserved for
upstream and mixed-runtime context, but it is not part of the active contract.

## Current Runtime Shape

```text
telemetry subjects and bridge-backed sources
    |
    v
bridge runtime registry
    |
    v
WhiskerAgent -> swarm-whisker detection strategies
    |
    v
configured pheromone substrate + mode/escalation state
    |
    +--> StalkerAgent investigation lane (optional)
    |       |
    |       v
    |   replay and investigation bundles
    |       |
    |       v
    |   WeaverAgent incident correlation lane (optional)
    |
    +--> SphinxAgent memory lane (optional)
    |
    +--> CalicoAgent deception lane (optional)
    |
    +--> KittenAgent evolution lane (optional)
    |
    v
TomAgent governance checks + approval and consensus receipts
    |
    v
PounceAgent response routing through configured adapters
    |
    v
swarm-spine + swarm-crypto audit and proof artifacts
```

## Active Lanes

### Critical lane

The critical lane is the path that must remain deterministic and safe enough to
ship in live runtime:

- telemetry ingress from direct subjects and configured bridges
- Whisker detection
- pheromone deposit, concentration, escalation, and mode state
- deterministic policy checks and human-gate rules
- Pounce response execution through configured adapters
- signed receipts and audit persistence

### Async lane

The async lane is shipped, but remains optional and bounded:

- Stalker investigation over replay and investigation bundles
- Weaver correlation into durable incidents
- Sphinx memory retrieval and retention when memory is enabled
- Calico deception lifecycle and high-confidence tripwire findings when
  deception is enabled

Async features enrich operator understanding and later decisions, but they do
not redefine the critical-lane safety boundary.

### Governance lane

The runtime already exposes bounded governance surfaces:

- persisted Ed25519 identities for runtime agents
- registry-backed identity admission
- Tom governance health and degraded-state tracking
- human approval thresholds from repo-owned policy config
- receipt-backed multi-instance response authorization and partition-era lease
  handling

Detailed semantics live in `docs/CONSENSUS.md`.

### Governance modes

The active architecture uses four governance modes across that lane:

| Mode | Applies when | Result |
| --- | --- | --- |
| Observation | Detection, investigation, correlation, memory, deception, and ordinary status publication | No governance receipt is required |
| Guarded response | Non-destructive response work such as escalation or decoy deployment | Policy and audit apply, but destructive-governance semantics do not |
| Receipt-backed response | Destructive response work such as block, isolate, and revoke | Signed governance receipt plus any required human approval |
| Maintenance-only | Local operator maintenance, review, export, replay, and bounded upkeep actions | Does not widen live-response authority or bypass the response path |

This is the shipped architecture boundary. A broader multi-operator governance
plane is still deferred.

Across those modes, the active safety rule is:

- fail closed for destructive response when quorum is unavailable
- fail open for observability, health reporting, and recovery inspection
- use staged contingency leases only as bounded partition-era exceptions
- persist reconciliation markers so healing does not erase partition history

### Evolution lane

The runtime already owns a real evolution path:

- replay and experiment artifacts
- proof and counterexample artifacts
- durable proposal and selection state
- canary and promotion handoff surfaces
- evolution status events and operator-visible outputs

Detailed semantics live in `docs/EVOLUTION.md`.

### Evolution state machine

The active evolution lane is one bounded operator-facing state machine:

`pressure -> mutation -> validation -> proof -> canary -> promotion -> review`

Interpretation rules:

- pressure, mutation, validation, and status publication can run automatically
  inside the bounded evolution lane
- proof, canary, and promotion are persisted as explicit artifacts rather than
  silent in-memory transitions
- operator review and export inspect the same artifacts and do not create a
  second rollout path

### Operator surfaces

Operators interact with the runtime through shipped local and HTTP surfaces:

- lifecycle and readiness endpoints such as `/startupz`, `/readyz`, `/livez`,
  `/healthz`, and `/prestop`
- demo and event-stream surfaces under `/v1/demo/*` and `/v1/events/stream`
- authenticated local review routes under `/v1/operator/review*`
- versioned platform APIs under `/v2/api/*`
- repo-owned CLI and deployment surfaces such as `swarmctl` and Helm manifests

### Operational Envelope

Performance and capacity claims are part of the operator contract only when they
come from shipped surfaces:

- `/startupz`, `/readyz`, and `/healthz` define whether the runtime is fit to
  accept work
- `/metrics` carries the request, stage-latency, heap-pressure, bridge-health,
  and ingest-rate series operators alert on
- `docs/benchmarks/fast-detection.md` is hot-path regression data only
- `docs/benchmarks/end-to-end-ingest.md` and `docs/CONFIGURATION.md` define the
  measured reference envelope and alert thresholds

Static agent-count folklore is not part of the active architecture. Capacity
guidance must be backed by rerunning the shipped benchmark on the target host
and substrate.

## Bounded And Deferred

The active contract should mark these as out of scope or reference-only unless a
later phase explicitly promotes them:

- revived Python control-plane or PyO3 bridge architecture
- external upstream kernels as live runtime dependencies
- governance or rollout semantics that exceed the current bounded receipt-backed
  runtime model
- gossip meshes, broader fleet-wide autonomy, or other distributed coordination
  expansion not described by the current runtime and config surfaces

## Related Documents

- `docs/AGENTS.md` for runtime role definitions and config gates
- `docs/CONSENSUS.md` for governance and response authorization
- `docs/EVOLUTION.md` for replay, proof, queue, canary, and promotion semantics
- `docs/CONFIGURATION.md` for the live config surface
- `docs/REFERENCE-STATUS.md` for the active-versus-historical policy
