# Ambush Engine: Rust-First Roadmap

> Product name: Ambush  
> Last updated: 2026-04-03

This roadmap replaces the earlier Python-first swarm plan with a Rust-first implementation sequence centered on fast detection and safe live response.

## Phase 0: Bootstrap And Assimilate

**Goal:** make the repo self-contained enough to build against without hidden upstream assumptions.

### Deliverables

- copy selected upstream references into `vendor/reference/`
- record source provenance and commit SHAs
- define which docs are canonical vs historical
- keep or rewrite only the crates that fit the Rust-first runtime
- add strict config-loading requirements to the plan

### Exit Criteria

- vendor reference tree exists and is documented
- canonical docs match the actual direction of the repo
- the workspace structure reflects the Rust-first plan

## Phase 1: Fast Detection Slice

**Goal:** prove the hot path.

### Deliverables

- one real telemetry input path
- one real Rust detector in `swarm-whisker`
- in-memory pheromone substrate in `swarm-pheromone`
- confidence and severity scoring with typed contracts
- benchmark harness for p50/p95/p99 detection latency

### Exit Criteria

- synthetic telemetry can drive end-to-end detection
- hot-path latency is measured and published
- tests cover detector behavior and pheromone math

## Phase 2: Safe Live Response Slice

**Goal:** prove that Ambush Engine can take live action safely.

### Deliverables

- deterministic gate in `swarm-policy`
- short-lived capability lease model
- one response adapter in `swarm-response`
- dry-run and sandboxed live modes
- signed receipt chain for authorize/execute results

### Exit Criteria

- the runtime can deny malformed or weak requests
- the runtime can execute one sandboxed action under policy control
- every action path yields a receipt bundle

## Phase 3: Runtime Composition

**Goal:** wire the production runtime into one coherent Rust service.

### Deliverables

- `swarm-runtime` as composition root
- runtime modes for detect-only and live-response
- structured startup/config flow
- end-to-end test from telemetry to response receipt

### Exit Criteria

- one integration test covers the full vertical slice
- the runtime can run in detect-only and live-response modes

## Phase 4: Durability And Operators

**Goal:** make the first slice operationally useful.

### Deliverables

- local journal-backed substrate
- replay support
- local replay-bundle store with receipt and hunt lookup
- metrics and tracing
- operator-facing status output

### Exit Criteria

- the runtime can replay and inspect recent decisions
- substrate durability no longer depends on process memory alone

## Phase 5: Async Investigation And Correlation

**Goal:** add richer context without destabilizing the critical lane.

### Deliverables

- async investigation workflow
- evidence summarization and context packaging
- optional correlation layer
- operator review surfaces

### Exit Criteria

- investigation improves triage quality without affecting the hot path

## Phase 6: Optional Advanced Governance

**Goal:** add distributed governance only if reality demands it.

### Candidate Work

- replicated policy services
- quorum-based approvals
- stronger lease distribution
- partition handling

These features are intentionally deferred. They are not prerequisites for a safe first live-response system.

## Phase 7: Optional Replay, Red-Team, And Evolution Work

**Goal:** use upstream ideas for evaluation after the core runtime is real.

### Candidate Work

- offline replay using Hellcat-inspired scenarios
- detector evolution experiments
- adversarial evaluation harnesses
- more formal safety properties

This work should remain offline until the main runtime is stable.

## Near-Term 30-Day Plan

1. finish bootstrap docs and vendor references
2. land real tests in `swarm-policy`, `swarm-response`, and `swarm-runtime`
3. implement one detector and one in-memory substrate path
4. implement one sandboxed live-response adapter
5. produce first latency benchmark report

## Explicit Non-Goals For The First Slice

- Python on the critical path
- PyO3 as a required runtime seam
- BFT as a launch blocker
- gossip mesh membership
- live co-evolution
- certification theater before a working vertical slice
