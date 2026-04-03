# Architecture Research: Build Order and Component Boundaries

## Proposed Components

### 1. Detection Lane

Responsibilities:

- ingest normalized telemetry events
- evaluate concrete detector logic
- emit pheromone deposits and response proposals

Boundary:

- should not depend on Python, consensus, or broad orchestration

### 2. Pheromone Substrate

Responsibilities:

- accept deposits
- compute concentration and decay
- support replay/query semantics

Boundary:

- start in-memory
- expose stable Rust APIs before adding NATS durability

### 3. Policy Gate

Responsibilities:

- evaluate live response requests
- deny or require human approval where appropriate
- issue short-lived capability leases for allowed actions

Boundary:

- deterministic only
- no adaptive or distributed governance assumptions in Phase 1

### 4. Response Execution

Responsibilities:

- dry-run and enforced execution
- narrow adapter surface
- normalized receipts and failures

Boundary:

- one sandboxed adapter first
- one real adapter only after tests and metrics exist

### 5. Audit and Receipts

Responsibilities:

- preserve request, decision, and execution trail
- sign or hash critical artifacts
- support replay and reconstruction later

Boundary:

- start with simple receipt records compatible with later spine/crypto hardening

## Data Flow

```text
Telemetry Event
  -> Detector
  -> Pheromone Deposit
  -> Response Proposal
  -> Policy Decision
  -> Capability Lease or Denial
  -> Response Adapter
  -> Receipt Record
```

The key architectural rule is that the detection lane must remain useful and measurable even if investigation, correlation, and advanced governance do not yet exist.

## Suggested Build Order

1. strict config and runtime contracts
2. one real telemetry event model
3. one real detector
4. in-memory substrate with decay and concentration
5. deterministic policy gate
6. sandbox response adapter
7. receipt chain and replay-friendly records
8. metrics, tracing, and load tests
9. only then: JetStream durability, deeper investigation, and optional distributed extensions

