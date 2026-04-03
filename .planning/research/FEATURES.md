# Feature Research: Table Stakes, Differentiators, Anti-Features

## Table Stakes

### Detection

- **Fast event ingestion** — normalized telemetry enters the runtime with minimal overhead
- **Concrete detector logic** — at least one real detector path exists, not only traits and scaffolds
- **Confidence-scored findings** — detections carry enough structure to drive downstream decisions
- **Published performance numbers** — latency and throughput are first-class outputs, not implied goals

### Response Safety

- **Deterministic policy evaluation** — allow, deny, or require human gate without ambiguity
- **Narrow response scope** — response actions are capability-scoped and auditable
- **Dry-run mode** — operators can verify intent before enabling side effects
- **Receipt generation** — every authorization and execution result is reconstructable

### Runtime Hygiene

- **Strict config loading** — malformed rulesets fail at load
- **Integration tests across the critical path** — detect -> authorize -> execute -> receipt
- **Metrics and traces** — enough visibility to debug latency regressions and false positives

## Differentiators

- **Pheromone-based coordination** — useful shared substrate abstraction for accumulating signal
- **Signed capability lease model** — better response control than broad one-off adapter calls
- **Local upstream reference archive** — lets STS absorb good ideas without runtime coupling
- **Rust-first safety floor** — strong positioning if detection and response remain deterministic and measurable

## Anti-Features

| Feature | Why Not In v1 |
|---------|----------------|
| Python agents in the critical path | Conflicts with the performance and safety goals |
| BFT committee as a launch blocker | Adds complexity before there are independent trust domains |
| Broad response catalog | Too much surface area before one safe action path is proven |
| Live red/blue co-evolution | Research-heavy and not needed to prove the first production slice |
| Gossip / membership mesh | Not justified without an actual multi-node deployment problem |

## Dependencies Between Features

- Fast detection depends on strict event contracts and a real benchmark harness
- Safe live response depends on deterministic policy and receipt generation
- Durable substrate work depends on stabilizing the in-memory substrate semantics first
- Investigation and correlation should depend on the hot path, not the other way around

