# Swarm Team Six

## What This Is

Swarm Team Six is a Rust-first threat detection and controlled live response runtime. It ingests telemetry, detects suspicious behavior quickly, evaluates narrow response actions through deterministic policy gates, and emits signed receipt chains for every decision.

The repository started with a larger Python-heavy swarm concept, but the active direction is now a self-contained Rust system built for fast detection first and safe live response second.

## Core Value

Detect real threats quickly enough to take safe action before the window to respond closes.

## Requirements

### Validated

- ✓ Rust workspace compiles with core domain crates plus runtime, policy, and response scaffolds — existing
- ✓ Top-level architecture and roadmap now reflect a Rust-first live-response direction — existing
- ✓ Focused upstream reference code from ClawdStrike, Hellcat, and Cyntra has been copied locally for porting inspiration — existing

### Active

- [ ] Build a benchmarked Rust detection lane from telemetry event to pheromone deposit
- [ ] Build a deterministic Rust policy gate for narrow live response actions
- [ ] Build sandboxed and enforced response execution modes with signed receipts
- [ ] Replace Python-runtime assumptions with STS-owned Rust implementations and contracts
- [ ] Keep the first production slice small enough to measure, test, and trust

### Out of Scope

- Python-first orchestration runtime — archived as reference while the production path moves to Rust
- BFT / VRF governance in v1 — deferred until a single-node live-response path is trusted
- Gossip mesh / CRDT membership — premature without proven multi-node operational need
- Live co-evolutionary attack/defense loops — deferred until the core detector and response path are real

## Context

This is a brownfield repo with significant existing documentation and scaffold code, but not a finished runtime. The project direction was clarified in-session:

- live response actions are intended, not merely advisory recommendations
- the first proof point is fast detection
- upstream sibling repos are considered stable enough to copy from, but the long-term goal is for STS to stand on its own
- Python code should be treated as inspiration and reference material, not as the production runtime

The repo now includes:

- Rust crates for core types, pheromones, guards, crypto, spine, policy, response, runtime, and detection
- legacy Python material under `kernel/` retained as reference
- copied upstream reference trees under `vendor/reference/`

## Constraints

- **Tech stack**: Production runtime is Rust-first — one type system, one operational path, one benchmarkable hot lane
- **Security**: Live response must stay behind deterministic policy and auditable receipts — destructive actions cannot depend on fuzzy orchestration
- **Architecture**: The first milestone must avoid premature distributed complexity — no BFT, gossip, or co-evolution in the critical path
- **Repository ownership**: Upstream ideas may be copied in temporarily, but product code must become STS-owned and self-contained
- **Performance**: The first success metric is measurable detection latency and throughput, not architectural completeness

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Move the production runtime to pure Rust | Fast detection and live response are easier to measure, secure, and ship with a single runtime | — Pending |
| Keep `kernel/` as reference only | The Python tree is useful design input but adds latency and seam complexity if kept on the hot path | — Pending |
| Keep `swarm-bridge` as legacy only | Avoid making PyO3 a strategic dependency while the core system is still being defined | — Pending |
| Start with a narrow response safety model | Human gating plus deterministic policy is a better first boundary than simulated consensus in one control plane | — Pending |
| Copy focused upstream code into `vendor/reference/` | Makes the project locally self-sufficient while porting the useful ideas inward | — Pending |

---
*Last updated: 2026-04-02 after initialization*
