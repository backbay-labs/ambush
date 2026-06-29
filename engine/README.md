# Ambush Engine

**Codename:** Ambush Engine  
**Product:** Ambush

Ambush Engine is now being rebuilt as a Rust-first autonomous detection and live-response engine.

The old Python-heavy swarm design is still present in this repository as reference material, but it is no longer the production direction. The current plan is:

- keep the hot path in Rust
- keep live response authorization deterministic
- absorb useful upstream code locally so the project can stand on its own
- treat Python and prior swarm docs as inspiration, not runtime dependencies

## Current Direction

The first proof point is **fast detection with safe live response**, not a full multi-agent platform.

The production slice is:

1. ingest telemetry in Rust
2. evaluate detections in Rust
3. deposit/query pheromones in Rust
4. authorize response through a static Rust policy gate
5. execute a small set of capability-scoped response actions
6. emit signed receipts for every step

Async investigation and correlation still matter, but they are now follow-on work. They do not belong on the initial critical path.

## Runtime Shape

```text
+------------------+     +------------------+     +------------------+
| Telemetry Input  | --> |  Whisker Detect  | --> | Pheromone State   |
| bridges + feeds  |     | rust hot path    |     | in-memory/NATS    |
+------------------+     +------------------+     +------------------+
          |                         |                         |
          +-------------------------+-------------------------+
                                    |
                                    v
                         +-----------------------+
                         | Rust Policy Gate      |
                         | static + fail-closed  |
                         +-----------------------+
                                    |
                                    v
                         +-----------------------+
                         | Response Executors    |
                         | dry-run/live adapters |
                         +-----------------------+
                                    |
                                    v
                         +-----------------------+
                         | Signed Receipt Chain  |
                         | audit + replay        |
                         +-----------------------+

                   async side lane: investigation / correlation / operator context
```

Canonical `swarm_finding` forwarding and replayable notification routing now sit on that runtime as optional outbound sinks configured from repo-owned YAML. The current detector slice also includes persistence and supply-chain strategy families alongside the earlier execution, DNS, lateral-movement, credential-access, and scripting coverage. The operator and configuration details live in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Design Principles

1. **Rust on the critical path.** Detection, policy, response, and receipts stay in one language and one type system.
2. **Live response is a product feature.** This is not an advisory-only system.
3. **Fail-closed by default.** Detection may be permissive; action execution may not.
4. **Small first slice.** One benchmarked detector, one real policy gate, one sandboxed response adapter.
5. **Self-contained codebase.** Upstream projects are reference sources, not permanent runtime dependencies.

## Repo Status

The repo currently contains three kinds of material:

- **Active Rust crates** in `crates/`
- **Archived legacy material** removed in `v1.28` from the live tree
- **Copied upstream references** in `vendor/reference/`

The canonical docs for the new direction are:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- [docs/DR-RUNBOOK.md](docs/DR-RUNBOOK.md)
- [docs/ROADMAP.md](docs/ROADMAP.md)
- [docs/decisions/0001-rust-first-runtime.md](docs/decisions/0001-rust-first-runtime.md)
- [docs/REFERENCE-STATUS.md](docs/REFERENCE-STATUS.md)
- [docs/VENDOR-REFERENCES.md](docs/VENDOR-REFERENCES.md)

## Workspace Layout

```text
ambush-engine/
|
|-- Cargo.toml
|-- crates/
|   |-- swarm-core/        # shared domain types
|   |-- swarm-whisker/     # detection primitives and stream runtime
|   |-- swarm-pheromone/   # substrate and concentration queries
|   |-- swarm-policy/      # deterministic response authorization
|   |-- swarm-response/    # response adapters and receipts
|   |-- swarm-runtime/     # composition root for the Rust runtime
|   |-- swarm-guard/       # imported/adapted safety rules
|   |-- swarm-spine/       # envelopes and receipt chain
|   |-- swarm-crypto/      # signing, hashing, merkle helpers
|   |-- swarm-consensus/   # deferred/optional advanced governance
|
|-- docs/
|-- rulesets/
|-- vendor/reference/      # copied upstream inspiration, not active deps
+-- .planning/             # milestone planning and archive artifacts
```

## Vendor References

Selected source trees from Hellcat, Cyntra, and the engine's own predecessor lineage have been copied into `vendor/reference/` for temporary inspiration while Ambush Engine is made self-contained.

See:

- [vendor/reference/README.md](vendor/reference/README.md)
- [docs/VENDOR-REFERENCES.md](docs/VENDOR-REFERENCES.md)

## Quick Start

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all
cargo clippy --workspace -- -D warnings
```

The Python tree is not part of the production runtime plan. Keep it only as a reference until the Rust rewrite is complete.

## Immediate Goal

Ship one vertical slice:

- synthetic telemetry in
- one Rust detector fires
- one pheromone is deposited
- one policy decision is made
- one response adapter runs in dry-run or sandbox mode
- one signed receipt chain is recorded
- latency numbers are published

## License

Apache-2.0
