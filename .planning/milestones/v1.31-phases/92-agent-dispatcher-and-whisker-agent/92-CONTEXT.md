# Phase 92: Agent Dispatcher And WhiskerAgent

## Decisions

- The dispatcher lives in `swarm-runtime` as `src/dispatcher.rs`, not in `swarm-core` (core defines the trait, runtime owns composition)
- WhiskerAgent lives in `swarm-runtime` as `src/whisker_agent.rs` because it depends on the detection pipeline and service stack
- The dispatcher is a standalone tokio task spawned alongside the axum server in `swarm_detect.rs`
- WhiskerAgent does NOT re-implement detection logic; it wraps `detect_and_deposit()` from `detection/pipeline.rs`
- Telemetry buffering uses a bounded `tokio::sync::mpsc` channel: ingest handler sends, WhiskerAgent drains on tick
- AgentDispatcher config fields: `tick_interval_ms` (default 100), `max_agents` (default 16), `enabled` (default true)
- Agent health is folded into the existing `/healthz` response under a new `agents` key in the `components` object
- The `SwarmAgent` trait requires `ed25519_dalek::VerifyingKey` for `identity()` -- WhiskerAgent generates a random keypair at construction for now (real PKI is deferred)
- The `SwarmEnvironment` passed to `tick()` is populated with recent pheromone deposits from the substrate and the current swarm mode (hardcoded `Normal` for now -- mode transitions come in Phase 93)

## Deferred Ideas

- Pheromone-driven mode transitions (Phase 93: AGENT-03, AGENT-04, AGENT-05)
- Multi-agent coordination or consensus
- Agent persistence across restarts
- Real PKI / identity verification for agents
- SwarmAction processing (the dispatcher collects tick outputs but does not yet route them)
- Dynamic agent registration at runtime via API

## Claude's Discretion

- Internal error handling strategy within the tick loop (log + mark degraded vs panic)
- Buffer capacity for the telemetry channel (suggest 10_000 based on typical ingest volumes)
- Whether to use `tokio::time::interval` or `tokio::time::sleep` for the tick loop
- Test fixture design for WhiskerAgent unit tests
