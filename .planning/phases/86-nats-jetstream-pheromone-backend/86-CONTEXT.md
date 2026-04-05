# Phase 86 Context: NATS JetStream Pheromone Backend

## Decisions

- **JetStream KV bucket** for deposit storage (key: deposit UUID, value: serialized PheromoneDeposit JSON). KV is the right abstraction because deposits are point-in-time records retrieved by ID or scanned by prefix, not a pub/sub stream.
- **async-nats** crate with `jetstream` feature enabled as workspace dependency. This is the canonical Rust NATS client.
- **Feature-gated** behind `nats` cargo feature on swarm-pheromone so the crate compiles without NATS when not needed.
- **Config variant** `JetStream { url: String }` added to `PheromoneBackendConfig` enum, selected via `pheromone.backend.kind: jetstream` in YAML config.
- **Bucket naming**: `swarm-pheromone-deposits` with TTL disabled (GC is application-managed via `gc_evaporated`).
- **Key format**: `{threat_class}.{timestamp_ms}.{agent_id_hash_prefix}` to enable prefix-scanned concentration queries without loading all keys.
- **GC strategy**: `gc_evaporated` scans keys, deserializes, checks `is_evaporated`, and issues KV deletes for expired entries. This is acceptable for single-digit-thousands deposit volumes per GC cycle.
- **Integration tests** use `testcontainers` or a `#[ignore]` guard with `NATS_URL` env var to avoid requiring a running NATS server in normal CI.

## Deferred Ideas

- Watch-based real-time deposit notification (Phase 87 will use this for multi-instance coordination)
- NATS cluster HA configuration
- Bucket replication factor tuning
- Subject-based stream alternative (KV is simpler for this phase)

## Claude's Discretion

- Error mapping from async-nats error types to SubstrateError variants
- Whether to add a `NatsJetStream` variant to SubstrateError or reuse string-based errors
- Internal caching strategy (if any) for hot concentration queries
- Exact testcontainers vs env-var-gated test approach
