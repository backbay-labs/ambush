# Phase 97: CloudTrail And Generic Json Bridges

## Vision

The shared bridge contract becomes useful beyond Tetragon. This phase adds JSON-oriented bridge implementations that normalize CloudTrail records and arbitrary JSON documents into the shared telemetry schema, while introducing reusable config shapes that the runtime registry can consume in the next phase without reworking the bridge APIs.

## Decisions

- A dedicated JSON ingest crate will own both `CloudTrailBridge` and `GenericJsonBridge` because both operate on pulled JSON documents, share record-source helpers, and need the same config-driven mapping utilities
- Bridge config shapes will live in `swarm-core::config` so repository-owned YAML can describe bridge mappings before runtime orchestration lands in phase 98
- Existing `TelemetrySourceConfig` remains backward compatible for current runtime tests by keeping `subject` but gaining an optional bridge config block for JSON-oriented bridges
- `GenericJsonBridge` will use JSON Pointer paths for field extraction so mappings can be loaded from config and evaluated without custom parser code or recompilation
- Both bridges fail closed on malformed input, missing required fields, or invalid normalized payloads; phase 98 will focus on orchestration, not input-shape correctness

## Deferred Ideas

- Live AWS API polling, SQS/S3 delivery, or file-watch based bridge adapters
- Bridge worker scheduling, retry loops, and background tasks in the runtime
- Operator-visible bridge metrics and health aggregation
- Tetragon config migration into the runtime bridge registry

## Claude's Discretion

- Exact crate name for JSON-oriented bridge implementations
- Whether bridge constructors accept in-memory record queues, file-backed sources, or both so long as the phase proves reusable constructors and config shapes
- Exact CloudTrail record heuristics for choosing `AuthenticationEvent` versus `NetworkConnect`
- Exact `FieldMappingConfig` enum structure so long as payload variant selection is config-driven and validated fail closed
