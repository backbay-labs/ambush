# Phase 223 Plan 01 Summary

## Delivered

- Added an explicit shared operator-facing schema contract in
  `crates/swarm-runtime/src/control.rs` so `ControlEnvelope<T>` now carries
  `schema_version`, ships a centralized current-version constant, and routes
  every repo-owned control response through one `ControlEnvelope::new(...)`
  constructor instead of ad hoc envelope assembly.
- Extended the platform API envelope in
  `crates/swarm-runtime/src/ingest/platform_api.rs` so findings, incidents,
  asset posture, and runtime status responses all emit the same top-level
  `schema_version` metadata and share one bounded
  `x-swarm-schema-version` negotiation path.
- Added authenticated operator-surface negotiation in
  `crates/swarm-runtime/src/http/core.inc` so unsupported requested schema
  versions fail closed with `400 Bad Request` before handler execution instead
  of silently drifting response shape.
- Updated `crates/swarm-cli/src/core.inc` so repo-owned `swarmctl` control
  outputs validate `--output-schema-version`, retain the current compatibility
  lane at schema version `1`, and reject unsupported versions before rendering.
- Documented the shipped negotiation contract in `docs/CONFIGURATION.md`,
  including the shared `X-Swarm-Schema-Version` request header and the
  `schema_version` field now present on the operator and platform JSON
  envelopes.

## Notes

- The compatibility lane is intentionally narrow: the current runtime and CLI
  support only schema version `1`, and the new negotiation seam exists to make
  future breaking response changes explicit instead of silently additive.
- This phase versions the shipped operator-control and platform-runtime/status
  surfaces only. It does not introduce generated OpenAPI artifacts or a
  multi-version SDK layer.
