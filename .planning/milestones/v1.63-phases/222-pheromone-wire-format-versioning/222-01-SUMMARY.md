# Phase 222 Plan 01 Summary

## Delivered

- Added explicit wire-version metadata to the shared pheromone deposit contract
  in `crates/swarm-core/src/pheromone.rs` through `schema_version` plus bounded
  current/previous-version helpers.
- Aligned substrate signing, verification, and hydration in
  `crates/swarm-pheromone/src/substrate.rs` on one version-aware canonical
  payload contract, including a legacy signing path for the previous schema and
  explicit fail-closed rejection for unsupported deposit versions.
- Migrated stored deposit reads in `crates/swarm-pheromone/src/jetstream.rs`
  and the local-journal reopen path so legacy payloads without
  `schema_version` still deserialize onto the bounded previous-version
  compatibility lane instead of silently bypassing validation.
- Updated current emitters and signed fixtures across the runtime, whisker
  stream, and pheromone substrate tests to emit the current schema version by
  default, so new deposits stay explicit while the compatibility path remains
  limited to current-plus-previous versions.

## Notes

- The compatibility contract is intentionally narrow: the runtime accepts only
  the current version and one immediately previous legacy shape, and unsupported
  versions now fail closed before signature verification or storage.
- Legacy migration remains scoped to deposit serialization and hydration. API
  envelope versioning and negotiation are deferred to Phase 223.
