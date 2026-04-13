# Phase 222 Verification

status: passed

## Result

Phase 222 verification passed.

## Commands

- `cargo fmt --all`
- `CARGO_TARGET_DIR=/tmp/sts-phase222-target cargo check -p swarm-pheromone -p swarm-runtime -p swarm-whisker -p swarm-core`
- `CARGO_TARGET_DIR=/tmp/sts-phase222-target cargo test -p swarm-pheromone deposit_ -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase222-target cargo test -p swarm-pheromone local_journal_recovers_ -- --nocapture`

## Verified Behaviors

- The shared `PheromoneDeposit` contract now compiles end-to-end with an
  explicit `schema_version` across the current runtime emitters, whisker stream
  deposits, substrate code, and signed test fixtures.
- The substrate accepts both the current deposit schema and the immediately
  previous signed schema version, preserving signature verification and identity
  binding on the compatibility path.
- Unsupported schema versions fail closed with explicit invalid-deposit errors,
  and local-journal reopen now recovers legacy deposits that omitted the new
  `schema_version` field by mapping them onto the bounded previous-version lane.
