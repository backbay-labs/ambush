# Vendor References

STS currently keeps a temporary local copy of selected upstream code in `vendor/reference/`.

These copies exist for:

- inspiration
- porting reference
- interface comparison
- staged local refactoring

They do **not** act as runtime dependencies.

## Source Provenance

- ClawdStrike: `../clawdstrike` at `b69fb2727ff4aa32fbbe6485581336baed011ce9`
- Hellcat: `../hellcat` at `3ace7f0f65328c4470fa30d958c77f824134dfb7`
- Cyntra kernel: `../../platform/kernel` at `1728a019258cccf2e7d4c8a5a318890802a08949`

## Copied Areas

### ClawdStrike

- `crates/libs/clawdstrike`
- `crates/libs/spine`
- `crates/libs/hush-core`
- `crates/services/clawdstrike-brokerd`
- `crates/bridges/tetragon-bridge`
- `crates/bridges/hubble-bridge`

Used for guard rules, receipt/spine ideas, signing, capability models, and telemetry bridge patterns.

### Hellcat

- `src/hellcat/core`
- `src/hellcat/operators`
- `src/hellcat/offensive`
- `src/hellcat/eval`
- `src/hellcat/kernel`

Used for offensive decomposition, replay/eval patterns, and operator structuring ideas.

### Cyntra

- `src/cyntra/core`
- `src/cyntra/kernel`
- `src/cyntra/trust`
- `src/cyntra/cognition`

Used for scheduling, dispatcher, verifier, workcell, and memory concepts.

## Rules

1. Do not import from `vendor/reference/` as a build dependency.
2. If a concept is promoted into STS proper, rewrite it in local crates and local terminology.
3. Preserve provenance when lifting ideas or code into active crates.
