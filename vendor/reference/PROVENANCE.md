# Reference Provenance

Swarm Team Six is temporarily copying focused upstream source into this directory for local reference only.

These copies are present to accelerate:

- API discovery
- architectural porting
- naming and crate-shape decisions
- selective Rust reimplementation

They are not part of the compiled STS dependency graph.

## Source Snapshots

### ClawdStrike

- source path: `../clawdstrike`
- snapshot commit: `b69fb2727`
- copied areas:
  - `crates/libs/clawdstrike`
  - `crates/libs/spine`
  - `crates/libs/hush-core`

### Hellcat

- source path: `../hellcat`
- snapshot commit: `3ace7f0`
- copied areas:
  - `src/hellcat/core`
  - `src/hellcat/kernel`
  - `src/hellcat/operators`

### Cyntra Kernel

- source path: `../../platform/kernel`
- snapshot commit: `1728a019`
- copied areas:
  - `src/cyntra/core`
  - `src/cyntra/kernel`
  - `src/cyntra/trust`

## Usage Guidance

- Treat this directory as a reading room, not as product code.
- Port ideas inward into STS-owned crates with STS-owned APIs.
- Remove copied reference trees as soon as the corresponding STS-native implementation is no longer ambiguous.
