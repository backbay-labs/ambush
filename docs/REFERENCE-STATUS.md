# Reference Status

This file marks which docs are canonical for the current Rust-first rebuild and which remain historical reference.

## Canonical Now

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/ROADMAP.md`
- `docs/decisions/0001-rust-first-runtime.md`
- `docs/VENDOR-REFERENCES.md`
- `docs/PORTING-TRACKER.md`
- `docs/ARC-UPSTREAM.md`
- `vendor/reference/README.md`

## Historical / Inspiration Only

These documents may still contain useful ideas, but they no longer define the near-term implementation target:

- `docs/AGENTS.md`
- `docs/CONFIGURATION.md`
- `docs/CONSENSUS.md`
- `docs/EVOLUTION.md`
- `docs/INTEGRATION.md`
- `docs/PHEROMONES.md`
- `docs/RESEARCH.md`
- `docs/plans/BRAINSTORM-v1.md`
- `docs/plans/BRAINSTORM-v2.md`

Legacy Python and PyO3 transition artifacts were removed from the live repo in `v1.28`:

- `kernel/`
- `pyproject.toml`
- `crates/swarm-bridge`

Historical discussion of those artifacts may still appear in older docs, but they are no longer
part of the workspace or filesystem layout.
