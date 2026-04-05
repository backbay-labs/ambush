# Phase 74: CI Pipeline And Quality Gates -- Context

## What This Phase Does

Create a GitHub Actions CI workflow and a cargo-deny configuration so every push and pull request to main is automatically checked for formatting, lint, build, and test correctness, and the dependency tree is governed for license compliance and known vulnerabilities.

## Why It Matters

The project has 10 workspace crates, 20+ external dependencies, and no CI. Developers currently rely on manual `cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace` before committing. A CI pipeline catches regressions automatically and prevents merge of non-compliant code. Dependency governance via cargo-deny prevents unapproved licenses and known-vulnerable crates from entering the tree silently.

## Decisions

- **One CI workflow file** -- a single `.github/workflows/ci.yml` with one job is sufficient; no matrix or multi-job complexity
- **Use stable Rust toolchain** -- pin to `stable` in the workflow; the project has no nightly features
- **Install cargo-deny in CI** -- use `cargo install cargo-deny --locked` or the `EmbarkStudios/cargo-deny-action` GitHub Action
- **License allowlist**: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Unicode-DFS-2016, Zlib, 0BSD, Unlicense -- covers all common permissive licenses used by Rust ecosystem crates
- **Advisory-db source**: Use the default RustSec advisory database for vulnerability scanning
- **No deny.toml bans section initially** -- start with licenses and advisories; crate bans can be added later if needed
- **Trigger on push to main AND pull_request to main** -- standard GitHub Actions pattern
- **cargo-deny checks both `licenses` and `advisories`** -- the two CI-02 requirements

## Workspace Shape

```
Cargo.toml (workspace root)
crates/
  swarm-core/
  swarm-whisker/
  swarm-pheromone/
  swarm-policy/
  swarm-response/
  swarm-runtime/
  swarm-consensus/
  swarm-spine/
  swarm-guard/
  swarm-crypto/
```

10 members in `[workspace].members`. `swarm-bridge` exists on disk but is NOT in the workspace.

## External Dependencies

From workspace Cargo.toml:
- tokio, async-trait, axum, tower (async runtime)
- serde, serde_json, serde_yaml (serialization)
- ed25519-dalek, sha2 (crypto)
- async-nats (messaging)
- tracing, tracing-subscriber (logging)
- thiserror, anyhow (errors)
- proptest (testing)
- hex, ryu, rand_core (added in Phase 71)

All of these use MIT or Apache-2.0 or both. The allowlist should cover the full transitive tree.

## Artifact Locations

| File | Purpose |
|---|---|
| `.github/workflows/ci.yml` | GitHub Actions workflow definition |
| `deny.toml` | cargo-deny configuration at workspace root |
