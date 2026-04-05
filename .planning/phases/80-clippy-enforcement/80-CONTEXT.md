---
phase: 80-clippy-enforcement
type: context
created: "2026-04-04"
---

# Phase 80: Clippy Enforcement -- Context

## Requirement

**OPS-30**: Workspace enforces clippy `unwrap_used` and `expect_used` denial across all crates.

## User Decisions (Locked)

- Workspace `Cargo.toml` `[workspace.lints.clippy]` denies `unwrap_used` and `expect_used`
- All crate `Cargo.toml` files inherit workspace lints via `[lints] workspace = true`
- Test code may use `#[allow(clippy::unwrap_used, clippy::expect_used)]` on `#[cfg(test)]` modules since panics in tests are acceptable
- CI already runs `cargo clippy --workspace --all-targets -- -D warnings` and will pick up the stricter lints automatically

## Violation Census (measured 2026-04-04)

**Total clippy violations: 1,030**

| Category | Count | Action |
|----------|-------|--------|
| Production code | 49 | Refactor to proper error handling |
| Test code (`#[cfg(test)]`) | 981 | Add `#[allow]` to test modules |
| Total | 1,030 | |

### Production violations by file

| File | Count | Fix approach |
|------|-------|--------------|
| `evidence.rs` | 10 | `?` propagation, `ok_or_else` |
| `bin/swarmctl.rs` | 7 | `.ok_or("msg")?` for CLI arg validation |
| `review_workbench.rs` | 7 | `?` propagation |
| `investigation.rs` | 6 | `?` propagation |
| `mutation.rs` | 3 | `?` propagation |
| `operator_http.rs` | 3 | `?` propagation |
| `examples/fast_detection_bench.rs` | 2 | `#[allow]` (example code) |
| `operator_maintenance.rs` | 2 | `?` propagation |
| `service.rs` | 2 | `?` propagation |
| `canary.rs` | 1 | `?` propagation |
| `drafting.rs` | 1 | `?` propagation |
| `evolution.rs` | 1 | `?` propagation |
| `portfolio.rs` | 1 | `?` propagation |
| `promotion.rs` | 1 | `?` propagation |
| `selection.rs` | 1 | `?` propagation |
| `strategy.rs` | 1 | `?` propagation |

### Test violations by crate

| Crate | Test violations |
|-------|-----------------|
| swarm-runtime | 938 (across 20+ test modules) |
| swarm-spine | 79 |
| swarm-crypto | 33 |
| swarm-pheromone | 23 |
| swarm-policy | 4 |
| swarm-response | 2 |

### Crates with zero violations (no changes needed to source)

- swarm-core
- swarm-whisker
- swarm-bridge
- swarm-consensus
- swarm-guard

## Key Insight

The initial estimate of 1,386 violations suggested a massive refactoring effort. Analysis reveals that 95% of violations are in test code where `unwrap()` is idiomatic and acceptable. Only 49 production-code call sites need actual refactoring. The remaining work is mechanical: add `#[allow]` to `#[cfg(test)]` modules and add workspace lint inheritance to each crate's `Cargo.toml`.

## Scope

- NOT a deep error-handling rewrite (per REQUIREMENTS.md out-of-scope list)
- Production `unwrap()`/`expect()` -> proper error handling (`?`, `ok_or_else`, `unwrap_or_default`)
- Test `unwrap()`/`expect()` -> module-level `#[allow]` annotations
- Example code -> file-level `#[allow]` annotations
