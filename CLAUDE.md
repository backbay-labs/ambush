# CLAUDE.md

## Project Overview

Swarm Team Six (codename) is an autonomous, self-evolving threat hunting swarm. Product name: **ClawdStrike Ambush**. Community name: **The Clowder**.

**Design philosophy:** Fail-closed. Classical swarm mechanics for coordination (fast), LLMs for reasoning (smart). The swarm is a diverse sensor array that makes the existing verified enforcement engine smarter.

## Architecture

Hybrid Rust/Python monorepo:
- `crates/` — Rust data plane (hot path: detection, pheromones, crypto, consensus wire protocol)
- `kernel/` — Python control plane (warm path: scheduling, dispatching, LLM-backed agents, evolution)
- `swarm-bridge` crate (PyO3) connects them in-process

Three foundational systems vendored/adapted:
- **ClawdStrike** → `swarm-guard`, `swarm-spine`, `swarm-crypto` (policy enforcement, transport, crypto)
- **Cyntra** → `kernel/scheduler`, `kernel/dispatcher`, `kernel/memory` (orchestration patterns)
- **Hellcat** → `kernel/red_swarm` (adversarial pressure, co-evolutionary arms race)

## Agent Archetypes

| Agent | Language | Role |
|-------|----------|------|
| Whisker | Rust | Streaming detection (no LLM, microsecond budget) |
| Stalker | Python | LLM-powered investigation |
| Weaver | Python | Multi-graph correlation |
| Pouncer | Python | Response execution (requires BFT consensus) |
| Tom | Python | Governance, policy, consensus committee |
| Kitten | Python | Strategy evolution (GA + Z3 gate) |
| Sphinx | Python | Long-term threat memory |
| Calico | Python | Deception infrastructure |

## Commands

```bash
# Build Rust crates
cargo build --workspace

# Test Rust crates
cargo test --workspace

# Lint
cargo fmt --all
cargo clippy --workspace -- -D warnings

# Python
uv sync
pytest kernel/
ruff check kernel/
mypy kernel/

# Build PyO3 bridge
maturin develop
```

## Conventions

- Commit messages: Conventional Commits (`feat(whisker):`, `fix(consensus):`, etc.)
- Clippy: `-D warnings`
- Rust edition: 2024
- Python: 3.12+, strict mypy, ruff
- All swarm actions produce Ed25519-signed receipts
- Response actions require BFT consensus (2f+1)
- Evolved strategies require Z3 verification before deployment
