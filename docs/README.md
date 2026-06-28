# Ambush Documentation

Architecture and product specs for **Ambush — Vector Swarm**, a cybersecurity agent-swarm
operations environment. Start with the [root README](../README.md) for the overview.

## Specs

| Doc | What it covers |
|-----|----------------|
| [PRODUCT.md](./PRODUCT.md) | Vision, personas, use cases (emergency surge, CTF, code-review swarm), concepts glossary, differentiation, non-goals, success metrics. |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System architecture: the two halves (Electron control plane + Rust engine), process model, IPC contract, event bus, domain model, subsystems, file map. |
| [SWARM-MODEL.md](./SWARM-MODEL.md) | Deep spec of swarm orchestration: Operation/Vector lifecycle, fan-out mechanics, worktree isolation, agent runtime + prompt delivery, consolidation, scaling. |
| [GOVERNANCE-SECURITY.md](./GOVERNANCE-SECURITY.md) | Dual governance (Chio-wrapped intel MCP + the engine's fail-closed policy gate), signed receipts, threat model, non-repudiation, hardening roadmap. |
| [ENGINE-INTEGRATION.md](./ENGINE-INTEGRATION.md) | How the Electron control plane and the Rust detection/response engine converge: integration surfaces, data contracts, phased plan. |
| [ROADMAP.md](./ROADMAP.md) | v0 status and the themed v0.1 → v1.0 milestone roadmap, plus the near-term task list. |

## Engine docs

The Rust detection + live-response engine carries its own docs under
[`../engine/docs/`](../engine/docs/) (architecture, configuration, DR runbook, decisions).

> These specs were authored by a team of agents reading the live codebase, so they cite
> concrete file paths and distinguish shipped behavior from planned work. Treat the code as the
> source of truth where they drift.
