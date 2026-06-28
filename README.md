<h1 align="center">Ambush</h1>

<p align="center">
  <strong>Vector Swarm — a cybersecurity agent-swarm operations environment.</strong><br/>
  Spin up massive agentic horsepower on a dime, govern every tool call with signed receipts,
  and consolidate findings into a living intel wiki.
</p>

<p align="center">
  <em>Orca's raw parallel-agent power · OpenKnowledge's calm intel brain · Chio's fail-closed governance.</em>
</p>

---

## What is Ambush

Ambush is a desktop app for running **swarms of coding/security agents in parallel** as an
incident- or emergency-response tool. You define an **Operation** (a mission against a target),
then deploy N **Vectors** — each Vector is one attack/work lane run by an agent inside its own
isolated git worktree and live terminal. Every finding flows into a shared, git-synced
**intel vault** (powered by OpenKnowledge), and every governed tool call is signed into an
append-only **Chio receipt** log.

The point is **speed and scale of fan-out**: turn one objective into dozens of coordinated
agents in seconds, watch them work, and roll their ephemeral output into durable, searchable
knowledge.

```
Operation (mission)
   └── Vector ×N  ── isolated git worktree + live PTY + agent CLI
          │
          ├── findings/<vector>.md ──▶ OpenKnowledge intel vault (wiki + graph)
          └── tool calls ───────────▶ Chio (policy + signed receipts)
                                          │
                          Consolidate ──▶ RUNBOOK.md (kill-chain)
```

## Heritage

| Borrowed from | What Ambush takes |
|---|---|
| **[Orca](https://github.com/stablyai/orca)** (MIT) | Electron + electron-vite + React 19 + Tailwind 4 stack, parallel **worktree-per-agent** isolation, WebGL PTY terminals, "any CLI agent" model, codebase structure |
| **OpenKnowledge** (GPL-3.0) | The intel/knowledge layer: WYSIWYG markdown wiki, MCP `write`/`search`, wiki-link graph, git sync — embedded as a **subprocess engine** so Ambush stays MIT |
| **[Chio](https://github.com/backbay-labs/chio)** | Fail-closed governance: every agent tool call against the intel vault is policy-checked and signed into a receipt log |

> **License boundary:** OpenKnowledge is GPL-3.0. Ambush invokes it strictly as a
> subprocess (`ok` CLI / MCP / local server) and never imports its source, keeping
> Ambush itself MIT-licensed.

## Quickstart

Requires **Node 24+** and **pnpm**. Optional but recommended: `chio` on PATH (governance) and
`@inkeep/open-knowledge` (`npm i -g @inkeep/open-knowledge`) for the live intel wiki.

```bash
pnpm install
pnpm approve-builds       # approve electron + esbuild native builds for dev
pnpm run rebuild          # (optional) build node-pty for real TTYs
pnpm dev                  # launch the app
```

Then:

1. **Create an Operation** — name it, set the objective and target (host/URL/CTF endpoint, and
   optionally a target repo to enable git worktrees).
2. **Deploy a swarm** — pick an agent runtime and a count, hit **Deploy**. Each Vector spins up
   in its own worktree with a mission briefing and (if available) a governed intel MCP config.
3. **Watch & steer** — every Vector has a live terminal; kill, redeploy, or open its worktree.
4. **Consolidate** — roll all findings into a single linked kill-chain `RUNBOOK.md`.
5. **Audit** — the Receipts tab shows every signed allow/deny decision from Chio.

If `ok`/`chio` aren't installed, Ambush degrades gracefully: agents still run and write findings
as plain markdown; the swarm just runs ungoverned and the wiki is a folder instead of a live UI.

## Two halves: control plane + engine

Ambush is a desktop **control plane** (TypeScript/Electron) sitting on top of a Rust
**detection & live-response engine** (originally *Swarm Team Six / ClawdStrike Ambush*).

- The **control plane** orchestrates agent swarms, intel, and governance for offensive /
  emergency-response work.
- The **engine** (`engine/`) is the Rust hot path: ingest telemetry → detect (whisker) →
  pheromone state → fail-closed policy gate → capability-scoped response → signed receipt chain.

The two share a philosophy — **fan-out + fail-closed governance + signed receipts** — and will
converge: the desktop app becomes the operator surface for the engine's detections and responses.

## Repo structure

Control plane mirrors Orca's Electron layout; the engine is a self-contained Cargo workspace.

```text
ambush/
├── src/                     # Electron control plane (TypeScript, MIT)
│   ├── main/                Electron main process
│   │   ├── swarm/           worktree manager, orchestrator, mission briefings
│   │   ├── terminal/        node-pty manager (+ piped fallback)
│   │   ├── engine/          OpenKnowledge subprocess engine
│   │   ├── governance/      Chio governor (policy + receipts)
│   │   ├── ipc/             IPC registration
│   │   └── util/            event bus, process helpers
│   ├── preload/             contextBridge → window.ambush
│   ├── shared/              domain types, IPC contract, agent profiles
│   └── renderer/src/        React UI (swarm, intel, receipts)
├── engine/                  # Rust detection + live-response engine (Apache-2.0)
│   ├── crates/              swarm-core, swarm-whisker, swarm-pheromone, swarm-policy,
│   │                        swarm-response, swarm-runtime, swarm-spine, swarm-crypto, …
│   ├── rulesets/  docs/  scenarios/  fixtures/
│   └── Cargo.toml
├── docs/                    # architecture specs (agent-authored)
└── electron.vite.config.ts
```

### Building the engine

```bash
cd engine
cargo check --workspace
cargo test --workspace
```

## Commands

```bash
pnpm dev          # run the app (electron-vite dev)
pnpm build        # bundle main + preload + renderer
pnpm typecheck    # tsc for node + web projects
pnpm rebuild      # rebuild node-pty against Electron
```

## Status

v0 — runnable. The swarm mechanism (worktree fan-out, PTY terminals, mission briefing,
findings consolidation), the OpenKnowledge engine embedding, and the Chio governance wrapper
are wired end-to-end with graceful degradation when external binaries are absent.

## License

The control plane (`src/`) is **MIT** (see [LICENSE](./LICENSE)). The Rust engine under
`engine/` originates from Swarm Team Six and is **Apache-2.0** (see `engine/README.md`). Both are
permissive and compatible.
