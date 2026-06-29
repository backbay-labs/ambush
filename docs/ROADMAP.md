# Ambush Roadmap — Vector Swarm

> Status: **v0 (runnable)** · Last updated: 2026-06-28
>
> Ambush is a cybersecurity agent-swarm operations desktop app. One mission (an
> **Operation**) fans out into many parallel agents (**Vectors**), each running in an
> isolated git worktree with a live terminal, reporting into an embedded
> **OpenKnowledge** intel vault, governed by **Chio** signed receipts. A separate Rust
> detection + live-response **engine** (`engine/`, from *Ambush Engine*) is present in-repo but **not yet wired** to the desktop control plane.

This document tracks where Ambush is today and where it's going. It is grounded in the
current code state — see the cross-referenced specs for deeper design detail.

---

## 1. Current status (v0)

The control plane (TypeScript/Electron, MIT) is wired end-to-end with graceful
degradation when external binaries are missing. Everything below reflects what the code
actually does today.

### What works

- **Swarm fan-out.** `SwarmOrchestrator.deploySwarm()` creates up to **100** Vectors per
  deploy and launches all lanes concurrently (`void this.launchVector(...)`), because
  speed of fan-out is the core value. Lanes that aren't given explicit objectives are
  auto-named from a built-in offensive/IR playbook (recon → triage → exploit → lateral →
  persist → harden → report).
- **Worktree isolation.** `WorktreeManager` gives each Vector its own `git worktree` +
  branch off `HEAD` when the target is a git repo. When the target is not a repo (CTF
  endpoint, host, empty dir), it falls back to a plain per-vector scratch directory so the
  mechanism still works everywhere. Worktrees live under `<target>/.ambush/worktrees/`.
- **PTY terminals + fallback.** `PtyManager` spawns real TTYs via `node-pty` (so TUI
  agents render correctly) and **falls back to piped child processes** if `node-pty` isn't
  rebuilt against Electron. Terminal data/exit are streamed over the bus to the renderer;
  exit codes feed back into Vector status (`done` on 0, `failed` otherwise).
- **"Any CLI agent" model.** Six built-in agent profiles (Claude Code, Codex, Cursor
  Agent, OpenCode, Hermes, and an always-available `shell`). Prompt delivery adapts per
  runtime: appended as an `arg`, typed into the PTY over `stdin` (auto-Enter), or left in
  `AMBUSH_MISSION.md` for the agent/operator to read.
- **OpenKnowledge engine embedding.** `OpenKnowledgeEngine` resolves a local `ok` binary,
  else `npx -y @inkeep/open-knowledge@latest`. It idempotently `init`s the intel vault,
  can `start` the web UI (default port `39847`, URL parsed from stdout), and exposes an
  MCP command (`ok mcp`) for agents — **strictly as a subprocess**, never importing GPL
  source, keeping Ambush MIT.
- **Chio governance wrap.** `ChioGovernor` writes a fail-closed HushSpec policy (allow the
  intel tools + read-only inspection, deny `delete`) and wraps the OpenKnowledge MCP
  command so every governed tool call is policy-checked and signed into an append-only
  `receipts.db`. The Receipts view lists normalized verdicts (`ALLOW`/`DENY`/…) parsed
  from `chio receipt list --json`.
- **Consolidation.** `consolidate()` rolls every Vector's `findings/<id>.md` into a single
  linked kill-chain `RUNBOOK.md` (wiki-link references, per-vector status marks).
- **Operation lifecycle & persistence.** Create / deploy / scale / kill / redeploy /
  recall-all, plus persistence to `operations/current.json`. On reload, stale `running`/
  `deploying` Vectors are reset to `idle` (terminals don't survive a process restart).

### Known limitations & graceful-degradation behaviors

- **No `ok` installed →** agents still run; findings are written as plain markdown and the
  "vault" is just a folder. No live wiki UI, no MCP intel tools.
- **No `chio` installed →** the swarm runs **ungoverned**; `wrapMcp()` returns the inner
  command unchanged and no receipts are produced.
- **No `node-pty` →** piped fallback only: no real TTY, `resize` is a no-op, and TUI agents
  may render poorly.
- **Engine is not wired.** The Rust `engine/` detection + live-response runtime is in-repo
  but has **no IPC channel, no UI surface, and no control-plane integration**. The two
  halves share a philosophy (fan-out + fail-closed + signed receipts) but do not yet talk.
- **Engine UI URL is optimistic.** If the port isn't parsed from stdout, the status falls
  back to assuming `http://127.0.0.1:39847` even though the server may not be up there.
- **Single active operation.** Only one Operation is held in memory / persisted at a time;
  there's no operation history, archive browser, or multi-op switching.
- **Findings ingestion is filesystem-trusting.** Consolidation reads whatever is on disk;
  there's no validation, dedup, or graph-aware merge beyond simple concatenation.
- **No merge-the-winner.** Worktrees are created and can be opened, but there's no in-app
  diff review or path to merge a winning Vector's branch back to the target.
- **Receipts are read-only & non-streaming.** Receipts are pulled on demand via CLI; there
  is no live receipt stream, filtering, or audit export.

---

## 2. Milestone roadmap (v0.1 → v1.0)

Milestones are themed, not strictly date-bound. Each lists a **goal**, **key
deliverables**, and **dependencies/sequencing**. Themes intentionally overlap; the
sequencing notes call out hard prerequisites.

### v0.1 — Harden the swarm core *(theme: a)*

**Goal:** make the existing fan-out reliable, observable, and safe to scale before adding
surface area.

**Key deliverables**
- Robust lifecycle: cleanup of worktrees/branches on kill/recall (wire up the existing
  `WorktreeManager.remove()`), reconcile orphaned worktrees on startup.
- Concurrency guardrails: deploy backpressure / batching so 100 concurrent spawns don't
  thrash the host; per-Vector resource hints.
- Status fidelity: surface the `reporting` status, detect findings during a run (not just
  on exit), and distinguish "exited clean, no findings" from "failed".
- Error visibility: structured error surfacing for spawn failures (exit 127), missing
  agent binaries, and worktree-add failures.
- Persisted operation history (multiple operations, archive/restore).

**Dependencies/sequencing:** foundational — most later themes assume a stable core. No
hard external prerequisites.

### v0.2 — In-app intel editor & the GPL boundary *(theme: b)*

**Goal:** give operators a first-class intel surface without compromising the MIT license.

**Key deliverables**
- Decide and document the **OpenKnowledge GPL boundary**: keep it as a subprocess
  (embed the `ok` web UI via `<webview>`, drive MCP/CLI) **vs.** vendoring (which would
  force Ambush to relicense). Default recommendation: **stay subprocess**, embed the
  running web UI and add a thin native intel panel that talks to `ok` over CLI/MCP only.
- Embed the OpenKnowledge web UI (`EngineStatus.url`) in a dedicated Intel tab with
  health/launch controls.
- Native read surfaces (search results, wiki-link graph, finding preview) sourced via the
  governed MCP — never by importing GPL code.
- Harden engine startup: replace the optimistic port assumption with real readiness
  detection.

**Dependencies/sequencing:** depends on v0.1 status fidelity. The GPL decision gates how
much intel UI can be native; resolve it first. See `GOVERNANCE-SECURITY.md` for the
license rationale.

### v0.3 — Orca-parity operator features *(theme: c)*

**Goal:** bring the proven Orca workflow ergonomics to the swarm.

**Key deliverables**
- **Quick-open** across Vectors, worktrees, findings, and intel.
- **Annotate-diff review**: per-Vector branch diff viewer with inline annotations.
- **Merge-the-winner**: select a winning Vector and merge its branch back to the target
  (with conflict surfacing), closing the worktree lifecycle loop.
- **SSH worktrees**: run Vectors against remote hosts/worktrees over SSH.
- Mobile companion (stretch) for watch/steer on the go.

**Dependencies/sequencing:** merge-the-winner depends on v0.1 worktree cleanup and v0.2
diff/review primitives. SSH worktrees depend on the hardened spawn path.

### v0.4 — Engine integration *(theme: d)*

**Goal:** converge the two halves so the desktop app becomes the operator surface for the
Rust engine's detections and responses. Stage it from subprocess to live service.

**Key deliverables**
- **Stage 1 — subprocess CLI:** invoke the engine like the OpenKnowledge engine (resolve a
  binary, run detect-only against fixtures/telemetry, parse receipts). Add an
  `EngineRuntime`-style manager mirroring `OpenKnowledgeEngine`.
- **Stage 2 — live service:** long-running engine process streaming detections /
  pheromone state / response receipts over the bus to the renderer.
- **Stage 3 — unified operator surface:** detections and live-response actions appear
  alongside swarm Vectors and intel; engine receipts merge into the same audit view.
- New IPC channels in `src/shared/ipc.ts` + registration in `register-ipc.ts` (per the
  single-IPC-source-of-truth rule), and graceful degradation when the engine binary is
  absent.

**Dependencies/sequencing:** depends on v0.5 governance depth for a shared receipt model,
and on v0.1 for bus/IPC stability. Detailed staging lives in **`ENGINE-INTEGRATION.md`**.

### v0.5 — Governance depth *(theme: e)*

**Goal:** make Chio governance richer and auditable, spanning both halves.

**Key deliverables**
- Richer policies: per-Vector / per-operation policy profiles beyond the single default
  HushSpec; editable in-app.
- **Streaming receipts**: live receipt feed (not on-demand polling) with verdict filtering
  and search.
- **Audit export**: signed, portable audit bundles (e.g. JSONL + policy hash) for an entire
  Operation, including engine-side receipts once v0.4 lands.
- Receipt verification UI (chain integrity, policy-hash provenance).

**Dependencies/sequencing:** builds on the existing `ChioGovernor`; the unified receipt
model is a prerequisite for v0.4 Stage 3. See `GOVERNANCE-SECURITY.md`.

### v1.0 — Packaging & distribution *(theme: f)*

**Goal:** ship a signed, auto-updating desktop product.

**Key deliverables**
- `electron-builder` packaging for macOS / Linux / Windows (the engine ships as a bundled
  or separately-installed binary, respecting the Apache-2.0 / GPL-3.0 / MIT boundaries).
- Code signing & notarization.
- Auto-update channel.
- First-run experience: detect/guide install of `ok`, `chio`, and agent CLIs; bundle
  `node-pty` rebuild.
- Hardened defaults and a security/permissions review before GA.

**Dependencies/sequencing:** last — assumes the core, intel, engine, and governance work
are stable. Distribution must finalize the license/packaging story for all three halves.

---

## 3. Near-term: next 5 tasks

1. **Wire worktree cleanup** into kill / recall / redeploy (call the existing
   `WorktreeManager.remove()`), and reconcile orphaned worktrees on startup.
2. **Fix engine readiness detection** — stop optimistically assuming `:39847` is up; only
   mark `running` once the URL is confirmed reachable.
3. **Add operation history/persistence** so more than one Operation can exist (archive +
   reopen), instead of a single `current.json`.
4. **Surface `reporting` + live findings detection** during a run, not just `hasFindings`
   on terminal exit.
5. **Draft `ENGINE-INTEGRATION.md` Stage 1** — define the subprocess CLI contract and IPC
   channels to invoke the Rust engine in detect-only mode against fixtures.

---

## 4. Related docs

These specs are authored alongside this roadmap in `docs/`:

- **`ARCHITECTURE.md`** — process model (main ↔ preload ↔ renderer), the bus/IPC event
  flow, and module boundaries.
- **`PRODUCT.md`** — the product vision, personas, and the Operation → Vector → intel →
  consolidate workflow.
- **`SWARM-MODEL.md`** — the Operation/Vector domain model, worktree isolation, agent
  profiles, and fan-out semantics.
- **`GOVERNANCE-SECURITY.md`** — Chio policy model, signed receipts, the OpenKnowledge
  GPL/MIT license boundary, and the threat model.
- **`ENGINE-INTEGRATION.md`** — the staged plan (subprocess CLI → live service → unified
  operator surface) for wiring the Rust `engine/` runtime into the control plane.

Engine-internal specs live under `engine/docs/` (e.g. `engine/docs/ARCHITECTURE.md`,
`engine/docs/ROADMAP.md`, `engine/docs/INTEGRATION.md`).
