# Ambush Agent Guide

Ambush is an Electron desktop app — **Vector Swarm**, a cybersecurity agent-swarm operations
environment. It fans one mission out into many isolated agents, governs their tool calls with
Chio receipts, and consolidates findings into an OpenKnowledge intel wiki.

## Start Here

- Read [README.md](./README.md) for the product overview and architecture.
- Stack: Electron + `electron-vite` + React 19 + Tailwind 4 + Zustand + xterm + node-pty.
- Use **Node 24+** and **pnpm**.

## Commands

```bash
pnpm install
pnpm dev          # run the app
pnpm typecheck    # tsc: node + web projects
pnpm build        # electron-vite build (main + preload + renderer)
```

Because the local pnpm enforces build-script approvals, native deps are configured in
`pnpm-workspace.yaml` (`onlyBuiltDependencies` / `ignoredBuiltDependencies`). If `pnpm run`
refuses to start due to a deps check, the underlying tools can be run directly from
`node_modules/.bin` (`tsc`, `electron-vite`).

## Architecture & boundaries

- **Process model:** `src/main` (Node/Electron) ↔ `src/preload` (contextBridge) ↔
  `src/renderer/src` (React). The renderer never touches Node APIs directly — everything goes
  through `window.ambush`, whose contract lives in `src/shared/ipc.ts`.
- **Single IPC source of truth:** add a channel to `src/shared/ipc.ts` (`IPC` map + `AmbushApi`),
  implement it in `src/main/ipc/register-ipc.ts`, and expose it in `src/preload/index.ts`.
- **Event flow:** managers publish to the in-process `bus` (`src/main/util/bus.ts`); the IPC
  layer forwards bus events to all renderer windows. Don't thread `webContents` into managers.
- **Domain types** are shared and authoritative in `src/shared/types.ts`. An Operation has
  Vectors; a Vector owns a worktree + terminal + findings path.

## External-tool integration rules

- **OpenKnowledge is GPL-3.0.** Ambush is MIT. Only ever invoke it as a **subprocess**
  (`ok` CLI / MCP / local server) via `src/main/engine/openknowledge-engine.ts`. Never import
  or vendor OpenKnowledge source into this repo, or Ambush would have to relicense.
- **Chio governance is preferred but optional.** Wrap agent-facing MCP commands through
  `ChioGovernor.wrapMcp(...)`. All external binaries (`ok`, `chio`, agent CLIs) must degrade
  gracefully when missing — detect, log to the bus, and keep the app usable.

## Conventions

- **File/module naming:** name files after what they contain (`worktree-manager.ts`,
  `pty-manager.ts`), never `utils`/`helpers`/`common`.
- **Comments:** explain *why* (a constraint or trade-off), briefly. Don't narrate the code.
- **Cross-platform:** target macOS, Linux, Windows. No hardcoded path separators; gate
  platform-specific behavior behind runtime checks. Agent profile commands already branch on
  `process.platform`.
- **Renderer types:** module files can't use the UMD `React` global — import
  `import type * as React from 'react'` where `React.*` types are referenced. The
  `window.ambush` global is declared in `src/renderer/src/types/global.d.ts`; the `<webview>`
  element in `src/renderer/src/types/webview.d.ts`.

## Before Finishing

```bash
pnpm typecheck && pnpm build
```
