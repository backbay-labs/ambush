// Shared helper: drive the real swarm-mcp-gate binary with a deterministic
// JSON-RPC client + the offline stub inner server, and resolve once the gate
// exits. Used by both `pnpm smoke` (gate-emission) and `pnpm e2e` (full bundle).

import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..')

export function resolveGate() {
  for (const rel of ['engine/target/release/swarm-mcp-gate', 'engine/target/debug/swarm-mcp-gate']) {
    const p = join(repoRoot, rel)
    if (existsSync(p)) return p
  }
  return null
}

/** The canonical one-ALLOW + one-DENY frame sequence the bundle needs. */
export const ALLOW_DENY_FRAMES = [
  { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
  // ALLOW: a safe write -> forwarded to the stub inner server.
  {
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'write', arguments: { path: 'findings/recon.md', content: '# recon\nsafe finding' } },
  },
  // DENY: a destructive exec -> blocked by the shell_command guard, never forwarded.
  {
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'exec', arguments: { command: 'rm -rf /' } },
  },
]

/** Spawn the gate over the stub inner server, write `frames`, return { stdout } on exit. */
export function driveGate({ vault, receiptLog, frames, vectorId = 'vec-smoke' }) {
  const gate = resolveGate()
  if (!gate) throw new Error('swarm-mcp-gate not built — run: cargo build -p swarm-mcp-gate')
  return new Promise((resolve, reject) => {
    const child = spawn(
      gate,
      ['--server-id', 'open-knowledge', '--vault', vault, '--', process.execPath, join(here, 'stub-inner-mcp.mjs')],
      {
        stdio: ['pipe', 'pipe', 'inherit'],
        env: {
          ...process.env,
          SWARM_GOVERNOR_KEY: 'ambush-smoke-key',
          AMBUSH_RECEIPT_LOG: receiptLog,
          AMBUSH_VAULT: vault,
          AMBUSH_VECTOR_ID: vectorId,
        },
      },
    )
    let stdout = ''
    child.stdout.on('data', (d) => {
      stdout += d.toString()
    })
    child.on('error', reject)
    child.on('close', () => resolve({ stdout }))
    for (const frame of frames) child.stdin.write(`${JSON.stringify(frame)}\n`)
    child.stdin.end()
  })
}
