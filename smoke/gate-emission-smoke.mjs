#!/usr/bin/env node
// Headless gate-emission smoke — the Wave-1 regression spine (NOT a product demo).
//
// Closes the "receipt-emission void": today nothing drives the governed MCP gate,
// so the attestation bundle is degenerate (ALLOW/DENY coverage `excluded`). This
// drives the REAL swarm-mcp-gate binary with a deterministic JSON-RPC client and
// an offline stub inner server, and asserts that exactly the two signed verdicts
// the bundle needs land in `receipts.jsonl`:
//   - an ALLOW receipt for a safe `write` (forwarded to the inner server), and
//   - a DENY receipt for `exec rm -rf /` (blocked by the shell_command guard).
// It also seeds a non-empty findings file (the other half of the void), so the
// bundle this feeds will show findings-present + allow:covered + deny:covered.
//
// Honest scope: these are real SIGNED receipts over SYNTHETIC actions through the
// real gate, on the evaluate_metered rails. It is the falsifiable plumbing gate,
// not proof the swarm produced real findings.

import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..')

function resolveGate() {
  for (const rel of ['engine/target/release/swarm-mcp-gate', 'engine/target/debug/swarm-mcp-gate']) {
    const p = join(repoRoot, rel)
    if (existsSync(p)) return p
  }
  return null
}

function fail(msg) {
  console.error(`\x1b[31mSMOKE FAIL:\x1b[0m ${msg}`)
  process.exit(1)
}

const gate = resolveGate()
if (!gate) fail('swarm-mcp-gate not built — run: cargo build -p swarm-mcp-gate')

// Per-run temp vault so the smoke is hermetic and repeatable.
const vault = mkdtempSync(join(tmpdir(), 'ambush-smoke-'))
const receiptLog = join(vault, 'receipts.jsonl')
const findingsPath = join(vault, 'findings', 'recon.md')

// Half 1 — seed a non-empty findings file (stands in for a non-interactive lane).
mkdirSync(dirname(findingsPath), { recursive: true })
writeFileSync(
  findingsPath,
  '# recon\n\nOpen port 8080 (http) on the target; [[triage]] should rank it.\n',
)

// The frames the deterministic MCP client drives into the gate.
const frames = [
  { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
  // ALLOW: a safe write under the vault -> forwarded to the stub inner server.
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
      AMBUSH_VECTOR_ID: 'vec-smoke',
    },
  },
)

let stdout = ''
child.stdout.on('data', (d) => {
  stdout += d.toString()
})

child.on('close', () => {
  // Assert the receipt log holds both signed verdicts the bundle requires.
  if (!existsSync(receiptLog)) fail('no receipts.jsonl was written by the gate')
  const receipts = readFileSync(receiptLog, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l))

  const signed = (r) => Boolean(r.receipt?.signatures?.signer)
  const allow = receipts.find((r) => r.tool === 'write' && r.verdict === 'ALLOW')
  const deny = receipts.find((r) => r.tool === 'exec' && r.verdict === 'DENY')

  const problems = []
  if (!allow) problems.push('missing ALLOW receipt for `write`')
  else if (!signed(allow)) problems.push('ALLOW receipt is not signed')
  if (!deny) problems.push('missing DENY receipt for `exec`')
  else if (!signed(deny)) problems.push('DENY receipt is not signed')
  else if (deny.guard !== 'shell_command') problems.push(`DENY guard was ${deny.guard}, expected shell_command`)
  // The DENY must NOT have been forwarded to the inner server (id 3 has no result echo).
  if (/"id":\s*3[,}]/.test(stdout) && /"result"/.test(stdout.split('"id":3')[1] ?? '')) {
    problems.push('the denied exec frame leaked to the inner server')
  }
  // Half 1 assertion: findings are non-empty.
  if (readFileSync(findingsPath, 'utf8').trim().length === 0) problems.push('findings file is empty')

  if (problems.length) fail(problems.join('; '))

  console.log('\x1b[32mSMOKE PASS\x1b[0m — gate emitted both signed verdicts + findings seeded')
  console.log(`  receipts: ${receipts.length}  (ALLOW write, DENY exec/${deny.guard})`)
  console.log(`  allow signed: ${signed(allow)}   deny signed: ${signed(deny)}`)
  console.log(`  findings: ${findingsPath}`)
  process.exit(0)
})

for (const frame of frames) child.stdin.write(`${JSON.stringify(frame)}\n`)
child.stdin.end()
