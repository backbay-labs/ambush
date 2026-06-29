#!/usr/bin/env node
// Headless gate-emission smoke — the Wave-1 regression spine (NOT a product demo).
//
// Closes the "receipt-emission void": today nothing drives the governed MCP gate,
// so the attestation bundle is degenerate (ALLOW/DENY coverage `excluded`). This
// drives the REAL swarm-mcp-gate binary (via drive-gate.mjs) and asserts both
// signed verdicts the bundle needs land in `receipts.jsonl`:
//   - an ALLOW receipt for a safe `write` (forwarded to the inner server), and
//   - a DENY receipt for `exec rm -rf /` (blocked by shell_command, never forwarded).
// It also seeds a non-empty findings file (the other half of the void).
//
// Honest scope: real SIGNED receipts over SYNTHETIC actions through the real gate,
// on the evaluate_metered rails. The falsifiable plumbing gate, not real findings.
// `pnpm e2e` goes further: it builds + verifies the full attestation bundle.

import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { ALLOW_DENY_FRAMES, driveGate } from './drive-gate.mjs'

function fail(msg) {
  console.error(`\x1b[31mSMOKE FAIL:\x1b[0m ${msg}`)
  process.exit(1)
}

const vault = mkdtempSync(join(tmpdir(), 'ambush-smoke-'))
const receiptLog = join(vault, 'receipts.jsonl')
const findingsPath = join(vault, 'findings', 'recon.md')

// Half 1 — seed a non-empty findings file (stands in for a non-interactive lane).
mkdirSync(dirname(findingsPath), { recursive: true })
writeFileSync(findingsPath, '# recon\n\nOpen port 8080 (http) on the target; [[triage]] should rank it.\n')

const { stdout } = await driveGate({ vault, receiptLog, frames: ALLOW_DENY_FRAMES }).catch((e) => fail(e.message))

// Half 2 — assert the receipt log holds both signed verdicts the bundle requires.
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
if (/"id":3[^}]*"result"/.test(stdout)) problems.push('the denied exec frame leaked to the inner server')
if (readFileSync(findingsPath, 'utf8').trim().length === 0) problems.push('findings file is empty')

if (problems.length) fail(problems.join('; '))

console.log('\x1b[32mSMOKE PASS\x1b[0m — gate emitted both signed verdicts + findings seeded')
console.log(`  receipts: ${receipts.length}  (ALLOW write, DENY exec/${deny.guard})`)
console.log(`  allow signed: ${signed(allow)}   deny signed: ${signed(deny)}`)
