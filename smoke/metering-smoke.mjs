#!/usr/bin/env node
// Per-lane metering enforcement smoke (the cost doom-loop lever).
//
// With AMBUSH_LANE_BUDGET_REQUESTS=1, two safe `write` calls go through the gate.
// The guard pipeline would ALLOW both, but the lane budget caps governed tool
// calls at 1: the first is ALLOW (recorded), the second is DENY at the
// `lane_budget` gate — a non-fabricated, SIGNED refusal. Asserts the receipt
// log shows exactly that, with the cost metadata flipping allowed true -> false.

import { existsSync, mkdtempSync, mkdirSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { driveGate } from './drive-gate.mjs'

function fail(msg) {
  console.error(`\x1b[31mMETERING SMOKE FAIL:\x1b[0m ${msg}`)
  process.exit(1)
}

process.env.AMBUSH_LANE_BUDGET_REQUESTS = '1'

const vault = mkdtempSync(join(tmpdir(), 'ambush-meter-'))
mkdirSync(join(vault, 'findings'), { recursive: true })
const receiptLog = join(vault, 'receipts.jsonl')

const frames = [
  { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
  { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'write', arguments: { path: 'findings/a.md', content: 'x' } } },
  { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'write', arguments: { path: 'findings/b.md', content: 'y' } } },
]

await driveGate({ vault, receiptLog, frames }).catch((e) => fail(e.message))

if (!existsSync(receiptLog)) fail('no receipts.jsonl written')
const receipts = readFileSync(receiptLog, 'utf8')
  .split('\n')
  .filter((l) => l.trim())
  .map((l) => JSON.parse(l))
  .filter((r) => r.tool === 'write')

const cost = (r) => r.receipt?.receipt?.metadata?.cost?.allowed
const problems = []
if (receipts.length !== 2) problems.push(`expected 2 write receipts, got ${receipts.length}`)
if (receipts[0]?.verdict !== 'ALLOW') problems.push('first write should be ALLOW (within budget)')
if (cost(receipts[0]) !== true) problems.push('first write cost.allowed should be true')
if (receipts[1]?.verdict !== 'DENY') problems.push('second write should be DENY (over budget)')
if (cost(receipts[1]) !== false) problems.push('second write cost.allowed should be false')

if (problems.length) fail(problems.join('; '))

console.log('\x1b[32mMETERING SMOKE PASS\x1b[0m — lane budget capped governed calls: ALLOW then signed DENY')
console.log(`  write #1: ${receipts[0].verdict} (cost.allowed=${cost(receipts[0])})`)
console.log(`  write #2: ${receipts[1].verdict} (cost.allowed=${cost(receipts[1])})  [over budget]`)
