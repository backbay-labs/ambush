#!/usr/bin/env node
// Governance-bypass regression smoke (from the adversarial review). Asserts the MCP gate is
// fail-closed against frames that previously slipped through ungoverned:
//   - a JSON-RPC batch ARRAY wrapping a tools/call (must be rejected, never forwarded), and
//   - a side-effecting non-tools/call method (resources/read) (must be hard-denied).
// Neither may reach the inner server; both must produce a JSON-RPC error to the agent.

import { mkdtempSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { driveGate } from './drive-gate.mjs'

function fail(msg) {
  console.error(`\x1b[31mSECURITY SMOKE FAIL:\x1b[0m ${msg}`)
  process.exit(1)
}

const vault = mkdtempSync(join(tmpdir(), 'ambush-sec-'))
mkdirSync(join(vault, 'findings'), { recursive: true })
const receiptLog = join(vault, 'receipts.jsonl')

const frames = [
  { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
  // (a) batch array wrapping a tools/call write — must NOT be forwarded ungoverned.
  [{ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'write', arguments: { path: 'x', content: 'y' } } }],
  // (b) side-effecting resources/read of a secret — must be hard-denied (deny-by-default on method).
  { jsonrpc: '2.0', id: 3, method: 'resources/read', params: { uri: 'file:///etc/shadow' } },
]

const { stdout } = await driveGate({ vault, receiptLog, frames }).catch((e) => fail(e.message))

const responses = stdout
  .split('\n')
  .filter((l) => l.trim())
  .map((l) => JSON.parse(l))

const problems = []
// The batch array must yield a JSON-RPC error and NOT an echoed tools/call result.
if (!responses.some((r) => r.error && r.error.data?.ambush_code === 'urn:ambush:gate:invalid-request')) {
  problems.push('batch array was not rejected as an invalid request')
}
// resources/read must be method-denied.
if (!responses.some((r) => r.id === 3 && r.error && r.error.data?.ambush_code === 'urn:ambush:gate:denied:method')) {
  problems.push('resources/read was not hard-denied')
}
// Neither the batch write (id 2) nor resources/read (id 3) may have a forwarded success result.
if (responses.some((r) => r.id === 2 && r.result)) problems.push('the batched write reached the inner server')
if (responses.some((r) => r.id === 3 && r.result)) problems.push('resources/read reached the inner server')

if (problems.length) fail(problems.join('; '))

console.log('\x1b[32mSECURITY SMOKE PASS\x1b[0m — batch-array + ungoverned-method bypasses are fail-closed')
