#!/usr/bin/env tsx
// Full end-to-end Wave-1 smoke (run via tsx): the genuine "close the void" proof.
//
//   create vault + seed findings
//   -> drive the REAL swarm-mcp-gate -> receipts.jsonl (ALLOW + DENY)
//   -> AttestationManager.exportBundle (the REAL producer)  [tests the real TS code]
//   -> assert manifest: findings-present verified, allow:covered, denial:covered
//   -> AttestationManager.verifyBundle (shells the REAL Rust ambush-verify) -> ok
//
// Unlike `pnpm smoke` (which stops at receipts.jsonl), this exercises the real
// attestation producer + verifier, so the bundle is non-degenerate and the
// TS<->Rust byte-compat is regression-guarded. Honest scope: signed receipts over
// SYNTHETIC actions; it certifies the orchestration + attestation chain, not real
// findings. AttestationManager imports only node builtins + type-only @shared, so
// tsx loads it with no electron/alias runtime resolution.

import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Operation, ReceiptSummary } from '../src/shared/types'
import { AttestationManager } from '../src/main/governance/attestation'
import { ALLOW_DENY_FRAMES, driveGate } from './drive-gate.mjs'

/** Map the gate's receipt-log envelope to the minimal ReceiptSummary exportBundle needs. */
function toSummaries(jsonl: string): ReceiptSummary[] {
  return jsonl
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .map((o) => ({
      id: String(o.id ?? ''),
      verdict: (o.verdict === 'ALLOW' ? 'ALLOW' : 'DENY') as ReceiptSummary['verdict'],
      tool: String(o.tool ?? ''),
      server: String(o.server ?? 'open-knowledge'),
      policyHash: typeof o.policy_hash === 'string' ? o.policy_hash : null,
      timestamp: typeof o.timestamp === 'string' ? Date.parse(o.timestamp) || null : null,
      source: 'intel-mcp',
      raw: o,
    }))
}

async function main(): Promise<void> {
  const opsDir = mkdtempSync(join(tmpdir(), 'ambush-e2e-'))
  const vault = join(opsDir, 'vault')
  mkdirSync(join(vault, 'findings'), { recursive: true })
  writeFileSync(join(vault, 'findings', 'recon.md'), '# recon\n\nOpen port 8080 (http) on the target.\n')
  const receiptLog = join(vault, 'receipts.jsonl')

  // 1. drive the real gate -> ALLOW + DENY signed receipts.
  await driveGate({ vault, receiptLog, frames: ALLOW_DENY_FRAMES })
  assert.ok(existsSync(receiptLog), 'receipts.jsonl was written')
  const receipts = toSummaries(readFileSync(receiptLog, 'utf8'))
  assert.ok(
    receipts.some((r) => r.verdict === 'ALLOW'),
    'has an ALLOW receipt',
  )
  // Require the DENY to come from the shell_command GUARD — not an internal-error/budget DENY that
  // would keep coverage green even if the `rm -rf /` guard regressed.
  assert.ok(
    receipts.some((r) => r.verdict === 'DENY' && (r.raw as { guard?: string }).guard === 'shell_command'),
    'has a DENY receipt from the shell_command guard',
  )

  // 2. build the bundle with the REAL producer (exportBundle reads name + intelVaultPath).
  const operation = { name: 'smoke-op', intelVaultPath: vault } as unknown as Operation
  const mgr = new AttestationManager()
  const result = mgr.exportBundle(operation, receipts)
  const manifestPath = join(result.bundleDir, 'manifest.json')
  assert.ok(existsSync(manifestPath), 'manifest.json written')

  // 3. assert the manifest is non-degenerate.
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  const coverage = Object.fromEntries(
    manifest.receipt_coverage.map((c: { category: string; status: string }) => [c.category, c.status]),
  )
  assert.equal(coverage.allow, 'covered', 'allow coverage is covered')
  assert.equal(coverage.denial, 'covered', 'denial coverage is covered')
  const findings = manifest.claims.find((c: { claim_id: string }) => c.claim_id === 'findings-present')
  assert.equal(findings?.result, 'verified', 'findings-present claim verified')

  // 4. verify with the REAL Rust ambush-verify.
  const outcome = await mgr.verifyBundle(result.bundleDir, result.signerKeyHex)
  assert.ok(outcome.ok, `ambush-verify ok (got ${JSON.stringify(outcome)})`)

  console.log('\x1b[32mE2E PASS\x1b[0m — gate -> receipts(ALLOW+DENY) -> bundle(findings + dual coverage) -> ambush-verify ok')
  console.log(`  receipts: ${receipts.length}   coverage: allow=${coverage.allow} denial=${coverage.denial}`)
  console.log(`  bundle: ${result.bundleDir}`)
}

main().catch((err: unknown) => {
  console.error('\x1b[31mE2E FAIL:\x1b[0m', err instanceof Error ? err.message : String(err))
  process.exit(1)
})
