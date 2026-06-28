import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { bus } from '../util/bus'
import { run, which } from '../util/run'
import type { GovernorStatus, ReceiptSummary } from '@shared/types'

// Default HushSpec-style policy for the swarm: allow the OpenKnowledge intel
// tools plus read-only inspection, deny everything else. Chio is fail-closed, so
// anything not listed is denied and every decision is signed into the receipt db.
const DEFAULT_POLICY = `# Ambush swarm governance policy (HushSpec)
# Wraps the OpenKnowledge intel MCP server. Fail-closed by default.
version: 1
tool_access:
  allow:
    - search
    - links
    - history
    - config
    - palette
    - workflow
    - write
    - edit
    - move
    - checkpoint
    - skills
    - exec
  deny:
    - delete
`

/**
 * Wraps swarm tool access with Chio so every agent action against the intel
 * vault produces a signed, append-only receipt. Fits the security mission:
 * non-repudiation for everything the swarm touches.
 */
export class ChioGovernor {
  private status: GovernorStatus = {
    available: false,
    binaryPath: null,
    policyPath: null,
    receiptDbPath: null,
    detail: 'not initialized',
  }

  getStatus(): GovernorStatus {
    return { ...this.status }
  }

  configure(opsDir: string): GovernorStatus {
    const bin = which('chio')
    if (!bin) {
      this.status = {
        available: false,
        binaryPath: null,
        policyPath: null,
        receiptDbPath: null,
        detail: 'chio not found on PATH. Agents run ungoverned.',
      }
      bus.governorUpdate(this.getStatus())
      return this.getStatus()
    }
    const chioDir = join(opsDir, 'chio')
    mkdirSync(chioDir, { recursive: true })
    const policyPath = join(chioDir, 'policy.yaml')
    const receiptDbPath = join(chioDir, 'receipts.db')
    writeFileSync(policyPath, DEFAULT_POLICY)

    this.status = {
      available: true,
      binaryPath: bin,
      policyPath,
      receiptDbPath,
      detail: 'governing intel MCP with signed receipts',
    }
    bus.governorUpdate(this.getStatus())
    return this.getStatus()
  }

  /**
   * Given the inner MCP command, return a Chio-wrapped command if available.
   * Otherwise the inner command is returned unchanged (ungoverned).
   */
  wrapMcp(inner: string[]): string[] {
    if (!this.status.available || !this.status.binaryPath || !this.status.policyPath) return inner
    return [
      this.status.binaryPath,
      '--receipt-db',
      this.status.receiptDbPath as string,
      'mcp',
      'serve',
      '--policy',
      this.status.policyPath,
      '--server-id',
      'open-knowledge',
      '--',
      ...inner,
    ]
  }

  async listReceipts(): Promise<ReceiptSummary[]> {
    if (!this.status.available || !this.status.binaryPath || !this.status.receiptDbPath) return []
    const res = await run(
      this.status.binaryPath,
      ['--receipt-db', this.status.receiptDbPath, 'receipt', 'list', '--admin-all', '--json'],
      { timeoutMs: 15_000 },
    )
    if (res.code !== 0) return []
    return parseReceipts(res.stdout)
  }
}

function parseReceipts(stdout: string): ReceiptSummary[] {
  const out: ReceiptSummary[] = []
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) continue
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>
      out.push(normalize(obj))
    } catch {
      // not JSONL; ignore
    }
  }
  // Some chio builds emit a single JSON array instead of JSONL.
  if (out.length === 0) {
    try {
      const arr = JSON.parse(stdout) as Record<string, unknown>[]
      if (Array.isArray(arr)) return arr.map(normalize)
    } catch {
      /* ignore */
    }
  }
  return out
}

function normalize(obj: Record<string, unknown>): ReceiptSummary {
  const verdictRaw = String(obj.verdict ?? obj.decision ?? 'UNKNOWN').toUpperCase()
  const verdict = (['ALLOW', 'DENY', 'CANCELLED', 'INCOMPLETE'].includes(verdictRaw)
    ? verdictRaw
    : 'UNKNOWN') as ReceiptSummary['verdict']
  const tsRaw = obj.timestamp ?? obj.created_at ?? obj.time
  let timestamp: number | null = null
  if (typeof tsRaw === 'number') timestamp = tsRaw
  else if (typeof tsRaw === 'string') {
    const parsed = Date.parse(tsRaw)
    timestamp = Number.isNaN(parsed) ? null : parsed
  }
  return {
    id: String(obj.receipt_id ?? obj.id ?? Math.random().toString(36).slice(2)),
    verdict,
    tool: String(obj.tool ?? obj.tool_name ?? '—'),
    server: String(obj.server ?? obj.tool_server ?? '—'),
    policyHash: obj.policy ? String(obj.policy) : obj.policy_hash ? String(obj.policy_hash) : null,
    timestamp,
    raw: obj,
  }
}
