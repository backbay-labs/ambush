import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { bus } from '../util/bus'
import { run, which } from '../util/run'
import type { GovernorStatus, ReceiptSummary } from '@shared/types'

// Default HushSpec-style policy for the swarm. Least-privilege: allow only the
// OpenKnowledge intel tools a reporting lane needs (read/search + write/edit its
// own findings). Fail-closed — anything not listed is denied. The dangerous verbs
// `exec`, `skills`, and `move` are intentionally NOT allowed (broad for an
// offensive-agent fleet), and `delete` is explicitly denied so findings can't be
// silently erased. The richer guard+capability policy lives in
// engine/rulesets/code-agent.yaml for the engine guard-eval path.
const DEFAULT_POLICY = `# Ambush swarm governance policy (HushSpec)
# Wraps the OpenKnowledge intel MCP server. Fail-closed, least-privilege.
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
    - checkpoint
  deny:
    - delete
    - exec
    - move
    - skills
`

/**
 * Wraps swarm tool access with Chio so every agent tool call against the intel
 * vault produces a signed, append-only receipt — non-repudiation for the
 * *governed intel-vault calls* (not arbitrary shell/agent actions outside that
 * path). Fail-closed: when no governor is available the swarm refuses to launch
 * unless the operator explicitly opts into ungoverned mode (AMBUSH_ALLOW_UNGOVERNED=1).
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

  /** Whether the swarm is running under real, signed governance right now. */
  isGoverned(): boolean {
    return this.status.available
  }

  /**
   * Fail-closed launch gate. Returns a human-readable reason a Vector launch is
   * blocked, or null if it may proceed. When no governor is available we refuse
   * to launch ungoverned by default; the operator overrides with
   * AMBUSH_ALLOW_UNGOVERNED=1 (fail-closed-but-overridable).
   */
  launchBlockReason(): string | null {
    if (this.status.available) return null
    if (process.env.AMBUSH_ALLOW_UNGOVERNED === '1') return null
    return 'governance unavailable (chio not found) and AMBUSH_ALLOW_UNGOVERNED is not set — refusing to launch ungoverned. Wire a governor or set AMBUSH_ALLOW_UNGOVERNED=1 to run without signed receipts.'
  }

  configure(opsDir: string): GovernorStatus {
    const bin = which('chio')
    if (!bin) {
      const overridden = process.env.AMBUSH_ALLOW_UNGOVERNED === '1'
      this.status = {
        available: false,
        binaryPath: null,
        policyPath: null,
        receiptDbPath: null,
        detail: overridden
          ? 'chio not found — running UNGOVERNED (operator override). No signed receipts.'
          : 'chio not found — governance unavailable. Swarm is fail-closed; set AMBUSH_ALLOW_UNGOVERNED=1 to run anyway.',
      }
      bus.log(
        'warn',
        'governance',
        overridden
          ? 'chio not found on PATH — swarm is UNGOVERNED by operator override (no signed receipts).'
          : 'chio not found on PATH — governance unavailable. Deploys are blocked (fail-closed). Set AMBUSH_ALLOW_UNGOVERNED=1 to run ungoverned.',
      )
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
