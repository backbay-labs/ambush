import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { writePrivateAtomic } from '../util/atomic-write'
import { resolveBin } from '../util/binary-resolver'
import { bus } from '../util/bus'
import { run } from '../util/run'
import type { GovernorStatus, ReceiptSummary, SiemExportResult } from '@shared/types'

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

  /** Per-operation Ed25519 signing secret (hex) the gate uses; never exposed to the renderer. */
  private signingSecret = ''

  getStatus(): GovernorStatus {
    return { ...this.status }
  }

  /** Resolve the real MCP-wrap gate binary: PATH (dev), dev build outputs, then packaged-app
   * resources — so fail-closed governance survives in a packaged Electron .app. */
  private resolveGateBin(): string | null {
    return resolveBin('swarm-mcp-gate', ['engine/bin', 'bin'])
  }

  /** Whether the swarm is running under real, signed governance right now. */
  isGoverned(): boolean {
    return this.status.available
  }

  /** The per-operation Ed25519 signing secret (hex), shared with the gate. Empty before configure. */
  getSigningKey(): string {
    return this.signingSecret
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
    const bin = this.resolveGateBin()
    if (!bin) {
      const overridden = process.env.AMBUSH_ALLOW_UNGOVERNED === '1'
      this.status = {
        available: false,
        binaryPath: null,
        policyPath: null,
        receiptDbPath: null,
        detail: overridden
          ? 'swarm-mcp-gate not found — running UNGOVERNED (operator override). No signed receipts.'
          : 'swarm-mcp-gate not found — governance unavailable. Swarm is fail-closed; set AMBUSH_ALLOW_UNGOVERNED=1 to run anyway.',
      }
      bus.log(
        'warn',
        'governance',
        overridden
          ? 'swarm-mcp-gate not found — swarm is UNGOVERNED by operator override (no signed receipts).'
          : 'swarm-mcp-gate not found — governance unavailable. Deploys are blocked (fail-closed). Build engine/crates/swarm-mcp-gate or set AMBUSH_ALLOW_UNGOVERNED=1.',
      )
      bus.governorUpdate(this.getStatus())
      return this.getStatus()
    }
    const chioDir = join(opsDir, 'chio')
    mkdirSync(chioDir, { recursive: true })
    const policyPath = join(chioDir, 'policy.yaml')
    const receiptLogPath = join(chioDir, 'receipts.jsonl')
    // Security-sensitive: write atomically with 0o600 so a crash can't leave a partial policy.
    writePrivateAtomic(policyPath, DEFAULT_POLICY) // informational; the gate's real policy is the guards + mapping

    // One pinned signing key per operation, so every gate process emits verifiable receipts.
    const secretPath = join(chioDir, 'governor.secret')
    if (existsSync(secretPath)) {
      this.signingSecret = readFileSync(secretPath, 'utf8').trim()
    } else {
      this.signingSecret = randomBytes(32).toString('hex')
      writePrivateAtomic(secretPath, this.signingSecret)
    }

    this.status = {
      available: true,
      binaryPath: bin,
      policyPath,
      receiptDbPath: receiptLogPath,
      detail: 'governing intel MCP via swarm-mcp-gate (real guards, signed receipts)',
    }
    bus.governorUpdate(this.getStatus())
    return this.getStatus()
  }

  /**
   * Wrap the inner MCP command with the swarm-mcp-gate proxy so every `tools/call` is gated by the
   * real guards and signed into the receipt log. Returns the inner command unchanged if unavailable.
   */
  wrapMcp(inner: string[]): string[] {
    if (!this.status.available || !this.status.binaryPath) return inner
    return [this.status.binaryPath, '--server-id', 'open-knowledge', '--', ...inner]
  }

  /** Env the governed MCP child needs: the signing key + the shared receipt log path. */
  gateEnv(): Record<string, string> {
    const env: Record<string, string> = {
      SWARM_GOVERNOR_KEY: this.signingSecret,
      AMBUSH_RECEIPT_LOG: this.status.receiptDbPath ?? '',
    }
    // Opt-in per-lane request budget: the operator sets AMBUSH_LANE_BUDGET_REQUESTS=N to cap
    // governed tool calls per Vector (over budget -> signed DENY at the gate). Off by default so
    // long legitimate sessions are not truncated; passed explicitly so it reaches the gate child.
    const budget = process.env.AMBUSH_LANE_BUDGET_REQUESTS
    if (budget && /^\d+$/.test(budget)) env.AMBUSH_LANE_BUDGET_REQUESTS = budget
    return env
  }

  async listReceipts(): Promise<ReceiptSummary[]> {
    const p = this.status.receiptDbPath
    if (!this.status.available || !p || !existsSync(p)) return []
    let content = ''
    try {
      content = readFileSync(p, 'utf8')
    } catch {
      return []
    }
    return parseReceipts(content)
  }

  /**
   * Render the operation's signed receipt log as SIEM events (OCSF/CEF/HEC) via the `ambush-siem`
   * engine binary, writing the result next to the receipt log. Returns null if unavailable.
   */
  async exportSiem(format: SiemExportResult['format'] = 'ocsf'): Promise<SiemExportResult | null> {
    const log = this.status.receiptDbPath
    if (!this.status.available || !log || !existsSync(log)) return null
    const bin = resolveBin('ambush-siem', ['engine/bin', 'bin'])
    if (!bin) {
      bus.log('warn', 'governance', 'ambush-siem not found — build engine/crates/swarm-siem')
      return null
    }
    const res = await run(bin, ['--format', format, log], { timeoutMs: 15_000 })
    if (res.code !== 0) {
      bus.log('warn', 'governance', `ambush-siem failed (exit ${res.code})`)
      return null
    }
    const ext = format === 'cef' ? 'cef' : 'json'
    const outPath = join(dirname(log), `siem-export.${format}.${ext}`)
    writeFileSync(outPath, res.stdout)
    const bytes = Buffer.byteLength(res.stdout)
    bus.log('info', 'governance', `SIEM export (${format}, ${bytes} bytes) → ${outPath}`)
    return { format, path: outPath, bytes }
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
    reason: typeof obj.gate_reason === 'string' ? obj.gate_reason : null,
    guard: typeof obj.guard === 'string' ? obj.guard : null,
    source: 'intel-mcp',
    raw: obj,
  }
}
