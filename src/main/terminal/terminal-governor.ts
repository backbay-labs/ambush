import type { Operation, ReceiptSummary } from '@shared/types'
import { resolveBin as resolveBinUtil } from '../util/binary-resolver'
import { bus } from '../util/bus'
import { run } from '../util/run'
import type { PtyManager } from './pty-manager'

interface TermState {
  line: string
  queue: Promise<void>
}

/**
 * Governs what is typed into agent terminals. Keystrokes forward live (echo/TUI stay responsive)
 * but the line-terminating carriage return is HELD: on Enter the reconstructed command is evaluated
 * once via the real swarm-governor guard pipeline. ALLOW releases the terminator (the command runs)
 * and signs an ALLOW receipt; DENY suppresses it, clears the echoed line, prints a red in-terminal
 * notice, and signs a DENY receipt onto evt:receipt (→ a DenyToast). Never evaluates per keystroke.
 *
 * Trust boundary: only renderer keystrokes (IPC.terminalWrite) are governed; the orchestrator's own
 * pty.write (trusted prompt injection) bypasses this. Fail-open if the binary is unresolved (dev
 * usability); set AMBUSH_TERM_FAILCLOSED=1 to deny instead.
 */
export class TerminalGovernor {
  private states = new Map<string, TermState>()
  private bin: string | null | undefined
  private warned = false

  constructor(
    private deps: {
      pty: PtyManager
      getOperation: () => Operation | null
      /** The governor's real per-operation signing secret (shared with the MCP gate). */
      getSigningKey?: () => string
    },
  ) {}

  /** Fail-closed denial: suppress the command, kill the echoed line, and warn in-terminal. */
  private failClosed(terminalId: string, why: string): void {
    this.deps.pty.write(terminalId, '\x15')
    bus.terminalData({
      terminalId,
      data: `\r\n\x1b[31m⛔ ambush: blocked — ${why} (fail-closed)\x1b[0m\r\n`,
    })
  }

  handleWrite(terminalId: string, data: string): void {
    const st = this.state(terminalId)
    if (!data.includes('\r') && !data.includes('\n')) {
      // common keystroke case: forward raw + reconstruct (pure sync, microseconds)
      this.deps.pty.write(terminalId, data)
      st.line = applyChars(st.line, data)
      return
    }
    this.processMixed(terminalId, st, data)
  }

  dispose(terminalId: string): void {
    this.states.delete(terminalId)
  }

  private state(id: string): TermState {
    let s = this.states.get(id)
    if (!s) {
      s = { line: '', queue: Promise.resolve() }
      this.states.set(id, s)
    }
    return s
  }

  private processMixed(terminalId: string, st: TermState, data: string): void {
    // Split into ordered (segment, terminator?) steps and serialize ALL of them through st.queue.
    // Forwarding a later command's bytes is chained AFTER the prior command's verdict, so a multi-
    // line paste (`true;\rrm -rf /\r`) cannot concatenate in the shell buffer and ride an earlier
    // ALLOW — the paste-concat deny bypass.
    const steps: { seg: string; terminator: string | null }[] = []
    let seg = ''
    for (let i = 0; i < data.length; i++) {
      const ch = data[i]
      if (ch === '\r' || ch === '\n') {
        const terminator = ch === '\r' && data[i + 1] === '\n' ? '\r\n' : ch
        if (terminator === '\r\n') i++
        steps.push({ seg, terminator })
        seg = ''
      } else {
        seg += ch
      }
    }
    if (seg) steps.push({ seg, terminator: null })

    for (const step of steps) {
      st.queue = st.queue
        .then(async () => {
          if (step.seg) {
            this.deps.pty.write(terminalId, step.seg)
            st.line = applyChars(st.line, step.seg)
          }
          if (step.terminator === null) return
          const cmd = st.line.trim()
          st.line = ''
          if (cmd === '') {
            this.deps.pty.write(terminalId, step.terminator)
            return
          }
          await this.evaluateAndApply(terminalId, step.terminator, cmd)
        })
        .catch(() => {})
    }
  }

  private resolveBin(): string | null {
    if (this.bin !== undefined) return this.bin
    // PATH (dev), dev build outputs, then packaged-app resources.
    this.bin = resolveBinUtil('swarm-governor', ['engine/bin', 'bin'])
    return this.bin
  }

  private async evaluateAndApply(terminalId: string, terminator: string, cmd: string): Promise<void> {
    const op = this.deps.getOperation()
    const v = op?.vectors.find((x) => x.terminalId === terminalId)
    const vectorId = v?.id ?? terminalId.replace(/^term-/, '')
    const vectorLabel = v?.name ?? terminalId

    const bin = this.resolveBin()
    if (!bin) {
      if (process.env.AMBUSH_TERM_FAILCLOSED === '1') {
        this.failClosed(terminalId, 'governance unavailable (governor not found)')
      } else {
        if (!this.warned) {
          this.warned = true
          bus.log('warn', 'term-gov', 'swarm-governor not found; terminal commands run ungoverned')
        }
        this.deps.pty.write(terminalId, terminator)
      }
      return
    }

    // Sign with the governor's real per-operation secret (shared with the MCP gate) so terminal
    // receipts are not forgeable from the public operation id; omit the var (ephemeral key) if none.
    const signingKey = this.deps.getSigningKey?.() ?? ''
    const action = JSON.stringify({ kind: 'shell_command', command: cmd.slice(0, 8192) })
    const res = await run(bin, [], {
      input: action,
      timeoutMs: 4000,
      env: {
        ...process.env,
        ...(signingKey ? { SWARM_GOVERNOR_KEY: signingKey } : {}),
        SWARM_AGENT_ID: vectorId,
      },
    })

    if (res.code === null || res.code === 2) {
      // Governor timed out or errored. Honor the operator's posture: fail-closed denies, else
      // fail-open keeps the terminal usable (the documented default).
      if (process.env.AMBUSH_TERM_FAILCLOSED === '1') {
        this.failClosed(terminalId, res.code === null ? 'governor timed out' : 'governor errored')
      } else {
        this.deps.pty.write(terminalId, terminator)
      }
      return
    }

    const summary = toReceiptSummary(res.stdout, cmd, vectorLabel)
    bus.receipt(summary)

    if (res.code === 0) {
      this.deps.pty.write(terminalId, terminator)
    } else {
      // DENY: suppress the terminator, kill the shell's echoed input line, print a red notice.
      this.deps.pty.write(terminalId, '\x15')
      bus.terminalData({
        terminalId,
        data: `\r\n\x1b[31m⛔ ambush: blocked by governance [${summary.reason ?? 'denied'}]\x1b[0m\r\n`,
      })
    }
  }
}

function applyChars(line: string, data: string): string {
  let out = line
  for (const ch of data) {
    const code = ch.charCodeAt(0)
    if (code === 0x7f || code === 0x08) out = out.slice(0, -1)
    else if (code === 0x03 || code === 0x15) out = ''
    else if (code >= 0x20) out += ch
    // other control/escape bytes are ignored for reconstruction (best-effort)
  }
  return out
}

interface GovernorReceiptJson {
  receipt?: {
    receipt_id?: string
    timestamp?: string
    content_hash?: string
    verdict?: { passed?: boolean; gate_id?: string }
    metadata?: { message?: string }
  }
}

function toReceiptSummary(stdout: string, cmd: string, vectorLabel: string): ReceiptSummary {
  let json: GovernorReceiptJson = {}
  try {
    json = JSON.parse(stdout) as GovernorReceiptJson
  } catch {
    /* leave empty */
  }
  const r = json.receipt ?? {}
  const verdict: ReceiptSummary['verdict'] = r.verdict?.passed ? 'ALLOW' : 'DENY'
  const tsParsed = r.timestamp ? Date.parse(r.timestamp) : Number.NaN
  return {
    id: r.receipt_id ?? `term-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    verdict,
    tool: cmd.slice(0, 120),
    server: `terminal:${vectorLabel}`,
    policyHash: r.content_hash ?? null,
    timestamp: Number.isNaN(tsParsed) ? null : tsParsed,
    reason: r.metadata?.message ?? r.verdict?.gate_id ?? null,
    guard: r.verdict?.gate_id ?? null,
    source: 'engine-governor',
    raw: json,
  }
}
