import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { Operation, ReceiptSummary } from '@shared/types'
import { bus } from '../util/bus'
import { run, which } from '../util/run'
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

  constructor(private deps: { pty: PtyManager; getOperation: () => Operation | null }) {}

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
    let seg = ''
    for (let i = 0; i < data.length; i++) {
      const ch = data[i]
      if (ch === '\r' || ch === '\n') {
        if (seg) {
          this.deps.pty.write(terminalId, seg)
          st.line = applyChars(st.line, seg)
          seg = ''
        }
        const terminator = ch === '\r' && data[i + 1] === '\n' ? '\r\n' : ch
        if (terminator === '\r\n') i++
        const cmd = st.line.trim()
        st.line = ''
        if (cmd === '') {
          this.deps.pty.write(terminalId, terminator)
          continue
        }
        const t = terminator
        const c = cmd
        st.queue = st.queue.then(() => this.evaluateAndApply(terminalId, t, c)).catch(() => {})
      } else {
        seg += ch
      }
    }
    if (seg) {
      this.deps.pty.write(terminalId, seg)
      st.line = applyChars(st.line, seg)
    }
  }

  private resolveBin(): string | null {
    if (this.bin !== undefined) return this.bin
    const onPath = which('swarm-governor')
    if (onPath) {
      this.bin = onPath
      return onPath
    }
    for (const rel of ['engine/target/release/swarm-governor', 'engine/target/debug/swarm-governor']) {
      const p = join(process.cwd(), rel)
      if (existsSync(p)) {
        this.bin = p
        return p
      }
    }
    this.bin = null
    return null
  }

  private async evaluateAndApply(terminalId: string, terminator: string, cmd: string): Promise<void> {
    const op = this.deps.getOperation()
    const v = op?.vectors.find((x) => x.terminalId === terminalId)
    const vectorId = v?.id ?? terminalId.replace(/^term-/, '')
    const vectorLabel = v?.name ?? terminalId

    const bin = this.resolveBin()
    if (!bin) {
      if (process.env.AMBUSH_TERM_FAILCLOSED !== '1') {
        if (!this.warned) {
          this.warned = true
          bus.log('warn', 'term-gov', 'swarm-governor not found; terminal commands run ungoverned')
        }
        this.deps.pty.write(terminalId, terminator)
      } else {
        bus.terminalData({
          terminalId,
          data: `\r\n\x1b[31m⛔ ambush: governance unavailable (fail-closed)\x1b[0m\r\n`,
        })
      }
      return
    }

    const action = JSON.stringify({ kind: 'shell_command', command: cmd.slice(0, 8192) })
    const res = await run(bin, [], {
      input: action,
      timeoutMs: 4000,
      env: {
        ...process.env,
        SWARM_GOVERNOR_KEY: `ambush-governor-${op?.id ?? 'default'}`,
        SWARM_AGENT_ID: vectorId,
      },
    })

    if (res.code === null || res.code === 2) {
      // evaluation error/timeout -> fail-open (forward), keep the terminal usable.
      this.deps.pty.write(terminalId, terminator)
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
    source: 'engine-governor',
    raw: json,
  }
}
