import { spawn as cpSpawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { bus } from '../util/bus'

// node-pty gives real TTYs (so TUI agents render correctly). It needs a native
// rebuild against Electron (`pnpm run rebuild`). If it isn't available we fall
// back to piped child processes so the swarm still runs headlessly.
type PtyProcess = {
  write(data: string): void
  resize(cols: number, rows: number): void
  kill(): void
  onData(cb: (d: string) => void): void
  onExit(cb: (code: number | null) => void): void
}

let ptyModule: typeof import('node-pty') | null = null
async function loadPty(): Promise<typeof import('node-pty') | null> {
  if (ptyModule) return ptyModule
  try {
    ptyModule = await import('node-pty')
    return ptyModule
  } catch {
    bus.log('warn', 'pty', 'node-pty unavailable; using piped fallback (no TTY). Run `pnpm run rebuild`.')
    return null
  }
}

export interface SpawnSpec {
  terminalId: string
  command: string
  args: string[]
  cwd: string
  env: NodeJS.ProcessEnv
  cols?: number
  rows?: number
}

export class PtyManager {
  private sessions = new Map<string, PtyProcess>()

  async spawn(spec: SpawnSpec): Promise<boolean> {
    const pty = await loadPty()
    if (pty) {
      try {
        const proc = pty.spawn(spec.command, spec.args, {
          name: 'xterm-color',
          cols: spec.cols ?? 100,
          rows: spec.rows ?? 30,
          cwd: spec.cwd,
          env: spec.env as Record<string, string>,
        })
        const wrapped: PtyProcess = {
          write: (d) => proc.write(d),
          resize: (c, r) => {
            try {
              proc.resize(c, r)
            } catch {
              /* terminal may have exited */
            }
          },
          kill: () => proc.kill(),
          onData: (cb) => proc.onData(cb),
          onExit: (cb) => proc.onExit(({ exitCode }) => cb(exitCode)),
        }
        this.register(spec.terminalId, wrapped)
        return true
      } catch (err) {
        bus.log('error', 'pty', `pty spawn failed (${spec.command}): ${String(err)}`)
        // fall through to piped fallback
      }
    }
    return this.spawnPiped(spec)
  }

  private spawnPiped(spec: SpawnSpec): boolean {
    let child: ChildProcessWithoutNullStreams
    try {
      child = cpSpawn(spec.command, spec.args, {
        cwd: spec.cwd,
        env: spec.env,
      }) as ChildProcessWithoutNullStreams
    } catch (err) {
      bus.log('error', 'pty', `spawn failed (${spec.command}): ${String(err)}`)
      bus.terminalData({ terminalId: spec.terminalId, data: `\r\n[ambush] cannot launch ${spec.command}\r\n` })
      bus.terminalExit({ terminalId: spec.terminalId, code: 127 })
      return false
    }
    const wrapped: PtyProcess = {
      write: (d) => child.stdin.write(d),
      resize: () => {},
      kill: () => child.kill('SIGKILL'),
      onData: (cb) => {
        child.stdout.on('data', (d) => cb(d.toString()))
        child.stderr.on('data', (d) => cb(d.toString()))
      },
      onExit: (cb) => child.on('close', (code) => cb(code)),
    }
    this.register(spec.terminalId, wrapped)
    return true
  }

  private register(terminalId: string, proc: PtyProcess): void {
    this.sessions.set(terminalId, proc)
    proc.onData((data) => bus.terminalData({ terminalId, data }))
    proc.onExit((code) => {
      this.sessions.delete(terminalId)
      bus.terminalExit({ terminalId, code })
    })
  }

  write(terminalId: string, data: string): void {
    this.sessions.get(terminalId)?.write(data)
  }

  resize(terminalId: string, cols: number, rows: number): void {
    this.sessions.get(terminalId)?.resize(cols, rows)
  }

  kill(terminalId: string): void {
    const proc = this.sessions.get(terminalId)
    if (proc) {
      proc.kill()
      this.sessions.delete(terminalId)
    }
  }

  killAll(): void {
    for (const id of [...this.sessions.keys()]) this.kill(id)
  }
}
