// Adapted from ClawdStrike (Apache-2.0): apps/agent/src-tauri/src/daemon/
// {manager,spawn,ready_probe,state}.rs — the daemon state machine, readiness
// gate, and capped-exponential-backoff crash-restart loop, distilled into a
// framework-agnostic TypeScript supervisor for a single managed child process.
//
// The supervisor knows nothing about OpenKnowledge, HTTP, or Electron. A caller
// hands it a spawn thunk, an optional readiness predicate, and status/log
// callbacks; the supervisor owns the lifecycle: spawn → wait-for-ready →
// supervise → auto-restart-on-crash (with backoff + a max-retries circuit
// breaker) → clean stop().

import type { ChildProcess } from 'node:child_process'

/** Lifecycle states. Mirrors the upstream DaemonState machine, simplified. */
export type SupervisorState = 'idle' | 'starting' | 'ready' | 'crashed' | 'stopped'

/** Emitted on every state transition so callers can project their own status. */
export interface SupervisorEvent {
  state: SupervisorState
  /** Human-readable reason for the transition. */
  detail: string
  /** Total number of crash-restarts since construction. */
  restartCount: number
  /** True once the circuit breaker has tripped (max retries exhausted). */
  givenUp: boolean
}

export interface ProcessSupervisorOptions {
  /** Label used in log lines. */
  name: string
  /** Spawn thunk: produce a fresh child process. Called on every (re)start. */
  spawn: () => ChildProcess
  /**
   * Readiness predicate, polled after each spawn until it returns true, the
   * process exits, or the readiness deadline elapses. Defaults to
   * "ready as soon as the process is alive".
   */
  isReady?: (proc: ChildProcess) => boolean | Promise<boolean>
  /** Poll interval for `isReady` (ms). Default 200. */
  readinessIntervalMs?: number
  /** Max time to wait for `isReady` after a spawn (ms). Default 10_000. */
  readinessTimeoutMs?: number
  /**
   * What to do when readiness times out. 'ready' (default) optimistically
   * declares the process ready; 'crash' kills it and triggers the restart loop.
   */
  readinessTimeout?: 'ready' | 'crash'
  /** Circuit breaker: max consecutive restarts before giving up. Default 5. */
  maxRetries?: number
  /** Base backoff delay (ms). Default 500. */
  backoffBaseMs?: number
  /** Backoff ceiling (ms). Default 20_000. */
  backoffCapMs?: number
  /**
   * If a process stays ready at least this long, the restart streak resets so a
   * later crash starts backoff from scratch. Default 60_000.
   */
  stableWindowMs?: number
  /** Graceful-shutdown grace period before SIGKILL on stop()/kill. Default 400. */
  killGraceMs?: number
  /** State transition callback. */
  onState?: (event: SupervisorEvent) => void
  /** Log callback. */
  onLog?: (level: 'info' | 'warn' | 'error', message: string) => void
}

/**
 * Capped exponential backoff with deterministic jitter. Ported verbatim from
 * upstream `compute_backoff`: 500ms * 2^(streak-1), clamped to `capMs`, plus a
 * small `restartCount`-derived jitter so concurrent supervisors don't resonate.
 */
export function computeBackoff(
  streak: number,
  restartCount: number,
  baseMs = 500,
  capMs = 20_000,
): number {
  const exponent = Math.min(Math.max(streak - 1, 0), 16)
  const rawMs = baseMs * 2 ** exponent
  const cappedMs = Math.min(rawMs, capMs)
  const jitterMs = (restartCount * 113) % 250
  return cappedMs + jitterMs
}

/** Supervises a single child process: readiness gate + crash-restart loop. */
export class ProcessSupervisor {
  private readonly name: string
  private readonly spawnThunk: () => ChildProcess
  private readonly isReady: (proc: ChildProcess) => boolean | Promise<boolean>
  private readonly readinessIntervalMs: number
  private readonly readinessTimeoutMs: number
  private readonly readinessTimeout: 'ready' | 'crash'
  private readonly maxRetries: number
  private readonly backoffBaseMs: number
  private readonly backoffCapMs: number
  private readonly stableWindowMs: number
  private readonly killGraceMs: number
  private readonly onStateCb?: (event: SupervisorEvent) => void
  private readonly onLogCb?: (level: 'info' | 'warn' | 'error', message: string) => void

  private proc: ChildProcess | null = null
  private state: SupervisorState = 'idle'
  private restartCount = 0
  private restartStreak = 0
  private givenUp = false
  private stopping = false
  /** Bumped on every spawn (and on stop) to invalidate stale timers/listeners. */
  private epoch = 0
  private readyAt: number | null = null
  private readinessTimer: ReturnType<typeof setTimeout> | null = null
  private backoffTimer: ReturnType<typeof setTimeout> | null = null

  constructor(options: ProcessSupervisorOptions) {
    this.name = options.name
    this.spawnThunk = options.spawn
    this.isReady = options.isReady ?? ((): boolean => true)
    this.readinessIntervalMs = options.readinessIntervalMs ?? 200
    this.readinessTimeoutMs = options.readinessTimeoutMs ?? 10_000
    this.readinessTimeout = options.readinessTimeout ?? 'ready'
    this.maxRetries = options.maxRetries ?? 5
    this.backoffBaseMs = options.backoffBaseMs ?? 500
    this.backoffCapMs = options.backoffCapMs ?? 20_000
    this.stableWindowMs = options.stableWindowMs ?? 60_000
    this.killGraceMs = options.killGraceMs ?? 400
    this.onStateCb = options.onState
    this.onLogCb = options.onLog
  }

  getState(): SupervisorState {
    return this.state
  }

  getRestartCount(): number {
    return this.restartCount
  }

  hasGivenUp(): boolean {
    return this.givenUp
  }

  /** Start (idempotent while starting/ready). Resets the circuit breaker. */
  start(): void {
    if (this.state === 'starting' || this.state === 'ready') return
    // Cancel any pending crash-backoff respawn so start() during the crashed/backoff window
    // does not double-spawn (the backoff timer would later spawn a second, orphaned child).
    this.clearBackoffTimer()
    this.stopping = false
    this.givenUp = false
    this.restartStreak = 0
    this.spawnOnce()
  }

  /** Stop cleanly: cancel timers, kill the child, no auto-restart. */
  stop(detail = 'stop requested'): void {
    this.stopping = true
    this.givenUp = false
    this.clearReadinessTimer()
    this.clearBackoffTimer()
    // Invalidate any in-flight readiness poll and the child's exit listener so
    // the imminent SIGTERM exit is not mistaken for a crash.
    this.epoch += 1
    const proc = this.proc
    this.proc = null
    this.restartStreak = 0
    this.readyAt = null
    if (proc) this.killProcess(proc)
    this.setState('stopped', detail)
  }

  /** Force a clean stop followed by a fresh start. */
  restart(detail = 'restart requested'): void {
    this.stop(detail)
    this.start()
  }

  private spawnOnce(): void {
    this.stopping = false
    const epoch = ++this.epoch
    this.setState('starting', this.restartCount > 0 ? `respawning ${this.name}` : `spawning ${this.name}`)

    let proc: ChildProcess
    try {
      proc = this.spawnThunk()
    } catch (err) {
      this.handleCrash(`spawn threw: ${(err as Error).message}`)
      return
    }

    this.proc = proc
    proc.once('exit', (code, signal) => this.onProcExit(epoch, code, signal))
    proc.once('error', (err) => this.onProcError(epoch, err))
    this.beginReadiness(epoch, proc)
  }

  private beginReadiness(epoch: number, proc: ChildProcess): void {
    const deadline = Date.now() + this.readinessTimeoutMs
    const poll = (): void => {
      if (epoch !== this.epoch || this.state !== 'starting') return
      let result: boolean | Promise<boolean>
      try {
        result = this.isReady(proc)
      } catch {
        result = false
      }
      Promise.resolve(result).then(
        (ready) => this.onReadinessResult(epoch, proc, deadline, ready, poll),
        () => this.onReadinessResult(epoch, proc, deadline, false, poll),
      )
    }
    poll()
  }

  private onReadinessResult(
    epoch: number,
    proc: ChildProcess,
    deadline: number,
    ready: boolean,
    poll: () => void,
  ): void {
    if (epoch !== this.epoch || this.state !== 'starting') return
    if (ready) {
      this.markReady(epoch)
      return
    }
    if (Date.now() >= deadline) {
      if (this.readinessTimeout === 'ready') {
        this.log('warn', `${this.name} readiness timed out; assuming ready`)
        this.markReady(epoch)
      } else {
        this.log('warn', `${this.name} readiness timed out; treating as crash`)
        this.killProcess(proc)
      }
      return
    }
    this.readinessTimer = setTimeout(poll, this.readinessIntervalMs)
  }

  private markReady(epoch: number): void {
    if (epoch !== this.epoch) return
    this.clearReadinessTimer()
    this.readyAt = Date.now()
    this.setState('ready', `${this.name} ready`)
  }

  private onProcExit(epoch: number, code: number | null, signal: NodeJS.Signals | null): void {
    if (epoch !== this.epoch) return
    // Invalidate this spawn's epoch immediately so a sibling 'error'/'exit' for the SAME child
    // (Node can emit both) fails its guard and cannot double-run handleCrash → double respawn.
    this.epoch += 1
    this.proc = null
    this.clearReadinessTimer()
    if (this.stopping) return
    const reason = signal ? `killed by ${signal}` : `exited with code ${code ?? 'unknown'}`
    this.handleCrash(reason)
  }

  private onProcError(epoch: number, err: Error): void {
    if (epoch !== this.epoch) return
    this.epoch += 1 // see onProcExit: invalidate so a sibling exit/error can't double-crash
    this.proc = null
    this.clearReadinessTimer()
    if (this.stopping) return
    this.handleCrash(`spawn error: ${err.message}`)
  }

  private handleCrash(reason: string): void {
    // A process that stayed ready beyond the stable window earns a clean slate,
    // so an isolated later crash restarts fast instead of inheriting old streak.
    if (this.readyAt !== null && Date.now() - this.readyAt >= this.stableWindowMs) {
      this.restartStreak = 0
    }
    this.readyAt = null
    this.restartStreak += 1
    this.restartCount += 1

    if (this.restartStreak > this.maxRetries) {
      this.givenUp = true
      this.setState('stopped', `circuit breaker tripped after ${this.maxRetries} retries (${reason})`)
      return
    }

    this.setState('crashed', reason)
    const delay = computeBackoff(this.restartStreak, this.restartCount, this.backoffBaseMs, this.backoffCapMs)
    this.log('info', `${this.name} restarting in ${delay}ms (attempt ${this.restartStreak}/${this.maxRetries})`)
    this.clearBackoffTimer() // never leave a prior pending timer to fire alongside this one
    this.backoffTimer = setTimeout(() => {
      this.backoffTimer = null
      if (this.stopping) return
      this.spawnOnce()
    }, delay)
  }

  private killProcess(proc: ChildProcess): void {
    if (proc.exitCode !== null || proc.signalCode !== null) return
    try {
      proc.kill('SIGTERM')
    } catch {
      return
    }
    const timer = setTimeout(() => {
      if (proc.exitCode === null && proc.signalCode === null) {
        try {
          proc.kill('SIGKILL')
        } catch {
          // already exited
        }
      }
    }, this.killGraceMs)
    timer.unref?.()
  }

  private clearReadinessTimer(): void {
    if (this.readinessTimer) {
      clearTimeout(this.readinessTimer)
      this.readinessTimer = null
    }
  }

  private clearBackoffTimer(): void {
    if (this.backoffTimer) {
      clearTimeout(this.backoffTimer)
      this.backoffTimer = null
    }
  }

  private setState(state: SupervisorState, detail: string): void {
    this.state = state
    this.onStateCb?.({ state, detail, restartCount: this.restartCount, givenUp: this.givenUp })
  }

  private log(level: 'info' | 'warn' | 'error', message: string): void {
    this.onLogCb?.(level, message)
  }
}
