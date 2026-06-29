import { spawn } from 'node:child_process'
import { existsSync, mkdirSync } from 'node:fs'
import { resolveBin } from '../util/binary-resolver'
import { bus } from '../util/bus'
import { ProcessSupervisor, type SupervisorEvent } from './process-supervisor'
import { run, which } from '../util/run'
import type { EngineStatus } from '@shared/types'

const UI_PORT = 39847

/**
 * Embeds OpenKnowledge as the swarm's intel brain. OpenKnowledge is GPL-3.0, so
 * Ambush keeps a clean license boundary by invoking it strictly as a subprocess
 * (its `ok` CLI / MCP / local web server) — never by importing its source.
 *
 * Resolution order: a local `ok` binary, else `npx @inkeep/open-knowledge`.
 */
export class OpenKnowledgeEngine {
  private supervisor: ProcessSupervisor | null = null
  private vaultPath = ''
  private status: EngineStatus = {
    available: false,
    source: 'none',
    running: false,
    url: null,
    governed: false,
    detail: 'not initialized',
  }

  getStatus(): EngineStatus {
    return { ...this.status }
  }

  /** [bin, ...baseArgs] used to invoke the OpenKnowledge CLI, or null. */
  resolveInvoker(): { bin: string; base: string[]; source: EngineStatus['source'] } | null {
    // PATH (dev), dev build outputs, then packaged-app resources so a bundled `ok` is found.
    const local = resolveBin('ok', ['engine/bin', 'bin'])
    if (local) return { bin: local, base: [], source: 'local-ok' }
    const npx = which('npx')
    if (npx) return { bin: npx, base: ['-y', '@inkeep/open-knowledge@latest'], source: 'npx' }
    return null
  }

  async configure(vaultPath: string): Promise<EngineStatus> {
    this.vaultPath = vaultPath
    mkdirSync(vaultPath, { recursive: true })
    const invoker = this.resolveInvoker()
    if (!invoker) {
      this.status = {
        available: false,
        source: 'none',
        running: false,
        url: null,
        governed: false,
        detail: 'OpenKnowledge not found. Install with `npm i -g @inkeep/open-knowledge`.',
      }
      bus.engineUpdate(this.getStatus())
      return this.getStatus()
    }
    this.status.available = true
    this.status.source = invoker.source
    this.status.detail = `resolved via ${invoker.source}`

    // Initialize the vault as an OpenKnowledge project once (idempotent).
    if (!existsSync(`${vaultPath}/.ok`)) {
      bus.log('info', 'engine', 'Initializing OpenKnowledge intel vault…')
      const res = await run(invoker.bin, [...invoker.base, 'init', '--no-mcp'], {
        cwd: vaultPath,
        timeoutMs: 120_000,
      })
      if (res.code !== 0) {
        bus.log('warn', 'engine', `ok init returned ${res.code}: ${res.stderr.trim().slice(0, 200)}`)
      }
    }
    bus.engineUpdate(this.getStatus())
    return this.getStatus()
  }

  /**
   * The command an agent uses to reach the intel vault over MCP. Returned as an
   * argv array so the Chio governor can wrap it.
   */
  mcpCommand(): string[] | null {
    const invoker = this.resolveInvoker()
    if (!invoker) return null
    return [invoker.bin, ...invoker.base, 'mcp']
  }

  async start(): Promise<EngineStatus> {
    if (this.supervisor && this.supervisor.getState() !== 'stopped') return this.getStatus()
    const invoker = this.resolveInvoker()
    if (!invoker || !this.vaultPath) return this.getStatus()

    bus.log('info', 'engine', 'Starting OpenKnowledge web UI…')
    // Drive the `ok` subprocess through a supervisor so a crash auto-restarts
    // with capped backoff and the renderer sees the same EngineStatus stream.
    this.supervisor = new ProcessSupervisor({
      name: 'openknowledge',
      spawn: () => {
        const proc = spawn(invoker.bin, [...invoker.base, 'start'], {
          cwd: this.vaultPath,
          env: { ...process.env, PORT: String(UI_PORT) },
        })
        proc.stdout?.on('data', (d) => {
          const text = d.toString()
          const m = text.match(/https?:\/\/(?:localhost|127\.0\.0\.1):(\d+)\S*/)
          if (m && !this.status.url) {
            this.status.url = m[0]
            // Surface a freshly-parsed URL only once we are already serving.
            if (this.status.running) bus.engineUpdate(this.getStatus())
          }
        })
        return proc
      },
      // Ready once the web UI prints its URL; otherwise the timeout below falls
      // back to optimistically assuming the conventional UI port.
      isReady: () => this.status.url !== null,
      readinessTimeoutMs: 1500,
      readinessTimeout: 'ready',
      onState: (event) => this.onSupervisorState(event),
      onLog: (level, message) => bus.log(level, 'engine', message),
    })
    this.supervisor.start()
    return this.getStatus()
  }

  /** Project supervisor lifecycle transitions onto EngineStatus + the bus. */
  private onSupervisorState(event: SupervisorEvent): void {
    switch (event.state) {
      case 'starting':
        this.status.running = false
        this.status.detail =
          event.restartCount > 0
            ? `restarting OpenKnowledge (attempt ${event.restartCount})…`
            : 'starting OpenKnowledge…'
        break
      case 'ready':
        this.status.running = true
        if (!this.status.url) this.status.url = `http://127.0.0.1:${UI_PORT}`
        this.status.detail = `running (${this.status.source})`
        break
      case 'crashed':
        this.status.running = false
        this.status.url = null
        this.status.detail = `OpenKnowledge crashed: ${event.detail}`
        break
      case 'stopped':
        this.status.running = false
        this.status.url = null
        this.status.detail = event.givenUp
          ? `OpenKnowledge stopped after ${event.restartCount} failed restarts`
          : 'stopped'
        break
    }
    bus.engineUpdate(this.getStatus())
  }

  stop(): EngineStatus {
    if (this.supervisor) {
      // supervisor.stop() drives the 'stopped' transition synchronously, which
      // clears running/url and emits the engine update via onSupervisorState.
      this.supervisor.stop()
      this.supervisor = null
      return this.getStatus()
    }
    this.status.running = false
    this.status.url = null
    this.status.detail = 'stopped'
    bus.engineUpdate(this.getStatus())
    return this.getStatus()
  }

  setGoverned(governed: boolean): void {
    this.status.governed = governed
    bus.engineUpdate(this.getStatus())
  }
}
