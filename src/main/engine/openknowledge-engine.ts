import { type ChildProcess, spawn } from 'node:child_process'
import { existsSync, mkdirSync } from 'node:fs'
import { bus } from '../util/bus'
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
  private proc: ChildProcess | null = null
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
    const local = which('ok')
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
    if (this.proc) return this.getStatus()
    const invoker = this.resolveInvoker()
    if (!invoker || !this.vaultPath) return this.getStatus()

    bus.log('info', 'engine', 'Starting OpenKnowledge web UI…')
    this.proc = spawn(invoker.bin, [...invoker.base, 'start'], {
      cwd: this.vaultPath,
      env: { ...process.env, PORT: String(UI_PORT) },
    })
    this.proc.stdout?.on('data', (d) => {
      const text = d.toString()
      const m = text.match(/https?:\/\/(?:localhost|127\.0\.0\.1):(\d+)\S*/)
      if (m && !this.status.url) {
        this.status.url = m[0]
        this.status.running = true
        bus.engineUpdate(this.getStatus())
      }
    })
    this.proc.on('close', (code) => {
      bus.log('warn', 'engine', `OpenKnowledge exited (${code})`)
      this.proc = null
      this.status.running = false
      this.status.url = null
      bus.engineUpdate(this.getStatus())
    })

    // Optimistically assume the conventional UI port if we don't parse one.
    this.status.running = true
    this.status.url = `http://127.0.0.1:${UI_PORT}`
    bus.engineUpdate(this.getStatus())
    return this.getStatus()
  }

  stop(): EngineStatus {
    if (this.proc) {
      this.proc.kill()
      this.proc = null
    }
    this.status.running = false
    this.status.url = null
    bus.engineUpdate(this.getStatus())
    return this.getStatus()
  }

  setGoverned(governed: boolean): void {
    this.status.governed = governed
    bus.engineUpdate(this.getStatus())
  }
}
