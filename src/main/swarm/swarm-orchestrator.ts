import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { AGENT_PROFILES, DEFAULT_PLAYBOOK, findAgentProfile } from '@shared/agents'
import type {
  CreateOperationInput,
  DeploySwarmInput,
  Operation,
  Vector,
  VectorStatus,
} from '@shared/types'
import { OpenKnowledgeEngine } from '../engine/openknowledge-engine'
import { ApprovalQueue } from '../governance/approval-queue'
import { ChioGovernor } from '../governance/chio-governor'
import { PtyManager } from '../terminal/pty-manager'
import { bus } from '../util/bus'
import { buildPrompt, writeMissionFiles } from './mission'
import { WorktreeManager, type WorktreeHandle } from './worktree-manager'

function shortId(): string {
  return randomBytes(4).toString('hex')
}

export class SwarmOrchestrator {
  private operation: Operation | null = null
  private handles = new Map<string, WorktreeHandle>()
  private dataDir: string

  constructor(
    userDataDir: string,
    private engine: OpenKnowledgeEngine,
    private governor: ChioGovernor,
    private approvals: ApprovalQueue,
    private worktrees: WorktreeManager,
    private pty: PtyManager,
  ) {
    this.dataDir = join(userDataDir, 'operations')
    mkdirSync(this.dataDir, { recursive: true })
  }

  getOperation(): Operation | null {
    return this.operation
  }

  private persist(): void {
    if (!this.operation) return
    try {
      writeFileSync(join(this.dataDir, 'current.json'), JSON.stringify(this.operation, null, 2))
    } catch (err) {
      bus.log('warn', 'swarm', `persist failed: ${String(err)}`)
    }
    bus.operationUpdate(this.operation)
  }

  loadPersisted(): Operation | null {
    const p = join(this.dataDir, 'current.json')
    if (!existsSync(p)) return null
    try {
      this.operation = JSON.parse(readFileSync(p, 'utf8')) as Operation
      // Stale vectors from a previous process are no longer running.
      for (const v of this.operation.vectors) {
        if (v.status === 'running' || v.status === 'deploying') v.status = 'idle'
        v.terminalId = null
      }
      return this.operation
    } catch {
      return null
    }
  }

  async createOperation(input: CreateOperationInput): Promise<Operation> {
    const id = shortId()
    const opsDir =
      input.targetPath && input.targetPath.length > 0
        ? join(input.targetPath, '.ambush')
        : join(this.dataDir, id, '.ambush')
    const intelVaultPath = join(opsDir, 'intel')
    mkdirSync(intelVaultPath, { recursive: true })

    this.operation = {
      id,
      name: input.name || 'Untitled Operation',
      objective: input.objective,
      targetPath: input.targetPath,
      target: input.target,
      intelVaultPath,
      status: 'active',
      vectors: [],
      createdAt: Date.now(),
    }

    // Stand up governance + intel brain for this operation.
    this.governor.configure(opsDir)
    await this.engine.configure(intelVaultPath)
    this.engine.setGoverned(this.governor.getStatus().available)
    void this.engine.start()

    this.persist()
    bus.log('info', 'swarm', `Operation "${this.operation.name}" created`)
    return this.operation
  }

  private newVector(index: number, objective: string, codename: string, agentProfileId: string): Vector {
    const id = `vec-${String(index).padStart(2, '0')}-${shortId()}`
    return {
      id,
      name: `vec-${String(index).padStart(2, '0')}-${codename}`,
      objective,
      status: 'idle',
      agentProfileId,
      worktreePath: null,
      branch: null,
      terminalId: null,
      findingsPath: `findings/${id}.md`,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      exitCode: null,
      hasFindings: false,
    }
  }

  private setVectorStatus(vector: Vector, status: VectorStatus, exitCode: number | null = null): void {
    vector.status = status
    vector.updatedAt = Date.now()
    if (exitCode !== null) vector.exitCode = exitCode
    bus.vectorUpdate(vector)
  }

  async deploySwarm(input: DeploySwarmInput): Promise<Operation> {
    if (!this.operation) throw new Error('no active operation')
    const profile = findAgentProfile(input.agentProfileId) ?? AGENT_PROFILES[AGENT_PROFILES.length - 1]
    const count = Math.max(1, Math.min(input.count, 100))
    const startIndex = this.operation.vectors.length

    for (let i = 0; i < count; i++) {
      const index = startIndex + i + 1
      const playbook = DEFAULT_PLAYBOOK[(index - 1) % DEFAULT_PLAYBOOK.length]
      const objective = input.vectorObjectives?.[i] ?? playbook.objective
      const codename = input.vectorObjectives?.[i] ? `lane${index}` : playbook.codename
      const vector = this.newVector(index, objective, codename, profile.id)
      this.operation.vectors.push(vector)
      bus.vectorUpdate(vector)
      // Launch lanes concurrently — speed of fan-out is the whole point.
      void this.launchVector(vector)
    }
    this.persist()
    bus.log('info', 'swarm', `Deploying ${count} vector(s) with ${profile.name}`)
    return this.operation
  }

  private async launchVector(vector: Vector): Promise<void> {
    if (!this.operation) return
    const profile = findAgentProfile(vector.agentProfileId)
    if (!profile) {
      this.setVectorStatus(vector, 'failed')
      return
    }
    this.setVectorStatus(vector, 'deploying')

    // Fail-closed governance gate: refuse to launch ungoverned unless the operator
    // opted in via env (AMBUSH_ALLOW_UNGOVERNED=1) or approved it in the human-gate.
    if (
      !this.governor.isGoverned() &&
      process.env.AMBUSH_ALLOW_UNGOVERNED !== '1' &&
      !this.approvals.isUngovernedAllowed()
    ) {
      this.approvals.requestUngovernedLaunch(this.operation.name)
      bus.log(
        'warn',
        'governance',
        `vector ${vector.name} held — ungoverned launch needs operator approval (Approvals tab) or AMBUSH_ALLOW_UNGOVERNED=1`,
      )
      this.setVectorStatus(vector, 'failed')
      this.persist()
      return
    }

    const handle = await this.worktrees.create(this.operation.targetPath, vector.id, vector.name)
    this.handles.set(vector.id, handle)
    vector.worktreePath = handle.path
    vector.branch = handle.branch

    const findingsAbsPath = join(this.operation.intelVaultPath, vector.findingsPath)
    const governedMcpCommand = (() => {
      const inner = this.engine.mcpCommand()
      return inner ? this.governor.wrapMcp(inner) : null
    })()

    const governed = this.governor.isGoverned()
    writeMissionFiles(handle.path, {
      operation: this.operation,
      vector,
      findingsAbsPath,
      governedMcpCommand,
      governed,
    })

    const prompt = buildPrompt({
      operation: this.operation,
      vector,
      findingsAbsPath,
      governedMcpCommand,
      governed,
    })

    const terminalId = `term-${vector.id}`
    vector.terminalId = terminalId

    const args = [...profile.command.slice(1)]
    if (profile.promptDelivery === 'arg') args.push(prompt)

    const ok = await this.pty.spawn({
      terminalId,
      command: profile.command[0],
      args,
      cwd: handle.path,
      env: {
        ...process.env,
        AMBUSH_VECTOR_ID: vector.id,
        AMBUSH_FINDINGS: findingsAbsPath,
        AMBUSH_VAULT: this.operation.intelVaultPath,
      },
    })

    if (!ok) {
      this.setVectorStatus(vector, 'failed', 127)
      this.persist()
      return
    }

    this.setVectorStatus(vector, 'running')

    // Deliver the prompt for runtimes that read it interactively (auto-Enter).
    if (profile.promptDelivery === 'stdin') {
      setTimeout(() => this.pty.write(terminalId, `${prompt}\r`), 1200)
    } else if (profile.promptDelivery === 'file' && profile.id === 'shell') {
      setTimeout(() => this.pty.write(terminalId, `cat AMBUSH_MISSION.md\r`), 400)
    }
    this.persist()
  }

  /** Called by the IPC layer when a terminal exits. */
  onTerminalExit(terminalId: string, code: number | null): void {
    if (!this.operation) return
    const vector = this.operation.vectors.find((v) => v.terminalId === terminalId)
    if (!vector) return
    vector.hasFindings = this.checkFindings(vector)
    this.setVectorStatus(vector, code === 0 ? 'done' : 'failed', code)
    this.persist()
  }

  private checkFindings(vector: Vector): boolean {
    if (!this.operation) return false
    const abs = join(this.operation.intelVaultPath, vector.findingsPath)
    try {
      return existsSync(abs) && statSync(abs).size > 0
    } catch {
      return false
    }
  }

  async killVector(vectorId: string): Promise<Operation> {
    if (!this.operation) throw new Error('no active operation')
    const vector = this.operation.vectors.find((v) => v.id === vectorId)
    if (vector?.terminalId) this.pty.kill(vector.terminalId)
    if (vector) this.setVectorStatus(vector, 'killed')
    this.persist()
    return this.operation
  }

  async redeployVector(vectorId: string): Promise<Operation> {
    if (!this.operation) throw new Error('no active operation')
    const vector = this.operation.vectors.find((v) => v.id === vectorId)
    if (vector) {
      if (vector.terminalId) this.pty.kill(vector.terminalId)
      void this.launchVector(vector)
    }
    this.persist()
    return this.operation
  }

  async scale(to: number): Promise<Operation> {
    if (!this.operation) throw new Error('no active operation')
    const active = this.operation.vectors.filter(
      (v) => v.status === 'running' || v.status === 'deploying',
    )
    const target = Math.max(0, Math.min(to, 100))
    if (target > active.length) {
      const lastProfile = this.operation.vectors.at(-1)?.agentProfileId ?? 'shell'
      await this.deploySwarm({ count: target - active.length, agentProfileId: lastProfile })
    } else if (target < active.length) {
      const toRecall = active.slice(target)
      for (const v of toRecall) await this.killVector(v.id)
    }
    return this.operation
  }

  async recallAll(): Promise<Operation> {
    if (!this.operation) throw new Error('no active operation')
    for (const v of this.operation.vectors) {
      if (v.terminalId) this.pty.kill(v.terminalId)
      if (v.status === 'running' || v.status === 'deploying') this.setVectorStatus(v, 'killed')
    }
    this.persist()
    return this.operation
  }

  /** Roll all vector findings into a single linked kill-chain runbook. */
  async consolidate(): Promise<{ runbookPath: string }> {
    if (!this.operation) throw new Error('no active operation')
    this.operation.status = 'consolidating'
    bus.operationUpdate(this.operation)

    const findingsDir = join(this.operation.intelVaultPath, 'findings')
    let entries: string[] = []
    try {
      entries = readdirSync(findingsDir).filter((f) => f.endsWith('.md'))
    } catch {
      entries = []
    }

    const lines: string[] = []
    lines.push(`# Kill-Chain Runbook — ${this.operation.name}`)
    lines.push('')
    lines.push(`> Consolidated ${new Date().toISOString()} · ${entries.length} finding file(s)`)
    lines.push('')
    lines.push(`**Objective:** ${this.operation.objective}`)
    lines.push(`**Target:** ${this.operation.target || this.operation.targetPath || '—'}`)
    lines.push('')
    lines.push('## Vectors')
    lines.push('')
    for (const v of this.operation.vectors) {
      const mark = v.hasFindings || this.checkFindings(v) ? '✅' : '·'
      lines.push(`- ${mark} **${v.name}** — ${v.status} — [[${v.findingsPath.replace(/\.md$/, '')}]]`)
      lines.push(`  - ${v.objective}`)
    }
    lines.push('')
    lines.push('## Collected Intel')
    lines.push('')
    for (const file of entries) {
      lines.push(`### ${file}`)
      lines.push('')
      try {
        lines.push(readFileSync(join(findingsDir, file), 'utf8').trim())
      } catch {
        lines.push('_(unreadable)_')
      }
      lines.push('')
    }

    const runbookPath = join(this.operation.intelVaultPath, 'RUNBOOK.md')
    writeFileSync(runbookPath, lines.join('\n'))
    this.operation.status = 'active'
    this.persist()
    bus.log('info', 'swarm', `Consolidated ${entries.length} finding(s) into RUNBOOK.md`)
    return { runbookPath }
  }
}
