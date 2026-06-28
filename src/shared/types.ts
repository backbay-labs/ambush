// Core domain types for Ambush — Vector Swarm.
// An "Operation" is an incident/mission. A "Vector" is one attack/work lane,
// run by a single agent inside an isolated git worktree. Findings flow into the
// shared intel vault (OpenKnowledge), and every governed tool call is recorded
// as a Chio receipt.

export type VectorStatus =
  | 'idle'
  | 'deploying'
  | 'running'
  | 'reporting'
  | 'done'
  | 'failed'
  | 'killed'

export type OperationStatus = 'draft' | 'active' | 'consolidating' | 'archived'

export interface AgentProfile {
  /** Stable id, e.g. "claude", "codex", "shell". */
  id: string
  /** Human label shown in the UI. */
  name: string
  /** Short description of the runtime. */
  description: string
  /** Executable + base args. The mission prompt is appended/typed separately. */
  command: string[]
  /**
   * How the initial mission prompt is delivered to the CLI:
   *  - "arg": appended as a final argument
   *  - "stdin": typed into the PTY after launch (orca-style auto-Enter)
   *  - "file": only written to MISSION.md in the worktree (agent reads it)
   */
  promptDelivery: 'arg' | 'stdin' | 'file'
  /** lucide-react icon name used by the renderer. */
  icon: string
}

export interface Vector {
  id: string
  /** Short codename, e.g. "vec-01-recon". */
  name: string
  /** What this lane is trying to accomplish. */
  objective: string
  status: VectorStatus
  agentProfileId: string
  worktreePath: string | null
  branch: string | null
  terminalId: string | null
  /** Path (relative to the intel vault) where this vector reports findings. */
  findingsPath: string
  createdAt: number
  updatedAt: number
  exitCode: number | null
  /** Whether this lane has produced a non-empty findings file yet. */
  hasFindings: boolean
}

export interface Operation {
  id: string
  name: string
  objective: string
  /** Target repo or directory the swarm operates against. May be empty for CTF/host targets. */
  targetPath: string
  /** Free-form target descriptor for non-filesystem targets (host, URL, CTF endpoint). */
  target: string
  /** Where the OpenKnowledge intel vault lives. */
  intelVaultPath: string
  status: OperationStatus
  vectors: Vector[]
  createdAt: number
}

export interface EngineStatus {
  /** Whether an OpenKnowledge runtime is resolvable (`ok` or npx). */
  available: boolean
  /** How we invoke it. */
  source: 'local-ok' | 'npx' | 'none'
  running: boolean
  /** Web UI URL to embed when running. */
  url: string | null
  /** Whether the agent-facing MCP is wrapped by Chio. */
  governed: boolean
  detail: string
}

export interface GovernorStatus {
  /** Whether the `chio` binary is present. */
  available: boolean
  binaryPath: string | null
  policyPath: string | null
  receiptDbPath: string | null
  detail: string
}

export interface ReceiptSummary {
  id: string
  verdict: 'ALLOW' | 'DENY' | 'CANCELLED' | 'INCOMPLETE' | 'UNKNOWN'
  tool: string
  server: string
  policyHash: string | null
  timestamp: number | null
  raw?: unknown
}

export interface DeploySwarmInput {
  count: number
  agentProfileId: string
  /** Optional explicit vector objectives; if omitted, generated from a playbook. */
  vectorObjectives?: string[]
}

export interface CreateOperationInput {
  name: string
  objective: string
  targetPath: string
  target: string
}

export interface TerminalChunk {
  terminalId: string
  data: string
}

export interface TerminalExit {
  terminalId: string
  code: number | null
}

export interface LogLine {
  level: 'info' | 'warn' | 'error'
  scope: string
  message: string
  at: number
}
