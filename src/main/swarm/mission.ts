import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { Operation, Vector } from '@shared/types'

export interface MissionContext {
  operation: Operation
  vector: Vector
  /** Absolute path the agent should write findings to. */
  findingsAbsPath: string
  /** Argv for the (possibly gate-wrapped) intel MCP server, or null. */
  governedMcpCommand: string[] | null
  /** Env the gate-wrapped MCP server needs (signing key + receipt log), or undefined. */
  governedMcpEnv?: Record<string, string>
  /** Whether real, signed governance is active. Drives honest briefing language. */
  governed: boolean
}

/** Write the per-vector briefing the agent reads on launch. */
export function writeMissionFiles(worktreePath: string, ctx: MissionContext): void {
  const { operation, vector, findingsAbsPath, governedMcpCommand, governed } = ctx
  mkdirSync(worktreePath, { recursive: true })

  const reportingNote = governed
    ? `Preferred path: use the **open-knowledge** MCP \`write\` tool to create/update
\`${vector.findingsPath}\`. These writes are **governed by Chio and signed into an
append-only receipt log** — non-repudiation is part of the mission.`
    : `Preferred path: use the **open-knowledge** MCP \`write\` tool to create/update
\`${vector.findingsPath}\`. (Note: governance is not active for this run, so these
writes are **not** signed into a receipt log.)`

  const briefing = `# AMBUSH MISSION BRIEFING

**Operation:** ${operation.name}
**Operation objective:** ${operation.objective}
**Target:** ${operation.target || operation.targetPath || '(none specified)'}

## Your vector: ${vector.name}

${vector.objective}

## Reporting protocol

You are one lane in a coordinated swarm. Report continuously — do not wait until
the end. Write your findings as markdown to:

\`${vector.findingsPath}\` (in the shared intel vault)

${reportingNote}

If the MCP server is unavailable, write directly to:
\`${findingsAbsPath}\`

Use \`[[wiki-links]]\` to connect related findings across vectors so the intel
graph stays navigable. When your lane is complete, print \`DONE\` on its own line.
`

  writeFileSync(join(worktreePath, 'AMBUSH_MISSION.md'), briefing)
  mkdirSync(dirname(findingsAbsPath), { recursive: true })

  // Drop a project MCP config so harness agents (Claude/Cursor/Codex) auto-wire
  // the governed intel server without manual setup.
  if (governedMcpCommand && governedMcpCommand.length > 0) {
    const [command, ...args] = governedMcpCommand
    const server: { command: string; args: string[]; env?: Record<string, string> } = {
      command,
      args,
    }
    if (ctx.governedMcpEnv) server.env = ctx.governedMcpEnv
    const mcpConfig = { mcpServers: { 'open-knowledge': server } }
    // .mcp.json carries the governor signing secret (SWARM_GOVERNOR_KEY) in its env block, so write
    // it owner-only (0o600) rather than the world-readable default inside the target worktree.
    writeFileSync(join(worktreePath, '.mcp.json'), JSON.stringify(mcpConfig, null, 2), { mode: 0o600 })
  }
}

export function buildPrompt(ctx: MissionContext): string {
  const { operation, vector, governed } = ctx
  const reportNote = governed
    ? `Record findings via the open-knowledge MCP 'write' tool to ${vector.findingsPath} (governed, receipt-logged).`
    : `Record findings via the open-knowledge MCP 'write' tool to ${vector.findingsPath} (ungoverned this run — not receipt-logged).`
  return [
    `You are vector ${vector.name} in Ambush operation "${operation.name}".`,
    `Objective: ${vector.objective}`,
    `Operation goal: ${operation.objective}.`,
    `Read AMBUSH_MISSION.md for the full briefing and reporting protocol.`,
    reportNote,
    `Print DONE when your lane is complete.`,
  ].join(' ')
}
