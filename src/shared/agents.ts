import type { AgentProfile } from './types'

// Built-in agent runtimes. Like Orca, Ambush works with "any CLI agent": if it
// runs in a terminal, it runs in a vector. The `shell` profile always works even
// with no agent installed, so the swarm mechanism is demonstrable out of the box.
export const AGENT_PROFILES: AgentProfile[] = [
  {
    id: 'claude',
    name: 'Claude Code',
    description: 'Anthropic Claude Code CLI',
    command: ['claude'],
    promptDelivery: 'arg',
    icon: 'Sparkles',
  },
  {
    id: 'codex',
    name: 'Codex',
    description: 'OpenAI Codex CLI',
    command: ['codex'],
    promptDelivery: 'arg',
    icon: 'Braces',
  },
  {
    id: 'cursor',
    name: 'Cursor Agent',
    description: 'Cursor CLI agent',
    command: ['cursor-agent'],
    promptDelivery: 'arg',
    icon: 'MousePointer2',
  },
  {
    id: 'opencode',
    name: 'OpenCode',
    description: 'OpenCode CLI',
    command: ['opencode'],
    promptDelivery: 'stdin',
    icon: 'TerminalSquare',
  },
  {
    id: 'hermes',
    name: 'Hermes',
    description: 'Nous Research Hermes agent (fleet default)',
    command: ['hermes'],
    promptDelivery: 'stdin',
    icon: 'Zap',
  },
  {
    id: 'shell',
    name: 'Shell (manual)',
    description: 'Interactive shell with the mission briefing pre-loaded',
    command: [process.platform === 'win32' ? 'powershell.exe' : 'bash'],
    promptDelivery: 'file',
    icon: 'SquareTerminal',
  },
]

export const DEFAULT_AGENT_ID = 'shell'

export function findAgentProfile(id: string): AgentProfile | undefined {
  return AGENT_PROFILES.find((p) => p.id === id)
}

// A small offensive/incident-response playbook used to auto-name vectors when
// the operator doesn't supply explicit objectives. Each line becomes one lane.
export const DEFAULT_PLAYBOOK: { codename: string; objective: string }[] = [
  { codename: 'recon', objective: 'Enumerate the target surface, map assets, services, and entry points.' },
  { codename: 'triage', objective: 'Identify the highest-severity weaknesses and rank them by exploitability.' },
  { codename: 'exploit', objective: 'Develop a proof-of-concept for the top candidate weakness.' },
  { codename: 'lateral', objective: 'Explore lateral movement and privilege-escalation paths.' },
  { codename: 'persist', objective: 'Assess persistence and post-exploitation footholds.' },
  { codename: 'harden', objective: 'Propose concrete remediations and detection signatures.' },
  { codename: 'report', objective: 'Synthesize a clear, evidence-backed writeup of what was found.' },
]
