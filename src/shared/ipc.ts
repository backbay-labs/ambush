// Single source of truth for IPC channel names and the typed surface exposed on
// `window.ambush`. Both the preload bridge and the renderer import from here.

import type {
  AgentProfile,
  CreateOperationInput,
  DeploySwarmInput,
  EngineStatus,
  GovernorStatus,
  LogLine,
  Operation,
  ReceiptSummary,
  TerminalChunk,
  TerminalExit,
  Vector,
} from './types'

export const IPC = {
  // request/response (ipcRenderer.invoke)
  agentsList: 'agents:list',
  operationGet: 'operation:get',
  operationCreate: 'operation:create',
  swarmDeploy: 'swarm:deploy',
  swarmScale: 'swarm:scale',
  swarmRecallAll: 'swarm:recallAll',
  vectorKill: 'vector:kill',
  vectorRedeploy: 'vector:redeploy',
  vectorOpenWorktree: 'vector:openWorktree',
  terminalWrite: 'terminal:write',
  terminalResize: 'terminal:resize',
  intelConsolidate: 'intel:consolidate',
  intelOpenVault: 'intel:openVault',
  engineStatus: 'engine:status',
  engineStart: 'engine:start',
  engineStop: 'engine:stop',
  governorStatus: 'governor:status',
  receiptsList: 'receipts:list',
  pickDirectory: 'dialog:pickDirectory',

  // events (main -> renderer)
  evtTerminalData: 'evt:terminal:data',
  evtTerminalExit: 'evt:terminal:exit',
  evtVectorUpdate: 'evt:vector:update',
  evtOperationUpdate: 'evt:operation:update',
  evtEngineUpdate: 'evt:engine:update',
  evtGovernorUpdate: 'evt:governor:update',
  evtLog: 'evt:log',
} as const

export interface AmbushApi {
  agentsList(): Promise<AgentProfile[]>
  operationGet(): Promise<Operation | null>
  operationCreate(input: CreateOperationInput): Promise<Operation>
  swarmDeploy(input: DeploySwarmInput): Promise<Operation>
  swarmScale(to: number): Promise<Operation>
  swarmRecallAll(): Promise<Operation>
  vectorKill(vectorId: string): Promise<Operation>
  vectorRedeploy(vectorId: string): Promise<Operation>
  vectorOpenWorktree(vectorId: string): Promise<void>
  terminalWrite(terminalId: string, data: string): void
  terminalResize(terminalId: string, cols: number, rows: number): void
  intelConsolidate(): Promise<{ runbookPath: string }>
  intelOpenVault(): Promise<void>
  engineStatus(): Promise<EngineStatus>
  engineStart(): Promise<EngineStatus>
  engineStop(): Promise<EngineStatus>
  governorStatus(): Promise<GovernorStatus>
  receiptsList(): Promise<ReceiptSummary[]>
  pickDirectory(): Promise<string | null>

  // subscriptions return an unsubscribe function
  onTerminalData(cb: (chunk: TerminalChunk) => void): () => void
  onTerminalExit(cb: (exit: TerminalExit) => void): () => void
  onVectorUpdate(cb: (vector: Vector) => void): () => void
  onOperationUpdate(cb: (op: Operation) => void): () => void
  onEngineUpdate(cb: (status: EngineStatus) => void): () => void
  onGovernorUpdate(cb: (status: GovernorStatus) => void): () => void
  onLog(cb: (line: LogLine) => void): () => void
}
