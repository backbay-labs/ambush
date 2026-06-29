import { contextBridge, ipcRenderer } from 'electron'
import { IPC, type AmbushApi } from '@shared/ipc'
import type {
  ApprovalRequest,
  ApprovalResolution,
  CreateOperationInput,
  DeploySwarmInput,
  TerminalChunk,
  TerminalExit,
} from '@shared/types'

function subscribe<T>(channel: string, cb: (payload: T) => void): () => void {
  const listener = (_e: unknown, payload: T): void => cb(payload)
  ipcRenderer.on(channel, listener)
  return () => ipcRenderer.removeListener(channel, listener)
}

const api: AmbushApi = {
  agentsList: () => ipcRenderer.invoke(IPC.agentsList),
  operationGet: () => ipcRenderer.invoke(IPC.operationGet),
  operationCreate: (input: CreateOperationInput) => ipcRenderer.invoke(IPC.operationCreate, input),
  swarmDeploy: (input: DeploySwarmInput) => ipcRenderer.invoke(IPC.swarmDeploy, input),
  swarmScale: (to: number) => ipcRenderer.invoke(IPC.swarmScale, to),
  swarmRecallAll: () => ipcRenderer.invoke(IPC.swarmRecallAll),
  vectorKill: (id: string) => ipcRenderer.invoke(IPC.vectorKill, id),
  vectorRedeploy: (id: string) => ipcRenderer.invoke(IPC.vectorRedeploy, id),
  vectorOpenWorktree: (id: string) => ipcRenderer.invoke(IPC.vectorOpenWorktree, id),
  terminalWrite: (terminalId: string, data: string) =>
    ipcRenderer.send(IPC.terminalWrite, { terminalId, data }),
  terminalResize: (terminalId: string, cols: number, rows: number) =>
    ipcRenderer.send(IPC.terminalResize, { terminalId, cols, rows }),
  intelConsolidate: () => ipcRenderer.invoke(IPC.intelConsolidate),
  intelOpenVault: () => ipcRenderer.invoke(IPC.intelOpenVault),
  engineStatus: () => ipcRenderer.invoke(IPC.engineStatus),
  engineStart: () => ipcRenderer.invoke(IPC.engineStart),
  engineStop: () => ipcRenderer.invoke(IPC.engineStop),
  governorStatus: () => ipcRenderer.invoke(IPC.governorStatus),
  receiptsList: () => ipcRenderer.invoke(IPC.receiptsList),
  approvalList: () => ipcRenderer.invoke(IPC.approvalList),
  approvalResolve: (id: string, resolution: ApprovalResolution) =>
    ipcRenderer.invoke(IPC.approvalResolve, { id, resolution }),
  pickDirectory: () => ipcRenderer.invoke(IPC.pickDirectory),

  onTerminalData: (cb) => subscribe<TerminalChunk>(IPC.evtTerminalData, cb),
  onTerminalExit: (cb) => subscribe<TerminalExit>(IPC.evtTerminalExit, cb),
  onVectorUpdate: (cb) => subscribe(IPC.evtVectorUpdate, cb),
  onOperationUpdate: (cb) => subscribe(IPC.evtOperationUpdate, cb),
  onEngineUpdate: (cb) => subscribe(IPC.evtEngineUpdate, cb),
  onGovernorUpdate: (cb) => subscribe(IPC.evtGovernorUpdate, cb),
  onApprovalNew: (cb) => subscribe<ApprovalRequest>(IPC.evtApprovalNew, cb),
  onApprovalResolved: (cb) => subscribe<ApprovalRequest>(IPC.evtApprovalResolved, cb),
  onApprovalExpired: (cb) => subscribe<string>(IPC.evtApprovalExpired, cb),
  onLog: (cb) => subscribe(IPC.evtLog, cb),
}

contextBridge.exposeInMainWorld('ambush', api)
