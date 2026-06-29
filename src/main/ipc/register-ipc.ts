import { BrowserWindow, dialog, ipcMain, shell } from 'electron'
import { AGENT_PROFILES } from '@shared/agents'
import { IPC } from '@shared/ipc'
import type { ApprovalResolution, CreateOperationInput, DeploySwarmInput } from '@shared/types'
import type { OpenKnowledgeEngine } from '../engine/openknowledge-engine'
import type { ApprovalQueue } from '../governance/approval-queue'
import type { AttestationManager } from '../governance/attestation'
import type { ChioGovernor } from '../governance/chio-governor'
import { reviewFindings } from '../intel/findings-review'
import type { SwarmOrchestrator } from '../swarm/swarm-orchestrator'
import type { PtyManager } from '../terminal/pty-manager'
import type { TerminalGovernor } from '../terminal/terminal-governor'
import { bus } from '../util/bus'

interface Deps {
  orchestrator: SwarmOrchestrator
  engine: OpenKnowledgeEngine
  governor: ChioGovernor
  approvals: ApprovalQueue
  attest: AttestationManager
  terminalGovernor: TerminalGovernor
  pty: PtyManager
}

export function registerIpc(deps: Deps): void {
  const { orchestrator, engine, governor, approvals, attest, terminalGovernor, pty } = deps

  const broadcast = (channel: string, payload: unknown): void => {
    for (const win of BrowserWindow.getAllWindows()) {
      if (!win.isDestroyed()) win.webContents.send(channel, payload)
    }
  }

  // Forward bus events to all renderer windows.
  for (const channel of [
    IPC.evtTerminalData,
    IPC.evtTerminalExit,
    IPC.evtVectorUpdate,
    IPC.evtOperationUpdate,
    IPC.evtEngineUpdate,
    IPC.evtGovernorUpdate,
    IPC.evtReceipt,
    IPC.evtApprovalNew,
    IPC.evtApprovalResolved,
    IPC.evtApprovalExpired,
    IPC.evtLog,
  ]) {
    bus.on(channel, (payload) => broadcast(channel, payload))
  }

  // Terminal lifecycle: keep the orchestrator's vector state in sync.
  bus.on(IPC.evtTerminalExit, (exit: { terminalId: string; code: number | null }) => {
    orchestrator.onTerminalExit(exit.terminalId, exit.code)
    terminalGovernor.dispose(exit.terminalId)
  })

  ipcMain.handle(IPC.agentsList, () => AGENT_PROFILES)
  ipcMain.handle(IPC.operationGet, () => orchestrator.getOperation())
  ipcMain.handle(IPC.operationCreate, (_e, input: CreateOperationInput) =>
    orchestrator.createOperation(input),
  )
  ipcMain.handle(IPC.swarmDeploy, (_e, input: DeploySwarmInput) => orchestrator.deploySwarm(input))
  ipcMain.handle(IPC.swarmScale, (_e, to: number) => orchestrator.scale(to))
  ipcMain.handle(IPC.swarmRecallAll, () => orchestrator.recallAll())
  ipcMain.handle(IPC.vectorKill, (_e, id: string) => orchestrator.killVector(id))
  ipcMain.handle(IPC.vectorRedeploy, (_e, id: string) => orchestrator.redeployVector(id))
  ipcMain.handle(IPC.vectorOpenWorktree, (_e, id: string) => {
    const v = orchestrator.getOperation()?.vectors.find((x) => x.id === id)
    if (v?.worktreePath) void shell.openPath(v.worktreePath)
  })

  ipcMain.on(IPC.terminalWrite, (_e, { terminalId, data }: { terminalId: string; data: string }) => {
    // Governed: keystrokes forward live, but each submitted command is evaluated by swarm-governor.
    terminalGovernor.handleWrite(terminalId, data)
  })
  ipcMain.on(
    IPC.terminalResize,
    (_e, { terminalId, cols, rows }: { terminalId: string; cols: number; rows: number }) => {
      pty.resize(terminalId, cols, rows)
    },
  )

  ipcMain.handle(IPC.intelConsolidate, () => orchestrator.consolidate())
  ipcMain.handle(IPC.intelOpenVault, () => {
    const vault = orchestrator.getOperation()?.intelVaultPath
    if (vault) void shell.openPath(vault)
  })
  ipcMain.handle(IPC.intelReview, () => {
    const op = orchestrator.getOperation()
    return op ? reviewFindings(op.intelVaultPath) : null
  })

  ipcMain.handle(IPC.engineStatus, () => engine.getStatus())
  ipcMain.handle(IPC.engineStart, () => engine.start())
  ipcMain.handle(IPC.engineStop, () => engine.stop())
  ipcMain.handle(IPC.governorStatus, () => governor.getStatus())
  ipcMain.handle(IPC.receiptsList, () => governor.listReceipts())
  ipcMain.handle(IPC.siemExport, (_e, format) => governor.exportSiem(format))
  ipcMain.handle(IPC.approvalList, () => approvals.list())
  ipcMain.handle(
    IPC.approvalResolve,
    (_e, { id, resolution }: { id: string; resolution: ApprovalResolution }) =>
      approvals.resolve(id, resolution),
  )
  ipcMain.handle(IPC.attestationExport, async () => {
    const op = orchestrator.getOperation()
    if (!op) throw new Error('no active operation to attest')
    const receipts = await governor.listReceipts()
    return attest.exportBundle(op, receipts)
  })
  ipcMain.handle(
    IPC.attestationVerify,
    (_e, { bundleDir, signerKeyHex }: { bundleDir: string; signerKeyHex: string }) =>
      attest.verifyBundle(bundleDir, signerKeyHex),
  )

  ipcMain.handle(IPC.pickDirectory, async () => {
    const win = BrowserWindow.getFocusedWindow() ?? BrowserWindow.getAllWindows()[0]
    const res = await dialog.showOpenDialog(win, { properties: ['openDirectory', 'createDirectory'] })
    return res.canceled || res.filePaths.length === 0 ? null : res.filePaths[0]
  })
}
