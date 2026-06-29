import { EventEmitter } from 'node:events'
import { IPC } from '@shared/ipc'
import type {
  ApprovalRequest,
  EngineStatus,
  GovernorStatus,
  LogLine,
  Operation,
  TerminalChunk,
  TerminalExit,
  Vector,
} from '@shared/types'

// Internal event hub. Managers publish here; the IPC layer forwards everything
// to renderer windows. Keeping a single bus avoids threading webContents
// references through every manager.
class AppBus extends EventEmitter {
  log(level: LogLine['level'], scope: string, message: string): void {
    const line: LogLine = { level, scope, message, at: Date.now() }
    // eslint-disable-next-line no-console
    console[level === 'error' ? 'error' : 'log'](`[${scope}] ${message}`)
    this.emit(IPC.evtLog, line)
  }

  terminalData(chunk: TerminalChunk): void {
    this.emit(IPC.evtTerminalData, chunk)
  }

  terminalExit(exit: TerminalExit): void {
    this.emit(IPC.evtTerminalExit, exit)
  }

  vectorUpdate(vector: Vector): void {
    this.emit(IPC.evtVectorUpdate, vector)
  }

  operationUpdate(op: Operation): void {
    this.emit(IPC.evtOperationUpdate, op)
  }

  engineUpdate(status: EngineStatus): void {
    this.emit(IPC.evtEngineUpdate, status)
  }

  governorUpdate(status: GovernorStatus): void {
    this.emit(IPC.evtGovernorUpdate, status)
  }

  approvalNew(req: ApprovalRequest): void {
    this.emit(IPC.evtApprovalNew, req)
  }

  approvalResolved(req: ApprovalRequest): void {
    this.emit(IPC.evtApprovalResolved, req)
  }

  approvalExpired(id: string): void {
    this.emit(IPC.evtApprovalExpired, id)
  }
}

export const bus = new AppBus()
