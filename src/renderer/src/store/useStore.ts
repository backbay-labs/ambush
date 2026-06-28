import { create } from 'zustand'
import type {
  AgentProfile,
  CreateOperationInput,
  EngineStatus,
  GovernorStatus,
  LogLine,
  Operation,
  ReceiptSummary,
  Vector,
} from '@shared/types'

export type Tab = 'swarm' | 'intel' | 'receipts'

interface AmbushState {
  operation: Operation | null
  agents: AgentProfile[]
  engine: EngineStatus | null
  governor: GovernorStatus | null
  receipts: ReceiptSummary[]
  logs: LogLine[]
  selectedVectorId: string | null
  tab: Tab
  booting: boolean

  bootstrap: () => Promise<void>
  setTab: (tab: Tab) => void
  selectVector: (id: string | null) => void

  createOperation: (input: CreateOperationInput) => Promise<void>
  deploy: (count: number, agentProfileId: string) => Promise<void>
  scale: (to: number) => Promise<void>
  recallAll: () => Promise<void>
  killVector: (id: string) => Promise<void>
  redeployVector: (id: string) => Promise<void>
  consolidate: () => Promise<string>
  refreshReceipts: () => Promise<void>

  _applyOperation: (op: Operation) => void
  _applyVector: (v: Vector) => void
}

export const useStore = create<AmbushState>((set, get) => ({
  operation: null,
  agents: [],
  engine: null,
  governor: null,
  receipts: [],
  logs: [],
  selectedVectorId: null,
  tab: 'swarm',
  booting: true,

  bootstrap: async () => {
    const [agents, operation, engine, governor] = await Promise.all([
      window.ambush.agentsList(),
      window.ambush.operationGet(),
      window.ambush.engineStatus(),
      window.ambush.governorStatus(),
    ])
    set({ agents, operation, engine, governor, booting: false })

    window.ambush.onOperationUpdate((op) => get()._applyOperation(op))
    window.ambush.onVectorUpdate((v) => get()._applyVector(v))
    window.ambush.onEngineUpdate((s) => set({ engine: s }))
    window.ambush.onGovernorUpdate((s) => set({ governor: s }))
    window.ambush.onLog((line) =>
      set((st) => ({ logs: [...st.logs.slice(-300), line] })),
    )
    if (governor.available) void get().refreshReceipts()
  },

  setTab: (tab) => set({ tab }),
  selectVector: (id) => set({ selectedVectorId: id }),

  createOperation: async (input) => {
    const op = await window.ambush.operationCreate(input)
    set({ operation: op })
  },
  deploy: async (count, agentProfileId) => {
    const op = await window.ambush.swarmDeploy({ count, agentProfileId })
    set({ operation: op })
  },
  scale: async (to) => {
    const op = await window.ambush.swarmScale(to)
    set({ operation: op })
  },
  recallAll: async () => {
    const op = await window.ambush.swarmRecallAll()
    set({ operation: op })
  },
  killVector: async (id) => {
    const op = await window.ambush.vectorKill(id)
    set({ operation: op })
  },
  redeployVector: async (id) => {
    const op = await window.ambush.vectorRedeploy(id)
    set({ operation: op })
  },
  consolidate: async () => {
    const { runbookPath } = await window.ambush.intelConsolidate()
    return runbookPath
  },
  refreshReceipts: async () => {
    const receipts = await window.ambush.receiptsList()
    set({ receipts })
  },

  _applyOperation: (op) => set({ operation: op }),
  _applyVector: (v) =>
    set((st) => {
      if (!st.operation) return st
      const exists = st.operation.vectors.some((x) => x.id === v.id)
      const vectors = exists
        ? st.operation.vectors.map((x) => (x.id === v.id ? v : x))
        : [...st.operation.vectors, v]
      return { operation: { ...st.operation, vectors } }
    }),
}))
