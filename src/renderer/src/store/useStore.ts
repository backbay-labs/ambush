import { create } from 'zustand'
import type {
  AgentProfile,
  ApprovalRequest,
  ApprovalResolution,
  AttestationResult,
  CreateOperationInput,
  DenyToast,
  EngineStatus,
  GovernorStatus,
  LogLine,
  Operation,
  ReceiptSummary,
  Vector,
  VerifyOutcome,
} from '@shared/types'

export type Tab = 'swarm' | 'intel' | 'receipts' | 'approvals'

interface AmbushState {
  operation: Operation | null
  agents: AgentProfile[]
  engine: EngineStatus | null
  governor: GovernorStatus | null
  receipts: ReceiptSummary[]
  approvals: ApprovalRequest[]
  attestation: AttestationResult | null
  verifyOutcome: VerifyOutcome | null
  attesting: boolean
  denyToasts: DenyToast[]
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
  refreshApprovals: () => Promise<void>
  resolveApproval: (id: string, resolution: ApprovalResolution) => Promise<void>
  exportAttestation: () => Promise<void>
  verifyAttestation: () => Promise<void>
  dismissDenyToast: (id: string) => void

  _applyOperation: (op: Operation) => void
  _applyApproval: (req: ApprovalRequest) => void
  _applyReceipt: (r: ReceiptSummary) => void
  _applyVector: (v: Vector) => void
}

export const useStore = create<AmbushState>((set, get) => ({
  operation: null,
  agents: [],
  engine: null,
  governor: null,
  receipts: [],
  approvals: [],
  attestation: null,
  verifyOutcome: null,
  attesting: false,
  denyToasts: [],
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
    // Live signed governance receipts (terminal-command verdicts + intel-MCP gate denials).
    window.ambush.onReceipt((r) => get()._applyReceipt(r))
    // Approvals can fire even when ungoverned (the fail-closed launch gate), so
    // refresh/subscribe unconditionally.
    void get().refreshApprovals()
    window.ambush.onApprovalNew((req) => get()._applyApproval(req))
    window.ambush.onApprovalResolved((req) => get()._applyApproval(req))
    window.ambush.onApprovalExpired((id) =>
      set((st) => ({ approvals: st.approvals.filter((a) => a.id !== id) })),
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
    // Merge: keep live engine-governor (terminal) receipts, re-fetch the intel-MCP gate log.
    const chio = await window.ambush.receiptsList()
    set((st) => {
      const live = st.receipts.filter((r) => r.source === 'engine-governor')
      const seen = new Set(live.map((r) => r.id))
      return { receipts: [...live, ...chio.filter((r) => !seen.has(r.id))] }
    })
  },
  refreshApprovals: async () => {
    const approvals = await window.ambush.approvalList()
    set({ approvals })
  },
  resolveApproval: async (id, resolution) => {
    const req = await window.ambush.approvalResolve(id, resolution)
    if (req) get()._applyApproval(req)
  },
  exportAttestation: async () => {
    set({ attesting: true, verifyOutcome: null })
    try {
      const attestation = await window.ambush.attestationExport()
      set({ attestation })
    } finally {
      set({ attesting: false })
    }
  },
  verifyAttestation: async () => {
    const att = get().attestation
    if (!att) return
    const verifyOutcome = await window.ambush.attestationVerify(att.bundleDir, att.signerKeyHex)
    set({ verifyOutcome })
  },

  _applyOperation: (op) => set({ operation: op }),
  dismissDenyToast: (id) => set((st) => ({ denyToasts: st.denyToasts.filter((t) => t.id !== id) })),

  _applyApproval: (req) =>
    set((st) => {
      const exists = st.approvals.some((a) => a.id === req.id)
      return {
        approvals: exists
          ? st.approvals.map((a) => (a.id === req.id ? req : a))
          : [req, ...st.approvals],
      }
    }),
  _applyReceipt: (r) =>
    set((st) => {
      const receipts = [r, ...st.receipts.filter((x) => x.id !== r.id)].slice(0, 500)
      if (r.verdict !== 'DENY') return { receipts }
      const toast: DenyToast = {
        id: `toast-${r.id}`,
        command: r.tool,
        reason: r.reason ?? null,
        vectorLabel: r.server.replace(/^terminal:/, ''),
        at: r.timestamp ?? Date.now(),
      }
      return { receipts, denyToasts: [...st.denyToasts, toast] }
    }),
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
