import type * as React from 'react'
import { useState } from 'react'
import { Layers, Rocket, Square } from 'lucide-react'
import { useStore } from '../store/useStore'

export function DeployControls(): React.JSX.Element {
  const agents = useStore((s) => s.agents)
  const deploy = useStore((s) => s.deploy)
  const recallAll = useStore((s) => s.recallAll)
  const operation = useStore((s) => s.operation)
  const [agentId, setAgentId] = useState('shell')
  const [count, setCount] = useState(5)
  const [busy, setBusy] = useState(false)

  const live =
    operation?.vectors.filter((v) => v.status === 'running' || v.status === 'deploying').length ?? 0

  const onDeploy = async (): Promise<void> => {
    setBusy(true)
    try {
      await deploy(count, agentId)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="border-b border-edge p-3">
      <div className="mb-2 flex items-center gap-2 text-xs font-medium text-zinc-400">
        <Layers size={13} /> Deploy swarm
      </div>

      <select
        className="mb-2 w-full rounded-lg border border-edge bg-[#0e1015] px-2.5 py-2 text-xs text-zinc-200 outline-none focus:border-accent"
        value={agentId}
        onChange={(e) => setAgentId(e.target.value)}
      >
        {agents.map((a) => (
          <option key={a.id} value={a.id}>
            {a.name}
          </option>
        ))}
      </select>

      <div className="mb-2 flex items-center gap-2">
        <input
          type="range"
          min={1}
          max={50}
          value={count}
          onChange={(e) => setCount(Number(e.target.value))}
          className="flex-1 accent-[#36f1a3]"
        />
        <span className="w-8 text-right font-mono text-sm text-accent">{count}</span>
      </div>

      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => void onDeploy()}
          disabled={busy}
          className="flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-accent py-2 text-xs font-semibold text-[#04130c] hover:brightness-110 disabled:opacity-50"
        >
          <Rocket size={13} /> {busy ? 'Deploying…' : `Deploy ${count}`}
        </button>
        <button
          type="button"
          onClick={() => void recallAll()}
          disabled={live === 0}
          className="flex items-center justify-center gap-1.5 rounded-lg border border-edge px-3 py-2 text-xs text-zinc-300 hover:border-danger hover:text-danger disabled:opacity-40"
          title="Recall all running vectors"
        >
          <Square size={12} />
        </button>
      </div>

      <div className="mt-2 text-center text-[11px] text-zinc-500">
        {live} live · {operation?.vectors.length ?? 0} total
      </div>
    </div>
  )
}
