import type * as React from 'react'
import { useStore } from '../store/useStore'
import { DeployControls } from './DeployControls'
import { TerminalPane } from './TerminalPane'
import { VectorCard } from './VectorCard'

export function SwarmView(): React.JSX.Element {
  const operation = useStore((s) => s.operation)
  const selectedVectorId = useStore((s) => s.selectedVectorId)
  const vectors = operation?.vectors ?? []
  const selected = vectors.find((v) => v.id === selectedVectorId) ?? null

  return (
    <div className="flex min-h-0 flex-1">
      <aside className="flex w-80 shrink-0 flex-col border-r border-edge bg-panel">
        <DeployControls />
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {vectors.length === 0 ? (
            <p className="px-2 py-6 text-center text-zinc-500">
              No vectors yet. Deploy a swarm to begin.
            </p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {vectors.map((v) => (
                <VectorCard key={v.id} vector={v} selected={v.id === selectedVectorId} />
              ))}
            </div>
          )}
        </div>
      </aside>

      <main className="flex min-w-0 flex-1 flex-col bg-surface">
        {selected && selected.terminalId ? (
          <TerminalPane key={selected.terminalId} terminalId={selected.terminalId} vector={selected} />
        ) : (
          <div className="flex flex-1 items-center justify-center text-zinc-600">
            {vectors.length === 0
              ? 'Deploy a swarm to spin up agent horsepower.'
              : 'Select a vector to view its live terminal.'}
          </div>
        )}
      </main>
    </div>
  )
}
