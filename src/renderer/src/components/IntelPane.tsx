import type * as React from 'react'
import { useState } from 'react'
import { ExternalLink, FolderOpen, Layers3, RefreshCw } from 'lucide-react'
import { useStore } from '../store/useStore'

export function IntelPane(): React.JSX.Element {
  const engine = useStore((s) => s.engine)
  const consolidate = useStore((s) => s.consolidate)
  const [reloadKey, setReloadKey] = useState(0)
  const [note, setNote] = useState<string | null>(null)

  const onConsolidate = async (): Promise<void> => {
    const path = await consolidate()
    setNote(`Consolidated → ${path}`)
    setReloadKey((k) => k + 1)
  }

  const running = engine?.running && engine.url

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-edge bg-panel px-3">
        <span className="text-xs font-medium text-zinc-300">Intel vault</span>
        {engine && (
          <span className="text-[11px] text-zinc-600">
            {engine.governed ? 'governed · ' : ''}
            {engine.source === 'none' ? 'engine unavailable' : `via ${engine.source}`}
          </span>
        )}
        <div className="ml-auto flex items-center gap-1">
          <ToolbarBtn title="Consolidate kill-chain runbook" onClick={() => void onConsolidate()}>
            <Layers3 size={13} /> Consolidate
          </ToolbarBtn>
          <ToolbarBtn title="Open vault folder" onClick={() => void window.ambush.intelOpenVault()}>
            <FolderOpen size={13} />
          </ToolbarBtn>
          <ToolbarBtn title="Reload" onClick={() => setReloadKey((k) => k + 1)}>
            <RefreshCw size={13} />
          </ToolbarBtn>
        </div>
      </div>

      {note && <div className="bg-emerald-500/10 px-3 py-1 text-[11px] text-emerald-400">{note}</div>}

      {running ? (
        <webview
          key={reloadKey}
          src={engine.url as string}
          partition="persist:intel"
          style={{ flex: 1, minHeight: 0, border: 'none' }}
        />
      ) : (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
          <p className="max-w-md text-zinc-400">
            The OpenKnowledge intel engine isn’t running yet. Agents can still write findings to the
            vault as plain markdown; install the engine to browse them as a live wiki.
          </p>
          <code className="rounded bg-panel-2 px-3 py-1.5 text-xs text-accent">
            npm i -g @inkeep/open-knowledge
          </code>
          <button
            type="button"
            onClick={() => void window.ambush.intelOpenVault()}
            className="flex items-center gap-1.5 rounded-lg border border-edge px-3 py-1.5 text-xs text-zinc-300 hover:border-accent"
          >
            <ExternalLink size={13} /> Open vault folder
          </button>
        </div>
      )}
    </div>
  )
}

function ToolbarBtn({
  children,
  onClick,
  title,
}: {
  children: React.ReactNode
  onClick: () => void
  title: string
}): React.JSX.Element {
  return (
    <button
      type="button"
      title={title}
      onClick={onClick}
      className="flex items-center gap-1.5 rounded-md border border-edge px-2 py-1 text-[11px] text-zinc-300 hover:border-accent hover:text-white"
    >
      {children}
    </button>
  )
}
