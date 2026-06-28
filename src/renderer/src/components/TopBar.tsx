import type * as React from 'react'
import { Crosshair, FileText, ScrollText, Waypoints } from 'lucide-react'
import { cn } from '../lib/cn'
import { useStore, type Tab } from '../store/useStore'

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: 'swarm', label: 'Swarm', icon: Waypoints },
  { id: 'intel', label: 'Intel', icon: FileText },
  { id: 'receipts', label: 'Receipts', icon: ScrollText },
]

export function TopBar(): React.JSX.Element {
  const tab = useStore((s) => s.tab)
  const setTab = useStore((s) => s.setTab)
  const operation = useStore((s) => s.operation)

  return (
    <header className="drag flex h-11 shrink-0 items-center gap-3 border-b border-edge bg-panel px-3">
      <div className="flex items-center gap-2 pl-16">
        <Crosshair size={16} className="text-accent" />
        <span className="font-semibold tracking-tight">Ambush</span>
        <span className="text-[11px] uppercase tracking-[0.2em] text-zinc-500">vector swarm</span>
      </div>

      {operation && (
        <>
          <div className="mx-1 h-4 w-px bg-edge" />
          <span className="truncate text-zinc-300">{operation.name}</span>
        </>
      )}

      <div className="no-drag ml-auto flex items-center gap-1 rounded-lg bg-panel-2 p-1">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1 text-xs transition-colors',
              tab === id ? 'bg-edge text-white' : 'text-zinc-400 hover:text-zinc-200',
            )}
          >
            <Icon size={13} />
            {label}
          </button>
        ))}
      </div>
    </header>
  )
}
