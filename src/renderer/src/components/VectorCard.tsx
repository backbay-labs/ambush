import type * as React from 'react'
import { FolderGit2, RotateCw, Square } from 'lucide-react'
import type { Vector, VectorStatus } from '@shared/types'
import { cn } from '../lib/cn'
import { useStore } from '../store/useStore'

const STATUS_COLOR: Record<VectorStatus, string> = {
  idle: 'bg-zinc-500',
  deploying: 'bg-vector',
  running: 'bg-accent',
  reporting: 'bg-vector',
  done: 'bg-emerald-500',
  failed: 'bg-danger',
  killed: 'bg-zinc-600',
}

export function VectorCard({
  vector,
  selected,
}: {
  vector: Vector
  selected: boolean
}): React.JSX.Element {
  const selectVector = useStore((s) => s.selectVector)
  const killVector = useStore((s) => s.killVector)
  const redeployVector = useStore((s) => s.redeployVector)
  const isLive = vector.status === 'running' || vector.status === 'deploying'

  return (
    <button
      type="button"
      onClick={() => selectVector(vector.id)}
      className={cn(
        'group w-full rounded-lg border p-2.5 text-left transition-colors',
        selected
          ? 'border-accent/60 bg-panel-2'
          : 'border-edge bg-panel hover:border-zinc-600 hover:bg-panel-2',
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className={cn('h-2 w-2 shrink-0 rounded-full', STATUS_COLOR[vector.status], isLive && 'live-ring')}
        />
        <span className="truncate font-mono text-xs text-zinc-200">{vector.name}</span>
        {vector.hasFindings && (
          <span className="ml-auto rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] text-emerald-400">
            intel
          </span>
        )}
      </div>
      <p className="mt-1 line-clamp-2 text-[11px] leading-snug text-zinc-500">{vector.objective}</p>

      <div className="mt-1.5 flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
        <span className="mr-auto text-[10px] uppercase tracking-wide text-zinc-600">
          {vector.status}
        </span>
        <Action title="Open worktree" onClick={() => void window.ambush.vectorOpenWorktree(vector.id)}>
          <FolderGit2 size={12} />
        </Action>
        <Action title="Redeploy" onClick={() => void redeployVector(vector.id)}>
          <RotateCw size={12} />
        </Action>
        {isLive && (
          <Action title="Kill" danger onClick={() => void killVector(vector.id)}>
            <Square size={11} />
          </Action>
        )}
      </div>
    </button>
  )
}

function Action({
  children,
  onClick,
  title,
  danger,
}: {
  children: React.ReactNode
  onClick: () => void
  title: string
  danger?: boolean
}): React.JSX.Element {
  return (
    <span
      role="button"
      tabIndex={-1}
      title={title}
      onClick={(e) => {
        e.stopPropagation()
        onClick()
      }}
      className={cn(
        'rounded p-1 text-zinc-400 hover:bg-edge',
        danger ? 'hover:text-danger' : 'hover:text-zinc-100',
      )}
    >
      {children}
    </span>
  )
}
