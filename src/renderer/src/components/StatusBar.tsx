import type * as React from 'react'
import { Brain, Cpu, ShieldCheck, ShieldX } from 'lucide-react'
import { useStore } from '../store/useStore'

export function StatusBar(): React.JSX.Element {
  const engine = useStore((s) => s.engine)
  const governor = useStore((s) => s.governor)
  const operation = useStore((s) => s.operation)
  const logs = useStore((s) => s.logs)
  const lastLog = logs.at(-1)

  const counts = (operation?.vectors ?? []).reduce(
    (acc, v) => {
      if (v.status === 'running' || v.status === 'deploying') acc.live++
      else if (v.status === 'done') acc.done++
      else if (v.status === 'failed') acc.failed++
      return acc
    },
    { live: 0, done: 0, failed: 0 },
  )

  return (
    <footer className="flex h-7 shrink-0 items-center gap-4 border-t border-edge bg-panel px-3 text-[11px] text-zinc-500">
      <span className="flex items-center gap-1.5">
        <Cpu size={12} className="text-accent" />
        <span className="text-accent">{counts.live}</span> live
        <span className="text-zinc-600">·</span>
        <span className="text-emerald-400">{counts.done}</span> done
        <span className="text-zinc-600">·</span>
        <span className="text-danger">{counts.failed}</span> failed
      </span>

      <span className="flex items-center gap-1.5">
        <Brain size={12} className={engine?.running ? 'text-accent' : 'text-zinc-600'} />
        intel {engine?.running ? 'live' : engine?.available ? 'ready' : 'offline'}
      </span>

      <span className="flex items-center gap-1.5">
        {governor?.available ? (
          <ShieldCheck size={12} className="text-accent" />
        ) : (
          <ShieldX size={12} className="text-zinc-600" />
        )}
        {governor?.available ? 'governed' : 'ungoverned'}
      </span>

      {lastLog && (
        <span className="ml-auto truncate font-mono text-zinc-600">
          [{lastLog.scope}] {lastLog.message}
        </span>
      )}
    </footer>
  )
}
