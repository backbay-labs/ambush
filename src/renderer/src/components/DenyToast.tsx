import type * as React from 'react'
import { useEffect } from 'react'
import { Ban, X } from 'lucide-react'
import type { DenyToast } from '@shared/types'
import { useStore } from '../store/useStore'

export function DenyToastStack(): React.JSX.Element | null {
  const denyToasts = useStore((s) => s.denyToasts)
  if (denyToasts.length === 0) return null
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      {denyToasts.map((t) => (
        <Toast key={t.id} toast={t} />
      ))}
    </div>
  )
}

function Toast({ toast }: { toast: DenyToast }): React.JSX.Element {
  const dismiss = useStore((s) => s.dismissDenyToast)
  useEffect(() => {
    const h = setTimeout(() => dismiss(toast.id), 6000)
    return () => clearTimeout(h)
  }, [toast.id, dismiss])
  return (
    <div className="flex w-80 items-start gap-2 rounded-lg border border-danger bg-red-500/10 p-3 text-danger shadow-lg">
      <Ban size={16} className="mt-0.5 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="text-xs font-medium">Blocked by governance</div>
        <div className="truncate font-mono text-[11px] text-zinc-200" title={toast.command}>
          {toast.command}
        </div>
        {toast.reason && <div className="text-[11px] text-zinc-400">{toast.reason}</div>}
        <div className="text-[10px] text-zinc-600">{toast.vectorLabel}</div>
      </div>
      <button
        type="button"
        onClick={() => dismiss(toast.id)}
        className="shrink-0 text-zinc-500 hover:text-zinc-200"
      >
        <X size={14} />
      </button>
    </div>
  )
}
