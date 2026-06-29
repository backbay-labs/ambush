import type * as React from 'react'
import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, Microscope, RefreshCw, ShieldCheck } from 'lucide-react'
import type { FindingsReview as Review } from '@shared/types'
import { cn } from '../lib/cn'
import { useStore } from '../store/useStore'

export function FindingsReview(): React.JSX.Element {
  const operation = useStore((s) => s.operation)
  const [review, setReview] = useState<Review | null>(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setReview(await window.ambush.intelReview())
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const corroborated = review?.clusters.filter((c) => c.label === 'corroborated') ?? []
  const quarantine = review?.clusters.filter((c) => c.label === 'quarantine') ?? []

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-edge bg-panel px-3">
        <Microscope size={14} className="text-accent" />
        <span className="text-xs font-medium text-zinc-300">Validated findings</span>
        <span className="text-[11px] text-zinc-600">cross-model corroboration filter</span>
        {review && (
          <div className="ml-3 flex items-center gap-3 text-[11px]">
            <span className="text-emerald-400">{review.corroborated} corroborated</span>
            <span className="text-warn">{review.quarantined} quarantine</span>
            <span className="text-zinc-500">
              diversity: {review.modelFamilies.length} model{review.modelFamilies.length === 1 ? '' : 's'} (
              {review.modelFamilies.join(', ') || '—'})
            </span>
          </div>
        )}
        <button
          type="button"
          onClick={() => void load()}
          className="ml-auto flex items-center gap-1.5 rounded-md border border-edge px-2 py-1 text-[11px] text-zinc-300 hover:border-accent hover:text-white"
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Re-review
        </button>
      </div>

      {!operation ? (
        <Empty>No operation.</Empty>
      ) : !review || review.clusters.length === 0 ? (
        <Empty>No findings yet — deploy lanes (or the `seed` profile) so the vault fills.</Empty>
      ) : (
        <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
          <Section
            title="Corroborated"
            hint="reported independently by ≥2 model families — trust these first"
            icon={<ShieldCheck size={14} className="text-emerald-400" />}
            clusters={corroborated}
            empty="Nothing corroborated yet — needs a second model family to agree."
          />
          <Section
            title="Quarantine"
            hint="single-source — possible slop until a second model confirms"
            icon={<AlertTriangle size={14} className="text-warn" />}
            clusters={quarantine}
            empty="Nothing quarantined."
          />
        </div>
      )}
    </div>
  )
}

function Section({
  title,
  hint,
  icon,
  clusters,
  empty,
}: {
  title: string
  hint: string
  icon: React.ReactNode
  clusters: Review['clusters']
  empty: string
}): React.JSX.Element {
  return (
    <div>
      <div className="mb-2 flex items-center gap-2">
        {icon}
        <span className="text-xs font-medium text-zinc-200">{title}</span>
        <span className="text-[11px] text-zinc-600">{hint}</span>
      </div>
      {clusters.length === 0 ? (
        <p className="px-1 text-[11px] text-zinc-600">{empty}</p>
      ) : (
        <div className="space-y-2">
          {clusters.map((c) => (
            <div
              key={c.id}
              className={cn(
                'rounded-md border p-3',
                c.label === 'corroborated' ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-warn/30 bg-amber-500/5',
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <span className="text-xs text-zinc-200">{c.summary}</span>
                <div className="flex shrink-0 gap-1">
                  {c.modelFamilies.map((f) => (
                    <span key={f} className="rounded bg-edge px-1.5 py-0.5 font-mono text-[10px] text-zinc-300">
                      {f}
                    </span>
                  ))}
                </div>
              </div>
              <div className="mt-2 space-y-1 border-t border-edge/50 pt-2">
                {c.evidence.map((e, i) => (
                  <div key={`${c.id}-${i}`} className="flex gap-2 text-[11px]">
                    <span className="shrink-0 font-mono text-zinc-500">{e.vector}</span>
                    <span className="text-zinc-400">{e.snippet}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function Empty({ children }: { children: React.ReactNode }): React.JSX.Element {
  return <div className="flex flex-1 items-center justify-center text-sm text-zinc-600">{children}</div>
}
