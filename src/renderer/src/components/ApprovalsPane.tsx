import type * as React from 'react'
import { useEffect } from 'react'
import { Check, ShieldQuestion, X } from 'lucide-react'
import type { ApprovalRequest } from '@shared/types'
import { cn } from '../lib/cn'
import { useStore } from '../store/useStore'

const STATUS_STYLE: Record<ApprovalRequest['status'], string> = {
  pending: 'text-warn bg-amber-500/10',
  resolved: 'text-emerald-400 bg-emerald-500/10',
  expired: 'text-zinc-400 bg-zinc-500/10',
}

export function ApprovalsPane(): React.JSX.Element {
  const approvals = useStore((s) => s.approvals)
  const refreshApprovals = useStore((s) => s.refreshApprovals)
  const resolveApproval = useStore((s) => s.resolveApproval)

  useEffect(() => {
    void refreshApprovals()
  }, [refreshApprovals])

  const pending = approvals.filter((a) => a.status === 'pending')

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-edge bg-panel px-3">
        <ShieldQuestion size={14} className="text-accent" />
        <span className="text-xs font-medium text-zinc-300">Human-gate approvals</span>
        <span className="text-[11px] text-zinc-600">
          {pending.length > 0 ? `${pending.length} awaiting decision` : 'no pending requests'}
        </span>
      </div>

      {approvals.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2 p-8 text-center text-zinc-400">
          <p>No approval requests.</p>
          <p className="text-[11px] text-zinc-600">
            Gated actions (e.g. launching an ungoverned swarm) surface here for an
            operator allow/deny decision.
          </p>
        </div>
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <ul className="divide-y divide-edge/60">
            {approvals.map((a) => (
              <li key={a.id} className="flex flex-col gap-2 px-4 py-3">
                <div className="flex items-center gap-2">
                  <span
                    className={cn('rounded px-1.5 py-0.5 text-[11px] font-medium', STATUS_STYLE[a.status])}
                  >
                    {a.status === 'resolved' && a.resolution ? a.resolution : a.status}
                  </span>
                  <span className="font-mono text-xs text-zinc-200">{a.tool}</span>
                  <span className="text-[11px] text-zinc-500">{a.guard}</span>
                  <span className="ml-auto text-[11px] uppercase tracking-wide text-zinc-600">
                    {a.severity}
                  </span>
                </div>
                <p className="text-xs text-zinc-300">{a.reason}</p>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-zinc-600">{a.resource}</span>
                  {a.status === 'pending' && (
                    <div className="ml-auto flex items-center gap-1.5">
                      <ResolveBtn
                        label="Allow once"
                        onClick={() => void resolveApproval(a.id, 'allow-once')}
                      />
                      <ResolveBtn
                        label="Allow session"
                        onClick={() => void resolveApproval(a.id, 'allow-session')}
                      />
                      <ResolveBtn
                        label="Deny"
                        danger
                        icon={<X size={12} />}
                        onClick={() => void resolveApproval(a.id, 'deny')}
                      />
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function ResolveBtn({
  label,
  onClick,
  danger,
  icon,
}: {
  label: string
  onClick: () => void
  danger?: boolean
  icon?: React.ReactNode
}): React.JSX.Element {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] transition-colors',
        danger
          ? 'border-edge text-danger hover:border-danger'
          : 'border-edge text-zinc-300 hover:border-accent hover:text-white',
      )}
    >
      {icon ?? <Check size={12} />}
      {label}
    </button>
  )
}
