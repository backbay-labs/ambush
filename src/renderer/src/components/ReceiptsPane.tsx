import type * as React from 'react'
import { useEffect } from 'react'
import { BadgeCheck, RefreshCw, Share2, ShieldAlert, ShieldCheck, ShieldX, Stamp } from 'lucide-react'
import type { ReceiptSummary } from '@shared/types'
import { cn } from '../lib/cn'
import { useStore } from '../store/useStore'

const VERDICT_STYLE: Record<ReceiptSummary['verdict'], string> = {
  ALLOW: 'text-emerald-400 bg-emerald-500/10',
  DENY: 'text-danger bg-red-500/10',
  CANCELLED: 'text-warn bg-amber-500/10',
  INCOMPLETE: 'text-warn bg-amber-500/10',
  UNKNOWN: 'text-zinc-400 bg-zinc-500/10',
}

export function ReceiptsPane(): React.JSX.Element {
  const receipts = useStore((s) => s.receipts)
  const governor = useStore((s) => s.governor)
  const operation = useStore((s) => s.operation)
  const refreshReceipts = useStore((s) => s.refreshReceipts)
  const attestation = useStore((s) => s.attestation)
  const verifyOutcome = useStore((s) => s.verifyOutcome)
  const attesting = useStore((s) => s.attesting)
  const exportAttestation = useStore((s) => s.exportAttestation)
  const verifyAttestation = useStore((s) => s.verifyAttestation)

  useEffect(() => {
    void refreshReceipts()
  }, [refreshReceipts])

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-edge bg-panel px-3">
        {governor?.available ? (
          <ShieldCheck size={14} className="text-accent" />
        ) : (
          <ShieldX size={14} className="text-zinc-500" />
        )}
        <span className="text-xs font-medium text-zinc-300">Governance receipts</span>
        <span className="text-[11px] text-zinc-600">{governor?.detail}</span>
        <div className="ml-auto flex items-center gap-1.5">
          <button
            type="button"
            disabled={!operation || attesting}
            onClick={() => void exportAttestation()}
            className="flex items-center gap-1.5 rounded-md border border-edge px-2 py-1 text-[11px] text-zinc-300 hover:border-accent hover:text-white disabled:opacity-40"
          >
            <Stamp size={13} /> {attesting ? 'Signing…' : 'Export Attestation'}
          </button>
          {attestation && (
            <button
              type="button"
              onClick={() => void verifyAttestation()}
              className="flex items-center gap-1.5 rounded-md border border-edge px-2 py-1 text-[11px] text-zinc-300 hover:border-accent hover:text-white"
            >
              <BadgeCheck size={13} /> Verify
            </button>
          )}
          <button
            type="button"
            disabled={!governor?.available || receipts.length === 0}
            onClick={() => void window.ambush.siemExport('ocsf')}
            title="Render the signed receipt log as OCSF for your SIEM (path logged)"
            className="flex items-center gap-1.5 rounded-md border border-edge px-2 py-1 text-[11px] text-zinc-300 hover:border-accent hover:text-white disabled:opacity-40"
          >
            <Share2 size={13} /> Export SIEM
          </button>
          <button
            type="button"
            onClick={() => void refreshReceipts()}
            className="flex items-center gap-1.5 rounded-md border border-edge px-2 py-1 text-[11px] text-zinc-300 hover:border-accent hover:text-white"
          >
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {attestation && (
        <div className="flex shrink-0 items-center gap-3 border-b border-edge bg-panel-2 px-3 py-1.5 text-[11px]">
          <Stamp size={13} className="text-accent" />
          <span className="text-zinc-300">Attestation</span>
          <span className="font-mono text-zinc-500">{attestation.bundleId}</span>
          <span className="text-zinc-600">{attestation.artifactCount} artifacts</span>
          <span className="font-mono text-zinc-600" title={attestation.bundleDir}>
            signer {attestation.signerKeyHex.slice(0, 12)}…
          </span>
          {verifyOutcome &&
            (verifyOutcome.ok ? (
              <span className="ml-auto flex items-center gap-1.5 rounded px-2 py-0.5 font-medium text-emerald-400 bg-emerald-500/10">
                <BadgeCheck size={13} /> VERIFIED · {verifyOutcome.signaturesVerified} sig ·{' '}
                {verifyOutcome.artifactsVerified} artifacts · chain intact
              </span>
            ) : (
              <span className="ml-auto flex items-center gap-1.5 rounded px-2 py-0.5 font-medium text-danger bg-red-500/10">
                <ShieldAlert size={13} /> {verifyOutcome.errorCode ?? 'FAILED'} ·{' '}
                {verifyOutcome.error}
              </span>
            ))}
        </div>
      )}

      {receipts.length === 0 ? (
        !governor?.available ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 p-8 text-center text-zinc-400">
            <p>No governor on PATH, so the swarm runs ungoverned.</p>
            <p className="text-[11px] text-zinc-600">
              Build swarm-mcp-gate to sign every agent tool call into an append-only receipt log.
            </p>
          </div>
        ) : (
          <div className="flex flex-1 items-center justify-center text-zinc-600">
            No receipts yet — they appear as governed vectors touch the vault or run commands.
          </div>
        )
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-panel text-zinc-500">
              <tr>
                <Th>Verdict</Th>
                <Th>Tool</Th>
                <Th>Guard</Th>
                <Th>Server</Th>
                <Th>Policy</Th>
                <Th>When</Th>
              </tr>
            </thead>
            <tbody>
              {receipts.map((r) => (
                <tr key={r.id} className="border-t border-edge/60 hover:bg-panel">
                  <td className="px-3 py-1.5">
                    <span className={cn('rounded px-1.5 py-0.5 font-medium', VERDICT_STYLE[r.verdict])}>
                      {r.verdict}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-zinc-200">{r.tool}</td>
                  <td className="px-3 py-1.5 font-mono text-zinc-500" title={r.reason ?? undefined}>
                    {r.guard ?? '—'}
                  </td>
                  <td className="px-3 py-1.5 text-zinc-400">{r.server}</td>
                  <td className="px-3 py-1.5 font-mono text-zinc-600">
                    {r.policyHash ? r.policyHash.slice(0, 10) : '—'}
                  </td>
                  <td className="px-3 py-1.5 text-zinc-500">
                    {r.timestamp ? new Date(r.timestamp).toLocaleTimeString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function Th({ children }: { children: React.ReactNode }): React.JSX.Element {
  return <th className="px-3 py-2 font-medium">{children}</th>
}
