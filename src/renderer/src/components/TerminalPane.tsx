import type * as React from 'react'
import { useEffect, useRef } from 'react'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { Terminal } from '@xterm/xterm'
import { FolderGit2, RotateCw } from 'lucide-react'
import type { Vector } from '@shared/types'
import { attach, getBuffer } from '../lib/terminalHub'
import { useStore } from '../store/useStore'

export function TerminalPane({
  terminalId,
  vector,
}: {
  terminalId: string
  vector: Vector
}): React.JSX.Element {
  const ref = useRef<HTMLDivElement>(null)
  const redeployVector = useStore((s) => s.redeployVector)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    const term = new Terminal({
      fontSize: 12,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
      cursorBlink: true,
      theme: {
        background: '#0a0b0e',
        foreground: '#d6dae4',
        cursor: '#36f1a3',
        selectionBackground: '#264532',
      },
      scrollback: 10_000,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.loadAddon(new WebLinksAddon())
    term.open(el)

    // Replay buffered scrollback, then stream live output.
    term.write(getBuffer(terminalId))
    const detach = attach(terminalId, (data) => term.write(data))

    term.onData((data) => window.ambush.terminalWrite(terminalId, data))

    const doFit = (): void => {
      try {
        fit.fit()
        window.ambush.terminalResize(terminalId, term.cols, term.rows)
      } catch {
        /* not mounted */
      }
    }
    doFit()
    const ro = new ResizeObserver(doFit)
    ro.observe(el)

    return () => {
      detach()
      ro.disconnect()
      term.dispose()
    }
  }, [terminalId])

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-edge bg-panel px-3">
        <span className="font-mono text-xs text-zinc-300">{vector.name}</span>
        <span className="text-[11px] text-zinc-600">{vector.branch ?? 'scratch dir'}</span>
        <div className="ml-auto flex items-center gap-1">
          <button
            type="button"
            className="rounded p-1 text-zinc-400 hover:bg-edge hover:text-zinc-100"
            title="Open worktree"
            onClick={() => void window.ambush.vectorOpenWorktree(vector.id)}
          >
            <FolderGit2 size={13} />
          </button>
          <button
            type="button"
            className="rounded p-1 text-zinc-400 hover:bg-edge hover:text-zinc-100"
            title="Redeploy"
            onClick={() => void redeployVector(vector.id)}
          >
            <RotateCw size={13} />
          </button>
        </div>
      </div>
      <div ref={ref} className="min-h-0 flex-1 p-2" />
    </div>
  )
}
