import type { TerminalChunk } from '@shared/types'

// Buffers terminal output globally so a vector's scrollback survives switching
// panes. Live xterm instances attach to receive subsequent chunks.
const MAX_CHARS = 200_000

const buffers = new Map<string, string>()
const listeners = new Map<string, Set<(data: string) => void>>()

let started = false

export function startTerminalHub(): void {
  if (started) return
  started = true
  window.ambush.onTerminalData((chunk: TerminalChunk) => {
    const prev = buffers.get(chunk.terminalId) ?? ''
    const next = (prev + chunk.data).slice(-MAX_CHARS)
    buffers.set(chunk.terminalId, next)
    const set = listeners.get(chunk.terminalId)
    if (set) for (const cb of set) cb(chunk.data)
  })
}

export function getBuffer(terminalId: string): string {
  return buffers.get(terminalId) ?? ''
}

export function attach(terminalId: string, cb: (data: string) => void): () => void {
  let set = listeners.get(terminalId)
  if (!set) {
    set = new Set()
    listeners.set(terminalId, set)
  }
  set.add(cb)
  return () => {
    set?.delete(cb)
  }
}
