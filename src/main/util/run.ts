import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { delimiter, join } from 'node:path'

export interface RunResult {
  code: number | null
  stdout: string
  stderr: string
}

/** Run a command to completion and capture output. Never throws on non-zero. */
export function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; input?: string; timeoutMs?: number } = {},
): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      shell: false,
    })
    const MAX_BYTES = 16 * 1024 * 1024 // cap captured output so a runaway child can't OOM main
    let stdout = ''
    let stderr = ''
    let bytes = 0
    let truncated = false
    let settled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    const finish = (code: number | null): void => {
      if (settled) return
      settled = true
      if (timer) clearTimeout(timer) // always clear, incl. the error path (was dangling)
      resolve({ code, stdout, stderr })
    }
    timer = opts.timeoutMs
      ? setTimeout(() => {
          child.kill('SIGKILL')
          finish(null)
        }, opts.timeoutMs)
      : null
    const capture = (chunk: Buffer, isStdout: boolean): void => {
      if (truncated) return
      bytes += chunk.length
      if (bytes > MAX_BYTES) {
        truncated = true
        try {
          child.kill('SIGKILL')
        } catch {
          /* already gone */
        }
        return
      }
      if (isStdout) stdout += chunk.toString()
      else stderr += chunk.toString()
    }
    child.stdout?.on('data', (d: Buffer) => capture(d, true))
    child.stderr?.on('data', (d: Buffer) => capture(d, false))
    // A child that closes stdin before/while we write `input` emits an async EPIPE on the stdin
    // stream; with no listener Node re-throws it as an uncaught exception that kills the whole main
    // process (this is the per-Enter governor trust path). Swallow it — the close/error wins.
    child.stdin?.on('error', () => {})
    child.on('error', () => finish(null))
    child.on('close', (code) => finish(code))
    if (opts.input) {
      try {
        if (child.stdin?.writable) {
          child.stdin.write(opts.input)
          child.stdin.end()
        }
      } catch {
        /* child exited before reading stdin — error/close resolves the promise */
      }
    }
  })
}

/** Resolve an executable on PATH without invoking a shell. */
export function which(bin: string): string | null {
  const paths = (process.env.PATH ?? '').split(delimiter)
  const exts =
    process.platform === 'win32' ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';') : ['']
  for (const p of paths) {
    if (!p) continue
    for (const ext of exts) {
      const candidate = join(p, bin + ext.toLowerCase()) // try lowercase ext too
      const candidateUpper = join(p, bin + ext)
      if (existsSync(candidate)) return candidate
      if (existsSync(candidateUpper)) return candidateUpper
    }
  }
  return null
}
