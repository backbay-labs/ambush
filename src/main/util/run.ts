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
    let stdout = ''
    let stderr = ''
    let settled = false
    const finish = (code: number | null): void => {
      if (settled) return
      settled = true
      resolve({ code, stdout, stderr })
    }
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          child.kill('SIGKILL')
          finish(null)
        }, opts.timeoutMs)
      : null
    child.stdout?.on('data', (d) => {
      stdout += d.toString()
    })
    child.stderr?.on('data', (d) => {
      stderr += d.toString()
    })
    child.on('error', () => finish(null))
    child.on('close', (code) => {
      if (timer) clearTimeout(timer)
      finish(code)
    })
    if (opts.input) {
      child.stdin?.write(opts.input)
      child.stdin?.end()
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
